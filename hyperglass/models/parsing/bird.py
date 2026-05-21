"""Data Models for Parsing BIRD 2.x 'show route all' Text Response."""

# Standard Library
import re
import typing as t
from ipaddress import ip_network
from datetime import datetime, timezone

# Project
from hyperglass.log import log
from hyperglass.models.data import BGPRouteTable

# Matches the start of a new prefix block, e.g.:
#   1.1.1.0/24           unicast [cloudflare1_4 2026-03-08 02:53:48] * (100) [AS13335i]
#                        unicast [openfactory4 ...] (100) [AS13335i]
_RE_ROUTE_HEADER = re.compile(
    r"^(?P<prefix>\S+)?\s+"
    r"(?P<route_type>\S+)\s+"
    r"\[(?P<peer>\S+)\s+(?P<since>[^\]]+)\]\s*"
    r"(?P<active>\*)?\s*"
    r"\(\d+\)\s*"
    r"(?:\[AS(?P<source_as>\d+).*?\])?"
)

# Matches RPKI table entries: 8.8.8.0/24-24 AS15169
_RE_RPKI_ENTRY = re.compile(
    r"^(?P<prefix>\S+)/(?P<max_len>\d+)\s+AS(?P<origin_as>\d+)"
)

_RE_VIA = re.compile(r"^\s+via\s+(?P<next_hop>\S+)")
_RE_ATTR = re.compile(r"^\s+BGP\.(?P<key>\w+):\s*(?P<value>.*)")

# RPKI state values matching hyperglass convention
_RPKI_VALID = 1
_RPKI_INVALID = 0
_RPKI_NOT_FOUND = 2
_RPKI_NOT_VALIDATED = 3


class _Roa(t.NamedTuple):
    """A single ROA entry from the RPKI table."""
    network: t.Any  # ip_network object
    max_len: int
    origin_as: int


def _rpki_state(prefix: str, origin_as: int, roas: t.List[_Roa]) -> int:
    """Determine RPKI validity of a prefix/origin_as pair against a list of ROAs."""
    try:
        net = ip_network(prefix, strict=False)
    except ValueError:
        return _RPKI_NOT_VALIDATED

    # ROAs whose network contains this prefix and whose max_len allows this prefix length
    covering = [
        r for r in roas
        if net.subnet_of(r.network) or net == r.network
        and net.prefixlen <= r.max_len
    ]

    if not covering:
        return _RPKI_NOT_FOUND
    if any(r.origin_as == origin_as for r in covering):
        return _RPKI_VALID
    return _RPKI_INVALID

def _parse_since(since: str) -> int:
    """Convert a BIRD timestamp string to an age in seconds."""
    since = since.strip().split(" from ")[0].strip()
    try:
        dt = datetime.strptime(since, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return int(datetime.now(timezone.utc).timestamp() - dt.timestamp())
    except ValueError:
        return 0


def _parse_large_communities(raw: str) -> t.List[str]:
    """Parse BIRD large community strings like '(213151, 1000, 2) (213151, 200, 41051)'."""
    return [
        ":".join(p.strip() for p in m.split(","))
        for m in re.findall(r"\(([^)]+)\)", raw)
    ]


def _parse_communities(raw: str) -> t.List[str]:
    """Parse standard community strings."""
    return [c.strip() for c in raw.split() if c.strip()]


def _parse_as_path(raw: str) -> t.List[int]:
    return [int(asn) for asn in raw.split() if asn.isdigit()]


def parse_bird(output: t.Sequence[str]) -> "BGPRouteTable":
    """Parse BIRD 2.x 'show route all' text output into a BGPRouteTable."""
    routes = []
    roas: t.List[_Roa] = []
    current_prefix: t.Optional[str] = None

    for response in output:
        lines = response.splitlines()
        route: t.Optional[t.Dict] = None
        in_bgp_table = True
        in_rpki_table = False

        for line in lines:
            # Track which table we're in
            if line.startswith("Table "):
                if route is not None:
                    routes.append(route)
                    route = None
                table_name = line.split()[1].rstrip(":")
                in_bgp_table = table_name.startswith(("master", "bgp"))
                in_rpki_table = table_name.startswith("rpki")
                current_prefix = None
                continue

            # Collect ROA entries from RPKI tables
            if in_rpki_table:
                rpki_match = _RE_RPKI_ENTRY.match(line)
                if rpki_match:
                    try:
                        roas.append(_Roa(
                            network=ip_network(rpki_match.group("prefix"), strict=False),
                            max_len=int(rpki_match.group("max_len")),
                            origin_as=int(rpki_match.group("origin_as")),
                        ))
                    except ValueError:
                        pass
                continue

            if not in_bgp_table:
                continue

            header_match = _RE_ROUTE_HEADER.match(line)
            if header_match:
                if route is not None:
                    routes.append(route)

                prefix_field = header_match.group("prefix")
                if prefix_field:
                    current_prefix = prefix_field

                route_type = header_match.group("route_type")
                route = {
                    "prefix": current_prefix,
                    "active": header_match.group("active") == "*",
                    "age": _parse_since(header_match.group("since")),
                    "peer_rid": header_match.group("peer") or "",
                    "route_type": route_type,
                    "next_hop": "" if route_type == "unreachable" else None,
                    "as_path": [],
                    "communities": [],
                    "source_as": int(header_match.group("source_as") or 0),
                    "source_rid": "",
                    "weight": 0,
                    "med": 0,
                    "local_preference": 100,
                    "rpki_state": _RPKI_NOT_VALIDATED,
                }
                continue

            if route is None:
                continue

            via_match = _RE_VIA.match(line)
            if via_match:
                route["next_hop"] = via_match.group("next_hop")
                continue

            attr_match = _RE_ATTR.match(line)
            if attr_match:
                key = attr_match.group("key").lower()
                value = attr_match.group("value").strip()

                if key == "as_path":
                    route["as_path"] = _parse_as_path(value)
                    if route["as_path"]:
                        route["source_as"] = route["as_path"][-1]
                elif key == "local_pref":
                    route["local_preference"] = int(value) if value else 100
                elif key == "med":
                    route["med"] = int(value) if value else 0
                elif key == "next_hop":
                    route["next_hop"] = value.split()[0] if value else ""
                elif key == "community":
                    route["communities"] += _parse_communities(value)
                elif key == "large_community":
                    route["communities"] += _parse_large_communities(value)
                elif key == "aggregator":
                    parts = value.split()
                    route["source_rid"] = parts[0] if parts else ""
                continue

        if route is not None:
            routes.append(route)

    # Apply RPKI state from collected ROAs, then filter and clean
    valid_routes = []
    for r in routes:
        if r.get("next_hop") is None or not r["prefix"]:
            continue
        if roas:
            r["rpki_state"] = _rpki_state(r["prefix"], r["source_as"], roas)
        valid_routes.append({k: v for k, v in r.items() if k != "route_type"})

    serialized = BGPRouteTable(
        vrf="default",
        count=len(valid_routes),
        routes=valid_routes,
        winning_weight="high",
    )

    log.bind(platform="bird", response=repr(serialized)).debug("Serialized response")
    return serialized
