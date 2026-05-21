"""Data Models for Parsing BIRD 2.x 'show route all' Text Response."""

# Standard Library
import re
import typing as t
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

_RE_VIA = re.compile(r"^\s+via\s+(?P<next_hop>\S+)")
_RE_ATTR = re.compile(r"^\s+BGP\.(?P<key>\w+):\s*(?P<value>.*)")

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
    current_prefix: t.Optional[str] = None
    in_bgp_table = False

    for response in output:
        lines = response.splitlines()
        route: t.Optional[t.Dict] = None

        for line in lines:
            # Track which table we're in — only parse BGP tables
            if line.startswith("Table "):
                if route is not None:
                    routes.append(route)
                    route = None
                table_name = line.split()[1].rstrip(":")
                in_bgp_table = table_name.startswith(("master", "bgp"))
                current_prefix = None
                continue

            if not in_bgp_table:
                continue

            header_match = _RE_ROUTE_HEADER.match(line)
            if header_match:
                # Save previous route
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
                    "rpki_state": 3,
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
                    # IPv6 next_hop may have two addresses: global + link-local
                    # Take only the first (global) one
                    route["next_hop"] = value.split()[0] if value else ""
                elif key == "community":
                    route["communities"] += _parse_communities(value)
                elif key == "large_community":
                    route["communities"] += _parse_large_communities(value)
                elif key == "aggregator":
                    # Format: "10.34.26.60 AS13335"
                    parts = value.split()
                    route["source_rid"] = parts[0] if parts else ""
                # BGP.atomic_aggr and other flag-only attributes are intentionally ignored
                continue

        if route is not None:
            routes.append(route)

    # Filter out routes with no valid next_hop (unreachable with no next_hop set)
    valid_routes = [r for r in routes if r.get("next_hop") is not None and r["prefix"]]

    serialized = BGPRouteTable(
        vrf="default",
        count=len(valid_routes),
        routes=valid_routes,
        winning_weight="high",
    )

    log.bind(platform="bird", response=repr(serialized)).debug("Serialized response")
    return serialized
