"""Tests for BIRD 2.x 'show route all' text output parser."""

# Standard Library
import typing as t
from unittest.mock import MagicMock, patch

# Third Party
import pytest


# ---------------------------------------------------------------------------
# Minimal stubs so the parser module can be imported without the full
# hyperglass application stack (Redis, state, etc.)
# ---------------------------------------------------------------------------

def _make_stubs():
    import sys
    import types

    def _stub_module(*parts):
        name = ".".join(parts)
        if name not in sys.modules:
            sys.modules[name] = types.ModuleType(name)

    for mod in (
        "hyperglass",
        "hyperglass.log",
        "hyperglass.state",
        "hyperglass.external",
        "hyperglass.external.rpki",
        "hyperglass.models",
        "hyperglass.models.main",
        "hyperglass.models.data",
        "hyperglass.models.data.bgp_route",
    ):
        _stub_module(mod)

    # log stub
    log_stub = MagicMock()
    log_stub.bind.return_value = log_stub
    sys.modules["hyperglass.log"].log = log_stub

    # HyperglassModel stub
    from pydantic import BaseModel
    sys.modules["hyperglass.models.main"].HyperglassModel = BaseModel

    # BGPRoute / BGPRouteTable stubs (real Pydantic models, no validators)
    from pydantic import BaseModel as BM
    import typing as t

    class BGPRoute(BM):
        prefix: str
        active: bool
        age: int
        weight: int
        med: int
        local_preference: int
        as_path: t.List[int]
        communities: t.List[str]
        next_hop: str
        source_as: int
        source_rid: str
        peer_rid: str
        rpki_state: int

    class BGPRouteTable(BM):
        vrf: str
        count: int = 0
        routes: t.List[BGPRoute]
        winning_weight: str

        def __add__(self, other):
            if isinstance(other, BGPRouteTable):
                self.routes = sorted([*self.routes, *other.routes], key=lambda r: r.prefix)
                self.count = len(self.routes)
            return self

    sys.modules["hyperglass.models.data.bgp_route"].BGPRoute = BGPRoute
    sys.modules["hyperglass.models.data.bgp_route"].BGPRouteTable = BGPRouteTable
    sys.modules["hyperglass.models.data"].BGPRouteTable = BGPRouteTable
    sys.modules["hyperglass.models.data"].BGPRoute = BGPRoute


_make_stubs()

from hyperglass.models.parsing.bird import parse_bird  # noqa: E402


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

SAMPLE_1_1_1_0 = """BIRD 2.17.1 ready.
Table master4:
1.1.1.0/24           unicast [cloudflare1_4 2026-03-08 02:53:48] * (100) [AS13335i]
        via 193.189.82.195 on eth2
        Type: BGP univ
        BGP.origin: IGP
        BGP.as_path: 13335
        BGP.next_hop: 193.189.82.195
        BGP.local_pref: 170
        BGP.aggregator: 10.34.26.60 AS13335
        BGP.community:
        BGP.ext_community:
        BGP.large_community: (213151, 1000, 2)
                     unicast [openfactory4 2026-03-08 02:53:13 from 193.189.83.80] (100) [AS13335i]
        via 193.189.82.195 on eth2
        Type: BGP univ
        BGP.origin: IGP
        BGP.as_path: 41051 13335
        BGP.next_hop: 193.189.82.195
        BGP.local_pref: 50
        BGP.aggregator: 10.34.26.60 AS13335
        BGP.community:
        BGP.ext_community:
        BGP.large_community: (213151, 1000, 2) (213151, 200, 41051)
                     unreachable [core_de_fra2_4 2026-05-05 15:38:41 from 185.197.135.225] (100) [AS13335i]
        Type: BGP univ
        BGP.origin: IGP
        BGP.as_path: 13335
        BGP.next_hop: 80.81.194.180
        BGP.local_pref: 170
        BGP.large_community: (213151, 400, 13335) (213151, 1000, 1)"""

SAMPLE_8_8_8_0 = """BIRD 2.17.1 ready.
Table master4:
8.8.8.0/24           unicast [meerfarbig4 2026-03-31 15:39:05] * (100) [AS15169i]
        via 80.77.16.225 on eth1
        Type: BGP univ
        BGP.origin: IGP
        BGP.as_path: 34549 15169
        BGP.next_hop: 80.77.16.225
        BGP.local_pref: 50
        BGP.community:
        BGP.ext_community:
        BGP.large_community: (213151, 1000, 1) (213151, 200, 34549)
                     unreachable [core_de_fra2_4 2026-03-20 13:53:34 from 185.197.135.225] (100) [AS15169i]
        Type: BGP univ
        BGP.origin: IGP
        BGP.as_path: 214292 15169
        BGP.next_hop: 80.81.193.221
        BGP.med: 100
        BGP.local_pref: 150
        BGP.large_community: (213151, 300, 6695) (213151, 1000, 1)"""

SAMPLE_EMPTY = "BIRD 2.17.1 ready.\n"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_active_route_selected():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = [r for r in result.routes if r.active]
    assert len(active) == 1
    assert active[0].peer_rid == "cloudflare1_4"


def test_unreachable_excluded():
    result = parse_bird([SAMPLE_1_1_1_0])
    # unreachable routes have no valid next_hop and should be filtered out
    assert all(r.next_hop != "" for r in result.routes)
    peers = [r.peer_rid for r in result.routes]
    assert "core_de_fra2_4" not in peers


def test_prefix_parsed():
    result = parse_bird([SAMPLE_1_1_1_0])
    assert all(r.prefix == "1.1.1.0/24" for r in result.routes)


def test_as_path_parsed():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = next(r for r in result.routes if r.active)
    assert active.as_path == [13335]

    second = next(r for r in result.routes if r.peer_rid == "openfactory4")
    assert second.as_path == [41051, 13335]


def test_source_as_is_last_in_path():
    result = parse_bird([SAMPLE_1_1_1_0])
    for route in result.routes:
        if route.as_path:
            assert route.source_as == route.as_path[-1]


def test_local_pref_parsed():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = next(r for r in result.routes if r.active)
    assert active.local_preference == 170

    second = next(r for r in result.routes if r.peer_rid == "openfactory4")
    assert second.local_preference == 50


def test_large_communities_parsed():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = next(r for r in result.routes if r.active)
    assert "213151:1000:2" in active.communities

    second = next(r for r in result.routes if r.peer_rid == "openfactory4")
    assert "213151:200:41051" in second.communities


def test_med_parsed():
    result = parse_bird([SAMPLE_8_8_8_0])
    # The unreachable route with MED 100 should be excluded; active route has no MED
    active = next(r for r in result.routes if r.active)
    assert active.med == 0


def test_next_hop_parsed():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = next(r for r in result.routes if r.active)
    assert active.next_hop == "193.189.82.195"


def test_source_rid_from_aggregator():
    result = parse_bird([SAMPLE_1_1_1_0])
    active = next(r for r in result.routes if r.active)
    assert active.source_rid == "10.34.26.60"


def test_empty_output_returns_empty_table():
    result = parse_bird([SAMPLE_EMPTY])
    assert result.count == 0
    assert result.routes == []


def test_route_count():
    result = parse_bird([SAMPLE_1_1_1_0])
    # 3 routes in sample, 1 unreachable filtered → 2
    assert result.count == 2


def test_multiple_prefixes_in_one_response():
    result = parse_bird([SAMPLE_8_8_8_0])
    # 2 routes, 1 unreachable filtered → 1
    assert result.count == 1
    assert result.routes[0].prefix == "8.8.8.0/24"
