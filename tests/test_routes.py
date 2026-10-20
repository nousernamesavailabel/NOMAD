import ipaddress
import json
from pathlib import Path

import pytest

from nomad.routes import build_add_route_script, build_delete_route_script, build_route_copy_command, \
    connected_network_warning, gateway_suggestions, matching_routes, parse_route_lookup, validate_route_input
from nomad.snapshot import Route, parse_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot.json"


@pytest.fixture
def adapters():
    return parse_snapshot(json.loads(FIXTURE.read_text())).adapters


def validate(adapters, destination, netmask="", gateway="", metric="", interface=None, family=4):
    return validate_route_input(family, destination, netmask, gateway, metric, interface, adapters)


def test_cidr_destination(adapters):
    spec, errors, _ = validate(adapters, "10.20.0.0/16", gateway="192.168.1.1")
    assert not errors
    assert spec["network"] == ipaddress.ip_network("10.20.0.0/16")
    assert spec["interface"] == "11"  # Found from the gateway's subnet


def test_netmask_destination(adapters):
    spec, errors, _ = validate(adapters, "10.20.0.0", "255.255.0.0", "192.168.1.1", "5")
    assert not errors and spec["metric"] == 5


@pytest.mark.parametrize("destination, netmask, field", [
    ("10.0.0.1/24", "", "destination"),  # Host bits set
    ("10.0.0.0", "", "netmask"),
    ("10.0.0.0", "0.0.0.255", "netmask"),  # Host mask, not a netmask
    ("10.0.0.0", "255.0.255.0", "netmask"),  # Non-contiguous
    ("10.0.0.0 & calc", "255.0.0.0", "destination"),  # Shell metacharacters rejected
])
def test_bad_destinations(adapters, destination, netmask, field):
    _, errors, _ = validate(adapters, destination, netmask, "192.168.1.1")
    assert field in errors


def test_gateway_outside_local_subnets_needs_interface(adapters):
    _, errors, _ = validate(adapters, "10.0.0.0/8", gateway="172.31.0.1")
    assert "gateway" in errors


def test_gateway_outside_chosen_interface_warns(adapters):
    spec, errors, warnings = validate(adapters, "10.0.0.0/8", gateway="172.31.0.1", interface="11")
    assert not errors and spec is not None and warnings


def test_on_link_route_needs_interface(adapters):
    _, errors, _ = validate(adapters, "10.0.0.0/8")
    assert "interface" in errors
    spec, errors, _ = validate(adapters, "10.0.0.0/8", interface="11")
    assert not errors and spec["gateway"] == ""


def test_metric_range(adapters):
    _, errors, _ = validate(adapters, "10.0.0.0/8", gateway="192.168.1.1", metric="10000")
    assert "metric" in errors


def test_ipv6_requires_prefix_and_interface(adapters):
    _, errors, _ = validate(adapters, "2001:db8::", family=6, gateway="fe80::1", interface="11")
    assert "destination" in errors
    _, errors, _ = validate(adapters, "2001:db8::/32", family=6, gateway="fe80::1")
    assert "interface" in errors
    spec, errors, _ = validate(adapters, "2001:db8::/32", family=6, gateway="fe80::1", interface="11")
    assert not errors


def test_add_script_persistent_and_active():
    network = ipaddress.ip_network("10.20.0.0/16")
    active = build_add_route_script(4, network, "192.168.1.1", "11", 5, persistent=False)
    assert "-PolicyStore ActiveStore" in active and "PersistentStore" not in active
    assert "-DestinationPrefix '10.20.0.0/16'" in active and "-RouteMetric 5" in active
    persistent = build_add_route_script(4, network, "", "11", None, persistent=True)
    # New-NetRoute rejects -PolicyStore PersistentStore; no store adds to both
    assert "PersistentStore" not in persistent
    assert persistent.splitlines()[-1] == "New-NetRoute -DestinationPrefix '10.20.0.0/16' -InterfaceIndex 11 " \
                                          "-NextHop '0.0.0.0' | Out-Null"


def lookup_routes():
    return [
        Route(4, ipaddress.ip_network("0.0.0.0/0"), "192.168.1.1", "11", 0, 25),
        Route(4, ipaddress.ip_network("10.0.0.0/8"), "192.168.1.254", "11", 5, 25),
        Route(4, ipaddress.ip_network("10.1.0.0/16"), "192.168.1.253", "11", 50, 25),
        Route(4, ipaddress.ip_network("10.1.0.0/16"), "192.168.1.252", "11", 10, 25),
        Route(4, ipaddress.ip_network("10.1.2.0/24"), "192.168.1.9", "11", 1, 25, persistent=True, active=False),
        Route(4, ipaddress.ip_network("172.16.0.0/12"), "192.168.1.254", "11", 5, 25),
    ]


def test_lookup_picks_longest_active_prefix_then_lowest_metric():
    matches, best = matching_routes(lookup_routes(), parse_route_lookup(4, "10.1.2.3"))
    assert [str(route.network) for route in matches] == ["0.0.0.0/0", "10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/16",
                                                          "10.1.2.0/24"]
    assert best.gateway == "192.168.1.252"  # The inactive /24 is skipped


def test_lookup_falls_back_to_default_route():
    _, best = matching_routes(lookup_routes(), parse_route_lookup(4, "8.8.8.8"))
    assert best.is_default


def test_lookup_of_a_network():
    matches, best = matching_routes(lookup_routes(), parse_route_lookup(4, "10.2.0.0/16"))
    assert len(matches) == 2 and str(best.network) == "10.0.0.0/8"


@pytest.mark.parametrize("text, network", [
    ("10.", "10.0.0.0/8"), ("10.1", "10.1.0.0/16"), ("10.1.2.", "10.1.2.0/24"), ("10.1.2.3", "10.1.2.3/32"),
])
def test_lookup_of_a_partly_typed_address(text, network):
    target = parse_route_lookup(4, text)
    assert str(target) == network
    _, best = matching_routes(lookup_routes(), target)
    assert best is not None  # The default route at least always matches


@pytest.mark.parametrize("text", ["10", "10..1", "10.1.300", "192.168.1.1 eth", "ethernet", "", "2001:db8::1"])
def test_lookup_ignores_plain_filter_text(text):
    assert parse_route_lookup(4, text) is None


def test_delete_script_removes_from_both_stores():
    route = Route(4, ipaddress.ip_network("10.0.0.0/8"), "On-link", "11", 5)
    script = build_delete_route_script(route)
    assert "'PersistentStore', 'ActiveStore'" in script
    assert "-NextHop '0.0.0.0'" in script


def test_copy_command():
    route = Route(4, ipaddress.ip_network("10.0.0.0/8"), "192.168.1.254", "11", 5, persistent=True)
    assert build_route_copy_command(route) == \
        "New-NetRoute -DestinationPrefix '10.0.0.0/8' -InterfaceIndex 11 -NextHop '192.168.1.254' -RouteMetric 5"


def test_gateway_suggestions_list_default_gateways_then_route_next_hops(adapters):
    routes = parse_snapshot(json.loads(FIXTURE.read_text())).routes
    suggestions = gateway_suggestions(4, adapters, routes)
    assert [(gateway, interface) for gateway, interface, _ in suggestions] == \
        [("192.168.1.1", "11"), ("192.168.1.254", "11")]  # Not the inactive 172.16.0.0/12 route's gateway
    assert "default gateway on Ethernet" in suggestions[0][2]
    assert "next hop of 1 route on Ethernet" in suggestions[1][2]
    assert [gateway for gateway, _, _ in gateway_suggestions(6, adapters, routes)] == ["fe80::1"]


@pytest.mark.parametrize("network, warned", [
    ("192.168.1.0/24", True), ("192.168.1.128/25", True),  # The computer is on it already
    ("192.168.0.0/16", False),  # A summary that covers the connected subnet is a real route
    ("10.5.0.0/16", False), ("127.0.0.0/8", False),
])
def test_connected_network_warning(adapters, network, warned):
    assert bool(connected_network_warning(ipaddress.ip_network(network), adapters)) == warned


def test_route_to_a_connected_subnet_warns_only_with_a_gateway(adapters):
    spec, errors, warnings = validate(adapters, "192.168.1.0/24", gateway="192.168.1.254")
    assert not errors and spec is not None and "already on 192.168.1.0/24" in warnings[0]
    _, _, warnings = validate(adapters, "192.168.1.0/24", interface="11")  # The connected route itself
    assert not warnings
