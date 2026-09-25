import ipaddress
import json
from pathlib import Path

import pytest

from nomad.routes import build_add_route_script, build_delete_route_script, build_route_copy_command, \
    validate_route_input
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
    assert "-PolicyStore PersistentStore" in persistent
    assert "-NextHop '0.0.0.0'" in persistent and "RouteMetric" not in persistent


def test_delete_script_removes_from_both_stores():
    route = Route(4, ipaddress.ip_network("10.0.0.0/8"), "On-link", "11", 5)
    script = build_delete_route_script(route)
    assert "'PersistentStore', 'ActiveStore'" in script
    assert "-NextHop '0.0.0.0'" in script


def test_copy_command():
    route = Route(4, ipaddress.ip_network("10.0.0.0/8"), "192.168.1.254", "11", 5, persistent=True)
    assert build_route_copy_command(route) == \
        "New-NetRoute -DestinationPrefix '10.0.0.0/8' -InterfaceIndex 11 -NextHop '192.168.1.254' -RouteMetric 5"
