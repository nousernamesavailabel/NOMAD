import ipaddress
import json
from pathlib import Path

import pytest

from nomad.snapshot import Adapter, parse_snapshot

FIXTURE = Path(__file__).parent / "fixtures" / "snapshot.json"


@pytest.fixture
def snapshot():
    data = json.loads(FIXTURE.read_text())
    return parse_snapshot(data, dns_is_static=lambda guid: guid.endswith("0011}"))


def find_route(snapshot, prefix, interface=None):
    return next(route for route in snapshot.routes
                if str(route.network) == prefix and (interface is None or route.interface == interface))


def test_adapters(snapshot):
    ethernet = snapshot.adapters["11"]
    assert ethernet.name == "Ethernet"
    assert ethernet.status == "Up"
    assert ethernet.mac == "00-11-22-33-44-55"
    assert ethernet.speed_text == "1 Gbps"
    assert ethernet.dhcp is False
    assert ethernet.ipv4 == [ipaddress.ip_interface("192.168.1.10/24"), ipaddress.ip_interface("192.168.1.11/24")]
    assert ethernet.ipv6 == [ipaddress.ip_interface("fe80::1234/64")]  # Zone ID stripped
    assert ethernet.gateways4 == ["192.168.1.1"]
    assert ethernet.gateways6 == ["fe80::1"]
    assert ethernet.dns4 == ["1.1.1.1", "8.8.8.8"]
    assert ethernet.dns_static is True
    assert ethernet.metric4 == 25 and ethernet.mtu4 == 1500


def test_adapter_states(snapshot):
    assert snapshot.adapters["12"].status == "Disconnected"
    assert snapshot.adapters["13"].status == "Disabled"
    assert not snapshot.adapters["13"].enabled
    assert "20" not in snapshot.adapters  # Hidden adapters are skipped


def test_loopback_is_not_a_real_adapter(snapshot):
    loopback = snapshot.adapters["1"]
    assert not loopback.is_adapter
    # Adapters that are up come first, then the rest by name
    assert [adapter.index for adapter in snapshot.real_adapters()] == ["11", "13", "12"]


def test_route_metrics_and_flags(snapshot):
    default = find_route(snapshot, "0.0.0.0/0")
    assert default.is_default and not default.is_system
    assert default.metric == 25  # Route metric 0 + interface metric 25
    on_link = find_route(snapshot, "192.168.1.0/24")
    assert on_link.on_link and on_link.gateway == "On-link" and on_link.next_hop == "0.0.0.0"
    assert find_route(snapshot, "192.168.1.10/32").is_system
    assert find_route(snapshot, "224.0.0.0/4").is_system
    assert find_route(snapshot, "fe80::/64").is_system


def test_persistent_routes_are_merged(snapshot):
    active_persistent = find_route(snapshot, "10.0.0.0/8")
    assert active_persistent.persistent and active_persistent.active
    assert len([route for route in snapshot.routes if str(route.network) == "10.0.0.0/8"]) == 1

    inactive = find_route(snapshot, "172.16.0.0/12")
    assert inactive.persistent and not inactive.active


def test_empty_snapshot():
    snapshot = parse_snapshot({})
    assert snapshot.adapters == {} and snapshot.routes == []


def test_single_items_are_not_lists():
    # ConvertTo-Json can collapse single-item arrays into objects
    data = {"adapters": {"InterfaceIndex": 5, "Name": "Solo", "InterfaceOperationalStatus": 1}}
    assert parse_snapshot(data).adapters["5"].name == "Solo"


@pytest.mark.parametrize("status, dhcp, addresses, expected", [
    ("Up", True, ["169.254.10.20/16"], True),  # Automatic (APIPA) address while the lease is pending
    ("Up", True, [], True),
    ("Up", True, ["169.254.10.20/16", "192.168.1.50/24"], False),
    ("Up", False, ["169.254.10.20/16"], False),  # Static
    ("Disconnected", True, ["169.254.10.20/16"], False),
])
def test_awaiting_dhcp(status, dhcp, addresses, expected):
    adapter = Adapter("1", "Ethernet", status=status, dhcp=dhcp,
                      ipv4=[ipaddress.ip_interface(address) for address in addresses])
    assert adapter.awaiting_dhcp is expected
