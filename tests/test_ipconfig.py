import pytest

from nomad.ipconfig import IPConfig, build_apply_commands, config_from_adapter, validate_ip_config, validate_mtu


def validate(dhcp=False, address="", netmask="", gateway="", primary="", backup="", dns_auto=False, secondary="",
             extra_gateways=""):
    return validate_ip_config(dhcp, address, netmask, gateway, primary, backup, dns_auto, secondary, extra_gateways)


def test_static_with_cidr():
    config, errors, warnings = validate(address="192.168.1.10/24", gateway="192.168.1.1", primary="1.1.1.1")
    assert not errors and not warnings
    assert (config.address, config.netmask, config.gateway, config.dns) == \
        ("192.168.1.10", "255.255.255.0", "192.168.1.1", ["1.1.1.1"])


@pytest.mark.parametrize("kwargs, field", [
    ({"address": ""}, "address"),
    ({"address": "192.168.1.10"}, "netmask"),
    ({"address": "192.168.1.0/24"}, "address"),  # Network address
    ({"address": "192.168.1.255/24"}, "address"),  # Broadcast address
    ({"address": "127.0.0.5/8"}, "address"),
    ({"address": "192.168.1.10/24", "gateway": "192.168.1.10"}, "gateway"),
    ({"address": "192.168.1.10/24", "backup": "8.8.8.8"}, "primary_dns"),  # Backup without primary
    ({"address": "192.168.1.10/24", "primary": "dns.google"}, "primary_dns"),
])
def test_invalid_static(kwargs, field):
    _, errors, _ = validate(**kwargs)
    assert field in errors


def test_gateway_outside_subnet_is_a_warning():
    config, errors, warnings = validate(address="192.168.1.10/24", gateway="10.0.0.1")
    assert config is not None and not errors and warnings


def test_dhcp_ignores_address_fields():
    config, errors, _ = validate(dhcp=True, address="garbage", dns_auto=True)
    assert not errors and config.dhcp and config.dns_auto


def test_dhcp_with_manual_dns():
    config, errors, _ = validate(dhcp=True, primary="1.1.1.1", backup="1.0.0.1")
    assert not errors and config.dns == ["1.1.1.1", "1.0.0.1"] and not config.dns_auto


def test_mtu_validation():
    assert validate_mtu("1500") == (1500, None)
    assert validate_mtu("100")[1] and validate_mtu("abc")[1]


def test_dhcp_step_skipped_when_already_dhcp():
    # netsh fails with "DHCP is already enabled" otherwise
    old = IPConfig(dhcp=True, dns_auto=False, dns=["1.1.1.1"])
    new = IPConfig(dhcp=True, dns_auto=True)
    commands = build_apply_commands("11", new, old)
    assert commands == [["netsh", "interface", "ipv4", "set", "dnsservers", "name=11", "source=dhcp"]]


def test_static_commands():
    new = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="", dns=["1.1.1.1", "8.8.8.8"])
    commands = build_apply_commands("11", new, IPConfig(dhcp=True, dns_auto=True))
    assert commands[0] == ["netsh", "interface", "ipv4", "set", "address", "name=11", "source=static",
                           "address=10.0.0.5", "mask=255.255.255.0", "gateway=none"]
    assert "address=1.1.1.1" in commands[1] and "register=primary" in commands[1]
    assert commands[2][:5] == ["netsh", "interface", "ipv4", "add", "dnsservers"] and "index=2" in commands[2]


def test_no_commands_when_unchanged():
    config = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", dns=["1.1.1.1"], mtu=1500)
    assert build_apply_commands("11", config, config) == []


def test_mtu_only_changed_when_requested():
    old = IPConfig(dhcp=True, dns_auto=True, mtu=1500)
    assert build_apply_commands("11", IPConfig(dhcp=True, dns_auto=True, mtu=None), old) == []
    commands = build_apply_commands("11", IPConfig(dhcp=True, dns_auto=True, mtu=1400), old)
    assert commands == [["netsh", "interface", "ipv4", "set", "subinterface", "interface=11", "mtu=1400",
                         "store=persistent"]]


def test_revert_restores_previous_settings():
    old = IPConfig(dhcp=True, dns_auto=True, mtu=1500)
    new = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", dns=["1.1.1.1"])
    revert = build_apply_commands("11", old, new)
    assert ["netsh", "interface", "ipv4", "set", "address", "name=11", "source=dhcp"] in revert
    assert ["netsh", "interface", "ipv4", "set", "dnsservers", "name=11", "source=dhcp"] in revert
    assert not any("subinterface" in command for command in revert)  # MTU wasn't touched going forward


def test_secondary_addresses_and_gateways():
    config, errors, warnings = validate(address="192.168.1.10/24", gateway="192.168.1.1 metric 10",
                                        secondary="192.168.1.11, 10.0.0.5 255.255.255.0; 172.16.0.1/32",
                                        extra_gateways="192.168.1.2 metric 20, 10.0.0.1")
    assert not errors and not warnings
    assert config.secondary == ["192.168.1.11/24", "10.0.0.5/24", "172.16.0.1/32"]
    assert (config.gateway, config.gateway_metric) == ("192.168.1.1", 10)
    assert config.extra_gateways == [{"gateway": "192.168.1.2", "metric": 20}, {"gateway": "10.0.0.1", "metric": None}]
    assert "192.168.1.11/24" in config.describe() and "192.168.1.2 metric 20" in config.describe()


@pytest.mark.parametrize("kwargs, field", [
    ({"secondary": "192.168.1.10"}, "secondary"),  # Same as the primary
    ({"secondary": "192.168.1.0/24"}, "secondary"),  # Network address
    ({"secondary": "banana"}, "secondary"),
    ({"extra_gateways": "192.168.1.1"}, "gateways"),  # Same as the default gateway
    ({"extra_gateways": "192.168.1.11", "secondary": "192.168.1.11"}, "gateways"),  # Own address
    ({"extra_gateways": "192.168.1.2 metric 0"}, "gateways"),
    ({"gateway": "192.168.1.1 metric x"}, "gateway"),
    ({"gateway": "", "extra_gateways": "192.168.1.2"}, "gateway"),  # Extras without a first gateway
])
def test_invalid_secondary_and_gateways(kwargs, field):
    _, errors, _ = validate(**{"address": "192.168.1.10/24", "gateway": "192.168.1.1", **kwargs})
    assert field in errors


def test_gateway_reachable_through_a_secondary_subnet():
    _, errors, warnings = validate(address="192.168.1.10/24", secondary="10.0.0.5/24", gateway="10.0.0.1")
    assert not errors and not warnings


def test_dhcp_to_static_with_extras():
    new = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1", gateway_metric=5,
                   secondary=["10.0.0.6/24"], extra_gateways=[{"gateway": "10.0.0.2", "metric": None}],
                   dns=["1.1.1.1"])
    commands = build_apply_commands("11", new, IPConfig(dhcp=True, dns_auto=True))
    assert commands[0][-2:] == ["gateway=10.0.0.1", "gwmetric=5"]
    assert ["netsh", "interface", "ipv4", "add", "address", "name=11", "address=10.0.0.6",
            "mask=255.255.255.0"] in commands
    assert ["netsh", "interface", "ipv4", "add", "address", "name=11", "gateway=10.0.0.2", "gwmetric=0"] in commands


def test_static_changes_add_before_removing():
    old = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1",
                   secondary=["10.0.0.6/24", "10.0.0.7/24"])
    new = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1",
                   secondary=["10.0.0.6/25", "10.0.0.8/24"], extra_gateways=[{"gateway": "10.0.0.2", "metric": 20}])
    commands = [" ".join(command[3:]) for command in build_apply_commands("11", new, old)]
    assert commands == ["delete address name=11 address=10.0.0.6",
                        "add address name=11 address=10.0.0.6 mask=255.255.255.128",
                        "add address name=11 address=10.0.0.8 mask=255.255.255.0",
                        "delete address name=11 address=10.0.0.7",
                        "add address name=11 gateway=10.0.0.2 gwmetric=20"]
    # Going back undoes it the same way, and the primary is never set over (which drops every connection)
    revert = [" ".join(command[3:]) for command in build_apply_commands("11", old, new)]
    assert "delete route prefix=0.0.0.0/0 interface=11 nexthop=10.0.0.2" in revert and not any("set address" in c for c in revert)


def test_new_primary_and_gateway_metric_change():
    old = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1")
    new = IPConfig(dhcp=False, address="10.0.0.9", netmask="255.255.255.0", gateway="10.0.0.1", gateway_metric=10)
    commands = [" ".join(command[3:]) for command in build_apply_commands("11", new, old)]
    assert commands == ["add address name=11 address=10.0.0.9 mask=255.255.255.0",
                        "delete address name=11 address=10.0.0.5",
                        "delete route prefix=0.0.0.0/0 interface=11 nexthop=10.0.0.1",
                        "add address name=11 gateway=10.0.0.1 gwmetric=10"]



def test_revert_after_a_part_way_apply():
    # The apply added the new gateway, then failed removing the old one: going back from how the adapter really is
    # removes the new gateway and leaves the old one alone (adding it again fails with "The object already exists")
    old = IPConfig(dhcp=False, address="10.10.117.3", netmask="255.255.255.0", gateway="10.10.117.1",
                   gateway_metric=1)
    part_way = IPConfig(dhcp=False, address="10.0.2.100", netmask="255.255.255.0", gateway="10.0.2.1",
                        extra_gateways=[{"gateway": "10.10.117.1", "metric": 1}])
    commands = [" ".join(command[3:]) for command in build_apply_commands("26", old, part_way)]
    assert commands == ["add address name=26 address=10.10.117.3 mask=255.255.255.0",
                        "delete address name=26 address=10.0.2.100",
                        "delete route prefix=0.0.0.0/0 interface=26 nexthop=10.0.2.1"]


def test_read_ip_config(monkeypatch):
    import ipaddress
    from nomad import snapshot
    from nomad.ipconfig import read_ip_config
    adapter = snapshot.Adapter(index="26", name="NIC 2", dhcp=False, ipv4=[ipaddress.ip_interface("10.0.2.100/24")],
                               gateways4=["10.0.2.1"])
    monkeypatch.setattr(snapshot, "load_snapshot", lambda: snapshot.NetworkSnapshot(adapters={"26": adapter}))
    assert (read_ip_config(26).address, read_ip_config(26).gateway) == ("10.0.2.100", "10.0.2.1")
    assert read_ip_config(17) is None

def test_primary_and_secondary_order_doesnt_matter():
    one = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", secondary=["10.0.0.6/24"],
                   gateway="10.0.0.1", extra_gateways=[{"gateway": "10.0.0.2", "metric": None}])
    two = IPConfig(dhcp=False, address="10.0.0.6", netmask="255.255.255.0", secondary=["10.0.0.5/24"],
                   gateway="10.0.0.2", extra_gateways=[{"gateway": "10.0.0.1", "metric": None}])
    assert build_apply_commands("11", one, two) == []


def test_static_to_dhcp_removes_extras_first():
    old = IPConfig(dhcp=False, address="10.0.0.5", netmask="255.255.255.0", gateway="10.0.0.1",
                   secondary=["10.0.0.6/24"], extra_gateways=[{"gateway": "10.0.0.2", "metric": None}])
    commands = [" ".join(command[3:]) for command in build_apply_commands("11", IPConfig(dhcp=True), old)]
    assert commands[:3] == ["delete route prefix=0.0.0.0/0 interface=11 nexthop=10.0.0.2",
                            "delete address name=11 address=10.0.0.6",
                            "set address name=11 source=dhcp"]


def test_config_from_adapter_reads_extras():
    import ipaddress
    from nomad.snapshot import Adapter
    adapter = Adapter(index="11", name="Ethernet", dhcp=False,
                      ipv4=[ipaddress.ip_interface("10.0.0.5/24"), ipaddress.ip_interface("169.254.1.1/16"),
                            ipaddress.ip_interface("10.0.0.6/24")],
                      gateways4=["10.0.0.1", "10.0.0.2"], gateway_metrics4={"10.0.0.1": 0, "10.0.0.2": 20})
    config = config_from_adapter(adapter)
    assert (config.address, config.secondary) == ("10.0.0.5", ["10.0.0.6/24"])
    assert (config.gateway, config.gateway_metric) == ("10.0.0.1", None)
    assert config.extra_gateways == [{"gateway": "10.0.0.2", "metric": 20}]
