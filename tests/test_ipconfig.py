import pytest

from nomad.ipconfig import IPConfig, build_apply_commands, validate_ip_config, validate_mtu


def validate(dhcp=False, address="", netmask="", gateway="", primary="", backup="", dns_auto=False):
    return validate_ip_config(dhcp, address, netmask, gateway, primary, backup, dns_auto)


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
