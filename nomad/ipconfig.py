"""IPv4 adapter configuration: validating, applying and reverting settings, plus adapter actions."""
import ipaddress
import logging
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

from .system import CommandError, run_command, run_powershell

log = logging.getLogger(__name__)

MIN_MTU = 576
MAX_MTU = 9216


@dataclass
class IPConfig:
    """IPv4 settings for one adapter."""
    dhcp: bool
    address: str = ""
    netmask: str = ""
    gateway: str = ""
    dns: list = field(default_factory=list)
    dns_auto: bool = False  # Get DNS servers from DHCP (only with dhcp=True)
    mtu: Optional[int] = None  # None leaves the MTU alone

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        return cls(
            dhcp=bool(data.get("dhcp")),
            address=str(data.get("address") or ""),
            netmask=str(data.get("netmask") or ""),
            gateway=str(data.get("gateway") or ""),
            dns=[str(server) for server in data.get("dns") or []],
            dns_auto=bool(data.get("dns_auto")),
            mtu=int(data["mtu"]) if data.get("mtu") else None,
        )

    def same_address(self, other):
        if self.dhcp or other.dhcp:
            return self.dhcp == other.dhcp
        return (self.address, self.netmask, self.gateway) == (other.address, other.netmask, other.gateway)

    def same_dns(self, other):
        if self.dhcp and self.dns_auto:
            return other.dhcp and other.dns_auto
        return not (other.dhcp and other.dns_auto) and self.dns == other.dns

    def describe(self):
        parts = ["DHCP" if self.dhcp else f"{self.address} / {self.netmask}"]
        if not self.dhcp:
            parts.append(f"gateway {self.gateway or 'none'}")
        if self.dhcp and self.dns_auto:
            parts.append("DNS automatic")
        else:
            parts.append(f"DNS {', '.join(self.dns) if self.dns else 'none'}")
        if self.mtu:
            parts.append(f"MTU {self.mtu}")
        return ", ".join(parts)


def config_from_adapter(adapter):
    """The adapter's current IPv4 settings (MTU included), as an IPConfig."""
    address = adapter.ipv4[0] if adapter.ipv4 else None
    return IPConfig(
        dhcp=bool(adapter.dhcp),
        address=str(address.ip) if address else "",
        netmask=str(address.netmask) if address else "",
        gateway=adapter.gateways4[0] if adapter.gateways4 else "",
        dns=list(adapter.dns4),
        dns_auto=bool(adapter.dhcp) and not adapter.dns_static,
        mtu=adapter.mtu4,
    )


def validate_ipv4_address(text, field_label):
    try:
        return ipaddress.IPv4Address(text), None
    except ValueError:
        return None, f"{field_label}: '{text}' is not a valid IPv4 address."


def validate_ip_config(dhcp, address, netmask, gateway, primary_dns, backup_dns, dns_auto):
    """Check the adapter settings form.

    address may use CIDR notation (192.168.1.10/24), in which case netmask is ignored.
    Returns (IPConfig or None, errors, warnings). errors maps a form field name to a message.
    """
    address, netmask, gateway, primary_dns, backup_dns = (
        value.strip() for value in (address, netmask, gateway, primary_dns, backup_dns))
    errors, warnings = {}, []
    config = IPConfig(dhcp=dhcp, dns_auto=dhcp and dns_auto)

    if not dhcp:
        interface = None
        if not address:
            errors["address"] = "IP address is required for a static configuration."
        elif "/" in address:
            try:
                interface = ipaddress.IPv4Interface(address)
            except ValueError:
                errors["address"] = f"'{address}' is not a valid IPv4 address with prefix length."
        else:
            ip, error = validate_ipv4_address(address, "IP address")
            if error:
                errors["address"] = error
            elif not netmask:
                errors["netmask"] = "Subnet mask is required (or use CIDR notation like 192.168.1.10/24)."
            else:
                try:
                    mask_network = ipaddress.IPv4Network(f"0.0.0.0/{netmask}")
                    if not netmask.isdigit() and mask_network.netmask != ipaddress.IPv4Address(netmask):
                        raise ValueError
                    interface = ipaddress.IPv4Interface(f"{ip}/{mask_network.prefixlen}")
                except ValueError:
                    errors["netmask"] = f"'{netmask}' is not a valid subnet mask."

        if interface is not None:
            ip, network = interface.ip, interface.network
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
                errors["address"] = f"{ip} can't be assigned to an adapter."
            elif network.prefixlen < 31 and ip in (network.network_address, network.broadcast_address):
                kind = "network" if ip == network.network_address else "broadcast"
                errors["address"] = f"{ip} is the {kind} address of {network}; pick an address inside it."
            elif network.prefixlen == 32:
                errors["netmask"] = "A /32 mask leaves no room for a gateway or other hosts."
            config.address, config.netmask = str(ip), str(interface.netmask)

        if gateway:
            gateway_ip, error = validate_ipv4_address(gateway, "Gateway")
            if error:
                errors["gateway"] = error
            elif interface is not None:
                if gateway_ip == interface.ip:
                    errors["gateway"] = "The gateway can't be the adapter's own address."
                elif gateway_ip not in interface.network:
                    warnings.append(f"Gateway {gateway_ip} is outside {interface.network}; "
                                    "it probably won't be reachable.")
            config.gateway = gateway

    if not config.dns_auto:
        if backup_dns and not primary_dns:
            errors["primary_dns"] = "Enter a primary DNS server before the backup one."
        for field_name, value, label in (("primary_dns", primary_dns, "Primary DNS"),
                                         ("backup_dns", backup_dns, "Backup DNS")):
            if value:
                _, error = validate_ipv4_address(value, label)
                if error:
                    errors[field_name] = error
                else:
                    config.dns.append(value)

    return (None if errors else config), errors, warnings


def validate_mtu(text):
    """Returns (mtu, error)."""
    text = text.strip()
    if not text.isdigit() or not MIN_MTU <= int(text) <= MAX_MTU:
        return None, f"MTU must be a number from {MIN_MTU} to {MAX_MTU}."
    return int(text), None


def build_apply_commands(index, new, old=None):
    """netsh commands that change an adapter from old (None = unknown) to new, skipping unchanged parts."""
    name = f"name={index}"
    commands = []

    if old is None or not new.same_address(old):
        if new.dhcp:
            if old is None or not old.dhcp:  # netsh fails if DHCP is already on
                commands.append(["netsh", "interface", "ipv4", "set", "address", name, "source=dhcp"])
        else:
            commands.append(["netsh", "interface", "ipv4", "set", "address", name, "source=static",
                             f"address={new.address}", f"mask={new.netmask}", f"gateway={new.gateway or 'none'}"])

    if old is None or not new.same_dns(old):
        if new.dhcp and new.dns_auto:
            commands.append(["netsh", "interface", "ipv4", "set", "dnsservers", name, "source=dhcp"])
        elif not new.dns:
            commands.append(["netsh", "interface", "ipv4", "set", "dnsservers", name, "source=static",
                             "address=none", "validate=no"])
        else:
            commands.append(["netsh", "interface", "ipv4", "set", "dnsservers", name, "source=static",
                             f"address={new.dns[0]}", "register=primary", "validate=no"])
            for position, server in enumerate(new.dns[1:], start=2):
                commands.append(["netsh", "interface", "ipv4", "add", "dnsservers", name, f"address={server}",
                                 f"index={position}", "validate=no"])

    if new.mtu is not None and (old is None or old.mtu is not None) and new.mtu != (old.mtu if old else None):
        commands.append(build_mtu_command(index, new.mtu))

    return commands


class ApplyError(CommandError):
    """Applying settings failed part-way. applied_steps says how many commands succeeded first."""

    def __init__(self, error, applied_steps):
        super().__init__(error.command, error.output)
        self.applied_steps = applied_steps


def apply_ip_config(index, new, old=None):
    """Apply new settings to an adapter. Raises ApplyError if a step fails."""
    commands = build_apply_commands(index, new, old)
    log.info("Applying to interface %s: %s", index, new.describe())
    for step, command in enumerate(commands):
        try:
            run_command(command)
        except CommandError as error:
            raise ApplyError(error, step) from None
    return len(commands)


def build_mtu_command(index, mtu):
    return ["netsh", "interface", "ipv4", "set", "subinterface", f"interface={index}", f"mtu={mtu}",
            "store=persistent"]


def set_mtu(index, mtu):
    run_command(build_mtu_command(index, mtu))


def set_adapter_enabled(index, enabled):
    verb = "Enable" if enabled else "Disable"
    run_powershell(f"Get-NetAdapter -InterfaceIndex {int(index)} | {verb}-NetAdapter -Confirm:$false")


def reset_adapter(index):
    """Disable and re-enable an adapter, which clears most stuck-connection problems."""
    set_adapter_enabled(index, False)
    time.sleep(3)
    set_adapter_enabled(index, True)


def release_dhcp(name):
    run_command(["ipconfig", "/release", name])


def renew_dhcp(name):
    run_command(["ipconfig", "/renew", name], timeout=180)


def flush_dns():
    run_command(["ipconfig", "/flushdns"])
