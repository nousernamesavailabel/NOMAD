"""IPv4 adapter configuration: validating, applying and reverting settings, plus adapter actions."""
import ipaddress
import logging
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

from .system import CommandError, run_command, run_powershell

log = logging.getLogger(__name__)

MIN_MTU = 576
MAX_MTU = 9216
MAX_GATEWAY_METRIC = 9999

ENTRY_SEPARATORS = re.compile(r"[,;\n]+")


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
    gateway_metric: Optional[int] = None  # None = automatic
    secondary: list = field(default_factory=list)  # More static addresses, as "10.0.0.6/24"
    extra_gateways: list = field(default_factory=list)  # More default gateways: {"gateway": ip, "metric": int|None}

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
            gateway_metric=int(data["gateway_metric"]) if data.get("gateway_metric") else None,
            secondary=[str(address) for address in data.get("secondary") or []],
            extra_gateways=[{"gateway": str(entry.get("gateway") or ""),
                             "metric": int(entry["metric"]) if entry.get("metric") else None}
                            for entry in data.get("extra_gateways") or [] if isinstance(entry, dict)],
        )

    def addresses(self):
        """Every static address (primary first) as IPv4Interfaces."""
        if self.dhcp or not self.address:
            return []
        return [ipaddress.IPv4Interface(f"{self.address}/{self.netmask}"),
                *(ipaddress.IPv4Interface(address) for address in self.secondary)]

    def gateways(self):
        """Every default gateway (first one first) as (ip, metric) pairs; metric 0 = automatic."""
        if self.dhcp or not self.gateway:
            return []
        return [(self.gateway, self.gateway_metric or 0),
                *((entry["gateway"], entry["metric"] or 0) for entry in self.extra_gateways)]

    def same_address(self, other):
        if self.dhcp or other.dhcp:
            return self.dhcp == other.dhcp
        return (set(self.addresses()) == set(other.addresses())
                and dict(self.gateways()) == dict(other.gateways()))

    def same_dns(self, other):
        if self.dhcp and self.dns_auto:
            return other.dhcp and other.dns_auto
        return not (other.dhcp and other.dns_auto) and self.dns == other.dns

    def describe(self):
        parts = ["DHCP" if self.dhcp else f"{self.address} / {self.netmask}"]
        if not self.dhcp:
            if self.secondary:
                parts[0] += " + " + " + ".join(self.secondary)
            gateways = [format_gateway(gateway, metric) for gateway, metric in self.gateways()]
            parts.append(f"gateway{'s' if len(gateways) > 1 else ''} {', '.join(gateways) or 'none'}")
        if self.dhcp and self.dns_auto:
            parts.append("DNS automatic")
        else:
            parts.append(f"DNS {', '.join(self.dns) if self.dns else 'none'}")
        if self.mtu:
            parts.append(f"MTU {self.mtu}")
        return ", ".join(parts)


def format_gateway(gateway, metric=None):
    return f"{gateway} metric {metric}" if metric else gateway


def config_from_adapter(adapter):
    """The adapter's current IPv4 settings (MTU included), as an IPConfig."""
    routable = [address for address in adapter.ipv4 if not address.ip.is_link_local]
    address = (routable or adapter.ipv4 or [None])[0]
    metrics = getattr(adapter, "gateway_metrics4", {})
    gateways = [(gateway, metrics.get(gateway) or None) for gateway in adapter.gateways4]
    static = not adapter.dhcp
    return IPConfig(
        dhcp=bool(adapter.dhcp),
        address=str(address.ip) if address else "",
        netmask=str(address.netmask) if address else "",
        gateway=gateways[0][0] if gateways else "",
        dns=list(adapter.dns4),
        dns_auto=bool(adapter.dhcp) and not adapter.dns_static,
        mtu=adapter.mtu4,
        gateway_metric=gateways[0][1] if gateways and static else None,
        secondary=[str(other) for other in routable if other is not address] if static else [],
        extra_gateways=[{"gateway": gateway, "metric": metric} for gateway, metric in gateways[1:]] if static else [],
    )


def validate_ipv4_address(text, field_label):
    try:
        return ipaddress.IPv4Address(text), None
    except ValueError:
        return None, f"{field_label}: '{text}' is not a valid IPv4 address."


def split_entries(text):
    """The entries of a comma, semicolon or line separated field."""
    return [entry.strip() for entry in ENTRY_SEPARATORS.split(text) if entry.strip()]


def parse_gateway(text, field_label):
    """'10.0.0.1', '10.0.0.1 metric 20' or '10.0.0.1 20'. Returns (ip, metric or None, error)."""
    words = text.split()
    if len(words) == 3 and words[1].lower() == "metric":
        words = [words[0], words[2]]
    gateway_ip, error = validate_ipv4_address(words[0], field_label)
    if error:
        return None, None, error
    if len(words) > 2:
        return None, None, f"{field_label}: write '{words[0]}' or '{words[0]} metric 20'."
    metric = None
    if len(words) == 2:
        if not words[1].isdigit() or not 1 <= int(words[1]) <= MAX_GATEWAY_METRIC:
            return None, None, f"{field_label}: the metric must be a number from 1 to {MAX_GATEWAY_METRIC}."
        metric = int(words[1])
    return gateway_ip, metric, None


def address_problem(ip, network):
    """Why ip can't be an adapter address on network, or None."""
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
        return f"{ip} can't be assigned to an adapter."
    if network.prefixlen < 31 and ip in (network.network_address, network.broadcast_address):
        kind = "network" if ip == network.network_address else "broadcast"
        return f"{ip} is the {kind} address of {network}; pick an address inside it."
    return None


def parse_secondary(text, primary):
    """One secondary address: '10.0.0.6/24', '10.0.0.6 255.255.255.0', or a bare address that takes the primary's
    mask. Returns (IPv4Interface, error)."""
    words = text.split()
    try:
        if len(words) == 2:
            mask_network = ipaddress.IPv4Network(f"0.0.0.0/{words[1]}")
            return ipaddress.IPv4Interface(f"{ipaddress.IPv4Address(words[0])}/{mask_network.prefixlen}"), None
        if "/" in text:
            return ipaddress.IPv4Interface(text), None
        if primary is not None:
            return ipaddress.IPv4Interface(f"{ipaddress.IPv4Address(text)}/{primary.network.prefixlen}"), None
        ipaddress.IPv4Address(text)
        return None, f"Secondary IPs: give {text} a mask (e.g. {text}/24)."
    except ValueError:
        return None, f"Secondary IPs: '{text}' is not an address like 192.168.1.11/24."


def validate_ip_config(dhcp, address, netmask, gateway, primary_dns, backup_dns, dns_auto, secondary="",
                       extra_gateways=""):
    """Check the adapter settings form.

    address may use CIDR notation (192.168.1.10/24), in which case netmask is ignored. gateway may carry a metric
    ('10.0.0.1 metric 20'). secondary and extra_gateways list more addresses and gateways, separated by commas.
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
            problem = address_problem(ip, network)
            if problem:
                errors["address"] = problem
            elif network.prefixlen == 32:
                errors["netmask"] = "A /32 mask leaves no room for a gateway or other hosts."
            config.address, config.netmask = str(ip), str(interface.netmask)

        # Secondary addresses may be /32s; only the primary needs room for a gateway
        interfaces = [interface] if interface is not None else []
        for entry in split_entries(secondary):
            other, error = parse_secondary(entry, interface)
            error = error or address_problem(other.ip, other.network)
            if not error and any(other.ip == known.ip for known in interfaces):
                error = f"Secondary IPs: {other.ip} is listed twice."
            if error:
                errors.setdefault("secondary", error)
                continue
            interfaces.append(other)
            config.secondary.append(str(other))

        own_addresses = {known.ip for known in interfaces}
        seen = set()
        for field_name, label, entries in (("gateway", "Gateway", [gateway] if gateway else []),
                                           ("gateways", "More gateways", split_entries(extra_gateways))):
            for entry in entries:
                gateway_ip, metric, error = parse_gateway(entry, label)
                if not error and gateway_ip in own_addresses:
                    error = f"{label}: {gateway_ip} is the adapter's own address."
                if not error and gateway_ip in seen:
                    error = f"{label}: {gateway_ip} is listed twice."
                if error:
                    errors.setdefault(field_name, error)
                    continue
                seen.add(gateway_ip)
                if interfaces and not any(gateway_ip in known.network for known in interfaces):
                    subnets = ", ".join(dict.fromkeys(str(known.network) for known in interfaces))
                    warnings.append(f"Gateway {gateway_ip} is outside {subnets}; it probably won't be reachable.")
                if field_name == "gateway":
                    config.gateway, config.gateway_metric = str(gateway_ip), metric
                else:
                    config.extra_gateways.append({"gateway": str(gateway_ip), "metric": metric})
        if config.extra_gateways and not gateway:
            errors.setdefault("gateway", "Put the first gateway in Default gateway; More gateways adds others.")

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
            if old is not None and not old.dhcp:
                # Take the extras off first: static gateways can outlive the switch to DHCP
                commands += [delete_gateway_command(name, gateway) for gateway, _ in old.gateways()[1:]]
                commands += [delete_address_command(name, address) for address in old.addresses()[1:]]
            if old is None or not old.dhcp:  # netsh fails if DHCP is already on
                commands.append(["netsh", "interface", "ipv4", "set", "address", name, "source=dhcp"])
        elif old is None or old.dhcp:
            gateway = [f"gateway={new.gateway}"] if new.gateway else ["gateway=none"]
            if new.gateway and new.gateway_metric:
                gateway.append(f"gwmetric={new.gateway_metric}")
            commands.append(["netsh", "interface", "ipv4", "set", "address", name, "source=static",
                             f"address={new.address}", f"mask={new.netmask}", *gateway])
            commands += [add_address_command(name, address) for address in new.addresses()[1:]]
            commands += [add_gateway_command(name, gateway, metric) for gateway, metric in new.gateways()[1:]]
        else:
            commands += static_change_commands(name, new, old)

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


def add_address_command(name, address):
    return ["netsh", "interface", "ipv4", "add", "address", name, f"address={address.ip}", f"mask={address.netmask}"]


def delete_address_command(name, address):
    return ["netsh", "interface", "ipv4", "delete", "address", name, f"address={address.ip}"]


def add_gateway_command(name, gateway, metric):
    return ["netsh", "interface", "ipv4", "add", "address", name, f"gateway={gateway}", f"gwmetric={metric or 0}"]


def delete_gateway_command(name, gateway):
    return ["netsh", "interface", "ipv4", "delete", "address", name, f"gateway={gateway}"]


def static_change_commands(name, new, old):
    """Turn one static setup into another an address and a gateway at a time, adding before removing, so adding a
    secondary IP or a gateway doesn't drop the connections already using the adapter."""
    old_addresses = {address.ip: address for address in old.addresses()}
    new_addresses = {address.ip: address for address in new.addresses()}
    remasked = [ip for ip, address in new_addresses.items() if old_addresses.get(ip, address) != address]
    commands = [delete_address_command(name, old_addresses[ip]) for ip in remasked]  # Must go before coming back
    commands += [add_address_command(name, address) for ip, address in new_addresses.items()
                 if ip not in old_addresses or ip in remasked]
    commands += [delete_address_command(name, address) for ip, address in old_addresses.items()
                 if ip not in new_addresses]

    old_gateways, new_gateways = dict(old.gateways()), dict(new.gateways())
    remetric = [gateway for gateway, metric in new_gateways.items() if old_gateways.get(gateway, metric) != metric]
    commands += [delete_gateway_command(name, gateway) for gateway in remetric]
    commands += [add_gateway_command(name, gateway, metric) for gateway, metric in new_gateways.items()
                 if gateway not in old_gateways or gateway in remetric]
    commands += [delete_gateway_command(name, gateway) for gateway in old_gateways if gateway not in new_gateways]
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
