"""A point-in-time view of the machine's adapters, addresses, DNS servers and routes.

Everything is read with one PowerShell call that queries CIM directly. The data comes back as
JSON, so parsing doesn't depend on the Windows display language.
"""
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Optional

from .system import run_powershell_json

log = logging.getLogger(__name__)

CIM_AF_INET = 2
CIM_AF_INET6 = 23
CIM_FAMILIES = {CIM_AF_INET: 4, CIM_AF_INET6: 6}

# Networks whose routes Windows creates and manages on its own
SYSTEM_ROUTE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),  # Loopback
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("ff00::/8"),  # IPv6 multicast
]

# Querying CIM directly avoids loading the NetAdapter/NetTCPIP/DnsClient modules, which takes
# several seconds in a fresh PowerShell process. Get-Instances returns the chosen properties of every
# instance of a class, optionally from a policy store such as 'PersistentStore'.
CIM_FUNCTIONS = r"""
$namespace = 'root/StandardCimv2'
$session = New-CimSession
function Get-Instances($class, $properties, $store) {
    $options = New-Object Microsoft.Management.Infrastructure.Options.CimOperationOptions
    if ($store) { $options.SetCustomOption('PolicyStore', $store, $false) }
    foreach ($instance in $session.EnumerateInstances($namespace, $class, $options)) {
        $row = [ordered]@{}
        foreach ($name in $properties) { $row[$name] = $instance.CimInstanceProperties[$name].Value }
        $row
    }
}
"""

SNAPSHOT_SCRIPT = CIM_FUNCTIONS + r"""
$routeProperties = 'InterfaceIndex', 'DestinationPrefix', 'NextHop', 'RouteMetric', 'AddressFamily'
$snapshot = [ordered]@{
    adapters = @(Get-Instances 'MSFT_NetAdapter' @('InterfaceIndex', 'Name', 'InterfaceDescription',
        'InterfaceOperationalStatus', 'MediaConnectState', 'InterfaceAdminStatus', 'PermanentAddress', 'Speed',
        'InterfaceGuid', 'Hidden'))
    ipInterfaces = @(Get-Instances 'MSFT_NetIPInterface' @('InterfaceIndex', 'InterfaceAlias', 'AddressFamily',
        'Dhcp', 'NlMtu', 'InterfaceMetric', 'ConnectionState'))
    addresses = @(Get-Instances 'MSFT_NetIPAddress' @('InterfaceIndex', 'IPAddress', 'PrefixLength',
        'AddressFamily', 'PrefixOrigin'))
    dns = @(Get-Instances 'MSFT_DNSClientServerAddress' @('InterfaceIndex', 'AddressFamily', 'ServerAddresses'))
    routes = @(Get-Instances 'MSFT_NetRoute' $routeProperties 'ActiveStore')
    persistentRoutes = @(Get-Instances 'MSFT_NetRoute' $routeProperties 'PersistentStore')
}
$snapshot | ConvertTo-Json -Depth 4 -Compress
"""

# MSFT_NetAdapter InterfaceAdminStatus / InterfaceOperationalStatus / MediaConnectState values
ADMIN_DOWN = 2
OPERATIONAL_UP = 1
MEDIA_DISCONNECTED = 2


@dataclass
class Adapter:
    """A network interface: a real adapter, or a pseudo-interface such as loopback."""
    index: str
    name: str
    description: str = ""
    status: str = "Unknown"  # Up, Disconnected, Disabled, Down or Unknown
    mac: str = ""
    speed_bps: Optional[int] = None
    guid: str = ""
    is_adapter: bool = False  # True for real adapters (listed by Get-NetAdapter)
    families: set = field(default_factory=set)  # IP versions enabled on the interface
    connected: bool = False
    dhcp: Optional[bool] = None  # IPv4 DHCP
    mtu4: Optional[int] = None
    mtu6: Optional[int] = None
    metric4: Optional[int] = None
    metric6: Optional[int] = None
    ipv4: list = field(default_factory=list)  # ipaddress.IPv4Interface
    ipv6: list = field(default_factory=list)  # ipaddress.IPv6Interface
    gateways4: list = field(default_factory=list)
    gateways6: list = field(default_factory=list)
    dns4: list = field(default_factory=list)
    dns6: list = field(default_factory=list)
    dns_static: Optional[bool] = None  # True if IPv4 DNS servers were entered manually

    @property
    def enabled(self):
        return self.status != "Disabled"

    @property
    def speed_text(self):
        if not self.speed_bps:
            return ""
        for divisor, unit in ((10 ** 9, "Gbps"), (10 ** 6, "Mbps"), (10 ** 3, "Kbps")):
            if self.speed_bps >= divisor:
                value = self.speed_bps / divisor
                return f"{value:g} {unit}" if value == int(value) else f"{value:.1f} {unit}"
        return f"{self.speed_bps} bps"

    @property
    def awaiting_dhcp(self):
        """Connected and using DHCP, but with no leased IPv4 address yet (only 169.254.x.x or nothing)."""
        return (self.status == "Up" and bool(self.dhcp)
                and not any(not address.ip.is_link_local for address in self.ipv4))

    def metric(self, family):
        return self.metric4 if family == 4 else self.metric6

    def label(self, family=4):
        if family == 4 and self.ipv4:
            return f"{self.name} ({', '.join(str(address.ip) for address in self.ipv4)})"
        return f"{self.name} (index {self.index})"

    def picker_label(self):
        """Label for the app-wide adapter picker."""
        details = [self.status]
        if self.ipv4:
            details.append(str(self.ipv4[0].ip))
        if self.speed_text and self.status == "Up":
            details.append(self.speed_text)
        return f"{self.name}  —  {', '.join(details)}"


@dataclass
class Route:
    """A single entry from the routing table."""
    family: int  # 4 or 6
    network: object  # ipaddress.IPv4Network / IPv6Network
    gateway: str  # IP address, or "On-link"
    interface: str  # Interface index
    route_metric: Optional[int] = None
    interface_metric: Optional[int] = None
    persistent: bool = False
    active: bool = True

    @property
    def metric(self):
        """Effective metric (route + interface), as 'route print' shows it."""
        if self.route_metric is None:
            return None
        return self.route_metric + (self.interface_metric or 0)

    @property
    def on_link(self):
        return self.gateway.lower() in ("on-link", "0.0.0.0", "::", "")

    @property
    def next_hop(self):
        """Gateway as the routing APIs expect it (unspecified address for on-link routes)."""
        if self.on_link:
            return "0.0.0.0" if self.family == 4 else "::"
        return self.gateway

    @property
    def match_key(self):
        """Identifies a route across the active and persistent stores."""
        return self.family, str(self.network), "on-link" if self.on_link else self.gateway.lower(), self.interface

    @property
    def is_default(self):
        return self.network.prefixlen == 0

    @property
    def is_system(self):
        """Loopback, multicast, broadcast and host routes that Windows manages automatically."""
        if self.is_default:
            return False
        if self.network.prefixlen == self.network.max_prefixlen:
            return True
        return any(self.network.version == system.version and self.network.subnet_of(system)
                   for system in SYSTEM_ROUTE_NETWORKS)


@dataclass
class NetworkSnapshot:
    adapters: dict = field(default_factory=dict)  # {index: Adapter}
    routes: list = field(default_factory=list)

    def real_adapters(self):
        return sorted((adapter for adapter in self.adapters.values() if adapter.is_adapter),
                      key=lambda adapter: (adapter.status != "Up", adapter.name.lower()))

    def adapter_by_name(self, name):
        return next((adapter for adapter in self.adapters.values() if adapter.name == name), None)


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _format_mac(value):
    value = (value or "").replace("-", "").replace(":", "")
    if len(value) != 12:
        return value
    return "-".join(value[i:i + 2] for i in range(0, 12, 2)).upper()


def _adapter_status(row):
    if row.get("InterfaceAdminStatus") == ADMIN_DOWN:
        return "Disabled"
    if row.get("InterfaceOperationalStatus") == OPERATIONAL_UP:
        return "Up"
    if row.get("MediaConnectState") == MEDIA_DISCONNECTED:
        return "Disconnected"
    return "Down"


def _parse_route(row, persistent):
    family = CIM_FAMILIES.get(row.get("AddressFamily"))
    try:
        network = ipaddress.ip_network(row["DestinationPrefix"], strict=False)
    except (KeyError, TypeError, ValueError):
        return None
    if family is None:
        family = network.version
    next_hop = row.get("NextHop") or ""
    gateway = "On-link" if next_hop in ("", "0.0.0.0", "::") else next_hop
    return Route(family, network, gateway, str(row.get("InterfaceIndex")), row.get("RouteMetric"),
                 persistent=persistent, active=not persistent)


def parse_snapshot(data, dns_is_static=None):
    """Build a NetworkSnapshot from the JSON written by SNAPSHOT_SCRIPT.

    dns_is_static(guid) optionally reports whether an adapter's DNS servers were set manually.
    """
    data = data or {}
    adapters = {}

    def get_adapter(index, name=""):
        index = str(index)
        if index not in adapters:
            adapters[index] = Adapter(index=index, name=name or f"Interface {index}")
        return adapters[index]

    for row in _as_list(data.get("adapters")):
        if row.get("Hidden"):
            continue
        adapter = get_adapter(row.get("InterfaceIndex"), row.get("Name") or "")
        adapter.name = row.get("Name") or adapter.name
        adapter.description = row.get("InterfaceDescription") or ""
        adapter.status = _adapter_status(row)
        adapter.mac = _format_mac(row.get("PermanentAddress"))
        adapter.speed_bps = row.get("Speed") or None
        adapter.guid = row.get("InterfaceGuid") or ""
        adapter.is_adapter = True

    for row in _as_list(data.get("ipInterfaces")):
        family = CIM_FAMILIES.get(row.get("AddressFamily"))
        if family is None:
            continue
        adapter = get_adapter(row.get("InterfaceIndex"), row.get("InterfaceAlias") or "")
        adapter.families.add(family)
        adapter.connected = adapter.connected or row.get("ConnectionState") == 1
        mtu = row.get("NlMtu")
        if family == 4:
            adapter.dhcp = row.get("Dhcp") == 1
            adapter.mtu4, adapter.metric4 = mtu, row.get("InterfaceMetric")
        else:
            adapter.mtu6, adapter.metric6 = mtu, row.get("InterfaceMetric")
        if not adapter.is_adapter:
            adapter.status = "Up" if adapter.connected else "Down"

    for row in _as_list(data.get("addresses")):
        index = str(row.get("InterfaceIndex"))
        if index not in adapters:
            continue
        address = (row.get("IPAddress") or "").partition("%")[0]
        try:
            interface = ipaddress.ip_interface(f"{address}/{row.get('PrefixLength')}")
        except ValueError:
            continue
        target = adapters[index].ipv4 if interface.version == 4 else adapters[index].ipv6
        target.append(interface)

    for row in _as_list(data.get("dns")):
        index = str(row.get("InterfaceIndex"))
        if index not in adapters:
            continue
        servers = [server for server in _as_list(row.get("ServerAddresses")) if server]
        if row.get("AddressFamily") == CIM_AF_INET:
            adapters[index].dns4 = servers
        elif row.get("AddressFamily") == CIM_AF_INET6:
            adapters[index].dns6 = servers

    active = [route for route in (_parse_route(row, False) for row in _as_list(data.get("routes"))) if route]
    persistent = [route for route in (_parse_route(row, True) for row in _as_list(data.get("persistentRoutes")))
                  if route]

    active_keys = {}
    for route in active:
        active_keys.setdefault(route.match_key, []).append(route)
    routes = list(active)
    for saved in persistent:
        matches = active_keys.get(saved.match_key)
        if matches:
            for route in matches:
                route.persistent = True
        else:
            routes.append(saved)  # Persistent route that isn't currently active

    for route in routes:
        adapter = adapters.get(route.interface)
        if adapter is None:
            continue
        route.interface_metric = adapter.metric(route.family)
        if route.is_default and route.active and not route.on_link:
            gateways = adapter.gateways4 if route.family == 4 else adapter.gateways6
            if route.gateway not in gateways:
                gateways.append(route.gateway)

    if dns_is_static:
        for adapter in adapters.values():
            if adapter.guid:
                adapter.dns_static = dns_is_static(adapter.guid)

    return NetworkSnapshot(adapters, routes)


def dns_is_static(guid):
    """Whether an adapter's IPv4 DNS servers were entered manually (rather than from DHCP)."""
    import winreg
    key_path = rf"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{guid}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "NameServer")
    except OSError:
        return False
    return bool(str(value).strip())


def load_snapshot():
    """Read the current network configuration. Slow (about a second); call it off the UI thread."""
    data = run_powershell_json(SNAPSHOT_SCRIPT)
    snapshot = parse_snapshot(data, dns_is_static)
    log.debug("Loaded snapshot: %d interfaces, %d routes", len(snapshot.adapters), len(snapshot.routes))
    return snapshot
