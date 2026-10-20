"""Validating, adding and deleting routes."""
import ipaddress

from .system import ps_quote, run_powershell


def _parse_destination(family, destination, netmask):
    """Parse the route form's destination/netmask. Returns (network, error field, error message)."""
    if "/" in destination:
        spec = destination
    elif family == 6:
        return None, "destination", "Enter an IPv6 prefix with its length, e.g. 2001:db8::/32."
    else:
        try:
            ipaddress.IPv4Address(destination)
        except ValueError:
            return None, "destination", f"'{destination}' is not a valid IPv4 address."
        if not netmask:
            return None, "netmask", "Netmask is required (or use CIDR notation like 10.0.0.0/24)."
        try:
            mask_network = ipaddress.IPv4Network(f"0.0.0.0/{netmask}")
            # ipaddress also accepts host masks like 0.0.0.255, which Windows does not
            if not netmask.isdigit() and mask_network.netmask != ipaddress.IPv4Address(netmask):
                raise ValueError
        except ValueError:
            return None, "netmask", f"'{netmask}' is not a valid netmask."
        spec = f"{destination}/{netmask}"

    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError:
        return None, "destination", f"'{destination}' is not a valid IPv{family} network."
    if network.version != family:
        return None, "destination", f"'{destination}' is not an IPv{family} network."
    if ipaddress.ip_address(spec.split("/")[0]) != network.network_address:
        return None, "destination", f"Host bits are set for this mask; did you mean {network.network_address}?"
    return network, None, None


def find_interface_for_gateway(gateway, adapters):
    """Pick the interface whose IPv4 subnet contains the gateway, like route.exe does."""
    gateway_ip = ipaddress.ip_address(gateway)
    for adapter in adapters.values():
        if any(gateway_ip in address.network for address in adapter.ipv4):
            return adapter.index
    return None


def connected_network_warning(network, adapters):
    """A warning when this computer already has an address in network, so it reaches it without a route.

    A route to a network bigger than the connected one (a summary like 10.0.0.0/8) is fine and isn't warned about.
    """
    for adapter in adapters.values():
        if not adapter.connected:
            continue
        for address in adapter.ipv4 if network.version == 4 else adapter.ipv6:
            if address.ip.is_loopback or address.ip.is_link_local:
                continue
            if network.subnet_of(address.network):
                return (f"This computer is already on {address.network} ({adapter.name}, {address.ip}), so it "
                        f"reaches {network} directly without a route.")
    return None


def gateway_suggestions(family, adapters, routes):
    """Next hops this computer already uses, for the route form's gateway list: [(gateway, interface, label)].

    Connected interfaces' default gateways come first, then the gateways other active routes go through.
    """
    suggestions, seen = [], set()
    for adapter in sorted(adapters.values(), key=lambda adapter: adapter.name.lower()):
        if not adapter.connected:
            continue
        for gateway in adapter.gateways4 if family == 4 else adapter.gateways6:
            key = (gateway.lower(), adapter.index)
            if key not in seen:
                seen.add(key)
                suggestions.append((gateway, adapter.index, f"{gateway}  ·  default gateway on {adapter.name}"))
    used = {}
    for route in routes:
        if route.family != family or route.on_link or not route.active or route.is_default:
            continue
        key = (route.gateway.lower(), route.interface)
        if key not in seen:
            used.setdefault(key, [route.gateway, route.interface, 0])[2] += 1
    for gateway, interface, count in sorted(used.values(), key=lambda entry: ipaddress.ip_address(entry[0])):
        adapter = adapters.get(interface)
        where = f" on {adapter.name}" if adapter is not None else ""
        suggestions.append((gateway, interface, f"{gateway}  ·  next hop of {count} route{'s' if count > 1 else ''}"
                                                f"{where}"))
    return suggestions


def validate_route_input(family, destination, netmask, gateway, metric, interface, adapters):
    """Check the add/edit route form.

    interface is an interface index, or None for automatic.
    Returns (route_spec, errors, warnings). errors maps a form field name to a message.
    route_spec is a dict with network, gateway, interface and metric when there are no errors.
    """
    destination, netmask, gateway, metric = (value.strip() for value in (destination, netmask, gateway, metric))
    errors, warnings = {}, []
    network = None

    if not destination:
        errors["destination"] = "Network destination is required."
    else:
        network, error_field, message = _parse_destination(family, destination, netmask)
        if error_field:
            errors[error_field] = message

    gateway_ip = None
    if gateway:
        try:
            gateway_ip = ipaddress.ip_address(gateway)
            if gateway_ip.version != family:
                raise ValueError
        except ValueError:
            errors["gateway"] = f"'{gateway}' is not a valid IPv{family} address."
            gateway_ip = None
    if gateway_ip is not None and gateway_ip.is_unspecified:
        gateway_ip = None  # 0.0.0.0 / :: means on-link

    if interface is None:
        if gateway_ip is None:
            if "gateway" not in errors:
                errors["interface"] = "Choose an interface for an on-link route (one with no gateway)."
        elif family == 6:
            errors["interface"] = "Choose an interface for IPv6 routes."
        else:
            interface = find_interface_for_gateway(str(gateway_ip), adapters)
            if interface is None:
                errors["gateway"] = f"Gateway {gateway_ip} isn't in any local subnet, so pick an interface for it."
    elif family == 4 and gateway_ip is not None and interface in adapters:
        adapter = adapters[interface]
        if adapter.ipv4 and not any(gateway_ip in address.network for address in adapter.ipv4):
            warnings.append(f"Gateway {gateway_ip} isn't in {adapter.name}'s subnet; Windows may reject it.")

    if metric:
        if not metric.isdigit() or not 1 <= int(metric) <= 9999:
            errors["metric"] = "Metric must be a number from 1 to 9999."

    if network is not None and gateway_ip is not None:  # An on-link route to it is just the connected route
        connected = connected_network_warning(network, adapters)
        if connected:
            warnings.append(connected)

    if errors:
        return None, errors, warnings
    return {
        "network": network,
        "gateway": str(gateway_ip) if gateway_ip is not None else "",
        "interface": interface,
        "metric": int(metric) if metric else None,
    }, errors, warnings


def parse_route_lookup(family, text):
    """The address or network a routing table filter is asking about, or None if it's ordinary filter text.

    A partly typed IPv4 address with at least one dot, like "10.1" or "10.1.", means the network its octets cover
    (10.1.0.0/16), so the lookup keeps working while an address is being typed.
    """
    text = text.strip()
    if family == 4 and "/" not in text:
        octets = text.rstrip(".").split(".")
        if "." in text and len(octets) < 4 and all(octet.isdigit() for octet in octets):
            text = ".".join(octets + ["0"] * (4 - len(octets))) + f"/{8 * len(octets)}"
    try:
        target = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    return target if target.version == family else None


def matching_routes(routes, target):
    """Routes that would carry traffic to target (an address or network), as a router's lookup would find them.

    Returns (matches, best). best is the active route Windows would pick: the longest prefix, then the lowest
    metric. It is None when no active route matches.
    """
    matches = [route for route in routes
               if route.family == target.version and target.subnet_of(route.network)]
    candidates = [route for route in matches if route.active]
    best = min(candidates, key=lambda route: (-route.network.prefixlen,
                                              route.metric if route.metric is not None else float("inf")),
               default=None)
    return matches, best


def _next_hop(family, gateway):
    return gateway or ("0.0.0.0" if family == 4 else "::")


def build_add_route_script(family, network, gateway, interface, metric, persistent):
    """PowerShell that adds a route. An empty gateway means an on-link route."""
    lookup = (f"-DestinationPrefix {ps_quote(network)} -InterfaceIndex {int(interface)} "
              f"-NextHop {ps_quote(_next_hop(family, gateway))}")
    parameters = lookup + (f" -RouteMetric {int(metric)}" if metric else "")
    if not persistent:
        return f"New-NetRoute {parameters} -PolicyStore ActiveStore | Out-Null"
    # New-NetRoute rejects -PolicyStore PersistentStore; with no store it adds to both the persistent and active
    # stores. It fails if the route is already active, so drop an active-only copy first.
    return (f"Get-NetRoute {lookup} -PolicyStore ActiveStore -ErrorAction SilentlyContinue | "
            f"Remove-NetRoute -Confirm:$false\n"
            f"New-NetRoute {parameters} | Out-Null")


def build_delete_route_script(route):
    """PowerShell that deletes a route from both the active and persistent stores."""
    lookup = (f"-DestinationPrefix {ps_quote(route.network)} -InterfaceIndex {int(route.interface)} "
              f"-NextHop {ps_quote(route.next_hop)}")
    return (
        "$found = $false\n"
        "foreach ($store in 'PersistentStore', 'ActiveStore') {\n"
        f"    $routes = @(Get-NetRoute {lookup} -PolicyStore $store -ErrorAction SilentlyContinue)\n"
        "    if ($routes) {\n"
        "        $routes | Remove-NetRoute -Confirm:$false\n"
        "        $found = $true\n"
        "    }\n"
        "}\n"
        "if (-not $found) { throw 'The route was not found. It may already have been removed.' }"
    )


def build_route_copy_command(route):
    """A one-line PowerShell command that recreates the route, for copying to the clipboard."""
    command = (f"New-NetRoute -DestinationPrefix {ps_quote(route.network)} -InterfaceIndex {int(route.interface)} "
               f"-NextHop {ps_quote(route.next_hop)}")
    if route.route_metric:
        command += f" -RouteMetric {route.route_metric}"
    if not route.persistent:
        command += " -PolicyStore ActiveStore"
    return command


def add_route(family, network, gateway, interface, metric, persistent):
    run_powershell(build_add_route_script(family, network, gateway, interface, metric, persistent))


def delete_route(route):
    run_powershell(build_delete_route_script(route))
