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

    if errors:
        return None, errors, warnings
    return {
        "network": network,
        "gateway": str(gateway_ip) if gateway_ip is not None else "",
        "interface": interface,
        "metric": int(metric) if metric else None,
    }, errors, warnings


def _next_hop(family, gateway):
    return gateway or ("0.0.0.0" if family == 4 else "::")


def build_add_route_script(family, network, gateway, interface, metric, persistent):
    """PowerShell that adds a route. An empty gateway means an on-link route."""
    lookup = (f"-DestinationPrefix {ps_quote(network)} -InterfaceIndex {int(interface)} "
              f"-NextHop {ps_quote(_next_hop(family, gateway))}")
    parameters = lookup + (f" -RouteMetric {int(metric)}" if metric else "")
    if not persistent:
        return f"New-NetRoute {parameters} -PolicyStore ActiveStore | Out-Null"
    # Add to the persistent store, then make sure it's active now too
    return (f"New-NetRoute {parameters} -PolicyStore PersistentStore | Out-Null\n"
            f"if (-not (Get-NetRoute {lookup} -PolicyStore ActiveStore -ErrorAction SilentlyContinue)) {{\n"
            f"    New-NetRoute {parameters} -PolicyStore ActiveStore | Out-Null\n"
            f"}}")


def build_delete_route_script(route):
    """PowerShell that deletes a route from both the active and persistent stores."""
    lookup = (f"-DestinationPrefix {ps_quote(route.network)} -InterfaceIndex {int(route.interface)} "
              f"-NextHop {ps_quote(route.next_hop)}")
    return (
        "$found = $false\n"
        "foreach ($store in 'PersistentStore', 'ActiveStore') {\n"
        f"    if (Get-NetRoute {lookup} -PolicyStore $store -ErrorAction SilentlyContinue) {{\n"
        f"        Remove-NetRoute {lookup} -PolicyStore $store -Confirm:$false\n"
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
