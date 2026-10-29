"""Watching a map for devices and hosts added to the network, and putting them on it.

Every few minutes each switch read over SNMP is asked for its CDP and LLDP neighbors (a couple of short columns, not
the whole crawl). When a switch's neighbors change from what they were, or a syslog message or trap says something
happened on it, the map is crawled again from that switch, the way Crawl from Here does: new neighbors are read and
added, and the hosts on its ports and its VLANs are refreshed (VLANs added, gone or renamed, ports moved to
another VLAN, subnets that appear, go or move between devices, and devices upgraded or with hardware swapped,
added or taken out are noted in the watch log). Every so often every switch is read like that, to catch hosts
plugged in where nothing announced it. What turns up is added to the map straight away and noted in its news, so it's
drawn as new until someone looks at it. A wireless controller is asked for its access points' status too, so an AP
going down (or coming back) has it read again, and noted in the watch log; its Wi-Fi clients come and go, roaming
between APs, so they aren't news.

Qt-free: NOMAD's map page and the Map Watcher service both use it. Reading runs on a worker thread; what changes the
map (apply_refresh) runs wherever the map is owned.
"""
import datetime
import logging
from dataclasses import dataclass, field, replace

from ..snmp import SnmpError, parse_oid
from . import aruba, collect, hardware
from .placement import places, vrf_text
from .vlans import vlan_names
from .crawl import CrawlSettings, Crawler, in_scope, parse_networks
from .model import AP_DOWN, AP_UP, NETWORK_KINDS, SNMP, WLC, normalize_name

log = logging.getLogger(__name__)

NEIGHBOR_INTERVAL = 300  # Seconds between asking the switches for their neighbors
HOST_INTERVAL = 3600  # Seconds between reading every switch's MAC table again
RECHECK_INTERVAL = 3600  # Seconds between asking devices that don't answer SNMP again
TRIGGER_DELAY = 45  # Seconds after a syslog message or trap before reading the switch (CDP needs time to see it)
# The watch timers, user adjustable: name -> (default, least, most), in seconds
TIMERS = {"neighbor_interval": (NEIGHBOR_INTERVAL, 60, 3600), "host_interval": (HOST_INTERVAL, 300, 86400),
          "recheck_interval": (RECHECK_INTERVAL, 300, 86400), "trigger_delay": (TRIGGER_DELAY, 0, 600)}
HOST_NEW_DAYS = 30  # A host back on the map within this many days isn't news
HOST_SEEN_KEEP_DAYS = 90  # host_seen entries older than this are dropped
MAX_FALLBACKS = 8  # Other addresses of a switch tried when its management address doesn't answer
PORTS_LISTED = 4  # Ports moved to another VLAN named in one line of the watch log
CDP_DEVICE_ID = f"{collect.CDP_CACHE_ENTRY}.6"
LLDP_SYS_NAME = f"{collect.LLDP_REM_ENTRY}.9"
LLDP_CHASSIS_ID = f"{collect.LLDP_REM_ENTRY}.5"
AP_STATUS = f"{aruba.AP_ENTRY}.{aruba.AP_STATUS}"
DEVICE, HOST = "device", "host"


def timer_values(values=None):
    """The watch timers ({name: seconds}) from saved values, each kept within its limits, with the defaults for any
    missing or unreadable."""
    values = values or {}
    result = {}
    for name, (default, least, most) in TIMERS.items():
        try:
            seconds = int(values.get(name, default))
        except (TypeError, ValueError):
            seconds = default
        result[name] = max(least, min(most, seconds))
    return result


def news_ref(kind, key):
    return f"{kind}:{key}"


def split_ref(ref):
    kind, _, key = ref.partition(":")
    return kind, key


@dataclass
class WatchOptions:
    """How to read the network for a watched map: what CrawlSettings needs besides where to start."""
    communities: list = field(default_factory=lambda: ["public"])
    overrides: list = field(default_factory=list)
    scope: list = field(default_factory=list)
    version: int = 1
    timeout: int = 2000
    max_hops: int = 6
    max_devices: int = 500
    workers: int = 16

    def crawl_settings(self, network_map, seeds):
        devices = network_map.devices.values()
        return CrawlSettings(seeds=list(seeds), communities=list(self.communities),
                             overrides=[tuple(item) for item in self.overrides], scope=list(self.scope),
                             max_hops=self.max_hops, max_devices=self.max_devices, version=self.version,
                             timeout=self.timeout, collect_hosts=True, trace=False, workers=self.workers,
                             corrections={device.key: device.corrections() for device in devices if device.corrected},
                             deleted={key: list(addresses) for key, (_, addresses) in network_map.deleted.items()})


# --------------------------------------------------------------------- Asking switches for their neighbors

def switches(network_map):
    """{key: address} of the network devices read over SNMP: the ones to ask for neighbors."""
    return {key: device.mgmt_ip for key, device in network_map.devices.items()
            if device.source == SNMP and device.mgmt_ip and device.kind in NETWORK_KINDS and not device.manual}


def controllers(network_map):
    """Keys of the wireless controllers among switches(): their access points' status is part of what's watched."""
    return {key for key in switches(network_map) if network_map.devices[key].kind == WLC}


def neighbor_signature(cdp_rows, lldp_name_rows, lldp_chassis_rows, ap_rows=()):
    """What a switch's neighbors are, from three short columns: {(local port index, neighbor name)}. The port is the
    table's own index (ifIndex for CDP, LLDP's port number), so interface names needn't be read."""
    signature = set()
    for oid, value in cdp_rows:
        index = oid[len(parse_oid(CDP_DEVICE_ID)):]
        name = collect.text(value)
        if len(index) == 2 and name:
            signature.add(("cdp", index[0], normalize_name(name)))
    names = {}
    for root, rows in ((LLDP_CHASSIS_ID, lldp_chassis_rows), (LLDP_SYS_NAME, lldp_name_rows)):
        for oid, value in rows:
            index = oid[len(parse_oid(root)):]
            if len(index) != 3:
                continue
            if root == LLDP_SYS_NAME:
                name = collect.text(value)
            elif isinstance(value.value, bytes) and len(value.value) == 6:
                name = collect.mac_text(value.value)
            else:
                name = collect.text(value)
            if name:
                names[(index[1], index[2])] = name  # The system name over the chassis ID
    for (port, _), name in names.items():
        signature.add(("lldp", port, normalize_name(name)))
    for index, value in collect.column(ap_rows, AP_STATUS).items():  # A wireless controller's APs: up or down
        if len(index) == 6:
            signature.add(("ap", collect.mac_text(bytes(index)), AP_UP if value.value == aruba.AP_UP else AP_DOWN))
    return frozenset(signature)


def read_signature(address, options, client_factory, should_stop=lambda: False, wireless=False):
    """A switch's neighbor signature, or None if it didn't answer any community string. wireless: it's a wireless
    controller, whose APs' status is in it too. Runs on a worker thread."""
    from .crawl import communities_for, parse_overrides
    for community in communities_for(address, options.communities, parse_overrides(options.overrides)):
        if should_stop():
            return None
        try:
            client = client_factory(address, community, options.version, timeout=options.timeout, retries=1)
            roots = (CDP_DEVICE_ID, LLDP_SYS_NAME, LLDP_CHASSIS_ID) + ((AP_STATUS,) if wireless else ())
            columns = [list(client.walk(parse_oid(root), should_stop=should_stop)) for root in roots]
            return neighbor_signature(*columns)
        except (SnmpError, OSError) as problem:
            log.debug("Neighbors of %s with a community: %s", address, problem)
    return None


def read_signatures(targets, options, client_factory, should_stop=lambda: False, workers=16, wireless=()):
    """{key: signature or None} for {key: address}, several at once. wireless: the keys of wireless controllers."""
    from concurrent.futures import ThreadPoolExecutor
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        futures = {key: executor.submit(read_signature, address, options, client_factory, should_stop,
                                        key in wireless)
                   for key, address in targets.items()}
        return {key: future.result() for key, future in futures.items()}


def unread_devices(network_map, scope):
    """{key: address} of the devices on the map that don't answer SNMP (they only ping, don't answer at all, or
    were only seen as a neighbor) and are inside the crawl's scope: the ones to ask again, as the credentials or
    the devices' SNMP set-up may have changed since."""
    networks = parse_networks(scope)
    return {key: device.mgmt_ip for key, device in network_map.devices.items()
            if device.source != SNMP and device.mgmt_ip and in_scope(device.mgmt_ip, networks)}


def credential_text(credential):
    """How an answer is logged: an SNMPv3 user by name and protocols, never a community string itself."""
    return credential.label if hasattr(credential, "label") else "a community string"


def recheck(targets, options, client_factory, should_stop=lambda: False, workers=16):
    """Ask devices that don't answer SNMP (unread_devices) again with the credentials as they are now. Returns
    {key: (address, Check)} of those that answer now. Runs on a worker thread."""
    from concurrent.futures import ThreadPoolExecutor
    from .crawl import check_device
    if not targets:
        return {}
    settings = CrawlSettings(seeds=[], communities=list(options.communities),
                             overrides=[tuple(item) for item in options.overrides], scope=list(options.scope),
                             version=options.version, timeout=options.timeout)

    def ask(item):
        key, address = item
        if should_stop():
            return key, address, None
        return key, address, check_device(settings, address, client_factory, pinger=lambda _: False)
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        results = list(executor.map(ask, targets.items()))
    return {key: (address, check) for key, address, check in results
            if check is not None and check.source == SNMP}


def fallback_addresses(network_map, keys, scope):
    """{key: [address]}: for each of these switches, the other addresses it reported having (inside the crawl's
    scope) to ask when its management address stops answering, as when the management network is renumbered. Not
    for a switch whose address was corrected by hand: that's the one to use."""
    networks = parse_networks(scope)
    result = {}
    for key in keys:
        device = network_map.devices.get(key)
        if device is None or "mgmt_ip" in device.corrected:
            continue
        candidates = [address for address in list(device.addresses) + [item[0] for item in device.interfaces_l3]
                      if address and address != device.mgmt_ip and in_scope(address, networks)]
        if candidates:
            result[key] = list(dict.fromkeys(candidates))[:MAX_FALLBACKS]
    return result


def read_switches(targets, fallbacks, options, client_factory, should_stop=lambda: False, workers=16, wireless=()):
    """read_signatures, then, for switches that didn't answer at their management address, their other addresses
    (fallbacks, from fallback_addresses) in turn. wireless: the keys of wireless controllers (controllers()).
    Returns ({key: signature or None}, {key: (old address, address it answers at now)}). Runs on a worker thread."""
    from concurrent.futures import ThreadPoolExecutor
    signatures = read_signatures(targets, options, client_factory, should_stop, workers, wireless)
    silent = [key for key, signature in signatures.items() if signature is None and fallbacks.get(key)]
    moved = {}
    if not silent or should_stop():
        return signatures, moved

    def try_others(key):
        for address in fallbacks[key]:
            if should_stop():
                return None
            signature = read_signature(address, options, client_factory, should_stop, key in wireless)
            if signature is not None:
                return address, signature
        return None
    with ThreadPoolExecutor(max_workers=min(workers, len(silent))) as executor:
        for key, found in zip(silent, executor.map(try_others, silent)):
            if found is not None:
                moved[key] = (targets[key], found[0])
                signatures[key] = found[1]
    return signatures, moved


def adopt_addresses(network_map, moved):
    """Make the addresses switches answer at now their management addresses. Returns lines for the watch log."""
    lines = []
    for key, (old, new) in moved.items():
        device = network_map.devices.get(key)
        if device is None or device.mgmt_ip != old or "mgmt_ip" in device.corrected:
            continue  # Gone, or its address changed meanwhile
        device.mgmt_ip = new
        lines.append(f"{device.label} doesn't answer at {old} any more but does at {new}: that's its management "
                     "address now")
    return lines


def known_names(network_map):
    """Normalized names the map already has: its devices', its hosts' (phones announce themselves) and the deleted
    ones'."""
    names = set()
    for key, device in network_map.devices.items():
        names.add(normalize_name(key))
        if device.name:
            names.add(normalize_name(device.name))
    names.update(normalize_name(host.name) for host in network_map.hosts if host.name)
    names.update(normalize_name(label) for label, _ in network_map.deleted.values())
    return names


class NeighborBaseline:
    """The neighbors each switch had when last looked at, to tell which ones have changed."""

    def __init__(self):
        self.signatures = {}  # Switch key -> signature

    def changed(self, network_map, signatures):
        """Switches whose neighbors changed since last time, from {key: signature or None}. The first time a switch
        is seen, it counts as changed only if one of its neighbors isn't on the map."""
        changed, names = [], None
        for key, signature in signatures.items():
            if signature is None:
                continue  # Didn't answer: nothing to compare
            before = self.signatures.get(key)
            if before is None:
                names = known_names(network_map) if names is None else names
                if any(name not in names for kind, _, name in signature if kind != "ap"):
                    changed.append(key)
                self.signatures[key] = signature
            elif before != signature:
                # Something appeared, or an AP went up or down (one that's gone is noted, not read again)
                if signature - before:
                    changed.append(key)
                self.signatures[key] = signature
        return changed

    def forget(self, keys):
        for key in keys:
            self.signatures.pop(key, None)


# --------------------------------------------------------------------- Reading switches again and noting what's new

def crawl_from(network_map, options, seeds, client_factory=None, pinger=None, echo=None, should_stop=lambda: False,
               events=lambda kind, *details: None):
    """Crawl from the switches at seeds, adding to network_map (which isn't changed). Runs on a worker thread.
    Returns the crawl's map, for apply_refresh."""
    extra = {name: value for name, value in (("client_factory", client_factory), ("pinger", pinger),
                                             ("echo", echo)) if value is not None}
    return Crawler(options.crawl_settings(network_map, seeds), should_stop=should_stop, events=events,
                   known=network_map, **extra).run()


@dataclass
class WatchResult:
    devices: list = field(default_factory=list)  # Keys of devices new to the map
    hosts: list = field(default_factory=list)  # MACs of hosts new to the map (not seen on it within HOST_NEW_DAYS)
    moved: list = field(default_factory=list)  # [(MAC, from, to)]
    lines: list = field(default_factory=list)  # For the watch log
    vlans: list = field(default_factory=list)  # Device keys whose VLANs changed
    subnets: list = field(default_factory=list)  # (VRF, CIDR) of subnets that appeared, went or moved
    hardware: list = field(default_factory=list)  # Device keys whose software or hardware changed
    access_points: list = field(default_factory=list)  # Keys of access points that went down or came back up
    links: list = field(default_factory=list)  # Links gone, or no longer seen by one end (Link.unseen_by)

    def __bool__(self):
        return bool(self.devices or self.hosts or self.moved or self.vlans or self.subnets or self.hardware
                    or self.access_points or self.links)


def link_text(network_map, link):
    return f"{place_text(network_map, link.a, link.a_port)} — {place_text(network_map, link.b, link.b_port)}"


def link_lines(network_map, gone, unseen):
    """The watch log's lines for links gone (both ends, or the only one that could give it, read without it) and
    links one end no longer gives (kept, faint, until the other end is read)."""
    lines = [f"Link gone: {link_text(network_map, link)}" for link in gone]
    for link in unseen:
        reader = network_map.devices[link.unseen_by].label if link.unseen_by in network_map.devices else link.unseen_by
        other = network_map.devices.get(link.other(link.unseen_by))
        lines.append(f"Link not seen by {reader}: {link_text(network_map, link)} (kept until "
                     f"{other.label if other else 'the other end'} is read again)")
    return lines


def place_text(network_map, device_key, port):
    device = network_map.devices.get(device_key)
    return f"{device.label if device else device_key} {port}".strip()


def where_found(network_map, key):
    """Where a new device was seen: the port of the switch it's linked to."""
    for link in network_map.links_of(key):
        other = link.other(key)
        if other in network_map.devices and network_map.devices[other].source == SNMP:
            return place_text(network_map, other, link.port_on(other))
    return ""


def today(now):
    return now.date().isoformat()


def mark_hosts_seen(network_map, now=None):
    """Note every host on the map as seen today, and forget ones not seen for a long time."""
    now = now or datetime.datetime.now()
    day = today(now)
    for host in network_map.hosts:
        if host.mac:
            network_map.host_seen[host.mac] = day
    oldest = (now - datetime.timedelta(days=HOST_SEEN_KEEP_DAYS)).date().isoformat()
    network_map.host_seen = {mac: seen for mac, seen in network_map.host_seen.items() if seen >= oldest}


def apply_refresh(network_map, crawled, now=None, by=""):
    """Add a watch crawl to the map (as Crawl from Here does) and note what's new in its news. Returns a
    WatchResult."""
    now = now or datetime.datetime.now()
    before_devices = set(network_map.devices)
    before_addresses = {device.mgmt_ip for device in network_map.devices.values() if device.mgmt_ip}
    before_hosts = {host.mac: host for host in network_map.hosts if host.mac}
    before_vlans = {key: (vlan_names(device), dict(device.port_vlans)) for key, device in network_map.devices.items()}
    before_places = places(network_map)
    before_hardware = {key: hardware_snapshot(device) for key, device in network_map.devices.items()}
    before_aps = {key: device.ap_status for key, device in network_map.devices.items() if device.ap_status}
    before_links = network_map.links_before()
    recent = (now - datetime.timedelta(days=HOST_NEW_DAYS)).date().isoformat()
    added, read = network_map.merge_crawl(crawled)
    network_map.fold_manual_devices(new=set(added))
    result = WatchResult()
    gone, unseen = network_map.link_changes(before_links)
    result.links = gone + unseen
    when = now.isoformat(timespec="seconds")
    for key in added:
        device = network_map.devices.get(key)
        if key in before_devices or device is None or device.manual or                 any(device.owns(address) for address in before_addresses):
            continue  # On the map before (perhaps under its address, before it answered SNMP)
        where = where_found(network_map, key)
        result.devices.append(key)
        network_map.news[news_ref(DEVICE, key)] = {"when": when, "where": where, "by": by}
        address = f" ({device.mgmt_ip})" if device.mgmt_ip else ""
        result.lines.append(f"New device: {device.label}{address}" + (f" on {where}" if where else ""))
    for host in network_map.hosts:
        if not host.mac or host.device not in read:
            continue  # (Wi-Fi clients are on access points, which aren't read: they roam, so aren't news)
        before = before_hosts.get(host.mac)
        where = place_text(network_map, host.device, host.port)
        name = host.name or host.ip or host.mac
        if before is None:
            if network_map.host_seen.get(host.mac, "") >= recent:
                continue  # Was on the map lately: back, not new
            result.hosts.append(host.mac)
            network_map.news[news_ref(HOST, host.mac)] = {"when": when, "where": where, "by": by}
            details = " ".join(part for part in (host.ip if host.ip != name else "", host.vendor) if part)
            result.lines.append(f"New host: {name}{f' ({details})' if details else ''} on {where}")
        else:
            was = place_text(network_map, before.device, before.port)
            if was != where:
                result.moved.append((host.mac, was, where))
                result.lines.append(f"Host moved: {name} from {was} to {where}")
    for key in sorted(read):
        if key in before_vlans and key in network_map.devices:
            lines = vlan_changes(network_map.devices[key], *before_vlans[key])
            if lines:
                result.vlans.append(key)
                result.lines += lines
    for key in sorted(read):
        if key in before_hardware and key in network_map.devices:
            lines = hardware_changes(network_map.devices[key], before_hardware[key])
            if lines:
                result.hardware.append(key)
                result.lines += lines
    for key, device in sorted(network_map.devices.items()):
        if device.controller not in read or key not in before_aps or key not in crawled.devices:
            continue
        if device.ap_status != before_aps[key]:
            controller = network_map.devices[device.controller].label
            result.access_points.append(key)
            result.lines.append(f"Access point {device.label} " + ("went down" if device.ap_status == AP_DOWN
                                                                   else "is up again") + f" ({controller})")
    for subnet, line in subnet_changes(network_map, before_places, places(network_map), read):
        result.subnets.append(subnet)
        result.lines.append(line)
    result.lines += link_lines(network_map, gone, unseen)
    mark_hosts_seen(network_map, now)
    prune_news(network_map)
    return result


def subnet_changes(network_map, before, after, read):
    """Subnets that appeared on, went from or moved between the devices read: [((VRF, CIDR), line for the log)].
    before, after: placement.places() of the map then and now."""
    def label(place):
        device = network_map.devices.get(place.device)
        return f"{device.label if device is not None else place.device} {place.port}"

    changes = []
    for subnet in sorted(set(before) | set(after)):
        old = {(place.device, place.port): place for place in before.get(subnet, []) if place.device in read}
        new = {(place.device, place.port): place for place in after.get(subnet, []) if place.device in read}
        gone = [old[spot] for spot in old if spot not in new]
        came = [new[spot] for spot in new if spot not in old]
        if not gone and not came:
            continue
        vrf, cidr = subnet
        name = f"Subnet {cidr}" + (f" (VRF {vrf_text(vrf)})" if vrf else "")
        elsewhere = [place for place in after.get(subnet, []) if place not in came]
        if gone and came:
            line = f"{name} moved from {', '.join(map(label, gone))} to {', '.join(map(label, came))}"
        elif came:
            line = f"{name} appeared on {', '.join(map(label, came))}"
            if elsewhere:
                line += f" (also on {', '.join(map(label, elsewhere[:3]))})"
        else:
            line = f"{name} gone from {', '.join(map(label, gone))}"
        changes.append((subnet, line))
    return changes


def hardware_snapshot(device):
    """What a device runs and is made of, to tell what changed after it's read again."""
    members = hardware.chassis(device.parts)
    return {"software": device.software, "read": device.inventory_read,
            "chassis": [(_member_name(part, len(members)), part.get("serial", ""), part.get("model", ""))
                        for part in members],
            "parts": {part["serial"]: part for part in device.parts
                      if part.get("class") != hardware.CHASSIS and part.get("serial")}}


def _member_name(part, count):
    if count < 2:
        return ""
    return part.get("name") or (f"Member {part['position']}" if part.get("position") else f"Chassis {part['index']}")


def _part_text(part):
    what = hardware.PART_NAMES.get(part.get("class"), "Part")
    model = part.get("model") or part.get("descr") or ""
    return f"{what} {part['serial']}" + (f" ({model})" if model else "")


def hardware_changes(device, before):
    """What changed in a device's software and hardware since it was last read, for the watch log: an upgrade (or
    downgrade), a chassis or stack member with another serial number (swapped), stack members added or gone, and
    parts with serial numbers added or taken out. Nothing for a device whose hardware wasn't read both times."""
    lines = []
    if before["software"] and device.software and before["software"] != device.software:
        lines.append(f"Software changed on {device.label}: {before['software']} → {device.software}")
    if not before["read"] or not device.inventory_read:
        return lines
    now = hardware_snapshot(device)
    old = {name: (serial, model) for name, serial, model in before["chassis"]}
    new = {name: (serial, model) for name, serial, model in now["chassis"]}
    where = (lambda name: f"{device.label} {name}".strip())
    for name, (serial, model) in new.items():
        if name not in old:
            lines.append(f"New stack member on {device.label}: {name} ({' '.join(filter(None, (model, serial)))})")
        elif old[name][0] and serial and old[name][0] != serial:
            lines.append(f"Hardware swapped on {where(name)}: {old[name][0]} → {serial}" + (f" ({model})" if model
                                                                                           else ""))
    for name, (serial, model) in old.items():
        if name not in new:
            lines.append(f"Stack member gone from {device.label}: {name} ({' '.join(filter(None, (model, serial)))})")
    chassis_serials = {serial for _, serial, _ in now["chassis"] + before["chassis"] if serial}
    added = [part for serial, part in now["parts"].items() if serial not in before["parts"]
             and serial not in chassis_serials]
    gone = [part for serial, part in before["parts"].items() if serial not in now["parts"]
            and serial not in chassis_serials]
    for title, listed in (("Parts added on", added), ("Parts taken out of", gone)):
        if listed:
            more = f" and {len(listed) - PORTS_LISTED} more" if len(listed) > PORTS_LISTED else ""
            lines.append(f"{title} {device.label}: {'; '.join(map(_part_text, listed[:PORTS_LISTED]))}{more}")
    return lines


def vlan_changes(device, names_before, ports_before):
    """What changed in a switch's VLANs since it was last read, for the watch log: VLANs added, gone or renamed,
    and ports moved to another VLAN. A switch read for its VLANs the first time (on a map made before NOMAD read
    them) gets one line."""
    names = vlan_names(device)
    if not names_before and not ports_before:
        return [f"Read {device.label}'s VLANs: {len(names)}"] if names else []
    lines = []
    for vlan in sorted(set(names) - set(names_before)):
        lines.append(f"New VLAN on {device.label}: {vlan} {names[vlan]}".rstrip())
    for vlan in sorted(set(names_before) - set(names)):
        lines.append(f"VLAN gone from {device.label}: {vlan} {names_before[vlan]}".rstrip())
    for vlan in sorted(set(names) & set(names_before)):
        if names[vlan] != names_before[vlan]:
            lines.append(f"VLAN {vlan} renamed on {device.label}: {names_before[vlan] or '(no name)'} → "
                         f"{names[vlan] or '(no name)'}")
    moved = []
    for port, entry in device.port_vlans.items():
        old = ports_before.get(port)
        if old is None or old == entry:
            continue
        if entry.get("mode") != old.get("mode"):
            moved.append(f"{port} {old.get('mode') or '?'} → {entry.get('mode') or '?'}")
        elif entry.get("mode") == "trunk":
            if entry.get("native") != old.get("native"):
                moved.append(f"{port} native {old.get('native', 1)} → {entry.get('native', 1)}")
            elif entry.get("allowed") != old.get("allowed"):
                moved.append(f"{port} allowed {old.get('allowed') or '(none)'} → {entry.get('allowed') or '(none)'}")
        elif entry.get("vlan") != old.get("vlan"):
            moved.append(f"{port} {old.get('vlan')} → {entry.get('vlan')}")
        elif entry.get("voice") != old.get("voice"):
            moved.append(f"{port} voice {old.get('voice') or 'none'} → {entry.get('voice') or 'none'}")
    if moved:
        more = f" and {len(moved) - PORTS_LISTED} more" if len(moved) > PORTS_LISTED else ""
        lines.append(f"Ports changed VLAN on {device.label}: {'; '.join(moved[:PORTS_LISTED])}{more}")
    return lines


def prune_news(network_map):
    """Drop news of devices and hosts no longer on the map."""
    macs = {host.mac for host in network_map.hosts if host.mac}
    kept = {}
    for ref, item in network_map.news.items():
        kind, key = split_ref(ref)
        if (kind == DEVICE and key in network_map.devices) or (kind == HOST and key in macs):
            kept[ref] = item
    network_map.news = kept


def acknowledge(network_map, refs=None):
    """Mark news as looked at (all of it when refs is None). Returns the refs cleared."""
    refs = list(network_map.news) if refs is None else [ref for ref in refs if ref in network_map.news]
    for ref in refs:
        network_map.news.pop(ref, None)
    return refs


def is_new(network_map, kind, key):
    return news_ref(kind, key) in network_map.news


def copy_for_thread(network_map):
    """A copy of the map's devices, links and hosts a worker thread can read while the map is edited."""
    copy = replace(network_map)
    copy.devices = {key: replace(device) for key, device in network_map.devices.items()}
    copy.links = [replace(link) for link in network_map.links]
    copy.hosts = [replace(host) for host in network_map.hosts]
    copy.deleted = dict(network_map.deleted)
    return copy
