"""Crawling the network: ask each device for its CDP/LLDP neighbors over SNMP, then ask those neighbors, and so on.

Starts from one or more seed addresses and stays within the scope (subnets, hops and a device limit). Devices that
don't answer SNMP are pinged, so the map can tell "wrong community or ACL" from "can't be reached". Switches' MAC
tables (per VLAN on Cisco IOS, where each VLAN has its own table) and routers' ARP tables put hosts on the edge
ports they're plugged into.
"""
import copy
import datetime
import ipaddress
import logging
import re
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait
from dataclasses import dataclass, field

from ..oui import format_mac, vendor
from ..snmp import V2C, SnmpClient, SnmpError, oid_text, parse_oid
from ..snmpv3 import credential_from_json, credential_to_json, is_v3, users_from_json
from . import aruba, collect, hardware, l3, vlans
from .model import AP, AP_DOWN, AP_UP, CONTROLLER, HOST, KIND_NAMES, NEIGHBOR, NETWORK_KINDS, NO_SNMP, PHONE, \
    ROUTER, SERVER, SNMP, SSH_READ, UNKNOWN, UNREACHABLE, Device, Host, Link, NetworkMap, Trace, display_name, \
    normalize_name, port_key, port_sort_key, short_port

log = logging.getLogger(__name__)

WORKERS = 16  # Devices read at once (Scope can change it)
MAX_WORKERS = 64
BULK_ROWS = 50  # Rows asked for in each SNMP GETBULK: fewer round trips than the usual 25
VLAN_WORKERS = 4  # A Catalyst's per-VLAN MAC tables read at once
STOPPED = "Stopped"
PINGS_NO_SNMP = "Answers ping but not SNMP: check the community string (or SNMPv3 user) and the device's SNMP ACL."
NO_ANSWER = "No answer to SNMP or ping."
LIVE_INTERVAL = 1.5  # Seconds between snapshots of the map for drawing it while it's crawled
ROUTE_ROWS = 20000  # Per column: a core with the full internet table shouldn't take all day
MAX_ROUTES = 5000  # Kept per device in the map
END_DEVICE_KINDS = {PHONE, HOST}  # Shown as hosts on their switch port, not as devices on the map


@dataclass
class CrawlSettings:
    seeds: list
    # Community strings and V3Users (snmpv3.py) to try, in order: "communities" for short, as they were first
    communities: list = field(default_factory=lambda: ["public"])
    overrides: list = field(default_factory=list)  # [(subnet text, community or V3User)]: tried first in the subnet
    scope: list = field(default_factory=list)  # Subnets the crawl may go into; empty means any private address
    max_hops: int = 6
    max_devices: int = 500
    version: int = V2C
    timeout: int = 2000  # Milliseconds per SNMP request
    retries: int = 1
    collect_hosts: bool = True
    trace: bool = True  # Traceroute to what SNMP couldn't show (for the logical view)
    max_traces: int = l3.MAX_TRACES
    workers: int = WORKERS
    read_inventory: bool = True  # Each device's chassis, parts, serial numbers and software version (ENTITY-MIB)
    # Device key -> {attribute: value} corrected by hand on the map before: an address to ask it at (CDP gave none,
    # or the wrong one), what kind it is (asked if a network device), its name. Kept over what the crawl finds.
    corrections: dict = field(default_factory=dict)
    # Device key -> [its addresses]: deleted from the map by hand, so left off it and not crawled through (unless
    # it's where the crawl starts)
    deleted: dict = field(default_factory=dict)


def parse_networks(lines):
    """Subnets from text, one per line (or separated by commas or spaces). Raises ValueError naming a bad one."""
    networks = []
    for item in " ".join(lines).replace(",", " ").split():
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ValueError(f"'{item}' isn't a subnet or address.") from None
    return networks


def parse_overrides(overrides):
    """[(subnet text, community)] as [(network, community)], the most specific subnet first."""
    return sorted(((ipaddress.ip_network(subnet, strict=False), community) for subnet, community in overrides),
                  key=lambda item: item[0].prefixlen, reverse=True)


def in_scope(address, networks):
    """Whether a crawl may ask address: inside networks (parse_networks'), or with none, any private address."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if networks:
        return any(ip.version == network.version and ip in network for network in networks)
    return ip.is_private and not ip.is_loopback and not ip.is_link_local


def ordered_credentials(communities, v3_users, v3_first=True):
    """What a crawl tries on each device: the SNMPv3 users and the community strings, in the order chosen. Users
    first by default: a device without the user says so at once (a Report), where a wrong community times out."""
    return list(v3_users) + list(communities) if v3_first else list(communities) + list(v3_users)


def credentials_to_json(communities, overrides, v3_users=(), v3_first=True):
    """A map's SNMP credentials as kept (encrypted) in the settings and as a tribe map's secrets."""
    return {"communities": list(communities),
            "overrides": [[subnet, credential_to_json(credential)] for subnet, credential in overrides],
            "v3_users": [user.to_json() for user in v3_users], "v3_first": bool(v3_first)}


def credentials_from_json(data, communities=("public",)):
    """(communities, overrides, v3 users, v3 first) from credentials_to_json's form (or an older one without
    users). communities: what to use if it has none."""
    data = data if isinstance(data, dict) else {}
    overrides = [(str(item[0]), credential_from_json(item[1])) for item in data.get("overrides") or []
                 if isinstance(item, (list, tuple)) and len(item) == 2]
    return ([str(item) for item in data.get("communities") or []] or list(communities), overrides,
            users_from_json(data.get("v3_users")), bool(data.get("v3_first", True)))


def communities_for(address, communities, overrides):
    """The community strings to try for address, in order: those for the subnets it's in (overrides, as
    parse_overrides gives them), then communities."""
    ip = ipaddress.ip_address(address)
    chosen = [community for network, community in overrides if ip.version == network.version and ip in network]
    return list(dict.fromkeys(chosen + list(communities)))


class Crawler:
    def __init__(self, settings, client_factory=SnmpClient, pinger=None, should_stop=lambda: False,
                 progress=lambda message: None, echo=None, events=lambda kind, *details: None, known=None):
        """events(kind, *details) reports progress for a live view, from the crawl's own and its worker threads:
            ("started", address, key or None)  a device is being read
            ("step", address, text)            what it's doing now (the table, the VLAN, the community)
            ("finished", address, outcome)     snmp, no-snmp, unreachable, again (a second address), stopped, traced
            ("log", text)                      something worth keeping in the crawl log
            ("counts", {...})                  read, reading, queued, found, no_snmp, unreachable
            ("map", NetworkMap)                a copy of the map so far (devices and links), every LIVE_INTERVAL
            ("phase", text)                    hosts, traceroute
            ("community", address, community)  the community string (or V3User) it answered to
        known: a map this crawl adds to (Crawl from Here). Devices it read aren't read again, and keep their keys.
        """
        self.settings = settings
        self.events = events
        self.counts = {"read": 0, "reading": 0, "queued": 0, "found": 0, "no_snmp": 0, "unreachable": 0}
        self.limit_logged = False
        self.client_factory = client_factory
        self.pinger = pinger or _ping
        self.echo = echo or l3.icmp_echo
        self.should_stop = should_stop
        self.progress = progress
        self.scope = parse_networks(settings.scope)
        self.overrides = parse_overrides(settings.overrides)
        self.map = NetworkMap(seeds=list(settings.seeds))
        self.aliases = {}  # Address or normalized name -> device key
        self.tables = {}  # Device key -> DeviceTables, for placing hosts at the end
        self.asked = set()  # Addresses already asked (or queued)
        self.completed = set()  # Visits recorded: don't mark a device down while another address is pending
        self.capabilities = {}  # Device key -> what its neighbors' CDP/LLDP say it is (router, switch...)
        # Names (normalized) that more than one device has: those devices are keyed by address, not found by name
        self.ambiguous = set()
        self.renamed = {}  # Old key -> new, for devices keyed by address once another turned up with their name
        self.advertised = {}  # (device key, port key) -> the address its neighbor on that port was asked at
        self.known = known
        if known is not None:
            names = {}
            for device in known.devices.values():
                if device.source == SNMP and not device.manual and device.name:
                    names[normalize_name(device.name)] = names.get(normalize_name(device.name), 0) + 1
            self.ambiguous = {name for name, count in names.items() if count > 1}
            for key, device in known.devices.items():
                if device.source == SNMP and not device.manual:  # Already read: recognize it, but don't ask again
                    for address in [device.mgmt_ip] + list(device.addresses):
                        if address:
                            self.aliases.setdefault(address, key)
                            self.asked.add(address)
                    if device.name:
                        self.aliases.setdefault(normalize_name(device.name), key)
            self.asked -= set(settings.seeds)  # Except where it starts from
        seeds = set(settings.seeds)
        self.deleted = {key for key, addresses in settings.deleted.items() if not seeds & set(addresses)}
        self.deleted_addresses = {address for key in self.deleted for address in settings.deleted[key]}
        self.left_out = set()  # Deleted devices seen as neighbors (logged once each)
        self.ap_controllers = {}  # Access point key -> the key of the controller that has it up (or lists it)

    # ----------------------------------------------------------------- Scope

    def in_scope(self, address):
        return in_scope(address, self.scope)

    def communities_for(self, address):
        return communities_for(address, self.settings.communities, self.overrides)

    # ----------------------------------------------------------------- Crawl

    def run(self):
        self.map.started = _now()
        queue = []
        for seed in self.settings.seeds:
            if seed not in self.asked:
                self.asked.add(seed)
                queue.append((seed, 0, None))
        done = 0
        last_snapshot, changed = 0.0, False
        self.events("log", f"Starting from {', '.join(self.settings.seeds)}")
        with ThreadPoolExecutor(max_workers=self.settings.workers) as executor:
            running = {}
            while (queue or running) and not self.should_stop():
                while queue and len(running) < self.settings.workers * 2:
                    address, hops, key = queue.pop(0)
                    key = self.current_key(key, address)  # Merged into another device meanwhile, or renamed
                    device = self.map.devices.get(key) if key is not None else None
                    if device is not None and device.source == SNMP and device.owns(address):
                        continue  # Reached at another address meanwhile
                    compare = [identity(self.tables[other]) for other in self.namesakes(key)]
                    running[executor.submit(self.visit, address, compare)] = (address, hops, key)
                    self.events("started", address, key)
                self.report_counts(len(running), len(queue))
                finished, _ = wait(running, timeout=0.2, return_when=FIRST_COMPLETED)
                for future in finished:
                    address, hops, key = running.pop(future)
                    key = self.current_key(key, address)
                    done += 1
                    try:
                        tables, error = future.result()
                    except Exception as crash:  # A bug reading one device shouldn't lose the whole map
                        log.exception("Reading %s failed", address)
                        tables, error = None, f"Couldn't read it: {crash}"
                        if self.should_stop():
                            error = STOPPED
                        else:
                            self.events("step", address, "Pinging")
                            if self.pinger(address):
                                self.events("log", f"{address}: {error}")
                                error = PINGS_NO_SNMP
                    queue.extend(self.record(address, hops, key, tables, error))
                    changed = True
                    self.report_counts(len(running), len(queue))
                    self.progress(f"Read {done} of {done + len(queue) + len(running)} devices "
                                  f"({len(self.map.devices)} found so far): {address}")
                if changed and time.monotonic() - last_snapshot >= LIVE_INTERVAL:
                    self.events("map", self.snapshot())
                    last_snapshot, changed = time.monotonic(), False
            self.map.stopped = self.should_stop()
            if self.map.stopped:
                self.events("log", f"Stopped, with {len(running)} being read and {len(queue)} still to read")
                for future in running:
                    future.cancel()
        self.map.remove_devices([key for key in self.map.devices if key in self.deleted])  # Reached another way
        read = {key for key, device in self.map.devices.items() if device.source == SNMP}
        for gone, found in self.map.fold_unread_devices(read):
            self.events("log", f"{gone.label} is {found.label} (it has that address)")
        self.report_counts(0, 0)
        self.events("map", self.snapshot())
        for key, corrections in self.settings.corrections.items():  # Corrected by hand: kept over what was found
            if key in self.map.devices:
                self.map.devices[key].apply_corrections(corrections)
        if self.settings.collect_hosts:
            self.events("phase", "Placing hosts on switch ports")
        self.place_hosts()
        if self.settings.collect_hosts:
            wireless = sum(1 for host in self.map.hosts if host.wireless)
            self.events("log", f"Placed {len(self.map.hosts) - wireless} hosts on switch ports"
                               + (f" and {wireless} Wi-Fi clients on access points" if wireless else ""))
        if self.settings.trace and not self.map.stopped:
            self.trace_paths()
        self.map.finished = _now()
        return self.map

    def report_counts(self, reading, queued):
        self.counts.update(reading=reading, queued=queued, found=len(self.map.devices))
        self.events("counts", dict(self.counts))

    def snapshot(self):
        """A copy of the devices and links found so far, for drawing while the crawl goes on."""
        snapshot = NetworkMap(seeds=list(self.map.seeds), started=self.map.started)
        snapshot.devices = {key: copy.copy(device) for key, device in self.map.devices.items()}
        for device in snapshot.devices.values():
            device.addresses = list(device.addresses)
        snapshot.links = [copy.copy(link) for link in self.map.links]
        for link in snapshot.links:
            link.protocols = list(link.protocols)
        return snapshot

    def trace_paths(self):
        """Traceroute from this computer to devices that didn't answer SNMP, unknown next hops and static routes'
        destinations."""
        targets = l3.trace_targets(self.map, self.in_scope, self.settings.max_traces)
        if not targets:
            return
        self.progress(f"Tracing the way to {len(targets)} addresses SNMP couldn't show...")
        self.events("phase", f"Traceroute to {len(targets)} addresses SNMP couldn't show")

        def echo(address, ttl):
            self.events("step", address, f"Traceroute, hop {ttl}")
            return self.echo(address, ttl)

        traces = []
        with ThreadPoolExecutor(max_workers=self.settings.workers) as executor:
            futures = {}
            for address, reason in targets:
                futures[executor.submit(l3.trace, address, echo, should_stop=self.should_stop)] = (address, reason)
                self.events("started", address, None)
            for number, future in enumerate(as_completed(futures), start=1):
                address, reason = futures[future]
                try:
                    hops, reached = future.result()
                except OSError as error:  # No ICMP (a locked-down laptop): the map is still worth having
                    log.warning("Couldn't trace %s: %s", address, error)
                    self.events("finished", address, "traced")
                    self.events("log", f"Traceroute to {address} failed: {error}")
                    continue
                traces.append(Trace(address, hops, reached, reason))
                self.events("finished", address, "traced")
                self.events("log", f"Traced {address} ({reason}): " + " > ".join(hop or "*" for hop in hops)
                            + ("" if reached else " (not reached)"))
                self.progress(f"Traced {number} of {len(targets)}: {address}")
        self.map.traces = sorted(traces, key=lambda item: ipaddress.ip_address(item.target))
        self.map.stopped = self.should_stop()

    def connect(self, address):
        """Find the community string (or SNMPv3 user) a device answers to. Returns (client, SystemInfo, community),
        or Nones when it answers none of them (or the crawl is stopping)."""
        communities = self.communities_for(address)
        for number, community in enumerate(communities, start=1):
            if self.should_stop():
                break
            self.events("step", address, f"Trying {credential_kind(community)} {number} of {len(communities)}")
            try:
                client = self.client_factory(address, community, self.settings.version,
                                             timeout=self.settings.timeout, retries=self.settings.retries)
                info = collect.system_info(client.get([parse_oid(collect.SYS_DESCR), parse_oid(collect.SYS_OBJECT_ID),
                                                       parse_oid(collect.SYS_NAME)]))
                self.events("community", address, community)
                return client, info, community
            except (SnmpError, OSError) as problem:
                log.debug("SNMP to %s: %s", address, problem)
                if is_v3(community) and "No answer" not in str(problem):  # A Report: say what the device said
                    self.events("log", str(problem))  # It names the device
                else:
                    self.events("log", f"{address}: no answer with {credential_kind(community)} {number} of "
                                       f"{len(communities)}")
        return None, None, None

    def visit(self, address, compare=()):
        """Read one device. Returns (DeviceTables or None, error). Runs on a worker thread. compare: identities of
        devices read already that it may be (its name's): when it's one of them, only enough to tell is read."""
        started = time.monotonic()
        client, info, community = self.connect(address)
        if client is None:
            if self.should_stop():
                return None, STOPPED
            self.events("step", address, "Pinging")
            return None, PINGS_NO_SNMP if self.pinger(address) else NO_ANSWER
        tables = collect.DeviceTables(info=info)
        tables.timings["Finding the community string"] = time.monotonic() - started
        if compare:
            tables.addresses = collect.ip_addresses(self.walk(client, collect.IP_ADDR_ENTRY, tables, "IP addresses"))
            tables.own_macs = collect.own_macs(self.walk(client, collect.IF_PHYS_ADDRESS, tables, "Interfaces"))
            if any(same_device(identity(tables), other) for other in compare):
                tables.timings["total"] = time.monotonic() - started
                return tables, ""
        self.read_tables(client, tables, community)
        tables.timings["total"] = time.monotonic() - started
        return tables, ""

    def walk(self, client, root, tables, what, limit=None, timing=None):
        """Walk one table (or column), noting the time it took under timing (or what) for the crawl log."""
        self.events("step", client.host, what)
        started = time.monotonic()
        try:
            options = {"limit": limit} if limit else {}
            return list(client.walk(parse_oid(root), max_repetitions=BULK_ROWS, should_stop=self.should_stop,
                                    **options))
        except (SnmpError, OSError) as problem:
            tables.warnings.append(f"{what}: {problem}")
            return []
        finally:
            step = timing or what
            tables.timings[step] = tables.timings.get(step, 0) + time.monotonic() - started

    def read_tables(self, client, tables, community):
        tables.interfaces = collect.interface_names(
            self.walk(client, collect.IF_NAME, tables, "Interface names", timing="Interfaces"),
            self.walk(client, collect.IF_DESCR, tables, "Interfaces"))
        tables.addresses = collect.ip_addresses(self.walk(client, collect.IP_ADDR_ENTRY, tables, "IP addresses"))
        tables.neighbors = collect.cdp_neighbors(self.walk(client, collect.CDP_CACHE_ENTRY, tables, "CDP",
                                                           timing="Neighbors"), tables.interfaces)
        lldp_rows = self.walk(client, collect.LLDP_REM_ENTRY, tables, "LLDP", timing="Neighbors")
        if lldp_rows:
            local_ports = collect.lldp_local_ports(self.walk(client, collect.LLDP_LOC_PORT_ENTRY, tables, "LLDP",
                                                             timing="Neighbors"))
            addresses = collect.lldp_management_addresses(
                self.walk(client, collect.LLDP_REM_MAN_ADDR_IF_SUBTYPE, tables, "LLDP", timing="Neighbors"))
            inventory = hardware.med_inventory(self.walk(client, hardware.LLDP_MED_INVENTORY_ENTRY, tables,
                                                         "LLDP-MED inventory", timing="Neighbors"))
            tables.neighbors += collect.lldp_neighbors(lldp_rows, local_ports, tables.interfaces, addresses,
                                                       inventory)
        tables.arp = collect.arp(self.walk(client, collect.ARP_PHYS_ADDRESS, tables, "ARP", timing="ARP table"))
        self.read_port_status(client, tables)
        self.read_tunnels(client, tables)
        self.read_routes(client, tables)
        self.read_vlans(client, tables)
        if aruba.is_controller(tables.info.object_id, tables.info.descr):
            self.read_wireless(client, tables)
        if self.settings.read_inventory:
            self.read_inventory(client, tables)
        tables.lag_parents = collect.lag_parents(
            self.walk(client, collect.IF_STACK_STATUS, tables, "Port-channels", timing="Interfaces"),
            self.walk(client, collect.LAG_ATTACHED, tables, "Port-channels", timing="Interfaces"))
        if not self.settings.collect_hosts:
            return
        if tables.interface_macs:  # Read with its hardware
            tables.own_macs = set(tables.interface_macs.values())
        else:
            tables.own_macs = collect.own_macs(self.walk(client, collect.IF_PHYS_ADDRESS, tables, "Interfaces"))
        info = tables.info
        vlan_list = sorted(tables.vlan_names) if info.object_id.startswith(collect.CISCO + ".") else []
        if vlan_list and "nx-os" not in info.descr.lower():
            if self.read_vlan_tables(client, tables, community, vlan_list):
                return
            tables.notes.append("No per-VLAN MAC tables (community@vlan or SNMPv3 vlan- contexts): read its one "
                                "MAC table instead")
        self.read_mac_table(client, tables)

    def read_inventory(self, client, tables):
        """Its chassis (each stack member's) and parts, with their models and serial numbers, from ENTITY-MIB, and
        the software version it runs. Only the class, containment and serial columns are walked: the rows worth
        having (chassis, and parts with a serial) are then asked for by GET, unless there are so many that walking
        the other columns is quicker."""
        tables.inventory_read = True
        entry = hardware.ENT_PHYSICAL_ENTRY
        class_rows = self.walk(client, f"{entry}.{hardware.CLASS}", tables, "Hardware", timing="Inventory")
        contained_rows, serial_rows, detail_rows = [], [], []
        if class_rows:
            contained_rows = self.walk(client, f"{entry}.{hardware.CONTAINED_IN}", tables, "Hardware",
                                       timing="Inventory")
            serial_rows = self.walk(client, f"{entry}.{hardware.SERIAL}", tables, "Serial numbers",
                                    timing="Inventory")
            chosen = hardware.chosen_indexes(class_rows, serial_rows, contained_rows)
            requests = -(-len(chosen) * len(hardware.DETAIL_COLUMNS) // hardware.GET_BATCH)
            walks = len(hardware.DETAIL_COLUMNS) * -(-len(class_rows) // BULK_ROWS)
            if chosen and walks < requests:
                for number in hardware.DETAIL_COLUMNS:
                    detail_rows += self.walk(client, f"{entry}.{number}", tables, "Models", timing="Inventory")
            elif chosen:
                detail_rows = self.get_many(client, hardware.detail_oids(chosen), tables, "Models",
                                            timing="Inventory")
        tables.parts = hardware.parts(class_rows, contained_rows, serial_rows, detail_rows)
        vendor_version = ""
        scalars = hardware.vendor_scalars(tables.info.object_id)
        if scalars is not None:
            found = {oid_text(oid): value for oid, value in
                     self.get_many(client, [parse_oid(oid) for oid in scalars if oid], tables, "Software version",
                                   timing="Inventory")}
            vendor_version = collect.text(found.get(scalars[0])) if scalars[0] else ""
            serial = hardware.clean(collect.text(found.get(scalars[1])))
            if serial and not any(part["serial"] for part in hardware.chassis(tables.parts)):
                model = tables.wireless.model if tables.wireless is not None else ""
                tables.parts.insert(0, hardware.blank_chassis(serial, model))
        tables.software = hardware.device_software(tables.info.descr, tables.parts, vendor_version)
        self.read_base_macs(client, tables)

    def read_wireless(self, client, tables):
        """A wireless controller's access points (each one's name, address, model, serial number, software and
        whether it's up) and the Wi-Fi clients on them (MAC, address, name, AP, SSID and VLAN). Only the columns
        wanted are walked: a controller's tables have dozens of counters."""
        def walk(entry, numbers, what):
            rows = []
            for number in numbers:
                rows += self.walk(client, f"{entry}.{number}", tables, what, timing="Wireless")
            return rows
        ap_rows = walk(aruba.AP_ENTRY, aruba.AP_COLUMNS, "Access points")
        access_points = aruba.access_points(ap_rows)
        found = aruba.Controller(aps=access_points, model=aruba.controller_model(tables.info.descr))
        if self.settings.collect_hosts:
            found.clients = aruba.clients(walk(aruba.STATION_ENTRY, aruba.STATION_COLUMNS, "Wi-Fi clients"),
                                          walk(aruba.USER_ENTRY, aruba.USER_COLUMNS, "Wi-Fi clients"),
                                          self.walk(client, aruba.BSSID_ESSID, tables, "Wi-Fi clients",
                                                    timing="Wireless"), access_points)
        tables.wireless = found
        up = sum(1 for item in access_points if item.up)
        tables.notes.append(f"Wireless controller: {len(access_points)} access points ({up} up)"
                            + (f", {len(found.clients)} Wi-Fi clients" if self.settings.collect_hosts else ""))

    def read_base_macs(self, client, tables):
        """Each chassis' MAC (hardware.set_chassis_macs) and the device's base MAC: a stack's members' from
        CISCO-STACKWISE-MIB, a device's own from its LLDP chassis ID or bridge address, or (with neither) the MAC of
        the interface it was asked on."""
        members = hardware.chassis(tables.parts)
        stack = {}
        if len(members) > 1 and tables.info.object_id.startswith(collect.CISCO + "."):
            stack = hardware.stack_macs(self.walk(client, hardware.STACK_MAC, tables, "Base MACs", timing="Inventory"))
        oids = [hardware.LLDP_LOC_CHASSIS_SUBTYPE, hardware.LLDP_LOC_CHASSIS_ID]
        values = {oid_text(oid): value for oid, value in
                  self.get_many(client, [parse_oid(oid) for oid in oids], tables, "Base MAC", timing="Inventory")}
        tables.base_mac = hardware.base_mac(values)
        if not tables.base_mac:
            values.update((oid_text(oid), value) for oid, value in
                          self.get_many(client, [parse_oid(hardware.BRIDGE_ADDRESS)], tables, "Base MAC",
                                        timing="Inventory"))
            tables.base_mac = hardware.base_mac(values)
        if not members:
            return
        tables.interface_macs = collect.interface_macs(self.walk(client, collect.IF_PHYS_ADDRESS, tables,
                                                                 "Interfaces", timing="Inventory"))
        management = ""
        if not tables.base_mac and len(members) == 1:
            addresses = tables.addresses or collect.ip_addresses(
                self.walk(client, collect.IP_ADDR_ENTRY, tables, "IP addresses", timing="Inventory"))
            management = hardware.management_mac(client.host, addresses, tables.interface_macs)
        hardware.set_chassis_macs(tables.parts, stack, tables.base_mac, management,
                                  set(tables.interface_macs.values()))

    def get_many(self, client, oids, tables, what, timing=None):
        """GET a list of OIDs a few at a time. Values a device doesn't have come back as exceptions (and are skipped
        by the parsers); a batch it refuses is noted and left out."""
        self.events("step", client.host, what)
        started = time.monotonic()
        rows = []
        try:
            for at in range(0, len(oids), hardware.GET_BATCH):
                if self.should_stop():
                    break
                try:
                    rows += client.get(oids[at:at + hardware.GET_BATCH])
                except SnmpError as problem:  # SNMPv1 refuses a whole GET for one OID it doesn't have
                    tables.warnings.append(f"{what}: {problem}")
        except OSError as problem:
            tables.warnings.append(f"{what}: {problem}")
        finally:
            step = timing or what
            tables.timings[step] = tables.timings.get(step, 0) + time.monotonic() - started
        return rows

    def read_port_status(self, client, tables):
        """Whether each interface is up, its speed and duplex (only those not shut down are kept)."""
        admin = self.walk(client, collect.IF_ADMIN_STATUS, tables, "Port status")
        if not admin:
            return
        oper = self.walk(client, collect.IF_OPER_STATUS, tables, "Port status")
        high = self.walk(client, collect.IF_HIGH_SPEED, tables, "Port speed", timing="Port status")
        low = [] if high else self.walk(client, collect.IF_SPEED, tables, "Port speed", timing="Port status")
        duplex = self.walk(client, collect.DOT3_DUPLEX, tables, "Duplex", timing="Port status")
        tables.port_status = collect.port_status(admin, oper, high, low, duplex)
        tables.status_read = True

    def read_tunnels(self, client, tables):
        """Its tunnel interfaces' ends (TUNNEL-MIB) and, on Cisco, its IKE sessions up (CISCO-IPSEC-FLOW-MONITOR-
        MIB): what the map's tunnels are drawn from. Only asked of a device with tunnel interfaces."""
        if not any(name.lower().startswith("tu") for name in tables.interfaces.values()):
            return
        rows = []
        for number in collect.TUNNEL_IF_COLUMNS:
            rows += self.walk(client, f"{collect.TUNNEL_IF_ENTRY}.{number}", tables, "Tunnels")
        tables.tunnels = collect.tunnels(rows)
        if not tables.info.object_id.startswith(collect.CISCO + "."):
            return
        if not self.walk(client, collect.IKE_ACTIVE_COUNT, tables, "IKE sessions", timing="Tunnels"):
            return  # No CISCO-IPSEC-FLOW-MONITOR-MIB: whether IPsec is up isn't known
        rows = []
        for number in collect.IKE_TUNNEL_COLUMNS:
            rows += self.walk(client, f"{collect.IKE_TUNNEL_ENTRY}.{number}", tables, "IKE sessions",
                              timing="Tunnels")
        entry = parse_oid(collect.IKE_TUNNEL_ENTRY)
        indexes = sorted({oid[len(entry) + 1:] for oid, _ in rows if oid[:len(entry)] == entry})
        started = time.monotonic()
        for at in range(0, len(indexes), 20):  # Each session's status
            try:
                rows += client.get([entry + (collect.IKE_STATUS,) + index for index in indexes[at:at + 20]])
            except (SnmpError, OSError) as problem:
                tables.warnings.append(f"IKE sessions: {problem}")
                break
        tables.timings["Tunnels"] = tables.timings.get("Tunnels", 0) + time.monotonic() - started
        tables.ike_sessions = collect.ike_sessions(rows)
        tables.ike_read = not any(warning.startswith("IKE sessions") for warning in tables.warnings)

    def read_routes(self, client, tables):
        """The global routing table, then which interfaces are in VRFs and each VRF's routing table."""
        route_rows = []
        for column in (5, 6, 7):  # ifIndex, type, protocol: the index holds destination, mask and next hop
            route_rows += self.walk(client, f"{collect.CIDR_ROUTE_ENTRY}.{column}", tables, "Routes", ROUTE_ROWS,
                                    timing="Routing table")
        old_rows = []
        if not route_rows:
            for column in (2, 7, 8, 9, 11):
                old_rows += self.walk(client, f"{collect.IP_ROUTE_ENTRY}.{column}", tables, "Routes", ROUTE_ROWS,
                                      timing="Routing table")
        tables.routes = collect.routes(route_rows, old_rows)
        tables.routes_truncated = len(route_rows) >= 3 * ROUTE_ROWS or len(old_rows) >= 5 * ROUTE_ROWS
        self.read_vrfs(client, tables)

    def read_vrfs(self, client, tables):
        """Which interfaces are in which VRF (CISCO-VRF-MIB on Cisco, else MPLS-L3VPN-STD-MIB), and, when there are
        any, each VRF's routes (MPLS-L3VPN-STD-MIB; a device without it has its VRFs' routes noted as unread)."""
        if tables.info.object_id.startswith(collect.CISCO + "."):
            names = self.walk(client, collect.CV_VRF_NAME, tables, "VRFs")
            if names:
                tables.interface_vrfs = collect.cisco_vrf_interfaces(
                    names, self.walk(client, collect.CV_VRF_INTERFACE_ENTRY, tables, "VRFs"))
        if not tables.interface_vrfs:
            tables.interface_vrfs = collect.l3vpn_vrf_interfaces(
                self.walk(client, collect.L3VPN_IF_CLASSIFICATION, tables, "VRFs"))
        if not tables.interface_vrfs:
            return
        rows = []
        for column in collect.L3VPN_ROUTE_COLUMNS:
            rows += self.walk(client, f"{collect.L3VPN_ROUTE_ENTRY}.{column}", tables, "VRF routes", ROUTE_ROWS,
                              timing="Routing table")
        tables.vrf_routes = collect.l3vpn_routes(rows)
        unread = sorted(set(tables.interface_vrfs.values()) - set(tables.vrf_routes))
        if unread:
            tables.notes.append(f"Routes in VRF{'s' if len(unread) > 1 else ''} {', '.join(unread)} couldn't be read "
                                "(the device doesn't offer MPLS-L3VPN-STD-MIB's VRF routing tables)")

    def read_vlans(self, client, tables):
        """Its VLANs and their names, its VTP domain, and each switch port's VLANs: from CISCO-VTP-MIB and
        CISCO-VLAN-MEMBERSHIP-MIB on Cisco switches, otherwise (or when those are empty) from Q-BRIDGE-MIB."""
        if tables.info.object_id.startswith(collect.CISCO + "."):
            tables.stp_mode = collect.stp_mode(self.walk(client, collect.STP_TYPE, tables, "Spanning tree",
                                                         timing="VLANs"))
            state_rows = self.walk(client, collect.VTP_VLAN_STATE, tables, "VLANs")
            if state_rows:
                tables.vlan_names = collect.vlan_names(
                    state_rows, self.walk(client, collect.VTP_VLAN_NAME, tables, "VLAN names", timing="VLANs"))
                domain_rows = []
                for number in (2, 3):  # Name and mode
                    domain_rows += self.walk(client, f"{collect.VTP_DOMAIN_ENTRY}.{number}", tables, "VTP domain",
                                             timing="VLANs")
                tables.vtp_domain, tables.vtp_mode = collect.vtp_domain(domain_rows)
                trunk_rows = []
                for number in (collect.TRUNK_STATUS, collect.TRUNK_NATIVE, *collect.TRUNK_ALLOWED_COLUMNS):
                    trunk_rows += self.walk(client, f"{collect.TRUNK_PORT_ENTRY}.{number}", tables, "Trunks",
                                            timing="VLANs")
                tables.port_vlans = collect.cisco_port_vlans(
                    trunk_rows, self.walk(client, collect.VM_VLAN, tables, "Access ports' VLANs", timing="VLANs"),
                    self.walk(client, collect.VM_VOICE_VLAN, tables, "Voice VLANs", timing="VLANs"))
        if not tables.vlan_names:
            tables.vlan_names = collect.q_vlan_names(self.walk(client, collect.Q_VLAN_STATIC_NAME, tables,
                                                               "VLAN names (Q-BRIDGE)", timing="VLANs"))
            if tables.vlan_names:
                base_ports = self.walk(client, collect.BASE_PORT_IFINDEX, tables, "Bridge ports", timing="VLANs")
                tables.port_vlans = collect.q_port_vlans(
                    self.walk(client, collect.Q_PVID, tables, "Ports' VLANs", timing="VLANs"),
                    self.walk(client, collect.Q_VLAN_EGRESS, tables, "VLAN members", timing="VLANs"),
                    self.walk(client, collect.Q_VLAN_UNTAGGED, tables, "VLAN members", timing="VLANs"), base_ports)
        tables.vlans_in_use = collect.ports_vlans_in_use(tables.port_vlans)

    def read_mac_table(self, client, tables):
        """The MAC table of a switch that keeps one for every VLAN (NX-OS, most non-Cisco switches)."""
        base_ports = self.walk(client, collect.BASE_PORT_IFINDEX, tables, "MAC table", timing="MAC tables")
        q_rows = []
        for column in (2, 3):  # Port and status: the index holds the VLAN and the MAC
            q_rows += self.walk(client, f"{collect.Q_FDB_ENTRY}.{column}", tables, "MAC table by VLAN",
                                timing="MAC tables")
        if not collect.fdb_by_vlan(q_rows, base_ports):
            for column in (2, 3):
                q_rows += self.walk(client, f"{collect.FDB_ENTRY}.{column}", tables, "MAC table",
                                    timing="MAC tables")
        tables.fdb = collect.fdb_by_vlan(q_rows, base_ports) or collect.fdb(q_rows, base_ports)

    def read_vlan_tables(self, client, tables, community, vlan_list):
        """Catalyst IOS keeps a MAC table per VLAN, read with community@vlan (or, over SNMPv3, in context vlan-N).
        Only the VLANs its ports use (a VTP domain can list hundreds the switch doesn't carry), several at once.
        Returns whether any VLAN answered (some images, and v3 users without the vlan- context, have none)."""
        in_use = tables.vlans_in_use  # Read with its VLANs (read_vlans)
        chosen = [vlan for vlan in vlan_list if vlan in in_use] if in_use else vlan_list
        if len(chosen) < len(vlan_list):
            tables.notes.append(f"MAC tables for the {len(chosen)} of {len(vlan_list)} VLANs its ports use "
                                f"({', '.join(str(vlan) for vlan in chosen[:12])}{'...' if len(chosen) > 12 else ''})")
        started = time.monotonic()
        done = [0]

        def read(vlan):
            if self.should_stop():
                return None
            try:
                vlan_client = self.vlan_client(client, community, vlan)
                rows = []
                for column in (2, 3):  # Port and status: the MAC is in the index
                    rows += list(vlan_client.walk(parse_oid(f"{collect.FDB_ENTRY}.{column}"),
                                                  max_repetitions=BULK_ROWS, should_stop=self.should_stop))
                ports = list(vlan_client.walk(parse_oid(collect.BASE_PORT_IFINDEX), max_repetitions=BULK_ROWS,
                                              should_stop=self.should_stop))
            except (SnmpError, OSError):
                return None  # A VLAN with no ports here doesn't answer on some models
            finally:
                done[0] += 1
                self.events("step", client.host, f"MAC tables: {done[0]} of {len(chosen)} VLANs read")
            return collect.fdb(rows, ports, vlan)

        answered = False
        with ThreadPoolExecutor(max_workers=VLAN_WORKERS) as executor:
            for entries in executor.map(read, chosen):
                if entries is not None:
                    answered = True
                    tables.fdb += entries
        tables.timings["MAC tables"] = tables.timings.get("MAC tables", 0) + time.monotonic() - started
        return answered

    def vlan_client(self, client, community, vlan):
        """A client for one VLAN's BRIDGE-MIB on a Catalyst: community@vlan, or over SNMPv3 the context vlan-N."""
        if is_v3(community):
            return self.client_factory(client.host, community, self.settings.version, timeout=self.settings.timeout,
                                       retries=self.settings.retries, context=f"vlan-{vlan}")
        return self.client_factory(client.host, f"{community}@{vlan}", self.settings.version,
                                   timeout=self.settings.timeout, retries=self.settings.retries)

    def read_stp(self, client, tables, community, vlan):
        """Whether each port forwards or blocks in one VLAN's spanning tree (for Carry VLAN): on Rapid-PVST and MST
        from CISCO-STP-EXTENSIONS-MIB's port roles (MST: in the instance the VLAN is mapped to), on PVST+ from
        BRIDGE-MIB read in the VLAN's context. Needs read_vlans first (its STP mode and VLANs)."""
        tables.stp_read = True
        mode = tables.stp_mode
        base_ports = collect.base_port_ifindexes(self.walk(client, collect.BASE_PORT_IFINDEX, tables, "Bridge ports",
                                                           timing="STP"))
        vlan_client = None
        if vlan in tables.vlan_names and tables.info.object_id.startswith(collect.CISCO + "."):
            try:
                vlan_client = self.vlan_client(client, community, vlan)
                # On a Catalyst the plain community's bridge ports are VLAN 1's: add the VLAN's own
                base_ports = {**collect.base_port_ifindexes(list(vlan_client.walk(
                    parse_oid(collect.BASE_PORT_IFINDEX), max_repetitions=BULK_ROWS, should_stop=self.should_stop))),
                              **base_ports}
            except (SnmpError, OSError) as problem:
                tables.warnings.append(f"VLAN {vlan} bridge ports: {problem}")
                vlan_client = None
        if mode in ("rapid-pvst", "mst"):
            instance = vlan
            if mode == "mst":
                instance = collect.mst_instance_of(self.walk(client, collect.MST_INSTANCE_ENTRY, tables,
                                                             "MST instances", timing="STP"), vlan)
                if instance < 0:
                    return
            tables.stp_instance = instance
            tables.stp_ports = collect.rstp_port_roles(
                self.walk(client, collect.RSTP_PORT_ROLE, tables, "STP port roles", timing="STP"), instance, base_ports)
            if tables.stp_ports:  # No root port: it's the root bridge
                tables.stp_root = not any(role == "root" for _, role in tables.stp_ports.values())
            if tables.stp_ports or mode == "mst":
                return
        if vlan_client is not None:  # PVST+ (or Rapid-PVST without the role table): the VLAN's own BRIDGE-MIB
            try:
                rows = list(vlan_client.walk(parse_oid(collect.STP_PORT_STATE), max_repetitions=BULK_ROWS,
                                             should_stop=self.should_stop))
            except (SnmpError, OSError) as problem:
                tables.warnings.append(f"VLAN {vlan} spanning tree: {problem}")
                return
            tables.stp_instance = vlan
            tables.stp_ports = collect.stp_port_states(rows, base_ports)
            try:
                tables.stp_root = collect.stp_root(list(vlan_client.walk(
                    parse_oid(collect.STP_ROOT_PORT), max_repetitions=BULK_ROWS, should_stop=self.should_stop)))
            except (SnmpError, OSError):
                pass  # Which ports block is what matters

    # ----------------------------------------------------------------- Putting results on the map

    def find(self, address="", name=""):
        """The key of the device with this address, or this name (unless more than one device has it)."""
        if self.aliases.get(address):
            return self.aliases[address]
        base = normalize_name(name) if name else ""
        return self.aliases.get(base) if base and base not in self.ambiguous else None

    def current_key(self, key, address):
        """A queued visit's key now: the device may have been merged into another, or keyed by address."""
        if key is None or key in self.map.devices:
            return key
        return self.renamed[key] if self.renamed.get(key) in self.map.devices else self.find(address)

    def new_key(self, name, address="", seen_on=None):
        """The key for a device first seen now: its name, or when more than one device has that name, its name and
        address (or where it was seen, (device key, port), if it gave no address)."""
        base = normalize_name(name)
        if not base or base not in self.ambiguous:
            return base
        if address:
            return f"{base}@{address}"
        return f"{base}@{seen_on[0]}/{short_port(seen_on[1])}" if seen_on else base

    def qualified_key(self, base, device):
        """new_key's form for a device found before its name turned out to be shared."""
        address = device.mgmt_ip or (device.addresses[0] if device.addresses else "")
        if address:
            return f"{base}@{address}"
        link = next(iter(self.map.links_of(device.key)), None)
        if link is None:
            return f"{base}@{device.key}"
        far = link.other(device.key)
        return f"{base}@{far}/{link.port_on(far)}"

    def rename(self, old, new):
        """Key device old as new, everywhere the crawl keeps it. Returns new."""
        device = self.map.devices.pop(old)
        device.key = new
        self.map.devices[new] = device
        for link in self.map.links:
            link.a, link.b = (new if link.a == old else link.a), (new if link.b == old else link.b)
        for alias, key in self.aliases.items():
            if key == old:
                self.aliases[alias] = new
        for table in (self.tables, self.capabilities):
            if old in table:
                table[new] = table.pop(old)
        self.advertised = {(new if key == old else key, port): address
                           for (key, port), address in self.advertised.items()}
        self.renamed[old] = new
        return new

    def namesakes(self, key, name=""):
        """Devices read in this crawl that device key (or one named name) could turn out to be: key itself, if it
        was read, and those with its name."""
        device = self.map.devices.get(key) if key is not None else None
        base = normalize_name(name or (device.name if device is not None else ""))
        return [other for other in self.tables if other in self.map.devices
                and (other == key or (base and normalize_name(self.map.devices[other].name) == base))]

    def known_identity(self, key):
        """identity() of a device read before on the map this crawl adds to, or None."""
        device = self.known.devices.get(key) if self.known is not None and key else None
        if device is None or device.source != SNMP or device.manual:
            return None
        return {item[0] for item in device.interfaces_l3}, set()

    def another_named(self, first, key, address, tables):
        """The device read at address has the name of device first (read already) but isn't it: two devices with
        one name (switches left named "Switch", or sw1.site-a and sw1.site-b). Both are keyed by address, so neither
        key depends on which was read first, and the links its neighbors drew to first by name move to it. key: the
        one its visit was queued under. Returns its key."""
        base = normalize_name(tables.info.name)
        first_device = self.map.devices.get(first) or self.known.devices[first]
        if base and normalize_name(first_device.name) == base:
            self.ambiguous.add(base)
            if first == base and first in self.tables:
                first = self.rename(first, self.qualified_key(base, first_device))
                key = self.renamed.get(key, key)
            new = f"{base}@{address}"
        else:  # Found by an address a neighbor gave for first: it has a name of its own
            new = self.new_key(tables.info.name, address) or f"ip:{address}"
        mine = {ip for ip, _, _ in tables.addresses} | {address}
        for ip in mine:
            self.aliases[ip] = new
        links, self.map.links = self.map.links, []
        for link in links:
            for end, far, far_port in (("a", link.b, link.b_port), ("b", link.a, link.a_port)):
                if getattr(link, end) in (first, key) and self.advertised.get((far, port_key(far_port))) in mine:
                    setattr(link, end, new)
            if link.a != link.b:
                self.map.add_link(link)
        return new

    def unaddressed_neighbor(self, other, key, neighbor):
        """A neighbor that gave no address, found by name as device other. Unless the port it's on has a link to
        somewhere else already: a port links to one place, so it's another device with that name. Returns its
        key."""
        if not neighbor.port:
            return other
        for link in self.map.links_of(other):
            far = link.other(other)
            if far != other and port_key(link.port_on(other)) == port_key(neighbor.port) \
                    and (far, port_key(link.port_on(far))) != (key, port_key(neighbor.local_port)):
                break
        else:
            return other
        base = normalize_name(neighbor.name)
        self.ambiguous.add(base)
        if other == base:
            self.rename(other, self.qualified_key(base, self.map.devices[other]))
        return self.new_key(neighbor.name, "", (key, neighbor.local_port))

    def found_address(self, key, address):
        """The address to note on a device as found: not one it was only asked at because it was corrected by
        hand (that's put back at the end, as a correction over what the crawl found)."""
        return "" if address == self.settings.corrections.get(key, {}).get("mgmt_ip") else address

    def add_device(self, key, **details):
        device = self.map.devices.get(key)
        if device is None:
            device = self.map.devices[key] = Device(key=key)
        for attribute, value in details.items():
            if value and not getattr(device, attribute):
                setattr(device, attribute, value)
        if device.mgmt_ip:
            self.aliases.setdefault(device.mgmt_ip, key)
        if device.name:
            self.aliases.setdefault(normalize_name(device.name), key)
        return device

    def merge(self, old, new):
        """Fold device old into new: its links, addresses and anything new doesn't know yet."""
        gone = self.map.devices.pop(old)
        target = self.map.devices[new]
        for attribute in ("name", "mgmt_ip", "platform", "software", "serial", "mac"):
            if not getattr(target, attribute):
                setattr(target, attribute, getattr(gone, attribute))
        links, self.map.links = self.map.links, []
        for link in links:
            link.a, link.b = (new if link.a == old else link.a), (new if link.b == old else link.b)
            if link.a != link.b:
                self.map.add_link(link)
        for alias, key in self.aliases.items():
            if key == old:
                self.aliases[alias] = new
        self.capabilities.setdefault(new, set()).update(self.capabilities.pop(old, ()))

    def record(self, address, hops, key, tables, error):
        """Put a visit's results on the map. Returns the neighbors to visit next as [(address, hops, key)]."""
        self.completed.add(address)
        if tables is None:
            key = key or self.find(address) or f"ip:{address}"
            device = self.add_device(key, mgmt_ip=self.found_address(key, address))
            if error == STOPPED:
                self.events("finished", address, "stopped")
            elif device.source != SNMP:
                outcome = NO_SNMP if error == PINGS_NO_SNMP else UNREACHABLE
                pending = any(ip not in self.completed and self.current_key(self.aliases.get(ip), ip) == key
                              for ip in self.asked)
                previous = device.source
                if outcome == NO_SNMP:
                    device.source, device.error = NO_SNMP, PINGS_NO_SNMP
                    if self.found_address(key, address):
                        device.mgmt_ip = address  # Prefer an address that actually answered ping
                elif device.source != NO_SNMP and not pending:
                    device.source, device.error = UNREACHABLE, error
                device.hops = hops
                if previous != device.source:
                    for source, counter in ((NO_SNMP, "no_snmp"), (UNREACHABLE, "unreachable")):
                        self.counts[counter] += int(device.source == source) - int(previous == source)
                self.events("finished", address, outcome)
                self.events("log", f"{device.label}: {error}")
            return []

        info = tables.info
        existing = self.find(address, info.name)
        # Devices read already that it may be: the one at this address, and those with its name. It's one of them
        # if their IP addresses overlap (an SNMP agent gives the same table at each of its addresses).
        read = list(dict.fromkeys(([existing] if existing in self.tables else []) + self.namesakes(key, info.name)))
        same = next((other for other in read if same_device(identity(self.tables[other]), identity(tables))), None)
        if same is not None:
            if key is not None and key != same and key in self.map.devices and self.map.devices[key].source != SNMP:
                self.merge(key, same)  # A neighbor's view of it, under another key
            self.aliases[address] = same
            self.events("finished", address, "again")
            self.events("log", f"{address} is {self.map.devices[same].label} again (another of its addresses)")
            return []  # Reached the same device at a second address
        before = next((other for other in (key, existing) if self.known_identity(other) is not None), None)
        if before is not None and same_device(self.known_identity(before), identity(tables)):
            before = None  # On the map this crawl adds to: read again under its key
        if read or before is not None:
            key = self.another_named(read[0] if read else before, key, address, tables)
        elif key is None:
            key = existing or self.new_key(info.name, address) or f"ip:{address}"
        elif existing and existing != key:
            self.merge(key, existing)  # Found under two names (a neighbor's view, and its own sysName)
            key = existing
        device = self.add_device(key)
        if device.source in (NO_SNMP, UNREACHABLE):
            self.counts["no_snmp" if device.source == NO_SNMP else "unreachable"] -= 1
        answered_at = self.found_address(key, address)
        if answered_at:  # Where it answered SNMP, over an address a neighbor advertised (which may not answer)
            device.mgmt_ip = answered_at
            self.aliases.setdefault(answered_at, key)
        device.name = info.name or device.name  # Its own sysName over how a neighbor wrote it
        device.source, device.error, device.hops = SNMP, "", hops
        device.sys_descr, device.sys_object_id = info.descr, info.object_id
        device.addresses = [ip for ip, _, _ in tables.addresses] or [address]
        device.interfaces_l3 = [[ip, prefix_length(mask), tables.interfaces.get(if_index, "")]
                                for ip, if_index, mask in tables.addresses]
        routes = [[destination, next_hop, tables.interfaces.get(if_index, ""), protocol]
                  for destination, next_hop, if_index, protocol in tables.routes]
        device.routes = routes[:MAX_ROUTES]
        device.routes_truncated = len(routes) > MAX_ROUTES or tables.routes_truncated
        device.vtp_domain, device.vtp_mode = tables.vtp_domain, tables.vtp_mode
        device.vlans = [[vlan, name] for vlan, name in sorted(tables.vlan_names.items())]
        device.port_vlans = vlans.device_port_vlans(tables, short_port)
        device.port_channels = vlans.device_port_channels(tables, short_port)
        device.stp_mode = tables.stp_mode
        device.port_status = port_status_of(tables)
        apply_vrfs(device, tables)
        apply_tunnels(device, tables)
        apply_inventory(device, tables)
        for ip in device.addresses:
            self.aliases.setdefault(ip, key)
        device.kind = collect.classify(info.object_id, info.descr, frozenset(self.capabilities.get(key, ())),
                                       device.platform, switchports=bool(tables.port_vlans))
        if tables.wireless is not None:
            self.add_access_points(key, hops, tables.wireless)
        if tables.warnings:
            log.info("%s: %s", device.label, "; ".join(tables.warnings))
            for warning in tables.warnings:
                self.events("log", f"{device.label}: couldn't read {warning}")
        if device.routes_truncated:
            self.events("log", f"{device.label}: only the first {len(device.routes):,} routes were kept")
        self.tables[key] = tables
        self.counts["read"] += 1
        self.events("finished", address, SNMP)
        self.events("log", f"Read {device.label} ({address}){timing_summary(tables.timings)}: "
                           f"{collect_summary(device, tables)}")
        for note in tables.notes:
            self.events("log", f"{device.label}: {note}")

        next_visits = []
        for neighbor in tables.neighbors:
            kind = collect.neighbor_kind(neighbor)
            if kind in END_DEVICE_KINDS:
                continue  # Placed on its port as a host at the end
            other = self.find(neighbor.address, neighbor.name) \
                or self.new_key(neighbor.name, neighbor.address, (key, neighbor.local_port))
            if other == key:
                continue
            if not neighbor.address and other in self.map.devices and self.map.devices[other].source != SNMP:
                other = self.unaddressed_neighbor(other, key, neighbor)
            if other in self.deleted or (neighbor.address and neighbor.address in self.deleted_addresses):
                if other not in self.left_out:
                    self.left_out.add(other)
                    self.events("log", f"Left out {display_name(neighbor.name) or neighbor.address} (seen on "
                                       f"{device.label}): it was deleted from the map")
                continue
            corrected = self.settings.corrections.get(other, {})  # By hand, on the map before
            found_kind, kind = kind, corrected.get("kind", kind)  # What to note, and what decides whether it's asked
            address = corrected.get("mgmt_ip") or neighbor.address
            fresh = other not in self.map.devices
            on_map = self.known is not None and other in self.known.devices  # From the map being added to
            known = not fresh or on_map
            if address != neighbor.address:
                self.aliases.setdefault(address, other)
            other_device = self.add_device(other, name=display_name(neighbor.name), mgmt_ip=neighbor.address,
                                           platform=neighbor.platform,
                                           software=hardware.neighbor_software(neighbor.version),
                                           serial=neighbor.serial or hardware.serial_in_name(neighbor.name),
                                           mac=neighbor.chassis_mac)
            if neighbor.address:
                self.aliases.setdefault(neighbor.address, other)
                if other_device.source != SNMP and neighbor.address not in other_device.addresses:
                    other_device.addresses.append(neighbor.address)
            if fresh:  # What the map says it is, if it's on it (an access point's port isn't an uplink)
                other_device.kind = found_kind
                if on_map:  # What the crawl found it to be before (the correction goes back on at the end)
                    before = self.known.devices[other]
                    other_device.kind = before.corrected.get("kind", [before.kind])[0]
                other_device.hops = hops + 1
            self.capabilities.setdefault(other, set()).update(neighbor.capabilities)
            self.map.add_link(Link(key, short_port(neighbor.local_port), other, short_port(neighbor.port),
                                   [neighbor.protocol]))
            if address:
                self.advertised[(key, port_key(neighbor.local_port))] = address
            # Read already, unless found by name at an address it doesn't have: maybe another device with its name
            if (other_device.source == SNMP and (not address or other_device.owns(address))) \
                    or (address and address in self.asked):
                continue
            name = f"{other_device.label} ({address})" if address else other_device.label
            if not known:
                self.events("log", f"Found {name} through {neighbor.protocol.upper()} on {device.label} "
                                   f"{short_port(neighbor.local_port)}")
            why_not = ""
            if not address:
                why_not = "it didn't announce a management address"
            elif not self.in_scope(address):
                why_not = "it's outside the scope"
            elif hops + 1 > self.settings.max_hops:
                why_not = f"it's more than {self.settings.max_hops} hops from the start"
            elif kind not in NETWORK_KINDS | {UNKNOWN}:
                why_not = f"it's {'an access point' if kind == AP else 'not a network device'}: shown, not asked"
            elif len(self.asked) >= self.settings.max_devices:
                if not self.limit_logged:
                    self.events("log", f"Reached the limit of {self.settings.max_devices} devices: no more will "
                                       "be asked (change it under Scope)")
                    self.limit_logged = True
                continue
            if why_not:
                if not known:
                    self.events("log", f"Not asking {name}: {why_not}")
                continue
            self.asked.add(address)
            if other_device.source == UNREACHABLE:
                other_device.source, other_device.error = NEIGHBOR, ""
                self.counts["unreachable"] -= 1
            next_visits.append((address, hops + 1, other))
        return next_visits

    def add_access_points(self, key, hops, found):
        """Put a wireless controller's access points on the map. One a switch's LLDP has put there already (matched
        by its MAC, which is its LLDP chassis ID, then by its address or name) gets what the controller knows of it;
        the rest are added, and laid out beside the controller. An AP two controllers list (a cluster, or a
        conductor and its controller) is the one that has it up's."""
        controller = self.map.devices[key]
        controller.platform = found.model or controller.platform  # Over its LLDP's whole description
        by_mac = {device.mac: other for other, device in self.map.devices.items()
                  if device.mac and device.kind in (AP, UNKNOWN) and device.source != SNMP}
        for item in found.aps:
            other = by_mac.get(item.mac) or self.find(item.ip, item.name)
            device = self.map.devices.get(other) if other else None
            if device is not None and (device.source == SNMP or device.kind not in (AP, UNKNOWN)):
                other = None  # Another device with its name (or address): not this AP
            if other is None:
                other = self.new_key(item.name, item.ip) or f"ap:{item.mac}"
                if other in self.map.devices and self.map.devices[other].kind not in (AP, UNKNOWN):
                    other = f"ap:{item.mac}"
            claimed = self.ap_controllers.get(other)
            if claimed not in (None, key) and (not item.up or self.map.devices[other].ap_status == AP_UP):
                continue  # Listed by another controller that has it up (or had it first)
            self.ap_controllers[other] = key
            fresh = other not in self.map.devices
            device = self.add_device(other, name=item.name, mgmt_ip=item.ip, mac=item.mac)
            device.kind = AP
            if fresh or device.source == NEIGHBOR:
                device.source = CONTROLLER
            if fresh:
                device.hops = hops + 1
            device.platform = item.model or device.platform
            device.serial = item.serial or device.serial
            device.software = item.software or device.software
            device.mac = item.mac
            if item.ip and item.ip not in device.addresses:
                device.addresses.append(item.ip)
                self.aliases.setdefault(item.ip, other)
            device.controller, device.ap_group = key, item.group
            device.ap_status = AP_UP if item.up else AP_DOWN

    def wireless_hosts(self, arp_table):
        """{MAC: Host} of the Wi-Fi clients the controllers read have, each on its access point (port: its SSID), or
        on the controller when its AP isn't on the map."""
        devices, found = self.map.devices, {}
        for key, tables in self.tables.items():
            if tables.wireless is None:
                continue
            ap_keys = {device.mac: other for other, device in devices.items() if device.controller == key}
            for client in tables.wireless.clients:
                place = ap_keys.get(client.ap) or (self.find("", client.ap_name) if client.ap_name else None)
                found[client.mac] = Host(mac=client.mac, device=place if place in devices else key,
                                         port=client.ssid or aruba.WIFI, ip=client.ip or arp_table.get(client.mac, ""),
                                         vendor=vendor(client.mac), vlan=client.vlan, name=client.name,
                                         controller=key, user=client.user)
        return found

    def place_hosts(self):
        """Put each MAC on the one edge port it was learned on, with its IP from the ARP tables. Phones and other end
        devices that announce themselves over CDP/LLDP get their names."""
        devices = self.map.devices
        network_macs, end_devices = set(), {}  # end_devices: (switch key, port key) -> Neighbor
        for key, tables in self.tables.items():
            if devices[key].kind in NETWORK_KINDS:
                network_macs |= tables.own_macs
            for neighbor in tables.neighbors:
                kind = collect.neighbor_kind(neighbor)
                if kind in END_DEVICE_KINDS:
                    place = (key, port_key(neighbor.local_port))
                    # A phone's CDP gives its model and firmware, its LLDP-MED its serial: one of each per port
                    end_devices[place] = combined(end_devices[place], neighbor) if place in end_devices else neighbor
                elif neighbor.chassis_mac and kind in NETWORK_KINDS:
                    network_macs.add(neighbor.chassis_mac)
        arp_table = {}
        for tables in self.tables.values():
            for mac, addresses in tables.arp.items():
                arp_table.setdefault(mac, addresses[0])
        # Wi-Fi clients are on their access point, wherever a switch learned their MAC (a controller's uplink, when
        # their traffic is tunneled to it); the controllers' APs aren't hosts on the switch ports they're plugged into
        wireless = self.wireless_hosts(arp_table)
        skip = set(wireless) | {device.mac for device in devices.values() if device.controller and device.mac}

        candidates = {}  # MAC -> [(switch key, port name, vlan, MACs on that port)]
        for key, tables in self.tables.items():
            uplinks = self.uplink_ports(key, tables, network_macs)
            learned = [(mac, short_port(tables.interfaces.get(tables.lag_parents.get(if_index, if_index),
                                                              str(if_index))), vlan)
                       for mac, if_index, vlan in tables.fdb]
            port_counts = {}
            for _, port, _ in learned:
                port_counts[port] = port_counts.get(port, 0) + 1
            for mac, port, vlan in learned:
                if port_key(port) not in uplinks and mac not in network_macs and mac not in tables.own_macs \
                        and mac not in skip:
                    candidates.setdefault(mac, []).append((key, port, vlan, port_counts[port]))

        hosts, named = [], set()
        for mac, places in candidates.items():
            key, port, vlan, _ = min(places, key=lambda place: place[3])  # Nearest: the port with fewest MACs
            host = Host(mac=mac, device=key, port=port, ip=arp_table.get(mac, ""), vendor=vendor(mac), vlan=vlan)
            neighbor = end_devices.get((key, port_key(port)))
            if neighbor is not None and mac in (end_device_mac(neighbor), neighbor.port_mac):
                host.name, host.platform = neighbor.name, neighbor.platform or neighbor.model
                host.software, host.serial = hardware.neighbor_software(neighbor.version), neighbor.serial
                host.ip = host.ip or neighbor.address
                named.add((key, port_key(port)))
            hosts.append(host)
        for (key, port), neighbor in end_devices.items():
            if (key, port) not in named:  # Its MAC wasn't in the table (or the table couldn't be read)
                mac = end_device_mac(neighbor)
                if mac in skip:
                    continue
                hosts.append(Host(mac=mac, device=key, port=short_port(neighbor.local_port), ip=neighbor.address,
                                  vendor=vendor(mac) if mac else "", name=neighbor.name,
                                  platform=neighbor.platform or neighbor.model,
                                  software=hardware.neighbor_software(neighbor.version), serial=neighbor.serial))
        hosts += wireless.values()
        hosts.sort(key=lambda host: (devices[host.device].label.lower(), port_key(host.port), host.mac))
        self.map.hosts = hosts

    def uplink_ports(self, key, tables, network_macs):
        """Ports (as port keys) leading to other network devices, whose MACs belong further along."""
        uplinks = set()
        for link in self.map.links_of(key):
            other = self.map.devices.get(link.other(key))
            if other is not None and other.kind not in (PHONE, HOST, AP, SERVER):
                uplinks.add(port_key(link.port_on(key)))
        members = {}
        for member, parent in tables.lag_parents.items():
            members.setdefault(parent, []).append(member)
        for parent, member_list in members.items():  # A port-channel is an uplink when its members are
            if any(port_key(tables.interfaces.get(member, "")) in uplinks for member in member_list):
                uplinks.add(port_key(tables.interfaces.get(parent, str(parent))))
        for mac, if_index, _ in tables.fdb:
            if mac in network_macs and mac not in tables.own_macs:
                port = tables.interfaces.get(tables.lag_parents.get(if_index, if_index), str(if_index))
                uplinks.add(port_key(port))
        return uplinks


@dataclass
class Check:
    """What asking one device (one added by hand) found: whether it answers SNMP with one of the communities, or
    only ping, or neither."""
    source: str  # SNMP, NO_SNMP or UNREACHABLE
    error: str = ""
    info: collect.SystemInfo = None
    community: object = ""  # The community string (or V3User) it answered to
    reasons: list = field(default_factory=list)  # Why it refused, when it said (an SNMPv3 user unknown, a password)

    def apply(self, device):
        """Note it on the device, as a crawl would: its sysName (if it hasn't a name), description and kind."""
        device.source, device.error = self.source, self.error
        if self.info is not None:
            device.name = device.name or self.info.name
            device.sys_descr, device.sys_object_id = self.info.descr, self.info.object_id
            device.software = hardware.software_version(self.info.descr) or device.software
            if device.kind == UNKNOWN:
                device.kind = collect.classify(self.info.object_id, self.info.descr, platform=device.platform)


def read_vlans_of(settings, address, client_factory=SnmpClient, routes=False, stp_vlan=None):
    """Read just a device's VLANs and IP interfaces (the VLAN interfaces among them), and with routes its routing
    tables (global and each VRF's), not its neighbors or tables of hosts: for a map made before NOMAD read these, or
    to bring them up to date quickly. stp_vlan: also how that VLAN's spanning tree has each port (Carry VLAN).
    Returns (DeviceTables, the community or V3User it answered to), or (None, None) when it answers none."""
    crawler = Crawler(settings, client_factory=client_factory)
    client, info, community = crawler.connect(address)
    if client is None:
        return None, None
    tables = collect.DeviceTables(info=info)
    tables.interfaces = collect.interface_names(
        crawler.walk(client, collect.IF_NAME, tables, "Interface names", timing="Interfaces"),
        crawler.walk(client, collect.IF_DESCR, tables, "Interfaces"))
    tables.addresses = collect.ip_addresses(crawler.walk(client, collect.IP_ADDR_ENTRY, tables, "IP addresses"))
    tables.lag_parents = collect.lag_parents(
        crawler.walk(client, collect.IF_STACK_STATUS, tables, "Port-channels", timing="Interfaces"),
        crawler.walk(client, collect.LAG_ATTACHED, tables, "Port-channels", timing="Interfaces"))
    crawler.read_vlans(client, tables)
    crawler.read_port_status(client, tables)
    if stp_vlan:
        crawler.read_stp(client, tables, community, stp_vlan)
    if routes:
        crawler.read_routes(client, tables)
        crawler.read_tunnels(client, tables)
        tables.routes_read = True
    return tables, community


def read_inventory_of(settings, address, client_factory=SnmpClient):
    """Read just a device's hardware and software (its chassis, parts, serial numbers and software version), not its
    neighbors or tables: Read Inventory Again. Returns (DeviceTables, the community or V3User it answered to), or
    (None, None) when it answers none."""
    crawler = Crawler(settings, client_factory=client_factory)
    client, info, community = crawler.connect(address)
    if client is None:
        return None, None
    tables = collect.DeviceTables(info=info)
    crawler.read_inventory(client, tables)
    return tables, community


def apply_inventory(device, tables):
    """Put what was read of a device's hardware on it (a crawl's, or Read Inventory Again's)."""
    if tables.inventory_read and (tables.parts or device.inventory_source != SSH_READ):
        # (Its SNMP saying nothing of its hardware doesn't undo what was read at its command line)
        device.parts = [dict(part) for part in tables.parts]
        device.inventory_read, device.inventory_source = True, ""
        members = hardware.chassis(device.parts)
        own = members[0].get("mac", "") if len(members) == 1 else ""
        device.mac = tables.base_mac or own or device.mac
    device.software = tables.software or hardware.software_version(tables.info.descr) or device.software
    if tables.info.descr:
        device.sys_descr = tables.info.descr


def apply_vlans(device, tables):
    """Put what read_vlans_of read on a device of the map (its routes too, when they were read)."""
    device.vtp_domain, device.vtp_mode = tables.vtp_domain, tables.vtp_mode
    device.vlans = [[vlan, name] for vlan, name in sorted(tables.vlan_names.items())]
    device.port_vlans = vlans.device_port_vlans(tables, short_port)
    device.port_channels = vlans.device_port_channels(tables, short_port)
    device.stp_mode = tables.stp_mode
    if tables.status_read:
        device.port_status = port_status_of(tables)
    if device.kind in (ROUTER, UNKNOWN) and tables.port_vlans and "kind" not in device.corrected:
        # A switch a crawl took for a router (its neighbors' CDP says "Router Switch"): its switchports say otherwise
        kind = collect.classify(device.sys_object_id, device.sys_descr, platform=device.platform, switchports=True)
        device.kind = kind if kind != UNKNOWN else device.kind
    if tables.addresses:
        device.interfaces_l3 = [[ip, prefix_length(mask), tables.interfaces.get(if_index, "")]
                                for ip, if_index, mask in tables.addresses]
    if tables.routes_read:
        routes = [[destination, next_hop, tables.interfaces.get(if_index, ""), protocol]
                  for destination, next_hop, if_index, protocol in tables.routes]
        device.routes = routes[:MAX_ROUTES]
        device.routes_truncated = len(routes) > MAX_ROUTES or tables.routes_truncated
        apply_vrfs(device, tables)
        apply_tunnels(device, tables)


def port_status_of(tables):
    """Device.port_status from what was read: by port's short name, in port order."""
    found = {short_port(tables.interfaces.get(if_index, str(if_index))): entry
             for if_index, entry in tables.port_status.items()}
    return dict(sorted(found.items(), key=lambda item: port_sort_key(item[0])))


def apply_vrfs(device, tables):
    """A device's VRFs as read: which of its ports are in which, and each VRF's routes (only the VRFs whose routes
    could be read are in vrf_routes)."""
    device.port_vrfs = {short_port(tables.interfaces.get(if_index, str(if_index))): vrf
                        for if_index, vrf in sorted(tables.interface_vrfs.items())}
    device.vrf_routes = {vrf: [[destination, next_hop, short_port(tables.interfaces.get(if_index, "")), protocol]
                               for destination, next_hop, if_index, protocol in routes[:MAX_ROUTES]]
                         for vrf, routes in sorted(tables.vrf_routes.items())}


def apply_tunnels(device, tables):
    """A device's tunnel interfaces' ends and its IKE sessions up, as read (netmap.tunnels draws them)."""
    device.tunnels = {short_port(tables.interfaces.get(if_index, str(if_index))):
                      {"local": local, "remote": remote, "ipsec": ipsec}
                      for if_index, (local, remote, ipsec) in sorted(tables.tunnels.items())}
    device.ike_sessions = [[local, remote] for local, remote in tables.ike_sessions]
    device.ike_read = tables.ike_read


def identity(tables):
    """What tells a device read over SNMP from another with its name: (its IP addresses, its own MACs)."""
    return {ip for ip, _, _ in tables.addresses}, set(tables.own_macs)


def same_device(one, other):
    """Whether two identities are one device. An SNMP agent gives the same tables at each of its addresses, so its
    addresses overlap (or failing those, its MACs). With nothing to compare, they're taken to be one."""
    (addresses, macs), (other_addresses, other_macs) = one, other
    if addresses and other_addresses:
        return bool(addresses & other_addresses)
    if macs and other_macs:
        return bool(macs & other_macs)
    return True


def credential_kind(credential):
    return "SNMPv3 user" if is_v3(credential) else "community"


def check_device(settings, address, client_factory=SnmpClient, pinger=None):
    """Ask one device for its system details with the communities a crawl would try; ping it if none answers.
    Returns a Check. Reads nothing else (no neighbors or tables): Crawl from Here does that."""
    said = []
    crawler = Crawler(settings, client_factory=client_factory, pinger=pinger,
                      events=lambda kind, *details: said.append(details[0]) if kind == "log" else None)
    _, info, community = crawler.connect(address)
    if info is not None:
        return Check(SNMP, "", info, community)
    reasons = [line for line in dict.fromkeys(said) if "no answer with" not in line]
    if crawler.pinger(address):
        return Check(NO_SNMP, PINGS_NO_SNMP, reasons=reasons)
    return Check(UNREACHABLE, NO_ANSWER, reasons=reasons)


def timing_summary(timings):
    """ " in 14.2 s (slowest: MAC tables 9.8 s)" for the crawl log."""
    total = timings.get("total")
    if total is None:
        return ""
    steps = {step: seconds for step, seconds in timings.items() if step != "total"}
    text = f" in {total:.1f} s"
    if steps and total >= 1:
        slowest = max(steps, key=steps.get)
        text += f" (slowest: {slowest} {steps[slowest]:.1f} s)"
    return text


def collect_summary(device, tables):
    """What was read from a device, for the crawl log."""
    parts = [KIND_NAMES.get(device.kind, device.kind).lower(), f"{len(tables.neighbors)} neighbors"]
    if tables.vlan_names:
        domain = f" (VTP domain {tables.vtp_domain}, {tables.vtp_mode})" if tables.vtp_domain else ""
        parts.append(f"{len(tables.vlan_names)} VLANs{domain}")
    if tables.fdb:
        parts.append(f"{len(tables.fdb)} MAC table entries")
    if tables.routes:
        parts.append(f"{len(tables.routes)} routes")
    chassis = hardware.chassis(tables.parts)
    if chassis:
        models = ", ".join(sorted({part["model"] for part in chassis if part["model"]}))
        text = f"{len(chassis)} chassis" if len(chassis) > 1 else "chassis"
        text += f" {models}" if models else ""
        parts.append(text + ("" if all(part["serial"] for part in chassis) else " (no serial number)"))
    if tables.software:
        parts.append(f"software {tables.software}")
    return ", ".join(parts)


def prefix_length(mask):
    try:
        return ipaddress.ip_network(f"0.0.0.0/{mask}").prefixlen
    except ValueError:
        return 32


def combined(first, second):
    """Two neighbors on one port that are one end device (its CDP and LLDP): the first, with what only the second
    said filled in."""
    merged = copy.copy(first)
    for attribute in ("address", "platform", "chassis_mac", "port_mac", "version", "serial", "model", "maker"):
        if not getattr(merged, attribute):
            setattr(merged, attribute, getattr(second, attribute))
    return merged


def end_device_mac(neighbor):
    """A phone's or computer's MAC: LLDP's chassis ID or port ID, or from a Cisco phone's CDP name (SEP followed by
    its MAC)."""
    if neighbor.chassis_mac or neighbor.port_mac:
        return neighbor.chassis_mac or neighbor.port_mac
    match = re.match(r"SEP([0-9A-Fa-f]{12})", neighbor.name)
    return format_mac(match.group(1)) if match else ""


def _ping(address):
    from ..sweep import ping_once  # Windows ICMP; imported here so the crawler itself runs anywhere
    try:
        return ping_once(address, 1000) is not None
    except OSError:
        return False


def _now():
    return datetime.datetime.now().isoformat(timespec="seconds")
