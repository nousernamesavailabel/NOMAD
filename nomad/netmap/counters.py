"""Link utilization and errors while monitoring: each poll reads the traffic and error counters of the ports at the
ends of the map's links (on the switches, routers and firewalls that answer SNMP), and the difference from the last
poll gives each port's rates. Kept in memory only: they're of the moment, not of the map."""
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from ..snmp import SnmpError, parse_oid
from . import collect
from .model import NETWORK_KINDS, SNMP, port_key, short_port

# What's read per port, in this order
COLUMNS = (collect.IF_HC_IN_OCTETS, collect.IF_HC_OUT_OCTETS, collect.IF_IN_ERRORS, collect.IF_OUT_ERRORS,
           collect.IF_IN_DISCARDS, collect.IF_OUT_DISCARDS, collect.IF_HIGH_SPEED)
PORTS_PER_GET = 6  # 42 values a request: well inside one packet
WORKERS = 16


@dataclass
class Sample:
    """One port's counters at one moment."""
    when: float
    in_octets: int
    out_octets: int
    errors: int  # In and out
    discards: int
    speed: int  # Mb/s (0: not known)


@dataclass
class Rate:
    """One port between two polls."""
    in_bps: float
    out_bps: float
    speed: int
    errors: int  # In the last interval
    discards: int
    seconds: float
    total_errors: int = 0  # Since monitoring started


def link_ports(network_map):
    """{device key: [port]} of the ports at the ends of links, on the network devices that answered SNMP."""
    found = {}
    for link in network_map.links:
        for key, port in ((link.a, link.a_port), (link.b, link.b_port)):
            device = network_map.devices.get(key)
            if device is None or device.source != SNMP or not device.mgmt_ip or device.kind not in NETWORK_KINDS:
                continue
            ports = found.setdefault(key, [])
            if port and port not in ports:
                ports.append(port)
    return found


def interface_index(client):
    """{port_key of the port's short name: ifIndex} from ifName (and ifDescr)."""
    names = collect.interface_names(list(client.walk(parse_oid(collect.IF_NAME))),
                                    list(client.walk(parse_oid(collect.IF_DESCR))))
    return {port_key(short_port(name)): if_index for if_index, name in names.items()}


def number(value):
    return value.value if value is not None and isinstance(value.value, int) else None


def read_samples(client, wanted, clock=time.monotonic):
    """{port key: Sample} for {port key: ifIndex}, a few ports a request. A port whose traffic counters didn't
    answer is left out."""
    found = {}
    items = list(wanted.items())
    for start in range(0, len(items), PORTS_PER_GET):
        chunk = items[start:start + PORTS_PER_GET]
        oids = [parse_oid(f"{column}.{if_index}") for _, if_index in chunk for column in COLUMNS]
        values = dict(client.get(oids))
        when = clock()
        for key, if_index in chunk:
            read = [number(values.get(parse_oid(f"{column}.{if_index}"))) for column in COLUMNS]
            in_octets, out_octets, in_errors, out_errors, in_discards, out_discards, speed = read
            if in_octets is None or out_octets is None:
                continue
            found[key] = Sample(when, in_octets, out_octets, (in_errors or 0) + (out_errors or 0),
                                (in_discards or 0) + (out_discards or 0), speed or 0)
    return found


def poll(targets, indexes, client_factory, workers=WORKERS):
    """Read every target's linked ports: targets [(device key, address, credential, version, timeout, [port])];
    indexes {device key: interface_index} read before (a device's is read the first time). Returns
    {device key: (its interface_index, {port key: Sample})}, leaving out devices that didn't answer."""
    def read(target):
        key, address, credential, version, timeout, ports = target
        try:
            client = client_factory(address, credential, version, timeout=timeout, retries=0)
            index = indexes.get(key)
            if index is None:
                index = interface_index(client)
            wanted = {port_key(port): index[port_key(port)] for port in ports if port_key(port) in index}
            return key, index, read_samples(client, wanted)
        except (SnmpError, OSError, ValueError):
            return key, None, None

    if not targets:
        return {}
    found = {}
    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets)))) as executor:
        for key, index, samples in executor.map(read, targets):
            if index is not None:
                found[key] = (index, samples)
    return found


class CounterTracker:
    """The last sample of each port and the rates since the one before."""

    def __init__(self):
        self.last = {}  # (device key, port key) -> Sample
        self.rates = {}  # (device key, port key) -> Rate
        self.totals = {}  # (device key, port key) -> errors since the first sample

    def clear(self):
        self.last, self.rates, self.totals = {}, {}, {}

    def update(self, key, samples):
        """Take a device's {port key: Sample}."""
        for port, sample in samples.items():
            where = (key, port)
            before = self.last.get(where)
            self.last[where] = sample
            if before is None or sample.when <= before.when:
                continue
            seconds = sample.when - before.when
            in_delta, out_delta = sample.in_octets - before.in_octets, sample.out_octets - before.out_octets
            if in_delta < 0 or out_delta < 0:
                self.rates.pop(where, None)  # Counters reset (a reload): start again from this one
                continue
            errors = max(0, sample.errors - before.errors)
            discards = max(0, sample.discards - before.discards)
            self.totals[where] = self.totals.get(where, 0) + errors
            self.rates[where] = Rate(in_delta * 8 / seconds, out_delta * 8 / seconds, sample.speed, errors, discards,
                                     seconds, self.totals[where])

    def forget_others(self, keys):
        """Drop devices no longer on the map."""
        for table in (self.last, self.rates, self.totals):
            for where in [where for where in table if where[0] not in keys]:
                del table[where]
