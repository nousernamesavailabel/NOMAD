"""A capture file opened in the viewer: its packets, decoded once for the list's columns, with TCP and UDP
conversations tracked (stream numbers, relative sequence numbers, retransmissions and the like), the summaries and the
problems found. A capture of ERSPAN (a switch mirroring to this PC) can be looked at as the frames it mirrored.
"""
import os
import time

from .. import erspan
from . import decode
from .reader import read_file, records

DUPLICATE_SECONDS = 0.005  # The same bytes again this soon is the same packet captured twice
DUPLICATE_MEMORY = 4096
MAX_PACKETS = 2_000_000
OUT_OF_ORDER_SECONDS = 0.003  # A segment from the past this soon after the newest is out of order, not resent
FAST_RETRANSMISSION_SECONDS = 0.02  # Resent this soon after duplicate ACKs asked for it
UNWRAP_SHARE = 0.5  # Show the mirrored frames first when at least this share of the capture is ERSPAN


class Cancelled(Exception):
    """Stopped while loading."""


class Packet:
    __slots__ = ("number", "time", "epoch", "delta", "data", "link_type", "wire_length", "interface", "note", "src",
                 "dst", "sport", "dport", "protocol", "info", "chain", "stream", "kind", "relative", "window", "analysis",
                 "color", "fast")

    def __init__(self, number, epoch, data, link_type, wire_length, interface=""):
        self.number, self.epoch, self.data, self.link_type = number, epoch, data, link_type
        self.wire_length, self.interface = wire_length, interface
        self.time = self.delta = 0.0
        self.note = ""
        self.src = self.dst = self.protocol = self.info = ""
        self.sport = self.dport = None  # TCP or UDP ports
        self.chain = ()
        self.stream, self.kind = -1, ""
        self.relative = self.window = None
        self.analysis = ()
        self.color = ""
        self.fast = None  # What common filters look at, kept so they needn't decode the packet again

    def clock(self):
        whole = int(self.epoch)
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(whole)) + f".{int((self.epoch - whole) * 1e6):06d}"

    def dissect(self, tree=False):
        return decode.dissect(self.data, self.link_type, tree, self)


# ----------------------------------------------------------------- TCP and UDP conversations

class Flow:
    """One direction of a TCP conversation."""
    __slots__ = ("base", "next_seq", "newest", "last_ack", "last_window", "dup_acks", "last_ack_time", "scale",
                 "fin", "packets", "bytes", "kept_alive")

    def __init__(self):
        self.base = self.next_seq = self.last_ack = self.last_window = None
        self.newest = self.last_ack_time = 0.0
        self.dup_acks = 0
        self.scale = None  # Window scale shift offered in its SYN (-1: none offered)
        self.fin = False
        self.kept_alive = False  # Its last packet was a keep-alive (so the answer is a keep-alive ACK)
        self.packets = self.bytes = 0


class Stream:
    """A TCP or UDP conversation: a, b are (address, port) with a the side that spoke first (or sent the SYN)."""

    def __init__(self, index, kind, a, b, first):
        self.index, self.kind, self.a, self.b = index, kind, a, b
        self.first = self.last = first
        self.flows = (Flow(), Flow())
        self.packets = []  # Indexes into the view's packets
        self.syn = self.syn_ack = self.handshake_done = None  # Times
        self.syn_count = 0
        self.reset_by = None  # 0 (a) or 1 (b)
        self.reset_time = None
        self.closed = False
        self.scaling = None  # Both sides offered window scaling (None: the handshake wasn't seen)
        self.counts = {}  # analysis flag -> packets

    @property
    def handshake_seconds(self):
        return self.syn_ack - self.syn if self.syn is not None and self.syn_ack is not None else None

    def describe(self):
        return f"{endpoint(self.a)} ↔ {endpoint(self.b)}"


def endpoint(pair):
    address, port = pair
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


class Tracker:
    """Gives each TCP and UDP packet its stream number and works out what Wireshark's TCP analysis does."""

    def __init__(self):
        self.streams = []  # Stream, by index (TCP and UDP numbered apart, as in Wireshark)
        self.tcp = {}  # canonical key -> Stream
        self.udp = {}
        self.tcp_count = self.udp_count = 0

    def udp_packet(self, packet, index, d):
        source, destination = (d.addresses[0], d.ports[1]), (d.addresses[1], d.ports[2])
        key = (source, destination) if source <= destination else (destination, source)
        stream = self.udp.get(key)
        if stream is None:
            stream = Stream(self.udp_count, "udp", source, destination, packet.time)
            self.udp_count += 1
            self.udp[key] = stream
            self.streams.append(stream)
        direction = 0 if source == stream.a else 1
        flow = stream.flows[direction]
        flow.packets += 1
        flow.bytes += packet.wire_length
        stream.last = packet.time
        stream.packets.append(index)
        packet.stream, packet.kind = stream.index, "udp"

    def tcp_packet(self, packet, index, d):
        sequence, ack, flags, window, length, options = d.tcp
        source, destination = (d.addresses[0], d.ports[1]), (d.addresses[1], d.ports[2])
        key = (source, destination) if source <= destination else (destination, source)
        syn, has_ack, fin, rst = flags & 0x002, flags & 0x010, flags & 0x001, flags & 0x004
        stream = self.tcp.get(key)
        reused = False
        if stream is not None and syn and not has_ack and stream.syn is not None:
            base = stream.flows[0 if source == stream.a else 1].base
            if stream.closed or (base is not None and sequence != base and packet.time - stream.last > 1):
                stream, reused = None, True  # A new connection on the same ports
        if stream is None:
            a, b = (destination, source) if syn and has_ack else (source, destination)
            stream = Stream(self.tcp_count, "tcp", a, b, packet.time)
            self.tcp_count += 1
            self.tcp[key] = stream
            self.streams.append(stream)
        direction = 0 if source == stream.a else 1
        flow, other = stream.flows[direction], stream.flows[1 - direction]
        flow.packets += 1
        flow.bytes += packet.wire_length
        stream.last = packet.time
        stream.packets.append(index)
        packet.stream, packet.kind = stream.index, "tcp"
        found = ["reused_ports"] if reused else []

        # Handshake
        if syn and not has_ack:
            stream.syn_count += 1
            if stream.syn is None:
                stream.syn = packet.time
            flow.scale = options.get("scale", -1)
            flow.base = sequence
        elif syn and has_ack:
            if stream.syn_ack is None:
                stream.syn_ack = packet.time
            flow.scale = options.get("scale", -1)
            flow.base = sequence
            if other.scale is not None:
                stream.scaling = other.scale >= 0 and flow.scale >= 0
        elif has_ack and stream.syn_ack is not None and stream.handshake_done is None and direction == 0:
            stream.handshake_done = packet.time
        if flow.base is None:
            flow.base = (sequence - 1) & 0xFFFFFFFF  # Joined mid-conversation: its first byte here is 1
        if has_ack and other.base is None:
            other.base = (ack - 1) & 0xFFFFFFFF
        relative_seq = (sequence - flow.base) & 0xFFFFFFFF
        relative_ack = (ack - other.base) & 0xFFFFFFFF if has_ack else 0
        packet.relative = (relative_seq, relative_ack)
        if syn:
            packet.window = window
        elif stream.scaling:
            packet.window = window << max(flow.scale, 0)
        elif stream.scaling is False:
            packet.window = window
        segment = length + (1 if syn else 0) + (1 if fin else 0)
        end = relative_seq + segment

        # Sequence analysis
        if window == 0 and not (syn or fin or rst):
            found.append("zero_window")
        keep_alive = (segment <= 1 and length <= 1 and not (syn or fin or rst) and flow.next_seq is not None
                      and relative_seq == flow.next_seq - 1)
        if keep_alive:
            found.append("keep_alive")
        elif segment and flow.next_seq is not None and not rst:
            if relative_seq < flow.next_seq:
                if other.last_ack is not None and other.last_ack >= end and has_ack and length:
                    found.append("spurious_retransmission")
                elif other.dup_acks >= 2 and other.last_ack == relative_seq and \
                        packet.time - other.last_ack_time < FAST_RETRANSMISSION_SECONDS:
                    found.append("fast_retransmission")
                elif packet.time - flow.newest < OUT_OF_ORDER_SECONDS and end <= flow.next_seq and \
                        relative_seq + segment != flow.next_seq:
                    found.append("out_of_order")
                else:
                    found.append("retransmission")
            elif relative_seq > flow.next_seq:
                found.append("lost_segment")
        flow.kept_alive = keep_alive
        if segment and (flow.next_seq is None or end > flow.next_seq):
            flow.next_seq = end
            flow.newest = packet.time

        # Acknowledgment analysis
        if has_ack and not syn:
            if length == 0 and not (fin or rst) and relative_ack == flow.last_ack and not keep_alive:
                if other.kept_alive and window == flow.last_window:
                    found.append("keep_alive_ack")
                    other.kept_alive = False
                elif window == flow.last_window and segment == 0:
                    flow.dup_acks += 1
                    found.append("duplicate_ack")
                elif window != flow.last_window:
                    found.append("window_update")
            elif relative_ack != flow.last_ack:
                flow.dup_acks = 0
            if other.next_seq is not None and relative_ack > other.next_seq and not rst:
                found.append("ack_lost_segment")
            flow.last_ack, flow.last_window, flow.last_ack_time = relative_ack, window, packet.time

        if rst:
            stream.reset_by, stream.reset_time = direction, packet.time
            stream.closed = True
        if fin:
            flow.fin = True
            if other.fin:
                stream.closed = True
        if found:
            packet.analysis = tuple(found)
            for flag in found:
                stream.counts[flag] = stream.counts.get(flag, 0) + 1


# ----------------------------------------------------------------- Views

class View:
    """The packets looked at (as captured, or the frames mirrored over ERSPAN) and what was worked out from them."""

    def __init__(self, packets, unwrapped):
        self.packets = packets
        self.unwrapped = unwrapped
        self.tracker = Tracker()
        self.summary = None
        self.problems = []

    def stream(self, kind, index):
        for stream in self.tracker.streams:
            if stream.kind == kind and stream.index == index:
                return stream
        return None


class CaptureFile:
    def __init__(self, path):
        self.path = path
        self.size = 0
        self.captured = []  # Packets as captured (one of each when it was captured twice)
        self.mirrored = []  # The frames mirrored to this PC over ERSPAN, if any
        self.erspan = erspan.Result()
        self.duplicates = 0
        self.truncated = 0  # Packets only partly kept
        self.too_many = False
        self.views = {}

    @property
    def name(self):
        return os.path.basename(self.path)

    def default_unwrapped(self):
        return bool(self.mirrored) and len(self.mirrored) >= UNWRAP_SHARE * max(1, len(self.captured) -
                                                                              self.erspan.duplicates)

    def view(self, unwrapped, progress=None, should_stop=None):
        """The View, worked out the first time it's asked for (which takes a moment for a big capture)."""
        unwrapped = unwrapped and bool(self.mirrored)
        if unwrapped not in self.views:
            self.views[unwrapped] = analyze(self, self.mirrored if unwrapped else self.captured, unwrapped, progress,
                                            should_stop)
        return self.views[unwrapped]


def load(path, keep_duplicates=False, progress=None, should_stop=None):
    """Read a pcap or pcapng file into a CaptureFile (packets not yet decoded). Raises reader.CaptureError, OSError or
    Cancelled."""
    capture = CaptureFile(path)
    data = read_file(path)
    capture.size = len(data)
    intake = Intake(capture, keep_duplicates)
    for count, record in enumerate(records(data)):
        if count % 5000 == 0:
            check(should_stop)
            if progress:
                progress("Reading", None)
        if not intake.add(record):
            break
    return capture


class Intake:
    """Takes a capture's packets one at a time (add()): into capture.captured, one of each when it was captured
    twice, and the frames mirrored over ERSPAN into capture.mirrored."""

    def __init__(self, capture, keep_duplicates=False):
        self.capture, self.keep_duplicates = capture, keep_duplicates
        self.recent = {}  # Hash of a packet's bytes -> (time, bytes) of the latest like it
        self.unwrapper = erspan.Unwrapper(capture.erspan)

    def add(self, record):
        """Take a reader.Record. False once the capture holds all it can (MAX_PACKETS)."""
        capture = self.capture
        packet = record.data
        if not self.keep_duplicates:
            key = hash(packet)
            earlier = self.recent.get(key)
            if earlier is not None and earlier[0] >= record.time - DUPLICATE_SECONDS and earlier[1] == packet:
                capture.duplicates += 1
                return True
            if len(self.recent) >= DUPLICATE_MEMORY:
                self.recent.clear()
            self.recent[key] = (record.time, packet)
        if len(capture.captured) >= MAX_PACKETS:
            capture.too_many = True
            return False
        if len(packet) < record.wire_length:
            capture.truncated += 1
        append(capture.captured, Packet(len(capture.captured) + 1, record.time, packet, record.link_type,
                                        record.wire_length, record.interface))
        if is_gre(record.link_type, packet):
            frame = self.unwrapper.add(record.link_type, record.time, packet)
            if frame is not None:
                append(capture.mirrored, Packet(len(capture.mirrored) + 1, record.time, frame, decode.ETHERNET,
                                                len(frame), "ERSPAN"))
        return True


def append(packets, packet):
    """Add packet to the end of packets, timed from the first (and the one before)."""
    if packets:
        packet.time = packet.epoch - packets[0].epoch
        packet.delta = packet.epoch - packets[-1].epoch
    packets.append(packet)


def is_gre(link_type, packet):
    """Whether a packet is IPv4 carrying GRE (what ERSPAN comes in), without decoding it."""
    if link_type in decode.RAW_IP_TYPES:
        return len(packet) > 9 and packet[9] == 47
    if link_type != decode.ETHERNET or len(packet) < 34:
        return False
    if packet[12] == 0x81 and packet[13] == 0x00:
        return packet[16] == 0x08 and packet[17] == 0x00 and len(packet) > 27 and packet[27] == 47
    return packet[12] == 0x08 and packet[13] == 0x00 and packet[23] == 47


def check(should_stop):
    if should_stop is not None and should_stop():
        raise Cancelled()


def analyze(capture, packets, unwrapped, progress=None, should_stop=None):
    """Decode every packet once: the list's columns, streams and TCP analysis, the summaries and problems found."""
    analyzer = Analyzer(capture, packets, unwrapped)
    total = len(packets) or 1
    for index in range(len(packets)):
        if index % 2000 == 0:
            check(should_stop)
            if progress:
                progress("Decoding", index / total)
        analyzer.add()
    if progress:
        progress("Summing up", 1.0)
    return analyzer.finish()


class Analyzer:
    """Decodes a view's packets in order, one at a time (add()), for the list's columns, streams and TCP analysis,
    and what the summaries and problems found (finish()) are worked out from. A capture still being taken has
    packets added to the view's list as they come."""

    def __init__(self, capture, packets, unwrapped):
        from . import expert, stats
        self.capture = capture
        self.view = View(packets, unwrapped)
        self.summary = stats.Collector()
        self.finder = expert.Collector(self.view)
        self.chains = {}
        self.shared = {}  # One copy of each MAC, address and fast tuple
        self.decoded = 0  # The view's first this many packets are decoded

    @property
    def waiting(self):
        return len(self.view.packets) - self.decoded

    def add(self):
        """Decode the view's next packet, and return its dissection."""
        index = self.decoded
        packet = self.view.packets[index]
        packet.relative = packet.window = None
        packet.analysis = ()
        packet.stream, packet.kind = -1, ""
        d = decode.dissect(packet.data, packet.link_type, False, packet, self.view.tracker, index)
        packet.src, packet.dst, packet.protocol, packet.info = d.src, d.dst, d.protocol, d.info
        packet.sport, packet.dport = d.ports[1:] if d.ports else (None, None)
        chain = tuple(d.protocols)
        packet.chain = self.chains.setdefault(chain, chain)
        packet.fast = fast_record(d, self.shared)
        packet.color = color_of(packet, d)
        self.summary.add(packet, d)
        self.finder.add(packet, index, d)
        self.decoded = index + 1
        return d

    def finish(self):
        """The view, with its summaries and the problems found so far."""
        view = self.view
        view.summary = self.summary.finish(view)
        view.problems = self.finder.finish(self.capture)
        return view


def fast_record(d, shared):
    """(source MAC, destination MAC, source IP, destination IP, "tcp"/"udp"/"", source port, destination port, TCP
    flags) for a packet with at most one IP header (no tunnel), else None."""
    if d.ip_layers > 1 or d.depth or not d.macs:
        return None
    source_ip, destination_ip = d.ips if d.ips else (None, None)
    transport, source_port, destination_port = d.ports if d.ports else ("", 0, 0)
    flags = d.tcp[2] if d.tcp is not None else -1
    record = (d.macs[0], d.macs[1], source_ip, destination_ip, transport, source_port, destination_port, flags)
    found = shared.get(record)
    if found is None:
        record = tuple(shared.setdefault(item, item) if isinstance(item, (str, bytes)) else item for item in record)
        shared[record] = record
        return record
    return found


def color_of(packet, d):
    """The packet list's row color, as Wireshark's coloring rules would pick it."""
    if d.malformed:
        return "bad"
    if packet.analysis and any(flag in BAD_FLAGS for flag in packet.analysis):
        return "bad"
    protocols = d.protocols
    if d.tcp is not None:
        if d.tcp[2] & 0x004:
            return "reset"
        if d.tcp[2] & 0x003:
            return "syn"
    if "icmp" in protocols or "icmpv6" in protocols:
        kind = d.values.get("icmp.type") or d.values.get("icmpv6.type")
        return "error" if kind and kind[0] in (3, 4, 5, 11, 12, 1, 2) else "icmp"
    if "arp" in protocols:
        return "arp"
    if protocols and protocols[-1] in ("stp", "cdp", "lldp", "lacp", "dtp", "vtp", "udld", "loop", "eapol", "eap"):
        return "layer2"
    if "dns" in protocols or "dhcp" in protocols or "mdns" in protocols or "llmnr" in protocols or "nbns" in protocols:
        return "names"
    if any(name in protocols for name in ("ospf", "eigrp", "hsrp", "vrrp", "bgp", "pim", "igmp", "bfd")):
        return "routing"
    if "tcp" in protocols:
        return "tcp"
    if "udp" in protocols:
        return "udp"
    return ""


BAD_FLAGS = {"retransmission", "fast_retransmission", "out_of_order", "lost_segment", "duplicate_ack",
             "zero_window", "spurious_retransmission", "ack_lost_segment"}
