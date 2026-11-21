"""Reading NetFlow export packets: v5 (fixed records), v9 (RFC 3954, Cisco Flexible NetFlow) and IPFIX (RFC 7011).

v9 and IPFIX describe their records with templates sent every so often; data that comes before its template is kept a
few minutes and read once the template arrives. Options records carry the tables Flexible NetFlow's "option" lines
export: interface names, NBAR application names, samplers and the exporter's boot time.

Times: a router's clock is often wrong (no NTP in a lab), so flow times are moved by how far the packet's export time
is from when it arrived here. Qt-free and socket-free: Decoder.feed() takes the packet's bytes and who sent it.
"""
import collections
import ipaddress
import logging
import socket
import struct
import time
from dataclasses import dataclass, field

log = logging.getLogger(__name__)

V5, V9, IPFIX = 5, 9, 10
VARIABLE = 65535

# Information elements NOMAD uses (the same numbers in v9 and IPFIX)
BYTES, PACKETS, PROTOCOL, TOS, TCP_FLAGS, SRC_PORT, SRC_V4, INPUT_IF, DST_PORT, DST_V4, OUTPUT_IF = \
    1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 14
LAST_UPTIME, FIRST_UPTIME, OUT_BYTES, OUT_PACKETS, SRC_V6, DST_V6 = 21, 22, 23, 24, 27, 28
SAMPLING_INTERVAL, SAMPLER_ID, SAMPLER_INTERVAL, DIRECTION = 34, 48, 50, 61
IF_NAME, IF_DESCRIPTION, APP_DESCRIPTION, APP_ID, APP_NAME = 82, 83, 94, 95, 96
TOTAL_BYTES, TOTAL_PACKETS = 85, 86
START_SECONDS, END_SECONDS, START_MS, END_MS, SYSTEM_INIT_MS = 150, 151, 152, 153, 160
SELECTOR_ID, PACKET_INTERVAL = 302, 305
ADDRESS_FIELDS = {SRC_V4, DST_V4, 15, 18, 27, 28, 62, 63, 225, 226}
TEXT_FIELDS = {IF_NAME, IF_DESCRIPTION, APP_DESCRIPTION, APP_NAME}
RAW_FIELDS = {APP_ID}  # Kept as bytes, then made a number
V9_SCOPES = {1: None, 2: INPUT_IF, 3: None, 4: None, 5: None}  # v9 scope types: system, interface, line card...

MAX_WAITING = 512  # Data sets kept per exporter while their template hasn't come
WAITING_SECONDS = 300
MAX_FLOW_SECONDS = 4 * 3600  # Longer than this is a clock problem: the flow is taken to have just ended


@dataclass
class Flow:
    exporter: str
    start: float  # Seconds since 1970, on this computer's clock
    end: float
    src: str
    dst: str
    sport: int
    dport: int
    proto: int
    in_if: int
    out_if: int
    bytes: int
    packets: int
    tcp_flags: int = 0
    app_id: int = 0  # NBAR's (classification engine << 24 | selector), 0 when the record has none
    egress: bool = False  # From a monitor on output: in_if may be any interface
    tos: int = 0


@dataclass
class Decoded:
    flows: list = field(default_factory=list)
    interfaces: list = field(default_factory=list)  # [(exporter, ifindex, name, description)]
    applications: list = field(default_factory=list)  # [(exporter, app id, name, description)]
    templates: int = 0  # Templates learned from this packet
    waiting: int = 0  # Data sets put aside for a template not seen yet


class DecodeError(ValueError):
    pass


def address_text(raw):
    if len(raw) == 4:
        return socket.inet_ntoa(raw)
    if len(raw) == 16:
        return str(ipaddress.IPv6Address(raw))
    return raw.hex()


def text_value(raw):
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace").strip()


class Template:
    """One template: its fields [(element or None to skip, length)], compiled to a struct when every length is
    fixed."""

    def __init__(self, template_id, fields, scope_count=0):
        self.template_id, self.fields, self.scope_count = template_id, fields, scope_count
        self.options = scope_count > 0
        self.fixed = all(length != VARIABLE for _, length in fields)
        self.size = sum(length for _, length in fields) if self.fixed else 0
        self.struct = None
        self.converters = []
        if self.fixed and self.size:
            codes = []
            for element, length in fields:
                if element in ADDRESS_FIELDS or element in TEXT_FIELDS or element in RAW_FIELDS or element is None \
                        or length not in (1, 2, 4, 8):
                    codes.append(f"{length}s")
                else:
                    codes.append({1: "B", 2: "H", 4: "I", 8: "Q"}[length])
            self.struct = struct.Struct("!" + "".join(codes))

    def same_as(self, other):
        return other is not None and other.fields == self.fields and other.scope_count == self.scope_count

    def records(self, data):
        """Each record of a data set as {element: value}."""
        if self.struct is not None:
            size = self.size
            for offset in range(0, len(data) - size + 1, size):
                yield self.convert(zip(self.fields, self.struct.unpack_from(data, offset)))
            return
        if not self.fields:
            return
        offset = 0
        minimum = sum(1 if length == VARIABLE else length for _, length in self.fields)
        while len(data) - offset >= max(1, minimum):
            values = []
            for element, length in self.fields:
                if length == VARIABLE:
                    if offset >= len(data):
                        return
                    length = data[offset]
                    offset += 1
                    if length == 255:
                        if offset + 2 > len(data):
                            return
                        length = int.from_bytes(data[offset:offset + 2], "big")
                        offset += 2
                if offset + length > len(data):
                    return
                values.append(((element, length), data[offset:offset + length]))
                offset += length
            yield self.convert((item, raw if not isinstance(raw, bytes) or item[0] in ADDRESS_FIELDS
                                or item[0] in TEXT_FIELDS or item[0] in RAW_FIELDS or item[0] is None
                                else int.from_bytes(raw, "big")) for item, raw in values)

    @staticmethod
    def convert(pairs):
        record = {}
        for (element, _length), value in pairs:
            if element is None:
                continue
            if element in ADDRESS_FIELDS:
                value = address_text(value)
            elif element in TEXT_FIELDS:
                value = text_value(value)
            elif element in RAW_FIELDS:
                value = int.from_bytes(value, "big")
            elif isinstance(value, bytes):
                value = int.from_bytes(value, "big")
            record[element] = value
        return record


@dataclass
class Exporter:
    """What's known of one exporter (one source ID or observation domain of a router)."""
    templates: dict = field(default_factory=dict)  # Template ID -> Template
    samplers: dict = field(default_factory=dict)  # Sampler ID -> packet interval
    init_ms: int = 0  # IPFIX: when the router started (systemInitTimeMilliseconds), for its uptime timestamps


@dataclass
class Waiting:
    domain: int
    template_id: int
    data: bytes
    context: tuple  # (version, export time, uptime ms, skew)
    received: float


class Decoder:
    def __init__(self, clock=time.time):
        self.clock = clock
        self.exporters = {}  # (exporter address, source ID / observation domain) -> Exporter
        self.waiting = {}  # Exporter address -> deque of Waiting
        self.stats = collections.Counter()

    def state(self, exporter, domain):
        key = (exporter, domain)
        found = self.exporters.get(key)
        if found is None:
            found = self.exporters[key] = Exporter()
        return found

    def template_count(self, exporter=None):
        return sum(len(state.templates) for (address, _), state in self.exporters.items()
                   if exporter is None or address == exporter)

    def feed(self, data, exporter, received=None):
        """Read one packet from exporter (its address). Returns Decoded; raises DecodeError for what isn't NetFlow."""
        received = self.clock() if received is None else received
        if len(data) < 4:
            raise DecodeError("too short for NetFlow")
        version = int.from_bytes(data[:2], "big")
        result = Decoded()
        if version == V5:
            self.read_v5(data, exporter, received, result)
        elif version == V9:
            self.read_v9(data, exporter, received, result)
        elif version == IPFIX:
            self.read_ipfix(data, exporter, received, result)
        else:
            raise DecodeError(f"version {version} isn't NetFlow v5, v9 or IPFIX")
        self.stats["packets"] += 1
        self.stats["flows"] += len(result.flows)
        return result

    # ----------------------------------------------------------------- v5

    V5_HEADER = struct.Struct("!HHIIIIBBH")
    V5_RECORD = struct.Struct("!4s4s4sHHIIIIHHxBBBHHBBxx")

    def read_v5(self, data, exporter, received, result):
        if len(data) < self.V5_HEADER.size:
            raise DecodeError("v5 header cut short")
        _, count, uptime, seconds, nanoseconds, _, _, _, sampling = self.V5_HEADER.unpack_from(data)
        export_time = seconds + nanoseconds / 1e9
        skew = received - export_time
        interval = sampling & 0x3FFF or 1
        offset = self.V5_HEADER.size
        for _ in range(count):
            if offset + self.V5_RECORD.size > len(data):
                break
            (src, dst, _, in_if, out_if, packets, octets, first, last, sport, dport, flags, proto, tos, _, _, _,
             _) = self.V5_RECORD.unpack_from(data, offset)
            offset += self.V5_RECORD.size
            start, end = self.times(export_time - (uptime - first) / 1000, export_time - (uptime - last) / 1000,
                                    skew, received)
            result.flows.append(Flow(exporter, start, end, socket.inet_ntoa(src), socket.inet_ntoa(dst), sport,
                                     dport, proto, in_if, out_if, octets * interval, packets * interval, flags,
                                     tos=tos))

    # ----------------------------------------------------------------- v9

    def read_v9(self, data, exporter, received, result):
        if len(data) < 20:
            raise DecodeError("v9 header cut short")
        uptime, export_time, _, domain = struct.unpack_from("!IIII", data, 4)
        context = (V9, export_time, uptime, received - export_time)
        offset = 20
        while offset + 4 <= len(data):
            set_id, length = struct.unpack_from("!HH", data, offset)
            if length < 4 or offset + length > len(data):
                self.stats["bad sets"] += 1
                break
            body = data[offset + 4:offset + length]
            if set_id == 0:
                self.v9_templates(body, exporter, domain, result)
            elif set_id == 1:
                self.v9_options(body, exporter, domain, result)
            elif set_id >= 256:
                self.data_set(exporter, domain, set_id, body, context, received, result)
            offset += length

    def v9_templates(self, body, exporter, domain, result):
        offset = 0
        while offset + 4 <= len(body):
            template_id, count = struct.unpack_from("!HH", body, offset)
            offset += 4
            if template_id < 256 or offset + count * 4 > len(body):
                break
            fields = [struct.unpack_from("!HH", body, offset + 4 * index) for index in range(count)]
            offset += count * 4
            self.learn(exporter, domain, Template(template_id, [(element, length) for element, length in fields]),
                       result)

    def v9_options(self, body, exporter, domain, result):
        offset = 0
        while offset + 6 <= len(body):
            template_id, scope_length, option_length = struct.unpack_from("!HHH", body, offset)
            offset += 6
            if template_id < 256 or offset + scope_length + option_length > len(body):
                break
            scopes = [struct.unpack_from("!HH", body, offset + index) for index in range(0, scope_length, 4)]
            offset += scope_length
            options = [struct.unpack_from("!HH", body, offset + index) for index in range(0, option_length, 4)]
            offset += option_length
            fields = [(V9_SCOPES.get(kind, kind), length) for kind, length in scopes] + options
            self.learn(exporter, domain, Template(template_id, fields, max(1, len(scopes))), result)
            if len(body) - offset < 6:
                break  # The rest is padding

    # ----------------------------------------------------------------- IPFIX

    def read_ipfix(self, data, exporter, received, result):
        if len(data) < 16:
            raise DecodeError("IPFIX header cut short")
        length, export_time, _, domain = struct.unpack_from("!HIII", data, 2)
        end = min(len(data), length) if length >= 16 else len(data)
        context = (IPFIX, export_time, 0, received - export_time)
        offset = 16
        while offset + 4 <= end:
            set_id, set_length = struct.unpack_from("!HH", data, offset)
            if set_length < 4 or offset + set_length > end:
                self.stats["bad sets"] += 1
                break
            body = data[offset + 4:offset + set_length]
            if set_id in (2, 3):
                self.ipfix_templates(body, exporter, domain, set_id == 3, result)
            elif set_id >= 256:
                self.data_set(exporter, domain, set_id, body, context, received, result)
            offset += set_length

    def ipfix_templates(self, body, exporter, domain, options, result):
        offset = 0
        header = 6 if options else 4
        while offset + header <= len(body):
            if options:
                template_id, count, scope_count = struct.unpack_from("!HHH", body, offset)
            else:
                (template_id, count), scope_count = struct.unpack_from("!HH", body, offset), 0
            offset += header
            if template_id < 256:
                break
            if count == 0:  # Withdrawn
                self.state(exporter, domain).templates.pop(template_id, None)
                continue
            fields = []
            for _ in range(count):
                if offset + 4 > len(body):
                    return
                element, length = struct.unpack_from("!HH", body, offset)
                offset += 4
                if element & 0x8000:  # An enterprise's own element: skipped
                    offset += 4
                    element = None
                fields.append((element, length))
            self.learn(exporter, domain, Template(template_id, fields, scope_count), result)

    # ----------------------------------------------------------------- Templates and data

    def learn(self, exporter, domain, template, result):
        state = self.state(exporter, domain)
        if not template.same_as(state.templates.get(template.template_id)):
            log.info("NetFlow: %s sent %stemplate %s (%s fields)", exporter, "options " if template.options else "",
                     template.template_id, len(template.fields))
        state.templates[template.template_id] = template
        result.templates += 1
        self.stats["templates"] += 1
        queue = self.waiting.get(exporter)
        if not queue:
            return
        ready = [item for item in queue if item.domain == domain and item.template_id == template.template_id]
        if not ready:
            return
        self.waiting[exporter] = collections.deque(item for item in queue if item not in ready)
        for item in ready:
            self.read_records(exporter, state, template, item.data, item.context, item.received, result)

    def data_set(self, exporter, domain, set_id, body, context, received, result):
        state = self.state(exporter, domain)
        template = state.templates.get(set_id)
        if template is None:
            queue = self.waiting.setdefault(exporter, collections.deque(maxlen=MAX_WAITING))
            while queue and received - queue[0].received > WAITING_SECONDS:
                queue.popleft()
            queue.append(Waiting(domain, set_id, bytes(body), context, received))
            result.waiting += 1
            self.stats["waiting for template"] += 1
            return
        self.read_records(exporter, state, template, body, context, received, result)

    def read_records(self, exporter, state, template, body, context, received, result):
        for record in template.records(body):
            if template.options:
                self.read_options(exporter, state, record, result)
                continue
            flow = self.flow(exporter, state, record, context, received)
            if flow is not None:
                result.flows.append(flow)

    def read_options(self, exporter, state, record, result):
        if INPUT_IF in record and (IF_NAME in record or IF_DESCRIPTION in record):
            result.interfaces.append((exporter, record[INPUT_IF], record.get(IF_NAME, ""),
                                      record.get(IF_DESCRIPTION, "")))
        if APP_ID in record and APP_NAME in record:
            result.applications.append((exporter, record[APP_ID], record[APP_NAME],
                                        record.get(APP_DESCRIPTION, "")))
        sampler = record.get(SAMPLER_ID, record.get(SELECTOR_ID))
        interval = record.get(SAMPLER_INTERVAL) or record.get(SAMPLING_INTERVAL) or record.get(PACKET_INTERVAL)
        if sampler is not None and interval:
            state.samplers[sampler] = interval
        if record.get(SYSTEM_INIT_MS):
            state.init_ms = record[SYSTEM_INIT_MS]

    def flow(self, exporter, state, record, context, received):
        src, dst = record.get(SRC_V4) or record.get(SRC_V6), record.get(DST_V4) or record.get(DST_V6)
        if not src or not dst:
            self.stats["records without addresses"] += 1
            return None
        octets = record.get(BYTES) or record.get(TOTAL_BYTES) or record.get(OUT_BYTES) or 0
        packets = record.get(PACKETS) or record.get(TOTAL_PACKETS) or record.get(OUT_PACKETS) or 0
        interval = record.get(SAMPLING_INTERVAL) or record.get(SAMPLER_INTERVAL) or 0
        sampler = record.get(SAMPLER_ID, record.get(SELECTOR_ID))
        if not interval and sampler:
            interval = state.samplers.get(sampler, 0)
        if interval > 1:
            octets, packets = octets * interval, packets * interval
        version, export_time, uptime, skew = context
        if END_MS in record:
            end = record[END_MS] / 1000
            start = record.get(START_MS, record[END_MS]) / 1000
        elif END_SECONDS in record:
            end, start = record[END_SECONDS], record.get(START_SECONDS, record[END_SECONDS])
        elif LAST_UPTIME in record and version == V9:
            end = export_time - (uptime - record[LAST_UPTIME]) / 1000
            start = export_time - (uptime - record.get(FIRST_UPTIME, record[LAST_UPTIME])) / 1000
        elif LAST_UPTIME in record and state.init_ms:
            end = (state.init_ms + record[LAST_UPTIME]) / 1000
            start = (state.init_ms + record.get(FIRST_UPTIME, record[LAST_UPTIME])) / 1000
        elif LAST_UPTIME in record:  # IPFIX uptimes with no boot time: the flow ended as it was sent
            end = export_time
            start = export_time - max(0, record[LAST_UPTIME] - record.get(FIRST_UPTIME, record[LAST_UPTIME])) / 1000
        else:
            end = start = export_time
        start, end = self.times(start, end, skew, received)
        return Flow(exporter, start, end, src, dst, record.get(SRC_PORT, 0), record.get(DST_PORT, 0),
                    record.get(PROTOCOL, 0), record.get(INPUT_IF, 0), record.get(OUTPUT_IF, 0), octets, packets,
                    record.get(TCP_FLAGS, 0), record.get(APP_ID, 0), record.get(DIRECTION) == 1,
                    record.get(TOS, 0))

    @staticmethod
    def times(start, end, skew, received):
        """(start, end) on this computer's clock, never after the packet came, and never backward."""
        start, end = start + skew, end + skew
        if end > received or end < received - MAX_FLOW_SECONDS:
            start, end = received - max(0.0, min(end - start, MAX_FLOW_SECONDS)), received
        if start > end or start < end - MAX_FLOW_SECONDS:
            start = end
        return start, end
