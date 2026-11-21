"""NetFlow v5, v9 and IPFIX export packets built by hand, shaped like Cisco Flexible NetFlow's (the record NOMAD's
NetFlow Config builds: addresses, ports, protocol, input interface, direction, output interface, bytes and packets as
64-bit counters, first and last uptimes), and its interface-table and application-table options."""
import socket
import struct

# The record NOMAD's builder sets up, in Cisco's v9 order: (element, length)
FNF_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (5, 1), (10, 4), (61, 1), (14, 4), (1, 8), (2, 8), (22, 4),
              (21, 4), (6, 1)]
FNF_APP_FIELDS = FNF_FIELDS + [(95, 4)]
IPFIX_FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (10, 4), (61, 1), (14, 4), (1, 8), (2, 8), (152, 8),
                (153, 8)]


def ip(text):
    return socket.inet_aton(text)


def pad4(data):
    return data + b"\0" * (-len(data) % 4)


def v9_packet(sets, uptime=100_000, export_time=1_700_000_000, sequence=1, source_id=0, count=None):
    body = b"".join(sets)
    return struct.pack("!HHIIII", 9, count if count is not None else len(sets), uptime, export_time, sequence,
                       source_id) + body


def v9_template(template_id, fields):
    body = struct.pack("!HH", template_id, len(fields)) + b"".join(struct.pack("!HH", *item) for item in fields)
    return struct.pack("!HH", 0, len(body) + 4) + body


def v9_options_template(template_id, scopes, options):
    body = struct.pack("!HHH", template_id, 4 * len(scopes), 4 * len(options))
    body += b"".join(struct.pack("!HH", *item) for item in scopes + options)
    body = pad4(body)
    return struct.pack("!HH", 1, len(body) + 4) + body


def data_set(template_id, records):
    body = pad4(b"".join(records))
    return struct.pack("!HH", template_id, len(body) + 4) + body


def fnf_record(src, dst, sport, dport, proto=6, in_if=1, out_if=2, octets=1000, packets=10, first=40_000,
               last=99_000, egress=False, app=None, tos=0, flags=0x18):
    data = ip(src) + ip(dst) + struct.pack("!HHBBIBIQQIIB", sport, dport, proto, tos, in_if, int(egress), out_if,
                                           octets, packets, first, last, flags)
    if app is not None:
        data += struct.pack("!I", app)
    return data


def interface_option(ifindex, name, description=""):
    return struct.pack("!I", ifindex) + name.encode().ljust(32, b"\0") + description.encode().ljust(64, b"\0")


def app_option(app_id, name, description=""):
    return struct.pack("!I", app_id) + name.encode().ljust(24, b"\0") + description.encode().ljust(55, b"\0")


def ipfix_packet(sets, export_time=1_700_000_000, sequence=1, domain=0):
    body = b"".join(sets)
    return struct.pack("!HHIII", 10, 16 + len(body), export_time, sequence, domain) + body


def ipfix_template(template_id, fields, scope_count=0):
    if scope_count:
        body = struct.pack("!HHH", template_id, len(fields), scope_count)
    else:
        body = struct.pack("!HH", template_id, len(fields))
    for element, length in fields:
        body += struct.pack("!HH", element, length)
    return struct.pack("!HH", 3 if scope_count else 2, len(body) + 4) + body


def ipfix_set(template_id, records):
    body = b"".join(records)
    return struct.pack("!HH", template_id, len(body) + 4) + body


def ipfix_record(src, dst, sport, dport, proto=6, in_if=1, out_if=2, octets=1000, packets=10,
                 start_ms=1_699_999_970_000, end_ms=1_699_999_999_000):
    return ip(src) + ip(dst) + struct.pack("!HHBIBIQQQQ", sport, dport, proto, in_if, 0, out_if, octets, packets,
                                           start_ms, end_ms)


def v5_packet(records, uptime=100_000, export_time=1_700_000_000, sampling=0):
    header = struct.pack("!HHIIIIBBH", 5, len(records), uptime, export_time, 0, 1, 0, 0, sampling)
    return header + b"".join(records)


def v5_record(src, dst, sport, dport, proto=6, in_if=1, out_if=2, octets=1000, packets=10, first=40_000,
              last=99_000):
    return struct.pack("!4s4s4sHHIIIIHHxBBBHHBBxx", ip(src), ip(dst), ip("0.0.0.0"), in_if, out_if, packets, octets,
                       first, last, sport, dport, 0x18, proto, 0, 0, 0, 24, 24)
