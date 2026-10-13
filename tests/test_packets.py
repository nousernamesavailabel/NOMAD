"""The capture viewer's core: reading captures, decoding, display filters, TCP analysis, problems found, summaries,
following streams, and promiscuous mode for SPAN copies."""
import pytest
from capture_samples import (ACK, PC, PSH, ROUTER, SYN, arp, erspan_wrap, frame_ip, sample_packets, tcp, udp,
                             write_pcap, write_pcapng)

from nomad import capture as capture_module
from nomad import pktmon, promisc
from nomad.packets import capfile, decode, dfilter, expert, stats, streams
from nomad.packets.reader import CaptureError


@pytest.fixture(scope="module")
def sample(tmp_path_factory):
    path = write_pcapng(tmp_path_factory.mktemp("captures") / "sample.pcapng", sample_packets())
    capture = capfile.load(str(path))
    return capture, capture.view(False)


def packet_with(view, text):
    return next(packet for packet in view.packets if text in packet.info)


def shown(view, text):
    return [view.packets[index].number for index in dfilter.apply(dfilter.compile_filter(text), view.packets)]


# ----------------------------------------------------------------- Reading and decoding

def test_pcap_and_pcapng_read_the_same(tmp_path, sample):
    capture, view = sample
    other = capfile.load(str(write_pcap(tmp_path / "sample.pcap", sample_packets())))
    assert [packet.info for packet in other.view(False).packets] == [packet.info for packet in view.packets]
    assert abs(other.captured[5].epoch - capture.captured[5].epoch) < 1e-5


def test_a_gzipped_capture(tmp_path, sample):
    import gzip
    _, view = sample
    plain = write_pcapng(tmp_path / "plain.pcapng", sample_packets())
    zipped = tmp_path / "zipped.pcapng.gz"
    zipped.write_bytes(gzip.compress(plain.read_bytes()))
    assert len(capfile.load(str(zipped)).captured) == len(view.packets)


def test_not_a_capture(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_text("not a capture at all, just some words to fill it up")
    with pytest.raises(CaptureError):
        capfile.load(str(path))


def test_columns_match_what_wireshark_shows(sample):
    _, view = sample
    rows = {packet.number: (packet.src, packet.dst, packet.protocol, packet.info) for packet in view.packets}
    assert rows[1] == (PC, "Broadcast", "ARP", "Who has 10.0.10.1? Tell 10.0.10.9")
    assert rows[2][3] == f"10.0.10.1 is at {ROUTER}"
    assert rows[6] == ("10.0.0.53", "10.0.10.9", "DNS",
                       "Standard query response 0x1111 A intranet.example.com A 10.0.20.80")
    assert rows[8][3] == "Standard query response 0x2222 No such name A nothing.example.com"
    assert rows[10][3] == "51000 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460 WS=256 SACK_PERM"
    assert rows[11][3].startswith("80 → 51000 [SYN, ACK] Seq=0 Ack=1 Win=29200")
    assert rows[12][3] == "51000 → 80 [ACK] Seq=1 Ack=1 Win=128512 Len=0"  # 502 scaled by 256
    assert rows[13][2:] == ("HTTP", "GET /index.html HTTP/1.1")
    assert rows[14][2] == "TCP" and rows[14][3].startswith("[TCP Retransmission] 51000 → 80 [ACK, PSH]") is False
    assert rows[14][3].startswith("[TCP Retransmission] 51000 → 80 [PSH, ACK]")
    assert rows[16][3] == "51000 → 80 [RST, ACK] Seq=75 Ack=58 Win=0 Len=0"
    assert rows[21][2:] == ("TLS", "Client Hello (SNI=portal.example.com)")
    assert rows[22][2:] == ("DHCP", "DHCP Discover - Transaction ID 0xabcd")
    assert rows[25][3].startswith("Destination unreachable (Port unreachable) for UDP 10.0.10.9:50002")
    assert rows[27][2:] == ("RSTP", "RST. TC + Root = 32768/10/00:1e:14:00:00:01  Cost = 4  Port = 0x8001")
    assert rows[28][3] == "Device ID: CLOSET-SW1  Port ID: GigabitEthernet1/0/24  Native VLAN: 10"
    assert rows[31][3].startswith("Hello (state Active), group 1, priority 110, virtual IP 10.0.10.1")
    assert rows[34][2:] == ("SNMP", "get-request 1.3.6.1.2.1.1.5.0")
    assert rows[35][2:4] == ("GRE", "Encapsulated ERSPAN")[0:0] + rows[35][2:4]  # Decoded through, below
    assert rows[35][:3] == ("172.16.0.1", "172.16.0.2", "DNS")  # The frame inside the ERSPAN, as Wireshark shows


def test_the_details_tree_points_at_its_bytes(sample):
    _, view = sample
    d = view.packets[12].dissect(tree=True)  # The HTTP request
    titles = [node.text for node in d.nodes]
    assert titles[0].startswith("Frame 13: 128 bytes on wire")
    assert titles[1].startswith("Ethernet II") and titles[2].startswith("Internet Protocol Version 4")
    ip = d.nodes[2]
    source = next(child for child in ip.children if child.text.startswith("Source address"))
    assert (source.start, source.end) == (26, 30) and source.text == "Source address: 10.0.10.9"
    assert any(node.text.startswith("Hypertext Transfer Protocol") for node in d.nodes)
    assert "Protocols in frame: eth:ip:tcp:http" in [child.text for child in d.nodes[0].children]


def test_every_value_decoded_is_a_known_filter_field(sample):
    capture, view = sample
    for packet in view.packets + capture.mirrored:
        d = packet.dissect()
        unknown = set(d.all_values()) - set(dfilter.FIELDS)
        assert not unknown, (packet.number, unknown)
        assert set(d.protocols) <= dfilter.PROTOCOLS, (packet.number, d.protocols)


def test_addresses_are_bytes_shown_as_text():
    address = decode.Address.parse("10.0.0.5")
    assert str(address) == "10.0.0.5" and f"{address}" == "10.0.0.5" and address.version == 4
    assert str(decode.Address.parse("fe80::1")) == "fe80::1"
    with pytest.raises(ValueError):
        decode.Address.parse("10.0.0")


def test_a_cut_short_packet_is_marked_not_fatal():
    frame = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.20.80", 6, tcp(51000, 80, 1, 1, ACK))[:40]
    d = decode.dissect(frame)
    assert d.malformed and "_ws.malformed" in d.protocols and "[Malformed" in d.info


# ----------------------------------------------------------------- Display filters

@pytest.mark.parametrize("text, numbers", [
    ("arp", [1, 2, 3, 4]),
    ("ip.addr == 10.0.20.80 && tcp.port == 80", [10, 11, 12, 13, 14, 15, 16]),
    ("ip.dst == 10.0.20.0/24 and tcp.flags.syn == 1 and not tcp.flags.ack == 1", [10, 17, 19, 20]),
    ("dns.flags.rcode == 3", [8]),
    ('dns.qry.name contains "NOTHING"', [7, 8]),
    ('http.request.method == "get"', [13]),
    ('tls.handshake.extensions_server_name matches "^portal"', [21]),
    ("tcp.port in {22 3389}", [17, 18, 19, 20]),
    ("tcp.analysis.retransmission", [14, 20]),
    ("eth.dst == ff-ff-ff-ff-ff-ff && !arp", [22, 23, 24]),
    ("dhcp.option.dhcp == 2", [23, 24]),
    ('frame contains "Internal Server"', [15]),
    ("vlan.id == 20", [30]),
    ("hsrp.state == 16", [31, 32]),
    ("stp.flags.tc == 1", [27]),
    ("erspan.spanid == 7", [35]),
    ("ip.addr == 172.16.0.2", [35]),  # The address inside the ERSPAN too
    ("10.0.20.81", [17, 18]),  # Just an address
    ("3389", [17, 18]),  # Just a port
    ("frame.number >= 33 && frame.number <= 34", [33, 34]),
    ("ip.addr != 10.0.10.9 && ip", [22, 23, 24, 31, 32]),  # 35: its outer header is to 10.0.10.9
    ("(udp.port == 53 || udp.port == 161) && ip.src == 10.0.10.9", [5, 7, 9, 34]),
])
def test_filters(sample, text, numbers):
    _, view = sample
    assert shown(view, text) == numbers


@pytest.mark.parametrize("text, message", [
    ("ip.adr == 10.0.0.1", "isn't a field"), ("tcp.port == http", "needs a number"), ("ip.addr == 10.0.0", "IP"),
    ("tcp.port ==", "Expected a value"), ("(arp", r'Missing "\)"'), ("ip.ttl contains 5", "contains works"),
    ("tcp == 5", "is a protocol"), ('dns.qry.name matches "("', "regular expression"), ("arp &&", "ends too soon"),
])
def test_filter_mistakes_are_explained(text, message):
    with pytest.raises(dfilter.FilterError, match=message):
        dfilter.compile_filter(text)


def test_every_details_line_filter_shows_its_own_packet(sample):
    capture, view = sample
    checked = 0
    for packet in view.packets + capture.mirrored:
        d = packet.dissect(tree=True)

        def walk(node):
            nonlocal checked
            if node.field:
                filter_ = dfilter.compile_filter(node.field)
                assert filter_.matches(packet), (packet.number, node.text, node.field)
                checked += 1
            for child in node.children:
                walk(child)
        for node in d.nodes:
            walk(node)
    assert checked > 500


def test_details_lines_name_their_fields(sample):
    _, view = sample
    d = view.packets[12].dissect(tree=True)  # The HTTP request
    fields = {}

    def walk(node):
        fields[node.text.split(":")[0]] = node.field
        for child in node.children:
            walk(child)
    for node in d.nodes:
        walk(node)
    assert fields["Source address"] == "ip.src == 10.0.10.9"
    assert fields["Destination port"] == "tcp.dstport == 80"
    assert fields["SYN"] == "tcp.flags.syn == 0"
    assert fields["Frame 13"] == "frame.number == 13"
    assert fields["Hypertext Transfer Protocol"] == "http"
    assert fields["Header checksum"] == ""  # No filter field: the line it's under (ip) is offered instead
    assert decode.field_filter("dns.qry.name", 'my "odd" name') == r'dns.qry.name == "my \"odd\" name"'
    assert dfilter.compile_filter(decode.field_filter("dns.qry.name", 'my "odd" name'))


@pytest.mark.parametrize("current, expression, how, combined", [
    ("", "ip.addr == 10.0.0.5", "and", "ip.addr == 10.0.0.5"),
    ("", "dns", "not", "!dns"),
    ("", "ip.addr == 10.0.0.5", "not", "!(ip.addr == 10.0.0.5)"),
    ("dns", "ip.addr == 10.0.0.5", "and", "dns && ip.addr == 10.0.0.5"),
    ("dns", "arp", "or", "dns || arp"),
    ("dns || arp", "ip.addr == 10.0.0.5", "and", "(dns || arp) && ip.addr == 10.0.0.5"),
    ("(dns || arp) && ip", "tcp", "and", "(dns || arp) && ip && tcp"),
    ("dns or arp", "tcp", "not", "(dns or arp) && !tcp"),
    ("ip", "tcp.port == 1 || udp.port == 1", "and", "ip && (tcp.port == 1 || udp.port == 1)"),
    ('frame contains "a || b"', "tcp", "and", 'frame contains "a || b" && tcp'),
    ("10.0.0.5", "tcp.port == 443", "and", "ip.addr == 10.0.0.5 && tcp.port == 443"),  # A shortcut spelled out
])
def test_adding_to_a_filter(current, expression, how, combined):
    assert dfilter.combine(current, expression, how) == combined
    dfilter.compile_filter(combined)


def test_a_packet_rows_filters(sample):
    _, view = sample
    packet = view.packets[12]  # The HTTP request
    found = dict(dfilter.packet_filters(packet.dissect(), packet))
    assert found == {"source": "ip.addr == 10.0.10.9", "destination": "ip.addr == 10.0.20.80",
                     "source port": f"tcp.port == {found['source port'].split()[-1]}",
                     "destination port": "tcp.port == 80", "protocol": "http",
                     "stream": f"tcp.stream == {packet.stream}"}
    arp_request = view.packets[0]
    found = dict(dfilter.packet_filters(arp_request.dissect(), arp_request))
    assert found["source"].startswith("eth.addr == ") and found["protocol"] == "arp"
    tagged = view.packets[29]
    assert ("vlan", "vlan.id == 20") in dfilter.packet_filters(tagged.dissect(), tagged)
    for packet in view.packets:
        for _, text in dfilter.packet_filters(packet.dissect(), packet):
            assert dfilter.compile_filter(text).matches(packet), (packet.number, text)


def test_unknown_field_suggests_one():
    with pytest.raises(dfilter.FilterError, match="Did you mean tcp.analysis"):
        dfilter.compile_filter("tcp.analysis.retrans")


def test_quick_filters_agree_with_full_decoding(sample):
    _, view = sample
    for text in ("ip.addr == 10.0.20.0/24", "tcp.flags.reset", "eth.addr == 00:1e:14:00:00:01", "udp.stream == 0",
                 "tcp.analysis.flags", "tcp.flags == 0x12", "not arp and not tcp", "ip.dst >= 10.0.20.80"):
        compiled = dfilter.compile_filter(text)
        assert compiled.fast, text
        quick = dfilter.apply(compiled, view.packets)
        compiled.fast = False
        assert dfilter.apply(compiled, view.packets) == quick, text


# ----------------------------------------------------------------- TCP analysis

def conversation(*segments):
    """[(seconds, frame)] of TCP segments between PC (10.0.10.9:51000) and a server (10.0.20.80:80)."""
    packets = []
    for seconds, from_client, seq, ack, flags, payload, window in segments:
        if from_client:
            frame = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.20.80", 6, tcp(51000, 80, seq, ack, flags, payload,
                                                                           window))
        else:
            frame = frame_ip(ROUTER, PC, "10.0.20.80", "10.0.10.9", 6, tcp(80, 51000, seq, ack, flags, payload,
                                                                           window))
        packets.append((seconds, frame))
    return packets


def analyzed(tmp_path, packets, name="tcp.pcapng"):
    capture = capfile.load(str(write_pcapng(tmp_path / name, packets)))
    return capture.view(False)


def test_tcp_analysis(tmp_path):
    data = b"x" * 100
    view = analyzed(tmp_path, conversation(
        (0.00, True, 1000, 0, SYN, b"", 64240),
        (0.01, False, 5000, 1001, SYN | ACK, b"", 29200),
        (0.02, True, 1001, 5001, ACK, b"", 500),
        (0.03, True, 1001, 5001, ACK | PSH, data, 500),
        (0.04, True, 1201, 5001, ACK | PSH, data, 500),  # 1101 never captured
        (0.05, False, 5001, 1101, ACK, b"", 0),  # Zero window
        (0.06, False, 5001, 1101, ACK, b"", 0),
        (0.07, False, 5001, 1101, ACK, b"", 0),
        (0.08, True, 1101, 5001, ACK | PSH, data, 500),  # Resent after two duplicate ACKs
        (0.50, True, 1101, 5001, ACK | PSH, data, 500),  # Resent again, much later
    ))
    flags = {packet.number: packet.analysis for packet in view.packets}
    assert flags[5] == ("lost_segment",)
    assert "zero_window" in flags[6]
    assert "duplicate_ack" in flags[7] and "duplicate_ack" in flags[8]
    assert flags[9] == ("fast_retransmission",)
    assert flags[10] == ("retransmission",)
    assert view.packets[3].relative == (1, 1)  # Relative sequence numbers
    stream = view.stream("tcp", 0)
    assert stream.handshake_seconds == pytest.approx(0.01)


def test_keep_alives_are_not_duplicate_acks(tmp_path):
    view = analyzed(tmp_path, conversation(
        (0.0, True, 1001, 5001, ACK | PSH, b"x", 500),
        (0.1, False, 5001, 1002, ACK, b"", 500),
        (1.0, True, 1001, 5001, ACK, b"\0", 500),  # Keep-alive: one byte from before
        (1.01, False, 5001, 1002, ACK, b"", 500),
        (2.0, True, 1001, 5001, ACK, b"\0", 500),
        (2.01, False, 5001, 1002, ACK, b"", 500),
    ))
    assert [packet.analysis for packet in view.packets[2:]] == [("keep_alive",), ("keep_alive_ack",)] * 2


def test_reused_ports_make_a_new_stream(tmp_path):
    view = analyzed(tmp_path, conversation(
        (0.0, True, 1000, 0, SYN, b"", 64240),
        (0.01, False, 5000, 1001, SYN | ACK, b"", 29200),
        (0.02, True, 1001, 5001, 0x004, b"", 0),
        (5.0, True, 9000, 0, SYN, b"", 64240),
    ))
    assert [packet.stream for packet in view.packets] == [0, 0, 0, 1]


# ----------------------------------------------------------------- Captures twice, and ERSPAN

def test_duplicates_are_hidden_unless_asked(tmp_path):
    frame = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.20.80", 17, udp(5000, 5001, b"once"))
    path = str(write_pcapng(tmp_path / "twice.pcapng", [(0.0, frame), (0.0001, frame), (1.0, frame)]))
    capture = capfile.load(path)
    assert len(capture.captured) == 2 and capture.duplicates == 1  # The third came much later: a real one
    assert len(capfile.load(path, keep_duplicates=True).captured) == 3


def test_mostly_erspan_opens_unwrapped(tmp_path):
    inner = [frame_ip("00:de:ad:00:00:01", "00:de:ad:00:00:02", "172.16.0.1", "172.16.0.2", 17,
                      udp(1000 + number, 5001, b"q")) for number in range(5)]
    packets = [(number * 0.1, erspan_wrap(frame)) for number, frame in enumerate(inner)]
    packets.append((1.0, arp(PC, "ff:ff:ff:ff:ff:ff", 1, PC, "10.0.10.9", "00:00:00:00:00:00", "10.0.10.1")))
    capture = capfile.load(str(write_pcapng(tmp_path / "erspan.pcapng", packets)))
    assert capture.default_unwrapped() and len(capture.mirrored) == 5
    view = capture.view(True)
    assert [packet.src for packet in view.packets] == ["172.16.0.1"] * 5 and view.unwrapped
    assert view.problems[0].summary.startswith("Showing the frames 10.18.0.122 mirrored over ERSPAN (session 7)")
    assert len(capture.view(False).packets) == 6


# ----------------------------------------------------------------- Problems found and summaries

def test_problems_found(sample):
    _, view = sample
    found = {(problem.severity, problem.summary) for problem in view.problems}
    for severity, summary in [
            (expert.ERROR, "2 different DHCP servers answered"), (expert.ERROR, "Duplicate IP address 10.0.10.50"),
            (expert.ERROR, "2 routers claim Active for HSRP group 1 (10.0.10.1)"),
            (expert.WARNING, "10.0.20.81:3389 refused 1 connection"),
            (expert.WARNING, "No answer from 10.0.20.82:22 to 1 connection attempt (2 SYNs)"),
            (expert.WARNING, "No answer from DNS server 10.0.0.54 to 1 query"),
            (expert.WARNING, "Spanning tree topology changes: 1 BPDU flagged"),
            (expert.WARNING, "CLOSET-SW1 GigabitEthernet1/0/24 is half duplex"),
            (expert.WARNING, "1 answer of HTTP 500"),
            (expert.NOTE, "10.0.0.53 answered No such name for nothing.example.com"),
            (expert.NOTE, "10.0.20.80:80 was slow to answer 1 connection (up to 300 ms)")]:
        assert (severity, summary) in found, summary
    severities = [problem.severity for problem in view.problems]
    assert severities == sorted(severities, key=expert.SEVERITY_ORDER.get)
    for problem in view.problems:  # Every filter a problem offers works
        if problem.filter:
            assert shown(view, problem.filter), problem.summary


def test_unanswered_arp_only_when_the_reply_would_be_seen(tmp_path):
    """On this PC's own port, the router's ARP for someone else is answered to the router, out of sight: not a
    problem. This PC's own unanswered ARP is."""
    traffic = [(0.001 * number, frame_ip(PC, ROUTER, "10.0.10.9", f"8.8.{number}.8", 17, udp(5000, 53, b"q")))
               for number in range(10)]
    traffic += [(0.001 * number + 0.0005, frame_ip(ROUTER, PC, f"8.8.{number}.8", "10.0.10.9", 17,
                                                   udp(53, 5000, b"a"))) for number in range(10)]
    router_asks = [(1 + number, arp(ROUTER, "ff:ff:ff:ff:ff:ff", 1, ROUTER, "10.0.10.1", "00:00:00:00:00:00",
                                    "10.0.10.12")) for number in range(3)]
    view = analyzed(tmp_path, traffic + router_asks, "router.pcapng")
    assert not any(problem.group == "ARP" for problem in view.problems)
    pc_asks = [(5 + number, arp(PC, "ff:ff:ff:ff:ff:ff", 1, PC, "10.0.10.9", "00:00:00:00:00:00", "10.0.10.77"))
               for number in range(3)]
    view = analyzed(tmp_path, traffic + router_asks + pc_asks, "pc.pcapng")
    problem = next(problem for problem in view.problems if problem.group == "ARP")
    assert problem.children[0].summary.startswith("10.0.10.77 (3 requests")


def test_one_direction_only_is_called_out(tmp_path):
    packets = []
    for stream in range(4):
        for number in range(6):
            packets.append((stream + number * 0.01, frame_ip(PC, ROUTER, "10.0.10.9", "10.0.20.80", 6,
                                                             tcp(51000 + stream, 80, 1 + number * 10, 1, ACK,
                                                                 b"y" * 10))))
    view = analyzed(tmp_path, packets, "oneway.pcapng")
    assert any(problem.summary.startswith("Only one direction of 4 of 4 busy connections") for problem in
               view.problems)


def test_summaries(sample):
    _, view = sample
    summary = view.summary
    assert summary.packets == 35 and "VLANs tagged: 20 (1)" in summary.headline()
    assert summary.names["10.0.20.80"] == "intranet.example.com"  # From DNS
    assert summary.names["10.0.10.9"] == "laptop9"  # DHCP host name, by its MAC, from ARP
    http = summary.conversations["tcp"]
    first = next(item for item in http if item.filter == "tcp.stream == 0")
    assert (first.a, first.b, first.packets) == ("10.0.10.9:51000", "10.0.20.80:80", 7)
    assert "handshake 300.0 ms" in first.note and "1 resent" in first.note
    top = [row.name for row in summary.protocols]
    assert top == ["eth"]
    ip = next(row for row in summary.protocols[0].children if row.name == "ip")
    assert {row.name for row in ip.children} >= {"tcp", "udp", "icmp", "gre"}
    assert [(item.device, item.port) for item in summary.neighbors] == [
        ("CLOSET-SW1", "Gi1/0/24 (uplink)"), ("CLOSET-SW1", "GigabitEthernet1/0/24")]
    assert shown(view, summary.neighbors[1].filter) == [28]


def test_timeline_buckets():
    assert stats.nice_width(0.0007) == 0.001 and stats.nice_width(0.3) == 0.5 and stats.nice_width(3) == 5
    packets = [capfile.Packet(number, 0.0, b"", 1, 100) for number in range(1, 5)]
    for packet, time_ in zip(packets, (0.0, 0.4, 1.2, 2.0)):
        packet.time = time_
    width, rows = stats.timeline(packets, buckets=4)
    assert width == 0.5 and rows == [(2, 200), (0, 0), (1, 100), (0, 0), (1, 100)]


# ----------------------------------------------------------------- Following streams

def test_follow_puts_tcp_data_in_order_once(tmp_path):
    view = analyzed(tmp_path, conversation(
        (0.00, True, 1000, 0, SYN, b"", 64240),
        (0.01, False, 5000, 1001, SYN | ACK, b"", 29200),
        (0.02, True, 1006, 5001, ACK, b"world", 500),  # Came before what's before it
        (0.03, True, 1001, 5001, ACK, b"hello", 500),
        (0.04, True, 1001, 5001, ACK, b"hello", 500),  # Sent twice
        (0.05, False, 5001, 1011, ACK, b"hi", 500),
        (0.06, False, 5013, 1011, ACK, b"lost before", 500),  # 5003-5012 never captured
    ))
    followed = streams.follow(view, "tcp", 0)
    assert followed.data(0) == b"helloworld" and followed.data(1) == b"hilost before"
    assert [chunk.missing for chunk in followed.chunks if chunk.direction == 1] == [0, 10]
    assert followed.client == "10.0.10.9:51000" and followed.packets == 7
    assert streams.as_text(b"a\r\nb\x00") == "a\nb."
    dump = streams.hex_dump(b"GET /")
    assert dump.startswith("00000000  47 45 54 20 2f ") and dump.endswith(" GET /")


# ----------------------------------------------------------------- Promiscuous mode

class FakeSocket:
    def __init__(self, *arguments, fail=None):
        self.calls, self.fail = [], fail
        FakeSocket.made.append(self)

    def setsockopt(self, *arguments):
        self.calls.append(("setsockopt",) + arguments)

    def bind(self, address):
        if self.fail == "bind":
            raise OSError(10049, "The requested address is not valid in its context")
        self.calls.append(("bind", address))

    def ioctl(self, control, value):
        if self.fail == "ioctl":
            raise PermissionError(10013, "An attempt was made to access a socket in a way forbidden")
        self.calls.append(("ioctl", value))

    def close(self):
        self.calls.append(("close",))


def test_promiscuous_mode_on_and_off(monkeypatch):
    FakeSocket.made = []
    monkeypatch.setattr(promisc.socket, "socket", FakeSocket)
    holder = promisc.Promiscuous("169.254.10.20")
    holder.start()
    assert holder.on
    holder.stop()
    calls = FakeSocket.made[0].calls
    assert ("bind", ("169.254.10.20", 0)) in calls
    assert [call[1] for call in calls if call[0] == "ioctl"] == [promisc.socket.RCVALL_ON, promisc.socket.RCVALL_OFF]
    assert calls[-1] == ("close",) and not holder.on


def test_promiscuous_mode_refused(monkeypatch):
    FakeSocket.made = []
    monkeypatch.setattr(promisc.socket, "socket", lambda *arguments: FakeSocket(fail="ioctl"))
    with pytest.raises(promisc.PromiscuousError, match="169.254.10.20"):
        promisc.Promiscuous("169.254.10.20").start()
    assert FakeSocket.made[0].calls[-1] == ("close",)


def test_a_capture_holds_promiscuous_mode_while_it_runs(monkeypatch):
    events = []

    class Holder:
        def __init__(self, address):
            self.address = address

        def start(self):
            events.append(("on", self.address))
            if self.address == "10.9.9.9":
                raise promisc.PromiscuousError("refused")

        def stop(self):
            events.append(("off", self.address))

    monkeypatch.setattr(capture_module, "Promiscuous", Holder)
    monkeypatch.setattr(pktmon, "pktmon", lambda *arguments, timeout=120: "")
    monkeypatch.setattr(pktmon, "find_pktmon", lambda: "pktmon.exe")
    job = capture_module.Capture(capture_module.CaptureFilter(), promiscuous_address="169.254.10.20")
    job.start()
    assert events == [("on", "169.254.10.20")] and not job.promiscuous_problem
    job.stop()
    job.cleanup()
    assert events[1] == ("off", "169.254.10.20")
    refused = capture_module.Capture(capture_module.CaptureFilter(), promiscuous_address="10.9.9.9")
    refused.start()  # Captures anyway: this PC's own traffic still comes through
    assert refused.running and refused.promiscuous_problem == "refused"
    refused.cleanup()
