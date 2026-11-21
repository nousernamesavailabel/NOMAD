"""NetFlow: reading v5, v9 and IPFIX, summing flows a minute at a time, and the collector and its API."""
import socket
import time

import pytest

from nomad.flows import api, collector, decode, store
from tests.flow_samples import (FNF_APP_FIELDS, FNF_FIELDS, IPFIX_FIELDS, app_option, data_set, fnf_record,
                                interface_option, ipfix_packet, ipfix_record, ipfix_set, ipfix_template,
                                v5_packet, v5_record, v9_options_template, v9_packet, v9_template)

NOW = 1_700_000_000.0  # The packets' export time, and when they arrive (a router with the right time)


def test_v9_template_then_data():
    decoder = decode.Decoder()
    packet = v9_packet([v9_template(256, FNF_FIELDS),
                        data_set(256, [fnf_record("10.1.1.5", "10.2.2.9", 51000, 443, octets=5000, packets=7)])])
    result = decoder.feed(packet, "192.0.2.1", NOW)
    assert result.templates == 1
    [flow] = result.flows
    assert (flow.src, flow.dst, flow.sport, flow.dport, flow.proto) == ("10.1.1.5", "10.2.2.9", 51000, 443, 6)
    assert (flow.in_if, flow.out_if, flow.bytes, flow.packets, flow.egress) == (1, 2, 5000, 7, False)
    # Uptime 100 s at export; the flow ran from 40 s to 99 s of uptime
    assert flow.end == pytest.approx(NOW - 1)
    assert flow.start == pytest.approx(NOW - 60)


def test_v9_data_before_template_is_read_when_it_comes():
    decoder = decode.Decoder()
    early = decoder.feed(v9_packet([data_set(256, [fnf_record("10.0.0.1", "10.0.0.2", 1234, 53, proto=17)])]),
                         "192.0.2.1", NOW)
    assert early.flows == [] and early.waiting == 1
    later = decoder.feed(v9_packet([v9_template(256, FNF_FIELDS)]), "192.0.2.1", NOW + 1)
    assert [flow.dport for flow in later.flows] == [53]
    assert decoder.waiting["192.0.2.1"] == type(decoder.waiting["192.0.2.1"])()


def test_templates_are_per_exporter_and_source_id():
    decoder = decode.Decoder()
    decoder.feed(v9_packet([v9_template(256, FNF_FIELDS)], source_id=1), "192.0.2.1", NOW)
    other = decoder.feed(v9_packet([data_set(256, [fnf_record("10.0.0.1", "10.0.0.2", 1, 2)])], source_id=1),
                         "192.0.2.2", NOW)
    assert other.flows == [] and other.waiting == 1
    domain = decoder.feed(v9_packet([data_set(256, [fnf_record("10.0.0.1", "10.0.0.2", 1, 2)])], source_id=2),
                          "192.0.2.1", NOW)
    assert domain.flows == []


def test_v9_options_name_interfaces_and_applications():
    decoder = decode.Decoder()
    interface_template = v9_options_template(257, [(2, 4)], [(82, 32), (83, 64)])  # Scope: interface
    app_template = v9_options_template(258, [(1, 4)], [(95, 4), (96, 24), (94, 55)])  # Scope: system
    packet = v9_packet([interface_template, app_template,
                        data_set(257, [interface_option(1, "Gi0/0", "WAN to ISP"), interface_option(2, "Gi0/1")]),
                        data_set(258, [b"\0\0\0\0" + app_option(0x0D000050, "http", "Web")])])
    # The app template has a 4-byte system scope first
    result = decoder.feed(packet, "192.0.2.1", NOW)
    assert result.interfaces == [("192.0.2.1", 1, "Gi0/0", "WAN to ISP"), ("192.0.2.1", 2, "Gi0/1", "")]
    assert result.applications == [("192.0.2.1", 0x0D000050, "http", "Web")]


def test_v9_skew_is_corrected_and_flows_never_end_in_the_future():
    decoder = decode.Decoder()
    # The router's clock is an hour fast: times move to this computer's
    packet = v9_packet([v9_template(256, FNF_FIELDS), data_set(256, [fnf_record("10.0.0.1", "10.0.0.2", 1, 2)])],
                       export_time=int(NOW) + 3600)
    [flow] = decoder.feed(packet, "192.0.2.1", NOW).flows
    assert flow.end == pytest.approx(NOW - 1)
    # A last uptime after the packet's own (a broken router): the flow ends as it arrived
    packet = v9_packet([v9_template(256, FNF_FIELDS),
                        data_set(256, [fnf_record("10.0.0.1", "10.0.0.2", 1, 2, first=90_000, last=200_000)])])
    [flow] = decoder.feed(packet, "192.0.2.1", NOW).flows
    assert flow.end == NOW and flow.start <= flow.end


def test_ipfix_with_absolute_times():
    decoder = decode.Decoder()
    packet = ipfix_packet([ipfix_template(300, IPFIX_FIELDS),
                           ipfix_set(300, [ipfix_record("172.16.0.10", "8.8.8.8", 40000, 53, proto=17, octets=200,
                                                        packets=2)])])
    [flow] = decoder.feed(packet, "192.0.2.9", NOW).flows
    assert (flow.src, flow.dst, flow.proto, flow.bytes) == ("172.16.0.10", "8.8.8.8", 17, 200)
    assert flow.end == pytest.approx(NOW - 1) and flow.start == pytest.approx(NOW - 30)


def test_ipfix_variable_length_and_enterprise_fields():
    decoder = decode.Decoder()
    import struct
    # src, dst, an enterprise element (skipped), a variable-length application name, bytes
    body = struct.pack("!HH", 301, 5) + struct.pack("!HH", 8, 4) + struct.pack("!HH", 12, 4) + \
        struct.pack("!HHI", 0x8000 | 12235, 2, 9) + struct.pack("!HH", 96, 65535) + struct.pack("!HH", 1, 4)
    template = struct.pack("!HH", 2, len(body) + 4) + body
    record = socket.inet_aton("10.0.0.1") + socket.inet_aton("10.0.0.2") + b"\0\1" + b"\x03ssh" + \
        struct.pack("!I", 77)
    packet = ipfix_packet([template, ipfix_set(301, [record])])
    [flow] = decoder.feed(packet, "192.0.2.9", NOW).flows
    assert (flow.src, flow.dst, flow.bytes) == ("10.0.0.1", "10.0.0.2", 77)


def test_v5():
    decoder = decode.Decoder()
    packet = v5_packet([v5_record("10.0.0.1", "10.0.0.2", 1000, 80), v5_record("10.0.0.3", "10.0.0.4", 22, 50000)],
                       sampling=(1 << 14) | 10)
    flows = decoder.feed(packet, "192.0.2.5", NOW).flows
    assert [(flow.src, flow.dport, flow.bytes) for flow in flows] == [("10.0.0.1", 80, 10000),
                                                                    ("10.0.0.3", 50000, 10000)]


def test_not_netflow():
    with pytest.raises(decode.DecodeError):
        decode.Decoder().feed(b"\x00\x07hello", "192.0.2.1", NOW)


# --------------------------------------------------------------------- Summing


def flow(src="10.1.1.5", dst="10.2.2.9", sport=51000, dport=443, octets=6000, start=NOW - 30, end=NOW - 1,
         in_if=1, out_if=2, exporter="192.0.2.1", app_id=0, egress=False, proto=6):
    return decode.Flow(exporter, start, end, src, dst, sport, dport, proto, in_if, out_if, octets, 10, 0, app_id,
                       egress)


def test_service_port_and_application_names():
    assert store.service_port(6, 51000, 443) == 443
    assert store.service_port(6, 22, 50000) == 22
    assert store.service_port(6, 40000, 9999) == 9999
    assert store.service_port(1, 0, 0) == 0
    assert store.application_name(flow(), {}) == "HTTPS"
    assert store.application_name(flow(dport=8081), {}) == "TCP/8081"
    assert store.application_name(flow(app_id=0x0D000050), {("192.0.2.1", 0x0D000050): "ms-teams"}) == "ms-teams"
    assert store.application_name(flow(dport=9000, app_id=(3 << 24) | 3389), {}) == "RDP"
    assert store.application_name(flow(proto=50, sport=0, dport=0), {}) == "ESP"


def test_spread_over_minutes():
    minute = 60 * 1000
    assert store.spread(minute + 10, minute + 50, 0) == [(1000, 1.0)]
    shares = store.spread(minute + 30, minute + 90, 0)
    assert shares == [(1000, pytest.approx(0.5)), (1001, pytest.approx(0.5))]
    # Minutes already closed go in the oldest one open
    assert store.spread(minute - 120, minute + 30, 1000) == [(1000, pytest.approx(1.0))]


def summarizer(tmp_path, now=NOW):
    return store.Summarizer(tmp_path / "flows.db", clock=lambda: now)


def test_flows_count_in_on_their_input_and_out_on_their_output(tmp_path):
    writer = summarizer(tmp_path)
    writer.add_packet("192.0.2.1", 9, [flow()])
    writer.add_flows([flow(octets=6000), flow(src="10.1.1.6", octets=3000),
                      flow(src="10.2.2.9", dst="10.1.1.5", sport=443, dport=51000, in_if=2, out_if=1, octets=90000)],
                     NOW)
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    start, end = NOW - 300, NOW
    top_in = queries.top("192.0.2.1", 1, store.IN, store.SOURCES, start, end)
    assert [row[:2] for row in top_in["rows"]] == [["10.1.1.5", 6000], ["10.1.1.6", 3000]]
    assert top_in["total"][0] == 9000
    top_out = queries.top("192.0.2.1", 1, store.OUT, store.SOURCES, start, end)
    assert [row[:2] for row in top_out["rows"]] == [["10.2.2.9", 90000]]
    both = queries.top("192.0.2.1", 1, store.BOTH, store.APPLICATIONS, start, end)
    assert both["rows"][0][:2] == ["HTTPS", 99000]
    conversations = queries.top("192.0.2.1", 2, store.IN, store.CONVERSATIONS, start, end)
    assert store.conversation_text(conversations["rows"][0][0]) == "10.2.2.9 → 10.1.1.5  HTTPS"
    # Every interface: each flow once, as it came in
    every = queries.top("192.0.2.1", None, store.BOTH, store.SOURCES, start, end)
    assert every["total"][0] == 99000
    series = queries.series("192.0.2.1", 1, start, end)
    # The flows ran 30 s across a minute's end: their bytes are split between the two minutes
    assert len(series) == 2 and series[0][0] + 60 == series[1][0]
    assert sum(row[1] for row in series) == pytest.approx(9000, abs=2)
    assert sum(row[2] for row in series) == pytest.approx(90000, abs=2)
    assert [item["ifindex"] for item in queries.interfaces("192.0.2.1")] == [1, 2]
    [exporter] = queries.exporters()
    assert exporter["exporter"] == "192.0.2.1"
    queries.close()
    writer.close()


def test_output_monitor_flows_count_only_out(tmp_path):
    writer = summarizer(tmp_path)
    writer.add_flows([flow(egress=True, in_if=5, out_if=2)], NOW)
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    assert queries.top("192.0.2.1", 5, store.IN, store.SOURCES, NOW - 300, NOW)["total"][0] == 0
    assert queries.top("192.0.2.1", 2, store.OUT, store.SOURCES, NOW - 300, NOW)["total"][0] == 6000
    queries.close()
    writer.close()


def test_only_the_top_are_kept_and_the_rest_is_other(tmp_path):
    writer = store.Summarizer(tmp_path / "flows.db", clock=lambda: NOW, top_n=3)
    writer.add_flows([flow(src=f"10.0.0.{number}", octets=number * 100) for number in range(1, 11)], NOW)
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    top = queries.top("192.0.2.1", 1, store.IN, store.SOURCES, NOW - 300, NOW, limit=2)
    assert [row[0] for row in top["rows"]] == ["10.0.0.10", "10.0.0.9"]
    assert top["other"][0] == sum(number * 100 for number in range(1, 9))
    assert top["total"][0] == sum(number * 100 for number in range(1, 11))
    queries.close()
    writer.close()


def test_open_minutes_are_rewritten_then_closed_and_old_data_trimmed(tmp_path):
    clock = [NOW]
    writer = store.Summarizer(tmp_path / "flows.db", raw_seconds=600, summary_days=1, clock=lambda: clock[0])
    writer.add_flows([flow(octets=100)], NOW)
    writer.flush(NOW)
    writer.add_flows([flow(octets=50)], NOW)  # Same minute, still open: rewritten with both
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    assert queries.top("192.0.2.1", 1, store.IN, store.SOURCES, NOW - 300, NOW)["rows"][0][1] == 150
    clock[0] = NOW + 10 * 60
    writer.flush(clock[0])
    assert writer.buckets == {}
    assert queries.top("192.0.2.1", 1, store.IN, store.SOURCES, NOW - 300, NOW)["rows"][0][1] == 150
    assert queries.summary()["raw_flows"] == 0  # Past the 10 minutes raw flows are kept
    clock[0] = NOW + 2 * 86400
    writer.next_trim = 0
    writer.flush(clock[0])
    assert queries.top("192.0.2.1", 1, store.IN, store.SOURCES, NOW - 300, NOW)["rows"] == []
    queries.close()
    writer.close()


def test_find_flows_by_address_or_subnet(tmp_path):
    writer = summarizer(tmp_path)
    writer.add_flows([flow(), flow(src="10.9.9.9", dst="192.168.1.1")], NOW)
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    assert [item["src"] for item in queries.flows("10.2.2.9", NOW - 300, NOW)] == ["10.1.1.5"]
    assert [item["dst"] for item in queries.flows("192.168.1.0/24", NOW - 300, NOW)] == ["192.168.1.1"]
    assert len(queries.flows("", NOW - 300, NOW)) == 2
    with pytest.raises(ValueError):
        queries.flows("not an address", NOW - 300, NOW)
    queries.close()
    writer.close()


# --------------------------------------------------------------------- Collector and API


def send(port, packet):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(packet, ("127.0.0.1", port))
    sock.close()


def wait_for(condition, seconds=5.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(0.05)
    return False


def test_collector_over_udp_and_the_api(tmp_path, monkeypatch):
    monkeypatch.setattr(collector, "FLUSH_SECONDS", 0.1)
    flows_collector = collector.FlowCollector(tmp_path / "flows.db", port=0, address="127.0.0.1")
    flows_collector.start()
    try:
        now = int(time.time())
        send(flows_collector.port, v9_packet([v9_template(256, FNF_APP_FIELDS),
                                              v9_options_template(258, [(1, 4)], [(95, 4), (96, 24), (94, 55)]),
                                              data_set(258, [b"\0\0\0\0" + app_option(0x0D0001BB, "ssl")])],
                                             export_time=now))
        send(flows_collector.port, v9_packet([data_set(256, [fnf_record("10.1.1.5", "10.2.2.9", 51000, 443,
                                                                        octets=4321, app=0x0D0001BB)])],
                                             export_time=now))
        assert wait_for(lambda: flows_collector.status()["flows"] == 1)
        status = flows_collector.status()
        assert status["exporters"]["127.0.0.1"]["templates"] == 2
        queries = store.FlowQueries(flows_collector.path)
        server = api.FlowApi(queries, flows_collector.status, port=0)
        server.start()
        try:
            source = api.ServiceSource(server.port)
            assert wait_for(lambda: source.exporters() != [])
            top = source.top("127.0.0.1", 1, store.IN, store.APPLICATIONS, now - 300, now + 60)
            assert top["rows"][0][:2] == ["ssl", 4321]
            assert source.status()["running"] is True
            assert [item["dst"] for item in source.flows("10.1.1.5", now - 300)] == ["10.2.2.9"]
            with pytest.raises(api.FlowSourceError):
                source.flows("nonsense")
            # A browser's request (no X-NOMAD header) is refused
            import urllib.error
            import urllib.request
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                    f"http://127.0.0.1:{server.port}/v1/status", timeout=5)
            assert refused.value.code == 403
            local = api.LocalSource(flows_collector)
            assert local.top("127.0.0.1", 1, store.IN, store.SOURCES, now - 300, now + 60)["rows"][0][0] == \
                "10.1.1.5"
            local.close()
        finally:
            server.stop()
            queries.close()
    finally:
        flows_collector.stop()


def test_second_collector_on_the_same_port_is_refused(tmp_path):
    first = collector.FlowCollector(tmp_path / "a.db", port=0, address="127.0.0.1")
    first.start()
    try:
        second = collector.FlowCollector(tmp_path / "b.db", port=first.port, address="127.0.0.1")
        with pytest.raises(OSError) as refused:
            second.start()
        assert "in use" in collector.port_problem(refused.value, first.port)
    finally:
        first.stop()


def test_service_source_says_when_nothing_answers():
    with pytest.raises(api.FlowSourceError):
        api.ServiceSource(port=1, timeout=1).status()


def test_service_engine_runs_collector_and_api(tmp_path):
    from nomad.flows import service
    config = service.make_config(port=0, raw_hours=1, summary_days=2, api_port=0)
    engine = service.CollectorEngine(tmp_path, config)
    engine.start()
    try:
        assert api.ServiceSource(engine.api.port).status()["summary_days"] == 2
    finally:
        engine.shutdown()


def test_a_minute_with_too_many_keys_sums_the_smaller_away(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "MAX_KEYS", 10)
    writer = store.Summarizer(tmp_path / "flows.db", clock=lambda: NOW, top_n=3)
    writer.add_flows([flow(src=f"10.0.1.{number}", octets=number * 10) for number in range(1, 31)], NOW)
    assert all(len(bucket.keys[store.SOURCES]) <= 10 for bucket in writer.buckets.values())
    writer.flush(NOW)
    queries = store.FlowQueries(tmp_path / "flows.db")
    top = queries.top("192.0.2.1", 1, store.IN, store.SOURCES, NOW - 300, NOW, limit=3)
    assert [row[0] for row in top["rows"]] == ["10.0.1.30", "10.0.1.29", "10.0.1.28"]
    assert top["total"][0] == pytest.approx(sum(range(10, 310, 10)), abs=30)  # Rounding over the 2 minutes
    assert top["other"][0] + sum(row[1] for row in top["rows"]) == top["total"][0]
    queries.close()
    writer.close()
