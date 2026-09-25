import socket
import struct
import threading

import pytest

from nomad.iperf import UDP_CONNECT_MSG, UDP_CONNECT_REPLY, IperfClient, IperfError, IperfParams, \
    IperfServer, StreamStats, _udp_hello_reply, format_bitrate, format_bytes, make_cookie, stream_ids


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def server():
    """An IperfServer on a free port for the duration of a test."""
    stop = threading.Event()
    port = free_port()
    log = []
    instance = IperfServer(port, on_log=log.append, should_stop=stop.is_set)
    thread = threading.Thread(target=instance.serve, daemon=True)
    thread.start()
    while not any("listening" in line for line in log):
        threading.Event().wait(0.01)
    yield port, log
    stop.set()
    thread.join(5)


def test_stream_ids_skip_two():
    # iperf3 numbers streams 1, 3, 4, ...; a mismatch makes real iperf3 reject our results
    assert stream_ids(1) == [1]
    assert stream_ids(4) == [1, 3, 4, 5]


def test_cookie_format():
    cookie = make_cookie()
    assert len(cookie) == 37 and cookie.endswith(b"\0")


def test_params_round_trip():
    params = IperfParams("udp", duration=5, parallel=3, reverse=True, bitrate=2_000_000, length=1200)
    data = params.to_json()
    assert data["udp"] is True and data["reverse"] is True and data["len"] == 1200
    assert IperfParams.from_json(data) == params


def test_unsupported_modes_rejected():
    with pytest.raises(IperfError):
        IperfParams.from_json({"tcp": True, "bidirectional": True})


def test_udp_hello_reply_matches_byte_order():
    assert _udp_hello_reply(struct.pack("<I", UDP_CONNECT_MSG)) == struct.pack("<I", UDP_CONNECT_REPLY)
    assert _udp_hello_reply(struct.pack(">I", UDP_CONNECT_MSG)) == struct.pack(">I", UDP_CONNECT_REPLY)
    assert _udp_hello_reply(b"junk") is None


def test_udp_loss_and_reordering():
    stats = StreamStats(1)
    for number in (1, 2, 5, 3, 6):  # 3 and 4 missing, then 3 arrives late
        stats.record_udp_packet(number, sent_seconds=0.0, arrival_seconds=0.01, size=100)
    assert stats.packets == 6
    assert stats.lost == 1  # Only 4 is really lost
    assert stats.out_of_order == 1


def test_formatting():
    assert format_bytes(1024 ** 2 * 3) == "3.00 MBytes"
    assert format_bitrate(941_000_000) == "941 Mbits/sec"


@pytest.mark.parametrize("params", [
    IperfParams("tcp", duration=1, parallel=1),
    IperfParams("tcp", duration=1, parallel=3, reverse=True),
    IperfParams("udp", duration=1, parallel=2, bitrate=5_000_000),
    IperfParams("udp", duration=1, parallel=1, reverse=True, bitrate=5_000_000),
])
def test_loopback(server, params):
    port, log = server
    intervals = []
    result = IperfClient("127.0.0.1", port, params, on_interval=intervals.append).run()
    assert result.sender_bytes > 0 and result.receiver_bytes > 0
    assert intervals and intervals[-1].end == pytest.approx(1.0, abs=0.2)
    if params.udp:
        assert result.packets > 0
        assert result.receiver_bps == pytest.approx(params.bitrate * params.parallel, rel=0.3)
    assert any(line.startswith("Test from 127.0.0.1") for line in log)


def test_stop_early_still_returns_results(server):
    port, _ = server
    calls = []

    def should_stop():
        calls.append(1)
        return len(calls) > 3

    result = IperfClient("127.0.0.1", port, IperfParams("tcp", duration=30), should_stop=should_stop).run()
    assert result.sender_seconds < 5 and result.receiver_bytes > 0


def test_connection_refused_message():
    with pytest.raises(IperfError, match="Couldn't connect"):
        IperfClient("127.0.0.1", free_port(), IperfParams(duration=1), timeout=2).run()
