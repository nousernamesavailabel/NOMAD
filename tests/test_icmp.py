from nomad.icmp import IP_REQ_TIMED_OUT, PROBE_ERROR, PROBE_OK, PROBE_TIMEOUT, PROBE_TOO_BIG, EchoReply, \
    PingStats, find_path_mtu, format_reply


def fake_probe(path_mtu, timeouts=None, calls=None):
    """A probe for a path whose MTU is path_mtu. timeouts maps an MTU to how many times it times out first."""
    timeouts = dict(timeouts or {})

    def probe(mtu):
        if calls is not None:
            calls.append(mtu)
        if timeouts.get(mtu, 0) > 0:
            timeouts[mtu] -= 1
            return PROBE_TIMEOUT, "timed out"
        return (PROBE_OK, "OK") if mtu <= path_mtu else (PROBE_TOO_BIG, "too big")
    return probe


def test_finds_exact_path_mtu():
    for path_mtu in (1200, 1350, 1472, 1499, 1500):
        mtu, _ = find_path_mtu(fake_probe(path_mtu), 1200, 1500)
        assert mtu == path_mtu


def test_maximum_works_immediately():
    calls = []
    mtu, _ = find_path_mtu(fake_probe(1500, calls=calls), 1200, 1500)
    assert mtu == 1500 and calls == [1500]


def test_single_timeout_is_retried_not_treated_as_too_big():
    mtu, _ = find_path_mtu(fake_probe(1500, timeouts={1500: 1}), 1200, 1500, retries=2)
    assert mtu == 1500


def test_persistent_timeouts_count_as_too_big():
    # A "black hole" router that silently drops big packets
    def probe(mtu):
        return (PROBE_OK, "OK") if mtu <= 1400 else (PROBE_TIMEOUT, "timed out")
    mtu, _ = find_path_mtu(probe, 1200, 1500, retries=1)
    assert mtu == 1400


def test_unreachable_host():
    mtu, message = find_path_mtu(lambda mtu: (PROBE_TIMEOUT, "timed out"), 1200, 1500, retries=0)
    assert mtu is None and "No reply" in message


def test_error_stops_search():
    mtu, message = find_path_mtu(lambda mtu: (PROBE_ERROR, "Destination host unreachable."), 1200, 1500)
    assert mtu is None and "unreachable" in message


def test_stop_request():
    mtu, message = find_path_mtu(fake_probe(1400), 1200, 1500, should_stop=lambda: True)
    assert mtu is None and message == "Stopped."


def test_ping_stats():
    stats = PingStats()
    for reply in (EchoReply(0, "1.1.1.1", 10, 57), EchoReply(IP_REQ_TIMED_OUT), EchoReply(0, "1.1.1.1", 20, 57)):
        stats.add(reply)
    assert (stats.sent, stats.received, stats.lost, stats.loss_percent) == (3, 2, 1, 33)
    assert "min 10 ms, avg 15 ms, max 20 ms" in stats.summary()


def test_format_reply():
    assert format_reply(EchoReply(0, "8.8.8.8", 0, 117), 32) == "Reply from 8.8.8.8: bytes=32 time<1ms TTL=117"
    assert format_reply(EchoReply(IP_REQ_TIMED_OUT), 32) == "Request timed out."
