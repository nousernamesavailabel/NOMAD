import pytest

from nomad.icmp import IP_DEST_HOST_UNREACHABLE, IP_REQ_TIMED_OUT, IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, EchoReply
from nomad.mtr import HopRow, HopStats, MtrTrace, hop_losses, report_text

TARGET = "8.8.8.8"


def expired(address, rtt):
    return EchoReply(IP_TTL_EXPIRED_TRANSIT, address, rtt)


def timed_out():
    return EchoReply(IP_REQ_TIMED_OUT)


def reply(rtt):
    return EchoReply(IP_SUCCESS, TARGET, rtt, 117)


def test_hop_stats():
    hop = HopStats(1)
    for probe in (expired("10.0.0.1", 2), timed_out(), expired("10.0.0.1", 4), expired("10.0.0.2", 6)):
        hop.add(probe)
    row = hop.row()
    assert (row.sent, row.received, row.loss_percent) == (4, 3, 25.0)
    assert (row.last, row.best, row.worst, row.average) == (6, 2, 6, 4)
    assert row.stdev == pytest.approx((8 / 3) ** 0.5)
    assert row.address == "10.0.0.1" and row.other_addresses == ("10.0.0.2",)
    assert not row.last_lost


def test_rounds_find_the_destination_and_stop_probing_past_it():
    trace = MtrTrace(max_hops=6)
    assert trace.probe_ttls() == [1, 2, 3, 4, 5, 6]
    # Every hop is probed at once; hops 3 and beyond reach the target
    trace.add_round({1: expired("10.0.0.1", 1), 2: timed_out(), 3: reply(20), 4: reply(21), 5: reply(20),
                     6: reply(22)})
    assert trace.reached and trace.destination_ttl == 3
    assert trace.probe_ttls() == [1, 2, 3]
    assert [row.ttl for row in trace.rows()] == [1, 2, 3]
    assert trace.hops[4].sent == 0  # Replies past the destination aren't counted
    trace.add_round({1: expired("10.0.0.1", 1), 2: expired("10.0.0.2", 5), 3: timed_out()})
    rows = trace.rows()
    assert rows[1].address == "10.0.0.2" and rows[1].loss_percent == 50
    assert rows[2].loss_percent == 50 and rows[2].last_lost


def test_unanswered_target_shows_one_row_past_the_last_router():
    trace = MtrTrace(max_hops=30)
    trace.add_round({ttl: expired(f"10.0.0.{ttl}", ttl) if ttl <= 4 else timed_out() for ttl in range(1, 31)})
    assert not trace.reached and trace.probe_ttls() == list(range(1, 31))
    assert [row.address for row in trace.rows()] == ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", ""]


def test_unreachable_ends_the_path():
    trace = MtrTrace(max_hops=10)
    trace.add_round({1: expired("10.0.0.1", 1), 2: EchoReply(IP_DEST_HOST_UNREACHABLE, "10.0.0.2", 3),
                     3: EchoReply(IP_DEST_HOST_UNREACHABLE, "10.0.0.2", 3)})
    assert trace.stop_ttl == 2 and trace.probe_ttls() == [1, 2]
    rows = trace.rows()
    assert len(rows) == 2 and rows[1].note == "Destination host unreachable."


def test_report_text():
    trace = MtrTrace(max_hops=3)
    trace.add_round({1: expired("10.0.0.1", 0), 2: timed_out(), 3: reply(15)})
    text = report_text("Tracing route to example", trace.rows(), {"10.0.0.1": "router.lan"})
    lines = text.splitlines()
    assert lines[0] == "Tracing route to example"
    assert lines[2].split() == ["Hop", "Host", "Loss%", "Path%", "Sent", "Last", "Avg", "Best", "Worst", "StDev",
                                "Note"]
    assert lines[3].split()[:5] == ["1", "router.lan", "(10.0.0.1)", "0%", "0%"]
    assert lines[4].split()[:5] == ["2", "???", "100%", "0%", "1"]
    assert lines[4].endswith("Router doesn't answer probes; traffic passes it fine")
    assert lines[5].split()[:6] == ["3", TARGET, "0%", "0%", "1", "15"]


def hop(ttl, loss, address=None):
    """A hop that answered all but loss% of ten probes."""
    received = 10 - loss // 10
    return HopRow(ttl, address if address is not None else (f"10.0.0.{ttl}" if received else ""), (), 10,
                  received, 5.0, 5.0 if received else None, 5.0, 5.0, 0.0, "", False)


def test_loss_at_one_router_is_the_router_skipping_probes():
    losses = hop_losses([hop(1, 0), hop(2, 60), hop(3, 100), hop(4, 0)])
    assert [loss.path for loss in losses] == [0, 0, 0, 0]
    assert [loss.router for loss in losses] == [0, 60, 100, 0]
    assert losses[1].note == "Router skips 60% of probes; traffic passes it fine"
    assert losses[2].note == "Router doesn't answer probes; traffic passes it fine"
    assert not losses[0].note and not losses[3].note


def test_loss_that_carries_on_starts_at_its_first_hop():
    # Hop 3 loses 20% for real (later hops all lose at least that), and its router skips another 30%;
    # hop 5 adds 10% more on top
    losses = hop_losses([hop(1, 0), hop(2, 0), hop(3, 50), hop(4, 20), hop(5, 30), hop(6, 30, TARGET)])
    assert [loss.path for loss in losses] == [0, 0, 20, 20, 30, 30]
    assert [loss.added for loss in losses] == [0, 0, 20, 0, 10, 0]
    assert losses[2].note == "Router skips 30% of probes; traffic passes it fine; Loss starts here (20%)"
    assert losses[4].note == "10% more lost here"
    assert not losses[3].note and not losses[5].note


def test_hops_past_the_last_reply_cant_be_judged():
    losses = hop_losses([hop(1, 0), hop(2, 20), hop(3, 100)])
    assert losses[2].path is None and not losses[2].note
    assert losses[1].path == 20 and losses[1].note == "Loss starts here (20%)"
    assert hop_losses([]) == []
