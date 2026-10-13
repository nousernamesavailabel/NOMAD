"""Packet Capture's live view: pktmon's packet events read as they come (the ETW listener, the feed holding them back
to put them in order), decoded one at a time exactly as a file is, and shown in the viewer while capturing."""
import ctypes
import os
import struct
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from capture_samples import PC, ROUTER, erspan_wrap, frame_ip, sample_packets, udp, write_pcapng  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad import capture as capture_module  # noqa: E402
from nomad import etw, pktmon, pktmon_live  # noqa: E402
from nomad.packets import capfile, dfilter  # noqa: E402
from nomad.packets.live import LiveCapture  # noqa: E402
from nomad.packets.reader import Record  # noqa: E402
from nomad.ui import capture_viewer  # noqa: E402

START = 1_790_000_000.0


def event(packet, media=1, original=None):
    """A pktmon packet event's data (event 160) carrying packet."""
    original = len(packet) if original is None else original
    return struct.pack("<QHHHHHHHIIHH", 7, 1, 1, 1, media, 3, 1, 0, 0, 0, original, len(packet)) + packet


def records(packets):
    return [Record(1, START + seconds, frame, len(frame)) for seconds, frame in packets]


class FakeSession:
    def __init__(self, lost=(0, 0)):
        self.lost_counts = lost
        self.started = self.stopped = False

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True

    def lost(self):
        return self.lost_counts


# ----------------------------------------------------------------- pktmon's packet events

def test_a_packet_event_gives_its_packet():
    frame = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.53", 17, udp(50000, 53, b"x" * 20))
    link_type, packet, wire_length, header = pktmon_live.parse_packet(event(frame))
    assert (link_type, packet, wire_length, header) == (1, frame, len(frame), pktmon_live.PACKET_HEADER)
    _, cut, wire_length, _ = pktmon_live.parse_packet(event(frame[:40], original=len(frame)))
    assert cut == frame[:40] and wire_length == len(frame)  # Only the start kept (Capture whole packets unticked)


def test_ip_without_ethernet_is_told_apart():
    ip_packet = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.53", 17, udp(50000, 53, b"abc"))[14:]
    assert pktmon_live.parse_packet(event(ip_packet, media=3))[0] == pktmon_live.RAW_IP
    frame = bytes.fromhex("45aa") + frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.53", 17, udp(1, 2, b""))[2:]
    assert pktmon_live.parse_packet(event(frame, media=3))[0] == pktmon_live.ETHERNET  # A MAC starting 45


def test_a_different_header_length_is_found():
    frame = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.53", 17, udp(50000, 53, b"abc"))
    data = bytes(36) + struct.pack("<HH", len(frame), len(frame)) + frame
    assert pktmon_live.parse_packet(data)[1:] == (frame, len(frame), 40)
    assert pktmon_live.parse_packet(b"\x01\x02\x03") is None


def test_the_feed_puts_packets_in_order_once_they_are_old_enough():
    session = FakeSession(lost=(5, 0))
    feed = pktmon_live.LiveFeed(session)
    feed.start()
    now = time.time()
    first = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.1", 17, udp(1, 2, b"first"))
    second = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.1", 17, udp(1, 2, b"second"))
    latest = frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.1", 17, udp(1, 2, b"latest"))
    feed.event(160, now - 2.0, event(second))  # Came first, from another processor's batch
    feed.event(160, now - 3.0, event(first))
    feed.event(160, now, event(latest))  # Too new: something older may still be on its way
    feed.event(20, now, b"not a packet")
    feed.event(160, now - 2.5, b"\x00\x01")  # Unreadable
    ready = feed.take(now)
    assert [bytes(record.data) for record in ready] == [first, second]
    assert feed.waiting == 1 and feed.missed() == (6, False)
    assert [bytes(record.data) for record in feed.take(now, everything=True)] == [latest]
    feed.stop()
    assert session.started and session.stopped


def test_the_feed_drops_packets_past_its_limit(monkeypatch):
    monkeypatch.setattr(pktmon_live, "MAX_WAITING", 2)
    feed = pktmon_live.LiveFeed(FakeSession(lost=(0, 3)))
    for _ in range(4):
        feed.event(160, time.time(), event(b"\x00" * 60))
    assert feed.waiting == 2 and feed.missed() == (2, True)


# ----------------------------------------------------------------- The ETW listener

def test_etw_structures_are_the_size_windows_expects():
    sizes = {"EVENT_TRACE_PROPERTIES": 120, "EVENT_TRACE_LOGFILEW": 448, "EVENT_RECORD": 112, "EVENT_HEADER": 80,
             "TRACE_LOGFILE_HEADER": 280, "EVENT_TRACE": 88}
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        pytest.skip("Sizes checked are 64-bit Windows'")
    assert {name: ctypes.sizeof(getattr(etw, name)) for name in sizes} == sizes
    guid = etw.GUID.parse(pktmon_live.PROVIDER)
    assert guid.Data1 == 0x4D4F80D9 and bytes(guid.Data4).hex() == "bb5b19c90402c5ac"
    assert etw.filetime_seconds((START + etw.FILETIME_EPOCH) * 1e7) == pytest.approx(START)


def test_an_etw_event_reaches_the_listener():
    got = []
    session = etw.RealtimeSession("NOMAD test", pktmon_live.PROVIDER, pktmon_live.PAYLOAD_KEYWORD,
                                  lambda *arguments: got.append(arguments))
    data = ctypes.create_string_buffer(b"packet bytes", 12)
    record = etw.EVENT_RECORD()
    record.EventHeader.ProviderId = etw.GUID.parse(pktmon_live.PROVIDER)
    record.EventHeader.EventDescriptor.Id = 160
    record.EventHeader.TimeStamp = int((START + etw.FILETIME_EPOCH) * 1e7)
    record.UserData = ctypes.cast(data, ctypes.c_void_p)
    record.UserDataLength = 12
    session.event(ctypes.pointer(record))
    other = etw.EVENT_RECORD()  # Another provider's (the session's own header): left out
    session.event(ctypes.pointer(other))
    assert len(got) == 1 and got[0][0] == 160 and got[0][2] == b"packet bytes"
    assert got[0][1] == pytest.approx(START, abs=1e-3)


@pytest.mark.skipif(os.name != "nt" or ctypes.windll.shell32.IsUserAnAdmin(), reason="Needs Windows, not elevated")
def test_listening_needs_administrator_rights():
    session = etw.RealtimeSession("NOMAD test", pktmon_live.PROVIDER, pktmon_live.PAYLOAD_KEYWORD, print)
    with pytest.raises(etw.EtwError, match="administrator"):
        session.start()


# ----------------------------------------------------------------- Decoding as packets come

def test_a_live_capture_decodes_as_a_file_does(tmp_path):
    packets = sample_packets()
    loaded = capfile.load(str(write_pcapng(tmp_path / "sample.pcapng", packets)))
    whole = loaded.view(False)
    live = LiveCapture("live", unwrapped=False)
    shown = []
    for start in range(0, len(packets), 4):  # A few at a time, looked at in between
        live.add(records(packets[start:start + 4]))
        shown += live.decode(limit=3)
        live.finish()
    shown += live.decode()
    view = live.finish()
    assert shown == list(range(len(whole.packets)))
    columns = [(p.number, round(p.time, 6), p.src, p.dst, p.protocol, p.info, p.stream, p.analysis, p.color)
               for p in view.packets]
    assert columns == [(p.number, round(p.time, 6), p.src, p.dst, p.protocol, p.info, p.stream, p.analysis, p.color)
                       for p in whole.packets]
    assert [(problem.severity, problem.summary, problem.count) for problem in view.problems] == \
        [(problem.severity, problem.summary, problem.count) for problem in whole.problems]
    assert view.summary.headline() == whole.summary.headline()
    assert len(live.capture.mirrored) == len(loaded.mirrored) == 1


def test_a_live_capture_filters_what_comes():
    packets = sample_packets()
    live = LiveCapture("live", unwrapped=False)
    live.add(records(packets[:12]))
    live.decode()
    assert len(live.set_filter(dfilter.compile_filter("tcp.port == 80"))) == 3
    live.add(records(packets[12:]))
    assert len(live.decode()) == 4
    assert live.set_filter(dfilter.compile_filter("frame.number <= 2")) == [0, 1]
    assert live.decode() == []


def test_a_live_capture_of_mostly_erspan_switches_to_the_mirrored_frames(monkeypatch):
    monkeypatch.setattr("nomad.packets.live.DEFAULT_UNWRAP_AFTER", 10)
    inner = [frame_ip("00:de:ad:00:00:01", "00:de:ad:00:00:02", "172.16.0.1", "172.16.0.2", 17,
                      udp(1234, 5001, bytes([n]) * 10)) for n in range(12)]
    live = LiveCapture("live")
    assert not live.add(records([(n * 0.01, erspan_wrap(frame)) for n, frame in enumerate(inner[:6])]))
    assert not live.unwrapped
    assert live.add(records([(0.1 + n * 0.01, erspan_wrap(frame)) for n, frame in enumerate(inner[6:])]))
    assert live.unwrapped and len(live.decode()) == 12
    live.show(False)
    assert not live.unwrapped and len(live.decode()) == 12


# ----------------------------------------------------------------- The viewer while capturing

class FakeFeed:
    """Hands over the sample's packets a few at a time, as a LiveFeed would."""

    def __init__(self, packets, step=5):
        self.pending = records(packets)
        self.step = step
        self.missed_count = 0

    def take(self, now=None, everything=False):
        ready, self.pending = self.pending[:self.step], self.pending[self.step:]
        return ready

    @property
    def waiting(self):
        return len(self.pending)

    def missed(self):
        return self.missed_count, False


class Window(QWidget):
    pass


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def viewer(app):
    window = Window()
    page = capture_viewer.CaptureViewer(window)
    yield page
    page.shutdown()  # Even when a test fails: a thread left running takes Python down at exit
    page.deleteLater()
    window.deleteLater()


def settle(viewer, until, seconds=10):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        QApplication.processEvents()
        if until():
            return True
        time.sleep(0.01)
    return False


def test_the_viewer_shows_packets_as_they_come(viewer):
    feed = FakeFeed(sample_packets())
    viewer.start_live(feed, "NOMAD capture.pcapng", unwrapped=False)
    assert viewer.follow_check.isVisibleTo(viewer) and not viewer.open_button.isEnabled()
    assert settle(viewer, lambda: viewer.model.rowCount() == 35)
    assert settle(viewer, lambda: "35 packets" in viewer.status_label.text())
    assert "1 ERSPAN frames inside" in viewer.status_label.text()

    viewer.filter_input.setText("dns")
    viewer.apply_filter()
    assert settle(viewer, lambda: viewer.model.rowCount() == 6)
    assert settle(viewer, lambda: "Showing 6 that match the filter" in viewer.status_label.text())

    viewer.ask_for_sums()
    viewer.tabs.setCurrentIndex(2)
    assert settle(viewer, lambda: viewer.problem_tree.topLevelItemCount() > 1)
    assert viewer.tabs.tabText(2).startswith("Problems (")

    viewer.tabs.setCurrentIndex(1)  # Devices Heard (CDP and LLDP) filled in as they come
    viewer.summary_tabs.setCurrentIndex(4)
    assert settle(viewer, lambda: viewer.neighbor_table.rowCount() == 2)
    assert "the switch and port this is plugged into" in viewer.neighbor_note.text()

    viewer.toggle_unwrapped()
    assert settle(viewer, lambda: viewer.view.unwrapped and viewer.model.rowCount() == 1)
    viewer.ask_for_sums()
    assert settle(viewer, lambda: viewer.neighbor_table.rowCount() == 0)
    assert "No device has announced itself over CDP or LLDP yet" in viewer.neighbor_note.text()
    assert viewer.unwrap_button.text() == "Show as Captured"

    feed.missed_count = 12
    assert settle(viewer, lambda: "missed 12 packets" in viewer.status_label.text())
    viewer.stop_live()
    assert viewer.live is None and not viewer.follow_check.isVisibleTo(viewer)
    assert viewer.model.rowCount() == 1 and viewer.open_button.isEnabled()


def test_following_the_newest_stops_when_scrolled_up(viewer):
    viewer.resize(900, 300)
    viewer.show()
    packets = [(n * 0.001, frame_ip(PC, ROUTER, "10.0.10.9", "10.0.0.1", 17, udp(1000, 2000, n.to_bytes(4, "big"))))
               for n in range(300)]
    viewer.start_live(FakeFeed(packets, step=100), "busy.pcapng", unwrapped=False)
    assert settle(viewer, lambda: viewer.model.rowCount() == 300)
    bar = viewer.table.verticalScrollBar()
    assert settle(viewer, lambda: bar.value() == bar.maximum() > 0)
    bar.setValue(0)
    assert not viewer.follow_check.isChecked()
    bar.setValue(bar.maximum())
    assert viewer.follow_check.isChecked()


# ----------------------------------------------------------------- The capture

def test_a_capture_starts_listening_before_pktmon(monkeypatch):
    calls = []
    monkeypatch.setattr(pktmon, "pktmon", lambda *arguments, timeout=120: calls.append(arguments[0]) or "")
    monkeypatch.setattr(pktmon, "find_pktmon", lambda: "pktmon.exe")
    session = FakeSession()
    monkeypatch.setattr(capture_module, "LiveFeed", lambda: pktmon_live.LiveFeed(session))
    job = capture_module.Capture(capture_module.CaptureFilter(), live=True)
    session.start = lambda: calls.append("listen")
    job.start()
    assert job.live and calls.index("listen") < calls.index("start")
    job.stop()
    job.cleanup()
    assert session.stopped


def test_a_capture_carries_on_when_it_cant_listen(monkeypatch):
    monkeypatch.setattr(pktmon, "pktmon", lambda *arguments, timeout=120: "")
    monkeypatch.setattr(pktmon, "find_pktmon", lambda: "pktmon.exe")

    class Refused(FakeSession):
        def start(self):
            raise etw.EtwError(5, "Couldn't start listening to Windows' events (NOMAD needs to run as administrator).")

    monkeypatch.setattr(capture_module, "LiveFeed", lambda: pktmon_live.LiveFeed(Refused()))
    job = capture_module.Capture(capture_module.CaptureFilter(), live=True)
    job.start()
    assert job.running and not job.live and "administrator" in job.live_problem
    job.cleanup()


def test_the_page_shows_a_capture_live_and_stops_with_it(app, tmp_path, monkeypatch):
    from types import SimpleNamespace

    from nomad.ui import capture_tab

    class PageWindow(QWidget):
        snapshot = SimpleNamespace(real_adapters=lambda: [])

        def set_busy(self, key, text):
            pass

        def clear_busy(self, key):
            pass

        def require_admin(self, what):
            return True

    made = []

    class FakeCapture:
        def __init__(self, capture_filter, whole, size, promiscuous, live=False):
            made.append(live)
            self.filter, self.promiscuous, self.promiscuous_problem = capture_filter, None, ""
            self.running, self.live, self.live_problem = True, live, ""
            self.feed = FakeFeed(sample_packets())

        def start(self):
            pass

        def elapsed(self):
            return 0.0

        def size(self):
            return 0

        def stop(self):
            self.running = False

        def cleanup(self):
            pass

    window = PageWindow()
    page = capture_tab.CaptureTab(window)
    try:
        monkeypatch.setattr(capture_tab, "Capture", FakeCapture)
        monkeypatch.setattr(capture_tab, "find_pktmon", lambda: "pktmon.exe")
        monkeypatch.setattr(capture_tab, "run_in_background", lambda function, done, failed: done(function()))
        page.output_input.setText(str(tmp_path / "out.pcapng"))
        assert page.live_check.isChecked()
        page.start()
        assert made == [True] and page.viewer.live is not None
        assert page.settings_panel.isHidden()  # Folded away while capturing
        assert settle(page.viewer, lambda: page.viewer.model.rowCount() == 35)
        page.stop(save=False)
        assert page.viewer.live is None and page.viewer.model.rowCount() == 35
        assert "Capture discarded" in page.status_label.text()
    finally:
        page.shutdown()
        page.deleteLater()
        window.deleteLater()
