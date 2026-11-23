"""The Syslog Collector: keeping messages (days and size), the service's API, the feed the Map Watcher and the Syslog
page read, moving between the service and the port, and the Syslog page reading and searching the service."""
import datetime
import os
import socket
import time
import urllib.error
import urllib.request

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad.syslog import parse_message  # noqa: E402
from nomad.syslogs import api, collector, feed, store  # noqa: E402
from nomad.syslogs import service as syslog_service  # noqa: E402


def message(text, source="10.0.0.1", when=None):
    return parse_message(text, source, datetime.datetime.fromtimestamp(when) if when else None)


def wait_for(condition, seconds=5, app=None):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if app is not None:
            app.processEvents()
        if condition():
            return True
        time.sleep(0.02)
    return False


# --------------------------------------------------------------------- Keeping messages


def test_store_keeps_searches_and_lists_senders(tmp_path):
    kept = store.SyslogStore(tmp_path / "syslog.db")
    queries = None
    try:
        last = kept.add([message("<189>Oct 11 22:14:15 sw1 53: %LINK-3-UPDOWN: Interface Gi1/0/7, changed state to up"),
                         message("<14>Oct 11 22:14:16 sw1 app: 100% done_now", "10.0.0.1"),
                         message("<11>fw1 kernel: link down", "10.0.0.2")])
        assert last == 3
        queries = store.SyslogQueries(tmp_path / "syslog.db")
        found = queries.search("updown gi1/0/7")
        assert [item["id"] for item in found] == [1]
        assert [item["id"] for item in queries.search("100%")] == [2]  # % and _ are taken as they are
        assert queries.search("done_now")[0]["id"] == 2 and queries.search("donexnow") == []
        assert [item["id"] for item in queries.search(severity=3)] == [3]  # Error and worse
        assert [item["id"] for item in queries.search(source="10.0.0.2")] == [3]
        assert [item["id"] for item in queries.search(limit=2)] == [2, 3]  # The newest, oldest first
        assert [item["id"] for item in queries.since(1)] == [2, 3]
        back = store.message_from_dict(queries.since(0)[0])
        assert back.id == 1 and back.severity_name == "Notice" and back.host == "sw1" and "UPDOWN" in back.message
        senders = {item["source"]: item for item in queries.senders()}
        assert senders["10.0.0.1"]["messages"] == 2 and senders["10.0.0.1"]["host"] == "sw1"
        assert queries.summary()["messages"] == 3
    finally:
        if queries is not None:
            queries.close()
        kept.close()


def test_store_deletes_past_the_days_and_the_oldest_past_the_size(tmp_path):
    now = [1_000_000.0]
    kept = store.SyslogStore(tmp_path / "syslog.db", keep_days=1, max_bytes=10 ** 9, clock=lambda: now[0])
    try:
        kept.add([message("<14>old", when=now[0] - 2 * 86400), message("<14>new", when=now[0] - 60)])
        assert kept.prune() == 1
        assert [row[0] for row in kept.connection.execute("SELECT raw FROM messages")] == ["<14>new"]

        kept.add([message("<14>" + "x" * 2000, when=now[0]) for _ in range(500)])
        kept.max_bytes = kept.used_bytes() // 2
        assert kept.prune() > 0
        assert kept.used_bytes() <= kept.max_bytes
        remaining = [row[0] for row in kept.connection.execute("SELECT id FROM messages ORDER BY id")]
        assert remaining and remaining[-1] == 502  # The newest stay
    finally:
        kept.close()


# --------------------------------------------------------------------- The collector and its API


def send_udp(port, text):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.sendto(text.encode(), ("127.0.0.1", port))


def test_service_engine_collects_and_answers_nomad(tmp_path):
    config = syslog_service.make_config(port=0, tcp=True, keep_days=5, api_port=0)
    engine = syslog_service.CollectorEngine(tmp_path, config)
    engine.start()
    try:
        port = engine.collector.port
        source = api.SyslogServiceSource(engine.api.port, timeout=5)
        assert source.status()["keep_days"] == 5 and source.status()["tcp"]
        send_udp(port, "<189>53: %LINK-3-UPDOWN: Interface Gi1/0/7, changed state to up")
        with socket.create_connection(("127.0.0.1", port)) as tcp:
            tcp.sendall(b"<11>fw1 kernel: over tcp\n")
        assert wait_for(lambda: len(source.since(0)) == 2)
        messages = source.since(0)
        assert {item.protocol for item in messages} == {"UDP", "TCP"}
        assert [item.message for item in source.search("tcp")] == ["fw1 kernel: over tcp"]
        assert source.latest(1)[0].id == messages[-1].id
        assert source.status()["senders"]["127.0.0.1"]["messages"] == 2
        assert source.senders()[0]["source"] == "127.0.0.1"

        request = urllib.request.Request(f"http://127.0.0.1:{engine.api.port}/v1/messages")  # No X-NOMAD header
        with pytest.raises(urllib.error.HTTPError) as refused:
            urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5)
        assert refused.value.code == 403

        second = collector.SyslogCollector(tmp_path / "other.db", port)
        with pytest.raises(OSError) as taken:
            second.start()  # The port is the service's alone
        assert "in use" in collector.port_problem(taken.value, port)
    finally:
        engine.shutdown()


def test_service_source_says_when_nothing_answers():
    with pytest.raises(api.SyslogSourceError, match="Syslog Collector service isn't answering"):
        api.SyslogServiceSource(port=1, timeout=1).status()


def test_service_config_round_trip(tmp_path):
    syslog_service.save_config(syslog_service.make_config(port=1514, tcp=True, keep_days=30, max_gb=0.5), tmp_path)
    config = syslog_service.load_config(tmp_path)
    assert (config["port"], config["tcp"], config["keep_days"], config["max_gb"]) == (1514, True, 30, 0.5)
    assert syslog_service.load_config(tmp_path / "missing")["keep_days"] == store.KEEP_DAYS


# --------------------------------------------------------------------- The feed


class FakeSource:
    timeout = 1

    def __init__(self, messages=()):
        self.messages = list(messages)
        self.fail = False

    def add(self, text):
        item = message(text)
        item.id = (self.messages[-1].id if self.messages else 0) + 1
        self.messages.append(item)

    def check(self):
        if self.fail:
            raise api.SyslogSourceError("The Syslog Collector service isn't answering (refused).")

    def status(self):
        self.check()
        return {"latest_id": self.messages[-1].id if self.messages else 0}

    def latest(self, limit):
        self.check()
        return self.messages[-limit:]

    def since(self, after, limit=1000):
        self.check()
        return [item for item in self.messages if item.id > after][:limit]


def test_feed_starts_from_now_or_with_a_backlog_and_follows():
    source = FakeSource()
    for text in ("<14>one", "<14>two", "<14>three"):
        source.add(text)
    got, problems = [], []
    fresh = feed.ServiceFeed(got.append, source=source, on_problem=problems.append)
    fresh.poll()
    assert got == [] and fresh.last_id == 3  # Only what comes from now
    source.add("<14>four")
    fresh.poll()
    assert [item.message for item in got] == ["four"]

    backlog = []
    with_backlog = feed.ServiceFeed(backlog.append, backlog=2, source=source)
    with_backlog.poll()
    assert [item.message for item in backlog] == ["three", "four"]

    source.messages = []  # Its messages were deleted: it counts from 1 again
    for _ in range(feed.RESTART_CHECK_POLLS):
        fresh.poll()
    assert fresh.last_id == 0
    source.add("<14>again")
    fresh.poll()
    assert got[-1].message == "again"


class ZeroStatusSource(FakeSource):
    """A Syslog Collector before the fix: latest_id 0 in its status until a message came in since it started."""

    def status(self):
        self.check()
        return {"latest_id": 0}


def test_a_service_saying_0_doesnt_get_its_messages_handed_over_again():
    source = ZeroStatusSource()
    for text in ("<14>one", "<14>two", "<14>three"):
        source.add(text)
    got = []
    page_feed = feed.ServiceFeed(got.append, backlog=2000, source=source)
    page_feed.poll()
    assert [item.message for item in got] == ["one", "two", "three"]
    for _ in range(feed.RESTART_CHECK_POLLS * 4):  # Two minutes of nothing new
        page_feed.poll()
    assert len(got) == 3  # Not the same three again every 30 s
    source.add("<14>four")
    for _ in range(feed.RESTART_CHECK_POLLS):
        page_feed.poll()
    assert [item.message for item in got] == ["one", "two", "three", "four"]

    watched = []  # The Map Watcher's: from now on only
    watcher_feed = feed.ServiceFeed(watched.append, source=source)
    for _ in range(feed.RESTART_CHECK_POLLS * 2):
        watcher_feed.poll()
    assert watched == []
    source.add("<14>five")
    watcher_feed.poll()
    assert [item.message for item in watched] == ["five"]


def test_the_collector_says_the_newest_kept_id_from_the_start(tmp_path):
    kept = store.SyslogStore(tmp_path / "syslog.db")
    kept.add([message("<14>one"), message("<14>two")])
    kept.close()
    restarted = collector.SyslogCollector(tmp_path / "syslog.db", 0)
    restarted.start()
    try:
        assert restarted.status()["latest_id"] == 2
    finally:
        restarted.stop()


def test_feed_thread_reports_the_service_going_away_and_coming_back(monkeypatch):
    monkeypatch.setattr(feed, "POLL_SECONDS", 0.02)
    source = FakeSource()
    got, problems = [], []
    running = feed.ServiceFeed(got.append, source=source, interval=0.02, on_problem=problems.append)
    running.start()
    try:
        source.add("<14>hello")
        assert wait_for(lambda: got and got[-1].message == "hello") or running.last_id == 1
        source.fail = True
        assert wait_for(lambda: problems and "isn't answering" in problems[-1])
        source.fail = False
        source.add("<14>back")
        assert wait_for(lambda: problems[-1] == "" and got and got[-1].message == "back")
    finally:
        running.stop()
    assert running.thread is None


class FakeFeed:
    made = []

    def __init__(self, callback):
        self.callback = callback
        self.running = False
        FakeFeed.made.append(self)

    def start(self):
        self.running = True

    def stop(self):
        self.running = False


def test_listener_moves_between_the_service_and_the_port():
    calls, service = [], [False]
    port_free = [True]

    def listen():
        if not port_free[0]:
            raise OSError("in use")
        calls.append("listen")

    listener = feed.SyslogListener(print, listen, lambda: calls.append("unlisten"), running=lambda: service[0],
                                   feed_factory=FakeFeed)
    assert listener.start() == listener.PORT and calls == ["listen"]
    assert listener.check() == ""
    service[0] = True  # The Syslog Collector service was installed
    assert listener.check() == listener.SERVICE
    assert calls == ["listen", "unlisten"] and FakeFeed.made[-1].running
    service[0] = False  # ...and removed, with someone else on the port
    port_free[0] = False
    with pytest.raises(OSError):
        listener.check()
    assert not FakeFeed.made[-1].running and listener.mode == ""
    port_free[0] = True
    assert listener.check() == listener.PORT  # Tried again
    listener.stop()
    assert calls[-1] == "unlisten" and listener.check() == ""


def test_map_watcher_service_reads_the_syslog_service(monkeypatch):
    from nomad.netmap import watch_service

    class Maps:
        def sync(self):
            pass

        def map_info(self, map_id):
            return None

    service = [True]
    clock = [0.0]
    engine = watch_service.WatchEngine(Maps(), [], "pc-service", clock=lambda: clock[0], listen=True,
                                       ports=(0, 0), syslog_options={"running": lambda: service[0],
                                                                     "feed_factory": FakeFeed})
    monkeypatch.setattr(watch_service.triggers.TrapReceiver, "start", lambda self: None)
    monkeypatch.setattr(watch_service.triggers.TrapReceiver, "stop", lambda self: None)
    engine.start_listening()
    try:
        assert engine.syslog.mode == feed.SyslogListener.SERVICE
        engine.queue.delay = 0
        FakeFeed.made[-1].callback(message("<189>53: %LINK-3-UPDOWN: Interface Gi1/0/7, changed state to up",
                                           "10.0.0.11"))
        assert [address for address, _ in engine.queue.due()] == ["10.0.0.11"]
        service[0] = False  # Removed: the watcher listens on the port itself again at the next check
        clock[0] += watch_service.SYSLOG_CHECK_SECONDS
        engine.step()
        assert engine.syslog.mode == feed.SyslogListener.PORT
    finally:
        engine.stop_listening()


# --------------------------------------------------------------------- The Syslog page


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    def __init__(self):
        super().__init__()
        self.snapshot = type("Snapshot", (), {"real_adapters": lambda self: []})()
        self.snapshot_changed = FakeSignal()
        self.statuses = []

    def show_status(self, text):
        self.statuses.append(text)


class FakeSignal:
    def connect(self, slot):
        pass


class PageFeed(FakeFeed):
    def __init__(self, callback, **options):
        super().__init__(callback)
        self.options = options


def test_syslog_page_shows_the_service_and_searches_what_it_kept(app, monkeypatch):
    from nomad.ui import syslog_tab
    searched = []

    class Source:
        port = 20557

        def __init__(self, port=20557, timeout=10):
            self.port = port

        def search(self, text="", severity=7, source="", start=None, end=None, before=None, limit=2000):
            searched.append((text, severity, start is not None, limit))
            found = message("<11>fw1 kernel: link down", "10.0.0.2")
            found.id = 7
            return [found]

    monkeypatch.setattr(syslog_tab, "SyslogServiceSource", Source)
    page = syslog_tab.SyslogTab(Window())
    try:
        page.use_service(Source(), {"port": 514, "tcp": False, "keep_days": 90, "senders": {"10.0.0.1": {}}},
                         feed_factory=PageFeed)
        made = FakeFeed.made[-1]
        assert made.running and made.options["backlog"] == syslog_tab.BACKLOG
        assert "Syslog Collector service" in page.status_label.text() and "1 device sent" in page.status_label.text()
        assert not page.start_button.isEnabled() and not page.port_input.isEnabled()
        assert not page.search_button.isHidden()

        made.callback(message("<14>sw1 app: hello"))
        page.flush()
        assert page.table.rowCount() == 1

        page.filter_input.setText("link")
        page.search_kept()
        assert wait_for(lambda: page.history is not None, app=app)
        assert searched == [("link", 7, True, syslog_tab.HISTORY_LIMIT)]
        assert page.table.rowCount() == 1 and page.table.item(0, 1).text() == "10.0.0.2"
        assert page.search_button.text() == "Back to Live" and "kept messages found" in page.count_label.text()

        made.callback(message("<14>sw1 app: link flapped"))
        page.flush()  # Waits while the search results are shown
        assert page.table.rowCount() == 1
        page.toggle_search()  # Back to Live
        assert page.history is None and page.table.rowCount() == 1  # The live ones matching "link"
        assert page.table.item(0, 6).text().endswith("link flapped")

        page.on_feed_problem("The Syslog Collector service isn't answering (refused).")
        page.flush()
        assert "isn't answering" in page.status_label.text()
    finally:
        page.shutdown()
    assert page.feed is None


def test_dialog_frees_the_port_for_the_service_and_gives_the_watcher_it_back(app, monkeypatch):
    from nomad.ui import syslog_service_dialog

    class Watcher:
        def __init__(self):
            self.syslog = object()
            self.calls = []

        def stop_listening(self):
            self.calls.append("stop")
            self.syslog = None

        def update_listening(self):
            self.calls.append("listen")

        def check_syslog(self):
            self.calls.append("check")

    window = Window()
    window.admin = True
    window.netmap_tab = type("Map", (), {"watcher": Watcher()})()
    page = type("Page", (), {"receiver": 514, "stopped": False})()
    page.stop = lambda: setattr(page, "stopped", True)
    monkeypatch.setattr(syslog_service, "status", lambda: "Not installed")
    dialog = syslog_service_dialog.SyslogCollectorDialog(window, page)
    try:
        dialog.free_port()
        assert page.stopped and window.netmap_tab.watcher.calls == ["stop"]
        dialog.done_text = "Done."
        dialog.finished_action()
        assert window.netmap_tab.watcher.calls == ["stop", "listen"]
        window.netmap_tab.watcher.syslog = object()
        dialog.failed_action(RuntimeError("no"))  # Stopping or removing: the watcher checks where to listen
        assert window.netmap_tab.watcher.calls[-1] == "check"
    finally:
        dialog.deleteLater()


def test_a_full_syslog_list_drops_only_the_oldest_rows(app, monkeypatch):
    from nomad.ui import syslog_tab
    monkeypatch.setattr(syslog_tab, "MAX_MESSAGES", 5)
    page = syslog_tab.SyslogTab(Window())
    try:
        refills = []
        original = page.refill
        monkeypatch.setattr(page, "refill", lambda: (refills.append(1), original()))
        page.filter_input.setText("keep")
        for number in range(5):
            page.on_message(message(f"<14>sw1 app: {'keep' if number % 2 == 0 else 'skip'} {number}"))
        page.flush()
        assert page.table.rowCount() == 3  # keep 0, 2, 4
        page.on_message(message("<14>sw1 app: keep 5"))
        page.on_message(message("<14>sw1 app: skip 6"))
        page.flush()  # 0 and 1 fall off the end: only 0 had a row
        assert [page.table.item(row, 6).text().split()[-2:] for row in range(page.table.rowCount())] == \
            [["keep", "2"], ["keep", "4"], ["keep", "5"]]
        assert not refills  # Not filled again from scratch
        assert len(page.messages) == 5
    finally:
        page.shutdown()
