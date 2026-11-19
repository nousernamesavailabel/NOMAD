"""Freeze reports in the log, and NOMAD closing without waiting on threads that are still busy."""
import logging
import os
import threading
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QThread, Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QLineEdit, QPushButton  # noqa: E402
from test_netmap_tab import Window, crawled  # noqa: E402,F401

from nomad.netmap import store  # noqa: E402
from nomad.ui import common, hang_watchdog, netmap_tab  # noqa: E402
from nomad.ui.hang_watchdog import HangWatchdog, window_context  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def watchdog(app):
    made = []

    def make(context=None, threshold=0.3):
        dog = HangWatchdog(context or (lambda: ["Map: a test map, 3 devices"]), threshold=threshold, beat_ms=50)
        dog.start()
        made.append(dog)
        return dog
    yield make
    for dog in made:
        dog.stop()


def run_events(app, seconds):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)


def a_slow_step(seconds):
    time.sleep(seconds)  # Stands in for work that holds up the UI thread


def freeze_messages(caplog):
    return [record.getMessage() for record in caplog.records
            if record.name == hang_watchdog.__name__ and record.levelno == logging.WARNING]


def test_a_freeze_is_reported_with_the_stacks_and_what_nomad_was_doing(app, watchdog, caplog):
    caplog.set_level(logging.DEBUG)
    watchdog()
    run_events(app, 0.3)
    a_slow_step(1.0)
    run_events(app, 0.4)
    messages = freeze_messages(caplog)
    assert len(messages) == 2, messages
    start, end = messages
    assert start.startswith("UI freeze #1: the window hasn't answered for")
    assert "Map: a test map, 3 devices" in start  # What NOMAD was doing
    assert "UI thread:" in start and "a_slow_step" in start and "time.sleep(seconds)" in start  # Its whole stack
    assert "Other threads (" in start
    assert end.startswith("UI freeze #1 over: the window didn't answer for")
    assert "a_slow_step" in end  # Where the time went
    length = float(end.split("for ")[1].split(" s")[0])
    assert 0.8 <= length <= 1.6


def test_a_busy_but_answering_window_isnt_reported(app, watchdog, caplog):
    caplog.set_level(logging.DEBUG)
    watchdog()
    for _ in range(10):
        a_slow_step(0.1)  # Short stretches of work, the window answering in between
        app.processEvents()
    run_events(app, 0.3)
    assert freeze_messages(caplog) == []


def test_the_report_says_what_was_clicked_but_never_what_was_typed(app, watchdog, caplog):
    caplog.set_level(logging.DEBUG)
    dog = watchdog()
    button = QPushButton("Rearrange")
    line = QLineEdit()
    button.show()
    line.show()
    try:
        QTest.keyClicks(line, "hunter2")
        QTest.mouseClick(button, Qt.LeftButton)
        run_events(app, 0.2)
        a_slow_step(0.7)
        run_events(app, 0.3)
    finally:
        button.close()
        line.close()
    report = "\n".join(freeze_messages(caplog))
    assert "Last input: click 'Rearrange' on QPushButton" in report
    assert "hunter2" not in report and "hunter2" not in dog.last_input


def hold_pythons_lock(milliseconds):
    """Block in Windows' Sleep without letting go of Python's lock, as a C call that doesn't release it would: no
    other thread runs meanwhile, the watcher included."""
    import ctypes
    ctypes.PyDLL("kernel32").Sleep(milliseconds)


@pytest.mark.skipif(os.name != "nt", reason="Windows' Sleep")
def test_a_freeze_holding_pythons_lock_is_still_reported(app, watchdog, caplog):
    caplog.set_level(logging.DEBUG)
    watchdog()
    run_events(app, 0.3)
    hold_pythons_lock(1500)
    run_events(app, 0.4)
    messages = freeze_messages(caplog)
    assert len(messages) == 2, messages
    assert "This report itself was held up" in messages[0]
    assert "over: the window didn't answer for 1." in messages[1]


@pytest.mark.skipif(os.name != "nt", reason="Windows' Sleep")
def test_the_computer_sleeping_isnt_a_freeze(app, watchdog, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(hang_watchdog, "awake_seconds", lambda: 100.0)  # The awake clock stands still: asleep
    watchdog()
    run_events(app, 0.3)
    hold_pythons_lock(1500)
    run_events(app, 0.4)
    assert freeze_messages(caplog) == []
    assert any("the computer slept" in record.getMessage() for record in caplog.records)


def test_describing_nomad_never_breaks_it(app, watchdog, caplog):
    caplog.set_level(logging.DEBUG)

    def broken():
        raise RuntimeError("no map page")
    watchdog(context=broken)
    run_events(app, 0.2)
    a_slow_step(0.7)
    run_events(app, 0.3)
    assert "Couldn't describe what NOMAD is doing" in freeze_messages(caplog)[0]


def test_window_context_describes_the_map_and_the_rest(app, tmp_path, monkeypatch, crawled):  # noqa: F811
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    try:
        page.on_crawled(crawled)
        view = SimpleNamespace(state="connected")
        window = SimpleNamespace(
            admin=True, netmap_tab=page,
            navigator=SimpleNamespace(currentWidget=lambda: page, title=lambda widget: "Network Map", popped={}),
            ipam_tab=SimpleNamespace(team=None, source="local", syncing=False, sweep_worker=None),
            terminal_tab=SimpleNamespace(all_tabs=lambda: [SimpleNamespace(views=lambda: [view])], windows=[]),
            tribe_banner=None)
        monkeypatch.setattr("nomad.ipam.client.is_tribe_server", lambda: False)
        hang_watchdog._server_here.clear()
        lines = window_context(window)
    finally:
        page.shutdown()
    text = "\n".join(lines)
    assert "? (" not in text, text  # Every part could be read
    devices = len(page.network_map.devices)
    assert f"Map: file '{os.path.basename(page.map_path)}': {devices} devices (0 by hand)" in text
    assert "Map activity: crawl running: no" in text
    assert "Tribe: this computer is the tribe server: no; no tribe key in use" in text
    assert "Page: Network Map" in text
    assert "IP Addresses: showing this computer's networks, not connected to the tribe" in text
    assert "Terminal: 1 sessions open (1 connected)" in text
    assert text.startswith("NOMAD: ") and "administrator: yes" in text
    assert "Python threads" in text


class Stuck(QThread):
    """A thread that takes a while to notice it was stopped (a wait on the server, say)."""

    def __init__(self, seconds):
        super().__init__()
        self.seconds = seconds

    def run(self):
        time.sleep(self.seconds)


def test_threads_get_only_a_moment_while_nomad_closes(app):
    thread = Stuck(1.5)
    thread.start()
    common.set_app_closing()
    try:
        started = time.monotonic()
        common.release_thread(thread, 10000)
        assert time.monotonic() - started < 1.0  # Not the 10 seconds asked for
        assert thread in common._orphaned_threads  # Left to finish on its own
    finally:
        common.set_app_closing(False)
        thread.wait(5000)


def test_threads_get_their_full_wait_otherwise(app):
    thread = Stuck(0.5)
    thread.start()
    common.release_thread(thread, 5000)
    assert thread.isFinished()


def test_closing_the_map_page_doesnt_wait_out_a_stuck_check(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    stuck = Stuck(3)
    stuck.stop = lambda: None
    stuck.start()
    page.check_threads.append(stuck)  # A device that hasn't answered SNMP yet
    common.set_app_closing()
    try:
        started = time.monotonic()
        page.shutdown()
        assert time.monotonic() - started < 2.0  # It used to wait up to the SNMP timeout x 2 + 3 s
    finally:
        common.set_app_closing(False)
        stuck.wait(5000)


def test_watcher_thread_ends_when_stopped(app):
    dog = HangWatchdog(lambda: [], threshold=0.3, beat_ms=50)
    dog.start()
    thread = dog.thread
    dog.stop()
    assert not thread.is_alive()
    assert all(item.name != "NOMAD freeze watchdog" for item in threading.enumerate())
