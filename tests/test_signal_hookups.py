"""Worker and thread signals go to methods, never lambdas or partials: a lambda's signal still waiting to be delivered
when its sender is freed (a page or session view closed, say) crashes Qt, where a method's is dropped with its
object."""
import os
import re
import threading
import time
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5 import sip  # noqa: E402
from PyQt5.QtCore import QThread  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from nomad.ui import common  # noqa: E402

UI = Path(__file__).resolve().parent.parent / "nomad" / "ui"
KEPT_QT_MADE = re.compile(r"\bself\.\w+ = [\w.]+\.(addAction|addMenu)\(")
HOOKUP = re.compile(r"\b(\w*(?:worker|thread|signals|runner))\.(\w+)\.connect\(\s*(lambda|(?:functools\.)?partial)\b")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def test_no_worker_signal_goes_to_a_lambda():
    found = []
    for path in sorted(UI.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in HOOKUP.finditer(source):
            line = source.count("\n", 0, match.start()) + 1
            found.append(f"{path.name}:{line} {match.group(1)}.{match.group(2)} -> {match.group(3)}")
    assert found == []


def test_the_check_finds_one():
    assert HOOKUP.search("self.worker.progress.connect(\n    lambda done, total: None)")
    assert HOOKUP.search("thread.finished.connect(partial(self.done, thread))")
    assert not HOOKUP.search("self.worker.progress.connect(self.show_progress)")


def test_pages_keep_only_the_menu_entries_python_made(app):
    """sip isn't told when Qt frees an entry it made (menu.addAction(text, slot), menu.addMenu(text)): a page keeping
    one could later be handed its stale wrapper. Pages keep entries made with common.add_action or add_submenu."""
    found = []
    for path in sorted(UI.glob("*.py")):
        source = path.read_text(encoding="utf-8")
        for match in KEPT_QT_MADE.finditer(source):
            found.append(f"{path.name}:{source.count(chr(10), 0, match.start()) + 1} {match.group(0)}")
    assert found == []
    assert KEPT_QT_MADE.search("self.sync_action = team_menu.addAction(\"Sync Now\", self.sync_now)")
    assert not KEPT_QT_MADE.search("action = team_menu.addAction(\"Sync Now\", self.sync_now)")
    from PyQt5.QtWidgets import QMenu
    menu, hits = QMenu(), []
    action = common.add_action(menu, "Sync Now", lambda: hits.append(1))
    submenu = common.add_submenu(menu, "More")
    assert menu.actions() == [action, submenu.menuAction()]
    assert sip.ispycreated(action) and sip.ispycreated(submenu)
    action.trigger()
    assert hits == [1]


def wait_for(app, condition, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        app.processEvents()
        if condition():
            return True
        time.sleep(0.01)
    return False


class Stuck(QThread):
    """A thread that won't stop until let go of."""

    def __init__(self):
        super().__init__()
        self.go = threading.Event()

    def run(self):
        self.go.wait(5)


def test_a_released_thread_still_running_is_freed_by_qt_once_it_finishes(app):
    thread = Stuck()
    thread.start()
    common.release_thread(thread, wait_ms=10)  # Still running: let go of
    assert thread in common._orphaned_threads and not sip.isdeleted(thread)
    thread.go.set()
    assert wait_for(app, lambda: sip.isdeleted(thread))
    common.forget_deleted(common._orphaned_threads)
    assert thread not in common._orphaned_threads


def test_background_task_answers_and_its_signals_are_freed(app):
    answers = []
    common.run_in_background(lambda: 6 * 7, answers.append)
    common.run_in_background(lambda: 1 / 0, None, lambda error: answers.append(type(error).__name__))
    assert wait_for(app, lambda: len(answers) == 2)
    assert sorted(answers, key=str) == [42, "ZeroDivisionError"]
    assert wait_for(app, lambda: all(sip.isdeleted(item) for item in common._running_signals))
    common.run_in_background(lambda: None)  # Starting another drops the ones freed
    assert all(not sip.isdeleted(item) for item in common._running_signals)
