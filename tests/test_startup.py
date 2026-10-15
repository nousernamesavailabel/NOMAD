"""Starting NOMAD: the text size set once before the pages are built, the splash, one copy per account, and the
flags a copy passes the one it starts as administrator."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import threading
import uuid

import pytest
from PyQt5.QtCore import QObject
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication

from nomad.system import ELEVATED_FOR_FLAG, RESTARTED_FLAG, elevated_for, relaunch_arguments
from nomad.ui import theme
from nomad.ui.single_instance import InstanceServer, RunningCopy, bring_to_front, find_running_copy, needs_asking
from nomad.ui.splash import SPLASH_HEIGHT, SPLASH_WIDTH, StartupSplash, draw_build_splash


@pytest.fixture
def app():
    return QApplication.instance() or QApplication([])


def test_text_scale_is_closest_choice():
    assert theme.closest_text_scale(1.0) == 1.0
    assert theme.closest_text_scale(1.3) == 1.25
    assert theme.closest_text_scale(9) == 2.0


def test_setting_the_same_text_scale_again_restyles_nothing(app, monkeypatch):
    # Put back exactly as found: other tests measure text (a terminal's columns), at the app's font
    font, scale, base = QFont(app.font()), app.property("text_scale"), app.property("base_point_size")
    restyled = []
    monkeypatch.setattr(app, "setStyleSheet", restyled.append)
    monkeypatch.setattr(app, "styleSheet", lambda: "")
    try:
        app.setProperty("base_point_size", font.pointSizeF())
        theme.set_text_scale(app, 1.1)
        assert len(restyled) == 1
        theme.set_text_scale(app, 1.1)
        assert len(restyled) == 1
        theme.set_text_scale(app, 1.25)
        assert len(restyled) == 2
    finally:
        monkeypatch.undo()
        app.setFont(font)
        app.setProperty("text_scale", scale)
        app.setProperty("base_point_size", base)


def test_splash_picture_and_steps(app):
    image = draw_build_splash()
    assert (image.width(), image.height()) == (SPLASH_WIDTH, SPLASH_HEIGHT)
    splash = StartupSplash()
    splash.show()
    splash.step("Loading the Network Map...", 0.35)
    assert (splash.message, splash.progress) == ("Loading the Network Map...", 0.35)
    splash.step("Still loading...")  # Progress stays where it was
    assert splash.progress == 0.35
    splash.close()
    splash.deleteLater()


def test_relaunch_arguments_drop_the_last_copys_flags():
    arguments = ["map.nomadmap", RESTARTED_FLAG, ELEVATED_FOR_FLAG + "LAB\\jo"]
    assert relaunch_arguments(arguments) == ["map.nomadmap"]
    assert relaunch_arguments(arguments, [RESTARTED_FLAG]) == ["map.nomadmap", RESTARTED_FLAG]
    assert elevated_for(arguments) == "LAB\\jo"
    assert elevated_for(["map.nomadmap"]) is None


def test_when_to_ask_before_handing_over():
    assert not needs_asking(RunningCopy("1.31.0", False), "1.31.0", False)
    assert not needs_asking(RunningCopy("1.31.0", True), "1.31.0", False)  # The open one has more rights
    assert not needs_asking(RunningCopy("1.31.0", True), "1.31.0", True)
    assert needs_asking(RunningCopy("1.31.0", False), "1.31.0", True)  # This one has rights the open one hasn't
    assert needs_asking(RunningCopy("1.30.0", True), "1.31.0", True)  # Another version
    assert not needs_asking(RunningCopy(), "1.31.0", True)  # Still starting: it shows itself


def run_client(app, name, show):
    """Say hello to the server named name from another thread (as another copy would, from its process) while
    this one runs the server; returns what the client found."""
    found = {}

    def client():
        running, socket = find_running_copy(name)
        found["running"] = running
        if socket is not None:
            if show:
                bring_to_front(socket)
            else:
                socket.abort()
            socket.deleteLater()

    thread = threading.Thread(target=client)
    thread.start()
    while thread.is_alive():
        app.processEvents()
        thread.join(0.01)
    for _ in range(20):  # The show line reaches the server after the client has gone
        app.processEvents()
    return found["running"]


class Window(QObject):
    """Stands in for the main window: counts the times it's asked to come to the front."""

    def __init__(self):
        super().__init__()
        self.shown = 0

    def bring_to_front(self):
        self.shown += 1


def test_second_copy_finds_the_open_one_and_brings_it_to_front(app):
    name = f"NOMAD-test-{uuid.uuid4().hex}"
    server = InstanceServer("1.31.0", True)
    window = Window()
    server.show_requested.connect(window.bring_to_front)
    assert server.listen(name)
    try:
        running = run_client(app, name, show=False)
        assert (running.version, running.admin) == ("1.31.0", True)
        assert window.shown == 0
        running = run_client(app, name, show=True)
        assert running.answered
        assert window.shown == 1
    finally:
        server.close()
        server.deleteLater()


def test_no_open_copy(app):
    running, socket = find_running_copy(f"NOMAD-test-{uuid.uuid4().hex}")
    assert running is None and socket is None
