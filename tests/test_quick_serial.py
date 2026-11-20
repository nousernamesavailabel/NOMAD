"""Quick connect with Serial picked offers the computer's COM ports and a speed instead of a text box."""
import pytest
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QWidget

from nomad.terminal.sessions import SERIAL, SSH, SessionStore
from nomad.ui import session_dialog
from nomad.ui.session_manager import SessionManager

PORTS = [("COM3", "USB Serial Port (COM3)"), ("COM12", "COM12")]


class Page(QWidget):
    def __init__(self):
        super().__init__()
        self.opened = []

    def open_session(self, session, saved=False, into=None):
        self.opened.append(session)


@pytest.fixture
def manager(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    ports = list(PORTS)
    monkeypatch.setattr(session_dialog, "serial_ports", lambda: ports)
    page = Page()
    manager = SessionManager(page, SessionStore(str(tmp_path / "sessions.json")))
    manager.ports = ports
    yield manager
    page.close()
    page.deleteLater()
    app.processEvents()


def test_serial_shows_the_port_list(manager):
    assert not manager.quick_serial.isVisibleTo(manager) and manager.quick_input.isVisibleTo(manager)
    manager.quick_protocol.setCurrentText(SERIAL)
    assert manager.quick_serial.isVisibleTo(manager) and manager.quick_baud.isVisibleTo(manager)
    assert not manager.quick_input.isVisibleTo(manager)
    combo = manager.quick_serial
    assert [combo.itemText(row) for row in range(combo.count())] == ["COM3  (USB Serial Port (COM3))", "COM12"]
    assert combo.port() == "COM3"  # The first one is picked

    combo.setCurrentIndex(1)
    manager.quick_baud.setCurrentText("115200")
    manager.quick_connect()
    session = manager.page.opened[-1]
    assert (session.protocol, session.serial_port, session.baud_rate) == (SERIAL, "COM12", 115200)

    manager.quick_protocol.setCurrentText(SSH)
    assert manager.quick_input.isVisibleTo(manager) and not manager.quick_serial.isVisibleTo(manager)


def test_typed_ports_and_mistakes(manager):
    manager.quick_protocol.setCurrentText(SERIAL)
    combo = manager.quick_serial
    combo.setEditText("com7:19200")  # Typed with its own speed
    manager.quick_connect()
    session = manager.page.opened[-1]
    assert (session.serial_port, session.baud_rate) == ("COM7", 19200)

    combo.setEditText("COM9")  # Not plugged in, so not listed; the speed box gives the speed
    manager.quick_connect()
    assert (manager.page.opened[-1].serial_port, manager.page.opened[-1].baud_rate) == ("COM9", 9600)

    count = len(manager.page.opened)
    combo.setEditText("")
    manager.quick_connect()
    assert "Pick a COM port" in manager.quick_status.text() and len(manager.page.opened) == count
    combo.setCurrentIndex(0)
    manager.quick_baud.setCurrentText("fast")
    manager.quick_connect()
    assert "isn't a speed" in manager.quick_status.text() and len(manager.page.opened) == count


def test_plugging_in_a_cable_shows_up_and_the_last_port_is_kept(manager, tmp_path):
    manager.quick_protocol.setCurrentText(SERIAL)
    manager.ports.append(("COM4", "Prolific USB-to-Serial"))
    manager.quick_serial.fill()
    assert manager.quick_serial.findData("COM4") >= 0

    manager.quick_serial.setCurrentIndex(manager.quick_serial.findData("COM4"))
    manager.quick_baud.setCurrentText("38400")
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat)
    manager.save_settings(settings)
    manager.quick_protocol.setCurrentText(SSH)
    manager.quick_serial.setCurrentIndex(0)
    manager.quick_baud.setCurrentText("9600")
    manager.restore_settings(settings)
    assert manager.quick_protocol.currentText() == SERIAL
    assert manager.quick_serial.port() == "COM4" and manager.quick_baud.currentText() == "38400"
