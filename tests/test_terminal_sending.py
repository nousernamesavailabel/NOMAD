"""Sending on the Terminal page: Send to All and Type in All, command buttons, the line delay, reconnecting
automatically, anti-idle and keyword highlighting."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QEvent, QPoint, Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QToolButton, QWidget  # noqa: E402

from nomad.terminal.commands import CommandButton, CommandStore  # noqa: E402
from nomad.terminal.highlight import HighlightStore  # noqa: E402
from nomad.terminal.sessions import TELNET, Session, SessionStore  # noqa: E402
from nomad.ui.terminal_tab import TerminalTab  # noqa: E402
from nomad.ui.terminal_view import CONNECTED, DISCONNECTED  # noqa: E402
from nomad.ui.scp_view import FileSessionView  # noqa: E402


class FakeTransport:
    local_echo = False

    def __init__(self, enter):
        self.enter = enter
        self.sent = b""

    def send(self, data):
        self.sent += data

    def close(self):
        pass

    def resize(self, columns, rows):  # The terminal shrinks when the Send to All bar opens
        pass


class Navigator:
    def setCurrentWidget(self, widget):
        pass


class Window(QWidget):
    focus_mode = False
    navigator = Navigator()


@pytest.fixture
def page(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = Window()
    page = TerminalTab(window, SessionStore(str(tmp_path / "sessions.json")),
                       HighlightStore(str(tmp_path / "highlights.json")), CommandStore(str(tmp_path / "commands.json")))
    window.resize(1000, 700)
    page.setParent(window)
    page.resize(1000, 700)
    window.show()
    yield page
    page.shutdown()
    window.deleteLater()
    app.processEvents()


def connect(page, name, enter="\r"):
    """A session tab that's 'connected' to a fake transport."""
    view = page.make_view(Session(name=name, protocol=TELNET, host=name))
    page.show_page(1)
    page.tabs.add_view(view)
    view.transport = FakeTransport(enter)
    view.view.enter = enter
    view.state = CONNECTED
    return view


def test_a_command_goes_to_every_connected_session_with_its_own_enter(page):
    one, two = connect(page, "one"), connect(page, "two", enter="\r\n")
    connect(page, "three").state = "Disconnected"
    assert page.send_to_all("show clock", "all") == 2
    assert one.transport.sent == b"show clock\r"
    assert two.transport.sent == b"show clock\r\n"


def test_sessions_left_out_get_nothing(page):
    one, two = connect(page, "one"), connect(page, "two")
    two.toggle_left_out()
    assert page.send_to_all("wr mem", "all") == 1
    assert two.transport.sent == b""
    assert "⊘" in page.tabs.panes[0].bar.tabText(1)


def test_on_screen_means_the_session_showing_in_each_pane(page):
    one, two, three = connect(page, "one"), connect(page, "two"), connect(page, "three")
    page.tabs.set_layout("side2")  # [one, two] and [three]
    page.tabs.show_view(one)
    assert {view.session.name for view in page.broadcast_targets("screen")} == {"one", "three"}


def test_type_in_all_mirrors_typing_only_while_on(page):
    one, two = connect(page, "one"), connect(page, "two", enter="\r\n")
    one.type_text("x")
    assert two.transport.sent == b""
    page.set_broadcast(mirror=True)
    one.type_text("y")
    one.type_text("\r")
    assert one.transport.sent == b"xy\r"
    assert two.transport.sent == b"y\r\n"  # Enter translated to the other session's own


def test_closing_the_bar_stops_type_in_all(page):
    connect(page, "one")
    page.tabs.show_send_bar(True)
    page.set_broadcast(mirror=True)
    assert page.tabs.send_bar.mirror_box.isChecked()
    page.tabs.show_send_bar(False)
    assert not page.mirror_typing


def test_the_bar_sends_and_remembers_the_command(page):
    one = connect(page, "one")
    page.tabs.show_send_bar(True)
    bar = page.tabs.send_bar
    bar.command_input.setText("terminal length 0")
    bar.send()
    assert one.transport.sent == b"terminal length 0\r"
    assert bar.command_input.history == ["terminal length 0"]
    assert "Sent to 1 session" in bar.status_label.text()


# ----------------------------------------------------------------- Control keys in the Send to All box

def test_ctrl_c_in_the_command_box_interrupts_every_session(page):
    one, two = connect(page, "one"), connect(page, "two")
    page.tabs.show_send_bar(True)
    QTest.keyClick(page.tabs.send_bar.command_input, Qt.Key_C, Qt.ControlModifier)
    assert one.transport.sent == two.transport.sent == b"\x03"
    assert "Sent Ctrl+C to 2 sessions" in page.tabs.send_bar.status_label.text()


def test_ctrl_c_still_copies_selected_text_in_the_box(page):
    one = connect(page, "one")
    page.tabs.show_send_bar(True)
    box = page.tabs.send_bar.command_input
    box.setText("show run")
    box.selectAll()
    QTest.keyClick(box, Qt.Key_C, Qt.ControlModifier)
    assert one.transport.sent == b""
    assert QApplication.clipboard().text() == "show run"


def test_ctrl_z_goes_to_the_sessions_only_when_the_box_is_empty(page):
    one = connect(page, "one")
    page.tabs.show_send_bar(True)
    box = page.tabs.send_bar.command_input
    box.setText("conf t")
    QTest.keyClick(box, Qt.Key_Z, Qt.ControlModifier)  # Undo, in the box
    assert one.transport.sent == b""
    box.clear()
    QTest.keyClick(box, Qt.Key_Z, Qt.ControlModifier)
    assert one.transport.sent == b"\x1a"


# ----------------------------------------------------------------- Command buttons

def test_a_command_button_sends_to_the_current_session(page):
    one, two = connect(page, "one"), connect(page, "two")
    button = CommandButton("Brief", "terminal length 0\nshow ip int brief")
    page.commands.put(button)
    page.tabs.show_command_bar(True)
    page.tabs.show_view(one)
    page.tabs.command_bar.send(button.id)
    assert one.transport.sent == b"terminal length 0\rshow ip int brief\r"
    assert two.transport.sent == b""


def test_a_command_button_goes_to_all_while_typing_in_all(page):
    one, two = connect(page, "one"), connect(page, "two")
    button = CommandButton("Ping", "ping ", press_enter=False)
    page.commands.put(button)
    page.set_broadcast(mirror=True)
    page.tabs.command_bar.send(button.id)
    assert one.transport.sent == two.transport.sent == b"ping "


def test_ctrl_number_presses_that_button_even_with_the_bar_hidden(page):
    one, two = connect(page, "one"), connect(page, "two")
    page.commands.put(CommandButton("Clock", "show clock"))
    page.commands.put(CommandButton("Brief", "show ip int brief"))
    assert not page.tabs.command_bar.isVisible()
    QTest.keyClick(two.view, Qt.Key_2, Qt.ControlModifier)  # In the session the key was pressed in
    assert two.transport.sent == b"show ip int brief\r" and one.transport.sent == b""
    page.tabs.show_command_bar(True)
    QTest.keyClick(two.view, Qt.Key_1, Qt.ControlModifier)
    assert two.transport.sent.endswith(b"show clock\r")


def test_ctrl_number_goes_to_the_device_without_a_button(page):
    one = connect(page, "one")
    page.commands.put(CommandButton("Clock", "show clock"))
    QTest.keyClick(one.view, Qt.Key_6, Qt.ControlModifier)  # No sixth button: Ctrl+^ as before
    assert one.transport.sent == b"\x1e"


def test_holding_ctrl_shows_numbers_without_moving_buttons_or_sending(page, tmp_path):
    one = connect(page, "one")
    for name in ("Clock", "Brief", "Run"):
        page.commands.put(CommandButton(name, f"show {name.lower()}"))
    page.tabs.show_command_bar(True)
    bar = page.tabs.command_bar
    page.window.activateWindow()
    one.view.setFocus()
    QTest.keyRelease(one.view, Qt.Key_Control)
    QApplication.processEvents()
    before = [button.geometry() for button in bar.row.buttons()]
    height = one.view.height()
    assert all(not button.shortcut_hint.isVisible() for button in bar.row.buttons())
    QTest.keyPress(one.view, Qt.Key_Control)
    QApplication.processEvents()
    assert [button.shortcut_hint.text() for button in bar.row.buttons()] == ["1", "2", "3"]
    assert all(button.shortcut_hint.isVisible() for button in bar.row.buttons())
    assert all(button.shortcut_hint.width() > 0 and button.shortcut_hint.height() > 0
               for button in bar.row.buttons())
    top = bar.mapTo(page.tabs, QPoint(0, 0)).y()
    for button in bar.row.buttons():
        assert button.sizeHint() == QToolButton.sizeHint(button)
        assert button.shortcut_hint.parentWidget() is page.tabs
        assert button.shortcut_hint.geometry().bottom() < top
        assert button.shortcut_hint.testAttribute(Qt.WA_TransparentForMouseEvents)
    assert [button.geometry() for button in bar.row.buttons()] == before
    assert one.view.height() == height
    assert one.transport.sent == b""
    screenshot = page.tabs.grab()
    screenshot.copy(0, max(0, top - 70), screenshot.width(), bar.height() + 70).save(
        str(tmp_path / "command-hints.png"))
    QTest.keyRelease(one.view, Qt.Key_Control)
    assert all(not button.shortcut_hint.isVisible() for button in bar.row.buttons())


def test_holding_ctrl_shows_log_and_config_keys_over_their_buttons(page, tmp_path):
    one = connect(page, "one")
    page.window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    assert not page.tabs.command_bar.isVisible()  # The session's own hints don't need the Buttons bar
    hints = {button.text(): hint for button, hint in one.key_hints}
    assert not any(hint.isVisible() for hint in hints.values())
    QTest.keyPress(one.view, Qt.Key_Control)
    QApplication.processEvents()
    assert {text: hint.text() for text, hint in hints.items()} == {"Log Session…": "S", "Save Config…": "Shift+S"}
    for button, hint in one.key_hints:
        assert hint.isVisible() and hint.testAttribute(Qt.WA_TransparentForMouseEvents)
        assert abs(hint.geometry().center().x() - button.mapTo(one, button.rect().center()).x()) <= 1
        assert hint.geometry().bottom() < button.mapTo(one, QPoint(0, 0)).y()  # Over it, not on it
    one.grab().save(str(tmp_path / "session-hints.png"))
    QTest.keyRelease(one.view, Qt.Key_Control)
    assert not any(hint.isVisible() for hint in hints.values())
    assert one.transport.sent == b""


def test_ctrl_hints_only_label_existing_hotkeys_and_follow_reordering(page):
    one = connect(page, "one")
    for number in range(10):
        page.commands.put(CommandButton(f"Command {number + 1}", "show clock"))
    page.tabs.show_command_bar(True)
    QTest.keyPress(one.view, Qt.Key_Control)
    bar = page.tabs.command_bar
    assert [button.shortcut_hint.text() for button in bar.row.buttons()] == [*map(str, range(1, 10)), ""]
    assert not bar.row.buttons()[-1].shortcut_hint.isVisible()
    last = page.commands.buttons[-1]
    page.commands.move_to(last.id, 0)
    QApplication.processEvents()
    first = bar.row.buttons()[0]
    assert first.button_id == last.id
    assert first.shortcut_hint.text() == "1" and first.shortcut_hint.isVisible()
    QTest.keyClick(one.view, Qt.Key_1, Qt.ControlModifier)
    assert one.transport.sent == b"show clock\r"
    QTest.keyRelease(one.view, Qt.Key_Control)
    assert all(not button.shortcut_hint.isVisible() for button in bar.row.buttons())


def test_ctrl_hints_clear_when_hidden_or_window_deactivates(page):
    one = connect(page, "one")
    page.commands.put(CommandButton("Clock", "show clock"))
    bar = page.tabs.command_bar
    QTest.keyPress(one.view, Qt.Key_Control)
    assert not bar.hints_shown
    QTest.keyRelease(one.view, Qt.Key_Control)
    page.tabs.show_command_bar(True)
    QTest.keyPress(one.view, Qt.Key_Control)
    assert bar.hints_shown
    QApplication.sendEvent(page.window, QEvent(QEvent.WindowDeactivate))
    assert not bar.hints_shown
    QTest.keyPress(one.view, Qt.Key_Control)
    page.tabs.show_command_bar(False)
    assert not bar.hints_shown
    QTest.keyRelease(one.view, Qt.Key_Control)


def test_ctrl_hints_work_in_popped_out_terminal(page):
    one = connect(page, "one")
    page.commands.put(CommandButton("Clock", "show clock"))
    page.tabs.show_command_bar(True)
    page.pop_out(one)
    window = page.windows[-1]
    window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    QTest.keyPress(one.view, Qt.Key_Control)
    assert window.tabs.command_bar.row.buttons()[0].shortcut_hint.isVisible()
    assert not page.tabs.command_bar.hints_shown
    QTest.keyRelease(one.view, Qt.Key_Control)
    assert not window.tabs.command_bar.hints_shown
    one.state = DISCONNECTED
    window.close()


def test_ctrl_overlay_tracks_scrolling_and_hides_offscreen_numbers(page):
    one = connect(page, "one")
    for number in range(9):
        page.commands.put(CommandButton(f"Command {number + 1}", "show clock"))
    page.tabs.show_command_bar(True)
    bar = page.tabs.command_bar
    for button in bar.row.buttons():
        button.setFixedWidth(150)
    QApplication.processEvents()
    bar.fit_height()
    scrollbar = bar.scroll.horizontalScrollBar()
    assert scrollbar.maximum() > 0
    QTest.keyPress(one.view, Qt.Key_Control)
    assert bar.row.buttons()[0].shortcut_hint.isVisible()
    assert not bar.row.buttons()[-1].shortcut_hint.isVisible()
    scrollbar.setValue(scrollbar.maximum())
    assert not bar.row.buttons()[0].shortcut_hint.isVisible()
    last = bar.row.buttons()[-1]
    assert last.shortcut_hint.isVisible()
    assert abs(last.shortcut_hint.geometry().center().x() - last.mapTo(page.tabs, last.rect().center()).x()) <= 1
    QTest.keyRelease(one.view, Qt.Key_Control)


def test_alt_arrows_switch_sessions_without_sending_to_remote(page):
    one, two = connect(page, "one"), connect(page, "two")
    page.window.activateWindow()
    two.view.setFocus()
    QApplication.processEvents()
    QTest.keyClick(two.view, Qt.Key_Left, Qt.AltModifier)
    assert page.tabs.currentWidget() is one
    QTest.keyClick(one.view, Qt.Key_Right, Qt.AltModifier)
    assert page.tabs.currentWidget() is two
    QTest.keyClick(two.view, Qt.Key_Right, Qt.AltModifier)
    assert page.tabs.currentWidget() is one
    assert one.transport.sent == two.transport.sent == b""


def test_ctrl_w_confirms_connected_session_and_can_cancel(page, monkeypatch):
    one = connect(page, "one")
    page.window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    sent = []
    one.view.key_input.connect(sent.append)
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.No)
    QTest.keyClick(one.view, Qt.Key_W, Qt.ControlModifier)
    assert page.tabs.currentWidget() is one
    assert sent == []
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    QTest.keyClick(one.view, Qt.Key_W, Qt.ControlModifier)
    assert page.tabs.count() == 0


def test_ctrl_w_confirmation_defaults_to_yes(page, monkeypatch):
    one = connect(page, "one")
    page.window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    defaults = []
    def confirm(*args):
        defaults.append(args[-1])
        return args[-1]
    monkeypatch.setattr(QMessageBox, "question", confirm)
    QTest.keyClick(one.view, Qt.Key_W, Qt.ControlModifier)
    assert defaults == [QMessageBox.Yes]
    assert page.tabs.count() == 0


def test_scp_close_warning_defaults_to_yes(page, monkeypatch):
    warning_view = QWidget(page)
    warning_view.session = Session("files", host="localhost")
    warning_view.problems = lambda: ["a running transfer"]
    defaults = []
    def confirm(*args):
        defaults.append(args[-1])
        return args[-1]
    monkeypatch.setattr(QMessageBox, "question", confirm)
    assert FileSessionView.confirm_close(warning_view)
    assert defaults == [QMessageBox.Yes]


def test_ctrl_shift_enter_moves_session_out_and_back(page):
    one = connect(page, "one")
    page.window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    QTest.keyClick(one.view, Qt.Key_Return, Qt.ControlModifier | Qt.ShiftModifier)
    window = page.windows[-1]
    assert window.tabs.currentWidget() is one
    assert page.tabs.count() == 0
    window.activateWindow()
    one.view.setFocus()
    QApplication.processEvents()
    QTest.keyClick(one.view, Qt.Key_Enter, Qt.ControlModifier | Qt.ShiftModifier)
    assert page.tabs.currentWidget() is one
    assert window.tabs.count() == 0


def test_reordering_buttons_moves_their_hotkeys_too(page):
    one = connect(page, "one")
    for name in ("Clock", "Brief", "Run"):
        page.commands.put(CommandButton(name, f"show {name.lower()}"))
    run = page.commands.buttons[2]
    page.commands.move_to(run.id, 0)
    assert [button.name for button in page.commands.buttons] == ["Run", "Clock", "Brief"]
    QTest.keyClick(one.view, Qt.Key_1, Qt.ControlModifier)
    assert one.transport.sent == b"show run\r"
    page.commands.move_to(run.id, 99)  # Past the end: last
    assert [button.name for button in page.commands.buttons] == ["Clock", "Brief", "Run"]


def test_dropping_a_button_puts_it_where_it_lands(page):
    for name in ("Clock", "Brief", "Run"):
        page.commands.put(CommandButton(name, f"show {name.lower()}"))
    connect(page, "one")  # So the sessions, and the bar under them, are showing
    page.tabs.show_command_bar(True)
    QApplication.processEvents()
    row = page.tabs.command_bar.row
    clock, brief, run = sorted(row.buttons(), key=lambda widget: widget.x())
    assert row.drop_position(0, run.button_id)[0] == 0  # Before Clock
    assert row.drop_position(brief.geometry().center().x() + 1, clock.button_id)[0] == 1  # After Brief
    assert row.drop_position(row.width(), clock.button_id)[0] == 2  # At the end

    from PyQt5.QtCore import QMimeData, QPoint
    from PyQt5.QtGui import QDropEvent
    from nomad.ui.command_bar import BUTTON_MIME
    mime = QMimeData()
    mime.setData(BUTTON_MIME, run.button_id.encode())
    row.dropEvent(QDropEvent(QPoint(1, 5), Qt.MoveAction, mime, Qt.LeftButton, Qt.NoModifier))
    QApplication.processEvents()
    assert [button.name for button in page.commands.buttons] == ["Run", "Clock", "Brief"]
    assert [widget.text() for widget in row.buttons()] == ["Run", "Clock", "Brief"]  # The bar shows it


def test_the_bar_shows_a_new_button(page):
    page.commands.put(CommandButton("Clock", "show clock"))
    layout = page.tabs.command_bar.row_layout
    names = [layout.itemAt(index).widget().text() for index in range(layout.count())
             if layout.itemAt(index).widget() is not None]
    assert names == ["Clock"]


# ----------------------------------------------------------------- Line delay

def test_with_a_line_delay_lines_go_one_at_a_time(page):
    one = connect(page, "one")
    one.session.line_delay = 30
    one.send_block("a\nb\nc", final_enter=False)
    assert one.transport.sent == b"a\r"
    assert "Sending line 2 of 3" in one.status_label.text()
    for _ in range(50):
        if one.transport.sent == b"a\rb\rc":
            break
        QTest.qWait(20)
    assert one.transport.sent == b"a\rb\rc"
    assert "Sending" not in one.status_label.text()


def test_a_block_can_ask_for_a_delay_the_session_does_not_have(page):
    one = connect(page, "one")
    assert one.session.line_delay == 0
    one.send_block("configure terminal\ncdp run\nend", min_delay=40)
    assert one.transport.sent == b"configure terminal\r"
    QTest.qWait(400)
    assert one.transport.sent == b"configure terminal\rcdp run\rend\r"
    one.send_block("a\nb")  # Later blocks go at the session's own pace again
    assert one.transport.sent.endswith(b"a\rb\r")


def test_stop_sending_drops_the_rest(page):
    one = connect(page, "one")
    one.session.line_delay = 1000
    one.send_block("a\nb\nc")
    one.stop_sending()
    QTest.qWait(50)
    assert one.transport.sent == b"a\r"


def test_a_paste_uses_the_line_delay(page):
    one = connect(page, "one")
    one.session.line_delay = 10
    QApplication.clipboard().setText("interface Gi1/0/1\n shutdown")
    one.paste()
    QTest.qWait(200)
    assert one.transport.sent == b"interface Gi1/0/1\r shutdown"  # No Enter after the last line, as pasted


# ----------------------------------------------------------------- Reconnecting automatically

def test_a_drop_starts_reconnecting_when_it_is_on(page):
    one = connect(page, "one")
    one.auto_reconnect = True
    one.on_closed("Connection closed by the device.")
    assert one.reconnect_timer.isActive() and one.reconnect_attempts == 1
    one.stop_reconnecting()
    assert not one.reconnect_timer.isActive()


def test_no_reconnecting_after_typing_exit(page):
    one = connect(page, "one")
    one.auto_reconnect = True
    one.type_text("exit\r")
    one.on_closed("Connection closed.")
    assert not one.reconnect_timer.isActive()


def test_no_reconnecting_when_it_is_off(page):
    one = connect(page, "one")
    one.on_closed("Connection closed.")
    assert not one.reconnect_timer.isActive()


def test_failing_while_reconnecting_tries_again_until_disconnected(page):
    one = connect(page, "one")
    one.auto_reconnect = True
    one.on_closed("Connection closed.")
    one.reconnect_timer.stop()
    one.on_failed("Connection refused.")  # The device is still starting
    assert one.reconnect_timer.isActive() and one.reconnect_attempts == 2
    one.disconnect_session()  # On purpose: stop
    assert not one.reconnect_timer.isActive() and one.state == DISCONNECTED


# ----------------------------------------------------------------- Anti-idle

def test_anti_idle_sends_after_the_idle_time(page):
    one = connect(page, "one")
    one.session.anti_idle = 1
    one.set_state(CONNECTED, "Connected.")
    QTest.qWait(1300)
    assert one.transport.sent == b" \b"


def test_typing_puts_anti_idle_off(page):
    one = connect(page, "one")
    one.session.anti_idle = 1
    one.set_state(CONNECTED, "Connected.")
    QTest.qWait(600)
    one.type_text("x")
    QTest.qWait(600)
    assert one.transport.sent == b"x"


# ----------------------------------------------------------------- Keyword highlighting

def test_keywords_are_colored_in_the_terminal(page):
    one = connect(page, "one")
    one.model.feed(b"Gi2 is administratively down, Gi3 down\r\n")  # Fits the narrow test terminal
    index = one.model.history_length
    colors = one.view.keyword_colors(one.model.line(index), one.model.columns)
    text = one.model.line_text(index)
    assert colors[text.index("administratively")] == "Amber"
    assert colors[text.rindex("down")] == "Red"
    assert colors[0] is None


def test_the_devices_own_colors_are_left_alone(page):
    one = connect(page, "one")
    one.model.feed(b"\x1b[32mdown\x1b[0m\r\n")
    assert one.view.keyword_colors(one.model.line(one.model.history_length), one.model.columns) is None


def test_switching_highlighting_off(page):
    one = connect(page, "one")
    page.highlights.set_enabled(False)
    assert one.view.highlighter is None
    page.highlights.set_enabled(True)
    assert one.view.highlighter is not None
