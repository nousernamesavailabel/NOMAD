"""The Editor page: files (open, edit, save keeping the line endings), Compare (copy arrows, Fix Commands), the local
config archive (changes, review, standards), the Terminal's saved configs, sending lines, closing with changes."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QThreadPool, Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QWidget  # noqa: E402

from nomad.configs import archive, diff  # noqa: E402
from nomad.netmap import configpush, model  # noqa: E402
from nomad.terminal.sessions import SSH, Session, SessionStore  # noqa: E402
from nomad.ui import compare_view, config_review, editor_tab  # noqa: E402
from nomad.ui.compare_view import CompareView  # noqa: E402
from nomad.ui.config_events import config_events  # noqa: E402
from nomad.ui.editor_tab import Document, EditorTab, config_lines  # noqa: E402

CONFIG = "hostname R1\n!\ninterface Gi0/1\n description A\n!\nntp server 10.0.0.1\n"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Navigator:
    def __init__(self):
        self.current = None

    def setCurrentWidget(self, widget):
        self.current = widget

    def currentWidget(self):
        return self.current


class MapPage(QWidget):
    def __init__(self):
        super().__init__()
        self.network_map = model.NetworkMap()
        self.network_map.devices["r"] = model.Device("r", name="R1", mgmt_ip="10.0.0.1", kind=model.ROUTER)
        self.notes = None

    def show_config_flags(self, notes):
        self.notes = notes


class Window(QWidget):
    def __init__(self, tmp_path):
        super().__init__()
        self.session_store = SessionStore(str(tmp_path / "sessions.json"))
        self.navigator = Navigator()
        self.netmap_tab = MapPage()
        self.statuses = []

    def tribe_key(self):
        return None

    def show_status(self, message, kind="success", timeout=10000):
        self.statuses.append(message)


def settle(app):
    for _ in range(5):
        QThreadPool.globalInstance().waitForDone(5000)
        app.processEvents()


@pytest.fixture
def page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(editor_tab, "app_data_dir", lambda: str(tmp_path))
    window = Window(tmp_path)
    tab = EditorTab(window)
    yield tab
    tab.shutdown()
    tab.deleteLater()


def test_open_edit_save_keeps_line_endings(page, tmp_path, app):
    path = tmp_path / "r1.cfg"
    path.write_bytes(b"hostname R1\r\ninterface Gi0/1\r\n")
    doc = page.open_file(str(path))
    assert isinstance(doc, Document) and doc.ending == "\r\n"
    assert page.open_file(str(path)) is doc  # Already open: shown again
    doc.editor.setText("hostname R2\ninterface Gi0/1\n")
    assert doc.is_modified() and page.docs.tabText(0).endswith("•")
    page.save_current()
    assert path.read_bytes() == b"hostname R2\r\ninterface Gi0/1\r\n"
    assert not doc.is_modified()


def test_binary_file_refused(page, tmp_path, monkeypatch):
    path = tmp_path / "image.bin"
    path.write_bytes(b"\x00\x01\x02")
    warned = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: warned.append(args[2]))
    assert page.open_file(str(path)) is None
    assert "isn't a text file" in warned[0]


def test_compare_copy_arrow_and_close_prompt(page, app, monkeypatch):
    view = page.open_compare("a\nb\nc", "a\nX\nc", "Left", "Right", mode=diff.PLAIN)
    assert isinstance(view, CompareView) and len(view.result.changes) == 1
    view.take(view.result.changes[0], to_right=True)
    assert view.right.editor.text() == "a\nb\nc" and view.result.same
    assert view.is_modified()
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Cancel)
    page.close_tab(page.docs.indexOf(view))
    assert page.docs.indexOf(view) >= 0  # Cancel keeps it open
    assert not page.confirm_close()
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Discard)
    assert page.confirm_close()
    page.close_tab(page.docs.indexOf(view))
    assert page.docs.count() == 0


def test_compare_prev_next_keep_sides_lined_up(app):
    from PyQt5.Qsci import QsciScintilla
    left, right = [], []
    for number in range(300):
        left.append(f"line {number}")
        right.append(f"line {number}")
        if number % 37 == 5:
            right.extend(f"added {number}.{extra}" for extra in range(12))
        if number % 53 == 9:
            left.extend(f"removed {number}.{extra}" for extra in range(9))
    view = CompareView(None, "\n".join(left), "\n".join(right), "Left", "Right", mode=diff.PLAIN)
    view.resize(900, 400)
    view.show()
    app.processEvents()

    def first_lines():
        return [pane.editor.SendScintilla(QsciScintilla.SCI_GETFIRSTVISIBLELINE) for pane in view.panes()]

    try:
        tops = set()
        for step in range(len(view.result.changes) * 2):
            view.next_change() if step < len(view.result.changes) else view.previous_change()
            app.processEvents()
            top_left, top_right = first_lines()
            assert top_left == top_right, f"change {view.current + 1}: left at {top_left}, right at {top_right}"
            tops.add(top_left)
        assert len(tops) > 1  # It really moved
        view.go_to_fraction(0.8)
        app.processEvents()
        top_left, top_right = first_lines()
        assert top_left == top_right and top_left > 0
    finally:
        view.deleteLater()


def test_prev_next_show_a_change_a_third_down_and_the_strip_follows_the_scroll_bar(app):
    from PyQt5.Qsci import QsciScintilla
    left = [f"line {number}" for number in range(600)]
    right = [line if number % 90 != 45 else f"changed {number}" for number, line in enumerate(left)]
    view = CompareView(None, "\n".join(left), "\n".join(right), "Left", "Right", mode=diff.PLAIN)
    view.resize(900, 500)
    view.show()
    app.processEvents()
    editor = view.right.editor
    try:
        for _ in range(3):
            view.next_change()
            app.processEvents()
            hunk = view.result.changes[view.current]
            top = editor.SendScintilla(QsciScintilla.SCI_GETFIRSTVISIBLELINE)
            screen = editor.SendScintilla(QsciScintilla.SCI_LINESONSCREEN)
            row = editor.SendScintilla(QsciScintilla.SCI_VISIBLEFROMDOCLINE, hunk.b_start)
            assert top + screen // 4 <= row <= top + screen // 2, (top, screen, row)
        bar = editor.verticalScrollBar()
        groove_top = view.strip.mapFromGlobal(bar.mapToGlobal(compare_view.QPoint(0, compare_view.groove_of(bar).top())))
        track_top, track_height = view.strip.track()
        assert track_top == groove_top.y() > 0 and track_height < view.strip.height()
        shown = view.strip.on_screen()
        total = len(view.result.rows)
        assert shown[0] <= row / total <= shown[1]  # The current change is in the on-screen box
    finally:
        view.deleteLater()


def test_fix_commands_from_compare(page, app):
    view = page.open_compare("hostname R1\ninterface Gi0/1\n description A\n",
                             "hostname R1\ninterface Gi0/1\n description B\n", "Now", "Wanted")
    view.left.context = {"address": "10.0.0.1", "platform": "ios"}
    view.fix_left()
    doc = page.current_document()
    assert isinstance(doc, Document) and doc.kind == Document.FIX
    assert "interface Gi0/1\n description B\nexit" in doc.editor.text()
    assert doc.context["address"] == "10.0.0.1"
    assert config_lines(doc.editor.text()) == ["interface Gi0/1", " description B", "exit"]


def test_archive_changes_review_and_map_flags(page, app, monkeypatch):
    configs = page.configs
    configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1")
    change = configs.upload("10.0.0.1", "running", CONFIG + "logging host 1.1.1.1\n", "alice", changed_by="bob")
    page.refresh_views()
    assert page.archive_panel.tree.topLevelItemCount() == 1
    assert page.changes_panel.table.rowCount() == 1
    assert page.window.netmap_tab.notes == {"10.0.0.1": "Config: 1 config change to review (Editor page)"}
    page.window.resize(1200, 800)
    page.resize(1200, 800)
    page.window.show()
    page.open_change(change["version_id"])
    settle(app)
    view = page.current_document()
    assert isinstance(view, CompareView) and view.result.counts() == (1, 0)
    assert view.left.editor.isReadOnly() and view.right.editor.isReadOnly()
    controller = view.review
    assert controller.reviewing and view.mode == diff.SECTION and not view.mode_combo.isEnabled()
    page.refresh_views()  # Opening it isn't reviewing it
    assert page.window.netmap_tab.notes == {"10.0.0.1": "Config: 1 config change to review (Editor page)"}
    assert page.changes_panel.table.item(0, 5).text() == "To review"
    settle(app)
    QTest.keyClick(view.right.editor, Qt.Key_Space)
    assert controller.state.done() and controller.state.verdicts == {0: "expected"}

    class Finish:
        def __init__(self, *args):
            pass

        def exec_(self):
            return QDialog.Accepted

        def reason(self):
            return "CHG-1"

    monkeypatch.setattr(config_review, "FinishDialog", Finish)
    controller.finish()
    settle(app)
    assert not controller.reviewing and "Approved" in controller.bar.title.text()
    page.refresh_views()
    assert page.window.netmap_tab.notes == {}
    assert page.changes_panel.table.item(0, 5).text() == "Approved"
    [row] = page.configs.store.reviews_of(change["version_id"])
    assert (row["outcome"], row["reason"], row["total"]) == ("approved", "CHG-1", 1)
    reason = page.changes_panel.table.item(0, 7)
    assert reason.text() == "Approved: CHG-1" and "Approved by" in reason.toolTip()
    page.window.hide()


def test_review_log_lists_reasons_and_opens_the_change(page, app, monkeypatch):
    from nomad.configs import review
    configs = page.configs
    configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1")
    change = configs.upload("10.0.0.1", "running", CONFIG + "username eve secret x\n", "alice")["version_id"]
    blocks = configs.store.review_blocks(change)
    verdicts = [{"index": block.index, "fingerprint": block.fingerprint, "verdict": "unexpected", "note": "who is eve",
                 "seconds": 2, "seen": True} for block in blocks]
    configs.finish_review(change, "bob", verdicts, "Nobody asked for eve")
    configs.close_raised(change, "carol", review.EXPLAINED, "Contractor, CHG-9")
    page.refresh_views()
    assert page.changes_panel.table.item(0, 7).text() == "Raised: Nobody asked for eve · Explained: Contractor, CHG-9"
    assert "who is eve" in page.changes_panel.table.item(0, 7).toolTip()
    page.show_review_log()
    dialog = page.review_log_dialog
    texts = [[dialog.table.item(row, column).text() for column in range(dialog.table.columnCount())]
             for row in range(dialog.table.rowCount())]
    assert {(row[3], row[4], row[5], row[6]) for row in texts} == {
        ("Review", "Raised", "bob", "Nobody asked for eve"), ("Closed", "Explained", "carol", "Contractor, CHG-9")}
    assert any("who is eve" in row[11] for row in texts)
    dialog.filter_input.setText("contractor")
    assert [dialog.table.isRowHidden(row) for row in range(2)].count(False) == 1
    opened = []
    monkeypatch.setattr(page, "open_change", lambda version_id: opened.append(version_id))
    dialog.on_double_click(0, 0)
    assert opened == [change]
    dialog.close()


def test_acknowledge_is_hidden_until_allowed(page, app):
    page.refresh_views()
    assert page.changes_panel.acknowledge_button.isHidden()
    page.configs.set_settings({"allow_acknowledge": True})
    page.refresh_views()
    assert not page.changes_panel.acknowledge_button.isHidden()


def test_nomads_pushes_are_kept_in_the_archive(page, app):
    page.configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1")
    configpush.notify_pushed("10.0.0.1", [], ["configure terminal", "logging host 1.1.1.1", "end"], "Carry VLAN")
    change = page.configs.upload("10.0.0.1", "running", CONFIG + "logging host 1.1.1.1\n", "alice")
    [push] = page.configs.pushes_for_version(change["version_id"])
    assert (push["source"], push["lines"]) == ("Carry VLAN", ["logging host 1.1.1.1"])


def test_put_back_writes_commands_to_an_old_version(page, app):
    configs = page.configs
    old = configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1", platform="ios")
    configs.upload("10.0.0.1", "running", CONFIG.replace("ntp server 10.0.0.1", "ntp server 10.9.9.9"), "alice")
    page.put_back(old["version_id"])
    settle(app)
    doc = page.current_document()
    assert doc.kind == Document.FIX
    assert "no ntp server 10.9.9.9" in doc.editor.text() and "\nntp server 10.0.0.1" in doc.editor.text()


def test_standard_saved_checks_archived_devices(page, app, monkeypatch):
    page.configs.set_scope([{"id": "10.0.0.1", "name": "R1", "address": "10.0.0.1", "names": [], "platform": "ios",
                             "kind": "router", "facts": {"hostname": "R1", "kind": "router"}}])
    page.configs.upload("10.0.0.1", "running", CONFIG, "alice")
    page.new_standard()
    doc = page.current_document()
    doc.editor.setText("! STANDARD: NTP\n! applies-to: kind=router\nntp server 10.0.0.1\nntp server 10.0.0.2\n")
    page.save_current()
    settle(app)
    assert not doc.is_modified() and doc.context["standard"] == "NTP"
    page.refresh_views()
    assert page.standards_panel.list.count() == 1
    assert page.standards_panel.table.rowCount() == 1
    page.open_result("10.0.0.1", "NTP")
    report = page.current_document()
    assert "Missing" in report.editor.text() and config_lines(report.editor.text()) == ["ntp server 10.0.0.2"]


def test_unnamed_standard_not_saved(page, app, monkeypatch):
    told = []
    monkeypatch.setattr(QMessageBox, "information", lambda *args: told.append(args[2]))
    page.new_standard()
    page.save_current()
    assert "STANDARD:" in told[0]


def test_terminal_saved_config_goes_in_archive(page, app):
    config_events().saved.emit({"host": "10.0.0.1", "name": "R1 session", "prompt": "R1#", "path": "x.cfg",
                              "text": CONFIG})
    settle(app)
    latest = page.configs.store.latest("10.0.0.1")
    assert latest is not None and latest["source"] == archive.TERMINAL
    assert page.configs.store.device("10.0.0.1")["name"] == "R1"
    assert any("config archive" in message for message in page.window.statuses)


class FakePusher:
    sent = []

    def __init__(self, *args, **kwargs):
        pass

    def set_up(self, address, text, applet="", names=()):
        FakePusher.sent.append((address, text))
        return configpush.Outcome(ok=True, transcript=text)

    def set_up_guarded(self, address, text, minutes, names=(), confirm=True):
        FakePusher.sent.append((address, text))
        return configpush.Outcome(ok=True, transcript=text, confirmed=True)

    def close(self):
        pass


def test_send_current_types_lines(page, app, monkeypatch):
    doc = page.open_text("! comment\nconfigure terminal\ninterface Gi0/1\n description B\nexit\nend\n", "Fix",
                         Document.FIX, False, {"address": "10.0.0.1", "platform": "ios"})
    monkeypatch.setattr(editor_tab.SendDialog, "exec_", lambda self: (self.pull_after.setChecked(False),
                                                                     self.revert.setChecked(False),
                                                                     editor_tab.SendDialog.Accepted)[2])
    asked = []
    monkeypatch.setattr(page.login_row, "logins", lambda status=None, devices=None: (asked.append(devices),
                                                                                     (object(), ""))[1])
    monkeypatch.setattr(page.login_row, "pusher_maker", lambda logins: (lambda should_stop: FakePusher()))
    FakePusher.sent.clear()
    page.docs.setCurrentWidget(doc)
    page.send_current()
    settle(app)
    [(address, text)] = FakePusher.sent
    assert address == "10.0.0.1"
    assert text == "configure terminal\ninterface Gi0/1\n description B\nexit\n!\nend"
    report = page.current_document()
    assert report.title == "Sent to 10.0.0.1" and "Every line was taken" in report.editor.text()
    assert asked == [[("10.0.0.1", ["R1"])]]  # The device is named (the map's R1), so its session is used


def send_with(page, monkeypatch, prepare=lambda dialog: None):
    """Send the current tab, the dialog answered at once; returns (what the dialog showed, [the addresses sent to])."""
    shown = {}

    def answer(dialog):
        shown.update(title=dialog.windowTitle(), asks=not dialog.address.isHidden(), device=dialog.device_label.text())
        dialog.pull_after.setChecked(False)
        dialog.revert.setChecked(False)
        prepare(dialog)
        return editor_tab.SendDialog.Accepted
    monkeypatch.setattr(editor_tab.SendDialog, "exec_", answer)
    monkeypatch.setattr(page.login_row, "logins", lambda status=None, devices=None: (object(), ""))
    monkeypatch.setattr(page.login_row, "pusher_maker", lambda logins: (lambda should_stop: FakePusher()))
    FakePusher.sent.clear()
    page.send_current()
    settle(QApplication.instance())
    return shown, [address for address, _ in FakePusher.sent]


def test_send_knows_the_device_without_asking(page, app, monkeypatch):
    page.configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1", platform="ios")
    newest = page.newest_id("10.0.0.1")
    page.open_version(newest)
    settle(app)
    page.current_document().editor.setReadOnly(False)
    shown, sent = send_with(page, monkeypatch)
    settle(app)
    assert shown == {"title": "Send to R1 (10.0.0.1)", "asks": False, "device": "<b>R1 (10.0.0.1)</b>"}
    assert sent == ["10.0.0.1"]
    # A file of its own: its hostname line names a device the archive knows
    page.open_text("hostname R1\ninterface Gi0/1\n description C\n", "r1-change.txt", Document.FILE, False)
    shown, sent = send_with(page, monkeypatch)
    settle(app)
    assert not shown["asks"] and sent == ["10.0.0.1"]
    # Nothing to go on: asked
    page.open_text("interface Gi0/1\n description D\n", "snippet.txt", Document.FILE, False)
    shown, sent = send_with(page, monkeypatch, lambda dialog: dialog.address.setEditText("10.9.9.9"))
    settle(app)
    assert shown["asks"] and shown["title"] == "Send to Device" and sent == ["10.9.9.9"]
    # Change... sends a known tab somewhere else
    page.open_text("hostname R1\ninterface Gi0/1\n description E\n", "r1-again.txt", Document.FILE, False)

    page.window.session_store.sessions.append(Session(name="CORE-SW", host="10.7.7.7", protocol=SSH))
    offered = []

    def elsewhere(dialog):  # Change... offers Pull Config's devices: the map's, the archive's, the saved sessions
        monkeypatch.setattr(dialog.address, "showPopup", lambda: None)
        dialog.change_device()
        offered.extend(dialog.address.itemText(index) for index in range(dialog.address.count()))
        dialog.address.setEditText("CORE-SW (10.7.7.7)")
    shown, sent = send_with(page, monkeypatch, elsewhere)
    settle(app)
    assert not shown["asks"] and sent == ["10.7.7.7"]
    assert {"R1 (10.0.0.1)", "CORE-SW (10.7.7.7)"} <= set(offered)


def test_preview_diff_is_approximate_after(page, app):
    page.show_preview_diff("R1", CONFIG, "interface Gi0/1\n description B\nexit\n")
    view = page.current_document()
    assert isinstance(view, CompareView) and view.mode == diff.SECTION
    assert " description B" in view.right.editor.text()
    assert len(view.result.changes) == 1


def test_local_scope_from_open_map(page):
    page.update_local_scope()
    device = page.configs.store.device("10.0.0.1")
    assert device is not None and device["in_scope"] and device["name"] == "R1"


def test_find_replace_through_page(page, app):
    doc = page.open_text("ntp server 10.0.0.1\nntp server 10.0.0.2\n", "x", Document.FILE, False)
    page.focus_find()
    page.find_bar.find_input.setText(r"10\.0\.0\.(\d)")
    page.find_bar.regex.setChecked(True)
    page.find_bar.replace_input.setText(r"10.9.9.\1")
    assert page.find_bar.replace_all() == 2
    assert doc.editor.text() == "ntp server 10.9.9.1\nntp server 10.9.9.2\n"


def test_pull_dialog_lists_devices_to_pick(page, app):
    from nomad.terminal.sessions import Session
    from nomad.ui.editor_panels import PullDialog
    page.window.session_store.sessions.append(Session("Core SW", host="10.0.0.9"))
    page.window.session_store.sessions.append(Session("R1 again", host="10.0.0.1"))  # On the map already
    choices = page.device_choices()
    assert [(target["name"], target["address"]) for target in choices] == [("Core SW", "10.0.0.9"),
                                                                          ("R1", "10.0.0.1")]
    dialog = PullDialog(page, choices)
    assert dialog.device.count() == 2 and dialog.device.currentText() == ""
    dialog.device.setCurrentIndex(1)
    picked = dialog.target(page.target_for_address)
    assert (picked["id"], picked["address"], picked["platform"]) == ("10.0.0.1", "10.0.0.1", "ios")
    dialog.device.setEditText("10.5.5.5")
    typed = dialog.target(page.target_for_address)
    assert (typed["id"], typed["address"]) == ("10.5.5.5", "10.5.5.5")
    dialog.device.setEditText("")
    assert dialog.target(page.target_for_address) is None


def test_a_saved_session_name_typed_pulls_its_host(page):
    from nomad.terminal.sessions import Session
    page.window.session_store.sessions.append(Session("Core SW", host="10.0.0.9"))
    page.window.session_store.sessions.append(Session("Edge", host="10.0.0.1"))  # On the map as R1
    target = page.target_for_address("core sw")
    assert (target["address"], target["names"]) == ("10.0.0.9", ["Core SW"])
    target = page.target_for_address("Edge")
    assert (target["name"], target["address"], target["names"][-1]) == ("R1", "10.0.0.1", "Edge")


def test_editor_logs_in_with_the_devices_saved_session_without_asking(page, monkeypatch):
    from nomad.terminal.sessions import Session
    from nomad.ui import ssh_push
    store = page.window.session_store
    store.put(Session("R1", host="10.0.0.1", username="admin", saved_password=store.vault.protect("pw")))
    monkeypatch.setattr(page.login_row, "ask_login", lambda: pytest.fail("asked for a login"))
    monkeypatch.setattr(ssh_push, "ensure_unlocked", lambda *args: True)
    logins, _ = page.login_row.logins(None, [("10.0.0.1", ["R1"])])
    session, label = logins.login_for("10.0.0.1", ["R1"])
    assert label == "saved session R1" and store.vault.reveal(session.saved_password) == "pw"
    assert logins.login_for("10.0.0.2") == (None, "")  # Nothing typed for the rest


def test_a_saved_session_without_a_password_has_it_asked_once(page, monkeypatch):
    from nomad.terminal.sessions import Session
    from nomad.ui import ssh_push
    page.window.session_store.put(Session("R1", host="10.0.0.1", username="admin"))
    monkeypatch.setattr(page.login_row, "ask_login", lambda: pytest.fail("asked for a login"))
    prompts = []

    class Secret:
        Accepted = 1

        def __init__(self, parent, title, prompt, can_save):
            prompts.append(prompt)
            self.field = type("Field", (), {"text": lambda self: "typed"})()

        def exec_(self):
            return ssh_push.QDialog.Accepted
    monkeypatch.setattr(ssh_push, "SecretDialog", Secret)
    logins, _ = page.login_row.logins(None, [("10.0.0.1", [])])
    assert logins.password == "typed" and prompts == ["Password for admin on R1 (its saved session has no saved "
                                                      "password):"]


def test_a_device_without_a_saved_session_still_asks(page, monkeypatch):
    asked = []
    monkeypatch.setattr(page.login_row.picker, "credential", lambda: None)
    monkeypatch.setattr(page.login_row, "ask_login", lambda: asked.append(1))
    assert page.login_row.logins(None, [("10.0.0.7", [])]) is None and asked == [1]


def test_next_backup_column_and_back_up_now(page, app):
    from nomad.ui.editor_panels import next_text
    assert next_text({"excluded": 1}, 100) == "Left out"
    assert next_text({"in_scope": 1, "next_due": 50}, 100) == "Due now"
    assert next_text({"in_scope": 0, "next_due": 50}, 100) == ""
    page.update_local_scope()
    page.refresh_views()
    item = page.archive_panel.tree.topLevelItem(0)
    assert item.text(2) not in ("", "Due now")  # Spread over the day
    page.back_up_now(["10.0.0.1"])
    settle(app)
    page.refresh_views()
    assert page.archive_panel.tree.topLevelItem(0).text(2) == "Due now"


def test_who_is_backing_up(page, app):
    page.update_local_scope()
    page.configs.claim("pc-gui", "PC", "gui", 0, status="Nothing due (checked 10:00)", user="alice (PC)")
    page.refresh_runners()
    settle(app)
    table = page.backups_panel.runners
    assert table.rowCount() == 1
    assert [table.item(0, column).text() for column in (0, 1, 2, 3)] == \
        ["PC", "NOMAD: alice", "Nothing now", "Nothing due (checked 10:00)"]
    assert "Nothing is due now" in page.backups_panel.runners_note.text()


def test_recent_backups_from_every_computer(page, app):
    page.update_local_scope()
    page.configs.upload("10.0.0.1", "running", CONFIG, "Map Watcher service (CORE)", archive.SCHEDULED)
    page.configs.report_failure("10.0.0.1", "PC2", "timed out", by="bob (PC2)")
    page.refresh_runners()
    settle(app)
    table = page.backups_panel.results
    assert table.rowCount() == 2
    assert [table.item(0, column).text() for column in (1, 2, 3)] == ["R1", "PC2 (bob)", "Couldn't: timed out"]
    assert [table.item(1, column).text() for column in (2, 3)] == ["CORE service", "first copy"]


class FakeBackupThread:
    def __init__(self, *args):
        self.stepped = self.failed = type("Signal", (), {"connect": lambda self, slot: None})()

    def start(self):
        pass

    def stop(self):
        pass

    def wait(self, ms):
        return True


def test_ticking_backups_with_the_master_password_locked_asks_for_it(page, monkeypatch):
    page.update_local_scope()
    store = page.window.session_store
    monkeypatch.setattr(type(store.vault), "enabled", property(lambda self: True))
    unlocked = []
    monkeypatch.setattr(type(store.vault), "unlocked", property(lambda self: bool(unlocked)))
    monkeypatch.setattr(editor_tab, "BackupThread", FakeBackupThread)
    asked = []

    def unlock(parent, store, reason=""):
        asked.append(reason)
        unlocked.append(1)
        return True
    monkeypatch.setattr(editor_tab, "ensure_unlocked", unlock)
    page.backups_panel.run_check.setChecked(True)
    assert len(asked) == 1 and "master password" in asked[0]
    assert page.backups_panel.run_check.isChecked() and page.backup_thread is not None
    assert "Running" in page.backups_panel.status.text()


def test_cancelling_the_master_password_leaves_a_link_to_unlock(page, monkeypatch):
    page.update_local_scope()
    store = page.window.session_store
    monkeypatch.setattr(type(store.vault), "enabled", property(lambda self: True))
    monkeypatch.setattr(type(store.vault), "unlocked", property(lambda self: False))
    asked = []
    monkeypatch.setattr(editor_tab, "ensure_unlocked", lambda *args: asked.append(1) and False)
    page.backups_panel.run_check.setChecked(True)
    assert asked == [1] and not page.backups_panel.run_check.isChecked() and page.backup_thread is None
    assert 'href="unlock"' in page.backups_panel.status.text()
    page.backups_link("unlock")  # The link asks again
    assert asked == [1, 1]


def test_backups_at_start_with_the_master_password_locked_wait_without_a_dialog(page, monkeypatch):
    from PyQt5.QtCore import QSettings
    page.update_local_scope()
    store = page.window.session_store
    monkeypatch.setattr(type(store.vault), "enabled", property(lambda self: True))
    monkeypatch.setattr(type(store.vault), "unlocked", property(lambda self: False))
    monkeypatch.setattr(editor_tab, "ensure_unlocked", lambda *args: pytest.fail("asked while starting"))
    settings = QSettings(str(page.window.session_store.path) + ".ini", QSettings.IniFormat)
    settings.setValue("editor/run_backups", True)
    page.restore_settings(settings)
    # The box stays ticked, waiting, with the link to unlock now
    assert page.backups_panel.run_check.isChecked() and page.backup_thread is None
    assert 'href="unlock"' in page.backups_panel.status.text() and "Waiting" in page.backups_panel.status.text()
    assert page.unlock_timer.isActive()
    page.save_settings(settings)
    assert settings.value("editor/run_backups", False, bool)  # Still on for next time


def test_waiting_backups_start_once_the_master_password_is_unlocked(page, monkeypatch):
    from PyQt5.QtCore import QSettings
    page.update_local_scope()
    store = page.window.session_store
    unlocked = []
    monkeypatch.setattr(type(store.vault), "enabled", property(lambda self: True))
    monkeypatch.setattr(type(store.vault), "unlocked", property(lambda self: bool(unlocked)))
    monkeypatch.setattr(editor_tab, "BackupThread", FakeBackupThread)
    settings = QSettings(str(store.path) + ".ini", QSettings.IniFormat)
    settings.setValue("editor/run_backups", True)
    page.restore_settings(settings)
    page.check_unlocked()
    assert page.backup_thread is None  # Still locked
    unlocked.append(1)  # Unlocked somewhere else (the Terminal)
    page.check_unlocked()
    assert page.backup_thread is not None and not page.unlock_timer.isActive()
    assert "Running" in page.backups_panel.status.text()


def test_a_device_with_its_own_login_uses_it(page, monkeypatch):
    from nomad.configs import logins as backup_logins
    from nomad.terminal.sessions import Credential, Session
    store = page.window.session_store
    own = Credential("Branch", username="branch", saved_password="secret-b")
    usual = Credential("Usual", username="usual", saved_password="secret-u")
    store.credentials.items = [own, usual]
    backup_logins.save({"10.0.0.1": own.id})
    page.show_device_logins_count()
    assert page.backups_panel.device_logins_note.text().startswith("1 device")
    fallback = store.credentials.apply(Session("", credential_id=usual.id))
    from nomad.ui.ssh_push import SavedLogins
    login, secret = page.with_device_logins((SavedLogins(store, fallback, None, "credential Usual"), "en"))
    session, label = login.login_for("10.0.0.1", ["R1"])
    assert (session.username, session.host, label) == ("branch", "10.0.0.1", "credential Branch")
    session, label = login.login_for("10.0.0.2", ["R2"])
    assert (session.username, label) == ("usual", "credential Usual")
    assert secret == "en"
    # Pull Config uses it too, with nothing asked for the usual login
    monkeypatch.setattr(editor_tab, "ensure_unlocked", lambda *args: True)
    monkeypatch.setattr(page.login_row, "logins", lambda *args: pytest.fail("asked for the usual login"))
    login, _ = page.pull_logins({"id": "10.0.0.1", "address": "10.0.0.1", "names": []})
    assert login.login_for("10.0.0.1")[1] == "credential Branch"


def test_device_logins_dialog(app, tmp_path):
    from nomad.terminal.sessions import Credential, SessionStore
    from nomad.ui.backup_logins_dialog import USUAL, DeviceLoginsDialog
    store = SessionStore(str(tmp_path / "sessions.json"))
    good = Credential("Branch", username="branch", saved_password="x")
    asked = Credential("Asked", username="asked")  # No saved password: backups can't use it
    store.credentials.items = [good, asked]
    devices = [{"id": "10.0.0.1", "name": "R1", "address": "10.0.0.1", "failures": [{"reason": "Login failed"}]},
               {"id": "10.0.0.2", "name": "R2", "address": "10.0.0.2", "failures": []}]
    dialog = DeviceLoginsDialog(None, store, devices, {"gone": good.id}, select=["10.0.0.2"])
    assert [dialog.combo.itemText(index) for index in range(dialog.combo.count())] == [USUAL, "Branch  (branch)"]
    assert dialog.selected_ids() == ["10.0.0.2"] and dialog.table.item(0, 3).text() == "Login failed"
    dialog.combo.setCurrentIndex(1)
    dialog.use_for_selected()
    assert dialog.table.item(1, 2).text() == "Branch"
    assert dialog.chosen() == {"gone": good.id, "10.0.0.2": good.id}  # A device not listed now is kept
    dialog.filter.setText("R1")
    assert dialog.table.isRowHidden(1) and not dialog.table.isRowHidden(0)
    dialog.deleteLater()


def test_device_logins_dialog_shows_the_saved_session_a_device_uses(app, tmp_path):
    from nomad.terminal.sessions import Credential, Session, SessionStore
    from nomad.ui.backup_logins_dialog import USUAL, DeviceLoginsDialog
    store = SessionStore(str(tmp_path / "sessions.json"))
    lab = Credential("Lab Admin", username="admin", saved_password="x")
    store.credentials.items = [lab]
    store.sessions = [Session("R2.home.lab", host="10.18.0.12", credential_id=lab.id),
                      Session("SW9", host="10.0.0.9", username="nobody")]
    devices = [{"id": "10.100.2.1", "name": "R2.home.lab", "address": "10.100.2.1",
                "names": ["R2.home.lab", "10.18.0.12"], "failures": []},
               {"id": "10.0.0.9", "name": "SW9", "address": "10.0.0.9", "names": [], "failures": []},
               {"id": "10.0.0.5", "name": "R5", "address": "10.0.0.5", "names": [], "failures": []}]
    dialog = DeviceLoginsDialog(None, store, devices, {})
    assert [dialog.table.item(row, 2).text() for row in range(3)] == [
        "Its saved session (R2.home.lab)", "Its saved session (SW9) has no saved password: the usual login", USUAL]
    dialog.deleteLater()


# ----------------------------------------------------------------- Backups' logins, set once for the Map Watcher too

def lab_logins(page, monkeypatch):
    """Lab Admin for R2's saved session, the archive holding R2 by another address, and passwords "encrypted" as
    <text> (for the Map Watcher's config too)."""
    from nomad.terminal import credentials
    from nomad.terminal.sessions import Credential, Session
    monkeypatch.setattr(credentials, "protect", lambda text, machine=False: f"<{text}>")
    monkeypatch.setattr(credentials, "unprotect", lambda text: text[1:-1])
    store = page.window.session_store
    lab = Credential("Lab Admin", username="admin", saved_password="<lab-pw>")
    longpw = Credential("jared longpw", username="jared", saved_password="<long-pw>")
    store.credentials.items = [lab, longpw]
    r2 = Session("R2.home.lab", host="10.18.0.12", credential_id=lab.id)
    store.credentials.apply(r2)
    store.sessions = [r2]
    with page.configs.lock:
        page.configs.store.sync_devices([{"id": "10.100.2.1", "name": "R2.home.lab", "address": "10.100.2.1",
                                          "names": ["R2.home.lab", "10.18.0.12"], "platform": "ios",
                                          "kind": "router", "facts": {}}])
    page.login_row.picker.fill("")
    return store, lab, longpw


def test_the_map_watcher_gets_the_editors_backup_logins(page, monkeypatch):
    from nomad.configs import logins as backup_logins
    from nomad.netmap import watch_service
    from nomad.ui import backup_logins_sync
    store, lab, longpw = lab_logins(page, monkeypatch)
    # Installed before: the login and enable password chosen in the Map Watcher's window
    watch_service.save_config({"maps": [], "backups": {
        "username": "jared", "label": "credential jared longpw", "password": "<long-pw>", "enable": "<en>",
        "credential_id": longpw.id, "devices": {}, "logins": {}}})
    page.backup_sync.restore()  # NOMAD starting: the Editor had no usual login, so it takes the Map Watcher's
    assert page.login_row.picker.credential_id() == longpw.id and page.login_row.enable_input.text() == "en"
    assert backup_logins.read()["usual"] == longpw.id
    saves = []
    real_save = watch_service.save_config
    monkeypatch.setattr(watch_service, "save_config", lambda config, *args: saves.append(1) or real_save(config))
    page.backup_sync.update_service()
    backups = watch_service.load_config()["backups"]
    # R2 is backed up with its saved session's login (Lab Admin), the rest with the usual one
    assert backups["devices"] == {"10.100.2.1": lab.id}
    assert backups["logins"][lab.id] == {"username": "admin", "password": "<lab-pw>", "label": "credential Lab Admin"}
    assert (backups["username"], backups["password"], backups["enable"]) == ("jared", "<long-pw>", "<en>")
    assert backup_logins.read()["enable"] == "<en>"  # Saved in the Editor's file now
    assert "now logs in the same way" in page.backups_panel.service_note.text()
    page.backup_sync.update_service()  # Nothing changed: nothing written
    assert len(saves) == 1
    # Changing the usual login in the Editor changes the service's at once
    page.login_row.picker.combo.setCurrentIndex(page.login_row.picker.combo.findData(lab.id))
    assert watch_service.load_config()["backups"]["username"] == "admin" and len(saves) == 2
    assert backup_logins.read()["usual"] == lab.id
    # And the enable password
    page.login_row.enable_input.setText("en2")
    page.login_row.enable_input.editingFinished.emit()
    assert backup_logins.read()["enable"] == "<en2>"
    assert watch_service.load_config()["backups"]["enable"] == "<en2>" and len(saves) == 3
    # A password changed while the master password is locked: a link to update the service, nothing asked
    monkeypatch.setattr(type(store.vault), "enabled", property(lambda self: True))
    monkeypatch.setattr(type(store.vault), "unlocked", property(lambda self: False))
    lab.saved_password = "<lab-pw2>"
    store.credentials.apply(store.sessions[0])
    monkeypatch.setattr(backup_logins_sync, "ensure_unlocked", lambda *args: pytest.fail("asked"))
    page.backup_sync.update_service()
    assert "Update the Service's Logins" in page.backups_panel.service_note.text() and len(saves) == 3
    monkeypatch.setattr(backup_logins_sync, "ensure_unlocked", lambda *args: True)  # Clicked, and unlocked
    page.service_note_link(backup_logins_sync.UPDATE_LINK)
    assert watch_service.load_config()["backups"]["logins"][lab.id]["password"] == "<lab-pw2>"


def test_no_map_watcher_here_leaves_the_backup_logins_alone(page, monkeypatch):
    from nomad.configs import logins as backup_logins
    from nomad.netmap import watch_service
    lab_logins(page, monkeypatch)
    page.backup_sync.restore()
    page.backup_sync.update_service(ask=True)  # Not installed (or not readable without administrator rights)
    assert page.backups_panel.service_note.text() == ""
    assert backup_logins.read()["usual"] == ""  # A user name and password asked for
    watch_service.save_config({"maps": []})  # Installed, without backups
    page.backup_sync.update_service(ask=True)
    assert "backups" not in watch_service.load_config()


def test_old_addresses_left_out_of_pull_and_merged_from_the_list(page, app, monkeypatch):
    from nomad.ui import editor_panels
    page.update_local_scope()
    # R1's old address, pulled by hand
    page.configs.upload("192.168.5.7", "running", CONFIG, "x", name="R1", address="192.168.5.7")
    page.configs.upload("10.0.0.99", "running", CONFIG, "x", name="Lab", address="10.0.0.99")
    assert [target["address"] for target in page.device_choices()] == ["10.0.0.99", "10.0.0.1"]
    page.refresh_views()
    labels = sorted(page.archive_panel.tree.topLevelItem(index).text(0)
                    for index in range(page.archive_panel.tree.topLevelItemCount()))
    assert labels == ["Lab", "R1 (10.0.0.1)", "R1 (192.168.5.7)"]
    monkeypatch.setattr(editor_panels.MergeDialog, "exec_", lambda self: editor_panels.MergeDialog.Accepted)
    page.merge_devices(["192.168.5.7"])
    settle(app)
    assert page.configs.store.device("192.168.5.7") is None and len(page.history_of("10.0.0.1")) == 1
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    page.forget_devices(["10.0.0.99"])
    settle(app)
    assert page.configs.store.device("10.0.0.99") is None
