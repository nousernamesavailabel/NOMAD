"""The Editor page: files (open, edit, save keeping the line endings), Compare (copy arrows, Fix Commands), the local
config archive (changes, review, standards), the Terminal's saved configs, sending lines, closing with changes."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QThreadPool  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402

from nomad.configs import archive, diff  # noqa: E402
from nomad.netmap import configpush, model  # noqa: E402
from nomad.terminal.sessions import SessionStore  # noqa: E402
from nomad.ui import editor_tab  # noqa: E402
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


def test_archive_changes_review_and_map_flags(page, app):
    configs = page.configs
    configs.upload("10.0.0.1", "running", CONFIG, "alice", name="R1", address="10.0.0.1")
    change = configs.upload("10.0.0.1", "running", CONFIG + "logging host 1.1.1.1\n", "alice", changed_by="bob")
    page.refresh_views()
    assert page.archive_panel.tree.topLevelItemCount() == 1
    assert page.changes_panel.table.rowCount() == 1
    assert page.window.netmap_tab.notes == {"10.0.0.1": "Config: 1 config change to review (Editor page)"}
    page.open_change(change["version_id"])
    settle(app)
    view = page.current_document()
    assert isinstance(view, CompareView) and view.result.counts() == (1, 0)
    assert view.left.editor.isReadOnly() and view.right.editor.isReadOnly()
    page.refresh_views()
    assert page.window.netmap_tab.notes == {}


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
    assert asked == [[("10.0.0.1", [])]]  # The device is named, so its saved session is used without asking


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
    assert not page.backups_panel.run_check.isChecked() and 'href="unlock"' in page.backups_panel.status.text()
    page.save_settings(settings)
    assert settings.value("editor/run_backups", False, bool)  # Still on for next time
