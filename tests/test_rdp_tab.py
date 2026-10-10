import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

import pytest
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QMenu, QMessageBox, QWidget

from nomad.terminal.sessions import RDP, SSH, Session, SessionStore
from nomad.ui import rdp_tab
from nomad.ui.rdp_dialog import RdpDialog
from nomad.ui.terminal_tab import TerminalTab
from nomad.ui.scp_tab import ScpTab
from nomad.ui.host_menu import HostActions
from nomad.ui.session_manager import SESSION_ROLE


@pytest.fixture
def page(tmp_path, monkeypatch):
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.navigator = SimpleNamespace(setCurrentWidget=lambda page: None)
    store = SessionStore(str(tmp_path / "sessions.json"))
    monkeypatch.setattr(rdp_tab, "clean_old_connections", lambda: None)
    page = rdp_tab.RdpTab(window, store)
    yield page
    page.shutdown()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_protocol_filters_and_editor(page):
    ssh = Session("SSH", host="host")
    rdp = Session("RDP", protocol=RDP, host="host", port=3389)
    page.store.source.put(ssh)
    page.store.put(rdp)
    assert page.manager.visible_sessions() == [rdp]
    assert RDP not in TerminalTab.protocols and ScpTab.protocols == {SSH}
    assert page.manager.make_session("").port == 3389
    assert page.manager.dialog_class is RdpDialog


def test_launch_recents_details_and_save_preferences(page, tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(rdp_tab, "launch_session", lambda session, password: calls.append((session, password)))
    item = Session("Server", protocol=RDP, host="host", port=3389, rdp_multimon=True)
    page.store.put(item)
    page.open_session(item)
    QApplication.instance().processEvents()
    assert calls == [(item, "")]
    assert len(page.store.recent) == 1
    assert "All monitors" in page.details_label.text()
    assert "Last launched:" in page.details_label.text()
    assert "launched" in page.status_label.text()
    settings = QSettings(str(tmp_path / "ui.ini"), QSettings.IniFormat)
    page.save_settings(settings)
    page.restore_settings(settings)
    assert settings.contains("rdp/columns")


def test_quick_launch_details_survive_tree_refresh(page, monkeypatch):
    monkeypatch.setattr(rdp_tab, "launch_session", lambda *args: object())
    page.open_address("server", RDP)
    QApplication.instance().processEvents()
    assert page.selected_session.host == "server"
    assert "server:3389" in page.details_label.text()
    assert page.save_button.isVisibleTo(page)


def test_locked_vault_cancel_does_not_launch(page, monkeypatch):
    monkeypatch.setattr(rdp_tab, "ensure_unlocked", lambda *args: False)
    monkeypatch.setattr(rdp_tab, "launch_session", lambda *args: pytest.fail("Must not launch"))
    page.open_session(Session("Server", protocol=RDP, host="host", port=3389, saved_password="encrypted"))
    assert not page.store.recent


def test_saved_password_revealed_only_for_launch(page, monkeypatch):
    monkeypatch.setattr(rdp_tab, "ensure_unlocked", lambda *args: True)
    monkeypatch.setattr(page.store.vault, "reveal", lambda secret: "password")
    calls = []
    monkeypatch.setattr(rdp_tab, "launch_session", lambda session, password: calls.append(password))
    page.open_session(Session("Server", protocol=RDP, host="host", port=3389, saved_password="encrypted"))
    assert calls == ["password"]
    assert page.store.recent[0].session.saved_password == ""
    assert "password" not in page.status_label.text()


def test_launch_failure_does_not_record_recent(page, monkeypatch):
    def fail(*args):
        raise OSError("Client not found")
    monkeypatch.setattr(rdp_tab, "launch_session", fail)
    page.open_session(Session("Server", protocol=RDP, host="host", port=3389))
    assert not page.store.recent
    assert "Client not found" in page.status_label.text()


def test_editor_preserves_and_forgets_password(page):
    item = Session("Server", protocol=RDP, host="host", port=3389, saved_password="encrypted")
    dialog = RdpDialog(page, item, [], store=page.store)
    dialog.name_input.setText("Updated")
    dialog.save()
    assert dialog.session.saved_password == "encrypted"
    dialog = RdpDialog(page, item, [], store=page.store)
    dialog.save_password_check.setChecked(False)
    dialog.save()
    assert dialog.session.saved_password == ""


def test_open_address_matches_saved_session(page, monkeypatch):
    item = Session("Saved", protocol=RDP, host="host", port=3390, username="admin")
    page.store.put(item)
    calls = []
    monkeypatch.setattr(page, "open_session", lambda session, **kwargs: calls.append(session))
    page.open_address("host", RDP)
    assert calls == [item]
    page.open_address("other", RDP, name="Other PC", folder="Site")
    assert calls[-1].port == 3389 and calls[-1].name == "Other PC" and calls[-1].folder == "Site"


def test_clear_recent_is_scoped_to_page(page, monkeypatch):
    page.store.remember(Session("SSH", host="host"))
    page.store.remember(Session("RDP", protocol=RDP, host="host", port=3389))
    monkeypatch.setattr(QMessageBox, "question", lambda *args: QMessageBox.Yes)
    page.manager.clear_recent()
    assert [entry.session.protocol for entry in page.store.recent] == [SSH]


def test_host_menu_launches_matching_rdp_session(page, monkeypatch):
    item = Session("Saved desktop", protocol=RDP, host="host", port=3389)
    page.store.put(item)
    page.window.rdp_tab = page
    other = SimpleNamespace(saved_matches=lambda *args: [])
    page.window.terminal_tab = page.window.scp_tab = other
    menu = QMenu(page)
    actions = HostActions(page.window, page).add_to(menu, "host")
    calls = []
    monkeypatch.setattr(page, "open_session", lambda session, **kwargs: calls.append(session))
    action = next(action for action in actions if action.text() == "Open RDP Session (Saved desktop)")
    actions[action]()
    assert calls == [item]
    assert "Create RDP Session..." not in [action.text() for action in actions]


def test_host_menu_creates_an_rdp_session_for_a_host_without_one(page, monkeypatch):
    page.window.rdp_tab = page
    page.window.terminal_tab = page.window.scp_tab = SimpleNamespace(saved_matches=lambda *args: [])
    page.window.statuses = []
    page.window.show_status = lambda text, kind: page.window.statuses.append(text)
    shown = []

    class Dialog:
        def __init__(self, parent, session, folders, title, store):
            shown.append(session)
            self.session = session

        def exec_(self):
            return True

    monkeypatch.setattr(page.manager, "dialog_class", Dialog)
    menu = QMenu(page)
    actions = HostActions(page.window, page).add_to(menu, "10.0.0.7", name="Desk 7", folder="Office")
    action = next(action for action in actions if action.text() == "Create RDP Session...")
    actions[action]()
    session, = shown
    assert (session.protocol, session.host, session.port, session.name, session.folder) ==         (RDP, "10.0.0.7", 3389, "Desk 7", "Office")
    assert page.store.matching(["10.0.0.7"], RDP) == [session]
    assert page.window.statuses == ["Saved the RDP session Office/Desk 7."]


def test_full_width_session_list_shows_launch_settings_and_preserves_columns(page, tmp_path):
    item = Session("Desktop", protocol=RDP, host="192.0.2.5", port=3390, username=r"CORP\user",
                   saved_password="encrypted", rdp_multimon=True)
    page.store.put(item)
    page.manager.fill_tree(select=item.id)
    page.resize(820, 580)
    page.show()
    QApplication.instance().processEvents()
    page.layout().activate()
    page.manager.layout().activate()
    tree = page.manager.tree
    row = tree.currentItem()
    assert row.data(0, SESSION_ROLE) == item.id
    assert [row.text(column) for column in range(1, 5)] == ["192.0.2.5:3390", r"CORP\user", "Saved", "All monitors"]
    assert tree.width() > page.width() * 0.9
    assert tree.columnWidth(0) >= 240  # Narrow windows scroll instead of crushing session names.
    tree.setColumnWidth(1, 220)
    settings = QSettings(str(tmp_path / "columns.ini"), QSettings.IniFormat)
    page.save_settings(settings)
    tree.setColumnWidth(1, 140)
    page.restore_settings(settings)
    assert tree.columnWidth(1) == 220


def test_activation_in_address_column_launches_the_selected_session(page, monkeypatch):
    item = Session("Desktop", protocol=RDP, host="server", port=3389)
    page.store.put(item)
    page.manager.fill_tree(select=item.id)
    calls = []
    monkeypatch.setattr(page, "open_session", lambda session, **kwargs: calls.append(session))
    page.manager.tree.itemActivated.emit(page.manager.tree.currentItem(), 1)
    assert calls == [item]


def test_quick_launch_can_log_in_with_a_saved_credential(page, monkeypatch):
    from PyQt5.QtWidgets import QDialog
    from nomad.terminal.sessions import Credential
    from nomad.ui import credential_dialogs
    store = page.store
    credential = Credential("Domain", username="jsmith@corp", saved_password=store.vault.protect("pw1"))
    store.credentials.put(credential, default=True)
    monkeypatch.setattr(credential_dialogs.LoginDialog, "exec_", lambda dialog: QDialog.Accepted)
    monkeypatch.setattr(rdp_tab, "ensure_unlocked", lambda *args: True)
    calls = []
    monkeypatch.setattr(rdp_tab, "launch_session", lambda session, password: calls.append((session.username, password)))
    page.open_address("server", RDP)
    assert calls == [("jsmith@corp", "pw1")]
    assert store.recent[0].session.credential_id == credential.id  # Recent launches it the same way
    page.open_session(store.recent_session(store.recent[0]))  # Without asking again
    assert calls[-1] == ("jsmith@corp", "pw1")

    monkeypatch.setattr(credential_dialogs.LoginDialog, "exec_", lambda dialog: QDialog.Rejected)
    page.open_address("other", RDP)  # Cancelled: nothing launched or recorded
    assert len(calls) == 2 and all(entry.session.host != "other" for entry in store.recent)
