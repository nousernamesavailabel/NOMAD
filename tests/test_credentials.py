import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from types import SimpleNamespace

import pytest
from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QDialog, QWidget

from nomad.terminal.backup import read_backup, restore_backup, write_backup
from nomad.terminal.commands import CommandStore
from nomad.terminal.highlight import HighlightStore
from nomad.terminal.sessions import AUTH_KEY, RDP, TELNET, TERMINAL_PROTOCOLS, Credential, Session, \
    SessionFolderStore, SessionStore, validate_credential
from nomad.ui import prompts
from nomad.ui.credential_dialogs import OWN_LOGIN, CredentialDialog
from nomad.ui.rdp_dialog import RdpDialog
from nomad.ui.session_dialog import SessionDialog


@pytest.fixture
def store(tmp_path):
    return SessionStore(str(tmp_path / "sessions.json"))


@pytest.fixture
def parent():
    app = QApplication.instance() or QApplication([])
    widget = QWidget()
    yield widget
    for dialog in widget.findChildren(QDialog):
        dialog.close()
    widget.close()
    widget.deleteLater()
    app.processEvents()


def tacacs(store, default=False, **values):
    values.setdefault("saved_password", store.vault.protect("pw1"))
    credential = Credential("TACACS", username="jsmith", **values)
    store.credentials.put(credential, default=default)
    return credential


def test_sessions_follow_their_credential(store, tmp_path):
    credential = tacacs(store)
    switch = Session("sw1", host="10.0.0.1", credential_id=credential.id)
    store.put(switch)
    assert switch.username == "jsmith" and store.vault.reveal(switch.saved_password) == "pw1"

    changed = Credential("TACACS", username="jsmith2", saved_password=store.vault.protect("pw2"), id=credential.id)
    store.credentials.put(changed)
    assert switch.username == "jsmith2" and store.vault.reveal(switch.saved_password) == "pw2"

    reloaded = SessionStore(str(tmp_path / "sessions.json"))
    assert reloaded.credentials.get(credential.id).username == "jsmith2"
    assert reloaded.get(switch.id).credential_id == credential.id
    assert reloaded.credentials.users(credential.id) == [reloaded.get(switch.id)]


def test_deleting_a_credential_leaves_sessions_their_login(store):
    credential = tacacs(store, default=True)
    switch = Session("sw1", host="10.0.0.1", credential_id=credential.id)
    store.put(switch)
    store.credentials.delete(credential.id)
    assert store.credentials.default is None
    assert switch.credential_id == "" and switch.username == "jsmith"
    assert store.vault.reveal(switch.saved_password) == "pw1"


def test_rdp_uses_only_password_credentials_and_assign_skips_others(store):
    key = Credential("Key", username="ops", auth=AUTH_KEY, key_file="C:/k")
    store.credentials.put(key)
    password = tacacs(store)
    assert [item.name for item in store.credentials.sorted(RDP)] == ["TACACS"]
    rdp = Session("pc", protocol=RDP, host="pc1", port=3389)
    telnet = Session("old", protocol=TELNET, host="10.0.0.9", port=23)
    ssh = Session("sw", host="10.0.0.1")
    store.sessions = [rdp, telnet, ssh]
    assert store.credentials.assign([rdp, telnet, ssh], key.id) == 1
    assert ssh.auth == AUTH_KEY and ssh.key_file == "C:/k" and rdp.credential_id == "" and telnet.credential_id == ""
    assert store.credentials.assign([rdp, ssh], password.id) == 2
    assert rdp.username == "jsmith" and store.vault.reveal(rdp.saved_password) == "pw1"
    assert store.credentials.assign([rdp], "") == 1
    assert rdp.credential_id == "" and rdp.username == "jsmith"  # Kept as its own


def test_folder_view_sees_every_session_and_credential(store):
    credential = tacacs(store)
    rdp_view = SessionFolderStore(store, {RDP}, "rdp_folders")
    rdp_view.put(Session("pc", protocol=RDP, host="pc1", port=3389, credential_id=credential.id))
    terminal_view = SessionFolderStore(store, TERMINAL_PROTOCOLS)
    terminal_view.put(Session("sw", host="10.0.0.1", credential_id=credential.id))
    assert len(terminal_view.credentials.users(credential.id)) == 2
    assert credential in terminal_view.credential_sessions


def test_recent_unsaved_connection_keeps_its_credential(store):
    credential = tacacs(store)
    quick = Session("10.0.0.5", host="10.0.0.5", credential_id=credential.id)
    store.credentials.apply(quick)
    entry = store.remember(quick)
    assert entry.session.saved_password == ""
    reopened = store.recent_session(entry)
    assert store.vault.reveal(reopened.saved_password) == "pw1"


def test_master_password_reencrypts_credentials(store):
    credential = tacacs(store)
    switch = Session("sw1", host="10.0.0.1", credential_id=credential.id)
    store.put(switch)
    store.vault.set_password(store.credential_sessions, "correct horse")
    assert store.vault.needs_master_password(credential.saved_password)
    assert store.vault.reveal(credential.saved_password) == "pw1"
    assert store.vault.reveal(switch.saved_password) == "pw1"


def test_validate_credential(store):
    tacacs(store)
    assert "name" in validate_credential(Credential(""))
    assert "already" in validate_credential(Credential("tacacs", username="x"), store.credentials)
    assert "user name" in validate_credential(Credential("Lab"))
    assert validate_credential(Credential("Lab", username="x")) is None


def test_backup_round_trip_keeps_credentials(tmp_path, store):
    credential = tacacs(store, default=True)
    store.put(Session("sw1", host="10.0.0.1", credential_id=credential.id))
    commands, highlights = CommandStore(str(tmp_path / "c.json")), HighlightStore(str(tmp_path / "h.json"))
    settings = QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat)
    write_backup(str(tmp_path / "b.nomad"), "backup-pass", store, commands, highlights, settings)

    target = SessionStore(str(tmp_path / "other" / "sessions.json"))
    data = read_backup(str(tmp_path / "b.nomad"), "backup-pass")
    restore_backup(data, target, CommandStore(str(tmp_path / "other" / "c.json")),
                   HighlightStore(str(tmp_path / "other" / "h.json")),
                   QSettings(str(tmp_path / "other" / "s.ini"), QSettings.IniFormat))
    assert target.credentials.default.name == "TACACS"
    assert target.vault.reveal(target.credentials.default.saved_password) == "pw1"
    assert target.sessions[0].credential_id == credential.id


def test_new_session_dialog_starts_with_the_default_credential(parent, store):
    credential = tacacs(store, default=True)
    dialog = SessionDialog(parent, Session(name=""), [], "New Session", store)
    assert dialog.credential_picker.credential_id() == credential.id
    assert dialog.username_input.text() == "jsmith" and not dialog.username_input.isEnabled()
    dialog.name_input.setText("sw1")
    dialog.host_input.setText("10.0.0.1")
    dialog.save()
    assert dialog.session.credential_id == credential.id and dialog.session.username == "jsmith"
    assert store.vault.reveal(dialog.session.saved_password) == "pw1"

    # Typing a login for this session instead brings back what was there before
    own = Session(name="", username="")
    dialog = SessionDialog(parent, own, [], "New Session", store)
    dialog.credential_picker.combo.setCurrentIndex(dialog.credential_picker.combo.findText(OWN_LOGIN))
    assert dialog.username_input.isEnabled() and dialog.username_input.text() == ""
    dialog.name_input.setText("sw2")
    dialog.host_input.setText("10.0.0.2")
    dialog.username_input.setText("admin")
    dialog.save()
    assert dialog.session.credential_id == "" and dialog.session.username == "admin"

    # A session that already has its own user name isn't given the default
    named = Session(name="x", host="h", username="root")
    assert SessionDialog(parent, named, [], "New Session", store).credential_picker.credential_id() == ""


def test_rdp_dialog_uses_credential(parent, store):
    credential = tacacs(store, default=True)
    dialog = RdpDialog(parent, Session(name="pc", protocol=RDP, host="pc1", port=3389), [], store=store)
    assert not dialog.password_input.isEnabled()
    dialog.save()
    assert dialog.session.credential_id == credential.id and dialog.session.username == "jsmith"
    assert store.vault.reveal(dialog.session.saved_password) == "pw1"


def test_first_credential_becomes_default(parent, store):
    dialog = CredentialDialog(parent, store, title="New Credential")
    assert dialog.default_check.isChecked()
    dialog.name_input.setText("TACACS")
    dialog.username_input.setText("jsmith")
    dialog.password_input.setText("pw")
    dialog.save()
    assert store.credentials.default is dialog.credential
    assert store.vault.reveal(dialog.credential.saved_password) == "pw"
    assert not CredentialDialog(parent, store).default_check.isChecked()


def test_password_saved_at_login_goes_to_the_credential(store, monkeypatch):
    credential = tacacs(store, saved_password="")
    switch = Session("sw1", host="10.0.0.1", credential_id=credential.id)
    other = Session("sw2", host="10.0.0.2", credential_id=credential.id)
    store.put(switch)
    store.put(other)
    reports = []
    monkeypatch.setattr(prompts, "protect_secret", lambda parent, store, value: store.vault.protect(value))
    owner = SimpleNamespace(store=store, session=switch.copy(id=switch.id),
                            report=lambda message, warning: reports.append(message))
    prompts.PromptAnswers.save_secret(owner, "password", "new-pw")
    assert store.vault.reveal(credential.saved_password) == "new-pw"
    assert store.vault.reveal(other.saved_password) == "new-pw"
    assert store.vault.reveal(owner.session.saved_password) == "new-pw"
    assert "TACACS" in reports[0]


# ----------------------------------------------------------------- Picking a credential for a quick connection

def test_login_dialog_starts_on_the_default_credential(parent, store):
    from nomad.ui.credential_dialogs import LoginDialog
    credential = tacacs(store, default=True)
    dialog = LoginDialog(parent, store, "SSH", "10.0.0.9")
    log_in = dialog.buttons.buttons()[0]
    assert dialog.credential() is credential and dialog.username_input.text() == "jsmith"
    assert not dialog.username_input.isEnabled() and log_in.isEnabled()
    dialog.picker.combo.setCurrentIndex(0)  # A user name typed here: needed for SSH
    assert dialog.credential() is None and dialog.username_input.isEnabled()
    assert dialog.username_input.text() == "" and not log_in.isEnabled()
    dialog.username_input.setText("admin")
    dialog.remember_typed("admin")
    assert log_in.isEnabled() and dialog.username() == "admin"
    dialog.picker.combo.setCurrentIndex(1)
    dialog.picker.combo.setCurrentIndex(0)
    assert dialog.username_input.text() == "admin"  # What was typed comes back

    rdp = LoginDialog(parent, store, RDP, "pc1")
    rdp.picker.combo.setCurrentIndex(0)
    assert rdp.buttons.buttons()[0].isEnabled()  # Blank: Windows asks


def test_no_default_starts_on_typing_a_user_name(parent, store):
    from nomad.ui.credential_dialogs import LoginDialog
    tacacs(store)
    dialog = LoginDialog(parent, store, "SSH", "10.0.0.9")
    assert dialog.credential() is None and dialog.picker.combo.count() == 2


def accept_login(monkeypatch, choose):
    """LoginDialog answers by itself: choose(dialog) sets it up, then it's accepted."""
    from nomad.ui import credential_dialogs

    def exec_(dialog):
        choose(dialog)
        return QDialog.Accepted
    monkeypatch.setattr(credential_dialogs.LoginDialog, "exec_", exec_)


def test_login_with_fills_in_the_credential(parent, store, monkeypatch):
    from nomad.ui.credential_dialogs import login_with
    credential = tacacs(store, default=True)
    accept_login(monkeypatch, lambda dialog: None)
    quick = Session("10.0.0.9", host="10.0.0.9")
    assert login_with(parent, store, quick)
    assert quick.credential_id == credential.id and quick.username == "jsmith"
    assert store.vault.reveal(quick.saved_password) == "pw1"

    def typed(dialog):
        dialog.picker.combo.setCurrentIndex(0)
        dialog.username_input.setText("admin")
    accept_login(monkeypatch, typed)
    other = Session("10.0.0.8", host="10.0.0.8")
    assert login_with(parent, store, other)
    assert other.username == "admin" and other.credential_id == "" and other.saved_password == ""


def test_login_with_asks_only_when_it_could_help(parent, store, monkeypatch):
    from nomad.ui import credential_dialogs
    from nomad.ui.credential_dialogs import login_with
    asked = []
    monkeypatch.setattr(credential_dialogs.LoginDialog, "exec_", lambda dialog: asked.append(1) or QDialog.Rejected)
    quick = Session("10.0.0.9", host="10.0.0.9")
    assert login_with(parent, store, quick) and not asked  # No credentials
    tacacs(store, auth=AUTH_KEY, key_file="id_rsa", saved_password="")
    assert login_with(parent, store, Session("pc", protocol=RDP, host="pc")) and not asked  # None RDP can use
    saved = Session("sw1", host="10.0.0.1")
    store.put(saved)
    assert login_with(parent, store, saved) and not asked  # A saved session keeps its own way
    assert login_with(parent, store, Session("x", host="h", username="root")) and not asked
    assert not login_with(parent, store, quick) and asked == [1]  # Cancelled
    assert quick.username == "" and quick.credential_id == ""


def test_ssh_login_offers_credentials_for_an_unsaved_connection(parent, store, monkeypatch):
    credential = tacacs(store, default=True)
    accept_login(monkeypatch, lambda dialog: None)
    quick = Session("10.0.0.9", host="10.0.0.9")
    view = Answers(store, quick)
    assert view.ask_user("username", "10.0.0.9") == "jsmith"
    assert quick.credential_id == credential.id
    reopened = store.recent_session(store.recent[0])
    assert reopened.credential_id == credential.id and store.vault.reveal(reopened.saved_password) == "pw1"


class Answers(prompts.PromptAnswers, QWidget):
    def __init__(self, store, session):
        super().__init__()
        self.store, self.session, self.reports = store, session, []

    def report(self, message, warning):
        self.reports.append(message)


def test_saved_session_still_just_asks_for_a_user_name(parent, store, monkeypatch):
    tacacs(store, default=True)
    saved = Session("sw1", host="10.0.0.1")
    store.put(saved)
    monkeypatch.setattr(prompts.QInputDialog, "getText", lambda *args: ("admin", True))
    assert Answers(store, saved).ask_user("username", "10.0.0.1") == "admin"
    assert saved.credential_id == ""


def test_password_typed_for_a_quick_connection_can_go_to_its_credential(store, monkeypatch):
    credential = tacacs(store, saved_password="")
    quick = store.credentials.apply(Session("10.0.0.9", host="10.0.0.9", credential_id=credential.id))
    monkeypatch.setattr(prompts, "protect_secret", lambda parent, store, value: store.vault.protect(value))
    reports = []
    owner = SimpleNamespace(store=store, session=quick, report=lambda message, warning: reports.append(message))
    prompts.PromptAnswers.save_secret(owner, "password", "typed-pw")
    assert store.vault.reveal(credential.saved_password) == "typed-pw"
    assert store.vault.reveal(quick.saved_password) == "typed-pw" and "TACACS" in reports[0]
    plain = Session("10.0.0.8", host="10.0.0.8")
    owner.session = plain
    prompts.PromptAnswers.save_secret(owner, "password", "other")  # No credential and not saved: nowhere to keep it
    assert plain.saved_password == "" and len(reports) == 1
