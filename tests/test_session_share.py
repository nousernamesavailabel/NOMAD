import json
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QWidget

from nomad.terminal.sessions import AUTH_AGENT, AUTH_KEY, AUTH_PASSWORD, RDP, SERIAL, TELNET, \
    TERMINAL_PROTOCOLS, Credential, Session, SessionFolderStore, SessionStore
from nomad.terminal import share
from nomad.terminal.share import KEEP_BOTH, REPLACE, SKIP, ImportChoice, ShareError, import_shared, match_hint, \
    read_share, write_share
from nomad.ui import session_share_dialogs
from nomad.ui.session_share_dialogs import FOLLOW, ShareExportDialog, ShareImportDialog

MARKERS = ("PW-MARKER", "PASSPHRASE-MARKER", "USER-MARKER", "KEYFILE-MARKER", "LOGDIR-MARKER")


@pytest.fixture
def store(tmp_path):
    return SessionStore(str(tmp_path / "sessions.json"))


@pytest.fixture
def other(tmp_path):
    """The person importing: their own store and credentials."""
    return SessionStore(str(tmp_path / "theirs.json"))


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


def credential(store, name, username="jsmith", auth=AUTH_PASSWORD, **values):
    if auth == AUTH_PASSWORD:
        values.setdefault("saved_password", store.vault.protect(f"{name}-pw"))
    item = Credential(name, username=username, auth=auth, **values)
    store.credentials.put(item)
    return item


def fill(store):
    """An SSH switch on a credential, an SSH box with its own key login, a Telnet and serial console, and RDP."""
    tacacs = credential(store, "TACACS", username="USER-MARKER")
    store.put(Session("core-sw1", host="10.1.0.1", folder="Site A/Core", credential_id=tacacs.id, notes="Rack 4"))
    store.put(Session("jump", host="10.1.0.9", folder="Site A", username="USER-MARKER", auth=AUTH_KEY,
                      key_file="C:\\KEYFILE-MARKER\\id", saved_passphrase=store.vault.protect("PASSPHRASE-MARKER"),
                      log_to_file=True, log_folder="C:\\LOGDIR-MARKER"))
    store.put(Session("old-sw", protocol=TELNET, host="10.1.0.20", port=23, folder="Site A",
                      saved_password=store.vault.protect("PW-MARKER")))
    store.put(Session("console", protocol=SERIAL, serial_port="COM3", baud_rate=115200, stop_bits=1.5,
                      folder="Site A"))
    store.put(Session("dc1", protocol=RDP, host="dc1.corp.local", port=3389, username="USER-MARKER",
                      saved_password=store.vault.protect("PW-MARKER"), rdp_width=1600, rdp_height=900))
    store.folders.add("Site A/Empty")
    store.save()
    return tacacs


def exported(store, tmp_path, **options):
    path = str(tmp_path / "shared.json")
    folders = SessionFolderStore(store, TERMINAL_PROTOCOLS).all_folders()
    rdp_folders = SessionFolderStore(store, {RDP}, "rdp_folders").all_folders()
    write_share(path, store.sessions, folders, rdp_folders, store.credentials, **options)
    return path


# ----------------------------------------------------------------- The file

def test_no_login_is_ever_written(store, tmp_path):
    fill(store)
    path = exported(store, tmp_path)
    text = open(path, encoding="utf-8").read()
    for marker in MARKERS:
        assert marker not in text
    data = json.loads(text)
    for item in data["sessions"]:
        assert set(item) <= set(share.SHARE_FIELDS) | {"credential_hint"}
        assert item["auth"] != AUTH_KEY
    assert data["format"] == share.FORMAT and data["version"] == share.VERSION
    assert "Site A/Empty" in data["folders"]


def test_credential_names_and_notes_are_optional(store, tmp_path):
    fill(store)
    data = json.load(open(exported(store, tmp_path), encoding="utf-8"))
    switch = next(item for item in data["sessions"] if item["name"] == "core-sw1")
    assert switch["credential_hint"] == "TACACS" and switch["notes"] == "Rack 4"
    data = json.load(open(exported(store, tmp_path, include_notes=False), encoding="utf-8"))
    assert all(item["notes"] == "" for item in data["sessions"])
    path = str(tmp_path / "bare.json")
    write_share(path, store.sessions)
    assert "credential_hint" not in open(path, encoding="utf-8").read()


def test_round_trip_keeps_how_sessions_connect(store, tmp_path):
    fill(store)
    shared = read_share(exported(store, tmp_path))
    by_name = {item.session.name: item for item in shared.sessions}
    assert set(by_name) == {"core-sw1", "jump", "old-sw", "console", "dc1"}
    assert by_name["console"].session.stop_bits == 1.5 and by_name["console"].session.baud_rate == 115200
    assert by_name["dc1"].session.rdp_width == 1600 and by_name["core-sw1"].session.folder == "Site A/Core"
    assert by_name["core-sw1"].hint == "TACACS" and by_name["old-sw"].hint == ""
    assert not shared.skipped
    originals = {session.id for session in store.sessions}
    assert not originals & {item.session.id for item in shared.sessions}


def test_a_hand_edited_file_cant_bring_in_a_login(tmp_path):
    path = tmp_path / "evil.json"
    path.write_text(json.dumps({"format": share.FORMAT, "version": 1, "sessions": [
        {"name": "sw", "protocol": "SSH", "host": "10.0.0.1", "port": 22, "saved_password": "x", "username": "root",
         "key_file": "C:\\Windows\\secret", "auth": AUTH_KEY, "credential_id": "abc", "log_to_file": True,
         "log_folder": "C:\\Windows", "id": "fixed", "scrollback": -5, "encoding": "rot13", "stop_bits": 7},
        {"name": "bad\nname", "protocol": "SSH", "host": "10.0.0.2"},
        {"name": "nohost", "protocol": "SSH"},
        {"name": "x", "protocol": "Gopher", "host": "h"},
        "not a session"]}), encoding="utf-8")
    shared = read_share(str(path))
    assert len(shared.sessions) == 1 and len(shared.skipped) == 4
    session = shared.sessions[0].session
    assert (session.saved_password, session.username, session.key_file, session.credential_id) == ("", "", "", "")
    assert not session.log_to_file and session.log_folder == "" and session.auth == AUTH_PASSWORD
    assert session.id != "fixed" and session.scrollback == 10000 and session.encoding == "utf-8"
    assert session.stop_bits == 1


@pytest.mark.parametrize("content, words", [
    ("not json", "Couldn't read"),
    (json.dumps({"format": "something else"}), "isn't a NOMAD shared sessions file"),
    (json.dumps({"format": share.FORMAT, "version": 99, "nomad_version": "9.0.0", "sessions": []}), "newer NOMAD"),
    (json.dumps({"format": share.FORMAT, "version": 1}), "no sessions"),
])
def test_files_that_arent_share_files(tmp_path, content, words):
    path = tmp_path / "file.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ShareError, match=words):
        read_share(str(path))


# ----------------------------------------------------------------- Importing

def test_credential_for_all_with_exceptions(store, other, tmp_path):
    fill(store)
    shared = read_share(exported(store, tmp_path))
    mine = credential(other, "Mine", username="me")
    lab = credential(other, "Lab", username="labuser")
    key = credential(other, "Key", username="keyuser", auth=AUTH_KEY, key_file="C:\\k")
    picks = {"core-sw1": mine.id, "jump": lab.id, "old-sw": mine.id, "console": mine.id, "dc1": key.id}
    result = import_shared(other, [ImportChoice(item, picks[item.session.name]) for item in shared.sessions],
                           "Shared", shared.folders, shared.rdp_folders)
    assert (result.added, result.with_credential, result.asking) == (5, 2, 1)  # RDP can't use a key credential
    by_name = {session.name: session for session in other.sessions}
    assert by_name["core-sw1"].credential_id == mine.id and by_name["core-sw1"].username == "me"
    assert other.vault.reveal(by_name["core-sw1"].saved_password) == "Mine-pw"
    assert by_name["jump"].credential_id == lab.id and by_name["jump"].key_file == ""
    assert by_name["old-sw"].credential_id == "" and by_name["old-sw"].saved_password == ""
    assert by_name["dc1"].credential_id == "" and by_name["dc1"].username == ""
    assert by_name["core-sw1"].folder == "Shared/Site A/Core" and by_name["dc1"].folder == "Shared"
    assert "Shared/Site A/Empty" in other.folders and "Shared" in other.rdp_folders
    reloaded = SessionStore(other.path)
    assert reloaded.credentials.users(mine.id)[0].name == "core-sw1"


def test_asking_keeps_agent_logins(other, tmp_path):
    source = SessionStore(str(tmp_path / "source.json"))
    source.put(Session("agent", host="10.0.0.1", auth=AUTH_AGENT, username="someone"))
    shared = read_share(exported(source, tmp_path))
    import_shared(other, [ImportChoice(item, "") for item in shared.sessions])
    session = other.sessions[0]
    assert session.auth == AUTH_AGENT and session.username == "" and session.folder == ""


def test_sessions_already_saved(store, other, tmp_path):
    fill(store)
    path = exported(store, tmp_path)
    shared = read_share(path)
    mine = credential(other, "Mine", username="me")
    import_shared(other, [ImportChoice(item, mine.id) for item in shared.sessions], "Shared")
    before = {session.name: session for session in other.sessions}

    result = import_shared(other, [ImportChoice(item, "", SKIP) for item in read_share(path).sessions], "Shared")
    assert (result.added, result.skipped) == (0, 5) and len(other.sessions) == 5

    changed = read_share(path)
    switch = next(item for item in changed.sessions if item.session.name == "core-sw1")
    switch.session.keepalive = 99
    result = import_shared(other, [ImportChoice(switch, "", REPLACE)], "Shared")
    updated = other.get(before["core-sw1"].id)
    assert result.replaced == 1 and updated.keepalive == 99
    assert updated.credential_id == mine.id and updated.username == "me" and len(other.sessions) == 5

    result = import_shared(other, [ImportChoice(switch, mine.id, KEEP_BOTH)], "Shared")
    assert result.added == 1 and {session.name for session in other.sessions} >= {"core-sw1", "core-sw1 (2)"}


def test_match_hint(other):
    mine = credential(other, "tacacs")
    key = credential(other, "KeyOnly", auth=AUTH_KEY, key_file="C:\\k")
    assert match_hint(other.credentials, "TACACS", "SSH") == mine.id
    assert match_hint(other.credentials, "KeyOnly", RDP) == ""
    assert match_hint(other.credentials, "KeyOnly", "SSH") == key.id
    assert match_hint(other.credentials, "", "SSH") == "" and match_hint(other.credentials, "Nope", "SSH") == ""


# ----------------------------------------------------------------- The dialogs

def test_export_dialog_starts_with_the_selection_ticked(parent, store, tmp_path, monkeypatch):
    fill(store)
    jump = next(session for session in store.sessions if session.name == "jump")
    dialog = ShareExportDialog(parent, store, [jump.id], ["Site A/Core"])
    sessions, folders, rdp_folders = dialog.ticked()
    assert {session.name for session in sessions} == {"core-sw1", "jump"}
    assert not rdp_folders and "Site A/Core" in folders

    everything = ShareExportDialog(parent, store)
    sessions, folders, _ = everything.ticked()
    assert len(sessions) == 5 and "Site A/Empty" in folders

    path = str(tmp_path / "out.json")
    monkeypatch.setattr(session_share_dialogs.QFileDialog, "getSaveFileName", lambda *args, **kwargs: (path, ""))
    everything.hints_check.setChecked(False)
    everything.export()
    assert everything.count == 5 and "credential_hint" not in open(path, encoding="utf-8").read()


def test_import_dialog_credential_for_all_and_exceptions(parent, store, other, tmp_path):
    fill(store)
    shared = read_share(exported(store, tmp_path))
    mine = credential(other, "Mine", username="me")
    tacacs = credential(other, "tacacs", username="tac")
    key = credential(other, "Key", username="k", auth=AUTH_KEY, key_file="C:\\k")
    dialog = ShareImportDialog(parent, other, shared, "site-a.json")
    assert dialog.prefix() == "Shared/site-a"
    rows = {row.shared.session.name: row for row in dialog.rows}
    assert rows["console"].combo is None and rows["old-sw"].combo is None
    assert rows["core-sw1"].choice == tacacs.id and rows["core-sw1"].matched == tacacs.id  # By name

    dialog.all_combo.setCurrentIndex(dialog.all_combo.findData(key.id))
    assert rows["jump"].choice == FOLLOW and dialog.effective(rows["jump"]) == key.id
    assert dialog.effective(rows["dc1"]) == ""  # Remote Desktop can't use a key credential
    assert "password credential" in rows["dc1"].combo.itemText(0)

    rows["jump"].combo.setCurrentIndex(rows["jump"].combo.findData(mine.id))  # An exception
    assert rows["jump"].choice == mine.id and rows["jump"].combo.font().bold()
    dialog.match_check.setChecked(False)
    assert rows["core-sw1"].choice == FOLLOW and rows["jump"].choice == mine.id

    dialog.set_choice([rows["dc1"]], mine.id)
    dialog.table.item(dialog.rows.index(rows["console"]), dialog.NAME).setCheckState(Qt.Unchecked)
    assert "1 left out" in dialog.summary_label.text()
    dialog.do_import()
    by_name = {session.name: session for session in other.sessions}
    assert "console" not in by_name
    assert by_name["core-sw1"].credential_id == key.id and by_name["jump"].credential_id == mine.id
    assert by_name["dc1"].credential_id == mine.id and by_name["core-sw1"].folder == "Shared/site-a/Site A/Core"


def test_import_dialog_notices_sessions_already_saved(parent, store, other, tmp_path):
    fill(store)
    path = exported(store, tmp_path)
    import_shared(other, [ImportChoice(item, "") for item in read_share(path).sessions], "Team")
    dialog = ShareImportDialog(parent, other, read_share(path), "x.json")
    assert all(row.existing is None for row in dialog.rows)
    dialog.folder_combo.setEditText("Team")
    assert all(row.existing is not None and row.duplicate_combo is not None for row in dialog.rows)
    switch = next(row for row in dialog.rows if row.shared.session.name == "core-sw1")
    assert not switch.combo.isEnabled()
    dialog.set_duplicate([switch], KEEP_BOTH)
    assert switch.combo.isEnabled()
    assert "1 to add" in dialog.summary_label.text() and "4 skipped" in dialog.summary_label.text()
    dialog.do_import()
    assert len(other.sessions) == 6


def test_import_shared_sessions_reports_a_bad_file(parent, tmp_path, other, monkeypatch):
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    shown = []
    monkeypatch.setattr(QMessageBox, "warning", lambda *args: shown.append(args[2]))
    assert session_share_dialogs.import_shared_sessions(parent, other, str(path)) is None
    assert "isn't a NOMAD shared sessions file" in shown[0]

