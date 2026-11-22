"""Backups' logins (configs/logins.py): the file that keeps them, and what the Map Watcher service is given: the usual
login, each device's own login and the login of each device's saved SSH session."""
import json

from nomad.configs import logins
from nomad.terminal.sessions import AUTH_KEY, Credential, Session, SessionStore


def test_the_file_keeps_the_usual_login_and_enable_beside_the_devices(tmp_path):
    path = str(tmp_path / "backup_logins.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"10.0.0.1": "c1"}, handle)  # The first version: only the devices
    assert logins.read(path) == {"devices": {"10.0.0.1": "c1"}, "usual": None, "enable": ""}
    logins.save_usual("c2", path)
    logins.save_enable("<en>", path)
    logins.save({"10.0.0.5": "c3"}, path)  # Saving the devices keeps the rest
    assert logins.read(path) == {"devices": {"10.0.0.5": "c3"}, "usual": "c2", "enable": "<en>"}
    assert logins.load(path) == {"10.0.0.5": "c3"}
    logins.save_usual("", path)  # A user name and password asked for
    assert logins.read(path)["usual"] == ""


def store_with(tmp_path):
    store = SessionStore(str(tmp_path / "sessions.json"))
    lab = Credential("Lab Admin", username="admin", saved_password="<lab>")
    usual = Credential("NetOps", username="netops", saved_password="<ops>")
    branch = Credential("Branch", username="branch", saved_password="<br>")
    asked = Credential("Asked", username="asked")  # No saved password
    store.credentials.items = [lab, usual, branch, asked]
    store.sessions = [
        Session("R2.home.lab", host="10.18.0.12", credential_id=lab.id),
        Session("SW1", host="sw1.corp", username="local", saved_password="<sw>"),
        Session("SW2", host="10.0.0.9", username="nobody"),  # No saved password: not copied
        Session("SW3", host="10.0.0.10", username="k", auth=AUTH_KEY, key_file="k.pem"),  # A key: not copied
        Session("PiHole", host="10.0.4.5", username="pi", saved_password="<pi>"),  # Not in the archive
    ]
    for session in store.sessions:
        store.credentials.apply(session)
    return store, lab, usual, branch, asked


DEVICES = [{"id": "10.100.2.1", "address": "10.100.2.1", "names": ["R2.home.lab", "10.18.0.12"]},
           {"id": "10.0.0.7", "address": "10.0.0.7", "names": ["sw1"]},
           {"id": "10.0.0.9", "address": "10.0.0.9", "names": []},
           {"id": "10.0.0.10", "address": "10.0.0.10", "names": []},
           {"id": "10.0.0.11", "address": "10.0.0.11", "names": []}]


def test_the_service_gets_the_saved_sessions_logins(tmp_path):
    store, lab, usual, branch, asked = store_with(tmp_path)
    chosen = {"10.0.0.11": branch.id, "10.0.0.9": asked.id, "elsewhere": branch.id}
    plan = logins.service_plan(store, usual.id, chosen, DEVICES)
    usual_login, mapped, found = plan
    assert usual_login == ("netops", "<ops>", "credential NetOps")
    sw1 = next(session for session in store.sessions if session.name == "SW1")
    assert mapped == {"10.100.2.1": lab.id,  # Its session's credential, by an address it has
                      "10.0.0.7": f"session:{sw1.id}",  # By its name without the domain
                      "10.0.0.11": branch.id, "elsewhere": branch.id}  # Their own logins
    # SW2's session has no saved password and its own login can't be used; SW3 logs in with a key: the usual login
    assert found == {lab.id: ("admin", "<lab>", "credential Lab Admin"),
                     f"session:{sw1.id}": ("local", "<sw>", "saved session SW1"),
                     branch.id: ("branch", "<br>", "credential Branch")}
    backups = logins.service_backups(plan, lambda text: text.strip("<>"), "en", True, "sig")
    assert backups["username"] == "netops" and backups["password"] == "ops" and backups["enable"] == "en"
    assert backups["logins"][lab.id] == {"username": "admin", "password": "lab", "label": "credential Lab Admin"}
    assert backups["devices"] == mapped and backups["signature"] == "sig"
    # A device's own login comes before its saved session
    plan = logins.service_plan(store, usual.id, {"10.100.2.1": branch.id}, DEVICES)
    assert plan[1]["10.100.2.1"] == branch.id


def test_the_signature_changes_only_with_what_the_service_logs_in_with(tmp_path):
    store, lab, usual, *_ = store_with(tmp_path)
    first = logins.signature(logins.service_plan(store, usual.id, {}, DEVICES), "<en>")
    assert logins.signature(logins.service_plan(store, usual.id, {}, DEVICES), "<en>") == first
    assert logins.signature(logins.service_plan(store, usual.id, {}, DEVICES), "<other>") != first
    assert logins.signature(logins.service_plan(store, usual.id, {}, DEVICES), "<en>", trust_new=False) != first
    lab.saved_password = "<new>"  # A password changed
    store.credentials.apply(store.sessions[0])
    assert logins.signature(logins.service_plan(store, usual.id, {}, DEVICES), "<en>") != first
    # No usual login (a user name and password asked for): only the devices' own and sessions' logins
    usual_login, mapped, _ = logins.service_plan(store, "", {}, DEVICES)
    assert usual_login is None and "10.100.2.1" in mapped
    backups = logins.service_backups(logins.service_plan(store, "", {}, DEVICES), lambda text: text)
    assert backups["username"] == "" and backups["password"] == ""
