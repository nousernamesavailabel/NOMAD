"""The "Log in with" row's logins: pages keep them until NOMAD closes, so they look up the saved sessions at each
login."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nomad.terminal.sessions import Credential, Session, SessionStore  # noqa: E402
from nomad.ui.ssh_push import SavedLogins  # noqa: E402


def test_a_password_saved_after_the_logins_were_made_is_used(tmp_path):
    store = SessionStore(str(tmp_path / "sessions.json"))
    router = Session("R5", host="10.0.0.5", username="admin")
    store.put(router)
    logins = SavedLogins(store)  # Read clicked before the password was saved
    session, label = logins.login_for("10.0.0.5", ["R5"])
    assert label == "saved session R5" and not session.saved_password

    store.put(router.copy(id=router.id, saved_password=store.vault.protect("pw")))
    session, _ = logins.login_for("10.0.0.5", ["R5"])
    assert store.vault.reveal(session.saved_password) == "pw" and session.host == "10.0.0.5"


def test_sessions_added_later_and_the_credential_changed_later_are_used(tmp_path):
    store = SessionStore(str(tmp_path / "sessions.json"))
    credential = Credential("TACACS", username="jsmith")
    store.credentials.put(credential)
    logins = SavedLogins(store, store.credentials.apply(Session("", credential_id=credential.id)), None,
                         "credential TACACS")
    session, label = logins.login_for("10.0.0.6")
    assert label == "credential TACACS" and not session.saved_password

    store.credentials.put(Credential("TACACS", username="jsmith", saved_password=store.vault.protect("pw2"),
                                     id=credential.id))
    session, _ = logins.login_for("10.0.0.6")
    assert store.vault.reveal(session.saved_password) == "pw2"

    store.put(Session("R6", host="10.0.0.6", username="admin"))
    assert logins.login_for("10.0.0.6")[1] == "saved session R6"
