"""Sending configuration to Cisco IOS / IOS-XE devices over SSH with no one watching, for the pages that build it
(Port Mirroring, Carry VLAN): the "Log in with" row (a saved credential, or a user name and password asked for once;
the enable password; trusting new SSH keys) and the thread that sends each device its lines in turn
(configpush.Pusher). Devices with a saved SSH session log in with it."""
import logging
from dataclasses import dataclass, field

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGridLayout, QHBoxLayout, QLabel, \
    QLineEdit, QVBoxLayout, QWidget

from ..netmap import configpush, macssh
from ..terminal.hostkeys import KnownHosts
from ..terminal.sessions import AUTH_PASSWORD, SSH, Session
from .common import StoppableThread, set_hint
from .credential_dialogs import CredentialPicker
from .prompts import SecretDialog
from .vault_dialog import ensure_unlocked

log = logging.getLogger(__name__)

ASK_LOGIN = "A user name and password asked for"


@dataclass
class Job:
    """One device's lines to send, for PushThread."""
    index: int  # The plan's step, or the record's
    address: str
    names: list = field(default_factory=list)
    text: str = ""
    applet: str = ""


class PushThread(StoppableThread):
    """Sends each device its lines in turn: setting up stops at the first device that refuses; taking away carries
    on."""
    step_started = pyqtSignal(int)
    step_done = pyqtSignal(int, object)  # Job index, configpush.Outcome

    def __init__(self, jobs, make_pusher, setting_up, parent=None):
        super().__init__(parent)
        self.jobs, self.make_pusher, self.setting_up = jobs, make_pusher, setting_up
        self.failed = False

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for job in self.jobs:
                if self.stopping:
                    break
                self.step_started.emit(job.index)
                try:
                    if self.setting_up:
                        outcome = pusher.set_up(job.address, job.text, job.applet, job.names)
                    else:
                        outcome = pusher.take_away(job.address, job.text, job.names)
                except Exception as error:
                    log.exception("Sending to %s failed", job.address)
                    outcome = configpush.Outcome(problem=str(error))
                self.step_done.emit(job.index, outcome)
                if self.setting_up and not outcome.ok:
                    self.failed = True
                    break
        finally:
            pusher.close()


class LoginRow(QWidget):
    """How NOMAD logs in to devices without a saved SSH session, and their enable password. stacked lays it out as a
    form (for a narrow column) instead of one row."""
    changed = pyqtSignal()

    def __init__(self, parent, sessions, purpose, stacked=False):
        super().__init__(parent)
        self.sessions, self.purpose = sessions, purpose  # purpose: what logs in, for the vault's question
        self.ssh_user = ""  # Typed last, offered again
        if sessions is not None:
            default = sessions.credentials.default
            self.picker = CredentialPicker(self, sessions, SSH, default.id if default else "", ASK_LOGIN)
            self.picker.combo.setToolTip("For devices without a saved SSH session: a saved credential "
                                         "(Manage... to add one), or a user name and password asked for once.")
            self.picker.combo.currentIndexChanged.connect(self.on_changed)
        else:
            self.picker = None
        self.enable_input = QLineEdit()
        self.enable_input.setEchoMode(QLineEdit.Password)
        self.enable_input.setPlaceholderText("If they log in at >")
        self.enable_input.setToolTip("For devices that log in at the > prompt. Kept only while NOMAD is open.")
        self.enable_input.textChanged.connect(self.on_changed)
        self.trust_check = QCheckBox("Trust new SSH keys")
        self.trust_check.setChecked(True)
        self.trust_check.toggled.connect(self.on_changed)
        if stacked:
            layout = QGridLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(QLabel("Log in with:"), 0, 0)
            if self.picker is not None:
                layout.addWidget(self.picker, 0, 1)
            layout.addWidget(QLabel("Enable password:"), 1, 0)
            layout.addWidget(self.enable_input, 1, 1)
            layout.addWidget(self.trust_check, 2, 0, 1, 2)
            layout.setColumnStretch(1, 1)
        else:
            layout = QHBoxLayout(self)
            layout.setContentsMargins(0, 0, 0, 0)
            layout.addWidget(QLabel("Log in with:"))
            if self.picker is not None:
                layout.addWidget(self.picker, 2)
            layout.addWidget(QLabel("Enable password:"))
            layout.addWidget(self.enable_input, 1)
            layout.addWidget(self.trust_check)

    def on_changed(self, *_):
        self.changed.emit()

    def logins(self, status_label=None):
        """(macssh.SshLogins, enable secret) for the devices, asking what's needed now; None if cancelled."""
        store = self.sessions
        if store is None:
            if status_label is not None:
                set_hint(status_label, "Saved sessions aren't available, so NOMAD can't log in to the devices.",
                         "error")
            return None
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions if session.protocol == SSH]
        credential = self.picker.credential() if self.picker is not None else None
        password = None
        if credential is None:
            asked = self.ask_login()
            if asked is None:
                return None
            username, password = asked
            fallback, label = Session("", username=username), f"user {username} (typed)"
        else:
            fallback = store.credentials.apply(Session("", credential_id=credential.id))
            label = f"credential {credential.name}"
            if credential.auth == AUTH_PASSWORD and not credential.saved_password:
                dialog = SecretDialog(self, "Password", f"Password for {credential.username} (the credential "
                                                       f"{credential.name}):", False)
                if dialog.exec_() != QDialog.Accepted:
                    return None
                password = dialog.field.text()
        secrets = any(item.saved_password or item.saved_passphrase for item in sessions + [fallback])
        if secrets and not ensure_unlocked(self, store, f"{self.purpose} logs in to devices with saved passwords."):
            return None
        return macssh.SshLogins(sessions, fallback, password, label), self.enable_input.text()

    def ask_login(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Log In to Devices")
        layout = QVBoxLayout(dialog)
        label = QLabel("For devices without a saved SSH session (kept only while NOMAD is open):")
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        username = QLineEdit(self.ssh_user)
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        form.addRow("User name:", username)
        form.addRow("Password:", password)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        (password if self.ssh_user else username).setFocus()
        if dialog.exec_() != QDialog.Accepted or not username.text().strip():
            return None
        self.ssh_user = username.text().strip()
        return self.ssh_user, password.text()

    def quiet_logins(self):
        """Logins that need nothing typed (for a timer with no one there), or None."""
        store = self.sessions
        if store is None or (store.vault.enabled and not store.vault.unlocked):
            return None
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions if session.protocol == SSH]
        credential = self.picker.credential() if self.picker is not None else None
        fallback = store.credentials.apply(Session("", credential_id=credential.id)) if credential is not None and \
            credential.saved_password else None
        return macssh.SshLogins(sessions, fallback, None, "saved"), self.enable_input.text()

    def pusher_maker(self, logins, shell_factory=configpush.ConfigShell):
        """make(should_stop) -> a configpush.Pusher logging in with logins, for PushThread (and the like)."""
        login, secret = logins
        vault = self.sessions.vault if self.sessions is not None else None
        trust = self.trust_check.isChecked()

        def make(should_stop):
            return configpush.Pusher(login, vault, KnownHosts(), trust, secret, should_stop,
                                     shell_factory=shell_factory)
        return make

    def save_settings(self, settings, prefix):
        settings.setValue(f"{prefix}/trust", self.trust_check.isChecked())
        settings.setValue(f"{prefix}/user", self.ssh_user)
        if self.picker is not None:
            settings.setValue(f"{prefix}/login", self.picker.credential_id())

    def restore_settings(self, settings, prefix):
        self.trust_check.setChecked(settings.value(f"{prefix}/trust", True, bool))
        self.ssh_user = settings.value(f"{prefix}/user", "", str)
        if self.picker is not None and settings.contains(f"{prefix}/login"):
            self.picker.fill(settings.value(f"{prefix}/login", "", str))
