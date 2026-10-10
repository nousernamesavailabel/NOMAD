"""Answering an SSH connection's questions (host keys, passwords, the master password) from its background thread.
Shared by terminal sessions and the SCP page."""
import threading

from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QInputDialog, QLabel, QLineEdit, QMessageBox, \
    QVBoxLayout

from ..terminal.transports import Prompter
from .credential_dialogs import login_with
from .vault_dialog import ensure_unlocked, protect_secret


class _Request:
    def __init__(self, kind, arguments):
        self.kind, self.arguments = kind, arguments
        self.result = None
        self.done = threading.Event()


class SecretDialog(QDialog):
    def __init__(self, parent, title, prompt, can_save, save_text="Save it (encrypted for your Windows account)"):
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        label = QLabel(prompt)
        label.setWordWrap(True)
        layout.addWidget(label)
        self.field = QLineEdit()
        self.field.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.field)
        self.save_check = QCheckBox(save_text)
        self.save_check.setVisible(can_save)
        layout.addWidget(self.save_check)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setMinimumWidth(380)


class UiPrompter(Prompter):
    """Answers a connection's questions with dialogs. Called on the connection's thread; waits for the UI thread.
    The view has a `question` signal (connected, queued, to its answer method; see PromptAnswers)."""

    def __init__(self, view):
        self.view = view
        self.pending = []
        self.cancelled = False  # The connection was closed: every question, now or later, goes unanswered

    def ask(self, kind, *arguments):
        request = _Request(kind, arguments)
        self.pending.append(request)
        try:
            if self.cancelled:
                return None
            try:
                self.view.question.emit(request)
            except RuntimeError:  # The view has been deleted (its tab closed)
                return None
            request.done.wait()
            return request.result
        finally:
            self.pending.remove(request)

    def cancel_all(self):
        self.cancelled = True
        for request in list(self.pending):
            request.result = None
            request.done.set()

    def host_key(self, host, port, key_type, fingerprint, changed, old_fingerprint):
        return self.ask("host_key", host, port, key_type, fingerprint, changed, old_fingerprint) or "cancel"

    def secret(self, title, prompt, can_save):
        return self.ask("secret", title, prompt, can_save)

    def text(self, title, prompt):
        return self.ask("text", title, prompt)

    def username(self, host):
        return self.ask("username", host)

    def unlock_vault(self):
        return bool(self.ask("unlock"))

    def save_secret(self, kind, value):
        self.ask("save", kind, value)


class PromptAnswers:
    """Mixin for a widget with `session`, `store` (or None) and a `report(message, warning)` method: shows the
    dialogs a UiPrompter asks for, and saves passwords the user asked to keep."""

    def answer(self, request):
        try:
            request.result = self.ask_user(request.kind, *request.arguments)
        finally:
            request.done.set()

    def ask_user(self, kind, *arguments):
        if kind == "host_key":
            return self.ask_host_key(*arguments)
        if kind == "secret":
            title, prompt, can_save = arguments
            saved_session = self.store is not None and self.store.get(self.session.id) is not None
            credential = self.store.credentials.get(self.session.credential_id) if self.store is not None else None
            if saved_session or credential is None:
                dialog = SecretDialog(self, title, prompt, can_save and saved_session)
            else:  # A connection logging in with a credential, not saved: the credential can keep it
                dialog = SecretDialog(self, title, prompt, can_save, f"Save it in the credential {credential.name}")
            if dialog.exec_() != QDialog.Accepted:
                return None
            return dialog.field.text(), dialog.save_check.isChecked()
        if kind == "text":
            title, prompt = arguments
            value, ok = QInputDialog.getText(self, title, prompt)
            return value if ok else None
        if kind == "username":
            return self.ask_username(*arguments)
        if kind == "unlock":
            if self.store is None:
                return False
            return ensure_unlocked(self, self.store, f"{self.session.name} has a saved password protected by the "
                                                     "master password.")
        if kind == "save":
            secret_kind, value = arguments
            self.save_secret(secret_kind, value)
            return None
        return None

    def ask_username(self, host):
        """No user name yet: for a connection with no saved session, a saved credential can be picked instead."""
        store = self.store
        if store is not None and store.get(self.session.id) is None and store.credentials.sorted(self.session.protocol):
            if not login_with(self, store, self.session):
                return None
            store.remember(self.session)  # Recent opens it the same way next time
            return self.session.username
        value, ok = QInputDialog.getText(self, "User Name", f"User name for {host}:")
        return value if ok else None

    def ask_host_key(self, host, port, key_type, fingerprint, changed, old_fingerprint):
        where = host if int(port) == 22 else f"{host} port {port}"
        box = QMessageBox(self)
        if changed:
            box.setIcon(QMessageBox.Warning)
            box.setWindowTitle("Host Key Changed")
            box.setText(f"<b>The SSH key of {where} has changed.</b>")
            box.setInformativeText(
                "That's expected if the device was replaced, reset or given a new key. Otherwise someone may be "
                "intercepting the connection (a man-in-the-middle attack).\n\n"
                f"Key it had before: {old_fingerprint}\nKey it has now: {fingerprint} ({key_type})")
            trust = box.addButton("Trust the New Key", QMessageBox.AcceptRole)
        else:
            box.setIcon(QMessageBox.Question)
            box.setWindowTitle("New Host Key")
            box.setText(f"NOMAD hasn't connected to {where} before.")
            box.setInformativeText(
                f"Its SSH key fingerprint is:\n{fingerprint} ({key_type})\n\nTo be sure it's the right device, compare "
                "this with the device's own fingerprint (for example \"show ip ssh\" or \"show crypto key "
                "mypubkey rsa\" on Cisco).")
            trust = box.addButton("Trust and Connect", QMessageBox.AcceptRole)
        once = box.addButton("Connect Once", QMessageBox.ActionRole)
        cancel = box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(cancel if changed else trust)
        box.exec_()
        clicked = box.clickedButton()
        return "trust" if clicked is trust else "once" if clicked is once else "cancel"

    def save_secret(self, kind, value):
        if self.store is None:
            return
        stored = self.store.get(self.session.id)
        credential = self.store.credentials.get((stored or self.session).credential_id)
        if stored is None and credential is None:
            return
        try:
            encrypted = protect_secret(self, self.store, value)
        except Exception as error:  # Saving is a convenience; the connection itself worked
            self.report(f"Couldn't save the {kind}: {error}", True)
            return
        if encrypted is None:
            self.report(f"The {kind} wasn't saved (the master password wasn't entered).", True)
            return
        if credential is not None:  # Shared: save it there, so every session using it gets the new one
            if kind == "password":
                credential.saved_password = encrypted
            else:
                credential.saved_passphrase = encrypted
            self.store.credentials.put(credential)
            source = stored if stored is not None else self.store.credentials.apply(self.session)
            self.session.saved_password, self.session.saved_passphrase = (source.saved_password,
                                                                          source.saved_passphrase)
            self.report(f"Saved the {kind} in the credential {credential.name}, for every session using it.", False)
            return
        if kind == "password":
            stored.saved_password = self.session.saved_password = encrypted
        else:
            stored.saved_passphrase = self.session.saved_passphrase = encrypted
        self.store.put(stored)
        how = "your master password and Windows account" if self.store.vault.enabled else "your Windows account"
        self.report(f"Saved the {kind} (encrypted with {how}).", False)
