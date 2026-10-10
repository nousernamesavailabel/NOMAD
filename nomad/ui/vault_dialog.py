"""Master password dialogs: unlocking saved passwords, setting or changing the master password, and managing it."""
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QApplication, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, \
    QLineEdit, QMessageBox, QPushButton, QVBoxLayout

from ..terminal.vault import LOCK_CHOICES, MINIMUM_LENGTH, VaultError, VaultLocked, password_problem
from .common import set_hint
from .theme import COLORS


def password_field(placeholder=""):
    field = QLineEdit()
    field.setEchoMode(QLineEdit.Password)
    field.setPlaceholderText(placeholder)
    return field


def vault_sessions(store):
    """Folder views share one vault; password changes must include every namespace (and the saved credentials)."""
    return getattr(store, "credential_sessions", store.sessions)


def busy(function):
    """Run a slow step (deriving the key takes a moment) with the wait cursor showing."""
    QApplication.setOverrideCursor(QCursor(Qt.WaitCursor))
    try:
        return function()
    finally:
        QApplication.restoreOverrideCursor()


class UnlockDialog(QDialog):
    def __init__(self, parent, store, reason=""):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Master Password")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        message = QLabel((reason + "\n\n" if reason else "") +
                         "Enter NOMAD's master password to use your saved passwords.")
        message.setWordWrap(True)
        layout.addWidget(message)
        self.field = password_field()
        layout.addWidget(self.field)
        self.error = QLabel()
        layout.addWidget(self.error)
        buttons = QHBoxLayout()
        forgot = QPushButton("Forgot It?")
        forgot.setFlat(True)
        buttons.addWidget(forgot)
        buttons.addStretch()
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.button(QDialogButtonBox.Ok).setText("Unlock")
        buttons.addWidget(box)
        layout.addLayout(buttons)
        box.accepted.connect(self.try_unlock)
        box.rejected.connect(self.reject)
        forgot.clicked.connect(self.forgot)

    def try_unlock(self):
        if busy(lambda: self.store.vault.unlock(self.field.text())):
            self.accept()
        else:
            set_hint(self.error, "That isn't the master password.", "error")
            self.field.selectAll()
            self.field.setFocus()

    def forgot(self):
        if forget_everything(self, self.store):
            self.reject()


def forget_everything(parent, store):
    reply = QMessageBox.warning(
        parent, "Forget Saved Passwords",
        "A forgotten master password can't be recovered, so the passwords saved with it can't be read.\n\n"
        "Forget every saved password and key passphrase, and turn the master password off? Your sessions are kept; "
        "NOMAD will ask for passwords when you connect.", QMessageBox.Yes | QMessageBox.No)
    if reply != QMessageBox.Yes:
        return False
    count = store.vault.forget_everything(vault_sessions(store))
    store.save()
    QMessageBox.information(parent, "Forget Saved Passwords",
                            f"Forgot {count} saved password{'' if count == 1 else 's'}. The master password is off.")
    return True


def ensure_unlocked(parent, store, reason=""):
    """True if saved passwords can be used now (no master password, or it's been entered)."""
    vault = store.vault
    if not vault.enabled or vault.unlocked:
        return True
    return UnlockDialog(parent, store, reason).exec_() == QDialog.Accepted


def protect_secret(parent, store, secret):
    """Encrypt a secret for saving, asking for the master password if needed. None if the user cancels."""
    try:
        return store.vault.protect(secret)
    except VaultLocked:
        if not ensure_unlocked(parent, store, "The master password is needed to save this password."):
            return None
        return store.vault.protect(secret)


class NewPasswordDialog(QDialog):
    """Set the master password for the first time, or change it."""

    def __init__(self, parent, store):
        super().__init__(parent)
        self.store = store
        changing = store.vault.enabled
        self.setWindowTitle("Change Master Password" if changing else "Set Master Password")
        self.setMinimumWidth(460)
        layout = QVBoxLayout(self)
        intro = QLabel(
            "Saved passwords will need both your Windows account and this master password, so other programs "
            "running as you can't read them. NOMAD asks for it once, when a saved password is first needed.\n\n"
            "If you forget it, it can't be recovered: you'd have to enter the device passwords again (your sessions "
            "are kept).")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.current = password_field()
        if changing:
            form.addRow("Current master password:", self.current)
        self.new = password_field(f"At least {MINIMUM_LENGTH} characters; a passphrase is best")
        self.confirm = password_field()
        form.addRow("New master password:", self.new)
        form.addRow("Type it again:", self.confirm)
        layout.addLayout(form)
        self.error = QLabel()
        self.error.setWordWrap(True)
        layout.addWidget(self.error)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.button(QDialogButtonBox.Ok).setText("Change" if changing else "Set Master Password")
        box.accepted.connect(self.save)
        box.rejected.connect(self.reject)
        layout.addWidget(box)
        self.changing = changing

    def save(self):
        new = self.new.text()
        problem = password_problem(new)
        if problem:
            set_hint(self.error, problem, "error")
            return
        if new != self.confirm.text():
            set_hint(self.error, "The two new passwords don't match.", "error")
            return
        try:
            cleared = busy(lambda: self.store.vault.set_password(vault_sessions(self.store), new,
                                                                 self.current.text() if self.changing else None))
        except VaultError as error:
            set_hint(self.error, str(error), "error")
            return
        self.store.save()
        self.cleared = cleared
        self.accept()


class SecurityDialog(QDialog):
    """How saved passwords are protected, and the master password controls."""

    def __init__(self, parent, store):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Saved Password Protection")
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.details = QLabel()
        self.details.setWordWrap(True)
        self.details.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(self.details)

        lock_row = QHBoxLayout()
        self.lock_label = QLabel("Stay unlocked:")
        self.lock_combo = QComboBox()
        for seconds, label in LOCK_CHOICES:
            self.lock_combo.addItem(label, seconds)
        lock_row.addWidget(self.lock_label)
        lock_row.addWidget(self.lock_combo, 1)
        layout.addLayout(lock_row)

        buttons = QHBoxLayout()
        self.set_button = QPushButton()
        self.remove_button = QPushButton("Remove Master Password...")
        self.lock_button = QPushButton("Lock Now")
        self.forget_button = QPushButton("Forget All Saved Passwords...")
        for button in (self.set_button, self.remove_button, self.lock_button):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        forget_row = QHBoxLayout()
        forget_row.addWidget(self.forget_button)
        forget_row.addStretch()
        close = QPushButton("Close")
        forget_row.addWidget(close)
        layout.addLayout(forget_row)

        self.set_button.clicked.connect(self.set_password)
        self.remove_button.clicked.connect(self.remove_password)
        self.lock_button.clicked.connect(self.lock_now)
        self.forget_button.clicked.connect(self.forget)
        self.lock_combo.activated.connect(lambda _: self.store.vault.set_lock_after(self.lock_combo.currentData()))
        close.clicked.connect(self.accept)
        self.refresh()

    def saved_count(self):
        """Saved secrets, counting a shared credential's once (not again for each session using it)."""
        return sum(1 for session in vault_sessions(self.store) if not getattr(session, "credential_id", "")
                   for field in (session.saved_password, session.saved_passphrase) if field)

    def refresh(self):
        vault = self.store.vault
        count = self.saved_count()
        saved = f"{count} saved password{'' if count == 1 else 's'} or passphrase{'' if count == 1 else 's'}"
        if vault.enabled:
            state = "unlocked" if vault.unlocked else "locked"
            self.status.setText(f"<b>Protected by your Windows account and a master password</b> ({state}). {saved}.")
            self.details.setText("Each saved password is encrypted with AES-256 using a key made from your master "
                                 "password (scrypt), then encrypted again by Windows for your account (DPAPI). "
                                 "Reading one needs both.")
        else:
            self.status.setText(f"<b>Protected by your Windows account</b> (no master password). {saved}.")
            self.details.setText("Saved passwords are encrypted by Windows for your account (DPAPI): they can't be "
                                 "read on another computer or account, but programs running as you could read them. "
                                 "A master password adds a second lock that only you know.")
        self.set_button.setText("Change Master Password..." if vault.enabled else "Set Master Password...")
        self.remove_button.setVisible(vault.enabled)
        self.lock_button.setVisible(vault.enabled)
        self.lock_button.setEnabled(vault.enabled and vault.unlocked)
        for widget in (self.lock_label, self.lock_combo):
            widget.setVisible(vault.enabled)
        self.lock_combo.setCurrentIndex(max(0, self.lock_combo.findData(vault.lock_after)))
        self.forget_button.setEnabled(count > 0 or vault.enabled)

    def set_password(self):
        dialog = NewPasswordDialog(self, self.store)
        if dialog.exec_() == QDialog.Accepted:
            note = f"\n\n{dialog.cleared} saved password(s) couldn't be read and were cleared." if dialog.cleared \
                else ""
            QMessageBox.information(self, "Master Password", "The master password is set. Your saved passwords are "
                                    "now protected by it." + note)
        self.refresh()

    def remove_password(self):
        field = password_field()
        dialog = QDialog(self)
        dialog.setWindowTitle("Remove Master Password")
        layout = QVBoxLayout(dialog)
        message = QLabel("Saved passwords will be protected by your Windows account only. Enter the master password "
                         "to confirm.")
        message.setWordWrap(True)
        layout.addWidget(message)
        layout.addWidget(field)
        error = QLabel()
        layout.addWidget(error)
        box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        box.button(QDialogButtonBox.Ok).setText("Remove")
        layout.addWidget(box)

        def remove():
            try:
                busy(lambda: self.store.vault.remove_password(vault_sessions(self.store), field.text()))
            except VaultError as problem:
                set_hint(error, str(problem), "error")
                return
            self.store.save()
            dialog.accept()

        box.accepted.connect(remove)
        box.rejected.connect(dialog.reject)
        dialog.exec_()
        self.refresh()

    def lock_now(self):
        self.store.vault.lock()
        self.refresh()

    def forget(self):
        forget_everything(self, self.store)
        self.refresh()
