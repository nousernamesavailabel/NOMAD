"""Saved credentials: named logins (such as the TACACS account used on every switch) that SSH and RDP sessions share,
so a new session doesn't need its user name and password typed again."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, \
    QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QTableWidgetItem, QVBoxLayout, QWidget

from ..terminal.credentials import CredentialError, protect
from ..terminal.sessions import AUTH_AGENT, AUTH_KEY, AUTH_PASSWORD, RDP, Credential, validate_credential
from .common import read_only_table, set_hint
from .vault_dialog import protect_secret

AUTH_CHOICES = [(AUTH_PASSWORD, "Password"), (AUTH_KEY, "Private key file"), (AUTH_AGENT, "Pageant or SSH agent")]
SAVED_PLACEHOLDER = "Saved (encrypted). Type to replace it."
OWN_LOGIN = "Typed for this session"


def secret_to_store(parent, store, field, save_check, existing):
    """The encrypted value to keep: a newly typed secret, the one already saved, or none. Raises CredentialError
    when the master password is needed but wasn't entered."""
    if not save_check.isChecked():
        return ""
    typed = field.text()
    if not typed:
        return existing
    encrypted = protect_secret(parent, store, typed) if store is not None else protect(typed)
    if encrypted is None:
        raise CredentialError("The master password is needed to save passwords. Enter it, or untick Save.")
    return encrypted


def sessions_text(count):
    return f"{count} session{'' if count == 1 else 's'}"


class CredentialDialog(QDialog):
    """Add or change one credential."""

    def __init__(self, parent, store, credential=None, title="Credential"):
        super().__init__(parent)
        self.store = store
        book = store.credentials
        self.credential = credential or Credential(name="")
        existing = book.get(self.credential.id) is not None
        self.setWindowTitle(title)
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_input = QLineEdit(self.credential.name)
        self.name_input.setPlaceholderText("Such as TACACS, Domain Admin or Lab")
        self.username_input = QLineEdit(self.credential.username)
        self.username_input.setPlaceholderText(r"jsmith, or DOMAIN\jsmith for Remote Desktop")
        self.auth_combo = QComboBox()
        for value, label in AUTH_CHOICES:
            self.auth_combo.addItem(label, value)
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(self.credential.auth)))
        self.auth_combo.setToolTip("Remote Desktop sessions can only use password credentials.")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText(SAVED_PLACEHOLDER if self.credential.saved_password else
                                               "Leave blank to be asked when connecting")
        self.save_password_check = QCheckBox("Save (encrypted)")
        self.save_password_check.setChecked(bool(self.credential.saved_password) or not existing)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_input, 1)
        password_row.addWidget(self.save_password_check)
        self.key_input = QLineEdit(self.credential.key_file)
        self.key_input.setPlaceholderText("OpenSSH private key, such as C:\\Users\\you\\.ssh\\id_ed25519")
        key_browse = QPushButton("Browse...")
        key_row = QHBoxLayout()
        key_row.addWidget(self.key_input, 1)
        key_row.addWidget(key_browse)
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.passphrase_input.setPlaceholderText(SAVED_PLACEHOLDER if self.credential.saved_passphrase else
                                                 "Only if the key is protected; asked when needed")
        self.save_passphrase_check = QCheckBox("Save (encrypted)")
        self.save_passphrase_check.setChecked(bool(self.credential.saved_passphrase))
        passphrase_row = QHBoxLayout()
        passphrase_row.addWidget(self.passphrase_input, 1)
        passphrase_row.addWidget(self.save_passphrase_check)
        self.default_check = QCheckBox("Use for new SSH and Remote Desktop sessions")
        self.default_check.setChecked(book.default_id == self.credential.id if existing else not book.items)
        self.notes_input = QLineEdit(self.credential.notes)
        self.notes_input.setPlaceholderText("Optional, such as which devices it works on")
        self.password_label, self.key_label, self.passphrase_label = (QLabel("Password:"), QLabel("Key file:"),
                                                                      QLabel("Passphrase:"))
        form.addRow("Name:", self.name_input)
        form.addRow("User name:", self.username_input)
        form.addRow("Log in with:", self.auth_combo)
        form.addRow(self.password_label, password_row)
        form.addRow(self.key_label, key_row)
        form.addRow(self.passphrase_label, passphrase_row)
        form.addRow("Notes:", self.notes_input)
        form.addRow("", self.default_check)
        layout.addLayout(form)
        users = book.users(self.credential.id) if existing else []
        if users:
            used = QLabel(f"Used by {sessions_text(len(users))}: changes here apply to all of them.")
            used.setWordWrap(True)
            layout.addWidget(used)
        self.password_widgets = [self.password_label, self.password_input, self.save_password_check]
        self.key_widgets = [self.key_label, self.key_input, key_browse, self.passphrase_label, self.passphrase_input,
                            self.save_passphrase_check]
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.auth_combo.currentIndexChanged.connect(self.update_auth_fields)
        key_browse.clicked.connect(self.browse_key)
        self.update_auth_fields()

    def update_auth_fields(self):
        auth = self.auth_combo.currentData()
        for widget in self.password_widgets:
            widget.setVisible(auth == AUTH_PASSWORD)
        for widget in self.key_widgets:
            widget.setVisible(auth == AUTH_KEY)

    def browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Private Key", self.key_input.text() or "", "All files (*)")
        if path:
            self.key_input.setText(path.replace("/", "\\"))

    def save(self):
        credential = Credential(name=self.name_input.text().strip(), username=self.username_input.text().strip(),
                                auth=self.auth_combo.currentData(), key_file=self.key_input.text().strip(),
                                notes=self.notes_input.text().strip(), id=self.credential.id)
        error = validate_credential(credential, self.store.credentials)
        if error:
            set_hint(self.error_label, error, "error")
            return
        try:
            if credential.auth == AUTH_PASSWORD:
                credential.saved_password = secret_to_store(self, self.store, self.password_input,
                                                            self.save_password_check, self.credential.saved_password)
            elif credential.auth == AUTH_KEY:
                credential.saved_passphrase = secret_to_store(self, self.store, self.passphrase_input,
                                                              self.save_passphrase_check,
                                                              self.credential.saved_passphrase)
        except CredentialError as error:
            QMessageBox.critical(self, "Save Password", str(error))
            return
        self.store.credentials.put(credential, default=self.default_check.isChecked())
        self.credential = credential
        self.accept()


class CredentialsDialog(QDialog):
    """Every saved credential: add, change, delete, and choose the one new sessions start with."""

    def __init__(self, parent, store, select=""):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Saved Credentials")
        self.setMinimumSize(620, 340)
        layout = QVBoxLayout(self)
        intro = QLabel("Save a user name and password once, then choose it in any SSH or Remote Desktop session "
                       "instead of typing them again. Changing a credential (such as after a password change) "
                       "updates every session that uses it.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = read_only_table(["Name", "User name", "Logs in with", "Used by", "New sessions"])
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.new_button = QPushButton("New...")
        self.edit_button = QPushButton("Edit...")
        self.default_button = QPushButton("Use for New Sessions")
        self.default_button.setToolTip("New SSH and Remote Desktop sessions start with this credential filled in.")
        self.delete_button = QPushButton("Delete")
        for button in (self.new_button, self.edit_button, self.default_button, self.delete_button):
            row.addWidget(button)
        row.addStretch(1)
        close = QPushButton("Close")
        row.addWidget(close)
        layout.addLayout(row)
        self.new_button.clicked.connect(self.new_credential)
        self.edit_button.clicked.connect(self.edit_selected)
        self.default_button.clicked.connect(self.toggle_default)
        self.delete_button.clicked.connect(self.delete_selected)
        self.table.itemDoubleClicked.connect(self.edit_selected)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        close.clicked.connect(self.accept)
        self.fill(select)

    def fill(self, select=""):
        book = self.store.credentials
        self.table.setRowCount(0)
        for credential in book.sorted():
            row = self.table.rowCount()
            self.table.insertRow(row)
            how = {AUTH_KEY: "Key file", AUTH_AGENT: "SSH agent"}.get(
                credential.auth, "Saved password" if credential.saved_password else "Password asked")
            values = [credential.name, credential.username, how, sessions_text(len(book.users(credential.id))),
                      "Default" if credential.id == book.default_id else ""]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.UserRole, credential.id)
                if column == 0 and credential.notes:
                    item.setToolTip(credential.notes)
                self.table.setItem(row, column, item)
            if credential.id == select:
                self.table.selectRow(row)
        if not self.table.selectedItems() and self.table.rowCount():
            self.table.selectRow(0)
        self.update_buttons()

    def selected(self):
        items = self.table.selectedItems()
        return self.store.credentials.get(items[0].data(Qt.UserRole)) if items else None

    def update_buttons(self):
        credential = self.selected()
        for button in (self.edit_button, self.default_button, self.delete_button):
            button.setEnabled(credential is not None)
        is_default = credential is not None and credential.id == self.store.credentials.default_id
        self.default_button.setText("Stop Using for New Sessions" if is_default else "Use for New Sessions")

    def new_credential(self):
        dialog = CredentialDialog(self, self.store, title="New Credential")
        if dialog.exec_():
            self.fill(dialog.credential.id)

    def edit_selected(self, *_):
        credential = self.selected()
        if credential is None:
            return
        dialog = CredentialDialog(self, self.store, credential, "Edit Credential")
        if dialog.exec_():
            self.fill(dialog.credential.id)

    def toggle_default(self):
        credential = self.selected()
        if credential is None:
            return
        book = self.store.credentials
        book.put(credential, default=credential.id != book.default_id)
        self.fill(credential.id)

    def delete_selected(self):
        credential = self.selected()
        if credential is None:
            return
        users = self.store.credentials.users(credential.id)
        text = f"Delete the credential {credential.name}?"
        if users:
            text += (f"\n\nThe {sessions_text(len(users))} using it keep its user name and saved password as their "
                     "own, so they still connect.")
        if QMessageBox.question(self, "Delete Credential", text, QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.store.credentials.delete(credential.id)
            self.fill()


class CredentialPicker(QWidget):
    """The "Credential:" row of a session editor: typed for this session, or a saved credential, plus Manage."""

    def __init__(self, parent, store, protocol, credential_id="", own_text=OWN_LOGIN):
        super().__init__(parent)
        self.store, self.protocol, self.own_text = store, protocol, own_text
        row = QHBoxLayout(self)
        row.setContentsMargins(0, 0, 0, 0)
        self.combo = QComboBox()
        self.combo.setToolTip("Log in with a saved credential (Manage... to add one), or type the user name and "
                              "password below for this session only.")
        self.manage_button = QPushButton("Manage...")
        row.addWidget(self.combo, 1)
        row.addWidget(self.manage_button)
        self.manage_button.clicked.connect(self.manage)
        self.fill(credential_id)

    def fill(self, select=""):
        self.combo.blockSignals(True)
        self.combo.clear()
        self.combo.addItem(self.own_text, "")
        for credential in self.store.credentials.sorted(self.protocol):
            self.combo.addItem(f"{credential.name}  ({credential.summary()})", credential.id)
        self.combo.setCurrentIndex(max(0, self.combo.findData(select)))
        self.combo.blockSignals(False)

    def set_protocol(self, protocol):
        self.protocol = protocol
        self.fill(self.credential_id())

    def credential_id(self):
        return self.combo.currentData() or ""

    def credential(self):
        return self.store.credentials.get(self.credential_id())

    def manage(self):
        before = self.credential_id()
        CredentialsDialog(self.window(), self.store, before).exec_()
        self.fill(before)
        self.combo.currentIndexChanged.emit(self.combo.currentIndex())  # Its details may have changed


class LoginDialog(QDialog):
    """How to log in to a host with no saved session (a quick connection, or one from another page): with a saved
    credential, starting on the default one, or as a user name typed here."""

    def __init__(self, parent, store, protocol, host):
        super().__init__(parent)
        self.store, self.protocol = store, protocol
        self.setWindowTitle("Log In")
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Log in to {host} with:"))
        form = QFormLayout()
        default = store.credentials.default
        usable = {credential.id for credential in store.credentials.sorted(protocol)}
        self.picker = CredentialPicker(self, store, protocol, default.id if default and default.id in usable else "",
                                       "A user name typed here")
        form.addRow("Credential:", self.picker)
        self.username_input = QLineEdit()
        if protocol == RDP:
            self.username_input.setPlaceholderText("Blank: Windows asks")
        form.addRow("User name:", self.username_input)
        layout.addLayout(form)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Log In")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.typed = ""
        self.picker.combo.currentIndexChanged.connect(self.update_fields)
        self.username_input.textEdited.connect(self.remember_typed)
        self.username_input.textChanged.connect(self.update_button)
        self.update_fields()
        self.setMinimumWidth(420)

    def credential(self):
        return self.picker.credential()

    def username(self):
        return self.username_input.text().strip()

    def remember_typed(self, text):
        self.typed = text

    def update_fields(self):
        """A credential shows its user name (fixed); typing one brings back what was typed."""
        credential = self.credential()
        self.username_input.setEnabled(credential is None)
        self.username_input.setText(credential.username if credential is not None else self.typed)
        self.update_button()
        if credential is None:
            self.username_input.setFocus()
        else:
            self.picker.combo.setFocus()

    def update_button(self):
        """SSH needs a user name; RDP can leave it to Windows to ask."""
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(self.protocol == RDP or self.credential() is not None
                                                            or bool(self.username()))

    def accept(self):
        if self.credential() is None and self.protocol != RDP and not self.username():
            return
        super().accept()


def login_with(parent, store, session):
    """For a connection with no saved session and no user name: when there are saved credentials it could use, ask
    which to log in with (or a user name typed instead) and fill it in. Returns False if cancelled, True otherwise
    (also when there was nothing to ask)."""
    if store is None or store.get(session.id) is not None or session.username or session.credential_id \
            or not store.credentials.sorted(session.protocol):
        return True
    dialog = LoginDialog(parent, store, session.protocol, session.host)
    if dialog.exec_() != QDialog.Accepted:
        return False
    credential = dialog.credential()
    if credential is None:
        session.username = dialog.username()
    else:
        session.credential_id = credential.id
        store.credentials.apply(session)
    return True


def default_credential_id(store, session):
    """The credential a new session should start with: the default one, for a new SSH or RDP session that has no user
    name of its own yet."""
    if store is None or store.get(session.id) is not None or session.username or session.credential_id:
        return session.credential_id
    default = store.credentials.default
    if default is None or (session.protocol == RDP and default.auth != AUTH_PASSWORD):
        return ""
    return default.id
