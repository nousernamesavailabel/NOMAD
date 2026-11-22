"""Device Logins: the saved credential scheduled backups log in to each device with, for the devices that need a
different login from their saved SSH session's or the usual one (configs/logins.py). Opened from the Editor's Backups
tab; the Map Watcher service on this computer is given the same."""
from PyQt5.QtCore import QItemSelectionModel, Qt
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, \
    QLineEdit, QPushButton, QTableWidgetItem, QVBoxLayout

from ..configs import logins
from ..terminal.sessions import AUTH_PASSWORD, SSH
from .common import read_only_table

USUAL = "The usual login"


def usable(credential):
    """Whether backups can log in with it with nobody there: a user name and a saved password."""
    return credential.auth == AUTH_PASSWORD and bool(credential.saved_password) and bool(credential.username)


class DeviceLoginsDialog(QDialog):
    def __init__(self, parent, store, devices, chosen, select=None):
        """devices: the archive's ({"id", "name", "address", "failures"}). chosen: {device id: credential id}.
        select: device ids to select at first (from the Archive's right-click)."""
        super().__init__(parent)
        self.setWindowTitle("Device Logins")
        self.setMinimumSize(640, 460)
        self.store = store
        self.choices = dict(chosen)
        self.devices = list(devices)
        self.sessions = logins.ssh_sessions(store)
        layout = QVBoxLayout(self)
        intro = QLabel("Devices with a saved SSH session log in with it, and the rest with the usual login. Choose "
                       "a login here for the devices that need another one. Scheduled backups and Pull Config use "
                       "it, in NOMAD and the Map Watcher service. Only saved credentials with a saved password can "
                       "be chosen, because nobody is there to type one.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by name or address")
        self.filter.setClearButtonEnabled(True)
        self.filter.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter)
        self.table = read_only_table(["Device", "Address", "Logs in with", "Last problem"])
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        row.addWidget(QLabel("For the selected devices:"))
        self.combo = QComboBox()
        self.combo.addItem(USUAL, "")
        for credential in store.credentials.sorted(SSH):
            if usable(credential):
                self.combo.addItem(f"{credential.name}  ({credential.username})", credential.id)
        row.addWidget(self.combo, 1)
        self.use_button = QPushButton("Use for Selected")
        self.use_button.clicked.connect(self.use_for_selected)
        row.addWidget(self.use_button)
        layout.addLayout(row)
        if self.combo.count() == 1:
            note = QLabel("There are no saved credentials with a saved password yet. Add one in the Terminal's "
                          "Credentials, or with Manage... next to Log in with.")
            note.setWordWrap(True)
            layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.fill(set(select or ()))

    def login_text(self, device):
        credential_id = self.choices.get(device["id"])
        credential = self.store.credentials.get(credential_id) if credential_id else None
        if credential is not None:
            return credential.name
        session = logins.session_for(self.sessions, device)
        if session is None:
            fallback = USUAL
        elif logins.usable(session):
            fallback = f"Its saved session ({session.name})"
        else:
            fallback = f"Its saved session ({session.name}) has no saved password: {USUAL.lower()}"
        return f"A credential that was deleted: {fallback[0].lower()}{fallback[1:]}" if credential_id else fallback

    def fill(self, select=()):
        self.table.setRowCount(len(self.devices))
        first = None
        for row, device in enumerate(self.devices):
            failures = device.get("failures") or []
            values = [device.get("name") or device["id"], device.get("address") or "",
                      self.login_text(device), failures[0]["reason"] if failures else ""]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                item.setToolTip(value)
                if column == 0:
                    item.setData(Qt.UserRole, device["id"])
                self.table.setItem(row, column, item)
            if device["id"] in select:
                self.table.selectionModel().select(self.table.model().index(row, 0),
                                                   QItemSelectionModel.Select | QItemSelectionModel.Rows)
                first = row if first is None else first
        self.table.resizeColumnsToContents()
        if first is not None:
            self.table.scrollToItem(self.table.item(first, 0))
            index = self.combo.findData(self.choices.get(self.devices[first]["id"], ""))
            self.combo.setCurrentIndex(max(index, 0))

    def selected_ids(self):
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [self.table.item(row, 0).data(Qt.UserRole) for row in rows if not self.table.isRowHidden(row)]

    def use_for_selected(self):
        credential_id = self.combo.currentData() or ""
        for device_id in self.selected_ids():
            if credential_id:
                self.choices[device_id] = credential_id
            else:
                self.choices.pop(device_id, None)
        for row, device in enumerate(self.devices):
            self.table.item(row, 2).setText(self.login_text(device))

    def apply_filter(self, text):
        text = text.strip().lower()
        for row in range(self.table.rowCount()):
            shown = not text or any(text in (self.table.item(row, column).text() or "").lower() for column in (0, 1))
            self.table.setRowHidden(row, not shown)

    def chosen(self):
        """{device id: credential id}, for configs.logins.save (those of devices not listed now are kept)."""
        return {device_id: credential_id for device_id, credential_id in self.choices.items() if credential_id}
