"""The Assets page's dialogs: adding or editing an asset, reviewing what a network map (or a server's or phone's own
answer) would change before bringing it in, asking servers and phones what they are, and the changes made offline
that the IPAM server refused."""
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, \
    QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, \
    QWidget

from .. import hostinfo
from ..ipam.asset_compare import ACTION_LABELS, CONFLICT, NEW, REPLACE, SAME, summary
from ..ipam.assets import DEVICE_KINDS, KINDS, PART_KINDS, STATUSES, label as asset_label, today
from ..ipam.store import IpamError
from ..netmap import macssh
from ..terminal.sessions import AUTH_PASSWORD, SSH, Session
from .common import ColumnFitter, StoppableThread, set_hint
from .ipam_dialogs import _EditDialog
from .theme import COLORS

log = logging.getLogger(__name__)

TYPED_LOGIN = "A user name and password typed here"
ACTION_COLORS = {NEW: "success", REPLACE: "warning", CONFLICT: "error", SAME: "muted"}
READ_WORKERS = 8


@dataclass
class Source:
    """Where assets are kept: the tribe's (through the IPAM server) or this computer's."""
    key: str  # "team" or "local", as the IP Addresses page names them
    label: str  # "Tribe" or "Local"
    ipam: object  # TeamStore or IpamStore: where its history is
    assets: object  # TeamAssetStore or AssetStore
    can_edit: bool = True


def _table(columns):
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.verticalHeader().setVisible(False)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setWordWrap(True)
    table.horizontalHeader().setStretchLastSection(True)
    return table


def _item(text, color=None, tooltip=None):
    item = QTableWidgetItem(text)
    item.setToolTip(tooltip or text)
    if color:
        item.setForeground(QColor(COLORS[color]))
    return item


# --------------------------------------------------------------------- One asset

class AssetDialog(_EditDialog):
    """Add an asset by hand (a spare on the shelf, a server, hardware the map can't read), or edit one."""

    DATES = (("purchased", "Purchased:"), ("warranty_end", "Warranty ends:"), ("eol", "End of life:"))

    def __init__(self, parent, source, asset=None, kind="", parents=()):
        super().__init__(parent, f"Edit {asset_label(asset)}" if asset else "Add Asset")
        self.source, self.asset = source, asset
        value = (lambda name, default="": getattr(asset, name) if asset is not None else default)
        self.inputs = {}
        self.kind_combo = QComboBox()
        for key, name in list(DEVICE_KINDS.items()) + list(PART_KINDS.items()):
            self.kind_combo.addItem(name, key)
        self.kind_combo.setCurrentIndex(max(0, self.kind_combo.findData(value("kind", kind or "switch"))))
        self.status_combo = QComboBox()
        for key, name in STATUSES.items():
            self.status_combo.addItem(name, key)
        self.status_combo.setCurrentIndex(max(0, self.status_combo.findData(value("status", "in_service"))))
        self.parent_combo = QComboBox()
        self.parent_combo.addItem("(not in another asset)", "")
        for other in parents:
            if asset is None or other.id != asset.id:
                self.parent_combo.addItem(asset_label(other) + (f" ({other.serial})" if other.serial else ""),
                                          other.id)
        self.parent_combo.setCurrentIndex(max(0, self.parent_combo.findData(value("parent_id"))))
        self.parent_combo.setToolTip("For a part (a module, power supply, fan or transceiver): the chassis it's in.")
        rows = [("hostname", "Hostname:", "As it names itself (from the map), or what it's called"),
                ("model", "Model:", "Such as C9300-48P"), ("maker", "Maker:", "Such as Cisco"),
                ("serial", "Serial number:", "What makes it this asset: never changes"),
                ("software", "Software:", "The version it runs"), ("mgmt_ip", "Management IP:", ""),
                ("mac", "MAC address:", "How a phone or server without a serial number is known"),
                ("slot", "Slot:", "Its stack member or chassis slot (Switch 2), or the port a phone is on"),
                ("location", "Location:", "Site / Building / Room, or anywhere"),
                ("asset_tag", "Asset tag:", "Your organization's tag on it"), ("owner", "Owner:", "Who it belongs to")]
        self.form.addRow("Kind:", self.kind_combo)
        for name, title, hint in rows:
            field = QLineEdit(value(name))
            field.setPlaceholderText(hint)
            self.inputs[name] = field
            self.form.addRow(title, field)
            if name == "slot":
                self.form.addRow("In:", self.parent_combo)
        self.form.addRow("Status:", self.status_combo)
        for name, title in self.DATES:
            field = QLineEdit(value(name))
            field.setPlaceholderText(f"YYYY-MM-DD, such as {today()}")
            self.inputs[name] = field
            self.form.addRow(title, field)
        self.notes = QPlainTextEdit(value("description"))
        self.notes.setFixedHeight(70)
        self.form.addRow("Notes:", self.notes)
        if asset is not None and (asset.first_seen or asset.last_seen):
            seen = QLabel(f"On a network map from {asset.first_seen or '?'} to {asset.last_seen or '?'}"
                          + (f" (last brought in by {asset.seen_by})" if asset.seen_by else "") + ".")
            seen.setWordWrap(True)
            self.form.addRow("", seen)
        self.finish_layout()

    def values(self):
        values = {name: field.text() for name, field in self.inputs.items()}
        values.update(kind=self.kind_combo.currentData(), status=self.status_combo.currentData(),
                      parent_id=self.parent_combo.currentData() or "", description=self.notes.toPlainText().strip())
        return values

    def apply(self):
        values = self.values()
        if self.asset is not None:
            values = {name: value for name, value in values.items() if str(getattr(self.asset, name)) != value}
            if not values:
                return self.asset
        if not self.source.can_edit:
            raise IpamError("The tribe's assets can't be changed right now (the IPAM server needs updating).")
        return self.source.assets.set_asset(self.asset.id if self.asset else None, **values)


class ValueDialog(_EditDialog):
    """One value for several assets at once: their location, owner or status."""

    def __init__(self, parent, title, prompt, value="", choices=None):
        super().__init__(parent, title)
        if choices:
            self.field = QComboBox()
            for key, name in choices.items():
                self.field.addItem(name, key)
            self.field.setCurrentIndex(max(0, self.field.findData(value)))
        else:
            self.field = QLineEdit(value)
        self.form.addRow(prompt, self.field)
        self.finish_layout()

    def value(self):
        return self.field.currentData() if isinstance(self.field, QComboBox) else self.field.text().strip()

    def apply(self):
        return self.value()


# --------------------------------------------------------------------- Reviewing what's found

class AssetImportDialog(QDialog):
    """What a map (or servers' and phones' own answers) would change in the asset list: tick the changes to make.
    Conflicts are only pointed out; changes that might undo what was said by hand start unticked."""

    COLUMNS = ["", "Change", "Hostname", "Slot", "Kind", "Model", "Serial", "What Changes", "Note"]

    def __init__(self, parent, source, changes, title="Bring In Hardware", intro=""):
        super().__init__(parent)
        self.source, self.changes = source, [change for change in changes if change.action != SAME]
        self.unchanged = len(changes) - len(self.changes)
        self.all_changes = changes
        self.setWindowTitle(title)
        self.resize(1200, 560)
        layout = QVBoxLayout(self)
        text = QLabel(intro or "What the map found that the asset list doesn't say yet. Tick what to bring in: new "
                      "hardware is added, renamed or upgraded hardware is changed, and where a hostname (or stack "
                      "member, or slot) now has another serial number, the old hardware is marked Replaced.")
        text.setWordWrap(True)
        layout.addWidget(text)
        self.table = _table(self.COLUMNS)
        layout.addWidget(self.table, 1)
        fitter = ColumnFitter(self.table)
        fitter.widest = {7: 420, 8: 360}
        self.count_label = QLabel()
        layout.addWidget(self.count_label)
        row = QHBoxLayout()
        tick_all, untick_all = QPushButton("Tick All"), QPushButton("Untick All")
        tick_all.clicked.connect(self.tick_all)
        untick_all.clicked.connect(self.untick_all)
        row.addWidget(tick_all)
        row.addWidget(untick_all)
        row.addStretch()
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Bring In")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        row.addWidget(self.buttons)
        layout.addLayout(row)
        self.fill()
        self.table.itemChanged.connect(self.on_ticked)

    def fill(self):
        self.table.setRowCount(len(self.changes))
        for row, change in enumerate(self.changes):
            sighting = change.sighting
            tick = QTableWidgetItem()
            if change.can_apply:
                tick.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                tick.setCheckState(Qt.Checked if change.chosen else Qt.Unchecked)
            else:
                tick.setFlags(Qt.ItemIsEnabled)
            self.table.setItem(row, 0, tick)
            values = [ACTION_LABELS[change.action], sighting.hostname, sighting.slot, KINDS.get(sighting.kind,
                                                                                                  sighting.kind),
                      sighting.model, sighting.serial or (sighting.mac and f"MAC {sighting.mac}") or "(none)",
                      change.describe(), change.note]
            for column, text in enumerate(values, start=1):
                self.table.setItem(row, column, _item(text, ACTION_COLORS.get(change.action) if column == 1 else None))
        self.table.resizeRowsToContents()
        self.show_count()

    def on_ticked(self, item):
        if item.column() == 0 and 0 <= item.row() < len(self.changes):
            self.changes[item.row()].chosen = item.checkState() == Qt.Checked
            self.show_count()

    def tick(self, chosen):
        self.table.blockSignals(True)
        for row, change in enumerate(self.changes):
            if change.can_apply:
                change.chosen = chosen
                self.table.item(row, 0).setCheckState(Qt.Checked if chosen else Qt.Unchecked)
        self.table.blockSignals(False)
        self.show_count()

    def tick_all(self):
        self.tick(True)

    def untick_all(self):
        self.tick(False)

    def show_count(self):
        chosen = summary(self.changes)
        parts = [f"To bring in: {chosen}." if chosen else "Nothing ticked."]
        if self.unchanged:
            parts.append(f"{self.unchanged} more as recorded (each is noted as seen today).")
        conflicts = sum(1 for change in self.changes if change.action == CONFLICT)
        if conflicts:
            parts.append(f"{conflicts} conflict{'s' if conflicts != 1 else ''}: left out (see Note).")
        self.count_label.setText(" ".join(parts))
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(bool(chosen) or bool(self.unchanged))


# --------------------------------------------------------------------- Asking servers and phones

class DetailsReader(StoppableThread):
    """Asks servers or phones what they are, a few at once."""
    answered = pyqtSignal(object)  # hostinfo.HostDetails

    def __init__(self, method, addresses, login, parent=None):
        super().__init__(parent)
        self.method, self.addresses, self.login = method, addresses, login  # login: see ReadDetailsDialog.login

    def run(self):
        with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(self.addresses)))) as executor:
            list(executor.map(self.ask, self.addresses))

    def ask(self, address):
        if self.stopping:
            return
        try:
            details = self.read(address)
        except Exception as error:  # One host's trouble shouldn't stop the rest
            log.exception("Asking %s what it is failed", address)
            details = hostinfo.HostDetails(address, self.method, error=f"Couldn't ask it: {error}")
        if not self.stopping:
            self.answered.emit(details)

    def read(self, address):
        login = self.login
        if self.method == hostinfo.WINDOWS:
            return hostinfo.windows_details(address, login.get("user", ""), login.get("password", ""))
        if self.method == hostinfo.PHONE:
            return hostinfo.phone_details(address)
        from ..terminal.hostkeys import KnownHosts
        logins = login["logins"]
        session, _ = logins.login_for(address)
        if session is None:
            return hostinfo.HostDetails(address, hostinfo.LINUX, error="No saved session or login to use.")
        prompter = macssh.BatchPrompter(login.get("trust", False), logins.password)
        return hostinfo.linux_details(address, session, KnownHosts(), prompter, login.get("vault"))


class ReadDetailsDialog(QDialog):
    """Ask servers or phones what they are (maker, model, serial number, operating system or firmware), then review
    what that changes in the asset list."""

    COLUMNS = ["Address", "Hostname", "Maker", "Model", "Serial", "Software", "Problem"]

    def __init__(self, parent, session_store, addresses=(), method=hostinfo.WINDOWS):
        super().__init__(parent)
        self.session_store = session_store
        self.reader = None
        self.results = {}
        self.setWindowTitle("Read Server or Phone Details")
        self.resize(1000, 520)
        layout = QVBoxLayout(self)
        intro = QLabel("Servers rarely tell SNMP their serial number, and phones tell their switch only some of it: "
                       "ask them instead. Windows servers are asked over WMI (WinRM, or DCOM), Linux servers over SSH, "
                       "and Cisco phones through their web page.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.method_combo = QComboBox()
        for key, name in hostinfo.METHODS.items():
            self.method_combo.addItem(name, key)
        self.method_combo.setCurrentIndex(max(0, self.method_combo.findData(method)))
        form.addRow("Ask:", self.method_combo)
        self.addresses_input = QPlainTextEdit("\n".join(addresses))
        self.addresses_input.setPlaceholderText("Addresses or names, one per line")
        self.addresses_input.setFixedHeight(80)
        form.addRow("Addresses:", self.addresses_input)
        self.login_row = QWidget()
        login_layout = QHBoxLayout(self.login_row)
        login_layout.setContentsMargins(0, 0, 0, 0)
        self.windows_combo = QComboBox()
        self.windows_combo.addItem("This Windows login", "")
        self.windows_combo.addItem(TYPED_LOGIN, "typed")
        login_layout.addWidget(self.windows_combo, 1)
        self.picker = None
        if session_store is not None:
            from .credential_dialogs import CredentialPicker
            default = session_store.credentials.default
            self.picker = CredentialPicker(self, session_store, SSH, default.id if default else "", TYPED_LOGIN)
            login_layout.addWidget(self.picker, 1)
        form.addRow("Log in with:", self.login_row)
        self.user_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Kept only while this window is open")
        form.addRow("User name:", self.user_input)
        form.addRow("Password:", self.password_input)
        self.trust_check = QCheckBox("Trust Linux servers' SSH keys NOMAD hasn't seen before")
        form.addRow("", self.trust_check)
        layout.addLayout(form)
        self.table = _table(self.COLUMNS)
        layout.addWidget(self.table, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        row = QHBoxLayout()
        self.ask_button = QPushButton("Ask Them")
        self.ask_button.setProperty("accent", True)
        self.stop_button = QPushButton("Stop")
        self.record_button = QPushButton("Review and Record...")
        close = QPushButton("Close")
        for button in (self.ask_button, self.stop_button):
            row.addWidget(button)
        row.addStretch()
        row.addWidget(self.record_button)
        row.addWidget(close)
        layout.addLayout(row)
        self.ask_button.clicked.connect(self.ask)
        self.stop_button.clicked.connect(self.stop)
        self.record_button.clicked.connect(self.accept)
        close.clicked.connect(self.reject)
        self.method_combo.currentIndexChanged.connect(self.update_fields)
        self.windows_combo.currentIndexChanged.connect(self.update_fields)
        if self.picker is not None:
            self.picker.combo.currentIndexChanged.connect(self.update_fields)
        self.update_fields()

    @property
    def method(self):
        return self.method_combo.currentData()

    def kind(self):
        return "phone" if self.method == hostinfo.PHONE else "server"

    def typed(self):
        if self.method == hostinfo.WINDOWS:
            return self.windows_combo.currentData() == "typed"
        if self.method == hostinfo.LINUX:
            return self.picker is None or not self.picker.credential_id()
        return False

    def update_fields(self):
        method = self.method
        self.login_row.setVisible(method != hostinfo.PHONE)
        self.windows_combo.setVisible(method == hostinfo.WINDOWS)
        if self.picker is not None:
            self.picker.setVisible(method == hostinfo.LINUX)
        typed = self.typed()
        for field in (self.user_input, self.password_input):
            field.setEnabled(typed)
        self.trust_check.setVisible(method == hostinfo.LINUX)
        reading = self.reader is not None
        self.ask_button.setEnabled(not reading)
        self.stop_button.setEnabled(reading)
        self.record_button.setEnabled(not reading and any(details.ok for details in self.results.values()))

    def addresses(self):
        text = self.addresses_input.toPlainText().replace(",", " ")
        return list(dict.fromkeys(item for item in text.split() if item))

    def login(self):
        """What the reader logs in with, or None (with the reason shown) when something's missing."""
        method = self.method
        if method == hostinfo.PHONE:
            return {}
        user, password = self.user_input.text().strip(), self.password_input.text()
        if method == hostinfo.WINDOWS:
            if self.typed() and not user:
                set_hint(self.status_label, "Give the user name (DOMAIN\\name) to log in as.", "warning")
                return None
            return {"user": user, "password": password} if self.typed() else {}
        store = self.session_store
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions
                    if session.protocol == SSH] if store is not None else []
        credential = self.picker.credential() if self.picker is not None else None
        if credential is None:
            if not user:
                set_hint(self.status_label, "Give the user name to log in with (or choose a saved credential).",
                         "warning")
                return None
            fallback, typed_password = Session("", username=user), password
        else:
            fallback = store.credentials.apply(Session("", credential_id=credential.id))
            typed_password = password if credential.auth == AUTH_PASSWORD and not credential.saved_password else None
        if store is not None:
            secrets = any(item.saved_password or item.saved_passphrase for item in sessions + [fallback])
            from .vault_dialog import ensure_unlocked
            if secrets and not ensure_unlocked(self, store, "Reading servers' details logs in with saved passwords."):
                return None
        return {"logins": macssh.SshLogins(sessions, fallback, typed_password), "trust": self.trust_check.isChecked(),
                "vault": store.vault if store is not None else None}

    def ask(self):
        addresses = self.addresses()
        if not addresses:
            set_hint(self.status_label, "Give the addresses to ask.", "warning")
            return
        login = self.login()
        if login is None:
            return
        self.results = {}
        self.table.setRowCount(0)
        self.reader = DetailsReader(self.method, addresses, login, self)
        self.reader.answered.connect(self.on_answer)
        self.reader.finished.connect(self.on_finished)
        self.asked = len(addresses)
        set_hint(self.status_label, f"Asking {len(addresses)} {'host' if len(addresses) == 1 else 'hosts'}...", "info")
        self.reader.start()
        self.update_fields()

    def stop(self):
        if self.reader is not None:
            self.reader.stop()
            set_hint(self.status_label, "Stopping: waiting for the hosts being asked...", "warning")

    def on_answer(self, details):
        self.results[details.address] = details
        row = self.table.rowCount()
        self.table.insertRow(row)
        values = [details.address, details.hostname, details.maker, details.model, details.serial,
                  " ".join(part for part in (details.os, details.software) if part), details.error or details.note]
        for column, text in enumerate(values):
            color = "error" if column == 6 and details.error else "warning" if column == 6 and details.note else None
            self.table.setItem(row, column, _item(text, color))
        self.table.resizeRowsToContents()

    def on_finished(self):
        reader, self.reader = self.reader, None
        if reader is not None:
            reader.deleteLater()
        good = sum(1 for details in self.results.values() if details.ok)
        bad = len(self.results) - good
        text = f"{good} answered" + (f", {bad} didn't (see Problem)" if bad else "") + "."
        if good:
            text += " Review and Record shows what that changes in the asset list."
        set_hint(self.status_label, text, "warning" if bad else "success")
        self.update_fields()

    def answers(self):
        return [details for details in self.results.values() if details.ok]

    def done(self, result):
        if self.reader is not None:
            self.reader.stop()
            from .common import release_thread
            release_thread(self.reader)
            self.reader = None
        super().done(result)


# --------------------------------------------------------------------- Refused changes

class AssetRefusedDialog(QDialog):
    """Asset changes made offline that the IPAM server refused (someone changed that asset first, or recorded its
    serial number as another): discard them, then make the change again if it's still wanted."""

    COLUMNS = ["Asset", "Change", "Made", "Why it was refused"]

    def __init__(self, parent, assets):
        super().__init__(parent)
        self.assets = assets
        self.setWindowTitle("Refused Asset Changes")
        self.resize(900, 380)
        layout = QVBoxLayout(self)
        intro = QLabel("These changes were made while the IPAM server couldn't be reached. When they were sent, "
                       "someone else had changed those assets (or recorded the serial number) first, so the server "
                       "kept theirs. Discard each, then make it again if it's still wanted.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = _table(self.COLUMNS)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.discard_button = QPushButton("Discard")
        close = QPushButton("Close")
        row.addWidget(self.discard_button)
        row.addStretch()
        row.addWidget(close)
        layout.addLayout(row)
        self.discard_button.clicked.connect(self.discard)
        close.clicked.connect(self.accept)
        self.fill()

    def fill(self):
        self.entries = self.assets.refused()
        self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            data = entry["data"]
            name = data.get("hostname") or data.get("serial") or data.get("model") or entry["asset_id"][:8]
            change = "Delete" if entry["action"] == "delete_asset" else ", ".join(
                f"{key}: {value}" for key, value in data.items() if key not in ("fields",) and value)
            for column, text in enumerate([name, change, entry["made"][:16].replace("T", " "), entry["error"]]):
                self.table.setItem(row, column, _item(text))
        self.table.resizeRowsToContents()
        self.discard_button.setEnabled(bool(self.entries))

    def discard(self):
        row = self.table.currentRow()
        if 0 <= row < len(self.entries):
            self.assets.discard(self.entries[row]["seq"])
            self.fill()
