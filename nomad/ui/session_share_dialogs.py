"""Export Sessions to Share and Import Shared Sessions: saved sessions passed to other people with no logins in them,
and on import one saved credential picked for all of them, with exceptions row by row."""
import os
from dataclasses import dataclass

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, \
    QFormLayout, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton, QTableWidget, QTableWidgetItem, QTreeWidget, \
    QTreeWidgetItem, QVBoxLayout

from ..terminal.sessions import CREDENTIAL_PROTOCOLS, RDP, normalize_folder
from ..terminal.share import DUPLICATE_ACTIONS, FILE_FILTER, KEEP_BOTH, REPLACE, SKIP, ImportChoice, ShareError, \
    import_shared, join_folder, match_hint, read_share, root_store, usable_credential, write_share
from .common import ColumnFitter, add_submenu, set_hint
from .credential_dialogs import CredentialDialog

KIND_ROLE = Qt.UserRole  # "session" or "folder"
VALUE_ROLE = Qt.UserRole + 1  # The session's id, or the folder's path
NAMESPACE_ROLE = Qt.UserRole + 2  # "terminal" or "rdp"
TERMINAL, REMOTE_DESKTOP = "terminal", "rdp"
FOLLOW = "\x00all"  # A row's credential: whatever Credential for all is
ASK_TEXT = "Ask when connecting"


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


def namespace_of(session):
    return REMOTE_DESKTOP if session.protocol == RDP else TERMINAL


def inside(path, folders):
    return any(path == folder or path.startswith(folder + "/") for folder in folders)


# ----------------------------------------------------------------- Export

class ShareExportDialog(QDialog):
    """Tick the sessions (and empty folders) to share, then save them to a file. session_ids and folders (in the
    namespace given) start ticked; with neither, everything does."""

    def __init__(self, parent, store, session_ids=None, folders=None, namespace=TERMINAL):
        super().__init__(parent)
        self.store = root_store(store)
        self.setWindowTitle("Export Sessions to Share")
        self.setMinimumSize(480, 560)
        self.path = ""
        self.count = 0
        layout = QVBoxLayout(self)
        intro = QLabel("Tick the sessions to share. The file has where and how each one connects, but no passwords, "
                       "keys or user names: whoever imports it picks their own saved credentials.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setIndentation(14)
        layout.addWidget(self.tree, 1)
        self.notes_check = QCheckBox("Include notes")
        self.notes_check.setChecked(True)
        self.notes_check.setToolTip("Session notes can hold anything that was typed in them. Untick this if yours "
                                    "might have something private in them.")
        self.hints_check = QCheckBox("Suggest credential names")
        self.hints_check.setChecked(True)
        self.hints_check.setToolTip("Writes the name of the credential each session uses here, such as TACACS (the "
                                    "name only). NOMAD starts a session on a credential of the same name when "
                                    "it's imported.")
        layout.addWidget(self.notes_check)
        layout.addWidget(self.hints_check)
        warning = QLabel("Host names and addresses are in the file, so share it only with people who should have "
                         "them.")
        warning.setWordWrap(True)
        layout.addWidget(warning)
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Export...")
        buttons.accepted.connect(self.export)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.fill(session_ids, folders, namespace)

    def fill(self, session_ids, folders, namespace):
        chosen = session_ids is not None or folders is not None
        session_ids, folders = set(session_ids or ()), [normalize_folder(folder) for folder in folders or ()]
        groups = [(TERMINAL, "Terminal (SSH, Telnet, serial, raw TCP)", self.store.folders),
                  (REMOTE_DESKTOP, "Remote Desktop", self.store.rdp_folders)]
        for group, label, empty_folders in groups:
            sessions = [session for session in self.store.sessions if namespace_of(session) == group]
            if not sessions and not empty_folders:
                continue
            top = QTreeWidgetItem([label])
            top.setFlags(top.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
            top.setCheckState(0, Qt.Unchecked)
            self.tree.addTopLevelItem(top)
            items = {"": top}

            def folder_item(path):
                if path in items:
                    return items[path]
                parent_path, _, name = path.rpartition("/")
                parent = folder_item(parent_path)
                item = QTreeWidgetItem([name])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable | Qt.ItemIsAutoTristate)
                item.setData(0, KIND_ROLE, "folder")
                item.setData(0, VALUE_ROLE, path)
                item.setData(0, NAMESPACE_ROLE, group)
                item.setCheckState(0, Qt.Unchecked)
                parent.addChild(item)
                items[path] = item
                return item

            for path in sorted(set(empty_folders) | {session.folder for session in sessions if session.folder},
                               key=str.lower):
                folder_item(path)
            for session in sorted(sessions, key=lambda item: item.name.lower()):
                where = session.copy(id=session.id, username="").target()  # User names never go in the file
                item = QTreeWidgetItem([f"{session.name}    {where}"])
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setData(0, KIND_ROLE, "session")
                item.setData(0, VALUE_ROLE, session.id)
                item.setData(0, NAMESPACE_ROLE, group)
                folder_item(session.folder).addChild(item)
            for item in self.walk(top):
                kind, value = item.data(0, KIND_ROLE), item.data(0, VALUE_ROLE)
                if item.childCount():
                    continue  # Its children decide
                if not chosen:
                    ticked = True
                elif group != namespace:
                    ticked = False
                elif kind == "session":
                    session = self.store.get(value)
                    ticked = value in session_ids or (session is not None and inside(session.folder, folders))
                else:
                    ticked = inside(value, folders)
                item.setCheckState(0, Qt.Checked if ticked else Qt.Unchecked)
        self.tree.expandAll()

    @staticmethod
    def walk(item):
        for index in range(item.childCount()):
            child = item.child(index)
            yield child
            yield from ShareExportDialog.walk(child)

    def ticked(self):
        """(sessions, terminal folders, RDP folders) ticked, folders holding ticked sessions included."""
        sessions, folders = [], {TERMINAL: set(), REMOTE_DESKTOP: set()}
        for index in range(self.tree.topLevelItemCount()):
            for item in self.walk(self.tree.topLevelItem(index)):
                if item.checkState(0) == Qt.Unchecked:
                    continue
                if item.data(0, KIND_ROLE) == "session":
                    session = self.store.get(item.data(0, VALUE_ROLE))
                    if session is not None:
                        sessions.append(session)
                else:
                    folders[item.data(0, NAMESPACE_ROLE)].add(item.data(0, VALUE_ROLE))
        return sessions, folders[TERMINAL], folders[REMOTE_DESKTOP]

    def export(self):
        sessions, folders, rdp_folders = self.ticked()
        if not sessions:
            set_hint(self.error_label, "Tick at least one session to share.", "error")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Sessions to Share", "nomad-sessions.json",
                                              f"{FILE_FILTER};;All files (*)")
        if not path:
            return
        try:
            self.count = write_share(path, sessions, folders, rdp_folders,
                                     self.store.credentials if self.hints_check.isChecked() else None,
                                     self.notes_check.isChecked())
        except OSError as error:
            QMessageBox.critical(self, "Export Sessions to Share", f"Couldn't save the file:\n\n{error}")
            return
        self.path = path
        self.accept()


def export_sessions_to_share(parent, store, session_ids=None, folders=None, namespace=TERMINAL):
    """The Export Sessions to Share dialog, then what was written."""
    store = root_store(store)
    if not store.sessions:
        QMessageBox.information(parent, "Export Sessions to Share", "There are no saved sessions to share.")
        return
    dialog = ShareExportDialog(parent, store, session_ids, folders, namespace)
    if dialog.exec_():
        QMessageBox.information(parent, "Export Sessions to Share",
                                f"Exported {plural(dialog.count, 'session')} to {os.path.basename(dialog.path)}.\n\n"
                                "No passwords, keys or user names are in the file. Whoever imports it uses File > "
                                "Import Shared Sessions and picks their own saved credentials.")


# ----------------------------------------------------------------- Import

@dataclass
class Row:
    shared: object  # SharedSession
    choice: str = FOLLOW  # FOLLOW, "" to ask when connecting, or a credential id
    matched: str = ""  # The credential matched by name, when the row's choice came from its hint
    existing: object = None  # The saved session it duplicates, under the import folder
    duplicate: str = SKIP
    combo: object = None
    duplicate_combo: object = None


class ShareImportDialog(QDialog):
    """Pick the folder to import into and how each session logs in: Credential for all, and exceptions by row."""
    COLUMNS = ["Session", "Folder", "Connects to", "Protocol", "Credential", "Already saved"]
    NAME, FOLDER, TARGET, PROTOCOL, CREDENTIAL, DUPLICATE = range(6)

    def __init__(self, parent, store, shared, file_name=""):
        super().__init__(parent)
        self.store = root_store(store)
        self.book = self.store.credentials
        self.shared = shared
        self.import_result = None
        self.setWindowTitle("Import Shared Sessions")
        self.resize(940, 600)
        layout = QVBoxLayout(self)
        about = f"{plural(len(shared.sessions), 'session')} in {file_name or 'the file'}"
        if shared.nomad_version:
            about += f", from NOMAD {shared.nomad_version}"
        heading = QLabel(about + ". They have no logins: pick a saved credential for all of them, then change any "
                                 "that log in differently.")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        if shared.skipped:
            skipped = QLabel(f"{plural(len(shared.skipped), 'session')} in the file can't be imported: "
                             + "; ".join(shared.skipped[:5]) + ("; ..." if len(shared.skipped) > 5 else ""))
            skipped.setWordWrap(True)
            set_hint(skipped, skipped.text(), "warning")
            layout.addWidget(skipped)

        form = QFormLayout()
        self.folder_combo = QComboBox()
        self.folder_combo.setEditable(True)
        existing_folders = (set(self.store.folders) | set(self.store.rdp_folders)
                            | {session.folder for session in self.store.sessions}) - {""}
        self.folder_combo.addItems(sorted(existing_folders, key=str.lower))
        stem = os.path.splitext(file_name)[0] if file_name else ""
        self.folder_combo.setEditText(normalize_folder(f"Shared/{stem}") if stem else "Shared")
        self.folder_combo.setToolTip("The folder the sessions go in, keeping the folders they had inside it. "
                                     "Empty: as they were in the file.")
        form.addRow("Import into folder:", self.folder_combo)
        all_row = QHBoxLayout()
        self.all_combo = QComboBox()
        self.all_combo.setToolTip("Every SSH and Remote Desktop session logs in with this, except the ones changed "
                                  "in the list.")
        self.new_button = QPushButton("New Credential...")
        all_row.addWidget(self.all_combo, 1)
        all_row.addWidget(self.new_button)
        form.addRow("Credential for all:", all_row)
        layout.addLayout(form)
        self.match_check = QCheckBox("Match credentials by name")
        self.match_check.setToolTip("A session whose credential where it was exported has the same name as one of "
                                    "yours (such as TACACS) starts on yours.")
        hints = any(row.hint for row in shared.sessions)
        self.match_check.setChecked(hints)
        self.match_check.setVisible(hints)
        layout.addWidget(self.match_check)

        self.table = QTableWidget(0, len(self.COLUMNS))
        self.table.setHorizontalHeaderLabels(self.COLUMNS)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.setToolTip("Right-click selected rows to set their credential, or what happens to ones already "
                              "saved, all at once.")
        layout.addWidget(self.table, 1)
        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.import_button = buttons.button(QDialogButtonBox.Ok)
        self.import_button.setText("Import")
        buttons.accepted.connect(self.do_import)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.rows = [Row(item) for item in shared.sessions]
        self.fill_all_combo(self.book.default_id if self.book.default is not None else "")
        self.fill_table()
        self.apply_matches()
        self.find_existing()
        ColumnFitter(self.table)
        self.all_combo.currentIndexChanged.connect(self.all_changed)
        self.new_button.clicked.connect(self.new_credential)
        self.match_check.toggled.connect(self.apply_matches)
        self.folder_combo.editTextChanged.connect(self.find_existing)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.table.itemChanged.connect(self.update_summary)

    # --- Credential for all

    def fill_all_combo(self, select):
        self.all_combo.blockSignals(True)
        self.all_combo.clear()
        self.all_combo.addItem(ASK_TEXT, "")
        for credential in self.book.sorted():
            self.all_combo.addItem(f"{credential.name}  ({credential.summary()})", credential.id)
        self.all_combo.setCurrentIndex(max(0, self.all_combo.findData(select)))
        self.all_combo.blockSignals(False)

    def all_id(self):
        return self.all_combo.currentData() or ""

    def all_changed(self):
        for row in self.rows:
            self.fill_row_combo(row)
        self.update_summary()

    def new_credential(self):
        dialog = CredentialDialog(self, self.store, title="New Credential")
        if not dialog.exec_():
            return
        self.fill_all_combo(dialog.credential.id)
        self.apply_matches()  # A new credential may be named like some sessions' hints
        self.all_changed()

    # --- The rows

    def fill_table(self):
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.rows))
        for index, row in enumerate(self.rows):
            session = row.shared.session
            name = QTableWidgetItem(session.name)
            name.setFlags(name.flags() | Qt.ItemIsUserCheckable)
            name.setCheckState(Qt.Checked)
            name.setToolTip("Untick to leave this session out.")
            self.table.setItem(index, self.NAME, name)
            self.table.setItem(index, self.FOLDER, QTableWidgetItem(session.folder))
            self.table.setItem(index, self.TARGET, QTableWidgetItem(session.target()))
            self.table.setItem(index, self.PROTOCOL, QTableWidgetItem(session.protocol))
            if session.protocol in CREDENTIAL_PROTOCOLS:
                combo = QComboBox()
                combo.setProperty("row", index)
                combo.currentIndexChanged.connect(self.row_combo_changed)
                row.combo = combo
                self.table.setCellWidget(index, self.CREDENTIAL, combo)
                self.fill_row_combo(row)
            else:
                item = QTableWidgetItem("Not used")
                item.setToolTip(f"{session.protocol} sessions don't log in with a saved credential.")
                item.setForeground(self.palette().placeholderText())
                self.table.setItem(index, self.CREDENTIAL, item)
            self.table.setItem(index, self.DUPLICATE, QTableWidgetItem("New"))
        self.table.blockSignals(False)

    def follow_text(self, row):
        credential = self.book.get(self.all_id())
        if credential is None:
            return f"For all: {ASK_TEXT}"
        if usable_credential(self.book, credential.id, row.shared.session.protocol) is None:
            return f"For all: {ASK_TEXT} (Remote Desktop needs a password credential)"
        return f"For all: {credential.name}"

    def fill_row_combo(self, row):
        combo = row.combo
        if combo is None:
            return
        protocol = row.shared.session.protocol
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(self.follow_text(row), FOLLOW)
        combo.addItem(ASK_TEXT, "")
        for credential in self.book.sorted(protocol):
            combo.addItem(f"{credential.name}  ({credential.summary()})", credential.id)
        index = combo.findData(row.choice)
        if index < 0:
            row.choice, row.matched, index = FOLLOW, "", 0
        combo.setCurrentIndex(index)
        combo.blockSignals(False)
        self.style_row(row)

    def style_row(self, row):
        combo = row.combo
        if combo is None:
            return
        font = combo.font()
        font.setBold(row.choice != FOLLOW)
        combo.setFont(font)
        if row.matched and row.choice == row.matched:
            credential = self.book.get(row.matched)
            tip = f"Matched by name: {credential.name if credential else row.shared.hint}."
        elif row.choice != FOLLOW:
            tip = "An exception: not the credential for all. Right-click > Set Credential > Credential for All to " \
                  "undo it."
        else:
            tip = "Logs in with the credential for all."
        if row.existing is not None and row.duplicate != KEEP_BOTH:
            tip = "Already saved: it keeps its own login." if row.duplicate == REPLACE else \
                "Already saved, and skipped."
        combo.setToolTip(tip)
        combo.setEnabled(row.existing is None or row.duplicate == KEEP_BOTH)

    def row_combo_changed(self):
        combo = self.sender()
        row = self.rows[combo.property("row")]
        row.choice = combo.currentData()
        if row.choice != row.matched:
            row.matched = ""
        self.style_row(row)
        self.update_summary()

    def set_choice(self, rows, choice):
        for row in rows:
            if row.combo is None:
                continue
            row.choice, row.matched = choice, ""
            self.fill_row_combo(row)
        self.update_summary()

    def apply_matches(self):
        """Rows whose hint names one of this computer's credentials start on it (or go back to the credential for
        all when matching is turned off)."""
        matching = self.match_check.isChecked()
        for row in self.rows:
            if row.combo is None:
                continue
            if matching and row.choice == FOLLOW:
                match = match_hint(self.book, row.shared.hint, row.shared.session.protocol)
                if match:
                    row.choice = row.matched = match
            elif not matching and row.matched and row.choice == row.matched:
                row.choice, row.matched = FOLLOW, ""
            self.fill_row_combo(row)
        self.update_summary()

    # --- Sessions already saved

    def prefix(self):
        return normalize_folder(self.folder_combo.currentText())

    def find_existing(self):
        prefix = self.prefix()
        index = {}
        for session in self.store.sessions:
            index.setdefault((session.protocol, session.folder.lower(), session.name.lower(), session.host.lower()),
                             session)
        self.table.blockSignals(True)
        for number, row in enumerate(self.rows):
            session = row.shared.session
            key = (session.protocol, join_folder(prefix, session.folder).lower(), session.name.lower(),
                   session.host.lower())
            existing = index.get(key)
            if (existing is None) != (row.existing is None):
                if existing is None:
                    self.table.removeCellWidget(number, self.DUPLICATE)
                    row.duplicate_combo = None
                    self.table.setItem(number, self.DUPLICATE, QTableWidgetItem("New"))
                else:
                    combo = QComboBox()
                    for value, label in DUPLICATE_ACTIONS:
                        combo.addItem(label, value)
                    combo.setCurrentIndex(max(0, combo.findData(row.duplicate)))
                    combo.setProperty("row", number)
                    combo.setToolTip("A session with this name, host and protocol is already saved in this folder.")
                    combo.currentIndexChanged.connect(self.duplicate_changed)
                    row.duplicate_combo = combo
                    self.table.setItem(number, self.DUPLICATE, QTableWidgetItem(""))
                    self.table.setCellWidget(number, self.DUPLICATE, combo)
            row.existing = existing
            self.style_row(row)
        self.table.blockSignals(False)
        self.update_summary()

    def duplicate_changed(self):
        combo = self.sender()
        row = self.rows[combo.property("row")]
        row.duplicate = combo.currentData()
        self.style_row(row)
        self.update_summary()

    def set_duplicate(self, rows, action):
        for row in rows:
            row.duplicate = action
            if row.duplicate_combo is not None:
                row.duplicate_combo.blockSignals(True)
                row.duplicate_combo.setCurrentIndex(max(0, row.duplicate_combo.findData(action)))
                row.duplicate_combo.blockSignals(False)
            self.style_row(row)
        self.update_summary()

    # --- Right-click, summary, import

    def selected_rows(self):
        return [self.rows[index.row()] for index in self.table.selectionModel().selectedRows()]

    def set_included(self, rows, included):
        self.table.blockSignals(True)
        for row in rows:
            self.table.item(self.rows.index(row), self.NAME).setCheckState(Qt.Checked if included else Qt.Unchecked)
        self.table.blockSignals(False)
        self.update_summary()

    def show_menu(self, position):
        rows = self.selected_rows()
        if not rows:
            return
        menu = QMenu(self)
        actions = {}
        logins = [row for row in rows if row.combo is not None]
        if logins:
            credentials = add_submenu(menu, "Set Credential")
            actions[credentials.addAction("Credential for All")] = lambda: self.set_choice(logins, FOLLOW)
            actions[credentials.addAction(ASK_TEXT)] = lambda: self.set_choice(logins, "")
            credentials.addSeparator()
            rdp = any(row.shared.session.protocol == RDP for row in logins)
            for credential in self.book.sorted(RDP if rdp else None):
                actions[credentials.addAction(credential.name)] = \
                    lambda credential_id=credential.id: self.set_choice(logins, credential_id)
        duplicates = [row for row in rows if row.existing is not None]
        if duplicates:
            submenu = add_submenu(menu, "If Already Saved")
            for value, label in DUPLICATE_ACTIONS:
                actions[submenu.addAction(label)] = lambda value=value: self.set_duplicate(duplicates, value)
        menu.addSeparator()
        actions[menu.addAction("Import These")] = lambda: self.set_included(rows, True)
        actions[menu.addAction("Leave These Out")] = lambda: self.set_included(rows, False)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def included(self, row):
        return self.table.item(self.rows.index(row), self.NAME).checkState() == Qt.Checked

    def effective(self, row):
        """The credential id a row logs in with ("" to ask), or None when it doesn't use one."""
        if row.combo is None:
            return None
        choice = self.all_id() if row.choice == FOLLOW else row.choice
        return choice if usable_credential(self.book, choice, row.shared.session.protocol) else ""

    def choices(self):
        return [ImportChoice(row.shared, self.effective(row) or "", row.duplicate if row.existing else SKIP)
                for row in self.rows if self.included(row)]

    def update_summary(self, *_):
        if not hasattr(self, "summary_label"):
            return
        rows = [row for row in self.rows if self.included(row)]
        skipped = [row for row in rows if row.existing is not None and row.duplicate == SKIP]
        replaced = [row for row in rows if row.existing is not None and row.duplicate == REPLACE]
        new = [row for row in rows if row not in skipped and row not in replaced]
        follow = sum(1 for row in new if row.combo is not None and row.choice == FOLLOW and self.effective(row))
        exceptions = sum(1 for row in new if row.combo is not None and row.choice != FOLLOW and self.effective(row))
        asking = sum(1 for row in new if row.combo is not None and not self.effective(row))
        no_login = sum(1 for row in new if row.combo is None)
        parts = [f"{len(new)} to add"]
        if follow:
            parts.append(f"{follow} with the credential for all")
        if exceptions:
            parts.append(plural(exceptions, "exception"))
        if asking:
            parts.append(f"{asking} will ask for a login")
        if no_login:
            parts.append(f"{no_login} {'doesn' if no_login == 1 else 'don'}'t log in (Telnet, serial, raw TCP)")
        text = ", ".join(parts) + "."
        if replaced or skipped:
            saved = ([f"{len(replaced)} to update, keeping their logins"] if replaced else []) +                 ([f"{len(skipped)} skipped"] if skipped else [])
            text += " Already saved: " + ", ".join(saved) + "."
        left_out = len(self.rows) - len(rows)
        if left_out:
            text += f" {left_out} left out."
        self.summary_label.setText(text)
        self.import_button.setEnabled(bool(new or replaced))

    def do_import(self):
        choices = self.choices()
        try:
            self.import_result = import_shared(self.store, choices, self.prefix(), self.shared.folders,
                                        self.shared.rdp_folders)
        except OSError as error:
            QMessageBox.critical(self, "Import Shared Sessions", f"Couldn't save the sessions:\n\n{error}")
            return
        self.accept()


def import_shared_sessions(parent, store, path=None):
    """Pick a share file, then the Import Shared Sessions dialog. Returns the ImportResult, or None."""
    if path is None:
        path, _ = QFileDialog.getOpenFileName(parent, "Import Shared Sessions", "", f"{FILE_FILTER};;All files (*)")
        if not path:
            return None
    try:
        shared = read_share(path)
    except ShareError as error:
        QMessageBox.warning(parent, "Import Shared Sessions", str(error))
        return None
    if not shared.sessions:
        message = "There are no sessions in this file NOMAD can import."
        if shared.skipped:
            message += "\n\n" + "\n".join(shared.skipped[:10])
        QMessageBox.information(parent, "Import Shared Sessions", message)
        return None
    dialog = ShareImportDialog(parent, store, shared, os.path.basename(path))
    if not dialog.exec_():
        return None
    result = dialog.import_result
    lines = [f"Added {plural(result.added, 'session')}."]
    if result.with_credential:
        lines.append(f"{result.with_credential} log in with a saved credential.")
    if result.asking:
        lines.append(f"{result.asking} will ask for a login when you connect.")
    if result.replaced:
        lines.append(f"Updated {plural(result.replaced, 'session')} you already had, keeping their logins.")
    if result.skipped:
        lines.append(f"Skipped {plural(result.skipped, 'session')} you already had.")
    QMessageBox.information(parent, "Import Shared Sessions", "\n\n".join(lines))
    return result
