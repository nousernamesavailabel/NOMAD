"""Dialogs for the SCP page: a file that already exists, properties and permissions, checksums, and synchronizing
folders."""
import os
import posixpath
import stat
import threading

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QGuiApplication
from PyQt5.QtWidgets import QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, \
    QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, \
    QRadioButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout

from ..terminal.files import BOTH_WAYS, DIFFERENT, DOWNLOAD, HASHES, LOCAL_NEWER, LOCAL_ONLY, NEWER, OVERWRITE, \
    REMOTE_NEWER, REMOTE_ONLY, RENAME, SAME, SKIP, TO_LOCAL, TO_REMOTE, UPLOAD, TransferCancelled, compare, \
    local_files, local_hash, permission_text, remote_files, suggested_action
from .common import ColumnFitter, format_size, set_hint
from .file_panes import format_time
from .theme import COLORS


class ConflictDialog(QDialog):
    """A file being copied already exists. result: (OVERWRITE / NEWER / SKIP / RENAME, apply to the rest)."""

    def __init__(self, parent, transfer, existing):
        super().__init__(parent)
        self.setWindowTitle("File Exists")
        self.result_value = (SKIP, False)
        where = "on the server" if transfer.direction == UPLOAD else "on this computer"
        layout = QVBoxLayout(self)
        heading = QLabel(f"<b>{existing.name or transfer.name}</b> already exists {where}.")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        form = QFormLayout()
        form.addRow("Existing:", QLabel(f"{format_size(existing.size)}, modified {format_time(existing.mtime)}"))
        form.addRow("New:", QLabel(f"{format_size(transfer.size)}, modified {format_time(transfer.source_mtime)}"))
        layout.addLayout(form)
        newer = transfer.source_mtime > existing.mtime
        hint = QLabel("The new file is newer." if newer else "The existing file is newer (or the same age).")
        set_hint(hint, hint.text(), "info" if newer else "warning")
        layout.addWidget(hint)
        self.remember = QCheckBox("Do the same for the rest of the queue")
        layout.addWidget(self.remember)
        buttons = QHBoxLayout()
        for label, choice in (("Overwrite", OVERWRITE), ("Overwrite if Newer", NEWER), ("Rename", RENAME),
                              ("Skip", SKIP)):
            button = QPushButton(label)
            button.clicked.connect(lambda _, choice=choice: self.choose(choice))
            buttons.addWidget(button)
            if choice == (OVERWRITE if newer else SKIP):
                button.setDefault(True)
        layout.addLayout(buttons)

    def choose(self, choice):
        self.result_value = (choice, self.remember.isChecked())
        self.accept()


class PropertiesDialog(QDialog):
    """Details of remote files, their permissions (chmod) and owner (chown). users and groups are the server's
    names, for the lists. On OK: mode_changed / mode, owner_change, group_change and recursive say what to do."""

    def __init__(self, parent, entries, users=(), groups=()):
        super().__init__(parent)
        self.entries = entries
        first = entries[0]
        self.setWindowTitle(f"Properties of {first.name}" if len(entries) == 1 else
                            f"Properties of {len(entries)} items")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        if len(entries) == 1:
            form.addRow("Name:", self.selectable(first.name))
            form.addRow("Location:", self.selectable(posixpath.dirname(first.path) or "/"))
            if first.is_link:
                form.addRow("Link to:", self.selectable(first.link_target or "(unknown)"))
            form.addRow("Size:", QLabel("Folder" if first.is_dir else f"{format_size(first.size)} "
                                                                          f"({first.size:,} bytes)"))
            form.addRow("Modified:", QLabel(format_time(first.mtime)))
        else:
            files = [entry for entry in entries if not entry.is_dir]
            form.addRow("Selected:", QLabel(f"{len(entries) - len(files)} folders, {len(files)} files "
                                            f"({format_size(sum(entry.size for entry in files))})"))
        layout.addLayout(form)

        box = QGroupBox("Permissions")
        grid = QGridLayout(box)
        self.checks = {}
        for column, name in enumerate(("Read", "Write", "Execute"), 1):
            grid.addWidget(QLabel(name), 0, column, Qt.AlignCenter)
        for row, (who, shift) in enumerate((("Owner", 6), ("Group", 3), ("Others", 0)), 1):
            grid.addWidget(QLabel(who), row, 0)
            for column, bit in enumerate((4, 2, 1), 1):
                check = QCheckBox()
                check.toggled.connect(self.update_octal)
                self.checks[bit << shift] = check
                grid.addWidget(check, row, column, Qt.AlignCenter)
        specials = QHBoxLayout()
        for label, bit, tip in (("Set UID", stat.S_ISUID, "Runs as the file's owner"),
                                ("Set GID", stat.S_ISGID, "Runs as the file's group; new files in a folder get "
                                                          "its group"),
                                ("Sticky", stat.S_ISVTX, "In a folder: only owners can delete their files")):
            check = QCheckBox(label)
            check.setToolTip(tip)
            check.toggled.connect(self.update_octal)
            self.checks[bit] = check
            specials.addWidget(check)
        grid.addLayout(specials, 4, 0, 1, 4)
        octal_row = QHBoxLayout()
        octal_row.addWidget(QLabel("Octal:"))
        self.octal = QLineEdit()
        self.octal.setMaximumWidth(70)
        self.octal.setToolTip("Such as 644 or 0755")
        self.octal.textEdited.connect(self.octal_edited)
        self.symbolic = QLabel()
        self.symbolic.setFont(QFont("Consolas"))
        octal_row.addWidget(self.octal)
        octal_row.addWidget(self.symbolic)
        octal_row.addStretch(1)
        grid.addLayout(octal_row, 5, 0, 1, 4)
        layout.addWidget(box)
        owners = QGroupBox("Owner")
        owner_form = QFormLayout(owners)
        self.original_owner = first.owner if len({entry.owner for entry in entries}) == 1 else ""
        self.original_group = first.group if len({entry.group for entry in entries}) == 1 else ""
        self.owner_combo, self.group_combo = QComboBox(), QComboBox()
        for combo, names, current in ((self.owner_combo, users, self.original_owner),
                                      (self.group_combo, groups, self.original_group)):
            combo.setEditable(True)
            combo.addItems(list(names))
            combo.setCurrentText(current)
            combo.lineEdit().setPlaceholderText("(different)" if not current else "")
        self.owner_combo.setToolTip("A user name from the server, or a number (uid)")
        self.group_combo.setToolTip("A group name from the server, or a number (gid)")
        owner_form.addRow("User:", self.owner_combo)
        owner_form.addRow("Group:", self.group_combo)
        owner_note = QLabel("Changing the owner usually needs root: right-click the tab > Work as Root (sudo).")
        owner_note.setWordWrap(True)
        set_hint(owner_note, owner_note.text(), "info")
        owner_form.addRow(owner_note)
        layout.addWidget(owners)
        self.recursive = QCheckBox("Also apply to everything inside (folders get Execute wherever Read is set)")
        self.recursive.setVisible(any(entry.is_dir for entry in entries))
        layout.addWidget(self.recursive)
        if len({entry.mode for entry in entries}) > 1:
            note = QLabel("The selected items have different permissions; these are the first one's.")
            set_hint(note, note.text(), "warning")
            layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.original = first.mode & 0o7777
        self.set_mode(self.original)

    @staticmethod
    def selectable(text):
        label = QLabel(text)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        return label

    @property
    def mode(self):
        return sum(bit for bit, check in self.checks.items() if check.isChecked())

    @property
    def mode_changed(self):
        return self.mode != self.original or self.recursive.isChecked() or \
            len({entry.mode & 0o7777 for entry in self.entries}) > 1

    @property
    def owner_change(self):
        """The new owner, or None to leave it."""
        text = self.owner_combo.currentText().strip()
        return text if text and text != self.original_owner else None

    @property
    def group_change(self):
        text = self.group_combo.currentText().strip()
        return text if text and text != self.original_group else None

    def set_mode(self, mode):
        for bit, check in self.checks.items():
            check.blockSignals(True)
            check.setChecked(bool(mode & bit))
            check.blockSignals(False)
        self.update_octal()

    def update_octal(self):
        mode = self.mode
        self.octal.setText(f"{mode:04o}" if mode > 0o777 else f"{mode:03o}")
        self.symbolic.setText(permission_text(mode))

    def octal_edited(self, text):
        try:
            mode = int(text.strip() or "0", 8)
        except ValueError:
            return
        if 0 <= mode <= 0o7777:
            for bit, check in self.checks.items():
                check.blockSignals(True)
                check.setChecked(bool(mode & bit))
                check.blockSignals(False)
            self.symbolic.setText(permission_text(mode))


class ChecksumDialog(QDialog):
    """A remote file's hash, worked out on the server, and comparing it with an expected value or a local file."""

    def __init__(self, parent, view, entry):
        super().__init__(parent)
        self.view, self.entry = view, entry
        self.setWindowTitle(f"Checksum of {entry.name}")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        row = QHBoxLayout()
        row.addWidget(QLabel("Algorithm:"))
        self.algorithm = QComboBox()
        self.algorithm.addItems(list(HASHES))
        row.addWidget(self.algorithm)
        row.addStretch(1)
        layout.addLayout(row)
        self.result = QLineEdit()
        self.result.setReadOnly(True)
        self.result.setFont(QFont("Consolas"))
        copy_row = QHBoxLayout()
        copy_row.addWidget(self.result, 1)
        copy_button = QPushButton("Copy")
        copy_button.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.result.text()))
        copy_row.addWidget(copy_button)
        layout.addWidget(QLabel(f"{entry.path} on the server:"))
        layout.addLayout(copy_row)
        layout.addWidget(QLabel("Compare with (paste the expected value, such as from the vendor's download page):"))
        self.expected = QLineEdit()
        self.expected.setFont(QFont("Consolas"))
        layout.addWidget(self.expected)
        local_row = QHBoxLayout()
        local_button = QPushButton("Compare with a Local File...")
        local_row.addWidget(local_button)
        local_row.addStretch(1)
        layout.addLayout(local_row)
        self.verdict = QLabel()
        self.verdict.setWordWrap(True)
        layout.addWidget(self.verdict)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.algorithm.currentTextChanged.connect(self.calculate)
        self.expected.textChanged.connect(self.check)
        local_button.clicked.connect(self.compare_local)
        self.calculate()

    def calculate(self):
        algorithm = self.algorithm.currentText()
        self.result.setText("")
        set_hint(self.verdict, f"Working out the {algorithm} on the server...", "info")
        path = self.entry.path

        def done(value):
            if algorithm == self.algorithm.currentText():
                self.result.setText(value)
                self.check()

        def failed(message):
            set_hint(self.verdict, message, "error")
        self.view.submit(lambda fs: fs.checksum(path, algorithm), done, failed)

    def check(self):
        mine, expected = self.result.text(), self.expected.text().strip().lower()
        if not mine:
            return
        if not expected:
            set_hint(self.verdict, "", "info")
        elif expected == mine:
            set_hint(self.verdict, "✓ They match.", "success")
        else:
            set_hint(self.verdict, "✗ They don't match.", "error")

    def compare_local(self):
        path, _ = QFileDialog.getOpenFileName(self, "Compare with a Local File", self.view.local.path or "")
        if not path:
            return
        algorithm = self.algorithm.currentText()
        set_hint(self.verdict, f"Working out the {algorithm} of {os.path.basename(path)}...", "info")
        self.view.submit(lambda fs: local_hash(path, algorithm), self.expected.setText,
                         lambda message: set_hint(self.verdict, message, "error"))


STATUS_COLORS = {LOCAL_ONLY: "success", REMOTE_ONLY: "link", LOCAL_NEWER: "success", REMOTE_NEWER: "link",
                 DIFFERENT: "warning", SAME: "muted"}
ACTION_TEXT = {UPLOAD: "↑ Upload", DOWNLOAD: "↓ Download", "": ""}


class SyncDialog(QDialog):
    """Compare a local folder with a remote one, review the differences, then queue the copies."""

    def __init__(self, parent, view, local_folder, remote_folder):
        super().__init__(parent)
        self.view = view
        self.differences = []
        self.stop_event = threading.Event()
        self.comparing = False
        self.setWindowTitle("Synchronize")
        self.resize(900, 560)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        local_row = QHBoxLayout()
        self.local_input = QLineEdit(local_folder)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self.browse_local)
        local_row.addWidget(self.local_input, 1)
        local_row.addWidget(browse)
        form.addRow("Local folder:", local_row)
        self.remote_input = QLineEdit(remote_folder)
        form.addRow("Remote folder:", self.remote_input)
        layout.addLayout(form)

        options = QHBoxLayout()
        self.direction_group = QButtonGroup(self)
        for label, direction, tip in (
                ("Upload changes to the server", TO_REMOTE, "Make the server match this computer (files newer on "
                                                            "the server are listed but not ticked)"),
                ("Download changes from the server", TO_LOCAL, "Make this computer match the server"),
                ("Both ways (newer wins)", BOTH_WAYS, "Copy each file that's only on one side, or newer there")):
            radio = QRadioButton(label)
            radio.setToolTip(tip)
            radio.setProperty("direction", direction)
            self.direction_group.addButton(radio)
            options.addWidget(radio)
        self.direction_group.buttons()[0].setChecked(True)
        options.addStretch(1)
        layout.addLayout(options)
        options2 = QHBoxLayout()
        self.by_checksum = QCheckBox("Compare contents by checksum (slower; finds edits that kept the same size)")
        options2.addWidget(self.by_checksum)
        self.show_same = QCheckBox("Show identical files")
        options2.addWidget(self.show_same)
        options2.addStretch(1)
        self.compare_button = QPushButton("Compare")
        self.compare_button.setDefault(True)
        options2.addWidget(self.compare_button)
        layout.addLayout(options2)

        self.tree = QTreeWidget()
        self.tree.setRootIsDecorated(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.setHeaderLabels(["File", "Difference", "Local size", "Local modified", "Remote size",
                                   "Remote modified", "Action"])
        ColumnFitter(self.tree, stretch=0)
        self.tree.setToolTip("Tick the files to copy. Right-click to choose upload or download for the selected "
                             "files.")
        layout.addWidget(self.tree, 1)
        self.summary = QLabel("Choose the folders and a direction, then Compare. Nothing is copied until you press "
                              "Synchronize.")
        self.summary.setWordWrap(True)
        layout.addWidget(self.summary)
        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.sync_button = QPushButton("Synchronize")
        self.sync_button.setEnabled(False)
        close = QPushButton("Close")
        buttons.addWidget(self.sync_button)
        buttons.addWidget(close)
        layout.addLayout(buttons)

        self.compare_button.clicked.connect(self.compare)
        self.sync_button.clicked.connect(self.synchronize)
        close.clicked.connect(self.reject)
        self.show_same.toggled.connect(self.fill)
        self.direction_group.buttonToggled.connect(lambda *_: self.apply_direction())
        self.tree.customContextMenuRequested.connect(self.show_menu)
        self.tree.itemChanged.connect(lambda *_: self.update_summary())

    @property
    def direction(self):
        return self.direction_group.checkedButton().property("direction")

    def browse_local(self):
        folder = QFileDialog.getExistingDirectory(self, "Local Folder", self.local_input.text())
        if folder:
            self.local_input.setText(os.path.normpath(folder))

    # ----------------------------------------------------------------- Comparing

    def compare(self):
        if self.comparing:
            self.stop_event.set()
            return
        local_root = self.local_input.text().strip()
        remote_root = self.remote_input.text().strip() or "/"
        if not os.path.isdir(local_root):
            set_hint(self.summary, f"{local_root or 'The local folder'} isn't a folder on this computer.", "error")
            return
        self.stop_event.clear()
        self.comparing = True
        self.compare_button.setText("Stop")
        self.sync_button.setEnabled(False)
        set_hint(self.summary, "Comparing...", "info")
        direction, by_checksum, stop = self.direction, self.by_checksum.isChecked(), self.stop_event

        def work(fs):
            cancelled = stop.is_set
            mine = local_files(local_root, cancelled)
            theirs = remote_files(fs, remote_root, cancelled)
            def same_contents(relative):
                if cancelled():
                    raise TransferCancelled()
                local_path = os.path.join(local_root, *relative.split("/"))
                return local_hash(local_path, "SHA-256", cancelled) == \
                    fs.checksum(theirs[relative].path, "SHA-256", cancelled)
            return compare(mine, theirs, direction, same_contents if by_checksum else None)

        self.local_root, self.remote_root = local_root, remote_root
        self.view.submit(work, self.compared, self.compare_failed)

    def compared(self, differences):
        self.comparing = False
        self.compare_button.setText("Compare")
        self.differences = differences
        self.fill()

    def compare_failed(self, message):
        self.comparing = False
        self.compare_button.setText("Compare")
        set_hint(self.summary, "Stopped." if message == "Cancelled." else message, "error")

    def apply_direction(self):
        """A new direction changes what each difference should do (the comparison itself stays)."""
        for difference in self.differences:
            difference.action = suggested_action(difference.status, self.direction)
        self.fill()

    def fill(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        for difference in self.differences:
            if difference.status == SAME and not self.show_same.isChecked():
                continue
            item = QTreeWidgetItem([
                difference.relative, difference.status,
                format_size(difference.local_size) if difference.local else "",
                format_time(difference.local_mtime) if difference.local else "",
                format_size(difference.remote.size) if difference.remote else "",
                format_time(difference.remote.mtime) if difference.remote else "",
                ACTION_TEXT[difference.action]])
            item.setData(0, Qt.UserRole, difference)
            item.setForeground(1, QColor(COLORS[STATUS_COLORS[difference.status]]))
            if difference.status != SAME:
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(0, Qt.Checked if difference.action else Qt.Unchecked)
            self.tree.addTopLevelItem(item)
        self.tree.blockSignals(False)
        self.update_summary()

    def checked(self):
        """The differences ticked, with an action."""
        found = []
        self.tree.blockSignals(True)
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            difference = item.data(0, Qt.UserRole)
            if item.checkState(0) == Qt.Checked:
                if not difference.action:
                    difference.action = self.natural_action(difference)
                    item.setText(6, ACTION_TEXT[difference.action])
                if difference.action:
                    found.append(difference)
        self.tree.blockSignals(False)
        return found

    def natural_action(self, difference):
        """Ticked without a suggestion (such as a newer file on the other side): copy in the chosen direction."""
        if difference.status == LOCAL_ONLY:
            return UPLOAD
        if difference.status == REMOTE_ONLY:
            return DOWNLOAD
        if self.direction == TO_REMOTE:
            return UPLOAD
        if self.direction == TO_LOCAL:
            return DOWNLOAD
        return UPLOAD if difference.status == LOCAL_NEWER else DOWNLOAD if difference.status == REMOTE_NEWER else ""

    def update_summary(self):
        if self.comparing:
            return
        chosen = self.checked()
        uploads = [item for item in chosen if item.action == UPLOAD]
        downloads = [item for item in chosen if item.action == DOWNLOAD]
        different = sum(1 for item in self.differences if item.status != SAME)
        same = len(self.differences) - different
        if not self.differences:
            set_hint(self.summary, "The folders are both empty.", "info")
        elif not different:
            set_hint(self.summary, f"The folders match ({same} identical file{'' if same == 1 else 's'}).",
                     "success")
        else:
            upload_size = sum(item.local_size or 0 for item in uploads)
            download_size = sum(item.remote.size for item in downloads if item.remote)
            set_hint(self.summary, f"{different} difference{'' if different == 1 else 's'}, {same} identical. "
                                   f"Ticked: {len(uploads)} to upload ({format_size(upload_size)}), "
                                   f"{len(downloads)} to download ({format_size(download_size)}).", "info")
        self.sync_button.setEnabled(bool(chosen))

    def show_menu(self, position):
        items = [item for item in self.tree.selectedItems() if item.flags() & Qt.ItemIsUserCheckable]
        if not items:
            return
        menu = QMenu(self)
        upload = menu.addAction("Upload (this computer's copy wins)")
        download = menu.addAction("Download (the server's copy wins)")
        menu.addAction("Don't Copy")
        upload.setEnabled(all(item.data(0, Qt.UserRole).local for item in items))
        download.setEnabled(all(item.data(0, Qt.UserRole).remote for item in items))
        chosen = menu.exec_(self.tree.viewport().mapToGlobal(position))
        if chosen is None:
            return
        action = UPLOAD if chosen is upload else DOWNLOAD if chosen is download else ""
        self.tree.blockSignals(True)
        for item in items:
            difference = item.data(0, Qt.UserRole)
            difference.action = action
            item.setText(6, ACTION_TEXT[action])
            item.setCheckState(0, Qt.Checked if action else Qt.Unchecked)
        self.tree.blockSignals(False)
        self.update_summary()

    # ----------------------------------------------------------------- Copying

    def synchronize(self):
        chosen = self.checked()
        if not chosen:
            return
        overwriting = [item for item in chosen if item.local and item.remote and
                       ((item.action == UPLOAD and item.status == REMOTE_NEWER) or
                        (item.action == DOWNLOAD and item.status == LOCAL_NEWER))]
        if overwriting:
            reply = QMessageBox.question(self, "Synchronize",
                                         f"{len(overwriting)} of the ticked files will replace a newer copy "
                                         f"(such as {overwriting[0].relative}). Continue?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        self.view.queue_sync(self.local_root, self.remote_root, chosen)
        self.accept()

    def reject(self):
        self.stop_event.set()
        super().reject()
