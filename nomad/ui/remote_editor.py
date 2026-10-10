"""Editing files on the server: a built-in text editor (saving uploads straight back), or any program on this
computer (NOMAD watches the downloaded copy and uploads it each time it's saved)."""
import codecs
import logging
import os
import shutil
import subprocess
import tempfile
import time
import uuid

from PyQt5.QtCore import QObject, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QFont, QKeySequence, QTextCursor, QTextDocument
from PyQt5.QtWidgets import QAction, QCheckBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMainWindow, \
    QMessageBox, QPlainTextEdit, QPushButton, QVBoxLayout, QWidget

from .common import format_size, set_hint
from .terminal_view import CONNECTED

log = logging.getLogger(__name__)

EDITOR_LIMIT = 10 * 1024 * 1024  # Bigger files are better in an external editor
EDIT_FOLDER = os.path.join(tempfile.gettempdir(), "NOMAD edits")


def decode(data):
    """(text with \\n line endings, encoding, line ending) for a file's bytes. latin-1 keeps any bytes as they were."""
    if data.startswith(codecs.BOM_UTF8):
        encoding = "utf-8-sig"
    else:
        try:
            data.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            encoding = "latin-1"
    text = data.decode(encoding)
    ending = "\r\n" if "\r\n" in text else "\n"
    return text.replace("\r\n", "\n"), encoding, ending


def encode(text, encoding, ending):
    return text.replace("\n", ending).encode(encoding, errors="replace")


def looks_binary(data):
    return b"\x00" in data[:8192]


class RemoteEditor(QMainWindow):
    """A text editor for one remote file. Saving goes through view.save_remote_file."""

    def __init__(self, view, entry, data, mtime):
        super().__init__()
        self.view, self.entry, self.mtime = view, entry, mtime
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.saving = False
        self.close_after_save = False
        text, self.encoding, self.ending = decode(data)
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.editor = QPlainTextEdit()
        self.editor.setLineWrapMode(QPlainTextEdit.NoWrap)
        font = QFont("Consolas")
        font.setStyleHint(QFont.Monospace)
        font.setPointSizeF(max(9.0, self.font().pointSizeF()))
        self.editor.setFont(font)
        self.editor.setTabStopDistance(self.editor.fontMetrics().horizontalAdvance(" ") * 4)
        self.editor.setPlainText(text)
        self.editor.document().setModified(False)
        layout.addWidget(self.editor, 1)

        # Find and replace
        self.find_bar = QWidget()
        find_layout = QVBoxLayout(self.find_bar)
        find_layout.setContentsMargins(6, 4, 6, 4)
        row = QHBoxLayout()
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find")
        self.case = QCheckBox("Match case")
        previous_button, next_button = QPushButton("Previous"), QPushButton("Next")
        row.addWidget(self.find_input, 1)
        row.addWidget(self.case)
        row.addWidget(previous_button)
        row.addWidget(next_button)
        find_layout.addLayout(row)
        self.replace_row = QWidget()
        replace_layout = QHBoxLayout(self.replace_row)
        replace_layout.setContentsMargins(0, 0, 0, 0)
        self.replace_input = QLineEdit()
        self.replace_input.setPlaceholderText("Replace with")
        replace_button, replace_all_button = QPushButton("Replace"), QPushButton("Replace All")
        replace_layout.addWidget(self.replace_input, 1)
        replace_layout.addWidget(replace_button)
        replace_layout.addWidget(replace_all_button)
        find_layout.addWidget(self.replace_row)
        self.find_status = QLabel()
        find_layout.addWidget(self.find_status)
        self.find_bar.setVisible(False)
        layout.addWidget(self.find_bar)
        self.setCentralWidget(central)

        self.position_label = QLabel()
        self.statusBar().addPermanentWidget(self.position_label)
        self.statusBar().showMessage(f"{entry.path} on {view.session.name}  ·  {format_size(len(data))}")

        file_menu = self.menuBar().addMenu("&File")
        self.add_action(file_menu, "&Save to Server", QKeySequence.Save, self.save)
        self.add_action(file_menu, "&Reload from Server", None, self.reload)
        file_menu.addSeparator()
        self.add_action(file_menu, "&Close", QKeySequence("Ctrl+W"), self.close)
        edit_menu = self.menuBar().addMenu("&Edit")
        self.add_action(edit_menu, "&Find...", QKeySequence.Find, lambda: self.show_find(False))
        self.add_action(edit_menu, "&Replace...", QKeySequence("Ctrl+H"), lambda: self.show_find(True))
        self.add_action(edit_menu, "Find &Next", QKeySequence("F3"), lambda: self.find(False))
        self.add_action(edit_menu, "Find &Previous", QKeySequence("Shift+F3"), lambda: self.find(True))
        self.add_action(edit_menu, "&Go to Line...", QKeySequence("Ctrl+G"), self.go_to_line)
        self.escape = QAction(self)
        self.escape.setShortcut(QKeySequence("Escape"))
        self.escape.triggered.connect(self.hide_find)
        self.addAction(self.escape)

        self.find_input.returnPressed.connect(lambda: self.find(False))
        next_button.clicked.connect(lambda: self.find(False))
        previous_button.clicked.connect(lambda: self.find(True))
        replace_button.clicked.connect(self.replace)
        replace_all_button.clicked.connect(self.replace_all)
        self.editor.cursorPositionChanged.connect(self.update_position)
        self.editor.document().modificationChanged.connect(lambda _: self.update_title())
        self.resize(900, 650)
        self.update_title()
        self.update_position()

    @staticmethod
    def add_action(menu, text, shortcut, slot):
        action = menu.addAction(text)
        if shortcut is not None:
            action.setShortcut(shortcut)
        action.triggered.connect(slot)
        return action

    def update_title(self):
        modified = "*" if self.editor.document().isModified() else ""
        self.setWindowTitle(f"{modified}{self.entry.name} ({self.view.session.name}) - NOMAD Editor")

    def update_position(self):
        cursor = self.editor.textCursor()
        encoding = {"utf-8": "UTF-8", "utf-8-sig": "UTF-8 BOM", "latin-1": "Latin-1"}[self.encoding]
        self.position_label.setText(f"Ln {cursor.blockNumber() + 1}, Col {cursor.positionInBlock() + 1}  ·  "
                                    f"{encoding}  ·  {'CRLF' if self.ending == chr(13) + chr(10) else 'LF'}")

    # ----------------------------------------------------------------- Find and replace

    def show_find(self, replace):
        self.find_bar.setVisible(True)
        self.replace_row.setVisible(replace)
        selected = self.editor.textCursor().selectedText()
        if selected and " " not in selected:
            self.find_input.setText(selected)
        self.find_input.setFocus()
        self.find_input.selectAll()

    def hide_find(self):
        self.find_bar.setVisible(False)
        self.editor.setFocus()

    def flags(self, backward=False):
        flags = QTextDocument.FindFlags()
        if backward:
            flags |= QTextDocument.FindBackward
        if self.case.isChecked():
            flags |= QTextDocument.FindCaseSensitively
        return flags

    def find(self, backward=False):
        text = self.find_input.text()
        if not text:
            self.show_find(self.replace_row.isVisible())
            return False
        if self.editor.find(text, self.flags(backward)):
            self.find_status.setText("")
            return True
        cursor = self.editor.textCursor()  # Wrap around
        cursor.movePosition(QTextCursor.End if backward else QTextCursor.Start)
        self.editor.setTextCursor(cursor)
        if self.editor.find(text, self.flags(backward)):
            set_hint(self.find_status, "Wrapped around.", "info")
            return True
        set_hint(self.find_status, "Not found.", "warning")
        return False

    def replace(self):
        cursor = self.editor.textCursor()
        text = self.find_input.text()
        matches = cursor.selectedText() == text if self.case.isChecked() else \
            cursor.selectedText().lower() == text.lower()
        if cursor.hasSelection() and matches:
            cursor.insertText(self.replace_input.text())
        self.find(False)

    def replace_all(self):
        text = self.find_input.text()
        if not text:
            return
        cursor = self.editor.textCursor()
        cursor.beginEditBlock()
        cursor.movePosition(QTextCursor.Start)
        self.editor.setTextCursor(cursor)
        count = 0
        while self.editor.find(text, self.flags()):
            self.editor.textCursor().insertText(self.replace_input.text())
            count += 1
        cursor.endEditBlock()
        set_hint(self.find_status, f"Replaced {count}.", "info")

    def go_to_line(self):
        line, ok = QInputDialog.getInt(self, "Go to Line", "Line:", self.editor.textCursor().blockNumber() + 1, 1,
                                       self.editor.blockCount())
        if ok:
            cursor = QTextCursor(self.editor.document().findBlockByNumber(line - 1))
            self.editor.setTextCursor(cursor)
            self.editor.centerCursor()

    # ----------------------------------------------------------------- Saving

    def save(self, force=False):
        if self.saving:
            return
        if self.view.state != CONNECTED:
            QMessageBox.warning(self, "Save", "The SCP tab isn't connected. Reconnect it, then save again.")
            return
        self.saving = True
        self.statusBar().showMessage("Saving to the server...")
        data = encode(self.editor.toPlainText(), self.encoding, self.ending)
        self.view.save_remote_file(self.entry.path, data, None if force else self.mtime, self.saved,
                                   self.save_failed)

    def saved(self, result):
        self.saving = False
        status, mtime = result
        if status == "changed":
            reply = QMessageBox.warning(self, "Changed on the Server",
                                        f"{self.entry.name} has changed on the server since you opened it. Replace "
                                        "it with your version anyway?", QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.save(force=True)
            else:
                self.close_after_save = False
                self.statusBar().showMessage("Not saved.")
            return
        self.mtime = mtime
        self.editor.document().setModified(False)
        self.statusBar().showMessage(f"Saved to {self.entry.path}.", 5000)
        if self.close_after_save:
            self.close()

    def save_failed(self, message):
        self.saving = False
        self.close_after_save = False
        self.statusBar().showMessage("Not saved.")
        QMessageBox.critical(self, "Save", f"Couldn't save {self.entry.name}:\n\n{message}")

    def reload(self):
        if self.editor.document().isModified():
            reply = QMessageBox.question(self, "Reload", "Throw away your changes and load the server's copy again?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        def loaded(result):
            data, mtime = result
            text, self.encoding, self.ending = decode(data)
            self.editor.setPlainText(text)
            self.editor.document().setModified(False)
            self.mtime = mtime
            self.statusBar().showMessage("Reloaded.", 5000)
        self.view.read_remote_file(self.entry.path, loaded,
                                   lambda message: QMessageBox.critical(self, "Reload", message))

    def closeEvent(self, event):
        if self.editor.document().isModified() and not self.view.closing_all:
            reply = QMessageBox.question(self, "Unsaved Changes", f"Save your changes to {self.entry.name} on the "
                                         "server?", QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                                         QMessageBox.Save)
            if reply == QMessageBox.Cancel:
                event.ignore()
                return
            if reply == QMessageBox.Save:
                self.close_after_save = True
                self.save()
                event.ignore()
                return
        if self in self.view.editors:
            self.view.editors.remove(self)
        super().closeEvent(event)


class ExternalEdit(QObject):
    """A remote file opened in another program: its downloaded copy is watched, and uploaded when it changes."""
    changed = pyqtSignal(object)  # This edit, once the copy has been saved (and stopped changing)

    def __init__(self, entry, local_path, parent=None):
        super().__init__(parent)
        self.entry, self.local_path = entry, local_path
        self.stamp = self.read_stamp()
        self.pending = None
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.check)
        self.timer.start(1000)

    def read_stamp(self):
        try:
            info = os.stat(self.local_path)
            return info.st_mtime_ns, info.st_size
        except OSError:
            return None  # Editors sometimes delete and rewrite the file while saving

    def check(self):
        stamp = self.read_stamp()
        if stamp is None or stamp == self.stamp:
            self.pending = None
            return
        if stamp != self.pending:  # Wait for it to stop changing (a big save can take a moment)
            self.pending = stamp
            return
        self.stamp, self.pending = stamp, None
        self.changed.emit(self)

    def stop(self):
        self.timer.stop()


def edit_folder():
    """A new, empty folder for a downloaded copy (so two files with the same name don't clash)."""
    folder = os.path.join(EDIT_FOLDER, uuid.uuid4().hex[:8])
    os.makedirs(folder, exist_ok=True)
    return folder


def remove_edit_copy(path):
    shutil.rmtree(os.path.dirname(path), ignore_errors=True)


def clean_old_edits(max_age=2 * 86400, now=None):
    """Delete downloaded copies left behind (NOMAD closed without tidying up, such as a crash) once nothing in
    them has changed for max_age seconds; newer ones may still be open in an editor. Returns how many went."""
    now = time.time() if now is None else now
    removed = 0
    try:
        folders = [entry.path for entry in os.scandir(EDIT_FOLDER) if entry.is_dir()]
    except OSError:
        return 0
    for folder in folders:
        try:
            newest = max([os.path.getmtime(folder)] + [entry.stat().st_mtime for entry in os.scandir(folder)])
        except OSError:
            continue
        if now - newest > max_age:
            shutil.rmtree(folder, ignore_errors=True)
            removed += 1
    return removed


def open_in_program(path, program=""):
    """Open a file in a program (or Windows' choice for its type). Returns an error message, or ""."""
    try:
        if program:
            subprocess.Popen([program, path], close_fds=True)
        else:
            os.startfile(path)
    except OSError as error:
        return f"Couldn't open {os.path.basename(path)}{' in ' + os.path.basename(program) if program else ''}: " \
               f"{error.strerror or error}"
    return ""
