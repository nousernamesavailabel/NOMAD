"""One SCP tab: this computer's files beside the server's, a transfer queue, and the SSH connection behind them."""
import io
import logging
import os
import tempfile
import threading

from PyQt5.QtCore import QFile, QSettings, QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QGuiApplication
from PyQt5.QtWidgets import QFileDialog, QHBoxLayout, QInputDialog, QLabel, QMenu, QMessageBox, QSplitter, \
    QVBoxLayout, QWidget

from ..terminal.files import CANCELLED, DONE, DOWNLOAD, FAILED, OVERWRITE, PAUSED, QUEUED, RUNNING, UPLOAD, Entry, \
    FileConnection, RemoteError, SCP, Transfer, TransferRunner, chmod_tree, chown_tree, join, parent as remote_parent, remove_tree
from .common import format_size, release_thread, set_hint
from .file_panes import LocalPane, RemotePane
from .prompts import PromptAnswers, UiPrompter
from .remote_editor import EDITOR_LIMIT, ExternalEdit, RemoteEditor, edit_folder, looks_binary, open_in_program, \
    remove_edit_copy
from .scp_dialogs import ChecksumDialog, ConflictDialog, PropertiesDialog, SyncDialog
from .scp_workers import ConnectThread, TaskWorker, TransferWorker
from .terminal_view import CONNECTED, CONNECTING, DISCONNECTED
from .transfer_queue import QueuePanel

log = logging.getLogger(__name__)

ALIVE_CHECK_MS = 5000
EDITOR_SETTING = "scp/editor"  # The program chosen with Edit With > Choose Program


class FileSessionView(PromptAnswers, QWidget):
    state_changed = pyqtSignal(object)  # This view
    question = pyqtSignal(object)  # A _Request from the connection thread

    def __init__(self, session, store, page, parent=None):
        super().__init__(parent)
        self.session, self.store, self.page = session, store, page
        self.state = DISCONNECTED
        self.connection = None
        self.connect_thread = None
        self.worker = None
        self.transfer_worker = None
        self.transfers = []  # Shared with the transfer worker, under self.lock
        self.lock = threading.Lock()
        self.editors = []
        self.external_edits = []
        self.closing_all = False
        self.sudo = bool(getattr(session, "scp_sudo", False))  # Working as root
        self.prompter = UiPrompter(self)
        self.question.connect(self.answer, Qt.QueuedConnection)
        self.pending_refresh = set()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 2)
        layout.setSpacing(4)
        self.local = LocalPane(id(self))
        self.remote = RemotePane(id(self))
        self.remote.open_requested = self.open_remote_file
        panes = QSplitter(Qt.Horizontal)
        panes.addWidget(self.local)
        panes.addWidget(self.remote)
        panes.setSizes([500, 500])
        self.queue = QueuePanel()
        vertical = QSplitter(Qt.Vertical)
        vertical.addWidget(panes)
        vertical.addWidget(self.queue)
        vertical.setStretchFactor(0, 3)
        vertical.setStretchFactor(1, 1)
        vertical.setSizes([450, 160])
        layout.addWidget(vertical, 1)
        status_row = QHBoxLayout()
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        self.busy_label = QLabel()
        status_row.addWidget(self.status_label, 1)
        status_row.addWidget(self.busy_label)
        layout.addLayout(status_row)

        for pane in (self.local, self.remote):
            pane.command_requested.connect(lambda name, pane=pane: self.command(pane, name))
            pane.list.dropped.connect(lambda payload, target, pane=pane: self.on_dropped(pane, payload, target))
            pane.list.customContextMenuRequested.connect(lambda position, pane=pane: self.show_menu(pane, position))
            pane.navigated.connect(lambda path, pane=pane: self.remember_folder(pane, path))
        self.queue.pause_toggled.connect(self.set_paused)
        self.queue.cancel_requested.connect(self.cancel_transfers)
        self.queue.retry_requested.connect(self.retry_transfers)
        self.queue.policy_changed.connect(self.set_policy)
        self.alive_timer = QTimer(self)
        self.alive_timer.timeout.connect(self.check_alive)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setSingleShot(True)
        self.refresh_timer.timeout.connect(self.refresh_after_transfers)

        self.remote.set_connected(False)
        self.update_root_title()
        local_folder = self.settings().value(f"{self.folder_key}/local", "", str)
        self.local.go(local_folder if local_folder and os.path.isdir(local_folder) else self.local.home())
        self.set_status("Not connected.", "info")

    # ----------------------------------------------------------------- In a tab (see session_tabs)

    @property
    def title(self):
        return self.session.name

    def focus_target(self):
        return self.remote.list if self.state == CONNECTED else self.local.list

    def add_tab_actions(self, menu, actions):
        synchronize = menu.addAction("Synchronize...")
        synchronize.setEnabled(self.state == CONNECTED)
        actions[synchronize] = self.show_sync
        hidden = menu.addAction("Show Hidden Files")
        hidden.setCheckable(True)
        hidden.setChecked(self.remote.show_hidden)
        actions[hidden] = self.toggle_hidden
        actions[self.add_sudo_action(menu)] = self.toggle_sudo

    def add_sudo_action(self, menu):
        action = menu.addAction("Work as Root (sudo)")
        action.setCheckable(True)
        action.setChecked(self.sudo)
        action.setToolTip("Reconnect this tab as root, running SFTP through sudo")
        return action

    def update_root_title(self):
        self.remote.set_title("Remote (as root)" if self.sudo else "Remote", warning=self.sudo)

    def toggle_sudo(self):
        """Switch between working as the login user and as root. Reconnects the tab (if it's connected)."""
        if not self.sudo and self.connection is not None and self.connection.mode == SCP:
            self.fail("Work as Root", "Sudo needs SFTP. Set this session's File transfer to Auto or SFTP (Edit "
                                      "Session), then try again.")
            return
        problems = self.problems() if self.state != DISCONNECTED else []
        if problems:
            reply = QMessageBox.question(self, "Work as Root", f"Switching reconnects {self.session.name}, which has "
                                         + " and ".join(problems) + ". Switch anyway?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        self.sudo = not self.sudo
        self.update_root_title()
        if self.state != DISCONNECTED:
            self.reconnect()

    def problems(self):
        """What closing this tab would lose, as phrases ("2 transfers still to finish")."""
        active = [transfer for transfer in self.queue.active() if not transfer.is_dir]
        unsaved = [editor for editor in self.editors if editor.editor.document().isModified()]
        problems = []
        if active:
            problems.append(f"{len(active)} transfer{'' if len(active) == 1 else 's'} still to finish")
        if unsaved:
            problems.append(f"unsaved changes in {len(unsaved)} editor window{'' if len(unsaved) == 1 else 's'}")
        if self.external_edits:
            problems.append(f"{len(self.external_edits)} file{'' if len(self.external_edits) == 1 else 's'} open in "
                            "another program (later saves won't be uploaded)")
        return problems

    def confirm_close(self):
        problems = self.problems()
        if not problems:
            return True
        reply = QMessageBox.question(self, "Close", f"{self.session.name} has " + " and ".join(problems) +
                                     ". Close it anyway?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        return reply == QMessageBox.Yes

    # ----------------------------------------------------------------- Status

    def set_state(self, state, detail=""):
        self.state = state
        self.state_changed.emit(self)
        if state == CONNECTING:
            self.set_status(f"Connecting to {self.session.target()}...", "info")
        elif state == CONNECTED:
            self.set_status(detail, "success")
        else:
            self.set_status(detail or "Not connected.", "info")

    def set_status(self, text, kind="info"):
        set_hint(self.status_label, text, kind)

    def report(self, message, warning):
        """A note from saving a password (PromptAnswers)."""
        self.set_status(message, "warning" if warning else "info")

    def settings(self):
        return QSettings()

    @property
    def folder_key(self):
        """Where the last folders used with this server are kept (quick connections included)."""
        session = self.session
        identity = f"{session.username}@{session.host}:{session.port}".replace("/", "_").replace("\\", "_")
        return f"scp/folders/{identity}"

    def remember_folder(self, pane, path):
        if pane is self.local and path or pane is self.remote and self.state == CONNECTED:
            self.settings().setValue(f"{self.folder_key}/{pane.side}", path)

    # ----------------------------------------------------------------- Connecting

    def connect_session(self):
        if self.state != DISCONNECTED:
            return
        self.set_state(CONNECTING)
        self.prompter = UiPrompter(self)  # A fresh one: the last connection's was cancelled when it closed
        self.connection = FileConnection(self.session, self.prompter, self.store.vault if self.store else None,
                                         sudo=self.sudo)
        self.connect_thread = ConnectThread(self.connection, self)
        self.connect_thread.connected.connect(self.on_connected)
        self.connect_thread.failed.connect(self.on_failed)
        self.connect_thread.start()

    def on_connected(self, fs):
        connection = self.connection
        if connection is None:
            return
        self.worker = TaskWorker(fs, self)
        self.worker.busy_changed.connect(self.show_busy)
        self.worker.start()
        self.remote.worker = self.worker
        self.transfer_worker = TransferWorker(connection, self.transfers, self.lock, self)
        self.transfer_worker.conflict_policy = self.queue.policy.currentData()
        self.transfer_worker.paused = self.queue.pause_button.isChecked()
        self.transfer_worker.changed.connect(self.queue.update)
        self.transfer_worker.added.connect(self.on_transfers_added)
        self.transfer_worker.finished_one.connect(self.on_transfer_finished)
        self.transfer_worker.conflict.connect(self.ask_conflict, Qt.QueuedConnection)
        self.transfer_worker.connection_lost.connect(self.on_connection_lost)
        self.transfer_worker.start()
        self.remote.set_connected(True)
        self.set_state(CONNECTED, connection.description)
        if connection.notice:
            self.set_status(f"{connection.description}. {connection.notice}", "warning")
        self.alive_timer.start(ALIVE_CHECK_MS)
        remembered = self.settings().value(f"{self.folder_key}/remote", "", str)

        def got_home(home):
            self.remote.home_path = home
            self.remote.go(remembered or home)

        def no_home(_message):
            self.remote.go(remembered or "/")
        self.worker.submit(lambda fs: fs.home(), got_home, no_home)
        self.remote.list.setFocus()
        log.info("Connected: %s", connection.description)

    def on_failed(self, message):
        self.connection = None
        self.connect_thread = None
        self.set_state(DISCONNECTED, message)
        set_hint(self.status_label, message, "error")

    def check_alive(self):
        if self.state == CONNECTED and (self.connection is None or not self.connection.active):
            self.on_connection_lost("The connection closed.")

    def on_connection_lost(self, message):
        if self.state != CONNECTED:
            return
        self.close_connection()
        self.set_state(DISCONNECTED, f"{message} Reconnect from the tab's right-click menu, then Retry any "
                                     "transfers that didn't finish.")
        set_hint(self.status_label, self.status_label.text(), "error")

    def reconnect(self):
        self.disconnect_session()
        self.connect_session()

    def disconnect_session(self):
        if self.state == DISCONNECTED:
            return
        self.close_connection()
        self.set_state(DISCONNECTED, "Disconnected.")

    def close_connection(self):
        self.alive_timer.stop()
        self.prompter.cancel_all()
        for thread in (self.connect_thread, self.transfer_worker, self.worker):
            if thread is not None:
                thread.stop()
        if self.connection is not None:
            self.connection.close()  # Unblocks anything waiting on the network
        for thread in (self.connect_thread, self.transfer_worker, self.worker):
            if thread is not None:
                release_thread(thread, 200 if thread is self.connect_thread else 3000)
        self.connect_thread = self.transfer_worker = self.worker = self.connection = None
        self.remote.worker = None
        self.remote.set_connected(False)
        self.busy_label.setText("")
        with self.lock:
            for transfer in self.transfers:
                if transfer.state in (RUNNING, QUEUED):
                    transfer.state, transfer.message = FAILED, "Disconnected"
                    self.queue.update(transfer)

    def shutdown(self):
        """The tab is closing: close editors and the connection, and delete downloaded copies."""
        self.closing_all = True
        for editor in list(self.editors):
            editor.close()
        for edit in self.external_edits:
            edit.stop()
            remove_edit_copy(edit.local_path)
        self.external_edits = []
        self.close_connection()
        self.state = DISCONNECTED

    def open_terminal(self):
        self.page.window.terminal_tab.open_session(self.session)

    # ----------------------------------------------------------------- Remote operations

    def submit(self, function, done=None, failed=None):
        """Run function(fs) on the browsing thread. failed(message) also hears about not being connected."""
        if self.worker is None:
            if failed is not None:
                failed("Not connected.")
            return

        def on_failure(message):
            if self.connection is not None and not self.connection.active:
                self.on_connection_lost("The connection closed.")
            if failed is not None:
                failed(message)
        self.worker.submit(function, done, on_failure)

    def fail(self, title, message):
        QMessageBox.warning(self, title, self.explain(message))

    def explain(self, message):
        """Add what to do about an error, where there's something to suggest."""
        if "permission denied" in message.lower() and not self.sudo:
            message += ("\n\nChanging files you don't own, and changing owners, usually needs root: right-click the "
                        "tab > Work as Root (sudo).")
        return message

    # ----------------------------------------------------------------- Commands (keys and menus)

    def command(self, pane, name):
        entries = pane.selected_entries()
        remote = pane is self.remote
        if name == "copy":
            self.copy_to_other(pane, entries)
        elif name == "mkdir":
            self.new_folder(pane)
        elif not entries:
            return
        elif name == "rename" and len(entries) == 1:
            self.rename(pane, entries[0])
        elif name == "delete":
            self.delete(pane, entries)
        elif name == "edit":
            files = [entry for entry in entries if not entry.is_dir]
            if remote and files:
                self.open_remote_file(files[0])
            elif not remote and files:
                pane.open_file(files[0])
        elif name == "properties":
            if remote:
                self.show_properties(entries)
            else:
                self.local_properties(entries[0])

    def copy_to_other(self, pane, entries):
        if not entries:
            return
        if self.state != CONNECTED:
            self.fail("Copy", "Connect first (right-click the tab > Connect).")
            return
        if pane is self.local:
            self.queue_uploads(entries, self.remote.path)
        else:
            if not self.local.path:
                self.fail("Download", "Open a folder in the Local pane to download into.")
                return
            self.queue_downloads(entries, self.local.path)

    def rename(self, pane, entry):
        name, ok = QInputDialog.getText(self, "Rename", f"New name for {entry.name}:", text=entry.name)
        name = name.strip()
        if not ok or not name or name == entry.name:
            return
        if "/" in name or (pane is self.local and "\\" in name):
            self.fail("Rename", "The new name can't contain a slash.")
            return
        if pane is self.local:
            try:
                target = os.path.join(os.path.dirname(entry.path), name)
                if os.path.exists(target):
                    raise OSError(f"{name} already exists.")
                os.rename(entry.path, target)
            except OSError as error:
                self.fail("Rename", f"Couldn't rename {entry.name}: {getattr(error, 'strerror', None) or error}")
            self.local.refresh(select=[name])
            return
        new = join(remote_parent(entry.path), name)
        self.submit(lambda fs: fs.rename(entry.path, new), lambda _: self.remote.refresh(select=[name]),
                    lambda message: self.fail("Rename", message))

    def new_folder(self, pane):
        if pane is self.local and not self.local.path:
            return
        if pane is self.remote and self.state != CONNECTED:
            return
        name, ok = QInputDialog.getText(self, "New Folder", f"Folder name (in {pane.path}):")
        name = name.strip()
        if not ok or not name:
            return
        if pane is self.local:
            try:
                os.mkdir(os.path.join(self.local.path, name))
            except OSError as error:
                self.fail("New Folder", f"Couldn't create {name}: {error.strerror or error}")
            self.local.refresh(select=[name])
            return
        path = join(self.remote.path, name)
        self.submit(lambda fs: fs.mkdir(path), lambda _: self.remote.refresh(select=[name]),
                    lambda message: self.fail("New Folder", message))

    def delete(self, pane, entries):
        folders = sum(1 for entry in entries if entry.is_dir)
        what = entries[0].name if len(entries) == 1 else f"{len(entries)} items"
        if pane is self.local:
            message = f"Move {what} to the Recycle Bin?"
        else:
            message = f"Permanently delete {what} from {self.session.name}?" + (
                "\n\nFolders are deleted with everything in them." if folders else "")
        reply = QMessageBox.question(self, "Delete", message, QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        if pane is self.local:
            failures = [entry.name for entry in entries if not QFile.moveToTrash(entry.path)[0]]
            if failures:
                self.fail("Delete", "Couldn't move to the Recycle Bin: " + ", ".join(failures[:5]))
            self.local.refresh()
            return

        def work(fs):
            for entry in entries:
                remove_tree(fs, entry, self.worker.cancelled if self.worker else lambda: False)
        self.set_status(f"Deleting {what}...", "info")
        self.submit(work, lambda _: (self.remote.refresh(), self.set_status(f"Deleted {what}.", "info")),
                    lambda message: (self.remote.refresh(), self.fail("Delete", message)))

    def show_properties(self, entries):
        """Read the server's user and group names for the lists (quick), then show the dialog."""
        self.submit(lambda fs: fs.accounts(), lambda accounts: self.open_properties(entries, *accounts),
                    lambda _message: self.open_properties(entries, {}, {}))

    def open_properties(self, entries, users, groups):
        dialog = PropertiesDialog(self, entries, sorted(users, key=str.lower), sorted(groups, key=str.lower))
        if not dialog.exec_():
            return
        mode = dialog.mode if dialog.mode_changed else None
        owner, group, recursive = dialog.owner_change, dialog.group_change, dialog.recursive.isChecked()
        if mode is None and owner is None and group is None:
            return

        def work(fs):
            for entry in entries:
                if owner is not None or group is not None:
                    chown_tree(fs, entry, owner, group, recursive)
                if mode is not None:
                    chmod_tree(fs, entry, mode, recursive)
        self.submit(work, lambda _: self.remote.refresh(), lambda message: (self.remote.refresh(),
                                                                             self.fail("Properties", message)))

    def local_properties(self, entry):
        try:
            os.startfile(entry.path, "properties")
        except OSError as error:
            self.fail("Properties", str(error.strerror or error))

    def toggle_hidden(self):
        show = not self.remote.show_hidden
        self.local.show_hidden = self.remote.show_hidden = show
        self.local.refresh()
        if self.state == CONNECTED:
            self.remote.refresh()

    def show_sync(self):
        if self.state != CONNECTED:
            return
        SyncDialog(self, self, self.local.path, self.remote.path).exec_()

    # ----------------------------------------------------------------- Context menus

    def show_menu(self, pane, position):
        item = pane.list.itemAt(position)
        entries = pane.selected_entries() if item is not None else []
        remote = pane is self.remote
        connected = self.state == CONNECTED
        menu = QMenu(self)
        files = [entry for entry in entries if not entry.is_dir]
        if entries:
            if remote:
                download = menu.addAction(f"Download to {self.local.path or 'a local folder'}\tF5",
                                          lambda: self.copy_to_other(pane, entries))
                download.setEnabled(bool(self.local.path))
                if len(files) == 1 and len(entries) == 1:
                    menu.addAction("Edit\tF4", lambda: self.open_remote_file(files[0]))
                    edit_with = menu.addMenu("Edit With")
                    program = self.settings().value(EDITOR_SETTING, "", str)
                    edit_with.addAction("Windows' Default Program", lambda: self.edit_external(files[0], ""))
                    if program:
                        edit_with.addAction(os.path.basename(program), lambda: self.edit_external(files[0], program))
                    edit_with.addAction("Choose Program...", lambda: self.choose_editor(files[0]))
                    menu.addAction("Checksum...", lambda: ChecksumDialog(self, self, files[0]).exec_())
            else:
                upload = menu.addAction(f"Upload to {self.remote.path if connected else 'the server'}\tF5",
                                        lambda: self.copy_to_other(pane, entries))
                upload.setEnabled(connected)
                if len(entries) == 1:
                    menu.addAction("Open", lambda: pane.open_file(entries[0]) if not entries[0].is_dir
                                   else pane.go(entries[0].path))
            menu.addSeparator()
            if len(entries) == 1:
                menu.addAction("Rename\tF2", lambda: self.rename(pane, entries[0]))
            menu.addAction("Delete\tF8", lambda: self.delete(pane, entries))
            if remote:
                menu.addAction("Properties and Permissions...\tAlt+Enter", lambda: self.show_properties(entries))
            elif len(entries) == 1:
                menu.addAction("Properties\tAlt+Enter", lambda: self.local_properties(entries[0]))
            menu.addAction("Copy Path", lambda: QGuiApplication.clipboard().setText(
                "\n".join(entry.path for entry in entries)))
            menu.addSeparator()
        if pane.path or remote:
            menu.addAction("New Folder...\tF7", lambda: self.new_folder(pane)).setEnabled(connected or not remote)
        menu.addAction("Refresh\tCtrl+R", pane.refresh).setEnabled(connected or not remote)
        if not remote and pane.path:
            menu.addAction("Show in Explorer", lambda: open_in_program(pane.path))
        hidden = menu.addAction("Show Hidden Files\tCtrl+Alt+H", self.toggle_hidden)
        hidden.setCheckable(True)
        hidden.setChecked(self.remote.show_hidden)
        if remote:
            self.add_sudo_action(menu).triggered.connect(self.toggle_sudo)
        menu.addSeparator()
        menu.addAction("Synchronize...", self.show_sync).setEnabled(connected)
        menu.addAction("Open in Terminal", self.open_terminal)
        menu.exec_(pane.list.viewport().mapToGlobal(position))

    # ----------------------------------------------------------------- Transfers

    def queue_transfers(self, transfers):
        if not transfers:
            return
        verify = self.queue.verify_algorithm
        for transfer in transfers:
            transfer.verify = transfer.verify or verify
        with self.lock:
            self.queue.remove_finished_transfers(self.transfers)
            self.transfers.extend(transfers)
        self.queue.add(transfers)
        if self.transfer_worker is not None:
            self.transfer_worker.poke()

    def queue_uploads(self, entries, folder):
        self.queue_transfers([Transfer(UPLOAD, entry.path, join(folder, entry.name), entry.size,
                                       is_dir=entry.is_dir) for entry in entries])

    def queue_downloads(self, entries, folder):
        self.queue_transfers([Transfer(DOWNLOAD, os.path.join(folder, entry.name), entry.path, entry.size,
                                       is_dir=entry.is_dir) for entry in entries])

    def queue_sync(self, local_root, remote_root, differences):
        transfers = []
        for difference in differences:
            local = os.path.join(local_root, *difference.relative.split("/"))
            remote = join(remote_root, difference.relative)
            if difference.action == UPLOAD:
                transfers.append(Transfer(UPLOAD, local, remote, difference.local_size or 0, conflict=OVERWRITE))
            elif difference.action == DOWNLOAD:
                transfers.append(Transfer(DOWNLOAD, local, remote, difference.remote.size, conflict=OVERWRITE))
        self.queue_transfers(transfers)
        self.set_status(f"Synchronizing: {len(transfers)} file{'' if len(transfers) == 1 else 's'} queued.", "info")

    def on_dropped(self, pane, payload, target):
        if pane is self.remote and payload["source"] == "remote":
            self.move_remote(payload["paths"], target)
            return
        if self.state != CONNECTED:
            self.fail("Copy", "Connect first (right-click the tab > Connect).")
            return
        if pane is self.remote:  # From the local pane or Windows Explorer
            entries = []
            for path in payload["paths"]:
                try:
                    info = os.stat(path)
                except OSError:
                    continue
                entries.append(Entry(os.path.basename(path.rstrip("\\/")) or path, path, is_dir=os.path.isdir(path),
                                     size=info.st_size, mtime=info.st_mtime))
            self.queue_uploads(entries, target.path if target is not None else self.remote.path)
        else:
            folder = target.path if target is not None else self.local.path
            if not folder:
                self.fail("Download", "Open a folder in the Local pane to download into.")
                return
            dirs = set(payload.get("dirs", []))
            entries = [Entry(path.rstrip("/").rpartition("/")[2], path, is_dir=path in dirs)
                       for path in payload["paths"]]
            self.queue_downloads(entries, folder)

    def move_remote(self, paths, target):
        if target is None:
            return
        names = [path.rstrip("/").rpartition("/")[2] for path in paths]
        reply = QMessageBox.question(self, "Move", f"Move {names[0] if len(names) == 1 else f'{len(names)} items'} "
                                     f"into {target.path}?", QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply != QMessageBox.Yes:
            return

        def work(fs):
            for path, name in zip(paths, names):
                fs.rename(path, join(target.path, name))
        self.submit(work, lambda _: self.remote.refresh(), lambda message: (self.remote.refresh(),
                                                                             self.fail("Move", message)))

    def set_paused(self, paused):
        if self.transfer_worker is not None:
            self.transfer_worker.set_paused(paused)

    def set_policy(self, policy):
        if self.transfer_worker is not None:
            self.transfer_worker.set_conflict_policy(policy)

    def cancel_transfers(self, transfers):
        for transfer in transfers:
            if self.transfer_worker is not None:
                self.transfer_worker.cancel(transfer)
            elif transfer.state in (QUEUED, PAUSED):
                transfer.state = CANCELLED
                self.queue.update(transfer)

    def retry_transfers(self, transfers):
        with self.lock:
            for transfer in transfers:
                transfer.state, transfer.message, transfer.done = QUEUED, "", 0
        for transfer in transfers:
            self.queue.update(transfer)
        if self.transfer_worker is not None:
            self.transfer_worker.poke()
        elif transfers:
            self.set_status("Transfers will start when the tab is connected again.", "warning")

    def ask_conflict(self, request):
        try:
            dialog = ConflictDialog(self, request.transfer, request.existing)
            dialog.exec_()
            request.result = dialog.result_value
        finally:
            request.done.set()

    # Worker signals go to methods, never lambdas: a lambda's signal still waiting to be delivered when its sender is freed
    # crashes Qt, where a method's is dropped with the view

    def show_busy(self, busy):
        self.busy_label.setText("Working..." if busy else "")

    def on_transfers_added(self, folder, files):
        self.queue.add(files, after=folder)

    def on_transfer_finished(self, transfer):
        if transfer.state != DONE:
            return
        folder = remote_parent(transfer.remote) if transfer.direction == UPLOAD else os.path.dirname(transfer.local)
        self.pending_refresh.add((transfer.direction, folder))
        if not self.refresh_timer.isActive():
            self.refresh_timer.start(400)

    def refresh_after_transfers(self):
        """Show what arrived, in whichever pane is looking at that folder."""
        for direction, folder in self.pending_refresh:
            if direction == UPLOAD:
                if self.state == CONNECTED and self.remote.path == folder:
                    self.remote.refresh()
            elif self.local.path and os.path.normcase(os.path.normpath(self.local.path)) == \
                    os.path.normcase(os.path.normpath(folder)):
                self.local.refresh()
        self.pending_refresh.clear()

    # ----------------------------------------------------------------- Editing remote files

    def open_remote_file(self, entry):
        """Edit a file in the built-in editor (or another program, for big or binary files)."""
        for editor in self.editors:
            if editor.entry.path == entry.path:
                editor.showNormal()
                editor.raise_()
                editor.activateWindow()
                return
        if entry.size > EDITOR_LIMIT:
            reply = QMessageBox.question(
                self, "Edit", f"{entry.name} is {format_size(entry.size)}, too big for NOMAD's editor. Open it in "
                              "another program instead (changes are uploaded each time you save)?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if reply == QMessageBox.Yes:
                self.edit_external(entry, self.settings().value(EDITOR_SETTING, "", str))
            return
        self.set_status(f"Opening {entry.name}...", "info")

        def loaded(result):
            data, mtime = result
            if looks_binary(data):
                reply = QMessageBox.question(self, "Edit", f"{entry.name} doesn't look like a text file. Open it in "
                                             "the text editor anyway?", QMessageBox.Yes | QMessageBox.No)
                if reply != QMessageBox.Yes:
                    self.set_status("", "info")
                    return
            editor = RemoteEditor(self, entry, data, mtime)
            self.editors.append(editor)
            editor.show()
            self.set_status(f"Editing {entry.path}. Ctrl+S in the editor saves it to the server.", "info")

        self.read_remote_file(entry.path, loaded, lambda message: self.fail("Edit", message))

    def read_remote_file(self, path, done, failed):
        def work(fs):
            buffer = io.BytesIO()
            mtime = fs.download(path, buffer)
            return buffer.getvalue(), mtime or (fs.stat(path) or Entry("", "")).mtime
        self.submit(work, done, failed)

    def save_remote_file(self, path, data, expected_mtime, done, failed):
        """Upload an editor's text. Returns ("changed", mtime) instead if the file changed on the server since it
        was opened (expected_mtime None skips that check)."""
        def work(fs):
            current = fs.stat(path)
            if expected_mtime is not None and current is not None and abs(current.mtime - expected_mtime) > 1:
                return "changed", current.mtime
            descriptor, temporary = tempfile.mkstemp(prefix="nomad-edit-")
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(data)
                transfer = TransferRunner(fs, OVERWRITE, preserve_times=False).run(Transfer(UPLOAD, temporary, path))
                if transfer.state != DONE:
                    raise RemoteError(transfer.message or f"The upload ended: {transfer.state}")
            finally:
                os.remove(temporary)
            saved = fs.stat(path)
            return "saved", saved.mtime if saved is not None else 0

        def saved(result):
            done(result)
            if result[0] == "saved" and self.remote.path == remote_parent(path):
                self.remote.refresh()
        self.submit(work, saved, failed)

    def choose_editor(self, entry):
        program, _ = QFileDialog.getOpenFileName(self, "Choose an Editor", os.environ.get("ProgramFiles", ""),
                                                 "Programs (*.exe);;All files (*)")
        if program:
            self.settings().setValue(EDITOR_SETTING, program)
            self.edit_external(entry, program)

    def edit_external(self, entry, program):
        """Download a copy, open it in a program, and upload it whenever it's saved there."""
        folder = edit_folder()
        local_path = os.path.join(folder, entry.name)
        self.set_status(f"Downloading {entry.name} to edit...", "info")

        def work(fs):
            with open(local_path, "wb") as file:
                fs.download(entry.path, file)

        def downloaded(_):
            error = open_in_program(local_path, program)
            if error:
                remove_edit_copy(local_path)
                self.fail("Edit", error)
                return
            edit = ExternalEdit(entry, local_path, self)
            edit.changed.connect(self.upload_edit)
            self.external_edits.append(edit)
            self.set_status(f"Editing {entry.name} in {os.path.basename(program) if program else 'its program'}. "
                            "Each save there is uploaded to the server.", "info")

        def failed(message):
            remove_edit_copy(local_path)
            self.fail("Edit", message)
        self.submit(work, downloaded, failed)

    def upload_edit(self, edit):
        if self.state != CONNECTED:
            self.set_status(f"{edit.entry.name} was saved, but the tab isn't connected: reconnect, then save it "
                            "again to upload.", "warning")
            return
        self.queue_transfers([Transfer(UPLOAD, edit.local_path, edit.entry.path, conflict=OVERWRITE)])
        self.set_status(f"Uploading your changes to {edit.entry.path}...", "info")
