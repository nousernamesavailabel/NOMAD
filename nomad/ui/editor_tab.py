"""Editor page: a Notepad++-style text editor for configurations (tabs, regular expression find and replace, Cisco
highlighting and folding), Compare (plain, without noise, or by section; copy changes across), and the config
archive: every change to each device's configuration, pulled by hand, saved from the Terminal or backed up on a
schedule; changes to review, standards every copy is checked against, and the commands that fix what differs."""
import itertools
import logging
import os
import socket
import time

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QKeySequence
from PyQt5.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QMenu, QMessageBox, \
    QPushButton, QShortcut, QSplitter, QTabWidget, QToolButton, QVBoxLayout, QWidget

from ..configs import apply, archive, checks, diff, fix, pull, scope, standards, text as config_text
from ..configs import logins as backup_logins
from ..configs.archive import ArchiveError
from ..configs.local import LocalConfigs
from ..ipam.client import IpamError, OldServerError
from ..system import account_name, app_data_dir, replace_file
from .code_editor import CISCO, LANGUAGE_NAMES, PLAIN, XML, CodeEditor, FindBar, language_for
from .common import add_action, release_thread, run_in_background, set_hint
from .compare_view import CompareView
from .config_events import config_events
from .editor_panels import ArchivePanel, BackupThread, BackupsPanel, ChangesPanel, CheckDialog, ConfigSyncThread, \
    PullDialog, SendDialog, StandardsPanel, when_text
from .remote_editor import decode, encode, looks_binary
from .ssh_push import LoginRow
from .vault_dialog import ensure_unlocked

log = logging.getLogger(__name__)

OPEN_LIMIT = 50 * 1024 * 1024
FILE_FILTER = "Configurations and text (*.cfg *.conf *.txt *.log *.xml);;All files (*)"
LOCAL_FILE = "configs.db"
SCOPE_SECONDS = 60
UNLOCK_CHECK_MS = 5000
STANDARD_TEMPLATE = r"""! STANDARD: New standard
! applies-to: kind=switch
!
! Lines every device it applies to must have (in their modes), "no ..." lines they mustn't have the other way,
! "~ regular expression" lines some line must match, and {{hostname}} {{mgmt_ip}} {{site}} {{building}} {{room}}
! filled in for each device.
!
service password-encryption
no ip http server
ntp server 10.0.0.1
~ ^logging host \S+
line vty 0 4
 transport input ssh
"""


class Document(QWidget):
    """A tab holding one text: a file, an archived copy, fix commands, a standard or a report."""
    FILE, VERSION, FIX, STANDARD, REPORT = "file", "version", "fix", "standard", "report"

    def __init__(self, parent, text="", path="", title="", kind=FILE, read_only=False, context=None,
                 encoding="utf-8", ending="\n"):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.editor = CodeEditor(self, read_only)
        self.editor.set_language(language_for(path, text))
        self.editor.setText(text)
        self.editor.setModified(False)
        layout.addWidget(self.editor)
        self.path, self.title, self.kind = path, title or os.path.basename(path) or "New", kind
        self.context = dict(context or {})
        self.encoding, self.ending = encoding, ending

    def is_modified(self):
        return self.editor.isModified() and not self.editor.isReadOnly()

    def tab_title(self):
        return self.title + (" •" if self.is_modified() else "")


class EditorTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.configs = None
        self.sync_thread = self.backup_thread = None
        self.quiet_start = False  # Starting backups on its own (not the box ticked): no master password dialog
        self.backups_waiting = False  # Ticked, but the master password is locked: they start once it's unlocked
        self.archive_note = ""
        self.jobs = {}
        self.job_ids = itertools.count(1)
        self.untitled = itertools.count(1)
        self.last_folder = os.path.expanduser("~")
        self.last_sync = 0.0
        self.init_ui()
        self.scope_timer = QTimer(self)
        self.scope_timer.timeout.connect(self.update_local_scope)
        self.unlock_timer = QTimer(self)  # While backups wait for the master password: unlocked anywhere starts them
        self.unlock_timer.setInterval(UNLOCK_CHECK_MS)
        self.unlock_timer.timeout.connect(self.check_unlocked)
        self.refresh_timer = QTimer(self)
        self.refresh_timer.setSingleShot(True)
        self.refresh_timer.timeout.connect(self.refresh_views)
        config_events().saved.connect(self.on_terminal_config_saved)
        config_events().open_requested.connect(self.open_file)
        self.setup_archive()

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        self.splitter = QSplitter(Qt.Horizontal)
        self.side = QTabWidget()
        self.archive_panel = ArchivePanel()
        self.changes_panel = ChangesPanel()
        self.standards_panel = StandardsPanel()
        self.login_row = LoginRow(self, self.window.session_store, "The Editor", stacked=True)
        self.backups_panel = BackupsPanel(self, self.login_row)
        self.side.addTab(self.archive_panel, "Archive")
        self.side.addTab(self.changes_panel, "Changes")
        self.side.addTab(self.standards_panel, "Standards")
        self.side.addTab(self.backups_panel, "Backups")
        self.splitter.addWidget(self.side)

        main = QWidget()
        main_layout = QVBoxLayout(main)
        main_layout.setContentsMargins(0, 0, 0, 0)
        bar = QHBoxLayout()
        buttons = []
        for label, tip, slot in (("New", "A new tab (Ctrl+N)", self.new_document),
                                 ("Open...", "Open files (Ctrl+O)", self.open_files),
                                 ("Save", "Save (Ctrl+S)", self.save_current),
                                 ("Save As...", "Save as a file (Ctrl+Shift+S)", self.save_current_as)):
            button = QPushButton(label)
            button.setToolTip(tip)
            button.clicked.connect(slot)
            bar.addWidget(button)
            buttons.append(button)
        self.compare_button = QPushButton("Compare")
        compare_menu = QMenu(self.compare_button)
        add_action(compare_menu, "This Tab with Another Tab...", self.compare_tabs)
        add_action(compare_menu, "This Tab with a File...", self.compare_tab_with_file)
        add_action(compare_menu, "Two Files...", self.compare_files)
        add_action(compare_menu, "This Tab with the Archive Version Selected", self.compare_tab_with_selected)
        compare_menu.addSeparator()
        add_action(compare_menu, "A Device's Running vs Startup...", self.pull_running_vs_startup)
        add_action(compare_menu, "A Device's Running vs This Tab...", self.pull_vs_tab)
        self.compare_button.setMenu(compare_menu)
        bar.addWidget(self.compare_button)
        self.send_button = QPushButton("Send to Device...")
        self.send_button.setToolTip("Type this tab's configuration lines into a device over SSH")
        self.send_button.clicked.connect(self.send_current)
        bar.addWidget(self.send_button)
        bar.addStretch(1)
        bar.addWidget(QLabel("Highlight:"))
        self.language_combo = QComboBox()
        for value in (CISCO, XML, PLAIN):
            self.language_combo.addItem(LANGUAGE_NAMES[value], value)
        self.language_combo.currentIndexChanged.connect(self.language_chosen)
        bar.addWidget(self.language_combo)
        main_layout.addLayout(bar)
        self.docs = QTabWidget()
        self.docs.setTabsClosable(True)
        self.docs.setMovable(True)
        self.docs.setDocumentMode(True)
        self.docs.tabCloseRequested.connect(self.close_tab)
        self.docs.currentChanged.connect(self.on_tab_changed)
        main_layout.addWidget(self.docs, 1)
        self.find_bar = FindBar(self, self.current_editor)
        main_layout.addWidget(self.find_bar)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        main_layout.addWidget(self.status_label)
        self.splitter.addWidget(main)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([340, 900])
        layout.addWidget(self.splitter)

        for keys, slot in (("Ctrl+N", self.new_document), ("Ctrl+O", self.open_files), ("Ctrl+S", self.save_current),
                           ("Ctrl+Shift+S", self.save_current_as), ("Ctrl+F4", self.close_current),
                           ("Ctrl+H", self.show_replace), ("F3", self.find_bar.find_next),
                           ("Shift+F3", self.find_bar.find_previous), ("Ctrl+G", self.go_to_line),
                           ("Escape", self.find_bar.close_bar)):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setContext(Qt.WidgetWithChildrenShortcut)
            shortcut.activated.connect(slot)

        self.archive_panel.history_source = self.history_of
        self.archive_panel.open_version.connect(self.open_version)
        self.archive_panel.menu_requested.connect(self.show_archive_menu)
        self.archive_panel.pull_button.clicked.connect(self.pull_dialog)
        self.changes_panel.open_change.connect(self.open_change)
        self.changes_panel.review_all_button.clicked.connect(self.review_all)
        self.standards_panel.new_button.clicked.connect(self.new_standard)
        self.standards_panel.edit_button.clicked.connect(self.edit_standard)
        self.standards_panel.list.itemDoubleClicked.connect(self.edit_standard)
        self.standards_panel.delete_button.clicked.connect(self.delete_standard)
        self.standards_panel.check_button.clicked.connect(self.check_dialog)
        self.standards_panel.open_result.connect(self.open_result)
        self.backups_panel.run_toggled.connect(self.set_backups_running)
        self.backups_panel.status.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
        self.backups_panel.status.linkActivated.connect(self.backups_link)
        self.backups_panel.interval_applied.connect(self.apply_interval)
        self.backups_panel.refresh_button.clicked.connect(self.refresh_runners)
        self.backups_panel.due_all_button.clicked.connect(self.back_up_everything_now)
        self.backups_panel.device_logins_button.clicked.connect(self.device_logins_clicked)
        self.show_device_logins_count()
        self.side.currentChanged.connect(self.side_changed)
        self.runners_timer = QTimer(self)
        self.runners_timer.timeout.connect(self.refresh_runners_if_shown)
        self.runners_timer.start(30000)
        self.update_buttons()

    # ----------------------------------------------------------------- Who and where

    @property
    def user(self):
        return f"{account_name()} ({socket.gethostname()})"

    @property
    def computer(self):
        return socket.gethostname()

    def status(self, message, kind="info"):
        set_hint(self.status_label, message, kind)

    # ----------------------------------------------------------------- Jobs on worker threads

    def run_job(self, work, done=None, failed=None, busy=""):
        """work() on a worker thread; done(result) or failed(error) back here."""
        job = next(self.job_ids)
        self.jobs[job] = (done, failed)
        if busy:
            self.status(busy)

        def task():
            try:
                return job, work(), None
            except Exception as error:  # Handed back to the page
                if not isinstance(error, (IpamError, ArchiveError, OSError)):
                    log.exception("An Editor job failed")
                return job, None, error
        run_in_background(task, self.job_done)

    def job_done(self, outcome):
        job, result, error = outcome
        done, failed = self.jobs.pop(job, (None, None))
        if error is not None:
            if failed is not None:
                failed(error)
            else:
                self.status(f"{error}", "error")
            return
        if done is not None:
            done(result)

    # ----------------------------------------------------------------- The archive (tribe or here)

    def setup_archive(self):
        """The tribe's archive when this computer has a tribe key (and the server keeps one), else this computer's."""
        self.stop_archive()
        key = None
        try:
            key = self.window.tribe_key()
        except Exception as error:  # A key file that can't be read: work on this computer's
            log.warning("Couldn't read the tribe key: %s", error)
        if key is not None:
            from ..configs.tribe import TribeConfigs
            from ..ipam.client import TeamClient
            self.configs = TribeConfigs(key.server_id, TeamClient(key))
            self.archive_note = "The tribe's archive (connecting...)"
            self.sync_thread = ConfigSyncThread(self.configs, self)
            self.sync_thread.synced.connect(self.on_synced)
            self.sync_thread.failed.connect(self.on_sync_failed)
            self.sync_thread.start()
        else:
            self.use_local_archive("Kept on this computer (join a tribe to share it).")
        self.refresh_views()

    def use_local_archive(self, note):
        self.configs = LocalConfigs(os.path.join(app_data_dir(), LOCAL_FILE))
        self.archive_note = note
        self.scope_timer.start(SCOPE_SECONDS * 1000)
        self.update_local_scope()

    def stop_archive(self):
        self.set_backups_running(False, keep_setting=True)
        if self.sync_thread is not None:
            self.sync_thread.stop()
            release_thread(self.sync_thread, 3000)
            self.sync_thread = None
        self.scope_timer.stop()
        if self.configs is not None:
            try:
                self.configs.close()
            except Exception:
                pass
            self.configs = None

    def tribe_key_changed(self):
        running = self.backups_panel.run_check.isChecked()
        self.setup_archive()
        if running:
            self.restart_backups_quietly()

    def on_synced(self, changed):
        self.last_sync = time.time()
        self.archive_note = f"The tribe's archive (in step {time.strftime('%H:%M')})"
        if changed or not self.archive_panel.tree.topLevelItemCount():
            self.refresh_views()
        else:
            self.archive_panel.status.setText(self.archive_note)

    def on_sync_failed(self, message, too_old):
        if too_old:
            running = self.backups_panel.run_check.isChecked()
            self.set_backups_running(False, keep_setting=True)
            self.sync_thread = None
            self.configs.close()
            self.use_local_archive("The tribe server is older than this NOMAD and keeps no config archive, so it's "
                                   "kept on this computer until the server is updated.")
            if running:
                self.restart_backups_quietly()
            self.refresh_views()
            return
        waiting = self.configs.waiting() if hasattr(self.configs, "waiting") else 0
        self.archive_note = (f"The tribe's archive (offline: {message}). Showing the copy from "
                             f"{when_text(self.last_sync) or 'before'}" +
                             (f"; {waiting} cop{'ies' if waiting != 1 else 'y'} wait to be sent." if waiting else "."))
        self.archive_panel.status.setText(self.archive_note)

    def update_local_scope(self):
        """No tribe: scheduled backups cover the open map's routers, switches, firewalls and WLCs."""
        if not isinstance(self.configs, LocalConfigs):
            return
        network_map = getattr(self.window.netmap_tab, "network_map", None) if hasattr(self.window, "netmap_tab") \
            else None
        if network_map is None:
            return
        rows = list(scope.rows_for_map(network_map).values())
        if self.configs.set_scope(rows):
            self.schedule_refresh()

    def poke_sync(self):
        if self.sync_thread is not None:
            self.sync_thread.wake.set()
        else:
            self.schedule_refresh()

    def schedule_refresh(self):
        self.refresh_timer.start(150)

    def refresh_views(self):
        configs = self.configs
        if configs is None:
            return
        now = time.time()
        with configs.lock:
            store = configs.store
            devices = store.devices()
            unreviewed, failing = store.unreviewed(), store.failing()
            recent, overdue = store.recent(200), store.overdue(now)
            standards_rows, compliance = store.standards(), store.compliance()
            interval = store.interval()
        names = {device["id"]: device["name"] for device in devices}
        self.archive_panel.fill(devices, unreviewed, failing, now)
        self.archive_panel.status.setText(self.archive_note)
        self.changes_panel.fill(recent, overdue)
        self.standards_panel.fill(standards_rows, compliance, names)
        if not self.backups_panel.interval.hasFocus():
            self.backups_panel.interval.setValue(int(round(interval / 3600)))
        in_scope = sum(1 for device in devices if device.get("in_scope") and not device.get("excluded"))
        where = "the tribe maps'" if getattr(configs, "is_tribe", False) else "the open map's"
        self.backups_panel.scope_label.setText(f"{in_scope} device{'s' if in_scope != 1 else ''} in scope: "
                                               f"{where} routers, switches, firewalls and WLCs with a management "
                                               f"address (right-click one on the map > Config to leave it out).")
        flags = {}
        for device_id in set(unreviewed) | set(failing):
            parts = []
            if unreviewed.get(device_id):
                parts.append(f"{unreviewed[device_id]} config change{'s' if unreviewed[device_id] != 1 else ''} "
                             f"to review")
            if failing.get(device_id):
                parts.append(f"fails {failing[device_id]} standard line{'s' if failing[device_id] != 1 else ''}")
            flags[device_id] = "Config: " + ", ".join(parts) + " (Editor page)"
        if hasattr(self.window, "netmap_tab") and hasattr(self.window.netmap_tab, "show_config_flags"):
            self.window.netmap_tab.show_config_flags(flags)

    def history_of(self, device_id):
        with self.configs.lock:
            return self.configs.store.history(device_id)

    def device_row(self, device_id):
        with self.configs.lock:
            return self.configs.store.device(device_id)

    def target_of(self, device_id):
        device = self.device_row(device_id) or {"id": device_id, "name": device_id, "address": device_id}
        return {"id": device["id"], "name": device.get("name") or device["id"],
                "address": device.get("address") or device["id"], "names": device.get("names") or [],
                "platform": device.get("platform") or ""}

    # ----------------------------------------------------------------- Tabs

    def documents(self):
        return [self.docs.widget(index) for index in range(self.docs.count())]

    def current_document(self):
        widget = self.docs.currentWidget()
        return widget if isinstance(widget, (Document, CompareView)) else None

    def current_editor(self):
        widget = self.current_document()
        if isinstance(widget, Document):
            return widget.editor
        if isinstance(widget, CompareView):
            pane = widget.focused_pane() or widget.left
            return pane.editor
        return None

    def add_tab(self, widget, title, tooltip=""):
        index = self.docs.addTab(widget, title)
        self.docs.setTabToolTip(index, tooltip or title)
        self.docs.setCurrentIndex(index)
        if isinstance(widget, Document):
            widget.editor.modificationChanged.connect(self.update_tab_titles)
        else:
            widget.modified_changed.connect(self.update_tab_titles)
            widget.fix_requested.connect(self.open_fix)
        return widget

    def update_tab_titles(self, *_):
        for index in range(self.docs.count()):
            widget = self.docs.widget(index)
            if isinstance(widget, Document):
                self.docs.setTabText(index, widget.tab_title())
            elif isinstance(widget, CompareView):
                title = f"{widget.left.title} ↔ {widget.right.title}"
                self.docs.setTabText(index, (title[:60] + "…" if len(title) > 60 else title) +
                                     (" •" if widget.is_modified() else ""))
        self.update_buttons()

    def on_tab_changed(self, *_):
        editor = self.current_editor()
        if editor is not None:
            self.language_combo.blockSignals(True)
            self.language_combo.setCurrentIndex(max(self.language_combo.findData(editor.language), 0))
            self.language_combo.blockSignals(False)
        self.update_buttons()

    def update_buttons(self):
        editor = self.current_editor()
        self.send_button.setEnabled(editor is not None and bool(editor.text().strip()))
        self.language_combo.setEnabled(editor is not None)

    def language_chosen(self, *_):
        editor = self.current_editor()
        if editor is not None:
            editor.set_language(self.language_combo.currentData())

    def new_document(self):
        self.add_tab(Document(self, title=f"New {next(self.untitled)}"), "New")
        self.update_tab_titles()

    def open_text(self, text, title, kind=Document.REPORT, read_only=True, context=None, path=""):
        doc = Document(self, text, path, title, kind, read_only, context)
        self.add_tab(doc, title)
        self.update_tab_titles()
        self.show_page()
        return doc

    def open_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Open", self.last_folder, FILE_FILTER)
        for path in paths:
            self.open_file(path)

    def read_file(self, path):
        """(text, encoding, line ending) of a text file, or None (and why, said)."""
        try:
            if os.path.getsize(path) > OPEN_LIMIT:
                QMessageBox.warning(self, "Open", f"{os.path.basename(path)} is too big for the Editor (over 50 MB).")
                return None
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError as error:
            QMessageBox.warning(self, "Open", f"Couldn't read {path}: {error.strerror or error}")
            return None
        if looks_binary(data):
            QMessageBox.warning(self, "Open", f"{os.path.basename(path)} isn't a text file.")
            return None
        return decode(data)

    def open_file(self, path):
        path = os.path.abspath(path)
        for index, widget in enumerate(self.documents()):
            if isinstance(widget, Document) and widget.path and os.path.normcase(widget.path) == os.path.normcase(path):
                self.docs.setCurrentIndex(index)
                self.show_page()
                return widget
        read = self.read_file(path)
        if read is None:
            return None
        text, encoding, ending = read
        self.last_folder = os.path.dirname(path)
        doc = Document(self, text, path, os.path.basename(path), Document.FILE, False, None, encoding, ending)
        self.add_tab(doc, doc.title, path)
        self.update_tab_titles()
        self.show_page()
        return doc

    def show_page(self):
        self.window.navigator.setCurrentWidget(self)

    def close_current(self):
        index = self.docs.currentIndex()
        if index >= 0:
            self.close_tab(index)

    def close_tab(self, index):
        widget = self.docs.widget(index)
        if widget is None:
            return
        if self.is_modified(widget):
            answer = QMessageBox.question(self, "Close", f"Save the changes to {self.docs.tabText(index).rstrip(' •')}?",
                                          QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                                          QMessageBox.Save)
            if answer == QMessageBox.Cancel:
                return
            if answer == QMessageBox.Save and not self.save_widget(widget):
                return
        self.docs.removeTab(index)
        widget.deleteLater()
        self.update_buttons()

    @staticmethod
    def is_modified(widget):
        return widget.is_modified() if isinstance(widget, (Document, CompareView)) else False

    def confirm_close(self):
        """NOMAD closing: offer to save tabs with changes. False to stay open."""
        changed = [widget for widget in self.documents() if self.is_modified(widget)]
        if not changed:
            return True
        names = ", ".join(self.docs.tabText(self.docs.indexOf(widget)).rstrip(" •") for widget in changed)
        answer = QMessageBox.question(self.window, "Editor", f"Save the changes in the Editor ({names})?",
                                      QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)
        if answer == QMessageBox.Cancel:
            return False
        if answer == QMessageBox.Save:
            for widget in changed:
                self.docs.setCurrentWidget(widget)
                if not self.save_widget(widget):
                    return False
        return True

    # ----------------------------------------------------------------- Saving

    def save_current(self):
        widget = self.current_document()
        if widget is not None:
            self.save_widget(widget)

    def save_current_as(self):
        widget = self.current_document()
        if isinstance(widget, Document):
            self.save_document_as(widget)
        elif isinstance(widget, CompareView):
            pane = widget.focused_pane() or widget.left
            self.save_pane(pane, ask=True)

    def save_widget(self, widget):
        if isinstance(widget, CompareView):
            for pane in widget.panes():
                if pane.editor.isModified() and not pane.editor.isReadOnly() and not self.save_pane(pane):
                    return False
            return True
        if widget.kind == Document.STANDARD:
            return self.save_standard(widget)
        if widget.path and not widget.editor.isReadOnly():
            return self.write(widget.path, widget.editor.text(), widget.encoding, widget.ending, widget.editor)
        return self.save_document_as(widget)

    def save_document_as(self, doc):
        suggested = doc.path or os.path.join(self.last_folder, safe_file_name(doc.title) + ".cfg")
        path, _ = QFileDialog.getSaveFileName(self, "Save As", suggested, FILE_FILTER)
        if not path:
            return False
        if not self.write(path, doc.editor.text(), doc.encoding, doc.ending, doc.editor):
            return False
        doc.path, doc.title = path, os.path.basename(path)
        if doc.kind != Document.STANDARD:
            doc.kind = Document.FILE
            doc.editor.setReadOnly(False)
        self.docs.setTabToolTip(self.docs.indexOf(doc), path)
        self.update_tab_titles()
        return True

    def save_pane(self, pane, ask=False):
        path = pane.path
        if ask or not path:
            path, _ = QFileDialog.getSaveFileName(self, "Save As", pane.path or os.path.join(
                self.last_folder, safe_file_name(pane.title) + ".cfg"), FILE_FILTER)
            if not path:
                return False
        if not self.write(path, pane.editor.text(), "utf-8", "\r\n" if os.name == "nt" and not pane.path else "\n",
                          pane.editor):
            return False
        pane.path, pane.title = path, os.path.basename(path)
        pane.show_title()
        self.update_tab_titles()
        return True

    def write(self, path, text, encoding, ending, editor):
        temporary = f"{path}.{os.getpid()}.tmp"
        try:
            with open(temporary, "wb") as handle:
                handle.write(encode(text, encoding, ending))
            replace_file(temporary, path)
        except OSError as error:
            try:
                os.remove(temporary)
            except OSError:
                pass
            QMessageBox.warning(self, "Save", f"Couldn't save {path}: {error.strerror or error}")
            return False
        editor.setModified(False)
        self.last_folder = os.path.dirname(path)
        self.status(f"Saved {path}", "success")
        return True

    # ----------------------------------------------------------------- Find, go to line

    def focus_find(self):
        self.find_bar.show_bar(False)

    def show_replace(self):
        self.find_bar.show_bar(True)

    def go_to_line(self):
        editor = self.current_editor()
        if editor is None:
            return
        line, accepted = QInputDialog.getInt(self, "Go to Line", f"Line (1 to {editor.lines()}):",
                                             editor.getCursorPosition()[0] + 1, 1, max(editor.lines(), 1))
        if accepted:
            editor.go_to(line - 1)
            editor.setFocus()

    # ----------------------------------------------------------------- Comparing

    def open_compare(self, left, right, left_title, right_title, read_only=(False, False), contexts=({}, {}),
                     paths=("", ""), mode=None):
        view = CompareView(self, left, right, left_title, right_title, mode or self.compare_mode, paths[0], paths[1],
                           read_only)
        view.left.context, view.right.context = dict(contexts[0]), dict(contexts[1])
        view.mode_combo.currentIndexChanged.connect(self.remember_mode)
        self.add_tab(view, f"{left_title} ↔ {right_title}", f"{left_title} ↔ {right_title}")
        self.update_tab_titles()
        self.show_page()
        return view

    def remember_mode(self, *_):
        view = self.sender().parent() if self.sender() is not None else None
        while view is not None and not isinstance(view, CompareView):
            view = view.parent()
        if view is not None:
            self.compare_mode = view.mode

    compare_mode = diff.SECTION

    def side_of(self, widget):
        """(text, title, path, context) of a tab, for comparing."""
        if isinstance(widget, Document):
            return widget.editor.text(), widget.title, widget.path, widget.context
        pane = widget.focused_pane() or widget.left
        return pane.editor.text(), pane.title, pane.path, pane.context

    def compare_tabs(self):
        current = self.current_document()
        others = [widget for widget in self.documents() if isinstance(widget, Document) and widget is not current]
        if current is None or not others:
            self.status("Open two tabs first.", "warning")
            return
        names = [f"{index + 1}. {widget.title}" for index, widget in enumerate(others)]
        chosen, accepted = QInputDialog.getItem(self, "Compare", "Compare this tab with:", names, 0, False)
        if not accepted:
            return
        other = others[names.index(chosen)]
        self.compare_widgets(current, other)

    def compare_widgets(self, first, second):
        left, left_title, left_path, left_context = self.side_of(first)
        right, right_title, right_path, right_context = self.side_of(second)
        read_only = (isinstance(first, Document) and first.editor.isReadOnly(),
                     isinstance(second, Document) and second.editor.isReadOnly())
        self.open_compare(left, right, left_title, right_title, read_only, (left_context, right_context),
                          (left_path, right_path))

    def compare_tab_with_file(self):
        current = self.current_document()
        if current is None:
            self.status("Open a tab to compare first.", "warning")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Compare With", self.last_folder, FILE_FILTER)
        if not path:
            return
        read = self.read_file(path)
        if read is None:
            return
        left, left_title, left_path, context = self.side_of(current)
        self.open_compare(left, read[0], left_title, os.path.basename(path), contexts=(context, {}),
                          paths=(left_path, path))

    def compare_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Compare Two Files", self.last_folder, FILE_FILTER)
        if len(paths) != 2:
            if paths:
                QMessageBox.information(self, "Compare", "Choose two files (hold Ctrl to pick the second).")
            return
        first, second = self.read_file(paths[0]), self.read_file(paths[1])
        if first is None or second is None:
            return
        self.last_folder = os.path.dirname(paths[0])
        self.open_compare(first[0], second[0], os.path.basename(paths[0]), os.path.basename(paths[1]),
                          paths=(paths[0], paths[1]))

    def compare_tab_with_selected(self):
        current = self.current_document()
        _, versions = self.archive_panel.selected()
        if current is None or not versions:
            self.status("Select a version in the Archive (open a device there) and a tab to compare it with.",
                        "warning")
            return
        version_id = versions[0]
        left, left_title, left_path, context = self.side_of(current)
        self.run_job(lambda: (self.version_title(version_id), self.configs.text(version_id),
                              self.version_context(version_id)),
                     lambda result: self.open_compare(result[1], left, result[0], left_title, (True, False),
                                                      (result[2], context), ("", left_path)),
                     busy="Fetching the archived copy...")

    # ----------------------------------------------------------------- Archived versions

    def version_row(self, version_id):
        with self.configs.lock:
            return self.configs.store.version(version_id, with_text=False)

    def version_title(self, version_id):
        version = self.version_row(version_id) or {}
        device = self.device_row(version.get("device_id")) if version else None
        name = (device or {}).get("name") or version.get("device_id") or "Device"
        moment = time.strftime("%Y-%m-%d %H:%M", time.localtime(version.get("pulled_at") or 0))
        return f"{name} {pull.WHICH_NAMES.get(version.get('which'), '')} {moment}"

    def version_context(self, version_id):
        version = self.version_row(version_id) or {}
        target = self.target_of(version.get("device_id")) if version else {}
        return dict(target, device_id=target.get("id"), version_id=version_id)

    def open_version(self, version_id):
        self.run_job(lambda: (self.version_title(version_id), self.configs.text(version_id),
                              self.version_context(version_id)),
                     self.version_fetched, busy="Fetching the archived copy...")

    def version_fetched(self, result):
        title, text, context = result
        self.open_text(text or "", title, Document.VERSION, True, context)
        self.status("")

    def open_change(self, version_id):
        """A change compared with the copy before it (and marked reviewed)."""
        version = self.version_row(version_id)
        if version is None:
            return
        previous = version.get("previous_id")

        def work():
            texts = (self.configs.text(previous) if previous else "", self.configs.text(version_id))
            if not version.get("reviewed_by"):
                self.configs.review(version_id, self.user)
            return texts
        self.run_job(work, lambda texts: self.change_fetched(version_id, previous, texts),
                     busy="Fetching the change...")

    def change_fetched(self, version_id, previous, texts):
        context = self.version_context(version_id)
        self.open_compare(texts[0], texts[1], self.version_title(previous) if previous else "(nothing before)",
                          self.version_title(version_id), (True, True), (context, context))
        self.status("")
        self.poke_sync()

    def review_all(self):
        ids = self.changes_panel.unreviewed_ids()
        if not ids:
            return

        def work():
            for version_id in ids:
                self.configs.review(version_id, self.user)
            return len(ids)
        self.run_job(work, self.reviewed, busy=f"Marking {len(ids)} changes reviewed...")

    def reviewed(self, count):
        self.status(f"Marked {count} change{'s' if count != 1 else ''} reviewed.", "success")
        self.poke_sync()

    def show_archive_menu(self, position):
        devices, versions = self.archive_panel.selected()
        menu = QMenu(self)
        actions = {}
        if len(versions) == 2:
            actions[menu.addAction("Compare the Two Selected")] = self.compare_two_versions
        if len(versions) == 1:
            version_id = versions[0]
            actions[menu.addAction("Open")] = lambda: self.open_version(version_id)
            row = self.version_row(version_id) or {}
            if row.get("previous_id"):
                actions[menu.addAction("Compare with the Copy Before")] = lambda: self.open_change(version_id)
            actions[menu.addAction("Compare with the Newest")] = lambda: self.compare_with_newest(version_id)
            actions[menu.addAction("Commands to Put This Version Back...")] = lambda: self.put_back(version_id)
            if not row.get("reviewed_by"):
                actions[menu.addAction("Mark Reviewed")] = lambda: self.run_job(
                    lambda: self.configs.review(version_id, self.user), self.reviewed_one)
        if len(devices) > 1:
            actions[menu.addAction(f"Back Up These {len(devices)} Now (Scheduled)")] = \
                lambda: self.back_up_now(list(devices))
            actions[menu.addAction(f"Log In to These {len(devices)} With...")] = \
                lambda: self.edit_device_logins(list(devices))
        if len(devices) == 1:
            device_id = devices[0]
            device = self.device_row(device_id) or {}
            if menu.actions():
                menu.addSeparator()
            actions[menu.addAction("Open the Newest Running-Config")] = lambda: self.open_newest(device_id)
            actions[menu.addAction("Pull Config Now")] = lambda: self.pull(self.target_of(device_id), mode="last")
            if device.get("in_scope") and not device.get("excluded"):
                actions[menu.addAction("Back Up Now (Scheduled)")] = lambda: self.back_up_now([device_id])
            actions[menu.addAction("Running vs Startup")] = lambda: self.pull(self.target_of(device_id),
                                                                              mode="startup")
            excluded = bool(device.get("excluded"))
            action = menu.addAction("Leave Out of Scheduled Backups")
            action.setCheckable(True)
            action.setChecked(excluded)
            actions[action] = lambda: self.set_excluded(device_id, not excluded)
            actions[menu.addAction("Log In With...")] = lambda: self.edit_device_logins([device_id])
        if not menu.actions():
            return
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def reviewed_one(self, _):
        self.poke_sync()

    def compare_two_versions(self):
        _, versions = self.archive_panel.selected()
        first, second = sorted(versions[:2])
        self.run_job(lambda: (self.configs.text(first), self.configs.text(second)),
                     lambda texts: self.open_compare(texts[0], texts[1], self.version_title(first),
                                                     self.version_title(second), (True, True),
                                                     (self.version_context(first), self.version_context(second))),
                     busy="Fetching the archived copies...")

    def newest_id(self, device_id, which="running"):
        with self.configs.lock:
            latest = self.configs.store.latest(device_id, which, with_text=False)
        return latest["id"] if latest else None

    def open_newest(self, device_id):
        newest = self.newest_id(device_id)
        if newest is None:
            self.status("There's no copy of it yet: Pull Config Now.", "warning")
            return
        self.open_version(newest)

    def compare_with_newest(self, version_id):
        version = self.version_row(version_id) or {}
        newest = self.newest_id(version.get("device_id"), version.get("which", "running"))
        if newest is None:
            return
        self.run_job(lambda: (self.configs.text(version_id), self.configs.text(newest)),
                     lambda texts: self.open_compare(texts[0], texts[1], self.version_title(version_id),
                                                     self.version_title(newest), (True, True),
                                                     (self.version_context(version_id), self.version_context(newest))),
                     busy="Fetching the archived copies...")

    def put_back(self, version_id):
        """The commands that take the device from its newest copy back to this version."""
        version = self.version_row(version_id) or {}
        newest = self.newest_id(version.get("device_id"))
        if newest is None:
            return
        self.run_job(lambda: (self.configs.text(newest), self.configs.text(version_id)),
                     lambda texts: self.open_fix(texts[0], texts[1], f"Put back {self.version_title(version_id)}",
                                                 self.version_context(version_id)),
                     busy="Fetching the archived copies...")

    def set_excluded(self, device_id, excluded):
        self.run_job(lambda: self.configs.set_excluded(device_id, excluded),
                     lambda _: (self.status("Left out of scheduled backups." if excluded else
                                            "Back in scheduled backups.", "success"), self.poke_sync()))

    # ----------------------------------------------------------------- Fix commands, sending

    def open_fix(self, current, wanted, title, context):
        platform = (context or {}).get("platform") or config_text.platform_of(current)
        if platform not in config_text.FIXABLE:
            QMessageBox.information(self, "Fix Commands", "NOMAD writes fix commands for Cisco IOS / IOS XE, NX-OS "
                                                          "and ASA only.")
            return
        lines = fix.fix_commands(current, wanted)
        if not lines:
            self.status("Nothing to type: they're the same (once noise and order are left out).", "success")
            return
        heading = [f"! {title}", "! The commands NOMAD worked out (check them before sending)", "!"]
        self.open_text("\n".join(heading) + "\n" + fix.as_config(lines) + "\n", f"Fix: {title}", Document.FIX, False,
                       context)

    def send_current(self):
        widget = self.current_document()
        editor = self.current_editor()
        if editor is None:
            return
        context = widget.context if isinstance(widget, Document) else {}
        lines = config_lines(editor.text())
        if not lines:
            self.status("There are no configuration lines to send (comments and configure terminal / end are left "
                        "out).", "warning")
            return
        dialog = SendDialog(self, context.get("address", ""), context.get("platform") or
                            config_text.IOS, len(lines))
        if dialog.exec_() != SendDialog.Accepted:
            return
        address = dialog.address.text().strip()
        names = list(context.get("names") or [])
        logins = self.login_row.logins(self.status_label, [(address, names)])
        if logins is None:
            return
        make = self.login_row.pusher_maker(logins)
        minutes = dialog.minutes.value() if dialog.revert.isChecked() else 0
        save, pull_after = dialog.save.isChecked(), dialog.pull_after.isChecked()
        target = self.target_of(context["device_id"]) if context.get("device_id") else \
            {"id": address.lower(), "name": address, "address": address, "names": names, "platform": ""}
        target["address"] = address

        def work():
            pusher = make(lambda: False)
            try:
                if minutes:
                    outcome = pusher.set_up_guarded(address, fix.as_config(lines, minutes), minutes, names)
                else:
                    outcome = pusher.set_up(address, fix.as_config(lines), "", names)
                saved = pusher.save_config(address, names) if outcome.ok and save else None
                uploaded = None
                if outcome.ok and pull_after:
                    result = pull.pull_device(pusher, address, names, target.get("platform", ""), keep=True)
                    if result.ok:
                        uploaded = self.configs.upload(target["id"], pull.RUNNING, result.texts[pull.RUNNING],
                                                       self.user, archive.MANUAL, result.changed_by, target["name"],
                                                       address, result.platform)
            finally:
                pusher.close()
            return outcome, saved, uploaded
        self.run_job(work, lambda result: self.sent(address, result), busy=f"Sending to {address}...")

    def sent(self, address, result):
        outcome, saved, uploaded = result
        lines = [f"! Sent to {address} {time.strftime('%Y-%m-%d %H:%M')}"]
        if outcome.ok:
            lines.append("! Every line was taken" + (" and confirmed (revert timer)" if outcome.confirmed else "") + ".")
        else:
            lines.append(f"! {outcome.problem or outcome.first_error}")
            if outcome.reverted:
                lines.append("! The device's configuration was put back.")
            elif outcome.reverts_at:
                lines.append(f"! The device puts its old configuration back at {outcome.reverts_at}.")
        if saved is not None:
            lines.append("! Saved to the startup-config." if saved[0] else f"! write memory failed: {saved[1]}")
        if uploaded is not None:
            lines.append("! Its running-config is in the archive" + (" (changed)." if uploaded.get("stored") else "."))
        lines += ["!", outcome.transcript]
        self.open_text("\n".join(lines), f"Sent to {address}", Document.REPORT, True)
        self.status(f"Sent to {address}." if outcome.ok else f"Sending to {address} failed: "
                    f"{outcome.problem or outcome.first_error}", "success" if outcome.ok else "error")
        self.poke_sync()

    # ----------------------------------------------------------------- Pulling

    def pull_dialog(self, address=""):
        dialog = PullDialog(self, self.device_choices(), address if isinstance(address, str) else "")
        target = dialog.target(self.target_for_address) if dialog.exec_() == PullDialog.Accepted else None
        if target is not None:
            self.pull(target, mode="startup" if dialog.startup.isChecked() else "last")

    def device_choices(self):
        """The devices to pick from when pulling: the open map's routers, switches, firewalls and WLCs, the
        archive's, and the saved SSH sessions (each once), by name."""
        from ..netmap import model
        from ..terminal.sessions import SSH
        found = {}
        network_map = getattr(self.window.netmap_tab, "network_map", None) if hasattr(self.window, "netmap_tab") \
            else None
        if network_map is not None:
            for device in network_map.devices.values():
                if device.kind in model.NETWORK_KINDS and device.mgmt_ip:
                    target = self.target_for_device(device)
                    found.setdefault(target["id"], target)
        if self.configs is not None:
            with self.configs.lock:
                devices = self.configs.store.devices()
            for device in devices:
                if device.get("address") and device["id"] not in found:
                    found[device["id"]] = self.target_of(device["id"])
        store = getattr(self.window, "session_store", None)
        for session in (store.sessions if store is not None else ()):
            host = (session.host or "").strip()
            if session.protocol == SSH and host and host.lower() not in found:
                found[host.lower()] = {"id": host.lower(), "name": session.name or host, "address": host,
                                       "names": [session.name] if session.name else [], "platform": ""}
        return sorted(found.values(), key=lambda target: (target["name"].lower(), target["address"]))

    def target_for_address(self, address):
        """What to pull for an address or name typed: the map device with it (or the archive's), else the saved SSH
        session named that (its host), else just the address."""
        found = self.known_target(address)
        if found is not None:
            return found
        from ..terminal.sessions import SSH
        store = getattr(self.window, "session_store", None)
        for session in (store.sessions if store is not None else ()):
            host = (session.host or "").strip()
            if session.protocol == SSH and host and (session.name or "").strip().lower() == address.lower():
                target = self.known_target(host) or {"id": host.lower(), "name": session.name, "address": host,
                                                     "names": [], "platform": ""}
                target["names"] = list(dict.fromkeys([*(target.get("names") or []), session.name]))
                return target
        return {"id": address.lower(), "name": address, "address": address, "names": [], "platform": ""}

    def known_target(self, address):
        """The map device with this address or name, or the archive's device with this id; None if neither."""
        network_map = getattr(self.window.netmap_tab, "network_map", None) if hasattr(self.window, "netmap_tab") \
            else None
        if network_map is not None:
            for device in network_map.devices.values():
                if device.mgmt_ip and (device.owns(address) or device.name.lower() == address.lower()):
                    return self.target_for_device(device)
        if self.device_row(address.lower()) is not None:
            return self.target_of(address.lower())
        return None

    @staticmethod
    def target_for_device(device):
        names = [name for name in dict.fromkeys([device.name, *(device.addresses or [])]) if name]
        return {"id": scope.device_id(device), "name": device.label, "address": device.mgmt_ip, "names": names,
                "platform": config_text.platform_for_device(device)}

    def pull_running_vs_startup(self):
        dialog = PullDialog(self, self.device_choices())
        dialog.startup.setChecked(True)
        dialog.startup.setEnabled(False)
        target = dialog.target(self.target_for_address) if dialog.exec_() == PullDialog.Accepted else None
        if target is not None:
            self.pull(target, mode="startup")

    def pull_vs_tab(self):
        current = self.current_document()
        if current is None:
            self.status("Open the file (a full configuration or a standard) to compare the device with first.",
                        "warning")
            return
        dialog = PullDialog(self, self.device_choices())
        dialog.startup.setVisible(False)
        target = dialog.target(self.target_for_address) if dialog.exec_() == PullDialog.Accepted else None
        if target is not None:
            other, title, path, _ = self.side_of(current)
            self.pull(target, mode="with", other=(other, title, path))

    def pull_logins(self, target):
        """Logins for pulling from a device: its own (Device Logins...) when it has one, else as usual; None if
        cancelled."""
        store = self.login_row.sessions
        if self.own_login(target["id"]) is None:
            return self.login_row.logins(self.status_label, [(target["address"], list(target.get("names") or ()))])
        if not ensure_unlocked(self, store, "The Editor logs in to devices with saved passwords."):
            return None
        from .ssh_push import SavedLogins
        return backup_logins.DeviceLogins(SavedLogins(store), self.own_login), self.login_row.enable_input.text()

    def pull(self, target, mode="open", other=None):
        """Read a device's configuration over SSH into the archive, then: open it (open), compare it with the copy
        before (last), with its startup-config (startup), or with a text (with: a standard is checked instead)."""
        if self.configs is None:
            return
        logins = self.pull_logins(target)
        if logins is None:
            return
        make = self.login_row.pusher_maker(logins)
        previous = self.newest_id(target["id"]) if mode == "last" else None
        which = (pull.RUNNING, pull.STARTUP) if mode == "startup" else (pull.RUNNING,)

        def work():
            before = self.configs.text(previous) if previous else None
            pusher = make(lambda: False)
            try:
                result = pull.pull_device(pusher, target["address"], target.get("names") or (),
                                          target.get("platform") or "", which)
            finally:
                pusher.close()
            uploads = {}
            if result.ok:
                for kind, config in result.texts.items():
                    uploads[kind] = self.configs.upload(target["id"], kind, config, self.user, archive.MANUAL,
                                                        result.changed_by, target["name"], target["address"],
                                                        result.platform)
            return result, uploads, before
        self.run_job(work, lambda outcome: self.pulled(target, mode, other, previous, outcome),
                     busy=f"Pulling {target['name']}'s configuration...")

    def pulled(self, target, mode, other, previous, outcome):
        result, uploads, before = outcome
        self.poke_sync()
        if not result.ok:
            self.status(f"Couldn't pull {target['name']}: {result.problem}", "error")
            return
        target = dict(target, platform=result.platform or target.get("platform", ""))
        context = dict(target, device_id=target["id"])
        running = result.texts[pull.RUNNING]
        stored = uploads.get(pull.RUNNING) or {}
        note = "queued to send to the tribe server" if stored.get("queued") else \
            "first copy in the archive" if stored.get("first") else \
            "changed since the last copy" if stored.get("stored") else "the same as the last copy"
        who = f", last changed by {result.changed_by}" if result.changed_by else ""
        self.status(f"Pulled {target['name']} ({note}{who}).", "success")
        now = time.strftime("%H:%M")
        if mode == "startup":
            startup = result.texts.get(pull.STARTUP)
            if startup is None:
                self.status(f"{target['name']} wouldn't show its startup-config; here's the running-config.",
                            "warning")
                self.open_text(running, f"{target['name']} running-config {now}", Document.VERSION, True, context)
                return
            self.open_compare(startup, running, f"{target['name']} startup-config",
                              f"{target['name']} running-config {now}", (True, True), (context, context))
        elif mode == "last" and before is not None:
            self.open_compare(before, running, self.version_title(previous), f"{target['name']} running-config {now}",
                              (True, True), (context, context))
        elif mode == "preview" and other is not None:
            self.show_preview_diff(target["name"], running, other[0], context)
        elif mode == "with" and other is not None:
            other_text, other_title, other_path = other
            if standards.is_standard(other_text):
                self.show_check(standards.parse(other_text, other_title), {target["id"]: running},
                                {target["id"]: self.facts_for_target(target, running)}, context)
            else:
                self.open_compare(running, other_text, f"{target['name']} running-config {now}", other_title,
                                  (True, False), (context, {}), ("", other_path))
        else:
            self.open_text(running, f"{target['name']} running-config {now}", Document.VERSION, True, context)

    def facts_for_target(self, target, config):
        with self.configs.lock:
            known = self.configs.store.device(target["id"]) is not None
            facts = checks.facts_for(self.configs.store, target["id"]) if known else None
        if facts is None:
            facts = scope.facts_for_text(config, target.get("address", ""))
        return facts

    # ----------------------------------------------------------------- Pages' previews as diffs

    def show_preview_diff(self, name, running, commands, context=None):
        """A device's running-config beside how it would look with a page's lines typed in (roughly: the device
        has the last word)."""
        before, after = apply.simulate(running, commands)
        context = dict(context or {})
        self.open_compare(before, after, f"{name} now", f"{name} with the changes (roughly)", (True, True),
                          (context, context), mode=diff.SECTION)

    def preview_diff_from_archive(self, target, commands):
        """Show as Diff for a page that hasn't read the device: its newest archived copy from today, else one
        pulled now."""
        if self.configs is None:
            return
        newest = self.newest_id(target["id"])
        row = self.version_row(newest) if newest else None
        if row is not None and time.time() - (row.get("pulled_at") or 0) < 24 * 3600:
            context = dict(target, device_id=target["id"])
            self.run_job(lambda: self.configs.text(newest),
                         lambda running: self.show_preview_diff(target["name"], running or "", commands, context),
                         busy="Fetching the archived copy...")
            return
        answer = QMessageBox.question(self, "Show as Diff", f"The config archive has no copy of {target['name']}'s "
                                                            f"running-config from today. Pull one now (over SSH)?")
        if answer == QMessageBox.Yes:
            self.pull(target, mode="preview", other=(commands, "", ""))

    # ----------------------------------------------------------------- Standards

    def new_standard(self):
        self.open_text(STANDARD_TEMPLATE, "New standard", Document.STANDARD, False, {"standard": ""})

    def edit_standard(self, *_):
        name = self.standards_panel.current_name()
        if not name:
            return
        with self.configs.lock:
            row = self.configs.store.standard(name)
        if row is not None:
            self.open_text(row["text"], f"Standard: {name}", Document.STANDARD, False, {"standard": name})

    def save_standard(self, doc):
        source = doc.editor.text()
        parsed = standards.parse(source)
        name = parsed.name.strip()
        if not standards.is_standard(source) or not name or name == "New standard":
            QMessageBox.information(self, "Save Standard", "Give the standard its name on its first line:\n\n"
                                                           "! STANDARD: Access switch baseline")
            return False
        if parsed.problems:
            QMessageBox.warning(self, "Save Standard", "Fix these first:\n\n" + "\n".join(parsed.problems))
            return False
        old = doc.context.get("standard")

        def work():
            self.configs.save_standard(name, source, self.user)
            if old and old != name:
                self.configs.delete_standard(old)
            return name
        self.run_job(work, lambda saved: self.standard_saved(doc, saved), busy=f"Saving the standard {name}...")
        return True

    def standard_saved(self, doc, name):
        doc.context["standard"] = name
        doc.title = f"Standard: {name}"
        doc.editor.setModified(False)
        self.update_tab_titles()
        self.status(f"Saved the standard {name}: every archived device it applies to is checked against it.",
                    "success")
        self.poke_sync()

    def delete_standard(self):
        name = self.standards_panel.current_name()
        if not name:
            return
        if QMessageBox.question(self, "Delete Standard", f"Delete the standard {name} (for everyone in the tribe, "
                                                         f"if the archive is the tribe's)?") != QMessageBox.Yes:
            return
        self.run_job(lambda: self.configs.delete_standard(name),
                     lambda _: (self.status(f"Deleted {name}.", "success"), self.poke_sync()))

    def check_dialog(self):
        with self.configs.lock:
            names = [row["name"] for row in self.configs.store.standards()]
        if not names:
            self.status("Make a standard first (New).", "warning")
            return
        devices, _ = self.archive_panel.selected()
        dialog = CheckDialog(self, names, self.standards_panel.current_name(), len(devices))
        if dialog.exec_() != CheckDialog.Accepted:
            return
        name, how = dialog.standard.currentText(), dialog.scope()
        with self.configs.lock:
            row = self.configs.store.standard(name)
            everything = self.configs.store.devices()
            facts = {device["id"]: checks.facts_for(self.configs.store, device["id"]) for device in everything}
            newest = {device["id"]: (self.configs.store.latest(device["id"], with_text=False) or {}).get("id")
                      for device in everything}
        standard = standards.parse(row["text"], name)
        standard.name = name
        if how == "selected":
            chosen = devices
        elif how == "every":
            chosen = [device["id"] for device in everything]
        else:
            chosen = [device["id"] for device in everything if standards.applies(standard, facts[device["id"]])]
        chosen = [device_id for device_id in chosen if newest.get(device_id)]
        if not chosen:
            self.status("None of those devices has an archived copy to check.", "warning")
            return
        self.run_job(lambda: {device_id: self.configs.text(newest[device_id]) for device_id in chosen},
                     lambda texts: self.show_check(standard, texts, facts),
                     busy=f"Checking {len(chosen)} device{'s' if len(chosen) != 1 else ''}...")

    def show_check(self, standard, texts, facts, context=None):
        """A report of devices against a standard: what fails, then the commands that fix it (all "!" comments but
        the commands, so it can be sent as it is when it's one device)."""
        names = {}
        with self.configs.lock:
            for device_id in texts:
                row = self.configs.store.device(device_id)
                names[device_id] = (row or {}).get("name") or device_id
        lines = [f"! Checked against the standard {standard.name} {time.strftime('%Y-%m-%d %H:%M')}"]
        fixes = {}
        for device_id, config in sorted(texts.items(), key=lambda item: names[item[0]].lower()):
            results = standards.check(standard, config or "", facts.get(device_id) or {})
            failed = standards.failed(results)
            lines.append("!")
            lines.append(f"! {names[device_id]}: " + (f"{len(failed)} of {len(results)} fail" if failed else
                                                     f"all {len(results)} pass"))
            lines += [f"!   {standards.STATUS_NAMES[result.status]:<12} {result.where + ' > ' if result.where else ''}"
                      f"{result.rule}" + (f"   ({result.detail})" if result.detail else "") +
                      ("" if result.fix else "   (report only)") for result in failed]
            if standards.fix_lines(results):
                fixes[device_id] = standards.fix_lines(results)
        if len(texts) == 1 and fixes:
            device_id = next(iter(texts))
            lines += ["!", "! Commands that fix it:", fix.as_config(fixes[device_id])]
        elif fixes:
            for device_id, device_lines in fixes.items():
                lines += ["!", f"! Commands that fix {names[device_id]}:"] + [f"!   {line}" for line in device_lines]
        if len(texts) == 1 and context is None:
            context = self.target_of(next(iter(texts)))
            context["device_id"] = context["id"]
        title = f"Check: {standard.name}" + (f" ({names[next(iter(texts))]})" if len(texts) == 1 else "")
        self.open_text("\n".join(lines) + "\n", title, Document.REPORT, False, context if len(texts) == 1 else None)
        self.status("")

    def open_result(self, device_id, standard_name):
        """A device's stored results against a standard, with the commands that fix it."""
        with self.configs.lock:
            rows = [row for row in self.configs.store.compliance(device_id) if row["standard"] == standard_name]
            name = (self.configs.store.device(device_id) or {}).get("name") or device_id
        if not rows:
            return
        results = checks.results_from(rows[0]["results"])
        failed = standards.failed(results)
        lines = [f"! {name} against the standard {standard_name} (checked {when_text(rows[0]['checked'])})",
                 f"! {len(failed)} of {len(results)} fail" if failed else f"! All {len(results)} pass"]
        lines += [f"!   {standards.STATUS_NAMES[result.status]:<12} {result.where + ' > ' if result.where else ''}"
                  f"{result.rule}" + (f"   ({result.detail})" if result.detail else "") +
                  ("" if result.fix else "   (report only)") for result in failed]
        fixes = standards.fix_lines(results)
        if fixes:
            lines += ["!", "! Commands that fix it:", fix.as_config(fixes)]
        context = self.target_of(device_id)
        context["device_id"] = device_id
        self.open_text("\n".join(lines) + "\n", f"{name}: {standard_name}", Document.REPORT, False, context)

    # ----------------------------------------------------------------- Scheduled backups

    def set_backups_running(self, on, keep_setting=False):
        if self.backup_thread is not None:
            self.backup_thread.stop()
            self.backup_thread.wait(2000)
            self.backup_thread = None
        if not on:
            if not keep_setting:
                self.backups_waiting = False
                self.unlock_timer.stop()
                self.backups_panel.status.setText("Not running on this computer.")
            return
        if self.configs is None:
            return
        logins = self.login_row.quiet_logins()
        if logins is None and not self.quiet_start and self.unlock_for_backups():
            logins = self.login_row.quiet_logins()
        if logins is None:
            if self.quiet_start or self.backups_waiting:
                # Started on its own (NOMAD starting) with the master password locked: the box stays ticked, and
                # they start as soon as it's unlocked (here, or for the Terminal...)
                self.backups_waiting = True
                self.unlock_timer.start()
                set_hint(self.backups_panel.status, "Waiting for the master password: backups start as soon as "
                                                    "it's unlocked. <a href=\"unlock\">Unlock and Start Backups..."
                                                    "</a>", "warning")
                return
            # Ticked by hand and the master password Cancelled: left off
            set_hint(self.backups_panel.status, "Backups need the master password unlocked on this computer. "
                                                "<a href=\"unlock\">Unlock and Start Backups...</a>", "error")
            self.backups_panel.run_check.blockSignals(True)
            self.backups_panel.run_check.setChecked(False)
            self.backups_panel.run_check.blockSignals(False)
            return
        self.backups_waiting = False
        self.unlock_timer.stop()
        make = self.login_row.pusher_maker(self.with_device_logins(logins))
        from ..configs import runner
        thread_ref = {}

        def pusher_factory():
            thread = thread_ref.get("thread")
            return make(lambda: thread is not None and thread.stop_event.is_set())
        backup_runner = runner.BackupRunner(self.configs, pusher_factory, f"{self.computer}-gui", self.computer,
                                            self.user, archive.GUI)
        self.backup_thread = BackupThread(backup_runner, None, self)
        thread_ref["thread"] = self.backup_thread
        self.backup_thread.stepped.connect(self.backups_done)
        self.backup_thread.failed.connect(self.backups_failed)
        self.backup_thread.start()
        set_hint(self.backups_panel.status, "Running: devices due are backed up a few at a time.", "success")

    def restart_backups_quietly(self):
        """Start backups with nothing asked (NOMAD starting, the archive changing): a locked master password leaves
        the link that unlocks it instead of a dialog."""
        self.quiet_start = True
        try:
            self.backups_panel.run_check.blockSignals(True)
            self.backups_panel.run_check.setChecked(True)
            self.backups_panel.run_check.blockSignals(False)
            self.set_backups_running(True)
        finally:
            self.quiet_start = False

    def unlock_for_backups(self):
        """Ask for the master password so backups can use saved passwords. True once unlocked."""
        store = self.login_row.sessions
        if store is None or not store.vault.enabled:
            return False
        return ensure_unlocked(self, store, "Scheduled backups log in to devices with saved passwords, so the master "
                                            "password must be unlocked on this computer.")

    def backups_link(self, _link):
        if self.backups_panel.run_check.isChecked():  # Waiting for the master password
            if self.unlock_for_backups():
                self.set_backups_running(True)
        else:
            self.backups_panel.run_check.setChecked(True)  # Asks for the master password, then starts them

    def check_unlocked(self):
        """Backups waiting for the master password: start them once it's unlocked."""
        store = self.login_row.sessions
        if not self.backups_waiting or not self.backups_panel.run_check.isChecked():
            self.unlock_timer.stop()
        elif store is not None and (not store.vault.enabled or store.vault.unlocked):
            self.restart_backups_quietly()

    # ----------------------------------------------------------------- Each device's own login

    def device_logins(self):
        return backup_logins.load()

    def own_login(self, device_id):
        """(Session, label) for a device given its own login (Device Logins...), or None. Looked up at each login,
        so a credential changed since is used."""
        store = self.login_row.sessions
        credential_id = self.device_logins().get(device_id)
        credential = store.credentials.get(credential_id) if store is not None and credential_id else None
        if credential is None:
            return None
        from ..terminal.sessions import Session
        return store.credentials.apply(Session("", credential_id=credential.id)), f"credential {credential.name}"

    def with_device_logins(self, logins):
        """logins (LoginRow's (logins, enable)) using each device's own login first."""
        login, secret = logins
        if not self.device_logins():
            return logins
        return backup_logins.DeviceLogins(login, self.own_login), secret

    def edit_device_logins(self, device_ids=None, parent=None):
        """Device Logins...: the login scheduled backups (and Pull Config) use for each device. parent: the window
        it's opened from (the Map Watcher's)."""
        store = self.login_row.sessions
        if store is None or self.configs is None:
            return
        with self.configs.lock:
            devices = self.configs.store.devices()
        from .backup_logins_dialog import DeviceLoginsDialog
        dialog = DeviceLoginsDialog(parent or self, store, devices, self.device_logins(), device_ids)
        if dialog.exec_() != DeviceLoginsDialog.Accepted:
            return
        try:
            backup_logins.save(dialog.chosen())
        except OSError as error:
            self.status(f"Couldn't save the device logins: {error}", "error")
            return
        self.show_device_logins_count()
        if self.backup_thread is not None:
            self.set_backups_running(True)  # Uses them from the next round

    def device_logins_clicked(self):
        self.edit_device_logins()

    def show_device_logins_count(self):
        count = len(self.device_logins())
        self.backups_panel.device_logins_note.setText(
            f"{count} device{'s' if count != 1 else ''} with {'its' if count == 1 else 'their'} own login." if count
            else "No device has its own login.")

    def backups_done(self, done):
        good = sum(1 for item in done if item.ok)
        set_hint(self.backups_panel.status, f"{time.strftime('%H:%M')}: backed up {good} of {len(done)}.",
                 "success" if good == len(done) else "warning")
        self.poke_sync()
        self.refresh_runners()

    def backups_failed(self, message):
        set_hint(self.backups_panel.status, message, "error")

    def back_up_now(self, device_ids):
        """Bring these devices' scheduled backups forward to now."""
        self.run_job(lambda: self.configs.make_due(device_ids), self.brought_forward)

    def back_up_everything_now(self):
        if QMessageBox.question(self, "Back Up Everything Now", "Bring every device's scheduled backup forward to "
                                                                "now? The computers running backups take them a few "
                                                                "at a time.") != QMessageBox.Yes:
            return
        self.run_job(lambda: self.configs.make_due(None), self.brought_forward)

    def brought_forward(self, count):
        running = self.backup_thread is not None
        self.status(f"{count} device{'s' if count != 1 else ''} due now" +
                    (": this computer is starting on them." if running else
                     " (for the computers running backups)." if count else "."),
                    "success" if count else "warning")
        if running:
            self.backup_thread.wake.set()
        self.poke_sync()
        QTimer.singleShot(2000, self.refresh_runners)

    def side_changed(self, *_):
        self.refresh_runners_if_shown()

    def refresh_runners_if_shown(self):
        if self.side.currentWidget() is self.backups_panel and self.isVisible():
            self.refresh_runners()

    def refresh_runners(self):
        if self.configs is None or getattr(self, "runners_pending", False):
            return
        self.runners_pending = True
        configs = self.configs

        def work():
            runners, results = configs.runners(), configs.results()
            with configs.lock:
                now = time.time()
                due = sum(1 for device in configs.store.devices() if device.get("in_scope") and
                          not device.get("excluded") and device.get("next_due") and device["next_due"] <= now)
            return runners, due, results
        self.run_job(work, self.runners_read, self.runners_failed)

    def runners_read(self, result):
        self.runners_pending = False
        runners, due, results = result
        self.backups_panel.fill_runners(runners, due)
        self.backups_panel.fill_results(results)

    def runners_failed(self, error):
        self.runners_pending = False
        set_hint(self.backups_panel.runners_note, f"Couldn't ask who's backing up: {error}", "error")

    def apply_interval(self, hours):
        self.run_job(lambda: self.configs.set_settings({"interval_hours": hours}),
                     lambda _: (self.status(f"Each device is now backed up every {hours} hours.", "success"),
                                self.poke_sync()))

    # ----------------------------------------------------------------- From other pages

    def device_config_menu(self, menu, actions, device):
        """The map's right-click > Config submenu for a router, switch, firewall or WLC."""
        if not device.mgmt_ip:
            return
        target = self.target_for_device(device)
        actions[menu.addAction("Pull Config")] = lambda: self.pull(target, mode="open")
        actions[menu.addAction("Compare with Last Copy")] = lambda: self.pull(target, mode="last")
        actions[menu.addAction("Running vs Startup")] = lambda: self.pull(target, mode="startup")
        unreviewed = {}
        if self.configs is not None:
            with self.configs.lock:
                unreviewed = self.configs.store.unreviewed()
                history = self.configs.store.history(target["id"], "running")
                excluded = bool((self.configs.store.device(target["id"]) or {}).get("excluded"))
                standard_names = [row["name"] for row in self.configs.store.standards()]
        else:
            history, excluded, standard_names = [], False, []
        if unreviewed.get(target["id"]):
            newest = next((item["id"] for item in history if not item.get("reviewed_by")), None)
            if newest is not None:
                actions[menu.addAction("Review the Change")] = lambda: self.open_change(newest)
        actions[menu.addAction("History")] = lambda: self.show_history(target["id"])
        if standard_names:
            check = QMenu("Check Against Standard", menu)
            menu.addMenu(check)
            for name in standard_names:
                actions[check.addAction(name)] = lambda name=name: self.check_device(target, name)
        if history or self.device_row(target["id"]) is not None:
            action = menu.addAction("Leave Out of Scheduled Backups")
            action.setCheckable(True)
            action.setChecked(excluded)
            actions[action] = lambda: self.set_excluded(target["id"], not excluded)

    def show_history(self, device_id):
        self.show_page()
        self.side.setCurrentWidget(self.archive_panel)
        if not self.archive_panel.show_device(device_id):
            self.status("It has no copies in the archive yet: Pull Config first.", "warning")

    def check_device(self, target, name):
        with self.configs.lock:
            row = self.configs.store.standard(name)
        newest = self.newest_id(target["id"])
        if row is None:
            return
        standard = standards.parse(row["text"], name)
        standard.name = name
        if newest is None:
            self.pull(target, mode="with", other=(row["text"], name, ""))
            return
        context = dict(target, device_id=target["id"])
        self.run_job(lambda: {target["id"]: self.configs.text(newest)},
                     lambda texts: self.show_check(standard, texts,
                                                   {target["id"]: self.facts_for_target(target, texts[target["id"]])},
                                                   context),
                     busy="Checking...")

    def on_terminal_config_saved(self, info):
        """The Terminal saved a running-config: a copy goes in the archive too."""
        if self.configs is None or not (info.get("text") or "").strip():
            return
        host = (info.get("host") or "").strip()
        target = self.target_for_address(host) if host else None
        name = config_text.hostname_in(info["text"]) or (info.get("prompt") or "").rstrip("#>$% ") or \
            info.get("name") or host
        if target is None:
            target = {"id": name.lower(), "name": name, "address": "", "names": [], "platform": ""}
        elif target["name"] == host:
            target["name"] = name
        self.run_job(lambda: self.configs.upload(target["id"], pull.RUNNING, info["text"], self.user, archive.TERMINAL,
                                                 pull.who_changed(info["text"]), target["name"], target["address"],
                                                 config_text.platform_of(info["text"])),
                     lambda outcome: (self.window.show_status(f"The running-config of {target['name']} is in the "
                                                              f"config archive" + (" (changed)." if outcome.get(
                                                                  "stored") and not outcome.get("first") else "."),
                                                              "success"), self.poke_sync()))

    def file_in_archive(self, path, source=archive.FILE):
        """A configuration file (from TFTP, say) kept in the archive as a device's running-config."""
        read = self.read_file(path)
        if read is None:
            return
        config = read[0]
        hostname = config_text.hostname_in(config)
        guess = self.target_for_address(hostname) if hostname else None
        suggestion = guess["address"] if guess and guess.get("address") else hostname
        address, accepted = QInputDialog.getText(self, "File in Config Archive", "Whose running-config is it? "
                                                                                 "(its address or name)",
                                                 text=suggestion or "")
        if not accepted or not address.strip():
            return
        target = self.target_for_address(address.strip())
        if hostname and target["name"] == address.strip():
            target["name"] = hostname
        self.run_job(lambda: self.configs.upload(target["id"], pull.RUNNING, config, self.user, source,
                                                 pull.who_changed(config), target["name"], target["address"],
                                                 config_text.platform_of(config)),
                     lambda outcome: (self.status(f"Filed {os.path.basename(path)} as {target['name']}'s "
                                                  f"running-config.", "success"), self.poke_sync()))

    def compare_file_with(self, path):
        """Compare a file with another, chosen now (TFTP's Compare With...)."""
        doc = self.open_file(path)
        if doc is not None:
            self.compare_tab_with_file()

    # ----------------------------------------------------------------- Settings

    def save_settings(self, settings):
        settings.setValue("editor/splitter", self.splitter.saveState())
        settings.setValue("editor/side_tab", self.side.currentIndex())
        settings.setValue("editor/run_backups", self.backups_panel.run_check.isChecked() or self.backups_waiting)
        settings.setValue("editor/compare_mode", self.compare_mode)
        settings.setValue("editor/folder", self.last_folder)
        self.login_row.save_settings(settings, "editor/login")

    def restore_settings(self, settings):
        state = settings.value("editor/splitter")
        if state is not None:
            self.splitter.restoreState(state)
        self.side.setCurrentIndex(settings.value("editor/side_tab", 0, int))
        self.compare_mode = settings.value("editor/compare_mode", diff.SECTION, str)
        self.last_folder = settings.value("editor/folder", self.last_folder, str)
        self.login_row.restore_settings(settings, "editor/login")
        if settings.value("editor/run_backups", False, bool):
            self.restart_backups_quietly()

    def shutdown(self):
        self.unlock_timer.stop()
        self.stop_archive()


def config_lines(text):
    """The lines of a tab to type into a device: without comments, blank lines, configure terminal and end."""
    lines = []
    for line in (text or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped == "end" or \
                stripped.startswith(("configure terminal", "conf t")):
            continue
        lines.append(line.rstrip())
    return lines


def safe_file_name(name):
    return "".join(character if character.isalnum() or character in " -_.@" else "_" for character in name).strip() \
        or "config"
