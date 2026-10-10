"""Saved RDP sessions: launch Windows Remote Desktop in its own windows."""
from datetime import datetime

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton, QTreeWidgetItemIterator, \
    QVBoxLayout, QWidget

from ..rdp import clean_old_connections, launch_session
from ..terminal.credentials import CredentialError
from ..terminal.sessions import RDP, Session, SessionFolderStore, target_key, validate_session
from ..terminal.vault import VaultError, VaultLocked
from .common import set_hint
from .credential_dialogs import login_with
from .rdp_dialog import RdpDialog
from .session_manager import RECENT_ROLE, SESSION_ROLE, SessionManager
from .session_page import SessionPage
from .vault_dialog import ensure_unlocked


class RdpSessionManager(SessionManager):
    dialog_class = RdpDialog
    launch_only = True

    def __init__(self, page, store, protocols, settings_prefix):
        super().__init__(page, store, protocols, settings_prefix)
        # Keep the session actions and storage logic, with an RDP-specific layout.
        layout = self.layout()
        while layout.count():
            item = layout.takeAt(0)
            child = item.layout()
            if child:
                while child.count():
                    child.takeAt(0)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        toolbar = QHBoxLayout()
        self.new_button.setText("New session")
        toolbar.addWidget(self.new_button)
        for button in (page.launch_button, page.edit_button, page.save_button):
            toolbar.addWidget(button)
        toolbar.addStretch()
        toolbar.addWidget(self.protection_button)
        layout.addLayout(toolbar)
        search = QHBoxLayout()
        self.filter_input.setPlaceholderText("Search sessions by name, address, username or notes (Ctrl+F)")
        search.addWidget(self.filter_input, 3)
        self.quick_input.setPlaceholderText("Quick connect: host or host:port")
        search.addWidget(self.quick_input, 2)
        quick_launch = QPushButton("Quick launch")
        quick_launch.clicked.connect(lambda: self.quick_connect())
        search.addWidget(quick_launch)
        layout.addLayout(search)
        layout.addWidget(self.quick_status)
        layout.addWidget(self.tree, 1)
        self.count_label = QLabel()
        layout.addWidget(self.count_label)
        self.tree.setHeaderHidden(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setAllColumnsShowFocus(True)
        self.tree.setRootIsDecorated(True)
        for column, width in enumerate((260, 180, 170, 100, 160, 170)):
            self.tree.header().setSectionResizeMode(column, QHeaderView.Interactive)
            self.tree.setColumnWidth(column, width)
        self.fill_tree()

    def fill_tree(self, select=None, select_folders=()):
        super().fill_tree(select, select_folders)
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(["Session", "Address", "Username", "Password", "Display", "Last launched"])
        iterator = QTreeWidgetItemIterator(self.tree)
        while iterator.value():
            item = iterator.value()
            session = self.store.get(item.data(0, SESSION_ROLE))
            entry = self.store.recent_entry(item.data(0, RECENT_ROLE))
            if entry:
                session = self.store.recent_session(entry)
            if session:
                host = f"[{session.host}]" if ":" in session.host else session.host
                recent = [entry.last_used for entry in self.store.recent
                          if target_key(entry.session) == target_key(session)]
                values = [f"{host}:{session.port}", session.username or "Ask in Windows",
                          "Saved" if session.saved_password else "Prompt", display_text(session),
                          datetime.fromtimestamp(max(recent)).strftime("%Y-%m-%d %H:%M") if recent else "—"]
                for column, value in enumerate(values, 1):
                    item.setText(column, value)
                    item.setToolTip(column, value)
            else:
                item.setFirstColumnSpanned(True)
            iterator += 1
        if hasattr(self, "count_label"):
            self.count_label.setText(f"{len(self.visible_sessions())} saved sessions · "
                                     f"{len(self.visible_recent())} recent launches · Double-click to launch")

    def make_session(self, folder):
        return Session(name="", protocol=RDP, port=3389, folder=folder)


def display_text(session):
    if session.rdp_multimon:
        return "All monitors"
    if session.rdp_fullscreen:
        return "Full screen"
    return f"Window: {session.rdp_width} × {session.rdp_height}"


class RdpTab(QWidget):
    protocols = {RDP}
    settings_prefix = "rdp"
    saved_matches = SessionPage.saved_matches
    open_address = SessionPage.open_address
    create_session = SessionPage.create_session

    def __init__(self, window, store):
        super().__init__(window)
        self.window = window
        self.store = store = SessionFolderStore(store, {RDP}, "rdp_folders")
        self.selected_session = None
        layout = QVBoxLayout(self)
        layout.setSpacing(8)
        heading = QLabel("Remote Desktop")
        font = heading.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 2)
        heading.setFont(font)
        layout.addWidget(heading)
        hint = QLabel("Save your computers here. Launch opens a separate Windows Remote Desktop window.")
        hint.setWordWrap(True)
        layout.addWidget(hint)
        self.launch_button = QPushButton("Launch")
        self.edit_button = QPushButton("Edit...")
        self.save_button = QPushButton("Save as Session...")
        self.manager = RdpSessionManager(self, store, self.protocols, self.settings_prefix)
        layout.addWidget(self.manager, 1)
        self.title_label = QLabel()
        self.title_label.setTextFormat(Qt.PlainText)
        layout.addWidget(self.title_label)
        self.details_label = QLabel()
        self.details_label.setTextFormat(Qt.PlainText)
        self.details_label.setWordWrap(True)
        self.details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.details_label.setMaximumHeight(76)
        layout.addWidget(self.details_label)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.manager.tree.currentItemChanged.connect(self.select_item)
        self.launch_button.clicked.connect(lambda: self.open_session(self.selected_session))
        self.edit_button.clicked.connect(lambda: self.manager.edit_session(self.selected_session))
        self.save_button.clicked.connect(self.save_selected)
        store.listeners.append(self.refresh_details)
        self.refresh_details()
        clean_old_connections()

    def select_item(self, item, previous=None):
        if item is None:  # Rebuilding the tree must not discard a just-launched quick connection.
            return
        self.selected_session = None
        if item is not None:
            self.selected_session = self.store.get(item.data(0, SESSION_ROLE))
            entry = self.store.recent_entry(item.data(0, RECENT_ROLE))
            if entry:
                self.selected_session = self.store.recent_session(entry)
        self.refresh_details()

    def refresh_details(self):
        session = self.selected_session
        saved = self.store.get(session.id) if session else None
        if saved:
            session = self.selected_session = saved
        self.launch_button.setEnabled(session is not None)
        self.edit_button.setEnabled(saved is not None)
        self.save_button.setVisible(session is not None and saved is None)
        self.title_label.setText(session.name if session else "")
        self.title_label.setVisible(session is not None)
        self.details_label.setVisible(session is not None)
        self.title_label.setTextFormat(Qt.PlainText)
        if session is None:
            self.details_label.clear()
            return
        host = f"[{session.host}]" if ":" in session.host else session.host
        parts = [f"{host}:{session.port}", display_text(session),
                 f"Clipboard: {'Shared' if session.rdp_clipboard else 'Off'}",
                 f"Audio: {['This computer', 'Remote computer', 'Off'][session.rdp_audio]}"]
        if session.rdp_admin:
            parts.append("Administrative session")
        recent = [entry.last_used for entry in self.store.recent if target_key(entry.session) == target_key(session)]
        if recent:
            parts.append("Last launched: " + datetime.fromtimestamp(max(recent)).strftime("%Y-%m-%d %H:%M"))
        text = " · ".join(parts)
        if session.notes:
            text += "\n" + session.notes
        self.details_label.setText(text)
        self.details_label.setToolTip(text)

    def save_selected(self):
        if self.selected_session is None:
            return
        session = self.selected_session.copy(name=self.store.unique_name(self.selected_session.name,
                                                                        self.selected_session.folder))
        dialog = RdpDialog(self, session, self.store.all_folders(), "Save RDP Session", self.store)
        if dialog.exec_():
            self.store.put(dialog.session)
            self.store.link_recent(dialog.session)
            self.manager.fill_tree(select=dialog.session.id)

    def open_session(self, session, saved=True, window=False, into=None):
        if session is None:
            return None
        if session.protocol != RDP:
            QMessageBox.warning(self, "Remote Desktop", "This page only launches RDP sessions.")
            return None
        problem = validate_session(session)
        if problem:
            QMessageBox.warning(self, "Remote Desktop", problem)
            return None
        if not login_with(self, self.store, session):  # Not saved and no user name: perhaps a saved credential
            return None
        password = ""
        if session.saved_password:
            if not ensure_unlocked(self, self.store, "Unlock the saved Remote Desktop password."):
                return None
            try:
                password = self.store.vault.reveal(session.saved_password)
            except (CredentialError, VaultError, VaultLocked) as error:
                QMessageBox.warning(self, "Remote Desktop Password", str(error))
                return None
        try:
            process = launch_session(session, password)
        except (OSError, ValueError, CredentialError) as error:
            set_hint(self.status_label, str(error), "error")
            return None
        finally:
            password = ""
        self.selected_session = session
        self.store.remember(session)
        self.refresh_details()
        set_hint(self.status_label, "Remote Desktop launched. Windows may ask you to sign in.", "success")
        self.window.navigator.setCurrentWidget(self)
        return process

    def all_views(self):
        return []

    def companion_actions(self, session):
        return []

    def focus_find(self):
        self.manager.filter_input.setFocus()
        self.manager.filter_input.selectAll()

    def save_settings(self, settings):
        self.manager.save_settings(settings)
        settings.remove("rdp/splitter")
        settings.setValue("rdp/columns", self.manager.tree.header().saveState())

    def restore_settings(self, settings):
        self.manager.restore_settings(settings)
        state = settings.value("rdp/columns")
        if state is not None:
            self.manager.tree.header().restoreState(state)

    def shutdown(self):
        self.manager.protection_timer.stop()
        for callback in (self.manager.schedule_refresh, self.refresh_details):
            if callback in self.store.listeners:
                self.store.listeners.remove(callback)
