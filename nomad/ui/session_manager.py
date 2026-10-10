"""The saved-session sidebar: quick connect, a filter, the session tree (folders, Recent), editing, importing and the
master password button. Shared by the Terminal page (every protocol) and the SCP page (SSH only), which use the same
session store."""
import time

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QFont, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QInputDialog, QLabel, \
    QLineEdit, QMenu, QMessageBox, QShortcut, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ..terminal.securecrt import IMPORT_FOLDER as SECURECRT_FOLDER, SecureCrtError, WrongPassphrase, \
    import_securecrt, read_securecrt_export
from ..terminal.sessions import CREDENTIAL_PROTOCOLS, PROTOCOLS, RDP, SSH, Session, import_putty, normalize_folder, \
    parse_quick_connect
from .common import set_hint
from .folder_picker import FolderPickerDialog
from .credential_dialogs import OWN_LOGIN, CredentialsDialog
from .session_dialog import SessionDialog
from .vault_dialog import SecurityDialog, ensure_unlocked
from .theme import COLORS

SESSION_ROLE = Qt.UserRole
FOLDER_ROLE = Qt.UserRole + 1
RECENT_ROLE = Qt.UserRole + 2  # A recent connection's entry id
RECENT_KEY = "/recent"  # The Recent group, in the collapsed set (no folder path starts with "/")


class SessionTree(QTreeWidget):
    """The saved sessions. Selected sessions and folders can be dragged onto a folder (or onto a session, meaning its
    folder, or empty space, meaning the top level). The page does the moving; the tree only says what went where."""
    dropped = pyqtSignal(list, list, str)  # Session ids, folder paths, the folder dropped into ("" for the top level)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setDefaultDropAction(Qt.MoveAction)
        self.setDropIndicatorShown(False)  # The target folder is highlighted instead
        self.setAutoExpandDelay(700)  # Hovering over a closed folder while dragging opens it
        self.highlighted = None

    def dragged(self):
        sessions = [item.data(0, SESSION_ROLE) for item in self.selectedItems() if item.data(0, SESSION_ROLE)]
        folders = [item.data(0, FOLDER_ROLE) for item in self.selectedItems() if item.data(0, FOLDER_ROLE)]
        return sessions, folders

    def target_at(self, position):
        """(folder path, the item to highlight) for a drop at a position, or (None, None) if nothing can go there."""
        item = self.itemAt(position)
        if item is None:
            return "", None
        if item.data(0, RECENT_ROLE) is not None:
            return None, None
        if item.data(0, FOLDER_ROLE):
            return item.data(0, FOLDER_ROLE), item
        if item.data(0, SESSION_ROLE):
            parent = item.parent()
            return (parent.data(0, FOLDER_ROLE), parent) if parent is not None else ("", None)
        return None, None

    def highlight(self, item):
        if self.highlighted is not None:
            self.highlighted.setBackground(0, QBrush())
        self.highlighted = item
        if item is not None:
            color = QColor(COLORS["accent"])
            color.setAlpha(70)
            item.setBackground(0, color)

    def dragEnterEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        super().dragMoveEvent(event)  # Scrolls and opens folders while dragging
        folder, item = self.target_at(event.pos())
        _, folders = self.dragged()
        if folder is None or any(folder == path or folder.startswith(path + "/") for path in folders):
            self.highlight(None)
            event.ignore()
            return
        self.highlight(item)
        event.setDropAction(Qt.MoveAction)
        event.accept()

    def dragLeaveEvent(self, event):
        self.highlight(None)
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        folder, _ = self.target_at(event.pos())
        self.highlight(None)
        sessions, folders = self.dragged()
        if folder is None or event.source() is not self:
            event.ignore()
            return
        # Report it as a copy so Qt doesn't remove the dragged rows itself, and move once the drag has finished
        event.setDropAction(Qt.CopyAction)
        event.accept()
        QTimer.singleShot(0, lambda: self.dropped.emit(sessions, folders, folder))

    def clear(self):
        self.highlighted = None
        super().clear()


class SessionManager(QWidget):
    """The session sidebar. The page it's on opens sessions (page.open_session(session, saved, window)) and lists the
    open ones (page.all_views()). protocols limits which saved sessions are shown (None for all)."""
    dialog_class = SessionDialog
    launch_only = False

    def make_session(self, folder):
        return Session(name="", folder=folder)

    def __init__(self, page, store, protocols=None, settings_prefix="terminal"):
        super().__init__(page)
        self.page = page
        self.store = store
        self.refresh_pending = False
        self.protocols = protocols
        self.settings_prefix = settings_prefix
        self.collapsed = set()
        self.setMinimumWidth(170)
        manager_layout = QVBoxLayout(self)
        manager_layout.setContentsMargins(4, 4, 2, 4)
        manager_layout.setSpacing(4)
        quick_row = QHBoxLayout()
        quick_row.setSpacing(2)
        self.quick_protocol = QComboBox()
        self.quick_protocol.addItems([protocol for protocol in PROTOCOLS if self.shows_protocol(protocol)])
        self.quick_protocol.setToolTip("Protocol for quick connect, unless the text says otherwise "
                                       "(\"telnet 10.0.0.5\", \"raw host:9100\", \"COM3:115200\").")
        self.quick_protocol.setVisible(self.quick_protocol.count() > 1)
        self.quick_input = QLineEdit()
        self.quick_input.setPlaceholderText("Quick connect")
        self.quick_input.setToolTip("admin@10.0.0.1, telnet 10.0.0.5, raw 10.0.0.9:9100 or COM3:115200, then Enter"
                                    if self.quick_protocol.count() > 1 else
                                    "admin@10.0.0.1 or admin@host:2222, then Enter")
        if self.launch_only:
            self.quick_input.setToolTip("Computer name, host:3389 or [IPv6]:3389, then Enter")
        quick_row.addWidget(self.quick_protocol)
        quick_row.addWidget(self.quick_input, 1)
        manager_layout.addLayout(quick_row)
        self.quick_status = QLabel()
        self.quick_status.setWordWrap(True)
        self.quick_status.setVisible(False)
        manager_layout.addWidget(self.quick_status)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter sessions")
        self.filter_input.setClearButtonEnabled(True)
        manager_layout.addWidget(self.filter_input)
        self.tree = SessionTree()
        self.tree.setHeaderHidden(True)  # One column: where a session connects to is in its tooltip
        self.tree.setToolTip("Drag sessions and folders to move them; Ctrl or Shift selects several")
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.setIndentation(14)
        manager_layout.addWidget(self.tree, 1)

        buttons = QHBoxLayout()
        buttons.setSpacing(2)
        self.new_button = QToolButton()
        self.new_button.setText("New")
        self.new_button.setPopupMode(QToolButton.MenuButtonPopup)
        self.new_button.setToolTip("New saved session (Ctrl+N; the arrow also offers a new folder)")
        new_menu = QMenu(self.new_button)
        new_menu.addAction("New Session...", lambda: self.new_session(self.selected_folder()))
        new_menu.addAction("New Folder...", lambda: self.new_folder(self.selected_folder()))
        new_menu.addSeparator()
        new_menu.addAction("Saved Credentials...", self.show_credentials)
        self.new_button.setMenu(new_menu)
        # The master password's state, which is also its menu: unlock, lock, or set up and change it
        self.protection_button = QToolButton()
        self.protection_button.setPopupMode(QToolButton.InstantPopup)
        self.protection_menu = QMenu(self.protection_button)
        self.protection_menu.aboutToShow.connect(self.fill_protection_menu)
        self.protection_button.setMenu(self.protection_menu)
        buttons.addWidget(self.new_button)
        buttons.addWidget(self.protection_button)
        buttons.addStretch(1)
        manager_layout.addLayout(buttons)
        self.protection_timer = QTimer(self)
        self.protection_timer.timeout.connect(self.update_protection)
        self.protection_timer.start(5000)  # Shows when the master password locks itself after being idle

        self.quick_input.returnPressed.connect(self.quick_connect)
        self.quick_input.textChanged.connect(lambda: self.quick_status.setVisible(False))
        self.filter_input.textChanged.connect(lambda: self.fill_tree())
        self.tree.itemActivated.connect(self.on_item_activated)
        self.tree.customContextMenuRequested.connect(self.show_tree_menu)
        self.tree.dropped.connect(self.move_items)
        self.tree.itemExpanded.connect(lambda item: self.collapsed.discard(self.group_key(item)))
        self.tree.itemCollapsed.connect(lambda item: self.collapsed.add(self.group_key(item)))
        self.new_button.clicked.connect(lambda: self.new_session(self.selected_folder()))
        QShortcut(QKeySequence("Ctrl+N"), self.page, context=Qt.WidgetWithChildrenShortcut).activated.connect(
            lambda: self.new_session(self.selected_folder()))
        QShortcut(QKeySequence("Ctrl+Shift+N"), self.page, context=Qt.WidgetWithChildrenShortcut).activated.connect(
            lambda: self.new_folder(self.selected_folder()))
        store.listeners.append(self.schedule_refresh)
        delete_shortcut = QShortcut(QKeySequence.Delete, self.tree)
        delete_shortcut.setContext(Qt.WidgetShortcut)
        delete_shortcut.activated.connect(self.delete_selected)
        self.update_protection()
        self.fill_tree()

    def shows_protocol(self, protocol):
        return self.protocols is None or protocol in self.protocols

    def shows(self, session):
        return self.shows_protocol(session.protocol)

    def schedule_refresh(self):
        """The store was saved (from this page or another): refresh once things settle, keeping the selection."""
        if not self.refresh_pending:
            self.refresh_pending = True
            QTimer.singleShot(0, self.refresh)

    def refresh(self):
        self.refresh_pending = False
        self.fill_tree()
        self.update_protection()

    def save_settings(self, settings):
        prefix = self.settings_prefix
        settings.setValue(f"{prefix}/quick", self.quick_input.text())
        settings.setValue(f"{prefix}/quick_protocol", self.quick_protocol.currentText())
        settings.setValue(f"{prefix}/collapsed", "\n".join(sorted(folder for folder in self.collapsed if folder)))

    def restore_settings(self, settings):
        prefix = self.settings_prefix
        self.quick_input.setText(settings.value(f"{prefix}/quick", "", str))
        self.quick_protocol.setCurrentText(settings.value(f"{prefix}/quick_protocol", SSH, str))
        self.collapsed = {folder for folder in settings.value(f"{prefix}/collapsed", "", str).split("\n") if folder}
        self.fill_tree()

    def visible_sessions(self):
        return [session for session in self.store.sessions if self.shows(session)]

    def visible_recent(self):
        """[(entry, session)] of the recent connections this sidebar shows."""
        pairs = ((entry, self.store.recent_session(entry)) for entry in self.store.recent)
        return [(entry, session) for entry, session in pairs if self.shows(session)]

    def fill_menu(self, menu, into=None):
        """The session list as a menu, for when it's hidden: folders become submenus. into: the tabs to open
        sessions in (a pop-out window's, or a pane's), instead of the page's."""
        menu.clear()
        menu.addAction("Quick Connect...", lambda: self.quick_connect_dialog(into))
        if into is None:
            menu.addAction("New Session...", lambda: self.new_session(""))
        recent = self.visible_recent()
        if recent:
            recent_menu = menu.addMenu("Recent")
            for entry, session in recent:
                action = recent_menu.addAction(session.name, lambda entry=entry: self.open_recent(entry, into=into))
                action.setToolTip(f"{session.target()} ({session.protocol})")
        menu.addSeparator()
        submenus = {"": menu}

        def folder_menu(path):
            if path in submenus:
                return submenus[path]
            parent_path, _, name = path.rpartition("/")
            submenus[path] = folder_menu(parent_path).addMenu(name)
            return submenus[path]

        for path in sorted(self.store.all_folders(), key=str.lower):
            folder_menu(path)
        for session in sorted(self.visible_sessions(), key=lambda item: item.name.lower()):
            action = folder_menu(session.folder).addAction(session.name, lambda session=session:
                                                           self.page.open_session(session, into=into))
            action.setToolTip(f"{session.target()} ({session.protocol})")
        if not self.visible_sessions():
            menu.addAction("No saved sessions").setEnabled(False)
        menu.addSeparator()

    def quick_connect_dialog(self, into=None):
        examples = "admin@10.0.0.1, telnet 10.0.0.5, COM3:115200" if self.quick_protocol.count() > 1 else             "admin@10.0.0.1, admin@host:2222"
        text, ok = QInputDialog.getText(into or self, "Quick Connect", f"Connect to ({examples}):",
                                        text=self.quick_input.text())
        if ok and text.strip():
            self.quick_input.setText(text.strip())
            self.quick_connect(into)

    def lock_now(self):
        self.store.vault.lock()
        self.update_protection()

    def update_protection(self):
        vault = self.store.vault
        if vault.enabled:
            text = "Master password " + ("unlocked" if vault.unlocked else "locked")
            tip = "Saved passwords need your Windows account and the master password."
        else:
            text, tip = "No master password", "Saved passwords are protected by your Windows account."
        self.protection_button.setText(text)
        self.protection_button.setToolTip(tip + " Click to manage the master password.")

    def fill_protection_menu(self):
        menu = self.protection_menu
        menu.clear()
        vault = self.store.vault
        if not vault.enabled:
            menu.addAction("Set Master Password...", self.show_protection)
        else:
            if vault.unlocked:
                menu.addAction("Lock Now", self.lock_now)
            else:
                menu.addAction("Unlock...", self.unlock_now)
            menu.addAction("Master Password Settings...", self.show_protection)
        menu.addSeparator()
        menu.addAction("Saved Credentials...", self.show_credentials)

    def unlock_now(self):
        ensure_unlocked(self, self.store)
        self.update_protection()

    def show_protection(self):
        SecurityDialog(self, self.store).exec_()
        self.update_protection()

    def show_credentials(self):
        CredentialsDialog(self, self.store).exec_()
        self.fill_tree()

    def add_credential_menu(self, menu, actions, sessions):
        """"Credential" (or "Use Credential" for several): log the SSH and RDP ones in with a saved credential."""
        sessions = [session for session in sessions if session.protocol in CREDENTIAL_PROTOCOLS]
        if not sessions:
            return
        submenu = menu.addMenu("Credential" if len(sessions) == 1 else "Use Credential")
        current = {session.credential_id for session in sessions}
        protocols = {session.protocol for session in sessions}
        choices = [("", OWN_LOGIN)] + [(credential.id, f"{credential.name}  ({credential.summary()})")
                                       for credential in self.store.credentials.sorted(RDP if protocols == {RDP}
                                                                                       else None)]
        for credential_id, label in choices:
            action = submenu.addAction(label)
            action.setCheckable(True)
            action.setChecked(current == {credential_id})
            actions[action] = lambda credential_id=credential_id: self.assign_credential(sessions, credential_id)
        submenu.addSeparator()
        actions[submenu.addAction("Manage Credentials...")] = self.show_credentials

    def assign_credential(self, sessions, credential_id):
        changed = self.store.credentials.assign(sessions, credential_id)
        skipped = len([session for session in sessions if session.credential_id != credential_id])
        if skipped:
            QMessageBox.information(self, "Use Credential", f"{skipped} Remote Desktop session"
                                    f"{'' if skipped == 1 else 's'} kept {'its' if skipped == 1 else 'their'} own "
                                    "login: Remote Desktop can only use a credential with a password.")
        if changed:
            self.fill_tree()

    def quick_connect(self, into=None):
        try:
            session = parse_quick_connect(self.quick_input.text(), self.quick_protocol.currentText())
            if not self.shows(session):
                raise ValueError(f"This page only opens {' and '.join(sorted(self.protocols))} sessions.")
        except ValueError as error:
            if into is not None:  # From a menu, perhaps in a pop-out window: the sidebar may not be in sight
                QMessageBox.warning(into, "Quick Connect", str(error))
                return
            set_hint(self.quick_status, str(error), "error")
            self.quick_status.setVisible(True)
            return
        self.page.open_session(session, saved=True, into=into)

    # ----------------------------------------------------------------- The session tree

    def fill_tree(self, select=None, select_folders=()):
        """Rebuild the tree. select is a session id or a list of them; select_folders are folder paths."""
        if select is None:
            select = [item.data(0, SESSION_ROLE) for item in self.tree.selectedItems() if item.data(0, SESSION_ROLE)]
            select_folders = select_folders or [item.data(0, FOLDER_ROLE) for item in self.tree.selectedItems()
                                                if item.data(0, FOLDER_ROLE)]
        selected = {select} if isinstance(select, str) else set(select)
        words = self.filter_input.text().lower().split()
        self.tree.setDragEnabled(not words)  # Hidden sessions would make a folder move unclear
        self.tree.clear()
        to_select = []
        folder_items = {}

        def folder_item(path):
            if not path:
                return self.tree.invisibleRootItem()
            if path in folder_items:
                return folder_items[path]
            parent_path, _, name = path.rpartition("/")
            parent = folder_item(parent_path)
            item = QTreeWidgetItem([name])
            font = QFont(item.font(0))
            font.setBold(True)
            item.setFont(0, font)
            item.setData(0, FOLDER_ROLE, path)
            parent.addChild(item)
            folder_items[path] = item
            return item

        self.fill_recent(words)
        if not words:
            for path in sorted(self.store.all_folders(), key=str.lower):
                folder_item(path)
        for session in sorted(self.visible_sessions(), key=lambda item: (item.folder.lower(), item.name.lower())):
            text = " ".join((session.path, session.target(), session.protocol, session.notes)).lower()
            if words and not all(word in text for word in words):
                continue
            item = QTreeWidgetItem([session.name])
            item.setData(0, SESSION_ROLE, session.id)
            lines = [f"{session.target()}  ({session.protocol})"]
            if session.folder:
                lines.append(f"Folder: {session.folder}")
            credential = self.store.credentials.get(session.credential_id)
            if credential is not None:
                lines.append(f"Credential: {credential.name}")
            if session.notes:
                lines.append(session.notes)
            item.setToolTip(0, "\n".join(lines))
            folder_item(session.folder).addChild(item)
            if session.id in selected:
                to_select.append(item)
        for path, item in folder_items.items():
            item.setExpanded(bool(words) or path not in self.collapsed)
            if path in select_folders:
                to_select.append(item)
        for index, item in enumerate(to_select):
            if index == 0:
                self.tree.setCurrentItem(item)
            item.setSelected(True)
        if not self.visible_sessions() and not words:
            hint = QTreeWidgetItem(["No saved sessions yet"])
            hint.setToolTip(0, "New creates a Remote Desktop session." if self.launch_only else
                            "New creates one; File > Import Sessions brings in your PuTTY or SecureCRT sessions.")
            hint.setFlags(Qt.NoItemFlags)
            self.tree.addTopLevelItem(hint)

    def fill_recent(self, words):
        """The Recent group at the top of the tree: the last connections made, newest first."""
        entries = []
        for entry, session in self.visible_recent():
            text = " ".join((session.name, session.target(), session.protocol)).lower()
            if not words or all(word in text for word in words):
                entries.append((entry, session))
        if not entries:
            return
        group = QTreeWidgetItem(["Recent"])
        group.setData(0, RECENT_ROLE, RECENT_KEY)
        group.setFlags(Qt.ItemIsEnabled)
        font = QFont(group.font(0))
        font.setBold(True)
        group.setFont(0, font)
        group.setForeground(0, QColor(COLORS["muted"]))
        group.setToolTip(0, f"The last {len(self.store.recent)} connections. Double-click one to reconnect; "
                            "right-click to save it as a session.")
        self.tree.addTopLevelItem(group)
        for entry, session in entries:
            saved = self.store.get(entry.saved_id) is not None
            item = QTreeWidgetItem([session.name])
            item.setData(0, RECENT_ROLE, entry.id)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            when = time.strftime("%Y-%m-%d %H:%M", time.localtime(entry.last_used)) if entry.last_used else "unknown"
            lines = [f"{session.target()}  ({session.protocol})", f"Last connected: {when}",
                     f"Saved session in {session.folder or 'the top level'}" if saved else
                     "Not saved: right-click > Save as Session to keep it"]
            item.setToolTip(0, "\n".join(lines))
            if not saved:
                italic = QFont(item.font(0))
                italic.setItalic(True)
                item.setFont(0, italic)
            group.addChild(item)
        group.setExpanded(bool(words) or RECENT_KEY not in self.collapsed)

    @staticmethod
    def group_key(item):
        """What the collapsed set calls a folder or the Recent group."""
        return RECENT_KEY if item.data(0, RECENT_ROLE) == RECENT_KEY else item.data(0, FOLDER_ROLE)

    def selected_id(self):
        item = self.tree.currentItem()
        return item.data(0, SESSION_ROLE) if item is not None else None

    def selected_folder(self):
        """The folder of the selected item (or the selected folder itself), for creating things in."""
        item = self.tree.currentItem()
        if item is None:
            return ""
        if item.data(0, FOLDER_ROLE):
            return item.data(0, FOLDER_ROLE)
        session = self.store.get(item.data(0, SESSION_ROLE))
        return session.folder if session else ""

    def on_item_activated(self, item, _column):
        entry = self.store.recent_entry(item.data(0, RECENT_ROLE))
        if entry is not None:
            self.open_recent(entry)
            return
        session = self.store.get(item.data(0, SESSION_ROLE))
        if session is not None:
            self.page.open_session(session)

    def show_tree_menu(self, position):
        item = self.tree.itemAt(position)
        if item is not None and not item.isSelected():
            self.tree.setCurrentItem(item)
        sessions, folders = self.selected_items()
        if item is not None and item.isSelected() and len(sessions) + len(folders) > 1:
            self.show_selection_menu(position, sessions, folders)
            return
        session = self.store.get(item.data(0, SESSION_ROLE)) if item is not None else None
        folder = item.data(0, FOLDER_ROLE) if item is not None else None
        entry = self.store.recent_entry(item.data(0, RECENT_ROLE)) if item is not None else None
        menu = QMenu(self)
        actions = {}
        if entry is not None:
            saved = self.store.get(entry.saved_id)
            actions[menu.addAction("Launch" if self.launch_only else "Connect")] = lambda: self.open_recent(entry)
            if not self.launch_only:
                actions[menu.addAction("Connect in New Window")] = lambda: self.open_recent(entry, window=True)
            self.add_companion_actions(menu, actions, self.store.recent_session(entry))
            menu.addSeparator()
            if saved is None:
                actions[menu.addAction("Save as Session...")] = lambda: self.save_recent(entry)
            else:
                actions[menu.addAction("Edit Saved Session...")] = lambda: self.edit_session(saved)
            actions[menu.addAction("Remove from Recent")] = lambda: self.forget_recent(entry)
            actions[menu.addAction("Clear Recent Connections")] = self.clear_recent
        elif item is not None and self.group_key(item) == RECENT_KEY:
            actions[menu.addAction("Clear Recent Connections")] = self.clear_recent
        if actions:
            chosen = menu.exec_(self.tree.viewport().mapToGlobal(position))
            if chosen in actions:
                actions[chosen]()
            return
        if session is not None:
            actions[menu.addAction("Launch" if self.launch_only else "Connect")] = lambda: self.page.open_session(session)
            if not self.launch_only:
                actions[menu.addAction("Connect in New Window")] = lambda: self.page.open_session(session, window=True)
            self.add_companion_actions(menu, actions, session)
            menu.addSeparator()
            actions[menu.addAction("Edit...")] = lambda: self.edit_session(session)
            self.add_credential_menu(menu, actions, [session])
            actions[menu.addAction("Duplicate")] = lambda: self.duplicate_session(session)
            actions[menu.addAction("Move to...")] = lambda: self.move_to_dialog([session], [])
            actions[menu.addAction("Delete")] = lambda: self.delete_session(session)
            menu.addSeparator()
        actions[menu.addAction("New Session...")] = lambda: self.new_session(self.selected_folder())
        actions[menu.addAction("New Folder...")] = lambda: self.new_folder(self.selected_folder())
        if folder:
            actions[menu.addAction("Rename Folder...")] = lambda: self.rename_folder(folder)
            actions[menu.addAction("Move Folder to...")] = lambda: self.move_to_dialog([], [folder])
            if "/" in folder:
                grandparent = folder.rpartition("/")[0].rpartition("/")[0]
                actions[menu.addAction("Move Up a Level")] = lambda: self.move_items([], [folder], grandparent)
            actions[menu.addAction("Delete Folder")] = lambda: self.delete_folder(folder)
        if not self.launch_only:
            menu.addSeparator()
            actions[menu.addAction("Import from PuTTY")] = self.import_from_putty
            actions[menu.addAction("Import from SecureCRT...")] = self.import_from_securecrt
        chosen = menu.exec_(self.tree.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def new_session(self, folder="", session=None):
        """The New Session dialog, filled in from session if given. Returns the saved session, or None."""
        session = session or self.make_session(folder)
        dialog = self.dialog_class(self, session, self.store.all_folders(), "New Session", self.store)
        if dialog.exec_():
            self.store.put(dialog.session)
            self.fill_tree(select=dialog.session.id)
            return dialog.session
        return None

    def edit_session(self, session):
        dialog = self.dialog_class(self, session.copy(id=session.id), self.store.all_folders(), "Edit Session", self.store)
        if dialog.exec_():
            self.store.put(dialog.session)
            for view in self.page.all_views():
                if view.session.id == session.id:
                    view.session = dialog.session  # Used from the next connect on
            self.fill_tree(select=dialog.session.id)

    def duplicate_session(self, session):
        copy = session.copy(name=self.store.unique_name(session.name, session.folder))
        self.store.put(copy)
        self.fill_tree(select=copy.id)

    def delete_session(self, session):
        reply = QMessageBox.question(self, "Delete Session", f"Delete the saved session {session.name}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.store.delete(session.id)
            self.fill_tree()

    def delete_selected(self):
        item = self.tree.currentItem()
        if item is None:
            return
        sessions, folders = self.selected_items()
        entry = self.store.recent_entry(item.data(0, RECENT_ROLE))
        if len(sessions) + len(folders) > 1:
            self.delete_items(sessions, folders)
        elif entry is not None:
            self.forget_recent(entry)
        elif folders:
            self.delete_folder(folders[0])
        elif sessions:
            self.delete_session(sessions[0])

    def delete_items(self, sessions, folders):
        inside = sum(1 for session in self.store.sessions
                     if any(session.folder == folder or session.folder.startswith(folder + "/") for folder in folders))
        parts = []
        if sessions:
            parts.append(f"{len(sessions)} session{'' if len(sessions) == 1 else 's'}")
        if folders:
            parts.append(f"{len(folders)} folder{'' if len(folders) == 1 else 's'}" +
                         (f" (with the {inside} session{'' if inside == 1 else 's'} in them)" if inside else ""))
        reply = QMessageBox.question(self, "Delete", f"Delete {' and '.join(parts)}?", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.store.delete_many({session.id for session in sessions})
            for folder in folders:
                self.store.delete_folder(folder)
            self.fill_tree()

    def new_folder(self, parent=""):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:" + (f" (inside {parent})" if parent else ""))
        if ok and normalize_folder(name):
            path = self.store.add_folder(f"{parent}/{name}" if parent else name)
            self.collapsed.discard(path)
            self.fill_tree()

    def rename_folder(self, folder):
        name, ok = QInputDialog.getText(self, "Rename Folder", "New name:", text=folder.rpartition("/")[2])
        if ok and normalize_folder(name) and "/" not in name.strip():
            parent = folder.rpartition("/")[0]
            new = normalize_folder(f"{parent}/{name}" if parent else name)
            self.store.rename_folder(folder, new)
            self.remap_collapsed(folder, new)
            self.fill_tree(select_folders=[new])

    def delete_folder(self, folder):
        count = sum(1 for session in self.store.sessions
                    if session.folder == folder or session.folder.startswith(folder + "/"))
        message = f"Delete the folder {folder}" + (f" and the {count} session{'' if count == 1 else 's'} in it"
                                                   if count else "") + "?"
        reply = QMessageBox.question(self, "Delete Folder", message, QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.store.delete_folder(folder)
            self.fill_tree()

    def import_from_putty(self):
        try:
            added = import_putty(self.store)
        except OSError as error:
            QMessageBox.critical(self, "Import from PuTTY", f"Couldn't read PuTTY's sessions:\n\n{error}")
            return
        self.fill_tree()
        message = f"Imported {added} session{'' if added == 1 else 's'} from PuTTY into the folder " \
                  "\"Imported from PuTTY\"." if added else \
            "No new PuTTY sessions to import (none saved, or all imported already)."
        QMessageBox.information(self, "Import from PuTTY", message)

    def import_from_securecrt(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import from SecureCRT", "",
                                              "SecureCRT export (*.xml);;All files (*)")
        if not path:
            return
        try:
            export = read_securecrt_export(path)
        except SecureCrtError as error:
            QMessageBox.warning(self, "Import from SecureCRT", str(error))
            return
        decrypted = self.decrypt_securecrt(export)
        protect = None
        if decrypted and ensure_unlocked(self, self.store, "The master password is needed to save the imported "
                                                           "passwords."):
            protect = self.store.vault.protect
        try:
            added, saved = import_securecrt(self.store, export, protect)
        except OSError as error:
            QMessageBox.critical(self, "Import from SecureCRT", f"Couldn't save the sessions:\n\n{error}")
            return
        self.collapsed.discard(SECURECRT_FOLDER)
        self.fill_tree()
        if not added:
            message = "No new sessions to import (none in the file, or all imported already)."
        else:
            message = f"Imported {added} session{'' if added == 1 else 's'} into the folder \"{SECURECRT_FOLDER}\"."
            if saved:
                how = "your master password and Windows account" if self.store.vault.enabled else \
                    "your Windows account"
                message += f"\n\nSaved {saved} password{'' if saved == 1 else 's'}, encrypted with {how}."
            missed = sum(1 for item in export.sessions if item.encrypted_password) - saved
            if missed > 0:
                message += (f"\n\n{missed} saved password{' was' if missed == 1 else 's were'} not imported; NOMAD "
                            "asks for them on the first connection.")
        if export.skipped:
            message += (f"\n\nSkipped {len(export.skipped)} session{'' if len(export.skipped) == 1 else 's'} NOMAD "
                        "can't open (RLogin, TAPI or no host): " + ", ".join(export.skipped[:5]) +
                        (", ..." if len(export.skipped) > 5 else ""))
        QMessageBox.information(self, "Import from SecureCRT", message)

    def decrypt_securecrt(self, export):
        """Decrypt the export's saved passwords, asking for SecureCRT's configuration passphrase if one was set.
        Returns how many decrypted (0 if the user skips them)."""
        if not export.encrypted_count:
            return 0
        try:
            return export.decrypt("")
        except WrongPassphrase:
            pass
        count = export.encrypted_count
        prompt = (f"{count} of these sessions have saved passwords, encrypted with SecureCRT's configuration "
                  "passphrase.\n\nEnter the passphrase to import the passwords too, or Cancel to import the "
                  "sessions without them:")
        while True:
            passphrase, ok = QInputDialog.getText(self, "SecureCRT Passphrase", prompt, QLineEdit.Password)
            if not ok:
                return 0
            try:
                return export.decrypt(passphrase)
            except WrongPassphrase:
                prompt = "That passphrase didn't decrypt the saved passwords. Try again, or Cancel to import the " \
                         "sessions without them:"

    # ----------------------------------------------------------------- Recent connections

    def open_recent(self, entry, window=False, into=None):
        self.page.open_session(self.store.recent_session(entry), window=window, into=into)

    def save_recent(self, entry):
        session = entry.session.copy(name=self.store.unique_name(entry.session.name, entry.session.folder))
        dialog = self.dialog_class(self, session, self.store.all_folders(), "Save Session", self.store)
        if dialog.exec_():
            self.store.put(dialog.session)
            self.store.link_recent(dialog.session)
            self.fill_tree(select=dialog.session.id)

    def forget_recent(self, entry):
        self.store.forget_recent(entry.id)
        self.fill_tree()

    def clear_recent(self):
        entries = self.visible_recent()
        if not entries:
            return
        reply = QMessageBox.question(self, "Clear Recent Connections", "Clear the list of recent connections? "
                                     "Saved sessions aren't affected.", QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            for entry, session in entries:
                self.store.forget_recent(entry.id)
            self.fill_tree()

    # ----------------------------------------------------------------- Moving sessions and folders

    def selected_items(self):
        """The selected saved sessions and folders, leaving out anything inside a selected folder (it moves or goes
        with its folder)."""
        folders = [item.data(0, FOLDER_ROLE) for item in self.tree.selectedItems() if item.data(0, FOLDER_ROLE)]
        folders = [folder for folder in folders
                   if not any(folder.startswith(other + "/") for other in folders if other != folder)]

        def inside(path):
            return any(path == folder or path.startswith(folder + "/") for folder in folders)

        sessions = [self.store.get(item.data(0, SESSION_ROLE)) for item in self.tree.selectedItems()
                    if item.data(0, SESSION_ROLE)]
        sessions = [session for session in sessions if session is not None and not inside(session.folder)]
        return sessions, folders

    def add_companion_actions(self, menu, actions, session):
        """Open in SCP / Open in Terminal, from the page this sidebar is on."""
        for label, action in self.page.companion_actions(session):
            actions[menu.addAction(label)] = action

    def show_selection_menu(self, position, sessions, folders):
        """The right-click menu when several sessions and folders are selected."""
        menu = QMenu(self)
        actions = {}
        if sessions:
            label = f"{'Launch' if self.launch_only else 'Connect'} {len(sessions)} Session{'' if len(sessions) == 1 else 's'}"
            actions[menu.addAction(label)] = lambda: [self.page.open_session(session) for session in sessions]
            menu.addSeparator()
        self.add_credential_menu(menu, actions, sessions)
        actions[menu.addAction("Move to...")] = lambda: self.move_to_dialog(sessions, folders)
        actions[menu.addAction("Delete...")] = lambda: self.delete_items(sessions, folders)
        chosen = menu.exec_(self.tree.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def move_to_dialog(self, sessions, folders):
        parts = []
        if len(sessions) == 1 and not folders:
            parts.append(sessions[0].name)
        elif sessions:
            parts.append(f"{len(sessions)} sessions")
        if len(folders) == 1:
            parts.append(f"the folder {folders[0]}")
        elif folders:
            parts.append(f"{len(folders)} folders")
        current = sessions[0].folder if sessions else folders[0].rpartition("/")[0] if folders else ""
        dialog = FolderPickerDialog(self, self.store.all_folders(), " and ".join(parts), current, folders)
        if dialog.exec_():
            self.move_items([session.id for session in sessions], folders, dialog.folder)

    def move_items(self, session_ids, folders, target):
        """Move sessions and folders into a folder ("" for the top level). Folders merge with ones of the same name
        already there; sessions whose names are taken get " (2)" added."""
        target = normalize_folder(target)
        folders = [folder for folder in folders
                   if not any(folder.startswith(other + "/") for other in folders if other != folder)]
        if any(target == folder or target.startswith(folder + "/") for folder in folders):
            QMessageBox.warning(self, "Move", "A folder can't be moved into itself.")
            return
        moved_folders = []
        for folder in folders:
            new = self.store.move_folder(folder, target)
            self.remap_collapsed(folder, new)
            moved_folders.append(new)

        def inside(path):
            return any(path == folder or path.startswith(folder + "/") for folder in moved_folders)

        session_ids = [session_id for session_id in session_ids
                       if self.store.get(session_id) is not None and not inside(self.store.get(session_id).folder)]
        if session_ids:
            self.store.move_sessions(set(session_ids), target)
        self.collapsed.discard(target)
        self.fill_tree(select=session_ids, select_folders=moved_folders)

    def remap_collapsed(self, old, new):
        """A folder moved or was renamed: keep it (and folders inside it) open or closed as they were."""
        self.collapsed = {new + folder[len(old):] if folder == old or folder.startswith(old + "/") else folder
                          for folder in self.collapsed}
