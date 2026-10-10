"""A page of session tabs beside the saved-session sidebar, with pop-out windows: the base of the Terminal and SCP
pages."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QHBoxLayout, QLabel, QListWidget, QListWidgetItem, QMenu, \
    QMessageBox, QSplitter, QStackedWidget, QToolButton, QVBoxLayout, QWidget

from ..terminal.sessions import DEFAULT_PORTS, SERIAL, SSH, normalize_folder, parse_quick_connect
from .session_dialog import SessionDialog
from .session_manager import SessionManager
from .session_tabs import SessionTabs, SessionWindow
from .terminal_view import CONNECTED, DISCONNECTED
from .theme import COLORS


class SessionPage(QWidget):
    """A page of session tabs beside the session sidebar: the Terminal page, and the SCP page. Subclasses set the
    protocols the sidebar shows, the placeholder text, and make_view(session)."""
    protocols = None
    settings_prefix = "terminal"
    window_title = "NOMAD Terminal"
    placeholder_text = ""
    kind = "terminal session"  # For "3 terminal sessions are still connected"
    tiling = False  # Offer the Layout menu, to show several sessions at once, and Send to All
    broadcast_scope = "all"  # Send to All: "all" connected sessions, those on "screen", or the "window"'s
    mirror_typing = False  # Send to All's Type in All: typing in one session goes to the others too

    def __init__(self, window, store):
        super().__init__(window)
        self.window = window
        self.store = store
        self.windows = []
        self.closing = False
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)  # Every pixel goes to the sessions
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(True)
        self.splitter = splitter
        self.manager = SessionManager(self, self.store, self.protocols, self.settings_prefix)
        splitter.addWidget(self.manager)

        # Open sessions
        self.stack = QStackedWidget()
        placeholder = QLabel(self.placeholder_text)
        placeholder.setAlignment(Qt.AlignCenter)
        placeholder.setWordWrap(True)
        placeholder.setStyleSheet(f"color: {COLORS['muted']};")
        self.tabs = SessionTabs(self)
        self.tabs.emptied.connect(self.on_tabs_emptied)
        self.stack.addWidget(placeholder)
        self.stack.addWidget(self.tabs)
        splitter.addWidget(self.stack)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([210, 990])
        layout.addWidget(splitter)

        # Beside the tabs: hide or show the session list, a menu of sessions while it's hidden, and focus mode
        corner_left = QWidget()
        left_layout = QHBoxLayout(corner_left)
        left_layout.setContentsMargins(0, 0, 4, 0)
        left_layout.setSpacing(0)
        self.manager_toggle = QToolButton()
        self.manager_toggle.setAutoRaise(True)
        self.sessions_button = QToolButton()
        self.sessions_button.setText("Sessions")
        self.sessions_button.setAutoRaise(True)
        self.sessions_button.setPopupMode(QToolButton.InstantPopup)
        self.sessions_menu = QMenu(self.sessions_button)
        self.sessions_menu.aboutToShow.connect(self.fill_sessions_menu)
        self.sessions_button.setMenu(self.sessions_menu)
        left_layout.addWidget(self.manager_toggle)
        left_layout.addWidget(self.sessions_button)
        self.tabs.setCornerWidget(corner_left, Qt.TopLeftCorner)
        self.focus_button = QToolButton()
        self.focus_button.setText("Focus")
        self.focus_button.setAutoRaise(True)
        self.focus_button.setCheckable(True)
        self.focus_button.setToolTip("Give the sessions the whole window: hides NOMAD's sidebar, the adapter bar and "
                                     "the session list (F11)")
        self.tabs.setCornerWidget(self.focus_button, Qt.TopRightCorner)

        self.manager_toggle.clicked.connect(lambda: self.set_manager_visible(not self.manager_shown))
        self.focus_button.clicked.connect(lambda checked: self.window.set_focus_mode(checked))
        self.splitter.splitterMoved.connect(self.on_splitter_moved)
        self.set_manager_visible(True)

    def focus_find(self):
        self.set_manager_visible(True)
        self.manager.filter_input.setFocus()
        self.manager.filter_input.selectAll()

    def make_view(self, session):
        raise NotImplementedError

    def companion_actions(self, session):
        """[(label, action)] for opening a session on the other page (Terminal ↔ SCP), for right-click menus."""
        return []

    # ----------------------------------------------------------------- Making room

    manager_shown = True

    def set_manager_visible(self, visible, remember=True):
        """Show or hide the session list. remember=False is for focus mode, which puts it back afterwards."""
        if remember:
            self.manager_shown = visible
        self.manager.setVisible(visible)
        if visible and self.splitter.sizes()[0] == 0:
            self.splitter.setSizes([210, max(400, self.splitter.width() - 210)])
        self.manager_toggle.setText("«" if visible else "»")
        self.manager_toggle.setToolTip("Hide the session list" if visible else "Show the session list")
        self.sessions_button.setVisible(not visible)

    def on_splitter_moved(self, position, _index):
        if position == 0:  # Dragged all the way closed: same as hiding it
            self.set_manager_visible(False)

    def show_page(self, index):
        """Switch between the placeholder (0) and the open sessions (1). With nothing open, the buttons that bring
        the session list back aren't on screen, so it's always shown then; the choice to hide it applies again once
        a session opens."""
        self.stack.setCurrentIndex(index)
        if not self.window.focus_mode:
            self.set_manager_visible(self.manager_shown or index == 0, remember=False)

    def on_tabs_emptied(self):
        self.show_page(0)

    def fill_sessions_menu(self):
        self.manager.fill_menu(self.sessions_menu)
        self.sessions_menu.addAction("Show the Session List", lambda: self.set_manager_visible(True))

    # ----------------------------------------------------------------- Page interface

    def save_settings(self, settings):
        prefix = self.settings_prefix
        settings.setValue(f"{prefix}/splitter", self.splitter.saveState())
        settings.setValue(f"{prefix}/manager", self.manager_shown)
        if self.tiling:
            settings.setValue(f"{prefix}/layout", self.tabs.layout_key)
            if self.tabs.command_bar is not None:
                settings.setValue(f"{prefix}/buttons", self.tabs.command_bar.isVisibleTo(self.tabs))
        self.manager.save_settings(settings)

    def restore_settings(self, settings):
        prefix = self.settings_prefix
        state = settings.value(f"{prefix}/splitter")
        if state is not None:
            self.splitter.restoreState(state)
        self.manager_shown = settings.value(f"{prefix}/manager", True, bool)
        if self.tiling:
            self.tabs.set_layout(settings.value(f"{prefix}/layout", "tabs", str))
            self.tabs.show_command_bar(settings.value(f"{prefix}/buttons", False, bool))
        self.show_page(self.stack.currentIndex())
        self.manager.restore_settings(settings)

    def shutdown(self):
        self.closing = True
        for window in list(self.windows):
            window.close()
        for view in self.tabs.views():
            self.tabs.close_view(view, ask=False)

    # ----------------------------------------------------------------- Send to All

    def all_tabs(self):
        return [self.tabs] + [window.tabs for window in self.windows]

    def broadcast_targets(self, scope, origin=None):
        """The connected sessions Send to All reaches: all, those on screen (the one showing in each pane of the
        windows in view), or those in the `origin` tabs' window. Sessions left out never are."""
        if scope == "window" and origin is not None:
            views = origin.views()
        elif scope == "screen":
            views = [pane.current() for tabs in self.all_tabs() if tabs.isVisible() for pane in tabs.panes
                     if pane.current() is not None]
        else:
            views = self.all_views()
        return [view for view in views if view.state == CONNECTED and hasattr(view, "send_line") and
                not view.left_out]

    def send_to_all(self, command, scope, origin=None):
        """Send a command line to the sessions; returns how many it went to."""
        return sum(bool(view.send_line(command)) for view in self.broadcast_targets(scope, origin))

    def set_broadcast(self, scope=None, mirror=None):
        if scope is not None:
            self.broadcast_scope = scope
        if mirror is not None:
            self.mirror_typing = mirror
        self.refresh_send_bars()

    def refresh_send_bars(self):
        for tabs in self.all_tabs():
            if tabs.send_bar is not None:
                tabs.send_bar.refresh()

    def mirror_typed(self, source, text, block=False):
        """Type in All: what was typed in one session goes to the others Send to All reaches. block: a paste
        sent line by line, which each session sends with its own line delay."""
        if not self.mirror_typing or source.left_out:
            return
        origin = next((tabs for tabs in self.all_tabs() if tabs.pane_of(source) is not None), None)
        for target in self.broadcast_targets(self.broadcast_scope, origin):
            if target is source:
                continue
            if block:
                target.send_block(text, final_enter=False)
            else:  # Each session's own Enter (\r, or \r\n for some Telnet devices)
                target.send_text(target.view.enter if text == source.view.enter else text)

    def send_keys_to_all(self, text, scope, origin=None):
        """Send keys as typed (Ctrl+C and the like) to the sessions; returns how many they went to."""
        return sum(bool(view.send_text(text)) for view in self.broadcast_targets(scope, origin))

    def all_views(self):
        views = self.tabs.views()
        for window in self.windows:
            views += window.tabs.views()
        return views

    def confirm_close(self):
        """Before the app closes: ask if sessions are still connected. Returns False to keep the app open."""
        connected = [view for view in self.all_views() if view.state != DISCONNECTED]
        if not connected:
            return True
        count = len(connected)
        reply = QMessageBox.question(self.window, "Sessions Open",
                                     f"{count} {self.kind}{'' if count == 1 else 's'} "
                                     f"{'is' if count == 1 else 'are'} still connected. Close NOMAD and "
                                     "disconnect?", QMessageBox.Yes | QMessageBox.No)
        return reply == QMessageBox.Yes

    # ----------------------------------------------------------------- Opening sessions

    def open_session(self, session, saved=True, window=False, into=None):
        """Open a tab for a session and connect. saved=False opens a copy that isn't tied to the saved one.
        into: the tabs to open it in (a pop-out window's), instead of this page's."""
        if not saved:
            session = session.copy()
        view = self.make_view(session)
        self.store.remember(session)
        if window:
            new_window = self.new_window()
            new_window.tabs.add_view(view)
            new_window.update_title()
            new_window.show()
        elif into is not None and into is not self.tabs:
            into.add_view(view)
            into.window().activateWindow()
        else:
            self.show_page(1)
            self.tabs.add_view(view)
            self.window.navigator.setCurrentWidget(self)
        view.connect_session()
        return view

    def saved_matches(self, host, aliases=(), protocol=SSH):
        """The saved sessions for a host from another page (aliases: its other addresses and names)."""
        if self.protocols is not None and protocol not in self.protocols:
            return []
        return self.store.matching([host, *aliases], protocol)

    def open_address(self, text, protocol=SSH, aliases=(), name="", folder="", use_saved=True):
        """Connect from another page, such as the Network Map's "Open SSH Session": with the saved session for the
        host if there is one (asking which if there are several), so its user name and saved password are used.
        Otherwise a quick connection, named name and suggesting folder when it's saved. aliases: the host's other
        addresses and names, which a saved session may use instead."""
        try:
            session = parse_quick_connect(text, protocol)
        except ValueError as error:
            QMessageBox.warning(self, "Connect", str(error))
            return None
        if use_saved and session.protocol != SERIAL:
            matches = self.store.matching([session.host, *aliases], session.protocol, session.username)
            if not matches:
                chosen = session
            elif len(matches) == 1:
                chosen = matches[0]
            else:
                chosen = choose_saved_session(self, session, matches)
            if chosen is None:
                return None
            if chosen is not session:
                return self.open_session(chosen)
        if name and not session.username:
            session.name = name.replace("/", "-")
        session.folder = normalize_folder(folder)
        return self.open_session(session, saved=True)

    def create_session(self, host, protocol=SSH, name="", folder=""):
        """From another page's "Create Terminal Session..." (or the RDP page's "Create RDP Session..."): the New
        Session dialog with host filled in, named name (or the host) in folder. Returns the saved session, or None
        if cancelled."""
        folder = normalize_folder(folder)
        session = self.manager.make_session(folder)
        session.protocol, session.host = protocol, host
        session.port = DEFAULT_PORTS.get(protocol, session.port)
        session.name = self.store.unique_name((name or host).replace("/", "-"), folder)
        return self.manager.new_session(folder, session)

    def new_window(self):
        new_window = SessionWindow(self)
        if self.tabs.command_bar is not None:  # Command buttons as in the main window
            new_window.tabs.show_command_bar(self.tabs.command_bar.isVisibleTo(self.tabs))
        self.windows.append(new_window)
        return new_window

    def pop_out(self, view):
        self.tabs.take_view(view)
        new_window = self.new_window()
        new_window.tabs.add_view(view)
        new_window.update_title()
        new_window.show()
        new_window.activateWindow()

    def move_to_main(self, view, source):
        source.take_view(view)
        self.show_page(1)
        self.tabs.add_view(view)
        self.window.navigator.setCurrentWidget(self)
        self.window.activateWindow()

    def save_quick_session(self, view):
        session = view.session
        dialog = SessionDialog(self, session.copy(id=session.id), self.store.all_folders(), "Save Session", self.store)
        if dialog.exec_():
            self.store.put(dialog.session)
            self.store.link_recent(dialog.session)
            view.session = dialog.session
            self.manager.fill_tree(select=dialog.session.id)


def choose_saved_session(parent, session, matches):
    """Ask which of several saved sessions to open for a host. Returns one of them, session for a new connection
    that doesn't use them, or None if cancelled."""
    dialog = QDialog(parent)
    dialog.setWindowTitle("Open Session")
    layout = QVBoxLayout(dialog)
    label = QLabel(f"There are {len(matches)} saved sessions for {session.host}. Which one?")
    label.setWordWrap(True)
    layout.addWidget(label)
    choices = QListWidget()
    for match in matches:
        item = QListWidgetItem(f"{match.path}    ({match.target()})")
        item.setData(Qt.UserRole, match)
        choices.addItem(item)
    new_item = QListWidgetItem(f"New connection to {session.host} (not a saved session)")
    new_item.setData(Qt.UserRole, session)
    choices.addItem(new_item)
    choices.setCurrentRow(0)
    choices.itemDoubleClicked.connect(dialog.accept)
    layout.addWidget(choices)
    buttons = QDialogButtonBox(QDialogButtonBox.Open | QDialogButtonBox.Cancel)
    buttons.accepted.connect(dialog.accept)
    buttons.rejected.connect(dialog.reject)
    layout.addWidget(buttons)
    dialog.resize(460, 260)
    if not dialog.exec_() or choices.currentItem() is None:
        return None
    return choices.currentItem().data(Qt.UserRole)
