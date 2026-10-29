"""Tabs of open sessions and the pop-out windows they can move to. Shared by the Terminal and SCP pages.

A view (a tab's widget) has: session, title, state (CONNECTING / CONNECTED / DISCONNECTED), a state_changed(view)
signal, connect_session(), reconnect(), disconnect_session(), shutdown(), confirm_close() (False keeps the tab open),
focus_target() (the widget to focus), and add_tab_actions(menu, actions) for its own entries in the tab's menu.
The page has: tabs, store, closing, tiling, open_session(session, saved), pop_out(view), move_to_main(view, source)
and save_quick_session(view), plus a window_title ("NOMAD Terminal").

Tiling: the sessions area can be split into panes (side by side, stacked or a grid). Each pane has its own tabs;
drag a tab onto another pane (or right-click it > Move to) to move the session there, even to a pane in another
window. Clicking in a pane makes it the active one, where new sessions open; an empty pane has an Open Session
menu of its own, and a pop-out window a Sessions menu, as they have no session list beside them. With the "tabs"
layout there's a single pane: ordinary tabs.
"""
from PyQt5.QtCore import QEvent, QMimeData, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QDrag, QKeySequence, QMouseEvent
from PyQt5.QtWidgets import QActionGroup, QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu, \
    QMessageBox, QShortcut, QSplitter, QStackedWidget, QTabBar, QToolButton, QVBoxLayout, QWidget

from .command_bar import CommandBar
from .send_bar import SendBar
from .terminal_view import CONNECTED, CONNECTING, DISCONNECTED
from .theme import COLORS

STATE_COLORS = {CONNECTED: COLORS["success"], CONNECTING: COLORS["warning"], DISCONNECTED: COLORS["muted"]}
DRAG_MIME = "application/x-nomad-session-tab"

# (key, menu label, panes in each row, pane names for "Move to")
LAYOUTS = [
    ("tabs", "One at a Time (Tabs)", [1], [""]),
    ("side2", "Two Side by Side", [2], ["Left", "Right"]),
    ("stack2", "Two Stacked", [1, 1], ["Top", "Bottom"]),
    ("side3", "Three Side by Side", [3], ["Left", "Middle", "Right"]),
    ("stack3", "Three Stacked", [1, 1, 1], ["Top", "Middle", "Bottom"]),
    ("grid4", "Four in a Grid (2 × 2)", [2, 2], ["Top Left", "Top Right", "Bottom Left", "Bottom Right"]),
    ("grid6", "Six in a Grid (3 × 2)", [3, 3],
     ["Top Left", "Top Middle", "Top Right", "Bottom Left", "Bottom Middle", "Bottom Right"]),
]
LAYOUT_ROWS = {key: rows for key, _, rows, _ in LAYOUTS}
PANE_NAMES = {key: names for key, _, _, names in LAYOUTS}


def arrange(groups, pane_count, focused=None):
    """Share sessions out among the panes of a new layout. groups: [(views, current view)] of the old panes that
    have sessions, in order; returns one (views, current) per new pane. One group (from ordinary tabs) is dealt out
    in tab order, a run to each pane. Otherwise each group keeps to the pane in its place (groups past the last pane
    join it), and any empty panes take a session from the fullest ones. The focused view stays selected."""
    result = [([], None) for _ in range(pane_count)]
    if len(groups) == 1:
        views, current = groups[0]
        count = min(len(views), pane_count)
        start = 0
        for index in range(count):
            size = len(views) // count + (1 if index < len(views) % count else 0)
            chunk = views[start:start + size]
            result[index] = (chunk, current if current in chunk else None)
            start += size
        return result
    for index, (views, current) in enumerate(groups):
        target = min(index, pane_count - 1)
        merged, merged_current = result[target]
        if focused in views or merged_current is None:
            merged_current = current
        result[target] = (merged + views, merged_current)
    for index in range(pane_count):
        if result[index][0]:
            continue
        donor_views, donor_current = max(result, key=lambda group: len(group[0]))
        keep = donor_current or donor_views[0] if donor_views else None
        movable = [view for view in donor_views if view is not keep]
        if movable:
            donor_views.remove(movable[0])
            result[index] = ([movable[0]], movable[0])
    return result


class PaneTabBar(QTabBar):
    """A pane's tabs. Dragging a tab well above or below the bar picks it up, to drop on another pane."""

    def __init__(self, pane):
        super().__init__()
        self.pane = pane
        self.press_position = None

    def mousePressEvent(self, event):
        self.press_position = event.pos() if event.button() == Qt.LeftButton else None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        outside = not self.rect().adjusted(0, -12, 0, 12).contains(event.pos())
        if self.press_position is not None and event.buttons() & Qt.LeftButton and outside and \
                self.pane.tabs.can_drag():
            index = self.tabAt(self.press_position)
            self.press_position = None
            if index >= 0:
                # Finish the bar's own tab-moving first, or the tab is left drawn where the mouse was
                super().mouseReleaseEvent(QMouseEvent(QEvent.MouseButtonRelease, event.pos(), Qt.LeftButton,
                                                      Qt.NoButton, Qt.NoModifier))
                self.pane.start_drag(index)
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self.press_position = None
        super().mouseReleaseEvent(event)


class SessionPane(QFrame):
    """One tile of the sessions area: its own tabs, and the session of the selected one (or a hint when empty)."""

    def __init__(self, tabs):
        super().__init__()
        self.tabs = tabs
        self.views = []  # In tab order
        self.setObjectName("sessionPane")
        self.setAcceptDrops(True)
        self.setMinimumSize(160, 100)  # Overrides the contents' own minimum, so the panes always fit
        self.bar = PaneTabBar(self)
        self.bar.setTabsClosable(True)
        self.bar.setMovable(True)
        self.bar.setDocumentMode(True)
        self.bar.setExpanding(False)
        self.bar.setContextMenuPolicy(Qt.CustomContextMenu)
        self.bar.customContextMenuRequested.connect(self.show_tab_menu)
        self.bar.tabCloseRequested.connect(lambda index: tabs.close_view(self.views[index]))
        self.bar.currentChanged.connect(self.on_selected)
        self.bar.tabMoved.connect(lambda source, destination:
                                  self.views.insert(destination, self.views.pop(source)))
        self.placeholder = QWidget()
        placeholder_layout = QVBoxLayout(self.placeholder)
        hint = QLabel("Empty pane: open a session here, or drag a tab here.")
        hint.setAlignment(Qt.AlignCenter)
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLORS['muted']};")
        self.open_button = QToolButton()
        self.open_button.setText("Open Session")
        self.open_button.setPopupMode(QToolButton.InstantPopup)
        open_menu = QMenu(self.open_button)
        open_menu.aboutToShow.connect(lambda: self.tabs.fill_open_menu(open_menu, self))
        self.open_button.setMenu(open_menu)
        placeholder_layout.addStretch()
        placeholder_layout.addWidget(hint)
        placeholder_layout.addWidget(self.open_button, 0, Qt.AlignHCenter)
        placeholder_layout.addStretch()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.placeholder)

        layout = QVBoxLayout(self)
        layout.setSpacing(0)
        header = QHBoxLayout()
        header.setContentsMargins(0, 0, 0, 0)
        header.setSpacing(0)
        self.left_slot = QHBoxLayout()
        self.right_slot = QHBoxLayout()
        header.addLayout(self.left_slot)
        header.addWidget(self.bar, 1)
        header.addLayout(self.right_slot)
        layout.addLayout(header)
        layout.addWidget(self.stack, 1)
        self.set_style(active=False, tiled=False)

    def current(self):
        index = self.bar.currentIndex()
        return self.views[index] if 0 <= index < len(self.views) else None

    def add(self, view, select=True):
        syncing, self.tabs.syncing = self.tabs.syncing, True
        self.views.append(view)
        self.stack.addWidget(view)
        index = self.bar.addTab(view.title)
        if select:
            self.bar.setCurrentIndex(index)
        self.tabs.syncing = syncing
        self.update_tab(view)
        self.show_current()

    def remove(self, view):
        """Take a view out of this pane; it's parked in the tabs' hidden store until it goes elsewhere."""
        index = self.views.index(view)
        syncing, self.tabs.syncing = self.tabs.syncing, True
        self.views.pop(index)
        self.bar.removeTab(index)
        self.stack.removeWidget(view)
        view.setParent(self.tabs.storage)
        self.tabs.syncing = syncing
        self.show_current()

    def select(self, view):
        syncing, self.tabs.syncing = self.tabs.syncing, True
        self.bar.setCurrentIndex(self.views.index(view))
        self.tabs.syncing = syncing
        self.show_current()

    def show_current(self):
        self.stack.setCurrentWidget(self.current() or self.placeholder)

    def update_tab(self, view):
        index = self.views.index(view)
        self.bar.setTabText(index, view.title)
        left_out = " (left out of Send to All)" if getattr(view, "left_out", False) else ""
        self.bar.setTabToolTip(index, f"{view.session.target()} ({view.session.protocol}): {view.state}{left_out}")
        self.bar.setTabText(index, f"⊘ {view.title}" if left_out else view.title)
        self.bar.setTabTextColor(index, QColor(STATE_COLORS[view.state]))

    def on_selected(self, _index):
        if self.tabs.syncing:
            return
        self.show_current()
        self.tabs.activate(self, focus=True)

    def set_style(self, active, tiled, drop_target=False):
        """Tiled panes get a border, in the accent color on the active pane (and on a pane a tab is dragged over);
        a single pane gets none, so it looks like ordinary tabs."""
        self.layout().setContentsMargins(*((1, 1, 1, 1) if tiled else (0, 0, 0, 0)))
        color = COLORS["link"] if drop_target else COLORS["accent"] if active else COLORS["border"]
        width = 2 if drop_target else 1
        self.setStyleSheet(f"#sessionPane {{ border: {width}px solid {color}; }}" if tiled else "")

    def show_tab_menu(self, position):
        index = self.bar.tabAt(position)
        if index >= 0:
            self.tabs.show_view_menu(self.views[index], self.bar.mapToGlobal(position))

    def mousePressEvent(self, event):
        self.tabs.activate(self, focus=True)
        super().mousePressEvent(event)

    # ----------------------------------------------------------------- Dragging tabs between panes

    def start_drag(self, index):
        view = self.views[index]
        SessionTabs.dragging = (self.tabs, view)
        mime = QMimeData()
        mime.setData(DRAG_MIME, view.title.encode("utf-8"))
        drag = QDrag(self.bar)
        drag.setMimeData(mime)
        drag.setPixmap(self.bar.grab(self.bar.tabRect(index)))
        drag.exec_(Qt.MoveAction)
        SessionTabs.dragging = None

    def accepts_drag(self, event):
        """A tab from another pane of the same page (Terminal or SCP), in this window or another."""
        if not event.mimeData().hasFormat(DRAG_MIME) or SessionTabs.dragging is None:
            return False
        source, view = SessionTabs.dragging
        return source.page is self.tabs.page and view not in self.views

    def dragEnterEvent(self, event):
        if self.accepts_drag(event):
            event.acceptProposedAction()
            self.set_style(self is self.tabs.active_pane, self.tabs.tiled(), drop_target=True)
        else:
            event.ignore()

    def dragLeaveEvent(self, event):
        self.tabs.update_panes()
        super().dragLeaveEvent(event)

    def dropEvent(self, event):
        if self.accepts_drag(event):
            event.acceptProposedAction()
            source, view = SessionTabs.dragging
            # After the drag has finished: moving the last tab out of a pop-out window closes it
            QTimer.singleShot(0, lambda: self.tabs.move_view(view, self, source))
        self.tabs.update_panes()


class SessionTabs(QWidget):
    """Tabs of open sessions, in one pane or tiled across several. Used on a page and in pop-out windows."""
    emptied = pyqtSignal()
    currentChanged = pyqtSignal(int)
    dragging = None  # (tabs, view) while a tab is dragged, from any window

    def __init__(self, page, parent=None):
        super().__init__(parent)
        self.page = page
        self.panes = []
        self.active_pane = None
        self.grid = None
        self.layout_key = "tabs"
        self.syncing = False  # Changing a pane's tabs in code, not by a click
        self.left_corners = []
        self.right_corners = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.storage = QWidget(self)  # Parent of views between panes, and of the corner widgets while re-tiling
        self.storage.hide()
        self.layout_button = None
        self.send_bar = None
        self.command_bar = None
        if getattr(page, "tiling", False):
            self.layout_button = QToolButton()
            self.layout_button.setText("Layout")
            self.layout_button.setAutoRaise(True)
            self.layout_button.setPopupMode(QToolButton.InstantPopup)
            self.layout_button.setToolTip("Show several sessions at once: side by side, stacked or in a grid")
            menu = QMenu(self.layout_button)
            group = QActionGroup(menu)
            self.layout_actions = {}
            for key, label, _, _ in LAYOUTS:
                action = menu.addAction(label)
                action.setCheckable(True)
                group.addAction(action)
                action.triggered.connect(lambda _, key=key: self.set_layout(key))
                self.layout_actions[key] = action
            self.layout_button.setMenu(menu)
            self.right_corners.append(self.layout_button)
            self.send_button = QToolButton()
            self.send_button.setText("Send to All")
            self.send_button.setAutoRaise(True)
            self.send_button.setCheckable(True)
            self.send_button.setToolTip("Send a command to many sessions at once, or type in all of them")
            self.send_button.clicked.connect(self.show_send_bar)
            self.right_corners.insert(0, self.send_button)
            if getattr(page, "commands", None) is not None:
                self.buttons_button = QToolButton()
                self.buttons_button.setText("Buttons")
                self.buttons_button.setAutoRaise(True)
                self.buttons_button.setCheckable(True)
                self.buttons_button.setToolTip("Command buttons: saved commands sent with one click")
                self.buttons_button.clicked.connect(self.show_command_bar)
                self.right_corners.insert(0, self.buttons_button)
                self.command_bar = CommandBar(page, self)
                layout.addWidget(self.command_bar)
            self.send_bar = SendBar(page, self)
            layout.addWidget(self.send_bar)

        QApplication.instance().focusChanged.connect(self.on_focus_changed)
        self.set_layout("tabs")
        shortcuts = [("Ctrl+W", self.close_current)] if getattr(page, "ctrl_w_closes", False) else []
        for keys, callback in shortcuts + [
            ("Alt+Left", lambda: self.step_session(-1)),
            ("Alt+Right", lambda: self.step_session(1)),
            ("Ctrl+Shift+Return", self.pop_out_current),
            ("Ctrl+Shift+Enter", self.pop_out_current),
        ]:
            shortcut = QShortcut(QKeySequence(keys), self, context=Qt.WindowShortcut)
            shortcut.setAutoRepeat(False)
            shortcut.activated.connect(callback)

    # ----------------------------------------------------------------- Tab-widget interface (all panes together)

    def views(self):
        return [view for pane in self.panes for view in pane.views]

    def count(self):
        return len(self.views())

    def widget(self, index):
        views = self.views()
        return views[index] if 0 <= index < len(views) else None

    def indexOf(self, view):
        views = self.views()
        return views.index(view) if view in views else -1

    def currentWidget(self):
        return self.active_pane.current() if self.active_pane is not None else None

    def currentIndex(self):
        return self.indexOf(self.currentWidget())

    def setCurrentIndex(self, index):
        view = self.widget(index)
        if view is not None:
            self.show_view(view)

    def setCornerWidget(self, widget, corner=Qt.TopRightCorner):
        """Widgets beside the tabs: at the left of the top-left pane's tabs, or the right of the top-right one's."""
        if corner == Qt.TopLeftCorner:
            self.left_corners.append(widget)
        else:
            self.right_corners.append(widget)
        self.place_corners()

    # ----------------------------------------------------------------- Adding and removing views

    def add_view(self, view, select=True):
        """Open a view in the active pane if it's empty, or else in an empty pane, or else the active pane."""
        active = self.active_pane or self.panes[0]
        pane = active if not active.views else self.empty_pane() or active
        view.state_changed.connect(self.update_tab)
        pane.add(view, select or not pane.views)
        if select:
            self.activate(pane, focus=True)
        return self.indexOf(view)

    def take_view(self, view):
        """Remove a view from these tabs without closing it (to move it elsewhere)."""
        pane = self.pane_of(view)
        if pane is None:
            return
        view.state_changed.disconnect(self.update_tab)
        pane.remove(view)
        if not self.count():
            self.emptied.emit()
        if pane is self.active_pane and pane.current() is not None:
            self.activate(pane, focus=True)
        self.currentChanged.emit(self.currentIndex())

    def close_view(self, view, ask=True):
        """Close a tab. ask=False skips the view's own question (such as transfers still running), for shutdown."""
        if self.pane_of(view) is None:
            return
        if ask and not view.confirm_close():
            return
        self.take_view(view)
        view.shutdown()
        view.deleteLater()

    def close_current(self):
        view = self.currentWidget()
        if view is None:
            return
        # SCP's existing question includes running transfers and unsaved edits.
        has_problems = hasattr(view, "problems") and bool(view.problems())
        if view.state != DISCONNECTED and not has_problems:
            reply = QMessageBox.question(self, "Close Session", f"Close {view.session.name} and disconnect?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if reply != QMessageBox.Yes:
                return
        self.close_view(view)

    def step_session(self, step):
        if self.count():
            self.setCurrentIndex((self.currentIndex() + step) % self.count())

    def pop_out_current(self):
        view = self.currentWidget()
        if view is not None:
            if self.page.tabs is self:
                self.page.pop_out(view)
            else:
                self.page.move_to_main(view, self)

    def move_view(self, view, pane, source_tabs=None):
        """Move a session to another pane (it stays connected), from these tabs or another window's."""
        if pane not in self.panes:
            return
        if source_tabs is not None and source_tabs is not self:
            if source_tabs.pane_of(view) is None:
                return
            source_tabs.take_view(view)
            view.state_changed.connect(self.update_tab)
            if self.page.tabs is self:  # The page may be showing its "nothing open" placeholder
                self.page.show_page(1)
        else:
            source = self.pane_of(view)
            if source is None or source is pane:
                return
            source.remove(view)
        pane.add(view)
        self.activate(pane, focus=True)
        self.window().activateWindow()

    def update_tab(self, view):
        pane = self.pane_of(view)
        if pane is not None:
            pane.update_tab(view)
        if self.send_bar is not None and self.send_bar.isVisible():
            self.send_bar.refresh()  # How many sessions it reaches may have changed

    # ----------------------------------------------------------------- Panes

    def show_command_bar(self, visible=True):
        if self.command_bar is not None:
            self.command_bar.setVisible(visible)
            self.buttons_button.setChecked(visible)

    def show_send_bar(self, visible=True):
        """Show or hide Send to All. Hiding it stops Type in All, so typing can't go astray unseen."""
        if self.send_bar is None:
            return
        self.send_bar.setVisible(visible)
        self.send_button.setChecked(visible)
        if visible:
            self.send_bar.focus()
        elif self.page.mirror_typing:
            self.page.set_broadcast(mirror=False)

    def tiled(self):
        return len(self.panes) > 1

    def can_drag(self):
        """Whether a tab can be dragged anywhere: to another pane, or another window."""
        return self.tiled() or bool(getattr(self.page, "windows", None))

    def fill_open_menu(self, menu, pane=None):
        """The saved sessions, Recent and Quick Connect, opening here: in `pane`, or the active one."""
        if pane is not None:
            self.activate(pane, focus=False)
        self.page.manager.fill_menu(menu, into=self)

    def set_layout(self, key):
        """Tile the sessions area. Each pane keeps its sessions (a pane that goes away hands them to the last one
        left), and new empty panes take sessions from the fullest panes, so more of them are on screen."""
        if key not in LAYOUT_ROWS:
            key = "tabs"
        rows = LAYOUT_ROWS[key]
        self.layout_key = key
        groups = [(list(pane.views), pane.current()) for pane in self.panes if pane.views]
        focused = self.currentWidget()
        for pane in self.panes:
            for view in list(pane.views):
                pane.remove(view)  # Before the old panes go, so the views aren't deleted with them
        for widget in self.left_corners + self.right_corners:
            widget.setParent(self.storage)
        if self.grid is not None:
            self.layout().removeWidget(self.grid)
            self.grid.deleteLater()

        self.grid = QSplitter(Qt.Vertical)
        self.grid.setChildrenCollapsible(False)
        self.panes = []
        for count in rows:
            row = QSplitter(Qt.Horizontal)
            row.setChildrenCollapsible(False)
            for _ in range(count):
                pane = SessionPane(self)
                row.addWidget(pane)
                self.panes.append(pane)
            row.setSizes([1000] * count)
            self.grid.addWidget(row)
        self.grid.setSizes([1000] * len(rows))
        self.layout().insertWidget(0, self.grid, 1)  # Above the Send to All bar
        self.place_corners()

        for pane, (views, current) in zip(self.panes, arrange(groups, len(self.panes), focused)):
            for view in views:
                pane.add(view, select=view is current)
        self.active_pane = self.pane_of(focused) or self.panes[0]
        self.update_panes()
        if self.layout_button is not None:
            self.layout_actions[key].setChecked(True)
        view = self.currentWidget()
        if view is not None:
            view.focus_target().setFocus()
        self.currentChanged.emit(self.currentIndex())

    def place_corners(self):
        """The page's buttons go beside the top panes' tabs, so a single pane looks like ordinary tabs."""
        if not self.panes:
            return
        top_right = self.panes[LAYOUT_ROWS[self.layout_key][0] - 1]
        for widget in self.left_corners:
            self.panes[0].left_slot.addWidget(widget)
            widget.show()
        for widget in self.right_corners:
            top_right.right_slot.addWidget(widget)
            widget.show()

    def pane_of(self, view):
        return next((pane for pane in self.panes if view in pane.views), None)

    def empty_pane(self):
        return next((pane for pane in self.panes if not pane.views), None)

    def update_panes(self):
        for pane in self.panes:
            pane.set_style(active=pane is self.active_pane, tiled=self.tiled())

    def show_view(self, view, focus=True):
        pane = self.pane_of(view)
        if pane is not None:
            pane.select(view)
            self.activate(pane, focus)

    def activate(self, pane, focus=True):
        if pane not in self.panes:
            return
        if pane is not self.active_pane:
            self.active_pane = pane
            self.update_panes()
        view = pane.current()
        if focus and view is not None:
            view.focus_target().setFocus()
        self.currentChanged.emit(self.currentIndex())

    def on_focus_changed(self, _old, new):
        """Clicking or tabbing into a pane makes it the active one."""
        widget = new
        while widget is not None:
            if isinstance(widget, SessionPane):
                if widget in self.panes and widget is not self.active_pane:
                    self.activate(widget, focus=False)
                return
            widget = widget.parentWidget()

    # ----------------------------------------------------------------- Menus

    def show_view_menu(self, view, global_position):
        menu = QMenu(self)
        actions = {}
        if view.state == DISCONNECTED:
            actions[menu.addAction("Connect")] = view.connect_session
        else:
            actions[menu.addAction("Reconnect")] = view.reconnect
            actions[menu.addAction("Disconnect")] = view.disconnect_session
        actions[menu.addAction("Duplicate Session")] = lambda: self.page.open_session(view.session, saved=False,
                                                                                         into=self)
        if self.page.tabs is self:
            actions[menu.addAction("Pop Out to a Window")] = lambda: self.page.pop_out(view)
        else:
            actions[menu.addAction("Move to Main Window")] = lambda: self.page.move_to_main(view, self)
        if self.tiled():
            move_menu = menu.addMenu("Move to")
            source = self.pane_of(view)
            for pane, name in zip(self.panes, PANE_NAMES[self.layout_key]):
                if pane is not source:
                    actions[move_menu.addAction(name)] = lambda pane=pane: self.move_view(view, pane)
        menu.addSeparator()
        view.add_tab_actions(menu, actions)
        for label, action in self.page.companion_actions(view.session):
            actions[menu.addAction(label)] = action
        if self.page.store.get(view.session.id) is None:
            actions[menu.addAction("Save as Session...")] = lambda: self.page.save_quick_session(view)
        menu.addSeparator()
        actions[menu.addAction("Close")] = lambda: self.close_view(view)
        if self.count() > 1:
            actions[menu.addAction("Close Other Tabs")] = lambda: [self.close_view(other) for other in self.views()
                                                                   if other is not view]
        chosen = menu.exec_(global_position)
        if chosen in actions:
            actions[chosen]()


class SessionWindow(QMainWindow):
    """A pop-out window of session tabs."""

    def __init__(self, page):
        super().__init__()
        self.page = page
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.tabs = SessionTabs(page, self)
        self.tabs.emptied.connect(self.close)
        self.tabs.currentChanged.connect(self.update_title)
        self.setCentralWidget(self.tabs)
        sessions_button = QToolButton()
        sessions_button.setText("Sessions")
        sessions_button.setAutoRaise(True)
        sessions_button.setPopupMode(QToolButton.InstantPopup)
        sessions_button.setToolTip("Open a session in this window")
        sessions_menu = QMenu(sessions_button)
        sessions_menu.aboutToShow.connect(lambda: self.tabs.fill_open_menu(sessions_menu))
        sessions_button.setMenu(sessions_menu)
        self.tabs.setCornerWidget(sessions_button, Qt.TopLeftCorner)
        self.resize(960, 620)
        next_tab = QShortcut(QKeySequence("Ctrl+Tab"), self)
        next_tab.activated.connect(lambda: self.tabs.setCurrentIndex((self.tabs.currentIndex() + 1) %
                                                                     max(1, self.tabs.count())))
        full_screen = QShortcut(QKeySequence("F11"), self)
        full_screen.activated.connect(self.toggle_full_screen)
        for keys, callback in (
            ("F1", lambda: self.page.window.show_shortcuts(
                "Terminal" if self.page.settings_prefix == "terminal" else "SCP")),
            ("Ctrl+N", lambda: self.page.manager.new_session(self.page.manager.selected_folder())),
            ("Ctrl+Shift+N", lambda: self.page.manager.new_folder(self.page.manager.selected_folder())),
        ):
            shortcut = QShortcut(QKeySequence(keys), self)
            shortcut.setAutoRepeat(False)
            shortcut.activated.connect(callback)

    def toggle_full_screen(self):
        """F11 in a pop-out window: the whole screen for its sessions."""
        self.setWindowState(self.windowState() ^ Qt.WindowFullScreen)

    def update_title(self):
        view = self.tabs.currentWidget()
        title = self.page.window_title
        self.setWindowTitle(f"{view.title} - {title}" if view is not None else title)

    def closeEvent(self, event):
        connected = [view for view in self.tabs.views() if view.state != DISCONNECTED]
        if connected and not self.page.closing:
            reply = QMessageBox.question(self, "Close Window",
                                         f"Close this window and disconnect {len(connected)} session"
                                         f"{'' if len(connected) == 1 else 's'}?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
            if reply != QMessageBox.Yes:
                event.ignore()
                return
        for view in self.tabs.views():
            self.tabs.take_view(view)
            view.shutdown()
            view.deleteLater()
        if self in self.page.windows:
            self.page.windows.remove(self)
        super().closeEvent(event)
