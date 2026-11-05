"""A tool popped out of the main window into a window of its own (the Network Map on a second screen, say).

The page itself moves, so whatever it's running carries on, and it keeps working with the main window as before
(its adapter, the other pages, the tribe). The window has its own adapter picker, status bar and the main window's
page shortcuts; closing it puts the page back in the main window."""
from PyQt5.QtCore import QEvent, QObject, Qt
from PyQt5.QtWidgets import QAction, QApplication, QComboBox, QDialog, QHBoxLayout, QLabel, QMainWindow, \
    QPushButton, QVBoxLayout, QWidget

from ..system import APP_NAME
from .theme import COLORS
from .workflow_shortcuts import DIAGNOSTIC_BUTTONS, perform_page_action

GEOMETRY_SETTING = "tool_windows/geometry/"  # + the tool's title
OPEN_SETTING = "tool_windows/open"  # Titles of the tools popped out when NOMAD closed, to pop out again next time


def show_status_on(bar, message, kind="success", timeout=10000):
    """A status bar message in the color for its kind (success, error, warning or info)."""
    colors = {"success": COLORS["success"], "error": COLORS["error"], "warning": COLORS["warning"], "info": ""}
    bar.setStyleSheet(f"QStatusBar {{ color: {colors.get(kind, '')}; }}")
    bar.showMessage(message, timeout)


class ToolWindow(QMainWindow):
    """One popped-out tool. main: the MainWindow; page: the tool's page; title: its name in the tool drawer."""

    def __init__(self, main, page, title):
        super().__init__()  # No parent: a window of its own on the taskbar, like the Terminal's pop-outs
        self.main = main
        self.page = page
        self.title = title
        self.closing_app = False  # Set when NOMAD is closing: the page goes back without being shown
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.setWindowTitle(f"{title} - {APP_NAME}")
        central = QWidget(self)
        self.central_layout = QVBoxLayout(central)

        # The main window's adapter picker, sharing its list: choosing here chooses there, for every page
        bar = QHBoxLayout()
        bar.setContentsMargins(0, 0, 0, 0)
        bar.addWidget(QLabel("Adapter:"))
        self.adapter_combo = QComboBox()
        self.adapter_combo.setModel(main.adapter_combo.model())
        self.adapter_combo.setMinimumWidth(160)
        self.adapter_combo.setToolTip(main.adapter_combo.toolTip())
        self.adapter_combo.activated.connect(self.choose_adapter)
        bar.addWidget(self.adapter_combo, 1)
        refresh_button = QPushButton("Refresh")
        refresh_button.setToolTip("Reload network settings (F5)")
        refresh_button.clicked.connect(self.refresh)
        bar.addWidget(refresh_button)
        back_button = QPushButton("Back to Main Window")
        back_button.setToolTip("Put this tool back in the main window (Ctrl+Shift+Enter)")
        back_button.clicked.connect(self.close)
        bar.addWidget(back_button)
        self.central_layout.addLayout(bar)
        self.setCentralWidget(central)
        main.adapter_changed.connect(self.sync_adapter)
        main.snapshot_changed.connect(self.sync_adapter)
        self.sync_adapter()
        self.add_shortcuts()
        self.resize(1000, 700)

    def add_shortcuts(self):
        """The main window's shortcuts that act on the page showing, acting on this one."""
        buttons = DIAGNOSTIC_BUTTONS.get(type(self.page).__name__)
        for title, keys, slot, enabled in (
            ("Back to Main Window", ["Ctrl+Shift+Return", "Ctrl+Shift+Enter"], self.close, True),
            ("Refresh", ["F5"], self.refresh, True),
            ("Find on This Page", ["Ctrl+F"], self.focus_find, True),
            ("Run Current Tool", ["Shift+Return", "Shift+Enter"], self.run_tool, buttons is not None),
            ("Stop Current Tool", ["Shift+Esc"], self.stop_tool, buttons is not None and buttons[1] is not None),
            ("Choose Adapter", ["Alt+A"], self.focus_adapter, True),
            ("Keyboard Guide", ["F1"], self.show_shortcuts, True),
            ("Full Screen", ["F11"], self.toggle_full_screen, True),
            ("Larger Text", ["Ctrl+=", "Ctrl++"], self.larger_text, True),
            ("Smaller Text", ["Ctrl+-"], self.smaller_text, True),
            ("Default Text Size", ["Ctrl+0"], self.default_text, True),
        ):
            action = QAction(title, self)
            action.setShortcuts(keys)
            action.setShortcutContext(Qt.WindowShortcut)
            action.setAutoRepeat(False)
            action.setEnabled(enabled)  # A disabled one leaves the key to the page (no ambiguous shortcuts)
            action.triggered.connect(slot)
            self.addAction(action)

    def open(self):
        """Take the page in and show the window where this tool's window was last time."""
        self.central_layout.addWidget(self.page, 1)
        self.page.show()
        geometry = self.main.settings.value(GEOMETRY_SETTING + self.title)
        if geometry is not None:
            self.restoreGeometry(geometry)
        self.show_window()

    def show_window(self):
        if self.isMinimized():
            self.setWindowState(self.windowState() & ~Qt.WindowMinimized)
        self.show()
        self.raise_()
        self.activateWindow()

    def save_geometry(self):
        self.main.settings.setValue(GEOMETRY_SETTING + self.title, self.saveGeometry())

    def show_status(self, message, kind="success", timeout=10000):
        show_status_on(self.statusBar(), message, kind, timeout)

    # ----------------------------------------------------------------- Adapter picker

    def sync_adapter(self, *_):
        self.adapter_combo.setCurrentIndex(self.main.adapter_combo.currentIndex())

    def choose_adapter(self, index):
        self.main.adapter_combo.setCurrentIndex(index)  # The main window tells every page, and this picker

    def focus_adapter(self):
        self.adapter_combo.setFocus()

    # ----------------------------------------------------------------- Shortcuts

    def refresh(self):
        self.main.refresh()

    def focus_find(self):
        if hasattr(self.page, "focus_find"):
            self.page.focus_find()
        else:
            self.show_status("This page has nothing to search.", "info", 3000)

    def run_tool(self):
        perform_page_action(self.page)

    def stop_tool(self):
        perform_page_action(self.page, stop=True)

    def show_shortcuts(self):
        self.main.show_shortcuts(self.title)

    def toggle_full_screen(self):
        self.setWindowState(self.windowState() ^ Qt.WindowFullScreen)

    def larger_text(self):
        self.main.step_text_scale(1)

    def smaller_text(self):
        self.main.step_text_scale(-1)

    def default_text(self):
        self.main.step_text_scale(0)

    # ----------------------------------------------------------------- Events

    def changeEvent(self, event):
        if event.type() == QEvent.ActivationChange and self.isActiveWindow():
            self.main.page_shown(self.page)  # Refreshes a stale page, as switching to it in the main window does
        super().changeEvent(event)

    def closeEvent(self, event):
        self.save_geometry()
        self.central_layout.removeWidget(self.page)
        self.main.tool_window_closed(self)
        super().closeEvent(event)


class DialogsFollowTools(QObject):
    """Application event filter: a dialog or message box a page opens over the main window (as many do, with
    self.window as parent) opens over the tool's own window instead while that's the window in use, rather than over
    the main window, perhaps on another screen."""

    def __init__(self, main):
        super().__init__(main)
        self.main = main

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Show and not event.spontaneous() and isinstance(watched, QDialog):
            active = QApplication.activeWindow()
            parent = watched.parentWidget()
            # QWidget.window: the pages' own window attribute (the main window) hides the method
            if isinstance(active, ToolWindow) and parent is not None and QWidget.window(parent) is self.main:
                geometry = watched.geometry()
                geometry.moveCenter(active.frameGeometry().center())
                watched.move(geometry.topLeft())
        return False
