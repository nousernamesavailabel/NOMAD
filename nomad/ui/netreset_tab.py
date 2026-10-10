"""Network Reset page: fix a damaged network stack, renew leases, and view or turn off proxy settings."""
import logging
import os
import time

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QKeySequence, QTextCursor, QTextDocument
from PyQt5.QtWidgets import QApplication, QFrame, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, \
    QPushButton, QShortcut, QVBoxLayout, QWidget

from ..neighbors import clear_neighbor_cache
from ..netreset import RESET_ACTIONS, ResetAction, cancel_restart, read_proxy, read_winhttp_proxy, \
    restart_computer, run_reset, without_proxy, write_proxy
from ..system import CommandError
from .common import run_in_background, set_hint
from .theme import COLORS, monospace_font

log = logging.getLogger(__name__)

CLEAR_ARP = ResetAction("arp", "Clear ARP Cache",
                        "Forget which MAC address answers for each IP. Useful after replacing a device that kept its "
                        "address.", [])
RESTART_DELAY_SECONDS = 10


class NetworkResetTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.proxy = None
        self.proxy_before = None  # Settings before Turn Off Proxy, for Undo
        self.restart_pending = False
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)

        self.restart_banner = QFrame()
        self.restart_banner.setStyleSheet(f"QFrame {{ background: {COLORS['warning_background']}; "
                                          f"border: 1px solid {COLORS['warning']}; }} QLabel {{ border: none; }}")
        banner_layout = QHBoxLayout(self.restart_banner)
        self.restart_label = QLabel("Restart the computer to finish the reset.")
        self.restart_label.setWordWrap(True)
        self.restart_button = QPushButton("Restart Now")
        self.cancel_restart_button = QPushButton("Cancel Restart")
        banner_layout.addWidget(self.restart_label, 1)
        banner_layout.addWidget(self.restart_button)
        banner_layout.addWidget(self.cancel_restart_button)
        self.restart_banner.setVisible(False)
        layout.addWidget(self.restart_banner)

        # Proxy settings
        proxy_group = QGroupBox("Proxy settings")
        proxy_layout = QVBoxLayout(proxy_group)
        intro = QLabel("A leftover proxy is a common cause of \"the network works but web pages don't load\". "
                       "Programs use this user's proxy; Windows services such as Windows Update use the "
                       "machine-wide WinHTTP proxy.")
        intro.setWordWrap(True)
        proxy_layout.addWidget(intro)
        grid = QGridLayout()
        grid.addWidget(QLabel("This user:"), 0, 0)
        self.user_proxy_label = QLabel()
        self.user_proxy_label.setWordWrap(True)
        grid.addWidget(self.user_proxy_label, 0, 1)
        grid.addWidget(QLabel("Windows services:"), 1, 0)
        self.winhttp_label = QLabel()
        self.winhttp_label.setWordWrap(True)
        grid.addWidget(self.winhttp_label, 1, 1)
        grid.setColumnStretch(1, 1)
        proxy_layout.addLayout(grid)
        proxy_buttons = QHBoxLayout()
        self.proxy_off_button = QPushButton("Turn Off Proxy")
        self.proxy_off_button.setToolTip("Stop this user's programs using the proxy server and setup script. The "
                                         "details are kept, so Undo can turn them back on.")
        self.proxy_undo_button = QPushButton("Undo")
        self.winhttp_button = QPushButton("Reset WinHTTP Proxy")
        self.winhttp_button.setToolTip(RESET_ACTIONS[-1].description)
        self.proxy_refresh_button = QPushButton("Refresh")
        self.proxy_settings_button = QPushButton("Windows Proxy Settings...")
        for button in (self.proxy_off_button, self.proxy_undo_button, self.winhttp_button, self.proxy_refresh_button):
            proxy_buttons.addWidget(button)
        proxy_buttons.addStretch()
        proxy_buttons.addWidget(self.proxy_settings_button)
        proxy_layout.addLayout(proxy_buttons)
        layout.addWidget(proxy_group)

        # Resets
        reset_group = QGroupBox("Resets")
        reset_layout = QGridLayout(reset_group)
        actions = [action for action in RESET_ACTIONS if action.key != "winhttp"]
        actions.insert(1, CLEAR_ARP)
        self.reset_buttons = {}
        for row, action in enumerate(actions):
            button = QPushButton(action.title)
            button.clicked.connect(lambda _, action=action: self.run_action(action))
            self.reset_buttons[action.key] = button
            description = QLabel(action.description + (" Needs a restart." if action.needs_restart else ""))
            description.setWordWrap(True)
            reset_layout.addWidget(button, row, 0)
            reset_layout.addWidget(description, row, 1)
        windows_reset = QPushButton("Windows Network Reset...")
        windows_reset.setToolTip("Open Windows Settings, whose Network reset also removes and reinstalls every "
                                 "network adapter.")
        windows_note = QLabel("The last resort: Windows' own network reset removes and reinstalls every adapter "
                              "(VPN and virtual adapters included) and restarts the computer.")
        windows_note.setWordWrap(True)
        reset_layout.addWidget(windows_reset, len(actions), 0)
        reset_layout.addWidget(windows_note, len(actions), 1)
        reset_layout.setColumnStretch(1, 1)
        layout.addWidget(reset_group)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.find_bar = QWidget()
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(0, 0, 0, 0)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find in command output (Enter: next, Shift+Enter: previous)")
        self.find_input.setClearButtonEnabled(True)
        self.find_status = QLabel()
        previous_button = QPushButton("Previous")
        next_button = QPushButton("Next")
        close_button = QPushButton("Close")
        find_layout.addWidget(self.find_input, 1)
        for widget in (self.find_status, previous_button, next_button, close_button):
            find_layout.addWidget(widget)
        layout.addWidget(self.find_bar)
        self.find_bar.hide()
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(monospace_font())
        self.output.setPlaceholderText("Output from the commands appears here.")
        layout.addWidget(self.output, 1)
        self.find_input.textChanged.connect(self.restart_find)
        self.find_input.returnPressed.connect(
            lambda: self.find_output(bool(QApplication.keyboardModifiers() & Qt.ShiftModifier)))
        next_button.clicked.connect(lambda: self.find_output())
        previous_button.clicked.connect(lambda: self.find_output(True))
        close_button.clicked.connect(self.hide_find)
        QShortcut(QKeySequence("Esc"), self.find_bar, context=Qt.WidgetWithChildrenShortcut).activated.connect(self.hide_find)

        self.proxy_off_button.clicked.connect(self.turn_off_proxy)
        self.proxy_undo_button.clicked.connect(self.undo_proxy)
        self.winhttp_button.clicked.connect(lambda: self.run_action(RESET_ACTIONS[-1]))
        self.proxy_refresh_button.clicked.connect(self.refresh_proxy)
        self.proxy_settings_button.clicked.connect(lambda: self.open_settings("ms-settings:network-proxy"))
        windows_reset.clicked.connect(lambda: self.open_settings("ms-settings:network-status"))
        self.restart_button.clicked.connect(self.restart)
        self.cancel_restart_button.clicked.connect(self.cancel_restart)
        self.update_proxy_buttons()

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.find_bar.show()
        self.find_input.setFocus()
        self.find_input.selectAll()

    def hide_find(self):
        self.find_bar.hide()
        self.output.setFocus()

    def restart_find(self):
        self.output.moveCursor(QTextCursor.Start)
        self.find_output()

    def find_output(self, backward=False):
        text = self.find_input.text()
        self.find_status.clear()
        if not text:
            return
        flags = QTextDocument.FindBackward if backward else QTextDocument.FindFlags()
        original = self.output.textCursor()
        if not self.output.find(text, flags):
            self.output.moveCursor(QTextCursor.End if backward else QTextCursor.Start)
            if not self.output.find(text, flags):
                self.output.setTextCursor(original)
                self.find_status.setText("No matches")

    def save_settings(self, settings):
        pass

    def restore_settings(self, settings):
        pass

    def shutdown(self):
        pass

    def refresh_if_stale(self):
        self.refresh_proxy()

    # ----------------------------------------------------------------- Proxy

    def refresh_proxy(self):
        def read():
            return read_proxy(), read_winhttp_proxy()

        run_in_background(read, self.show_proxy, lambda error: set_hint(
            self.status_label, f"Couldn't read the proxy settings: {error}", "error"))

    def show_proxy(self, settings):
        self.proxy, winhttp = settings
        self.user_proxy_label.setText("\n".join(self.proxy.describe()))
        self.user_proxy_label.setStyleSheet(f"color: {COLORS['warning']};" if self.proxy.active else "")
        self.winhttp_label.setText("\n".join(winhttp.describe()))
        self.winhttp_label.setStyleSheet(f"color: {COLORS['warning']};" if winhttp.proxy else "")
        self.winhttp_set = bool(winhttp.proxy)
        self.update_proxy_buttons()

    def update_proxy_buttons(self):
        self.proxy_off_button.setEnabled(self.proxy is not None and self.proxy.active)
        self.proxy_undo_button.setEnabled(self.proxy_before is not None)
        self.winhttp_button.setEnabled(getattr(self, "winhttp_set", False))

    def turn_off_proxy(self):
        if self.proxy is None or not self.proxy.active:
            return
        before = self.proxy
        try:
            write_proxy(without_proxy(before))
        except OSError as error:
            QMessageBox.critical(self, "Turn Off Proxy", f"Couldn't change the proxy settings:\n\n{error}")
            return
        self.proxy_before = before
        self.log_output("Turned off this user's proxy. Was:\n  " + "\n  ".join(before.describe()))
        set_hint(self.status_label, "Proxy turned off. Programs pick up the change straight away; Undo puts it "
                                    "back.", "success")
        self.refresh_proxy()

    def undo_proxy(self):
        if self.proxy_before is None:
            return
        try:
            write_proxy(self.proxy_before)
        except OSError as error:
            QMessageBox.critical(self, "Undo", f"Couldn't restore the proxy settings:\n\n{error}")
            return
        self.log_output("Restored this user's proxy:\n  " + "\n  ".join(self.proxy_before.describe()))
        self.proxy_before = None
        set_hint(self.status_label, "Proxy settings restored.", "success")
        self.refresh_proxy()

    # ----------------------------------------------------------------- Resets

    def run_action(self, action):
        if action.warning:
            reply = QMessageBox.question(self, action.title, f"{action.warning}\n\nContinue?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        function = clear_neighbor_cache if action.key == CLEAR_ARP.key else (lambda: run_reset(action))
        set_hint(self.status_label, f"{action.title}...", "info")
        started = self.window.run_change(action.title, function,
                                         on_success=lambda output: self.on_action_done(action, output),
                                         on_error=lambda error: self.on_action_failed(action, error),
                                         needs_admin=action.needs_admin)
        if not started:
            self.status_label.clear()

    def on_action_done(self, action, output):
        self.log_output(f"{action.title}: done." + (f"\n{output.strip()}" if output and output.strip() else ""))
        if action.needs_restart:
            self.restart_pending = True
            self.restart_banner.setVisible(True)
            set_hint(self.status_label, f"{action.title} done. Restart the computer to finish.", "warning")
        else:
            set_hint(self.status_label, f"{action.title} done.", "success")
        if action.key == "winhttp":
            self.refresh_proxy()

    def on_action_failed(self, action, error):
        output = error.output if isinstance(error, CommandError) else str(error)
        self.log_output(f"{action.title} failed:\n{output}")
        set_hint(self.status_label, f"{action.title} failed. See the output below.", "error")

    def log_output(self, text):
        self.output.appendPlainText(f"[{time.strftime('%H:%M:%S')}] {text}\n")

    def restart(self):
        reply = QMessageBox.question(self, "Restart Now",
                                     f"Restart the computer in {RESTART_DELAY_SECONDS} seconds? Save your work in "
                                     "other programs first.", QMessageBox.Yes | QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        try:
            restart_computer(RESTART_DELAY_SECONDS)
        except CommandError as error:
            QMessageBox.critical(self, "Restart", f"Couldn't restart:\n\n{error}")
            return
        self.restart_label.setText(f"Restarting in {RESTART_DELAY_SECONDS} seconds. Cancel Restart stops it.")

    def cancel_restart(self):
        try:
            cancel_restart()
        except CommandError:
            set_hint(self.status_label, "There was no restart to cancel.", "info")
            return
        self.restart_label.setText("Restart cancelled. Restart the computer later to finish the reset.")

    def open_settings(self, page):
        try:
            os.startfile(page)
        except OSError as error:
            QMessageBox.critical(self, "Windows Settings", f"Couldn't open Windows Settings:\n\n{error}")
