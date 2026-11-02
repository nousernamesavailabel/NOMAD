"""Is the tribe server up to date? Each time NOMAD starts (and when the tribe key changes) the server is asked what it
runs, on a background thread, however long it takes to come within reach. A server older than this NOMAD gets a banner
across the window recommending the update. It's asked again now and then, so the banner goes once it's updated; a
server as new as this NOMAD, or newer, is left alone. Which pages are open doesn't matter: they connect when needed."""
import logging
import threading

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QMessageBox, QPushButton

from ..ipam.client import ServerUnreachable, TeamClient, server_update
from ..ipam.server import ADMIN
from .theme import COLORS

log = logging.getLogger(__name__)

RETRY_SECONDS = 60  # Until the server first answers
RECHECK_SECONDS = 600  # While it needs updating


class ServerVersionCheck(QObject):
    """Asks the server its status on a background thread until it's up to date (or can't be asked: nothing to say)."""
    checked = pyqtSignal(object)  # The server's status

    def __init__(self, key_loader, parent=None):
        super().__init__(parent)
        self.key_loader = key_loader
        self.key = None
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, name="Tribe server version check", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()  # The thread ends when its current request returns

    def run(self):
        try:
            self.key = self.key_loader()
            if self.key is None:
                return
            client = TeamClient(self.key)
            while not self.stopping.is_set():
                try:
                    status = client.status()
                except ServerUnreachable:
                    self.stopping.wait(RETRY_SECONDS)
                    continue
                if status.get("server_id") != self.key.server_id:
                    return  # Set up again: the pages say so
                if self.stopping.is_set():
                    return
                self.checked.emit(status)
                if server_update(status) is None:
                    return
                self.stopping.wait(RECHECK_SECONDS)
        except Exception as error:  # A refused key, say: the pages say so
            log.info("Couldn't check the tribe server's version: %s", error)


class TribeUpdateBanner(QFrame):
    """Across the window while the tribe server needs updating, unless it's been dismissed."""

    def __init__(self, key_loader, parent=None):
        super().__init__(parent)
        self.key_loader = key_loader
        self.checker = None
        self.update_needed = None
        self.dismissed = None  # The server's API level when dismissed: a later level is news
        self.on_server = False
        self.focused = False  # Focus mode: only the current page shows
        self.setStyleSheet(f"QFrame {{ background: {COLORS['warning_background']}; "
                           f"border: 1px solid {COLORS['warning']}; }}"
                           "QLabel { border: none; }")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        self.label = QLabel()
        self.label.setWordWrap(True)
        layout.addWidget(self.label, 1)
        self.details_button = QPushButton("How to Update...")
        self.details_button.clicked.connect(self.show_steps)
        layout.addWidget(self.details_button)
        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.setToolTip("Hide this until NOMAD next starts.")
        self.dismiss_button.clicked.connect(self.dismiss)
        layout.addWidget(self.dismiss_button)
        self.hide()

    def check(self):
        """Start checking the server (again: the tribe key may have changed)."""
        self.stop()
        self.update_needed = None
        self.show_state()
        self.checker = ServerVersionCheck(self.key_loader, self)
        self.checker.checked.connect(self.on_checked)
        self.checker.start()

    def stop(self):
        if self.checker is not None:
            self.checker.stop()
            self.checker = None

    def on_checked(self, status):
        if self.sender() is not self.checker:
            return  # From before the tribe key changed
        self.on_server = self.checker.key.role == ADMIN
        self.update_needed = server_update(status)
        log.info("Tribe server %s runs NOMAD %s (Tribe API %s)", status.get("name"), status.get("version"),
                 status.get("api"))
        if self.update_needed is not None:
            self.label.setText(self.update_needed.summary)
        self.show_state()

    def show_state(self):
        update = self.update_needed
        self.setVisible(update is not None and update.api != self.dismissed and not self.focused)

    def set_focused(self, on):
        self.focused = on
        self.show_state()

    def dismiss(self):
        self.dismissed = self.update_needed.api
        self.show_state()

    def show_steps(self):
        QMessageBox.information(self, "Update the Tribe Server", f"{self.update_needed.summary}\n\n"
                                                                 f"{self.update_needed.steps(self.on_server)}")
