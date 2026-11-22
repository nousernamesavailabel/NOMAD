"""A banner across NOMAD's window while a NOMAD service on this computer wants updating (see service_versions): one
running an older NOMAD, or started before its copy of NOMAD changed. Like the tribe server's banner (tribe_version),
it's checked again now and then (on a worker thread), so it goes once they're updated, and Dismiss hides it until
something else wants updating."""
import logging

from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QPushButton

from .common import run_in_background
from .theme import COLORS

log = logging.getLogger(__name__)

CHECK_SECONDS = 120
FIRST_CHECK_MS = 3000  # After NOMAD has started: it doesn't hold the window up


def find_behind():
    """[service_versions.Behind] on this computer (on a worker thread)."""
    from .. import service_versions, services_catalog
    return service_versions.behind(services_catalog.SERVICES, services_catalog.status)


def and_list(items):
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def banner_text(found, admin):
    """"The Map Watcher and NOMAD Dashboard run NOMAD 2.7.1. Update them in...": those with the same reason together."""
    by_reason = {}
    for item in found:
        by_reason.setdefault(item.reason, []).append(item.title)
    names = []
    for reason, titles in by_reason.items():
        if len(titles) > 1:  # "runs" -> "run", "was started" -> "were started"
            verb, _, rest = reason.partition(" ")
            reason = f"{ {'runs': 'run', 'was': 'were'}.get(verb, verb)} {rest}"
        names.append(f"the {and_list(titles)} {reason}")
    listed = and_list(names)
    what = "it" if len(found) == 1 else "them"
    how = (f"Tick {what} in Tools > Services & Firewall and click Install or Update Ticked."
           if admin else f"Ask an administrator of this computer to update {what} in Tools > Services & Firewall.")
    heading = ("A NOMAD service on this computer needs updating" if len(found) == 1 else
               "NOMAD services on this computer need updating")
    return f"{heading}: {listed[0].upper()}{listed[1:]}. {how}"


class ServiceUpdateBanner(QFrame):
    open_services = pyqtSignal()

    def __init__(self, admin, parent=None, finder=None):
        """finder(): [service_versions.Behind] (default find_behind), on a worker thread."""
        super().__init__(parent)
        self.admin = admin
        self.finder = finder
        self.found = []
        self.dismissed = None  # What was found when dismissed: anything else is news
        self.focused = False
        self.checking = False
        self.setStyleSheet(f"QFrame {{ background: {COLORS['warning_background']}; "
                           f"border: 1px solid {COLORS['warning']}; }}"
                           "QLabel { border: none; }")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        self.label = QLabel()
        self.label.setWordWrap(True)
        layout.addWidget(self.label, 1)
        self.services_button = QPushButton("Services & Firewall...")
        self.services_button.clicked.connect(self.on_services_clicked)
        layout.addWidget(self.services_button)
        self.dismiss_button = QPushButton("Dismiss")
        self.dismiss_button.setToolTip("Hide this until another service needs updating.")
        self.dismiss_button.clicked.connect(self.dismiss)
        layout.addWidget(self.dismiss_button)
        self.timer = QTimer(self)
        self.timer.setInterval(CHECK_SECONDS * 1000)
        self.timer.timeout.connect(self.check)
        self.hide()

    def on_services_clicked(self):
        self.open_services.emit()

    def start(self):
        QTimer.singleShot(FIRST_CHECK_MS, self.check)
        self.timer.start()

    def stop(self):
        self.timer.stop()

    def check(self):
        if self.checking:
            return
        self.checking = True
        run_in_background(self.finder or find_behind, self.on_found, self.on_failed)

    def on_found(self, found):
        self.checking = False
        self.set_found(found)

    def on_failed(self, error):
        self.checking = False
        log.info("Couldn't check the services' versions: %s", error)

    def set_found(self, found):
        found = list(found)
        if found != self.found:
            for item in found:
                if item not in self.found:
                    log.info("The %s service %s: it needs updating", item.title, item.reason)
        self.found = found
        if found:
            self.label.setText(banner_text(found, self.admin))
        self.show_state()

    def show_state(self):
        self.setVisible(bool(self.found) and self.found != self.dismissed and not self.focused)

    def set_focused(self, on):
        self.focused = on
        self.show_state()

    def dismiss(self):
        self.dismissed = list(self.found)
        self.show_state()
