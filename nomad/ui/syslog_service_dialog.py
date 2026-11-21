"""Tools > Syslog Collector Service (and Collector Service... on the Syslog page): keep the syslog messages devices
send on this computer all the time, for everyone using NOMAD here (the NOMAD Syslog Collector Windows service)."""
import logging
import os

from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFormLayout, QHBoxLayout, QLabel, \
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout

from ..syslog import SYSLOG_PORT
from ..syslogs import service as syslog_service
from .common import run_in_background, set_hint
from .theme import accent_button

log = logging.getLogger(__name__)


class SyslogCollectorDialog(QDialog):
    def __init__(self, window, page=None):
        super().__init__(window)
        self.window, self.page = window, page
        self.setWindowTitle("Syslog Collector Service")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        intro = QLabel("Keep the syslog messages devices send to this computer all the time, whether NOMAD is open or "
                       "not. Everyone using NOMAD on this computer sees the same messages, and can search all of them "
                       "on the Syslog page: on a server several people use over Remote Desktop, only one program can "
                       "listen for syslog, so install this instead of using Start Listening. The Map Watcher reads "
                       "its messages too.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        config = syslog_service.load_config() if self.readable() else syslog_service.default_config()
        form = QFormLayout()
        self.status_label = QLabel()
        form.addRow("Service:", self.status_label)
        port_row = QHBoxLayout()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(int(config.get("port", SYSLOG_PORT)))
        self.port_input.setToolTip("The port devices send syslog to (opened in Windows Firewall)")
        self.tcp_check = QCheckBox("Also TCP")
        self.tcp_check.setChecked(bool(config.get("tcp", False)))
        self.tcp_check.setToolTip("Also accept syslog over TCP on the same port (most devices use UDP)")
        port_row.addWidget(self.port_input)
        port_row.addWidget(self.tcp_check)
        port_row.addStretch()
        form.addRow("Listen on UDP:", port_row)
        self.days_input = QSpinBox()
        self.days_input.setRange(1, 3650)
        self.days_input.setSuffix(" days")
        self.days_input.setValue(int(config.get("keep_days", 90)))
        self.days_input.setToolTip("Older messages are deleted")
        form.addRow("Keep messages:", self.days_input)
        self.size_input = QDoubleSpinBox()
        self.size_input.setRange(0.1, 500)
        self.size_input.setDecimals(1)
        self.size_input.setSuffix(" GB")
        self.size_input.setValue(float(config.get("max_gb", 2)))
        self.size_input.setToolTip("When the messages take more than this, the oldest are deleted, even if they're "
                                   "newer than the days to keep")
        form.addRow("Most space to use:", self.size_input)
        layout.addLayout(form)
        row = QHBoxLayout()
        self.install_button = accent_button("Install Service")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.uninstall_button = QPushButton("Uninstall...")
        self.folder_button = QPushButton("Open Its Folder")
        for button in (self.install_button, self.start_button, self.stop_button, self.uninstall_button,
                       self.folder_button):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.install_button.clicked.connect(self.install)
        self.start_button.clicked.connect(self.start_service)
        self.stop_button.clicked.connect(self.stop_service)
        self.uninstall_button.clicked.connect(self.uninstall)
        self.folder_button.clicked.connect(self.open_folder)
        self.busy = False
        self.done_text = ""
        self.released_watcher = None
        self.refresh()

    @staticmethod
    def readable():
        try:
            (syslog_service.collector_dir() / "config.json").stat()
            return True
        except OSError:
            return False

    def refresh(self):
        admin = getattr(self.window, "admin", False)
        try:
            state = syslog_service.status()
        except Exception as error:  # pywin32 missing (running from an unusual setup)
            state = f"Unknown ({error})"
        module = service()
        self.status_label.setText(state)
        installed = state != module.NOT_INSTALLED
        idle = admin and not self.busy
        self.install_button.setText("Update Service" if installed else "Install Service")
        self.install_button.setEnabled(idle)
        self.start_button.setEnabled(idle and state == module.STOPPED)
        self.stop_button.setEnabled(idle and state == module.RUNNING)
        self.uninstall_button.setEnabled(idle and installed)
        self.folder_button.setEnabled(syslog_service.collector_dir().exists())
        if not admin and not self.busy:
            set_hint(self.message_label, "Installing the Syslog Collector needs administrator rights: use File > "
                                         "Restart as Administrator, then open this again. Once it's installed, "
                                         "everyone's NOMAD on this computer reads it without the rights.", "warning")

    def run(self, message, action, done):
        self.busy = True
        self.done_text = done
        set_hint(self.message_label, message, "info")
        self.refresh()
        run_in_background(action, self.finished_action, self.failed_action)

    def finished_action(self, _result=None):
        self.busy = False
        self.give_port_back()
        set_hint(self.message_label, self.done_text, "success")
        self.refresh()

    def failed_action(self, error):
        self.busy = False
        self.give_port_back()
        log.warning("Syslog Collector service: %s", error)
        set_hint(self.message_label, str(error), "error")
        self.refresh()

    def free_port(self):
        self.released_watcher = free_syslog_port(self.window, self.page) or self.released_watcher

    def give_port_back(self):
        give_syslog_port_back(self.window, self.released_watcher)
        self.released_watcher = None

    def install(self):
        self.free_port()
        config = syslog_service.make_config(self.port_input.value(), self.tcp_check.isChecked(),
                                            self.days_input.value(), self.size_input.value())
        log.info("Installing the Syslog Collector service on port %s", config["port"])
        self.run("Installing the service (this takes a few seconds)...", lambda: syslog_service.install(config),
                 f"The Syslog Collector is running, listening on port {config['port']}. Point the devices' logging "
                 "at this computer (SNMP Config page, or \"logging host\" on Cisco).")

    def start_service(self):
        self.free_port()
        self.run("Starting the service...", lambda: service().start(syslog_service.spec()), "Started.")

    def stop_service(self):
        self.run("Stopping the service...", lambda: service().stop(syslog_service.spec()), "Stopped.")

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the Syslog Collector",
                                "Stop and remove the Syslog Collector service and its firewall rule? The messages "
                                "it kept stay in its folder.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", syslog_service.uninstall, "Removed.")

    def open_folder(self):
        try:
            os.startfile(syslog_service.collector_dir())
        except OSError as error:
            set_hint(self.message_label, f"Couldn't open its folder: {error} (it's readable by administrators "
                                         "only).", "error")


def free_syslog_port(window, page=None):
    """This NOMAD stops listening for syslog itself (the Syslog page, and the Map Watcher), so the service can take
    the port. Returns the Map Watcher it stopped (or None), for give_syslog_port_back after."""
    page = page if page is not None else getattr(window, "syslog_tab", None)
    if page is not None and page.receiver is not None:
        page.stop()
    watcher = getattr(getattr(window, "netmap_tab", None), "watcher", None)
    if watcher is not None and watcher.syslog is not None:
        watcher.stop_listening()
        return watcher
    return None


def give_syslog_port_back(window, released=None):
    """The Map Watcher listens again: from the service if it runs now, else from the port."""
    if released is not None:
        released.update_listening()
        return
    watcher = getattr(getattr(window, "netmap_tab", None), "watcher", None)
    if watcher is not None and watcher.syslog is not None:
        watcher.check_syslog()


def service():
    from ..ipam import service as module  # pywin32 is loaded only when it's needed
    return module
