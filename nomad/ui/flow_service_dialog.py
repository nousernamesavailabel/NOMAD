"""Tools > Flow Collector Service (and Collector Service... on the NetFlow page): collect NetFlow on this computer all
the time, for everyone using NOMAD here (the NOMAD Flow Collector Windows service)."""
import logging
import os

from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QDoubleSpinBox, QFormLayout, QHBoxLayout, QLabel, \
    QMessageBox, QPushButton, QSpinBox, QVBoxLayout

from ..flows import service as flow_service
from ..flows.collector import FLOW_PORT
from .common import run_in_background, set_hint
from .theme import accent_button

log = logging.getLogger(__name__)


class FlowCollectorDialog(QDialog):
    def __init__(self, window, page=None):
        super().__init__(window)
        self.window, self.page = window, page
        self.setWindowTitle("Flow Collector Service")
        self.setMinimumWidth(600)
        layout = QVBoxLayout(self)
        intro = QLabel("Collect the flows routers send (NetFlow and IPFIX) on this computer all the time, whether "
                       "NOMAD is open or not. Everyone using NOMAD on this computer sees the same flows: on a server "
                       "several people use over Remote Desktop, only one program can listen for flows, so install "
                       "this instead of using Collect Here. Routers send to this computer's address.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        config = flow_service.load_config() if self.readable() else flow_service.default_config()
        form = QFormLayout()
        self.status_label = QLabel()
        form.addRow("Service:", self.status_label)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(int(config.get("port", FLOW_PORT)))
        self.port_input.setToolTip("The UDP port routers send flows to (opened in Windows Firewall)")
        form.addRow("Listen on UDP:", self.port_input)
        self.raw_input = QDoubleSpinBox()
        self.raw_input.setRange(0.25, 72)
        self.raw_input.setDecimals(2)
        self.raw_input.setSuffix(" hours")
        self.raw_input.setValue(float(config.get("raw_hours", 2)))
        self.raw_input.setToolTip("Each flow as sent, for Find Flows (busy routers make a lot of them: a few "
                                  "hours is plenty)")
        form.addRow("Keep each flow:", self.raw_input)
        self.days_input = QSpinBox()
        self.days_input.setRange(1, 400)
        self.days_input.setSuffix(" days")
        self.days_input.setValue(int(config.get("summary_days", 14)))
        self.days_input.setToolTip("Each interface's minute by minute totals and top talkers, applications and "
                                   "conversations")
        form.addRow("Keep minute summaries:", self.days_input)
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
        self.refresh()

    @staticmethod
    def readable():
        try:
            (flow_service.collector_dir() / "config.json").stat()
            return True
        except OSError:
            return False

    def refresh(self):
        admin = getattr(self.window, "admin", False)
        try:
            state = flow_service.status()
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
        self.folder_button.setEnabled(flow_service.collector_dir().exists())
        if not admin and not self.busy:
            set_hint(self.message_label, "Installing the Flow Collector needs administrator rights: use File > "
                                         "Restart as Administrator, then open this again. Once it's installed, "
                                         "everyone's NOMAD on this computer reads it without the rights.", "warning")

    def run(self, message, action, done):
        self.busy = True
        set_hint(self.message_label, message, "info")
        self.refresh()
        run_in_background(action, lambda _: self.finished_action(done), self.failed_action)

    def finished_action(self, done):
        self.busy = False
        set_hint(self.message_label, done, "success")
        self.refresh()

    def failed_action(self, error):
        self.busy = False
        log.warning("Flow Collector service: %s", error)
        set_hint(self.message_label, str(error), "error")
        self.refresh()

    def install(self):
        if self.page is not None and self.page.local is not None:
            self.page.stop_collect_here()  # It has the port the service is about to take
        config = flow_service.make_config(self.port_input.value(), self.raw_input.value(), self.days_input.value())
        log.info("Installing the Flow Collector service on UDP %s", config["port"])
        self.run("Installing the service (this takes a few seconds)...", lambda: flow_service.install(config),
                 f"The Flow Collector is running, listening on UDP {config['port']}. Set routers up to send their "
                 "flows to this computer (NetFlow Config page).")

    def start_service(self):
        self.run("Starting the service...", lambda: service().start(flow_service.spec()), "Started.")

    def stop_service(self):
        self.run("Stopping the service...", lambda: service().stop(flow_service.spec()), "Stopped.")

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the Flow Collector",
                                "Stop and remove the Flow Collector service and its firewall rule? The flows it "
                                "kept stay in its folder.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", flow_service.uninstall, "Removed.")

    def open_folder(self):
        try:
            os.startfile(flow_service.collector_dir())
        except OSError as error:
            set_hint(self.message_label, f"Couldn't open its folder: {error} (it's readable by administrators "
                                         "only).", "error")


def service():
    from ..ipam import service as module  # pywin32 is loaded only when it's needed
    return module
