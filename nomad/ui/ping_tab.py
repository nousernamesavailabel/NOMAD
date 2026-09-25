"""Ping tab: ping a host with live output and a running summary."""
import logging
import time
from dataclasses import replace

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QFont, QIntValidator
from PyQt5.QtWidgets import QCheckBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton, \
    QVBoxLayout, QWidget

from ..icmp import IcmpClient, PingStats, format_reply, resolve_host
from .common import StoppableThread
from .theme import accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"host": "8.8.8.8", "count": "4", "size": "32", "timeout": "2000"}
PING_INTERVAL_SECONDS = 1.0


class PingThread(StoppableThread):
    line = pyqtSignal(str)
    stats = pyqtSignal(object)  # PingStats

    def __init__(self, host, count, size, timeout, dont_fragment, parent=None):
        super().__init__(parent)
        self.host, self.count, self.size = host, count, size  # count None = until stopped
        self.timeout, self.dont_fragment = timeout, dont_fragment

    def run(self):
        stats = PingStats()
        try:
            address, family = resolve_host(self.host)
            shown = address if address == self.host else f"{self.host} [{address}]"
            self.line.emit(f"Pinging {shown} with {self.size} bytes of data:")
            with IcmpClient(family) as client:
                while not self.stopping and (self.count is None or stats.sent < self.count):
                    started = time.monotonic()
                    reply = client.echo(address, size=self.size, timeout=self.timeout,
                                        dont_fragment=self.dont_fragment)
                    stats.add(reply)
                    self.line.emit(format_reply(reply, self.size))
                    self.stats.emit(replace(stats, rtts=list(stats.rtts)))  # A copy, since stats keeps changing
                    if self.count is not None and stats.sent >= self.count:
                        break
                    # Wait out the rest of the interval, waking immediately if stopped
                    self.stop_event.wait(max(0.0, PING_INTERVAL_SECONDS - (time.monotonic() - started)))
        except (OSError, ValueError) as error:
            self.line.emit(str(error))
        if stats.sent:
            self.line.emit("")
            self.line.emit(stats.summary())
        self.stats.emit(stats)


class PingTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.restart_when_stopped = False
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.update_quick_buttons())
        window.adapter_changed.connect(lambda _: self.update_quick_buttons())
        self.update_quick_buttons()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)

        host_row = QHBoxLayout()
        self.host_input = QLineEdit(DEFAULTS["host"])
        self.host_input.setPlaceholderText("Host name or IPv4/IPv6 address")
        host_row.addWidget(self.host_input, 1)
        self.gateway_button = QPushButton("Gateway")
        self.gateway_button.setToolTip("Ping the selected adapter's default gateway.")
        self.dns_button = QPushButton("DNS Server")
        self.dns_button.setToolTip("Ping the selected adapter's first DNS server.")
        host_row.addWidget(self.gateway_button)
        host_row.addWidget(self.dns_button)

        self.count_input = QLineEdit(DEFAULTS["count"])
        self.count_input.setValidator(QIntValidator(1, 100000))
        self.continuous_check = QCheckBox("Until stopped")
        count_row = QHBoxLayout()
        count_row.addWidget(self.count_input, 1)
        count_row.addWidget(self.continuous_check)
        self.size_input = QLineEdit(DEFAULTS["size"])
        self.size_input.setValidator(QIntValidator(0, 65500))
        self.timeout_input = QLineEdit(DEFAULTS["timeout"])
        self.timeout_input.setValidator(QIntValidator(100, 60000))
        self.df_check = QCheckBox("Don't fragment (DF)")
        self.df_check.setToolTip("Set the Don't Fragment bit (IPv4 only), useful for testing MTU by hand.")

        form = QFormLayout()
        form.addRow("Remote host:", host_row)
        form.addRow("Count:", count_row)
        form.addRow("Size (bytes):", self.size_input)
        form.addRow("Timeout (ms):", self.timeout_input)
        form.addRow("Options:", self.df_check)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Ping")
        self.stop_button = QPushButton("Stop")
        self.clear_button = QPushButton("Clear")
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addWidget(self.clear_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.summary_label = QLabel()
        font = QFont(self.summary_label.font())
        font.setBold(True)
        self.summary_label.setFont(font)
        layout.addWidget(self.summary_label)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9))
        self.output.setMaximumBlockCount(10000)  # Keep continuous pings from growing without limit
        layout.addWidget(self.output, 1)

        self.start_button.clicked.connect(self.start_ping)
        self.stop_button.clicked.connect(self.stop_ping)
        self.clear_button.clicked.connect(self.clear_output)
        self.host_input.returnPressed.connect(self.start_ping)
        self.continuous_check.toggled.connect(lambda checked: self.count_input.setEnabled(not checked))
        self.gateway_button.clicked.connect(lambda: self.ping_quick_target("gateway"))
        self.dns_button.clicked.connect(lambda: self.ping_quick_target("dns"))

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("ping/host", self.host_input.text())
        settings.setValue("ping/count", self.count_input.text())
        settings.setValue("ping/size", self.size_input.text())
        settings.setValue("ping/timeout", self.timeout_input.text())
        settings.setValue("ping/continuous", self.continuous_check.isChecked())
        settings.setValue("ping/df", self.df_check.isChecked())

    def restore_settings(self, settings):
        self.host_input.setText(settings.value("ping/host", DEFAULTS["host"], str))
        self.count_input.setText(settings.value("ping/count", DEFAULTS["count"], str))
        self.size_input.setText(settings.value("ping/size", DEFAULTS["size"], str))
        self.timeout_input.setText(settings.value("ping/timeout", DEFAULTS["timeout"], str))
        self.continuous_check.setChecked(settings.value("ping/continuous", False, bool))
        self.df_check.setChecked(settings.value("ping/df", False, bool))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)

    # ----------------------------------------------------------------- Quick targets

    def quick_targets(self):
        adapter = self.window.current_adapter()
        if adapter is None:
            return None, None
        gateway = (adapter.gateways4 + adapter.gateways6 or [None])[0]
        dns = (adapter.dns4 + adapter.dns6 or [None])[0]
        return gateway, dns

    def update_quick_buttons(self):
        gateway, dns = self.quick_targets()
        self.gateway_button.setEnabled(gateway is not None)
        self.gateway_button.setText(f"Gateway ({gateway})" if gateway else "Gateway")
        self.dns_button.setEnabled(dns is not None)
        self.dns_button.setText(f"DNS ({dns})" if dns else "DNS Server")

    def ping_quick_target(self, kind):
        gateway, dns = self.quick_targets()
        target = gateway if kind == "gateway" else dns
        if target:
            self.ping_host(target)

    def ping_host(self, host):
        """Ping host now, stopping any ping that's already running."""
        self.host_input.setText(host)
        if self.worker is not None:
            self.restart_when_stopped = True  # Start the new ping once the current one ends
            self.stop_ping()
        else:
            self.start_ping()

    # ----------------------------------------------------------------- Ping

    def start_ping(self):
        if self.worker is not None:
            return
        count = None if self.continuous_check.isChecked() else int(self.count_input.text() or DEFAULTS["count"])
        size = int(self.size_input.text() or DEFAULTS["size"])
        timeout = int(self.timeout_input.text() or DEFAULTS["timeout"])
        host = self.host_input.text().strip() or DEFAULTS["host"]

        if self.output.toPlainText():
            self.output.appendPlainText("")
        self.summary_label.clear()
        self.worker = PingThread(host, count, size, timeout, self.df_check.isChecked(), self)
        self.worker.line.connect(self.output.appendPlainText)
        self.worker.stats.connect(lambda stats: self.summary_label.setText(stats.summary() if stats.sent else ""))
        self.worker.finished.connect(self.on_finished)
        self.worker.start()
        self.update_buttons()

    def stop_ping(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.update_buttons()
        if self.restart_when_stopped:
            self.restart_when_stopped = False
            self.start_ping()

    def clear_output(self):
        self.output.clear()
        self.summary_label.clear()

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
