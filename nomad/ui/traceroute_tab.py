"""Traceroute tab: show each router on the path to a host."""
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QIntValidator
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, \
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..icmp import IP_REQ_TIMED_OUT, TTL_EXPIRED_STATUSES, IcmpClient, resolve_host
from .common import StoppableThread, set_hint
from .theme import accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"host": "8.8.8.8", "max_hops": "30", "timeout": "1000"}
PROBES_PER_HOP = 3
COLUMNS = ["Hop", "Probe 1", "Probe 2", "Probe 3", "Address", "Host name", "Note"]
COL_NAME = COLUMNS.index("Host name")


class TracerouteThread(StoppableThread):
    started_trace = pyqtSignal(str)
    hop = pyqtSignal(int, list, str, str)  # (hop number, probe times, address, note)
    name_resolved = pyqtSignal(int, str)
    finished_trace = pyqtSignal(str)

    def __init__(self, host, max_hops, timeout, resolve_names, parent=None):
        super().__init__(parent)
        self.host, self.max_hops, self.timeout, self.resolve_names = host, max_hops, timeout, resolve_names

    def run(self):
        resolver = ThreadPoolExecutor(max_workers=4) if self.resolve_names else None
        message = ""
        try:
            address, family = resolve_host(self.host)
            self.started_trace.emit(f"Tracing route to {self.host} [{address}] over a maximum of {self.max_hops} hops")
            with IcmpClient(family) as client:
                for hop_number in range(1, self.max_hops + 1):
                    if self.stopping:
                        message = "Stopped."
                        break
                    times, responder, note, reached = [], "", "", False
                    for _ in range(PROBES_PER_HOP):
                        if self.stopping:
                            break
                        reply = client.echo(address, timeout=self.timeout, ttl=hop_number)
                        if reply.status == IP_REQ_TIMED_OUT:
                            times.append("*")
                            continue
                        times.append("<1 ms" if not reply.rtt else f"{reply.rtt} ms")
                        responder = responder or reply.address
                        if reply.ok:
                            reached = True
                        elif reply.status not in TTL_EXPIRED_STATUSES:
                            note = reply.message
                    self.hop.emit(hop_number, times, responder, note or ("" if responder else "Request timed out."))
                    if responder and resolver is not None:
                        future = resolver.submit(self.reverse_lookup, responder)
                        future.add_done_callback(
                            lambda done, hop_number=hop_number: self.name_resolved.emit(hop_number, done.result()))
                    if reached:
                        message = "Trace complete."
                        break
                    if note:  # Unreachable and similar errors end the trace
                        message = f"Trace stopped: {note}"
                        break
                else:
                    message = f"Reached the maximum of {self.max_hops} hops without reaching {self.host}."
        except (OSError, ValueError) as error:
            message = str(error)
        finally:
            if resolver is not None:
                resolver.shutdown(wait=True)
        self.finished_trace.emit(message)

    @staticmethod
    def reverse_lookup(address):
        try:
            return socket.gethostbyaddr(address)[0]
        except OSError:
            return ""


class TracerouteTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.init_ui()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.host_input = QLineEdit(DEFAULTS["host"])
        self.host_input.setPlaceholderText("Host name or IPv4/IPv6 address")
        self.max_hops_input = QLineEdit(DEFAULTS["max_hops"])
        self.max_hops_input.setValidator(QIntValidator(1, 255))
        self.timeout_input = QLineEdit(DEFAULTS["timeout"])
        self.timeout_input.setValidator(QIntValidator(100, 60000))
        self.resolve_check = QCheckBox("Look up router names")
        self.resolve_check.setChecked(True)
        form = QFormLayout()
        form.addRow("Remote host:", self.host_input)
        form.addRow("Maximum hops:", self.max_hops_input)
        form.addRow("Timeout per probe (ms):", self.timeout_input)
        form.addRow("Options:", self.resolve_check)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Traceroute")
        self.stop_button = QPushButton("Stop")
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(COL_NAME, QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

        self.start_button.clicked.connect(self.start_trace)
        self.stop_button.clicked.connect(self.stop_trace)
        self.host_input.returnPressed.connect(self.start_trace)

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("trace/host", self.host_input.text())
        settings.setValue("trace/max_hops", self.max_hops_input.text())
        settings.setValue("trace/timeout", self.timeout_input.text())
        settings.setValue("trace/resolve", self.resolve_check.isChecked())

    def restore_settings(self, settings):
        self.host_input.setText(settings.value("trace/host", DEFAULTS["host"], str))
        self.max_hops_input.setText(settings.value("trace/max_hops", DEFAULTS["max_hops"], str))
        self.timeout_input.setText(settings.value("trace/timeout", DEFAULTS["timeout"], str))
        self.resolve_check.setChecked(settings.value("trace/resolve", True, bool))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(5000)

    # ----------------------------------------------------------------- Trace

    def start_trace(self):
        if self.worker is not None:
            return
        host = self.host_input.text().strip()
        if not host:
            set_hint(self.status_label, "Enter a host to trace.", "error")
            return
        self.table.setRowCount(0)
        set_hint(self.status_label, f"Resolving {host}...", "info")
        self.worker = TracerouteThread(host, int(self.max_hops_input.text() or DEFAULTS["max_hops"]),
                                       int(self.timeout_input.text() or DEFAULTS["timeout"]),
                                       self.resolve_check.isChecked(), self)
        self.worker.started_trace.connect(lambda text: set_hint(self.status_label, text, "info"))
        self.worker.hop.connect(self.add_hop)
        self.worker.name_resolved.connect(self.set_hop_name)
        self.worker.finished_trace.connect(self.on_trace_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.update_buttons()

    def add_hop(self, hop_number, times, address, note):
        row = self.table.rowCount()
        self.table.insertRow(row)
        times = times + [""] * (PROBES_PER_HOP - len(times))
        values = [str(hop_number)] + times + [address or "*", "", note]
        for column, value in enumerate(values):
            self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.scrollToBottom()

    def set_hop_name(self, hop_number, name):
        if not name:
            return
        for row in range(self.table.rowCount()):
            if self.table.item(row, 0).text() == str(hop_number):
                self.table.setItem(row, COL_NAME, QTableWidgetItem(name))

    def on_trace_finished(self, message):
        kind = "success" if message == "Trace complete." else "warning"
        set_hint(self.status_label, message, kind)

    def stop_trace(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.update_buttons()

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
