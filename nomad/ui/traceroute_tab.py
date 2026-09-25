"""Traceroute tab: each router on the path to a host, with loss and latency per hop (like MTR / WinMTR)."""
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QColor, QIntValidator
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QFormLayout, QHBoxLayout, QHeaderView, \
    QLabel, QLineEdit, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..icmp import IcmpClient, resolve_host
from ..mtr import MtrTrace, format_ms, report_text
from .common import StoppableThread, set_hint
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"host": "8.8.8.8", "max_hops": "30", "timeout": "1000", "rounds": 3}
COLUMNS = ["Hop", "Address", "Host name", "Loss", "Sent", "Last", "Avg", "Best", "Worst", "StDev", "Note"]
COL_HOP, COL_ADDRESS, COL_NAME, COL_LOSS = 0, 1, 2, 3
ROUND_INTERVAL_SECONDS = 1.0  # Between rounds when running continuously
NAME_LOOKUP_WORKERS = 4


class TracerouteThread(StoppableThread):
    started_trace = pyqtSignal(str)
    updated = pyqtSignal(list, int)  # (HopRows, rounds done)
    name_resolved = pyqtSignal(str, str)  # (address, name)
    finished_trace = pyqtSignal(str, bool)  # (message, reached the host)

    def __init__(self, host, max_hops, timeout, rounds, continuous, resolve_names, parent=None):
        super().__init__(parent)
        self.host, self.max_hops, self.timeout = host, max_hops, timeout
        self.rounds, self.continuous, self.resolve_names = rounds, continuous, resolve_names
        self.address = ""

    def run(self):
        resolver = ThreadPoolExecutor(max_workers=NAME_LOOKUP_WORKERS) if self.resolve_names else None
        looked_up = set()
        clients = []
        message, reached = "", False
        try:
            self.address, family = resolve_host(self.host)
            mode = "until stopped" if self.continuous else f"{self.rounds} probe{'' if self.rounds == 1 else 's'}" \
                                                           " per hop"
            self.started_trace.emit(f"Tracing route to {self.host} [{self.address}] over a maximum of "
                                    f"{self.max_hops} hops, {mode}")
            # One ICMP handle per hop, so every hop can be probed at the same time
            clients = [IcmpClient(family) for _ in range(self.max_hops)]
            trace = MtrTrace(self.max_hops)
            with ThreadPoolExecutor(max_workers=self.max_hops) as probes:
                while not self.stopping and (self.continuous or trace.rounds < self.rounds):
                    started = time.monotonic()
                    ttls = trace.probe_ttls()
                    futures = {ttl: probes.submit(clients[ttl - 1].echo, self.address, timeout=self.timeout, ttl=ttl)
                               for ttl in ttls}
                    replies = {ttl: future.result() for ttl, future in futures.items()}
                    if self.stopping:
                        break
                    trace.add_round(replies)
                    rows = trace.rows()
                    self.updated.emit(rows, trace.rounds)
                    for row in rows:
                        for address in (row.address,) + row.other_addresses:
                            if resolver is not None and address and address not in looked_up:
                                looked_up.add(address)
                                future = resolver.submit(self.reverse_lookup, address)
                                future.add_done_callback(lambda done, address=address: self.report_name(address, done))
                    if self.continuous:
                        self.stop_event.wait(max(0.0, ROUND_INTERVAL_SECONDS - (time.monotonic() - started)))
            reached = trace.reached
            hops = trace.shown_ttls()
            if self.stopping:
                message = "Stopped."
            elif trace.reached:
                message = f"Trace complete: {self.host} is {hops} hop{'' if hops == 1 else 's'} away."
            elif trace.stop_ttl:
                message = f"Trace stopped at hop {trace.stop_ttl}: {trace.hops[trace.stop_ttl].note}"
            else:
                message = (f"{self.host} didn't answer within {self.max_hops} hops. It may block ping; the "
                           "last router that answered is the furthest point known to work.")
        except (OSError, ValueError) as error:
            message = str(error)
        finally:
            for client in clients:
                client.close()
            if resolver is not None:
                # When stopped, drop queued name lookups instead of waiting on them
                resolver.shutdown(wait=True, cancel_futures=self.stopping)
        self.finished_trace.emit(message, reached)

    def report_name(self, address, future):
        if not future.cancelled() and future.exception() is None and future.result():
            self.name_resolved.emit(address, future.result())

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
        self.restart_when_stopped = False
        self.rows = []
        self.names = {}  # address -> host name
        self.traced = ""  # Description of the last trace, for the copied report
        self.init_ui()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.host_input = QLineEdit(DEFAULTS["host"])
        self.host_input.setPlaceholderText("Host name or IPv4/IPv6 address")
        self.max_hops_input = QLineEdit(DEFAULTS["max_hops"])
        self.max_hops_input.setValidator(QIntValidator(1, 64))
        self.timeout_input = QLineEdit(DEFAULTS["timeout"])
        self.timeout_input.setValidator(QIntValidator(100, 60000))
        self.rounds_input = QSpinBox()
        self.rounds_input.setRange(1, 1000)
        self.rounds_input.setValue(DEFAULTS["rounds"])
        self.rounds_input.setButtonSymbols(QSpinBox.NoButtons)
        self.continuous_check = QCheckBox("Keep running until stopped (MTR)")
        self.continuous_check.setToolTip("Probe every hop once a second to build up loss and latency figures. "
                                         "Loss that starts at one hop\nand carries on to the destination shows "
                                         "where a problem is; loss at a single router in the middle\nusually just "
                                         "means that router doesn't bother answering.")
        self.resolve_check = QCheckBox("Look up router names")
        self.resolve_check.setChecked(True)
        rounds_row = QHBoxLayout()
        rounds_row.addWidget(self.rounds_input)
        rounds_row.addWidget(self.continuous_check)
        rounds_row.addStretch()
        form = QFormLayout()
        form.addRow("Remote host:", self.host_input)
        form.addRow("Maximum hops:", self.max_hops_input)
        form.addRow("Timeout per probe (ms):", self.timeout_input)
        form.addRow("Probes per hop:", rounds_row)
        form.addRow("Options:", self.resolve_check)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Traceroute")
        self.stop_button = QPushButton("Stop")
        self.copy_button = QPushButton("Copy Report")
        self.copy_button.setToolTip("Copy the results as a text table, for an email or a ticket with your ISP.")
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        buttons.addWidget(self.copy_button)
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
        self.copy_button.clicked.connect(self.copy_report)
        self.host_input.returnPressed.connect(self.start_trace)
        self.continuous_check.toggled.connect(lambda checked: self.rounds_input.setEnabled(not checked))

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("trace/host", self.host_input.text())
        settings.setValue("trace/max_hops", self.max_hops_input.text())
        settings.setValue("trace/timeout", self.timeout_input.text())
        settings.setValue("trace/rounds", self.rounds_input.value())
        settings.setValue("trace/continuous", self.continuous_check.isChecked())
        settings.setValue("trace/resolve", self.resolve_check.isChecked())

    def restore_settings(self, settings):
        self.host_input.setText(settings.value("trace/host", DEFAULTS["host"], str))
        self.max_hops_input.setText(settings.value("trace/max_hops", DEFAULTS["max_hops"], str))
        self.timeout_input.setText(settings.value("trace/timeout", DEFAULTS["timeout"], str))
        self.rounds_input.setValue(settings.value("trace/rounds", DEFAULTS["rounds"], int))
        self.continuous_check.setChecked(settings.value("trace/continuous", False, bool))
        self.resolve_check.setChecked(settings.value("trace/resolve", True, bool))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(int(self.timeout_input.text() or DEFAULTS["timeout"]) + 5000)

    def trace_host(self, host):
        """Trace to host now, stopping any trace that's still running."""
        self.host_input.setText(host)
        if self.worker is not None:
            self.restart_when_stopped = True  # Start the new trace once the current one ends
            self.stop_trace()
        else:
            self.start_trace()

    # ----------------------------------------------------------------- Trace

    def start_trace(self):
        if self.worker is not None:
            return
        host = self.host_input.text().strip()
        if not host:
            set_hint(self.status_label, "Enter a host to trace.", "error")
            return
        self.table.setRowCount(0)
        self.rows, self.names, self.traced = [], {}, host
        set_hint(self.status_label, f"Resolving {host}...", "info")
        max_hops = max(1, min(64, int(self.max_hops_input.text() or DEFAULTS["max_hops"])))
        self.worker = TracerouteThread(host, max_hops, int(self.timeout_input.text() or DEFAULTS["timeout"]),
                                       self.rounds_input.value(), self.continuous_check.isChecked(),
                                       self.resolve_check.isChecked(), self)
        self.worker.started_trace.connect(self.on_trace_started)
        self.worker.updated.connect(self.show_rows)
        self.worker.name_resolved.connect(self.set_name)
        self.worker.finished_trace.connect(self.on_trace_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.update_buttons()

    def on_trace_started(self, text):
        self.traced = text
        set_hint(self.status_label, text, "info")

    def show_rows(self, rows, rounds):
        self.rows = rows
        self.table.setRowCount(len(rows))
        for index, row in enumerate(rows):
            address = row.address or "*"
            if row.other_addresses:
                address += f" (+{len(row.other_addresses)})"
            values = [str(row.ttl), address, self.names.get(row.address, ""), f"{row.loss_percent:.0f}%",
                      str(row.sent), format_ms(row.last), format_ms(row.average), format_ms(row.best),
                      format_ms(row.worst), format_ms(row.stdev), row.note]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == COL_ADDRESS and row.other_addresses:
                    item.setToolTip("Replies came from several routers at this hop (load balancing):\n" +
                                    "\n".join((row.address,) + row.other_addresses))
                if column == COL_LOSS and row.sent and row.received < row.sent:
                    item.setForeground(QColor(COLORS["error"] if row.received == 0 else COLORS["warning"]))
                self.table.setItem(index, column, item)
        if self.worker is not None and self.worker.continuous:
            set_hint(self.status_label, f"{self.traced}  ·  round {rounds}", "info")

    def set_name(self, address, name):
        self.names[address] = name
        for index, row in enumerate(self.rows):
            if row.address == address:
                self.table.setItem(index, COL_NAME, QTableWidgetItem(name))

    def on_trace_finished(self, message, reached):
        set_hint(self.status_label, message, "success" if reached else "warning")

    def stop_trace(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.update_buttons()
        if self.restart_when_stopped:
            self.restart_when_stopped = False
            self.start_trace()

    def copy_report(self):
        QApplication.clipboard().setText(report_text(self.traced, self.rows, self.names))
        self.window.show_status("Copied the traceroute report to the clipboard.", "info")

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.copy_button.setEnabled(bool(self.rows))
