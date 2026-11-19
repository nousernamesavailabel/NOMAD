"""Ports tab: check whether TCP ports on a host are open, closed or filtered by a firewall."""
import logging
import subprocess
import time
import webbrowser

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFormLayout, QHBoxLayout, QLabel, \
    QLineEdit, QMenu, QMessageBox, QProgressBar, QPushButton, QSpinBox, QTableWidget, QVBoxLayout, QWidget

from ..icmp import resolve_host
from ..ports import CLOSED, FILTERED, OPEN, PORT_PRESETS, SCAN_PASSES, WEB_PORTS, check_port, parse_ports, \
    scan_ports, summarize
from .common import ColumnFitter, SortableTableItem, StoppableThread, release_thread, set_hint, set_invalid
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"ports": PORT_PRESETS[0][1], "workers": 100, "timeout": 1000}
COLUMNS = ["Port", "State", "Service", "Response Time", "Details"]
COL_PORT, COL_STATE, COL_SERVICE, COL_RTT, COL_DETAIL = range(len(COLUMNS))
STATE_COLORS = {OPEN: COLORS["success"], CLOSED: COLORS["muted"], FILTERED: COLORS["warning"]}
PROGRESS_INTERVAL_SECONDS = 0.05
CUSTOM_PRESET = "Custom"


class PortScanThread(StoppableThread):
    resolved = pyqtSignal(str)  # Address being scanned
    result = pyqtSignal(object)  # PortResult
    progress = pyqtSignal(int, int)
    finished_scan = pyqtSignal(str, bool)  # (message, succeeded)

    def __init__(self, host, ports, workers, timeout, parent=None):
        super().__init__(parent)
        self.host, self.ports, self.workers, self.timeout = host, ports, workers, timeout
        self.last_progress = 0.0

    def report_progress(self, done, total):
        now = time.monotonic()
        if done == total or now - self.last_progress >= PROGRESS_INTERVAL_SECONDS:
            self.last_progress = now
            self.progress.emit(done, total)

    def run(self):
        try:
            address, family = resolve_host(self.host)
        except ValueError as error:
            self.finished_scan.emit(str(error), False)
            return
        self.resolved.emit(address)
        started = time.monotonic()
        results = scan_ports(self.ports, lambda port: check_port(address, family, port, self.timeout), self.workers,
                             should_stop=lambda: self.stopping, result=self.result.emit,
                             progress=self.report_progress)
        elapsed = time.monotonic() - started
        summary = summarize(results.values()) or "nothing checked"
        verb = "stopped" if self.stopping else "complete"
        self.finished_scan.emit(f"Scan of {self.host} {verb}: {summary} ({elapsed:.1f} seconds).", True)


class PortsTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.results = []
        self.port_count = 0
        self.scanned_host = ""
        self.restart_when_stopped = False
        self.init_ui()
        window.adapter_changed.connect(lambda _: self.update_gateway_button())
        window.snapshot_changed.connect(lambda _: self.update_gateway_button())
        self.update_gateway_button()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)

        host_row = QHBoxLayout()
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Host name or IPv4/IPv6 address")
        host_row.addWidget(self.host_input, 1)
        self.gateway_button = QPushButton("Adapter's Gateway")
        self.gateway_button.setToolTip("Scan the selected adapter's default gateway.")
        host_row.addWidget(self.gateway_button)

        ports_row = QHBoxLayout()
        self.preset_combo = QComboBox()
        for label, ports in PORT_PRESETS:
            self.preset_combo.addItem(label, ports)
        self.preset_combo.addItem(CUSTOM_PRESET, None)
        ports_row.addWidget(self.preset_combo)
        self.ports_input = QLineEdit(DEFAULTS["ports"])
        self.ports_input.setPlaceholderText("Ports and ranges, such as 22, 80, 443, 8000-8100")
        ports_row.addWidget(self.ports_input, 1)

        self.workers_input = QSpinBox()
        self.workers_input.setRange(1, 500)
        self.workers_input.setValue(DEFAULTS["workers"])
        self.workers_input.setToolTip("How many ports to try at the same time.")
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(100, 10000)
        self.timeout_input.setSingleStep(100)
        self.timeout_input.setValue(DEFAULTS["timeout"])
        self.timeout_input.setToolTip("How long to wait for an answer before calling a port filtered.")
        for spin_box in (self.workers_input, self.timeout_input):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        self.show_all_check = QCheckBox("Show closed and filtered ports")
        self.show_all_check.setToolTip("Closed: the host refused the connection, so nothing is listening.\n"
                                       "Filtered: no answer, usually because a firewall drops the connection.")

        form = QFormLayout()
        form.addRow("Host:", host_row)
        form.addRow("Ports:", ports_row)
        form.addRow("Parallel connections:", self.workers_input)
        form.addRow("Timeout (ms):", self.timeout_input)
        form.addRow("Options:", self.show_all_check)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Scan")
        self.start_button.setToolTip(f"Try a TCP connection to each port. Ports that don't answer are tried "
                                     f"again, {SCAN_PASSES} tries in all.")
        self.stop_button = QPushButton("Stop")
        self.copy_button = QPushButton("Copy Results")
        for button in (self.start_button, self.stop_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.copy_button)
        layout.addLayout(buttons)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_PORT, Qt.AscendingOrder)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)
        layout.addWidget(self.table, 1)

        self.gateway_button.clicked.connect(self.use_gateway)
        self.host_input.returnPressed.connect(self.start_scan)
        self.ports_input.returnPressed.connect(self.start_scan)
        self.ports_input.textEdited.connect(self.on_ports_edited)
        self.ports_input.textChanged.connect(lambda: set_invalid(self.ports_input, False))
        self.preset_combo.activated.connect(self.on_preset_chosen)
        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.copy_button.clicked.connect(self.copy_results)
        self.show_all_check.toggled.connect(self.fill_table)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.table.doubleClicked.connect(lambda index: self.open_port(self.port_at(index.row())))

    # ----------------------------------------------------------------- Tab interface

    def focus_find(self):
        self.host_input.setFocus()
        self.host_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("ports/host", self.host_input.text())
        settings.setValue("ports/ports", self.ports_input.text())
        settings.setValue("ports/workers", self.workers_input.value())
        settings.setValue("ports/timeout", self.timeout_input.value())
        settings.setValue("ports/show_all", self.show_all_check.isChecked())

    def restore_settings(self, settings):
        self.host_input.setText(settings.value("ports/host", "", str))
        self.ports_input.setText(settings.value("ports/ports", DEFAULTS["ports"], str))
        self.workers_input.setValue(settings.value("ports/workers", DEFAULTS["workers"], int))
        self.timeout_input.setValue(settings.value("ports/timeout", DEFAULTS["timeout"], int))
        self.show_all_check.setChecked(settings.value("ports/show_all", False, bool))
        self.on_ports_edited()

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            release_thread(self.worker, self.timeout_input.value() + 3000)

    def scan_host(self, host, ports=None):
        """Scan host now (the common ports unless given others), stopping any scan that's still running."""
        self.host_input.setText(host)
        if ports is not None:
            self.ports_input.setText(ports)
        elif self.preset_combo.currentData() is None:  # Custom list: switch to the common ports
            self.ports_input.setText(DEFAULTS["ports"])
        self.on_ports_edited()
        if self.worker is not None:
            self.restart_when_stopped = True
            self.stop_scan()
        else:
            self.start_scan()

    # ----------------------------------------------------------------- Inputs

    def gateway(self):
        adapter = self.window.current_adapter()
        gateways = (adapter.gateways4 + adapter.gateways6) if adapter else []
        return gateways[0] if gateways else None

    def update_gateway_button(self):
        gateway = self.gateway()
        self.gateway_button.setEnabled(gateway is not None)
        self.gateway_button.setText(f"Adapter's Gateway ({gateway})" if gateway else "Adapter's Gateway")

    def use_gateway(self):
        gateway = self.gateway()
        if gateway:
            self.host_input.setText(gateway)

    def on_preset_chosen(self, index):
        ports = self.preset_combo.itemData(index)
        if ports is not None:
            self.ports_input.setText(ports)

    def on_ports_edited(self):
        """Show the preset that matches the typed ports, or Custom."""
        index = self.preset_combo.findData(self.ports_input.text().replace(" ", ""))
        self.preset_combo.setCurrentIndex(index if index >= 0 else self.preset_combo.count() - 1)

    # ----------------------------------------------------------------- Scan

    def start_scan(self):
        if self.worker is not None:
            return
        host = self.host_input.text().strip()
        if not host:
            set_invalid(self.host_input, True)
            set_hint(self.status_label, "Enter a host to scan.", "error")
            return
        set_invalid(self.host_input, False)
        try:
            ports = parse_ports(self.ports_input.text())
        except ValueError as error:
            set_invalid(self.ports_input, True)
            set_hint(self.status_label, str(error), "error")
            return

        self.results = []
        self.port_count = len(ports)
        self.scanned_host = host
        self.fill_table()
        self.progress_bar.setRange(0, len(ports))
        self.progress_bar.setValue(0)
        count = f"{len(ports):,} port{'' if len(ports) == 1 else 's'}"
        set_hint(self.status_label, f"Resolving {host}...", "info")
        log.info("Scanning %s on %s", count, host)
        self.worker = PortScanThread(host, ports, self.workers_input.value(), self.timeout_input.value(), self)
        self.worker.resolved.connect(self.on_resolved)
        self.worker.result.connect(self.add_result)
        self.worker.progress.connect(self.show_progress)
        self.worker.finished_scan.connect(self.on_scan_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.window.set_busy("ports", f"Scanning ports on {host}")
        self.update_buttons()

    def stop_scan(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_scan_finished(self, message, succeeded):
        if not succeeded:
            set_hint(self.status_label, message, "error")
            return
        if not self.worker.stopping:
            self.progress_bar.setValue(self.progress_bar.maximum())
        if self.port_count == 1 and self.results:  # Checking a single port: say what happened to it
            result = self.results[0]
            message = f"Port {result.port} on {self.scanned_host} is {result.state.lower()}" + \
                      (f": {result.detail}." if result.detail else ".")
        has_open = any(result.state == OPEN for result in self.results)
        set_hint(self.status_label, message, "success" if has_open else "warning")
        log.info(message)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.window.clear_busy("ports")
        self.update_buttons()
        if self.restart_when_stopped:
            self.restart_when_stopped = False
            self.start_scan()

    def on_resolved(self, address):
        count, host = self.port_count, self.scanned_host
        set_hint(self.status_label, f"Scanning {count:,} port{'' if count == 1 else 's'} on {host}"
                                    f"{'' if address == host else f' [{address}]'}...", "info")

    def show_progress(self, done, total):
        self.progress_bar.setValue(done)

    def add_result(self, result):
        self.results.append(result)
        if self.shown(result):
            self.table.setSortingEnabled(False)
            self.add_row(result)
            self.table.setSortingEnabled(True)
        self.update_buttons()

    def shown(self, result):
        return result.state == OPEN or self.show_all_check.isChecked() or self.port_count == 1

    def fill_table(self):
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        for result in self.results:
            if self.shown(result):
                self.add_row(result)
        self.table.setSortingEnabled(True)
        self.update_buttons()

    def add_row(self, result):
        row = self.table.rowCount()
        self.table.insertRow(row)
        rtt = "" if result.rtt is None else "<1 ms" if result.rtt < 1 else f"{result.rtt:.0f} ms"
        cells = [(str(result.port), result.port), (result.state, result.state), (result.service, result.service),
                 (rtt, -1 if result.rtt is None else result.rtt), (result.detail, result.detail)]
        for column, (text, sort_key) in enumerate(cells):
            item = SortableTableItem(text, sort_key, result)
            if column == COL_STATE and result.state in STATE_COLORS:
                item.setForeground(QColor(STATE_COLORS[result.state]))
            self.table.setItem(row, column, item)

    def copy_results(self):
        lines = [f"Port scan of {self.scanned_host}"]
        for result in sorted(self.results, key=lambda result: result.port):
            if self.shown(result):
                service = f" ({result.service})" if result.service else ""
                lines.append(f"{result.port}/tcp{service}: {result.state}")
        lines.append(summarize(self.results))
        QApplication.clipboard().setText("\n".join(lines) + "\n")
        self.window.show_status("Copied the scan results to the clipboard.", "info")

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running and not self.worker.stopping)
        self.copy_button.setEnabled(bool(self.results) and not running)

    # ----------------------------------------------------------------- Actions on a port

    def port_at(self, row):
        item = self.table.item(row, COL_PORT)
        return item.data_object if item is not None else None

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.selectRow(item.row())
        result = self.port_at(item.row())
        host = self.scanned_host
        target = f"[{host}]:{result.port}" if ":" in host else f"{host}:{result.port}"
        menu = QMenu(self)
        actions = {}
        if result.state == OPEN:
            if result.port in WEB_PORTS:
                url = f"{WEB_PORTS[result.port]}://{target}"
                actions[menu.addAction(f"Open {url}")] = lambda: self.open_port(result)
                actions[menu.addAction("Check Web Server (timings, certificate)")] = lambda: self.check_web(url)
            elif result.port == 3389:
                actions[menu.addAction("Remote Desktop")] = lambda: self.open_port(result)
            elif result.port == 22:
                actions[menu.addAction("Open SSH Session")] = lambda: self.open_port(result)
                actions[menu.addAction("Open SCP Session")] = lambda: self.window.scp_tab.open_address(host)
                actions[menu.addAction("SSH with PuTTY")] = lambda: self.window.sweep_tab.open_ssh(self.scanned_host)
            elif result.port == 23:
                actions[menu.addAction("Open Telnet Session")] = lambda: self.open_port(result)
            if actions:
                menu.addSeparator()
        actions[menu.addAction(f"Copy {target}")] = lambda: QApplication.clipboard().setText(target)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def check_web(self, url):
        self.window.navigator.setCurrentWidget(self.window.web_check_tab)
        self.window.web_check_tab.check_url(url)

    def open_port(self, result):
        """Open a web page, Remote Desktop or SSH session on an open port."""
        if result is None or result.state != OPEN:
            return
        host = self.scanned_host
        target = f"[{host}]:{result.port}" if ":" in host else f"{host}:{result.port}"
        if result.port in WEB_PORTS:
            url = f"{WEB_PORTS[result.port]}://{target}"
            webbrowser.open_new_tab(url)
            self.window.show_status(f"Opened {url}.", "info")
        elif result.port == 3389:
            try:
                subprocess.Popen(["mstsc.exe", f"/v:{target}"])
            except OSError as error:
                QMessageBox.critical(self, "Remote Desktop", f"Couldn't start Remote Desktop:\n\n{error}")
        elif result.port == 22:
            self.window.terminal_tab.open_address(host, "SSH")
        elif result.port == 23:
            self.window.terminal_tab.open_address(host, "Telnet")
