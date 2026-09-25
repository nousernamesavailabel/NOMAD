"""Sweep tab: find the hosts on a subnet, with their names, MAC addresses and vendors, then SSH, browse, ping,
trace or port scan them."""
import csv
import ipaddress
import logging
import os
import subprocess
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, \
    QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QProgressBar, QPushButton, QSpinBox, QTableWidget, \
    QVBoxLayout, QWidget

from ..oui import vendor
from ..sweep import LARGE_SWEEP_HOSTS, SWEEP_PASSES, add_to_user_path, find_putty, local_networks, lookup_host, \
    make_probe, putty_locations, run_sweep, sweep_hosts
from .common import SortableTableItem, StoppableThread, set_hint, set_invalid
from .theme import accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"workers": 100, "timeout": 1000}
COLUMNS = ["IP Address", "Response Time", "Host Name", "MAC Address", "Vendor"]
COL_ADDRESS, COL_RTT, COL_NAME, COL_MAC, COL_VENDOR = range(len(COLUMNS))
PROGRESS_INTERVAL_SECONDS = 0.05  # Limit progress updates so big sweeps don't flood the UI
NAME_LOOKUP_WORKERS = 16
ARP_ONLY_SORT_KEY = 10 ** 9  # Hosts that only answered ARP sort after every response time


class SweepThread(StoppableThread):
    found = pyqtSignal(str, object)  # (address, SweepHit)
    host_details = pyqtSignal(str, str, str)  # (address, name, MAC reported over NetBIOS)
    progress = pyqtSignal(int, int, int, int)  # (done, total, pass number, hosts in this pass)
    looking_up_names = pyqtSignal(int)  # Name lookups still running after the sweep itself finished
    finished_sweep = pyqtSignal(str)

    def __init__(self, hosts, workers, timeout, arp_networks, find_by_arp, resolve_names, parent=None):
        super().__init__(parent)
        self.hosts, self.workers, self.timeout = hosts, workers, timeout
        self.arp_networks, self.find_by_arp, self.resolve_names = arp_networks, find_by_arp, resolve_names
        self.last_progress = 0.0
        self.resolver = None
        self.pending_names = []

    def report_progress(self, done, total, pass_number, remaining):
        now = time.monotonic()
        if done == total or now - self.last_progress >= PROGRESS_INTERVAL_SECONDS:
            self.last_progress = now
            self.progress.emit(done, total, pass_number, remaining)

    def on_found(self, address, hit):
        self.found.emit(str(address), hit)
        if self.resolver is not None:
            future = self.resolver.submit(lambda: None if self.stopping else lookup_host(address))
            future.add_done_callback(lambda done, address=str(address): self.report_details(address, done))
            self.pending_names.append(future)

    def report_details(self, address, future):
        if future.cancelled() or future.exception() is not None or future.result() is None:
            return
        name, mac = future.result()
        if (name or mac) and not self.stopping:
            self.host_details.emit(address, name, mac)

    def run(self):
        started = time.monotonic()
        probe = make_probe(self.timeout, self.arp_networks, self.find_by_arp)
        self.resolver = ThreadPoolExecutor(max_workers=NAME_LOOKUP_WORKERS) if self.resolve_names else None
        alive = []
        try:
            alive = run_sweep(self.hosts, probe, self.workers, should_stop=lambda: self.stopping,
                              found=self.on_found, progress=self.report_progress)
            if self.resolver is not None and not self.stopping:
                remaining = sum(1 for future in self.pending_names if not future.done())
                if remaining:
                    self.looking_up_names.emit(remaining)
        finally:
            if self.resolver is not None:
                # When stopped, drop queued lookups; DNS can be slow to give up when there's no DNS server
                self.resolver.shutdown(wait=not self.stopping, cancel_futures=self.stopping)
        elapsed = time.monotonic() - started
        found = f"{len(alive)} host{'' if len(alive) == 1 else 's'} found in {elapsed:.1f} seconds"
        self.finished_sweep.emit(f"Sweep stopped: {found}." if self.stopping else f"Sweep complete: {found}.")


class SweepTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.init_ui()
        window.adapter_changed.connect(self.on_adapter_changed)
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)

        subnet_row = QHBoxLayout()
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("IPv4 subnet, such as 192.168.1.0/24")
        subnet_row.addWidget(self.subnet_input, 1)
        self.adapter_subnet_button = QPushButton("Adapter's Subnet")
        self.adapter_subnet_button.setToolTip("Sweep the subnet of the selected adapter's IPv4 address.")
        subnet_row.addWidget(self.adapter_subnet_button)

        self.workers_input = QSpinBox()
        self.workers_input.setRange(1, 1000)
        self.workers_input.setValue(DEFAULTS["workers"])
        self.workers_input.setToolTip("How many hosts to ping at the same time.")
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(100, 10000)
        self.timeout_input.setSingleStep(100)
        self.timeout_input.setValue(DEFAULTS["timeout"])
        for spin_box in (self.workers_input, self.timeout_input):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)  # Like the other tabs' number fields

        self.arp_check = QCheckBox("Find hosts that block ping (ARP)")
        self.arp_check.setChecked(True)
        self.arp_check.setToolTip("On subnets this computer is directly connected to, also ask each address for "
                                  "its MAC address.\nFinds devices whose firewall drops ping, but makes the "
                                  "first pass slower.")
        self.names_check = QCheckBox("Look up host names")
        self.names_check.setChecked(True)
        self.names_check.setToolTip("Look up each host's name in DNS, falling back to its NetBIOS (Windows) "
                                    "name,\nwhich works on networks without a DNS server.")
        options = QHBoxLayout()
        options.addWidget(self.arp_check)
        options.addWidget(self.names_check)
        options.addStretch()

        form = QFormLayout()
        form.addRow("Subnet:", subnet_row)
        form.addRow("Parallel pings:", self.workers_input)
        form.addRow("Timeout (ms):", self.timeout_input)
        form.addRow("Options:", options)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Sweep")
        self.start_button.setToolTip(f"Ping every address on the subnet. Hosts that don't answer are retried, "
                                     f"up to {SWEEP_PASSES} tries in all.")
        self.stop_button = QPushButton("Stop")
        self.clear_button = QPushButton("Clear")
        self.copy_button = QPushButton("Copy Addresses")
        self.export_button = QPushButton("Export CSV...")
        for button in (self.start_button, self.stop_button, self.clear_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.export_button)
        layout.addLayout(buttons)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel()
        layout.addWidget(self.status_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        host_buttons = QHBoxLayout()
        self.ssh_button = QPushButton("SSH (PuTTY)")
        self.web_button = QPushButton("Open in Browser")
        self.web_button.setToolTip("Open https://<host> in the default browser.")
        self.ping_button = QPushButton("Ping")
        self.trace_button = QPushButton("Traceroute")
        self.ports_button = QPushButton("Scan Ports")
        self.ports_button.setToolTip("Check the host's common TCP ports on the Ports tab.")
        self.host_buttons = (self.ssh_button, self.web_button, self.ping_button, self.trace_button, self.ports_button)
        host_buttons.addWidget(QLabel("Selected host:"))
        for button in self.host_buttons:
            host_buttons.addWidget(button)
        host_buttons.addStretch()
        layout.addLayout(host_buttons)

        self.adapter_subnet_button.clicked.connect(self.use_adapter_subnet)
        self.subnet_input.returnPressed.connect(self.start_sweep)
        self.subnet_input.textChanged.connect(lambda: set_invalid(self.subnet_input, False))
        self.start_button.clicked.connect(self.start_sweep)
        self.stop_button.clicked.connect(self.stop_sweep)
        self.clear_button.clicked.connect(self.clear_results)
        self.copy_button.clicked.connect(self.copy_addresses)
        self.export_button.clicked.connect(self.export_csv)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.ssh_button.clicked.connect(lambda: self.open_ssh(self.selected_host()))
        self.web_button.clicked.connect(lambda: self.open_web(self.selected_host()))
        self.ping_button.clicked.connect(lambda: self.ping(self.selected_host()))
        self.trace_button.clicked.connect(lambda: self.trace(self.selected_host()))
        self.ports_button.clicked.connect(lambda: self.scan_ports(self.selected_host()))

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("sweep/subnet", self.subnet_input.text())
        settings.setValue("sweep/workers", self.workers_input.value())
        settings.setValue("sweep/timeout", self.timeout_input.value())
        settings.setValue("sweep/arp", self.arp_check.isChecked())
        settings.setValue("sweep/names", self.names_check.isChecked())

    def restore_settings(self, settings):
        self.subnet_input.setText(settings.value("sweep/subnet", "", str))
        self.workers_input.setValue(settings.value("sweep/workers", DEFAULTS["workers"], int))
        self.timeout_input.setValue(settings.value("sweep/timeout", DEFAULTS["timeout"], int))
        self.arp_check.setChecked(settings.value("sweep/arp", True, bool))
        self.names_check.setChecked(settings.value("sweep/names", True, bool))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(self.timeout_input.value() + 3000)

    # ----------------------------------------------------------------- Subnet

    def adapter_subnet(self):
        adapter = self.window.current_adapter()
        return str(adapter.ipv4[0].network) if adapter is not None and adapter.ipv4 else None

    def on_adapter_changed(self, _adapter):
        subnet = self.adapter_subnet()
        self.adapter_subnet_button.setEnabled(subnet is not None)
        self.adapter_subnet_button.setText(f"Adapter's Subnet ({subnet})" if subnet else "Adapter's Subnet")
        if subnet and not self.subnet_input.text().strip():
            self.subnet_input.setText(subnet)

    def use_adapter_subnet(self):
        subnet = self.adapter_subnet()
        if subnet:
            self.subnet_input.setText(subnet)

    # ----------------------------------------------------------------- Sweep

    def start_sweep(self):
        if self.worker is not None:
            return
        try:
            network, hosts = sweep_hosts(self.subnet_input.text())
        except ValueError as error:
            set_invalid(self.subnet_input, True)
            set_hint(self.status_label, str(error), "error")
            return
        if len(hosts) > LARGE_SWEEP_HOSTS:
            reply = QMessageBox.question(self, "Large Sweep",
                                         f"{network} has {len(hosts):,} addresses, which will take a while.\n\n"
                                         "Sweep it anyway?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        self.clear_results()
        self.progress_bar.setRange(0, len(hosts) * SWEEP_PASSES)
        arp_networks = [local for local in local_networks(self.window.snapshot) if local.overlaps(network)]
        via_arp = " with ARP" if arp_networks and self.arp_check.isChecked() else ""
        set_hint(self.status_label, f"Sweeping {network} ({len(hosts):,} addresses){via_arp}...", "info")
        log.info("Sweeping %s (ARP on %s)", network, ", ".join(map(str, arp_networks)) or "no local subnets")
        self.worker = SweepThread(hosts, self.workers_input.value(), self.timeout_input.value(), arp_networks,
                                  self.arp_check.isChecked(), self.names_check.isChecked(), self)
        self.worker.found.connect(self.add_host)
        self.worker.host_details.connect(self.set_host_details)
        self.worker.looking_up_names.connect(self.on_looking_up_names)
        self.worker.progress.connect(self.on_progress)
        self.worker.finished_sweep.connect(self.on_sweep_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.window.set_busy("sweep", f"Sweeping {network}")
        self.update_buttons()

    def stop_sweep(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)
            set_hint(self.status_label, "Stopping the sweep...", "info")

    def on_progress(self, done, total, pass_number, remaining):
        self.progress_bar.setValue(done)
        what = f"{remaining:,} addresses" if pass_number == 1 else f"retrying {remaining:,} that didn't answer"
        found = self.table.rowCount()
        set_hint(self.status_label, f"Pass {pass_number} of {SWEEP_PASSES}: {what}  ·  "
                                    f"{found} host{'' if found == 1 else 's'} found", "info")

    def on_looking_up_names(self, remaining):
        self.progress_bar.setValue(self.progress_bar.maximum())
        set_hint(self.status_label, f"Looking up names for {remaining} host{'' if remaining == 1 else 's'}...",
                 "info")

    def on_sweep_finished(self, message):
        if not self.worker.stopping:
            self.progress_bar.setValue(self.progress_bar.maximum())
        set_hint(self.status_label, message, "success")
        log.info(message)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.window.clear_busy("sweep")
        self.update_buttons()

    def local_addresses(self):
        return {str(address.ip): adapter for adapter in self.window.snapshot.real_adapters()
                for address in adapter.ipv4}

    def add_host(self, address, hit):
        self.table.setSortingEnabled(False)  # Sorting while inserting would scramble the row
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, COL_ADDRESS, SortableTableItem(address, int(ipaddress.ip_address(address)), address))
        if hit.rtt is None:
            rtt_item = SortableTableItem("No ping reply", ARP_ONLY_SORT_KEY)
            rtt_item.setToolTip("Found by ARP: the host is there, but its firewall drops ping.")
        else:
            rtt_item = SortableTableItem("<1 ms" if hit.rtt < 1 else f"{hit.rtt} ms", hit.rtt)
        self.table.setItem(row, COL_RTT, rtt_item)
        local = self.local_addresses().get(address)
        self.table.setItem(row, COL_NAME, SortableTableItem("(this computer)" if local else ""))
        self.set_mac(row, hit.mac or (local.mac if local else ""))
        self.table.setSortingEnabled(True)
        self.update_buttons()

    def set_mac(self, row, mac):
        self.table.setItem(row, COL_MAC, SortableTableItem(mac))
        self.table.setItem(row, COL_VENDOR, SortableTableItem(vendor(mac)))

    def row_for(self, address):
        return next((row for row in range(self.table.rowCount())
                     if self.table.item(row, COL_ADDRESS).text() == address), None)

    def set_host_details(self, address, name, mac):
        row = self.row_for(address)
        if row is None:
            return
        self.table.setSortingEnabled(False)
        if name:
            this_computer = address in self.local_addresses()
            self.table.setItem(row, COL_NAME, SortableTableItem(f"{name} (this computer)" if this_computer else name))
        if mac and not self.table.item(row, COL_MAC).text():
            self.set_mac(row, mac)
            self.table.item(row, COL_MAC).setToolTip("Reported by the host over NetBIOS.")
        self.table.setSortingEnabled(True)

    def clear_results(self):
        self.table.setRowCount(0)
        self.progress_bar.reset()
        self.status_label.clear()
        self.update_buttons()

    def addresses(self):
        rows = [self.table.item(row, 0) for row in range(self.table.rowCount())]
        return [item.text() for item in sorted(rows, key=lambda item: item.sort_key)]

    def copy_addresses(self):
        addresses = self.addresses()
        QApplication.clipboard().setText("\n".join(addresses))
        self.window.show_status(f"Copied {len(addresses)} addresses to the clipboard.", "info")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export Sweep Results", "sweep-results.csv",
                                              "CSV files (*.csv);;All files (*)")
        if not path:
            return
        by_address = {self.table.item(row, COL_ADDRESS).text(): row for row in range(self.table.rowCount())}
        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(["IP Address", "Response Time (ms)", "Host Name", "MAC Address", "Vendor"])
                for address in self.addresses():
                    row = by_address[address]
                    rtt = self.table.item(row, COL_RTT).sort_key
                    writer.writerow([address, "" if rtt == ARP_ONLY_SORT_KEY else rtt] +
                                    [self.table.item(row, column).text()
                                     for column in (COL_NAME, COL_MAC, COL_VENDOR)])
        except OSError as error:
            QMessageBox.critical(self, "Export Failed", f"Couldn't save {path}:\n\n{error}")
            return
        self.window.show_status(f"Exported {len(by_address)} hosts to {path}.")

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running and not self.worker.stopping)
        self.clear_button.setEnabled(not running)
        has_results = self.table.rowCount() > 0
        self.copy_button.setEnabled(has_results)
        self.export_button.setEnabled(has_results)
        selected = self.selected_host() is not None
        for button in self.host_buttons:
            button.setEnabled(selected)

    # ----------------------------------------------------------------- Host actions

    def selected_host(self):
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).text() if rows else None

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.selectRow(item.row())
        host = self.selected_host()

        menu = QMenu(self)
        actions = {
            menu.addAction("SSH with PuTTY"): lambda: self.open_ssh(host),
            menu.addAction(f"Open https://{host}"): lambda: self.open_web(host),
            menu.addAction(f"Open http://{host}"): lambda: self.open_web(host, "http"),
            menu.addAction("Ping"): lambda: self.ping(host),
            menu.addAction("Traceroute"): lambda: self.trace(host),
            menu.addAction("Monitor Latency"): lambda: self.monitor_latency(host),
            menu.addAction("Scan Ports"): lambda: self.scan_ports(host),
        }
        menu.addSeparator()
        actions[menu.addAction("Copy Address")] = lambda: QApplication.clipboard().setText(host)
        mac = self.table.item(item.row(), COL_MAC).text()
        if mac:
            actions[menu.addAction("Copy MAC Address")] = lambda: QApplication.clipboard().setText(mac)
            name = self.table.item(item.row(), COL_NAME).text().replace(" (this computer)", "")
            actions[menu.addAction("Wake-on-LAN...")] = lambda: self.window.wake_device(mac, name)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def open_ssh(self, host):
        if not host:
            return
        putty = find_putty()
        if not putty:
            QMessageBox.warning(self, "PuTTY Not Found",
                                "PuTTY wasn't found on the PATH or in its usual install folders. "
                                "Install PuTTY from https://www.putty.org, then try again.")
            return
        try:
            subprocess.Popen([putty, "-ssh", host])
        except OSError as error:
            QMessageBox.critical(self, "SSH", f"Couldn't start PuTTY:\n\n{error}")
            return
        self.window.show_status(f"Opened an SSH session to {host}.", "info")

    def open_web(self, host, scheme="https"):
        if host:
            url = f"{scheme}://{host}"
            webbrowser.open_new_tab(url)
            self.window.show_status(f"Opened {url}.", "info")

    def ping(self, host):
        if host:
            self.window.tabs.setCurrentWidget(self.window.ping_tab)
            self.window.ping_tab.ping_host(host)

    def trace(self, host):
        if host:
            self.window.tabs.setCurrentWidget(self.window.traceroute_tab)
            self.window.traceroute_tab.trace_host(host)

    def monitor_latency(self, host):
        if host:
            self.window.tabs.setCurrentWidget(self.window.latency_tab)
            self.window.latency_tab.add_target(host, host)

    def scan_ports(self, host):
        if host:
            self.window.tabs.setCurrentWidget(self.window.ports_tab)
            self.window.ports_tab.scan_host(host)

    # ----------------------------------------------------------------- Menu actions

    def add_putty_to_path(self):
        putty = next((path for path in putty_locations() if os.path.isfile(path)), None) or find_putty()
        if not putty:
            QMessageBox.warning(self, "PuTTY Not Found",
                                "PuTTY wasn't found in its usual install folders. Install PuTTY first.")
            return
        directory = os.path.dirname(os.path.abspath(putty))
        try:
            added = add_to_user_path(directory)
        except OSError as error:
            QMessageBox.critical(self, "Add PuTTY to PATH", f"Couldn't update your PATH:\n\n{error}")
            return
        if added:
            log.info("Added %s to the user PATH", directory)
            QMessageBox.information(self, "Add PuTTY to PATH",
                                    f"Added {directory} to your PATH.\n\nCommand prompts that are already open "
                                    "need to be restarted to see it.")
        else:
            QMessageBox.information(self, "Add PuTTY to PATH", f"{directory} is already on your PATH.")
