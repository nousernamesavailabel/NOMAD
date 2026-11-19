"""SNMP Walk page: read a device's details, walk any part of its MIB, or summarize its interfaces and error counters."""
import csv
import logging
import time

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, \
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QTableWidget, QVBoxLayout, QWidget

from ..snmp import SYSTEM, VERSIONS, WALK_PRESETS, SnmpClient, SnmpError, community_is_valid, format_value, \
    interface_summary, oid_name, oid_text, parse_oid
from ..snmpv3 import AUTH_NAMES, PRIV_NAMES, V3User, is_v3
from .common import SortableTableItem, StoppableThread, release_thread, set_hint, set_invalid
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

WALK_COLUMNS = ["Name", "OID", "Type", "Value"]
INTERFACE_COLUMNS = ["Index", "Name", "Description / Alias", "Type", "Admin", "Status", "Speed", "MTU", "MAC Address",
                     "In Errors", "Out Errors", "In Discards", "Out Discards"]
BATCH_SECONDS = 0.2
CUSTOM_OID = "Custom OID"
V3 = "v3"  # The version combo's SNMPv3 choice


class SnmpThread(StoppableThread):
    rows = pyqtSignal(list)  # [(oid, Value)] in batches
    interfaces = pyqtSignal(list)  # [InterfaceRow]
    finished_request = pyqtSignal(str, str)  # (message, kind)

    def __init__(self, client, mode, oid, parent=None):
        super().__init__(parent)
        self.client, self.mode, self.oid = client, mode, oid

    def run(self):
        started = time.monotonic()
        try:
            if self.mode == "interfaces":
                rows = interface_summary(self.client, should_stop=lambda: self.stopping)
                self.interfaces.emit(rows)
                count = f"{len(rows)} interface{'' if len(rows) == 1 else 's'}"
            elif self.mode == "get":
                results = self.client.get([self.oid])
                self.rows.emit(results)
                count = "1 value" if results and not results[0][1].is_exception else "nothing at that OID"
            else:
                batch, total, last_emit = [], 0, time.monotonic()
                for item in self.client.walk(self.oid, should_stop=lambda: self.stopping):
                    batch.append(item)
                    total += 1
                    if time.monotonic() - last_emit >= BATCH_SECONDS:
                        self.rows.emit(batch)
                        batch, last_emit = [], time.monotonic()
                if batch:
                    self.rows.emit(batch)
                count = f"{total:,} value{'' if total == 1 else 's'}"
        except SnmpError as error:
            self.finished_request.emit(str(error), "error")
            return
        except OSError as error:
            self.finished_request.emit(f"Couldn't reach {self.client.host}: {error.strerror or error}", "error")
            return
        elapsed = time.monotonic() - started
        verb = "Stopped" if self.stopping else "Done"
        self.finished_request.emit(f"{verb}: {count} from {self.client.host} in {elapsed:.1f} seconds.",
                                   "warning" if self.stopping else "success")


class SnmpTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.results = []  # [(oid, Value)] for a walk or get
        self.interface_rows = []
        self.showing = "walk"
        self.init_ui()
        window.adapter_changed.connect(lambda _: self.update_gateway_button())
        window.snapshot_changed.connect(lambda _: self.update_gateway_button())
        self.update_gateway_button()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        host_row = QHBoxLayout()
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Switch, router, printer or UPS: host name or IP address")
        self.gateway_button = QPushButton("Adapter's Gateway")
        host_row.addWidget(self.host_input, 1)
        host_row.addWidget(self.gateway_button)

        access_row = QHBoxLayout()
        self.community_input = QLineEdit("public")
        self.community_input.setToolTip("The SNMP community string (a read-only one is enough). Devices often ship "
                                        "with \"public\".")
        self.version_combo = QComboBox()
        self.version_combo.addItems(list(VERSIONS) + [V3])
        self.version_combo.setToolTip("v2c reads faster and supports 64-bit counters; use v1 for old devices, and v3 "
                                      "for a user name with authentication and encryption.")
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(200, 20000)
        self.timeout_input.setSingleStep(500)
        self.timeout_input.setValue(2000)
        self.timeout_input.setButtonSymbols(QSpinBox.NoButtons)
        access_row.addWidget(self.community_input, 1)
        access_row.addWidget(QLabel("Version:"))
        access_row.addWidget(self.version_combo)
        access_row.addWidget(QLabel("Timeout (ms):"))
        access_row.addWidget(self.timeout_input)

        self.v3_row = QWidget()
        v3_layout = QHBoxLayout(self.v3_row)
        v3_layout.setContentsMargins(0, 0, 0, 0)
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("User")
        self.auth_combo, self.priv_combo = QComboBox(), QComboBox()
        for key, label in AUTH_NAMES.items():
            self.auth_combo.addItem(label, key)
        for key, label in PRIV_NAMES.items():
            self.priv_combo.addItem(label, key)
        self.auth_combo.setCurrentIndex(self.auth_combo.findData("sha"))
        self.priv_combo.setCurrentIndex(self.priv_combo.findData("aes128"))
        self.auth_password_input, self.priv_password_input = QLineEdit(), QLineEdit()
        for widget, text in ((self.auth_password_input, "Authentication password"),
                             (self.priv_password_input, "Privacy password")):
            widget.setEchoMode(QLineEdit.Password)
            widget.setPlaceholderText(text)
        self.context_input = QLineEdit()
        self.context_input.setPlaceholderText("Context (optional)")
        self.context_input.setToolTip("The SNMPv3 context to read. Catalyst switches keep each VLAN's MAC address "
                                      "table in context vlan-<number>.")
        for widget in (self.user_input, self.auth_combo, self.auth_password_input, self.priv_combo,
                       self.priv_password_input, self.context_input):
            v3_layout.addWidget(widget, 1 if isinstance(widget, QLineEdit) else 0)
        self.v3_label = QLabel("SNMPv3:")

        what_row = QHBoxLayout()
        self.preset_combo = QComboBox()
        for label, oid in WALK_PRESETS:
            self.preset_combo.addItem(label, oid)
        self.preset_combo.addItem(CUSTOM_OID, None)
        self.oid_input = QLineEdit(SYSTEM)
        self.oid_input.setPlaceholderText("OID, such as 1.3.6.1.2.1.1")
        what_row.addWidget(self.preset_combo)
        what_row.addWidget(self.oid_input, 1)

        form = QFormLayout()
        form.addRow("Device:", host_row)
        self.access_label = QLabel("Community:")
        form.addRow(self.access_label, access_row)
        form.addRow(self.v3_label, self.v3_row)
        form.addRow("Read:", what_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.walk_button = accent_button("Walk")
        self.walk_button.setToolTip("Read everything under the OID.")
        self.get_button = QPushButton("Get")
        self.get_button.setToolTip("Read just this exact OID (such as 1.3.6.1.2.1.1.5.0 for the device's name).")
        self.interfaces_button = QPushButton("Interface Summary")
        self.interfaces_button.setToolTip("One row per port: name, description, status, speed and error counters.")
        self.stop_button = QPushButton("Stop")
        self.copy_button = QPushButton("Copy")
        self.export_button = QPushButton("Export CSV...")
        for button in (self.walk_button, self.get_button, self.interfaces_button, self.stop_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.export_button)
        layout.addLayout(buttons)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.table = QTableWidget(0, len(WALK_COLUMNS))
        self.table.setHorizontalHeaderLabels(WALK_COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self.gateway_button.clicked.connect(self.use_gateway)
        self.version_combo.currentIndexChanged.connect(lambda _: self.update_access())
        self.auth_combo.currentIndexChanged.connect(lambda _: self.update_access())
        self.priv_combo.currentIndexChanged.connect(lambda _: self.update_access())
        self.update_access()
        self.preset_combo.activated.connect(self.on_preset_chosen)
        self.oid_input.textEdited.connect(self.on_oid_edited)
        self.oid_input.textChanged.connect(lambda: set_invalid(self.oid_input, False))
        self.host_input.returnPressed.connect(lambda: self.start("walk"))
        self.oid_input.returnPressed.connect(lambda: self.start("walk"))
        self.walk_button.clicked.connect(lambda: self.start("walk"))
        self.get_button.clicked.connect(lambda: self.start("get"))
        self.interfaces_button.clicked.connect(lambda: self.start("interfaces"))
        self.stop_button.clicked.connect(self.stop)
        self.copy_button.clicked.connect(self.copy_results)
        self.export_button.clicked.connect(self.export_csv)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.host_input.setFocus()
        self.host_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("snmp/host", self.host_input.text())
        settings.setValue("snmp/community", self.community_input.text())
        settings.setValue("snmp/version", self.version_combo.currentText())
        settings.setValue("snmp/v3_user", self.user_input.text())  # Not its passwords
        settings.setValue("snmp/v3_auth", self.auth_combo.currentData())
        settings.setValue("snmp/v3_priv", self.priv_combo.currentData())
        settings.setValue("snmp/v3_context", self.context_input.text())
        settings.setValue("snmp/timeout", self.timeout_input.value())
        settings.setValue("snmp/oid", self.oid_input.text())

    def restore_settings(self, settings):
        self.host_input.setText(settings.value("snmp/host", "", str))
        self.community_input.setText(settings.value("snmp/community", "public", str))
        self.version_combo.setCurrentText(settings.value("snmp/version", "v2c", str))
        self.user_input.setText(settings.value("snmp/v3_user", "", str))
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(settings.value("snmp/v3_auth", "sha", str))))
        self.priv_combo.setCurrentIndex(max(0, self.priv_combo.findData(settings.value("snmp/v3_priv", "aes128",
                                                                                       str))))
        self.context_input.setText(settings.value("snmp/v3_context", "", str))
        self.timeout_input.setValue(settings.value("snmp/timeout", 2000, int))
        self.oid_input.setText(settings.value("snmp/oid", SYSTEM, str))
        self.on_oid_edited()

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            release_thread(self.worker, self.timeout_input.value() * 3 + 2000)

    def query_host(self, host, community=None, version=None):
        """Read a device's system details now (from the Sweep or Network Map page), with community and version
        (V1 or V2C), or a V3User, when the page knows what the device answers to."""
        self.host_input.setText(host)
        if is_v3(community):
            self.set_v3_user(community)
        elif community:
            self.community_input.setText(community)
            names = {number: name for name, number in VERSIONS.items()}
            if version in names:
                self.version_combo.setCurrentText(names[version])
        self.oid_input.setText(SYSTEM)
        self.on_oid_edited()
        if self.worker is None:
            self.start("walk")

    # ----------------------------------------------------------------- Inputs

    def is_v3(self):
        return self.version_combo.currentText() == V3

    def update_access(self):
        """Community string for v1 and v2c; user, protocols and passwords for v3."""
        v3 = self.is_v3()
        self.community_input.setVisible(not v3)
        self.access_label.setText("Access:" if v3 else "Community:")
        self.v3_label.setVisible(v3)
        self.v3_row.setVisible(v3)
        auth = self.auth_combo.currentData() != "none"
        self.auth_password_input.setEnabled(auth)
        self.priv_combo.setEnabled(auth)
        self.priv_password_input.setEnabled(auth and self.priv_combo.currentData() != "none")

    def set_v3_user(self, user):
        self.version_combo.setCurrentText(V3)
        self.user_input.setText(user.user)
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(user.auth)))
        self.priv_combo.setCurrentIndex(max(0, self.priv_combo.findData(user.priv)))
        self.auth_password_input.setText(user.auth_password)
        self.priv_password_input.setText(user.priv_password)

    def v3_user(self):
        auth = self.auth_combo.currentData()
        priv = self.priv_combo.currentData() if auth != "none" else "none"
        return V3User(self.user_input.text().strip(), auth,
                      self.auth_password_input.text() if auth != "none" else "", priv,
                      self.priv_password_input.text() if priv != "none" else "")

    def gateway(self):
        adapter = self.window.current_adapter()
        return adapter.gateways4[0] if adapter is not None and adapter.gateways4 else None

    def update_gateway_button(self):
        gateway = self.gateway()
        self.gateway_button.setEnabled(gateway is not None)
        self.gateway_button.setText(f"Adapter's Gateway ({gateway})" if gateway else "Adapter's Gateway")

    def use_gateway(self):
        if self.gateway():
            self.host_input.setText(self.gateway())

    def on_preset_chosen(self, index):
        oid = self.preset_combo.itemData(index)
        if oid:
            self.oid_input.setText(oid)

    def on_oid_edited(self):
        index = self.preset_combo.findData(self.oid_input.text().strip().strip("."))
        self.preset_combo.setCurrentIndex(index if index >= 0 else self.preset_combo.count() - 1)

    # ----------------------------------------------------------------- Requests

    def start(self, mode):
        if self.worker is not None:
            return
        host, community = self.host_input.text().strip(), self.community_input.text()
        if not host:
            set_invalid(self.host_input, True)
            set_hint(self.status_label, "Enter the device to read.", "error")
            return
        set_invalid(self.host_input, False)
        if self.is_v3():
            community = self.v3_user()
            if community.problem():
                set_hint(self.status_label, community.problem(), "error")
                return
        elif not community_is_valid(community):
            set_hint(self.status_label, "Enter the community string (such as public).", "error")
            return
        oid = None
        if mode != "interfaces":
            try:
                oid = parse_oid(self.oid_input.text())
            except ValueError as error:
                set_invalid(self.oid_input, True)
                set_hint(self.status_label, str(error), "error")
                return
        try:
            client = SnmpClient(host, community, VERSIONS.get(self.version_combo.currentText(), 1),
                                self.timeout_input.value(), context=self.context_input.text().strip() if
                                self.is_v3() else "")
        except OSError:
            set_hint(self.status_label, f"Couldn't find {host}.", "error")
            return
        self.show_mode("interfaces" if mode == "interfaces" else "walk")
        self.results, self.interface_rows = [], []
        what = {"walk": f"Walking {oid_text(oid)}" if oid else "", "get": f"Reading {oid_text(oid)}" if oid else "",
                "interfaces": "Reading the interface tables"}[mode]
        set_hint(self.status_label, f"{what} on {host}...", "info")
        self.worker = SnmpThread(client, mode, oid, self)
        self.worker.rows.connect(self.add_rows)
        self.worker.interfaces.connect(self.show_interfaces)
        self.worker.finished_request.connect(self.on_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.window.set_busy("snmp", f"Reading SNMP from {host}")
        self.update_buttons()

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_finished(self, message, kind):
        set_hint(self.status_label, message, kind)
        if self.showing == "walk":
            self.table.resizeColumnsToContents()
            self.table.horizontalHeader().setStretchLastSection(True)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.window.clear_busy("snmp")
        self.update_buttons()

    def show_mode(self, mode):
        self.showing = mode
        columns = INTERFACE_COLUMNS if mode == "interfaces" else WALK_COLUMNS
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.table.setColumnCount(len(columns))
        self.table.setHorizontalHeaderLabels(columns)

    def add_rows(self, rows):
        self.results.extend(rows)
        table = self.table
        start = table.rowCount()
        table.setRowCount(start + len(rows))
        for offset, (oid, value) in enumerate(rows):
            row = start + offset
            cells = [oid_name(oid), oid_text(oid), value.type_name, format_value(oid, value)]
            for column, text in enumerate(cells):
                item = SortableTableItem(text, oid if column in (0, 1) else None)
                if value.is_exception:
                    item.setForeground(QColor(COLORS["muted"]))
                table.setItem(row, column, item)
        if start == 0:
            table.resizeColumnsToContents()
            table.horizontalHeader().setStretchLastSection(True)

    def show_interfaces(self, rows):
        self.interface_rows = rows
        self.table.setRowCount(len(rows))
        for row, interface in enumerate(rows):
            speed = "" if interface.speed_mbps is None else \
                f"{interface.speed_mbps / 1000:g} Gbps" if interface.speed_mbps >= 1000 else f"{interface.speed_mbps} Mbps"
            detail = " / ".join(part for part in (interface.description, interface.alias)
                                if part and part != interface.name)
            cells = [(str(interface.index), interface.index), (interface.name, interface.name.lower()),
                     (detail, detail), (interface.kind, interface.kind), (interface.admin, interface.admin),
                     (interface.oper, interface.oper), (speed, interface.speed_mbps or 0),
                     (str(interface.mtu or ""), interface.mtu or 0), (interface.mac, interface.mac)]
            for count in (interface.in_errors, interface.out_errors, interface.in_discards, interface.out_discards):
                cells.append(("" if count is None else f"{count:,}", count or 0))
            for column, (text, sort_key) in enumerate(cells):
                item = SortableTableItem(text, sort_key, interface)
                if column == 5:
                    item.setForeground(QColor(COLORS["success"] if text == "up" else
                                              COLORS["muted"] if interface.admin == "down" else COLORS["warning"]))
                if column >= 9 and sort_key:
                    item.setForeground(QColor(COLORS["warning"]))
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setStretchLastSection(True)

    # ----------------------------------------------------------------- Output

    def table_text(self):
        header = [self.table.horizontalHeaderItem(column).text() for column in range(self.table.columnCount())]
        rows = [[self.table.item(row, column).text() if self.table.item(row, column) else ""
                 for column in range(self.table.columnCount())] for row in range(self.table.rowCount())]
        return header, rows

    def copy_results(self):
        header, rows = self.table_text()
        QApplication.clipboard().setText("\n".join("\t".join(row) for row in [header] + rows) + "\n")
        self.window.show_status(f"Copied {len(rows)} rows to the clipboard.", "info")

    def export_csv(self):
        name = "snmp-interfaces.csv" if self.showing == "interfaces" else "snmp-walk.csv"
        path, _ = QFileDialog.getSaveFileName(self, "Export SNMP Results", name, "CSV files (*.csv);;All files (*)")
        if not path:
            return
        header, rows = self.table_text()
        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(header)
                writer.writerows(rows)
        except OSError as error:
            QMessageBox.critical(self, "Export Failed", f"Couldn't save {path}:\n\n{error}")
            return
        self.window.show_status(f"Exported {len(rows)} rows to {path}.")

    def update_buttons(self):
        running = self.worker is not None
        for button in (self.walk_button, self.get_button, self.interfaces_button):
            button.setEnabled(not running)
        self.stop_button.setEnabled(running and not self.worker.stopping)
        has_rows = self.table.rowCount() > 0
        self.copy_button.setEnabled(has_rows and not running)
        self.export_button.setEnabled(has_rows and not running)
