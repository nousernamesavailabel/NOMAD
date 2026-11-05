"""Connections tab: TCP connections and listening ports, with the program that owns each (like netstat -ano)."""
import ipaddress
import logging
import time

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMenu, \
    QPushButton, QTableWidget, QVBoxLayout, QWidget

from ..connections import TCP, UDP, list_connections, matches
from .common import ColumnFitter, SortableTableItem, run_in_background, set_hint

log = logging.getLogger(__name__)

COLUMNS = ["Protocol", "Local Address", "Local Port", "Remote Address", "Remote Port", "State", "PID", "Program"]
COL_PROTOCOL, COL_LOCAL, COL_LOCAL_PORT, COL_REMOTE, COL_REMOTE_PORT, COL_STATE, COL_PID, COL_PROCESS = \
    range(len(COLUMNS))
AUTO_REFRESH_MILLISECONDS = 2000
AUTO_REFRESH_AFTER_SECONDS = 3


def address_key(text):
    try:
        address = ipaddress.ip_address(text.partition("%")[0])
    except ValueError:
        return 0, 0
    return address.version, int(address)


class ConnectionsTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.connections = []
        self.loading = False
        self.last_load = 0.0
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.on_timer)

    def init_ui(self):
        layout = QVBoxLayout(self)

        toolbar = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by port, address, program or PID, such as 443 or chrome (Ctrl+F)")
        self.filter_input.setClearButtonEnabled(True)
        toolbar.addWidget(self.filter_input, 1)
        self.tcp_check = QCheckBox("TCP")
        self.tcp_check.setChecked(True)
        self.udp_check = QCheckBox("UDP")
        self.udp_check.setChecked(True)
        self.listening_check = QCheckBox("Listening only")
        self.listening_check.setToolTip("Only show ports waiting for connections: what this computer offers to "
                                        "the network.")
        self.hide_local_check = QCheckBox("Hide loopback")
        self.hide_local_check.setToolTip("Hide connections and ports only reachable from this computer "
                                         "(127.0.0.1 and ::1).")
        self.auto_check = QCheckBox("Auto refresh")
        self.auto_check.setToolTip(f"Refresh every {AUTO_REFRESH_MILLISECONDS // 1000} seconds while this tab "
                                   "is showing.")
        for check in (self.tcp_check, self.udp_check, self.listening_check, self.hide_local_check, self.auto_check):
            toolbar.addWidget(check)
        layout.addLayout(toolbar)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_LOCAL_PORT, Qt.AscendingOrder)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)
        layout.addWidget(self.table, 1)

        bottom = QHBoxLayout()
        self.status_label = QLabel()
        bottom.addWidget(self.status_label, 1)
        self.refresh_button = QPushButton("Refresh")
        bottom.addWidget(self.refresh_button)
        layout.addLayout(bottom)

        self.filter_input.textChanged.connect(self.fill_table)
        for check in (self.tcp_check, self.udp_check, self.listening_check, self.hide_local_check):
            check.toggled.connect(self.fill_table)
        self.auto_check.toggled.connect(self.update_timer)
        self.refresh_button.clicked.connect(self.refresh)
        self.table.customContextMenuRequested.connect(self.show_context_menu)

    # ----------------------------------------------------------------- Tab interface

    def focus_find(self):
        """Ctrl+F on this page."""
        self.filter_input.setFocus()
        self.filter_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("connections/tcp", self.tcp_check.isChecked())
        settings.setValue("connections/udp", self.udp_check.isChecked())
        settings.setValue("connections/listening", self.listening_check.isChecked())
        settings.setValue("connections/hide_local", self.hide_local_check.isChecked())
        settings.setValue("connections/auto", self.auto_check.isChecked())

    def restore_settings(self, settings):
        self.tcp_check.setChecked(settings.value("connections/tcp", True, bool))
        self.udp_check.setChecked(settings.value("connections/udp", True, bool))
        self.listening_check.setChecked(settings.value("connections/listening", False, bool))
        self.hide_local_check.setChecked(settings.value("connections/hide_local", False, bool))
        self.auto_check.setChecked(settings.value("connections/auto", False, bool))

    def shutdown(self):
        self.timer.stop()

    def refresh_if_stale(self):
        if time.monotonic() - self.last_load > AUTO_REFRESH_AFTER_SECONDS:
            self.refresh()

    def show_port(self, port):
        """Show what's using a local port."""
        self.listening_check.setChecked(False)
        self.filter_input.setText(str(port))

    # ----------------------------------------------------------------- Loading

    def update_timer(self):
        if self.auto_check.isChecked() and self.window.is_page_showing(self):
            if not self.timer.isActive():
                self.timer.start(AUTO_REFRESH_MILLISECONDS)
        else:
            self.timer.stop()

    def on_timer(self):
        self.refresh()

    def refresh(self):
        if self.loading:
            return
        self.loading = True
        run_in_background(list_connections, self.on_loaded, self.on_load_failed)

    def on_loaded(self, connections):
        self.loading = False
        self.last_load = time.monotonic()
        self.connections = connections
        self.fill_table()

    def on_load_failed(self, error):
        self.loading = False
        set_hint(self.status_label, f"Couldn't read the connection table: {error}", "error")

    # ----------------------------------------------------------------- Table

    def visible_connections(self):
        protocols = {protocol for protocol, check in ((TCP, self.tcp_check), (UDP, self.udp_check))
                     if check.isChecked()}
        text = self.filter_input.text()
        for connection in self.connections:
            if connection.protocol not in protocols:
                continue
            if self.listening_check.isChecked() and not connection.listening:
                continue
            if self.hide_local_check.isChecked() and is_loopback(connection):
                continue
            if matches(connection, text):
                yield connection

    def fill_table(self):
        selected = self.selected_connection()
        selected_key = self.connection_key(selected) if selected else None
        connections = list(self.visible_connections())
        table = self.table
        scroll = table.verticalScrollBar().value()
        table.setSortingEnabled(False)
        table.setRowCount(len(connections))
        for row, connection in enumerate(connections):
            remote_port = str(connection.remote_port) if connection.remote_address else ""
            cells = [(connection.protocol, connection.protocol),
                     (connection.local_address, address_key(connection.local_address)),
                     (str(connection.local_port), connection.local_port),
                     (connection.remote_address, address_key(connection.remote_address)),
                     (remote_port, connection.remote_port),
                     (connection.state, connection.state),
                     (str(connection.pid), connection.pid),
                     (connection.process, connection.process.lower())]
            for column, (text, sort_key) in enumerate(cells):
                table.setItem(row, column, SortableTableItem(text, sort_key, connection))
        table.setSortingEnabled(True)
        for row in range(table.rowCount()):
            if self.connection_key(table.item(row, 0).data_object) == selected_key:
                table.selectRow(row)
                break
        table.verticalScrollBar().setValue(scroll)
        listening = sum(1 for connection in self.connections if connection.listening)
        set_hint(self.status_label, f"Showing {len(connections)} of {len(self.connections)} "
                                    f"({listening} listening)  ·  updated {time.strftime('%H:%M:%S')}", "info")

    @staticmethod
    def connection_key(connection):
        return (connection.protocol, connection.local_address, connection.local_port, connection.remote_address,
                connection.remote_port, connection.pid)

    def selected_connection(self):
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).data_object if rows else None

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.selectRow(item.row())
        connection = item.data_object
        menu = QMenu(self)
        actions = {}
        remote = connection.remote_address.partition("%")[0]
        if remote and not is_loopback(connection):
            actions[menu.addAction(f"Ping {remote}")] = lambda: self.window.sweep_tab.ping(remote)
            actions[menu.addAction(f"Traceroute to {remote}")] = lambda: self.window.sweep_tab.trace(remote)
            menu.addSeparator()
        if connection.process:
            actions[menu.addAction(f"Show only {connection.process}")] = \
                lambda: self.filter_input.setText(connection.process)
        actions[menu.addAction(f"Show only port {connection.local_port}")] = \
            lambda: self.filter_input.setText(str(connection.local_port))
        menu.addSeparator()
        row_text = "\t".join(self.table.item(item.row(), column).text() for column in range(len(COLUMNS)))
        actions[menu.addAction("Copy Row")] = lambda: QApplication.clipboard().setText(row_text)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()


def is_loopback(connection):
    for text in (connection.local_address, connection.remote_address):
        if not text:
            continue
        try:
            if ipaddress.ip_address(text.partition("%")[0]).is_loopback:
                return True
        except ValueError:
            pass
    return False
