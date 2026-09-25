"""DNS lookup tab: query records for a name (or reverse-lookup an address)."""
import logging

from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, \
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..lookup import RECORD_TYPES, resolve, validate_lookup_input
from .common import run_in_background, set_hint
from .theme import accent_button

log = logging.getLogger(__name__)

COLUMNS = ["Name", "Type", "TTL", "Section", "Data"]


class LookupTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.running = False
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.update_server_button())
        window.adapter_changed.connect(lambda _: self.update_server_button())
        self.update_server_button()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.name_input = QLineEdit("example.com")
        self.name_input.setPlaceholderText("Host name, or an IP address for a reverse lookup")
        self.type_combo = QComboBox()
        self.type_combo.addItems(RECORD_TYPES)
        self.server_input = QLineEdit()
        self.server_input.setPlaceholderText("Blank = use Windows' configured DNS servers")
        self.adapter_dns_button = QPushButton("Use Adapter DNS")
        self.adapter_dns_button.setToolTip("Ask the selected adapter's first DNS server directly.")
        server_row = QHBoxLayout()
        server_row.addWidget(self.server_input, 1)
        server_row.addWidget(self.adapter_dns_button)
        form = QFormLayout()
        form.addRow("Name:", self.name_input)
        form.addRow("Record type:", self.type_combo)
        form.addRow("DNS server:", server_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.lookup_button = accent_button("Look Up")
        buttons.addWidget(self.lookup_button)
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
        header.setSectionResizeMode(len(COLUMNS) - 1, QHeaderView.Stretch)
        layout.addWidget(self.table, 1)

        self.lookup_button.clicked.connect(self.start_lookup)
        self.name_input.returnPressed.connect(self.start_lookup)
        self.server_input.returnPressed.connect(self.start_lookup)
        self.adapter_dns_button.clicked.connect(self.use_adapter_dns)

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("lookup/name", self.name_input.text())
        settings.setValue("lookup/type", self.type_combo.currentText())
        settings.setValue("lookup/server", self.server_input.text())

    def restore_settings(self, settings):
        self.name_input.setText(settings.value("lookup/name", "example.com", str))
        self.type_combo.setCurrentText(settings.value("lookup/type", "A", str))
        self.server_input.setText(settings.value("lookup/server", "", str))

    def shutdown(self):
        pass

    # ----------------------------------------------------------------- Lookup

    def adapter_dns(self):
        adapter = self.window.current_adapter()
        servers = (adapter.dns4 + adapter.dns6) if adapter else []
        return servers[0] if servers else None

    def update_server_button(self):
        server = self.adapter_dns()
        self.adapter_dns_button.setEnabled(server is not None)
        self.adapter_dns_button.setText(f"Use Adapter DNS ({server})" if server else "Use Adapter DNS")

    def use_adapter_dns(self):
        server = self.adapter_dns()
        if server:
            self.server_input.setText(server)

    def start_lookup(self):
        if self.running:
            return
        name, server, record_type = self.name_input.text(), self.server_input.text(), self.type_combo.currentText()
        error = validate_lookup_input(name, server)
        if error:
            set_hint(self.status_label, error, "error")
            return
        self.running = True
        self.lookup_button.setEnabled(False)
        self.table.setRowCount(0)
        via = f" via {server.strip()}" if server.strip() else ""
        set_hint(self.status_label, f"Looking up {record_type} records for {name.strip()}{via}...", "info")
        run_in_background(lambda: resolve(name, record_type, server), self.show_results, self.show_error)

    def show_results(self, records):
        self.finish()
        self.table.setRowCount(len(records))
        for row, record in enumerate(records):
            for column, value in enumerate([record.name, record.type, str(record.ttl), record.section, record.data]):
                self.table.setItem(row, column, QTableWidgetItem(value))
        set_hint(self.status_label, f"{len(records)} record(s) found." if records else "No records found.",
                 "success" if records else "warning")

    def show_error(self, error):
        self.finish()
        set_hint(self.status_label, str(error), "error")

    def finish(self):
        self.running = False
        self.lookup_button.setEnabled(True)
