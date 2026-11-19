"""DHCP Servers page: find every DHCP server on the selected adapter's network, to spot rogue ones."""
import logging

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QFormLayout, QHBoxLayout, QLabel, QLineEdit, QProgressBar, \
    QPushButton, QSpinBox, QSplitter, QTableWidget, QVBoxLayout, QWidget

from ..dhcp import CLIENT_PORT, assess, current_dhcp_server, discover_servers
from ..system import allow_inbound_port
from .common import ColumnFitter, SortableTableItem, StoppableThread, release_thread, set_hint
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

COLUMNS = ["DHCP Server", "Verdict", "Offered Address", "Subnet Mask", "Gateway", "DNS Servers", "Lease", "Domain",
           "Relayed By", "Answered In"]
COL_SERVER, COL_VERDICT = 0, 1
DETAIL_COLUMNS = ["Option", "Name", "Value"]
FIREWALL_RULE = "NOMAD DHCP test"


class DhcpThread(StoppableThread):
    expected = pyqtSignal(str)
    found = pyqtSignal(object)  # dhcp.Offer
    finished_test = pyqtSignal(list, str, str)  # (offers, message, kind)

    def __init__(self, adapter, source, seconds, parent=None):
        super().__init__(parent)
        self.adapter, self.source, self.seconds = adapter, source, seconds

    def run(self):
        expected = current_dhcp_server(self.adapter.index) if self.adapter.dhcp else ""
        self.expected.emit(expected)
        try:
            offers = discover_servers(self.source, self.adapter.mac, self.seconds, should_stop=lambda: self.stopping,
                                      found=self.found.emit)
        except OSError as error:
            self.finished_test.emit([], str(error), "error")
            return
        kind, message = assess(offers, expected)
        self.finished_test.emit(offers, "Stopped. " + message if self.stopping else message, kind)


class DhcpTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.expected_server = ""
        self.init_ui()
        window.adapter_changed.connect(lambda _: self.update_adapter_label())
        window.snapshot_changed.connect(lambda _: self.update_adapter_label())
        self.update_adapter_label()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Ask the network for a DHCP offer and list every server that answers. A second server "
                       "usually means a rogue one, such as a home router plugged in the wrong way round, handing "
                       "out bad addresses. Only a request is sent: no address is taken and nothing on this "
                       "computer changes.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.adapter_label = QLabel()
        self.seconds_input = QSpinBox()
        self.seconds_input.setRange(2, 60)
        self.seconds_input.setValue(6)
        self.seconds_input.setButtonSymbols(QSpinBox.NoButtons)
        self.seconds_input.setToolTip("How long to wait for offers. Slow or distant (relayed) servers can take a few "
                                      "seconds.")
        form = QFormLayout()
        form.addRow("Adapter:", self.adapter_label)
        form.addRow("Listen for (s):", self.seconds_input)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Find DHCP Servers")
        self.stop_button = QPushButton("Stop")
        self.firewall_button = QPushButton("Open Firewall Port")
        self.firewall_button.setToolTip(f"Allow DHCP offers (UDP port {CLIENT_PORT}) in through Windows Firewall, if "
                                        "none arrive even though the network has a DHCP server.")
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        buttons.addWidget(self.firewall_button)
        layout.addLayout(buttons)

        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter servers by address (Ctrl+F)")
        self.filter_input.setClearButtonEnabled(True)
        self.filter_input.textChanged.connect(self.apply_filter)
        layout.addWidget(self.filter_input)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)

        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(0, 0, 0, 0)
        details_header = QHBoxLayout()
        self.details_label = QLabel("Offer details: select a server above to see every option it sent.")
        self.copy_button = QPushButton("Copy Details")
        self.copy_button.setToolTip("Copy the selected server's offer, with every option, as text.")
        details_header.addWidget(self.details_label, 1)
        details_header.addWidget(self.copy_button)
        details_layout.addLayout(details_header)
        self.details = QTableWidget(0, len(DETAIL_COLUMNS))
        self.details.setHorizontalHeaderLabels(DETAIL_COLUMNS)
        self.details.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.details.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.details.verticalHeader().setVisible(False)
        self.details.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.details)
        details_layout.addWidget(self.details, 1)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.table)
        splitter.addWidget(details)
        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.copy_button.clicked.connect(self.copy_details)

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        self.firewall_button.clicked.connect(self.open_firewall)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.filter_input.setFocus()
        self.filter_input.selectAll()

    def apply_filter(self):
        words = self.filter_input.text().lower().split()
        for row in range(self.table.rowCount()):
            address = self.table.item(row, COL_SERVER).text().lower()
            self.table.setRowHidden(row, not all(word in address for word in words))
        selected = self.table.selectionModel().selectedRows()
        if selected and self.table.isRowHidden(selected[0].row()):
            self.table.clearSelection()
        if not self.table.selectionModel().selectedRows():
            first = next((row for row in range(self.table.rowCount()) if not self.table.isRowHidden(row)), None)
            if first is not None:
                self.table.selectRow(first)

    def save_settings(self, settings):
        settings.setValue("dhcp/seconds", self.seconds_input.value())

    def restore_settings(self, settings):
        self.seconds_input.setValue(settings.value("dhcp/seconds", 6, int))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            release_thread(self.worker, 3000)

    # ----------------------------------------------------------------- Test

    def source_address(self, adapter):
        """The adapter's IPv4 address to send from: a leased one if it has one, else its 169.254 address."""
        if adapter is None or not adapter.ipv4:
            return None
        usable = [address for address in adapter.ipv4 if not address.ip.is_link_local]
        return str((usable or adapter.ipv4)[0].ip)

    def update_adapter_label(self):
        adapter = self.window.current_adapter()
        if adapter is None:
            self.adapter_label.setText("No adapter selected.")
        else:
            source = self.source_address(adapter)
            how = "DHCP" if adapter.dhcp else "static address"
            self.adapter_label.setText(f"{adapter.name} ({source or 'no IPv4 address'}, {how})")
        self.update_buttons()

    def start(self):
        if self.worker is not None:
            return
        adapter = self.window.current_adapter()
        source = self.source_address(adapter)
        if adapter is None or source is None:
            set_hint(self.status_label, "The selected adapter needs an IPv4 address (even an automatic 169.254 "
                                        "one) to send from.", "error")
            return
        if adapter.status != "Up":
            set_hint(self.status_label, f"{adapter.name} isn't connected.", "error")
            return
        self.table.setRowCount(0)
        self.details.setRowCount(0)
        self.expected_server = ""
        self.progress_bar.setRange(0, 0)
        set_hint(self.status_label, f"Asking for DHCP offers on {adapter.name}...", "info")
        log.info("Looking for DHCP servers from %s", source)
        self.worker = DhcpThread(adapter, source, self.seconds_input.value(), self)
        self.worker.expected.connect(self.on_expected)
        self.worker.found.connect(self.add_offer)
        self.worker.finished_test.connect(self.on_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.window.set_busy("dhcp", "Looking for DHCP servers")
        self.update_buttons()

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
            self.stop_button.setEnabled(False)

    def on_expected(self, server):
        self.expected_server = server
        for row in range(self.table.rowCount()):
            self.style_row(row)

    def add_offer(self, offer):
        row = self.table.rowCount()
        self.table.insertRow(row)
        via = offer.relay or (offer.sender if offer.sender != offer.server else "")
        values = [offer.server, "", offer.address, offer.subnet_mask, ", ".join(offer.routers), ", ".join(offer.dns),
                  offer.lease_text, offer.domain, via, f"{offer.rtt:.0f} ms"]
        for column, value in enumerate(values):
            self.table.setItem(row, column, SortableTableItem(value, data=offer))
        self.style_row(row)
        self.apply_filter()  # Include offers arriving while a filter is active.

    def selected_offer(self):
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), COL_SERVER).data_object if rows else None

    def show_details(self):
        offer = self.selected_offer()
        self.details.setRowCount(0)
        if offer is None:
            self.details_label.setText("Offer details: select a server above to see every option it sent.")
            self.update_buttons()
            return
        rows = offer.details()
        raw = dict(offer.options)
        self.details_label.setText(f"Offer details from {offer.server}: {len(offer.options)} options")
        self.details.setRowCount(len(rows))
        for row, (code, name, value) in enumerate(rows):
            cells = [(str(code), code if code != "" else -1), (name, name), (value, value)]
            for column, (text, sort_key) in enumerate(cells):
                item = SortableTableItem(text, sort_key)
                if column == 2:
                    item.setToolTip(f"{value}\n\nRaw: {raw[code].hex(' ')}" if code in raw else value)
                if code == "":
                    item.setForeground(QColor(COLORS["muted"]))
                self.details.setItem(row, column, item)
        self.update_buttons()

    def copy_details(self):
        offer = self.selected_offer()
        if offer is None:
            return
        lines = [f"DHCP offer from {offer.server}"]
        for code, name, value in offer.details():
            lines.append(f"  {f'{code:>3}' if code != '' else '   '}  {name}: {value}")
        QApplication.clipboard().setText("\n".join(lines) + "\n")
        self.window.show_status(f"Copied the offer from {offer.server} to the clipboard.", "info")

    def style_row(self, row):
        server = self.table.item(row, COL_SERVER).text()
        if not self.expected_server:
            verdict, color = ("Only server so far" if self.table.rowCount() == 1 else "Several servers answered",
                              COLORS["success"] if self.table.rowCount() == 1 else COLORS["error"])
        elif server == self.expected_server:
            verdict, color = "Expected (this adapter's lease)", COLORS["success"]
        else:
            verdict, color = "Unexpected: possible rogue", COLORS["error"]
        item = self.table.item(row, COL_VERDICT)
        item.setText(verdict)
        item.setForeground(QColor(color))

    def on_finished(self, offers, message, kind):
        for row in range(self.table.rowCount()):
            self.style_row(row)
        if self.expected_server and not any(offer.server == self.expected_server for offer in offers) and offers:
            message += f" ({self.expected_server}, where this adapter's lease came from, didn't answer.)"
        set_hint(self.status_label, message, kind)
        log.info(message)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(1)
        self.window.clear_busy("dhcp")
        self.update_buttons()

    def open_firewall(self):
        self.window.run_change(f"Opening UDP port {CLIENT_PORT} in Windows Firewall",
                               lambda: allow_inbound_port(FIREWALL_RULE, CLIENT_PORT),
                               on_success=lambda _: self.window.show_status(
                                   f"Windows Firewall now lets DHCP offers (UDP {CLIENT_PORT}) in."))

    def update_buttons(self):
        running = self.worker is not None
        self.start_button.setEnabled(not running and self.window.current_adapter() is not None)
        self.stop_button.setEnabled(running and not self.worker.stopping)
        self.copy_button.setEnabled(self.selected_offer() is not None)
