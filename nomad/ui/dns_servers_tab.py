"""DNS Servers page: compare how quickly DNS servers answer, and check forward/reverse DNS."""
import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, \
    QPushButton, QShortcut, QSpinBox, QTableWidget, QVBoxLayout, QWidget

from ..dnsclient import RCODE_MEANINGS, benchmark_server, forward_reverse
from ..lookup import HOSTNAME_PATTERN
from .common import ColumnFitter, SortableTableItem, StoppableThread, format_ms, release_thread, run_in_background, \
    set_hint, set_invalid
from .name_lookup import resolve_now
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

PUBLIC_DNS = [("1.1.1.1", "Cloudflare"), ("8.8.8.8", "Google"), ("9.9.9.9", "Quad9"),
              ("208.67.222.222", "OpenDNS")]
DEFAULT_TEST_NAMES = "example.com, microsoft.com, wikipedia.org"
DNS_COLUMNS = ["Server", "Source", "Average", "Median", "First Lookup", "Answered", "Result"]
COL_SERVER, COL_SOURCE, COL_AVERAGE, COL_MEDIAN, COL_FIRST, COL_ANSWERED, COL_RESULT = range(len(DNS_COLUMNS))
FR_COLUMNS = ["Address", "PTR Name", "Result"]
NO_ANSWER_SORT_KEY = 10 ** 9
PARALLEL_SERVERS = 8


class DnsBenchmarkThread(StoppableThread):
    result = pyqtSignal(object)  # ServerResult

    def __init__(self, servers, names, rounds, timeout, parent=None):
        super().__init__(parent)
        self.servers, self.names, self.rounds, self.timeout = servers, names, rounds, timeout

    def run(self):
        # Servers are tested side by side (each one's queries in turn), so dead servers don't hold up the rest
        with ThreadPoolExecutor(max_workers=PARALLEL_SERVERS) as pool:
            futures = [pool.submit(benchmark_server, server, self.names, self.rounds, self.timeout, label,
                                   lambda: self.stopping) for server, label in self.servers]
            for future in as_completed(futures):
                self.result.emit(future.result())


class DnsServersTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.dns_worker = None
        self.custom_servers = []
        self.removed_servers = set()  # Built-in servers taken off the list
        self.fr_server_chosen = False  # Keep the user's choice of server across refreshes
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.fill_servers())
        window.adapter_changed.connect(lambda _: self.fill_servers())
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Time how quickly each DNS server answers, asking it directly (Windows' DNS cache is "
                       "skipped). Tick the servers to compare. The first lookup of a name is usually slower, "
                       "because the server has to look it up itself.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        self.names_input = QLineEdit(DEFAULT_TEST_NAMES)
        self.names_input.setPlaceholderText("Names to look up, separated by commas")
        self.names_input.setToolTip("On a network without internet access, use names your own DNS server knows.")
        self.rounds_input = QSpinBox()
        self.rounds_input.setRange(1, 20)
        self.rounds_input.setValue(3)
        self.dns_timeout_input = QSpinBox()
        self.dns_timeout_input.setRange(200, 10000)
        self.dns_timeout_input.setSingleStep(100)
        self.dns_timeout_input.setValue(2000)
        for spin_box in (self.rounds_input, self.dns_timeout_input):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        add_row = QHBoxLayout()
        self.add_server_input = QLineEdit()
        self.add_server_input.setPlaceholderText("Another DNS server's IP address or name")
        self.add_server_button = QPushButton("Add Server")
        self.remove_server_button = QPushButton("Remove Selected")
        self.remove_server_button.setToolTip("Take the selected server off the list (Delete). Untick a server "
                                             "instead to skip it for now.")
        self.restore_servers_button = QPushButton("Restore Removed")
        self.restore_servers_button.setToolTip("Bring back the adapter, gateway and public servers you removed.")
        add_row.addWidget(self.add_server_input, 1)
        add_row.addWidget(self.add_server_button)
        add_row.addWidget(self.remove_server_button)
        add_row.addWidget(self.restore_servers_button)
        form = QFormLayout()
        form.addRow("Names:", self.names_input)
        form.addRow("Lookups of each name:", self.rounds_input)
        form.addRow("Timeout (ms):", self.dns_timeout_input)
        form.addRow("Add a server:", add_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.dns_start_button = accent_button("Test Servers")
        self.dns_stop_button = QPushButton("Stop")
        buttons.addWidget(self.dns_start_button)
        buttons.addWidget(self.dns_stop_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.dns_status = QLabel()
        self.dns_status.setWordWrap(True)
        layout.addWidget(self.dns_status)

        self.dns_table = QTableWidget(0, len(DNS_COLUMNS))
        self.dns_table.setHorizontalHeaderLabels(DNS_COLUMNS)
        self.dns_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.dns_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.dns_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.dns_table.verticalHeader().setVisible(False)
        self.dns_table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.dns_table)
        layout.addWidget(self.dns_table, 1)

        check_group = QGroupBox("Forward / reverse check")
        check_layout = QHBoxLayout(check_group)
        self.fr_name_input = QLineEdit()
        self.fr_name_input.setPlaceholderText("Host name, such as server.example.com")
        self.fr_server_combo = QComboBox()
        self.fr_server_combo.setToolTip("The DNS server to ask.")
        self.fr_button = QPushButton("Check")
        self.fr_button.setToolTip("Check that the name's addresses have PTR records pointing back to it. Mail "
                                  "servers and some logins need this to match.")
        check_layout.addWidget(self.fr_name_input, 1)
        check_layout.addWidget(QLabel("Server:"))
        check_layout.addWidget(self.fr_server_combo)
        check_layout.addWidget(self.fr_button)
        layout.addWidget(check_group)
        self.fr_status = QLabel()
        self.fr_status.setWordWrap(True)
        layout.addWidget(self.fr_status)
        self.fr_table = QTableWidget(0, len(FR_COLUMNS))
        self.fr_table.setHorizontalHeaderLabels(FR_COLUMNS)
        self.fr_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.fr_table.verticalHeader().setVisible(False)
        self.fr_table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.fr_table)
        self.fr_table.setMaximumHeight(150)
        layout.addWidget(self.fr_table)

        self.dns_start_button.clicked.connect(self.start_dns_test)
        self.dns_stop_button.clicked.connect(self.stop_dns_test)
        self.names_input.returnPressed.connect(self.start_dns_test)
        self.add_server_button.clicked.connect(self.add_server)
        self.add_server_input.returnPressed.connect(self.add_server)
        self.add_server_input.textChanged.connect(lambda: set_invalid(self.add_server_input, False))
        self.remove_server_button.clicked.connect(self.remove_server)
        self.restore_servers_button.clicked.connect(self.restore_removed_servers)
        delete_shortcut = QShortcut(QKeySequence.Delete, self.dns_table)
        delete_shortcut.setContext(Qt.WidgetShortcut)
        delete_shortcut.activated.connect(self.remove_server)
        self.dns_table.itemSelectionChanged.connect(self.update_buttons)
        self.fr_server_combo.activated.connect(lambda _: setattr(self, "fr_server_chosen", True))
        self.fr_button.clicked.connect(self.start_forward_reverse)
        self.fr_name_input.returnPressed.connect(self.start_forward_reverse)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.names_input.setFocus()
        self.names_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("services/names", self.names_input.text())
        settings.setValue("services/rounds", self.rounds_input.value())
        settings.setValue("services/dns_timeout", self.dns_timeout_input.value())
        settings.setValue("services/custom_servers", json.dumps(self.custom_servers))
        settings.setValue("services/removed_servers", json.dumps(sorted(self.removed_servers)))
        settings.setValue("services/unchecked", json.dumps(self.unchecked_servers()))
        settings.setValue("services/fr_name", self.fr_name_input.text())

    def restore_settings(self, settings):
        self.names_input.setText(settings.value("services/names", DEFAULT_TEST_NAMES, str))
        self.rounds_input.setValue(settings.value("services/rounds", 3, int))
        self.dns_timeout_input.setValue(settings.value("services/dns_timeout", 2000, int))
        try:
            self.custom_servers = [str(server) for server in
                                   json.loads(settings.value("services/custom_servers", "[]", str))]
            self.restored_unchecked = set(json.loads(settings.value("services/unchecked", "[]", str)))
            self.removed_servers = {str(server) for server in
                                    json.loads(settings.value("services/removed_servers", "[]", str))}
        except (ValueError, TypeError):
            self.custom_servers, self.restored_unchecked, self.removed_servers = [], set(), set()
        self.fr_name_input.setText(settings.value("services/fr_name", "", str))
        self.fill_servers()

    def shutdown(self):
        if self.dns_worker is not None:
            self.dns_worker.stop()
            release_thread(self.dns_worker, self.dns_timeout_input.value() + 3000)

    # ----------------------------------------------------------------- DNS servers

    def built_in_servers(self):
        """(server, source) for the adapter's DNS servers, its gateway and well-known public servers."""
        adapter = self.window.current_adapter()
        servers = []
        if adapter is not None:
            servers += [(server, "Adapter DNS") for server in adapter.dns4 + adapter.dns6]
            servers += [(gateway, "Gateway") for gateway in adapter.gateways4]
        return servers + [(server, f"Public ({name})") for server, name in PUBLIC_DNS]

    def candidate_servers(self):
        """The servers to list: built-in ones that haven't been removed, then added ones."""
        servers = [(server, source) for server, source in self.built_in_servers()
                   if server not in self.removed_servers]
        servers += [(server, "Added") for server in self.custom_servers]
        seen, unique = set(), []
        for server, source in servers:
            if server not in seen:
                seen.add(server)
                unique.append((server, source))
        return unique

    def unchecked_servers(self):
        return [self.dns_table.item(row, COL_SERVER).text() for row in range(self.dns_table.rowCount())
                if self.dns_table.item(row, COL_SERVER).checkState() != Qt.Checked]

    def fill_servers(self):
        if self.dns_worker is not None:
            return
        unchecked = set(self.unchecked_servers()) if self.dns_table.rowCount() else \
            getattr(self, "restored_unchecked", set())
        servers = self.candidate_servers()
        self.dns_table.setSortingEnabled(False)
        self.dns_table.setRowCount(len(servers))
        for row, (server, source) in enumerate(servers):
            item = SortableTableItem(server, server, server)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked if server in unchecked else Qt.Checked)
            self.dns_table.setItem(row, COL_SERVER, item)
            self.dns_table.setItem(row, COL_SOURCE, SortableTableItem(source, source))
            for column in range(COL_AVERAGE, len(DNS_COLUMNS)):
                self.dns_table.setItem(row, column, SortableTableItem("", NO_ANSWER_SORT_KEY))
        self.dns_table.setSortingEnabled(True)
        current = self.fr_server_combo.currentText()
        self.fr_server_combo.clear()
        self.fr_server_combo.addItems([server for server, _ in servers])
        index = self.fr_server_combo.findText(current) if self.fr_server_chosen else -1
        self.fr_server_combo.setCurrentIndex(max(index, 0))  # Otherwise the adapter's own DNS server
        self.update_buttons()

    def add_server(self):
        text = self.add_server_input.text().strip()
        try:
            found = resolve_now(text, window=self.window)
        except ValueError as error:
            set_invalid(self.add_server_input, True)
            set_hint(self.dns_status, str(error), "error")
            return
        server = found.address.partition("%")[0]
        if found.is_name:
            set_hint(self.dns_status, f"Added {found.note()}.", "info")
        if server in self.removed_servers:
            self.removed_servers.discard(server)  # Adding a removed built-in server brings it back
        elif server not in self.custom_servers and server not in [item for item, _ in self.candidate_servers()]:
            self.custom_servers.append(server)
        self.add_server_input.clear()
        self.fill_servers()

    def remove_server(self):
        """Take the selected server off the list: added ones are forgotten, built-in ones hidden."""
        rows = self.dns_table.selectionModel().selectedRows()
        if not rows or self.dns_worker is not None:
            return
        row = rows[0].row()
        server = self.dns_table.item(row, COL_SERVER).text()
        if server in self.custom_servers:
            self.custom_servers.remove(server)
        else:
            self.removed_servers.add(server)
        self.fill_servers()
        if self.dns_table.rowCount():  # Keep the selection nearby, so Delete can remove several in a row
            self.dns_table.selectRow(min(row, self.dns_table.rowCount() - 1))
        set_hint(self.dns_status, f"Removed {server}." + (" Restore Removed brings it back." if server in
                                                          self.removed_servers else ""), "info")

    def restore_removed_servers(self):
        count = len(self.removed_servers)
        self.removed_servers.clear()
        self.fill_servers()
        set_hint(self.dns_status, f"Restored {count} server{'' if count == 1 else 's'}.", "info")

    def row_for_server(self, server):
        return next((row for row in range(self.dns_table.rowCount())
                     if self.dns_table.item(row, COL_SERVER).text() == server), None)

    def start_dns_test(self):
        if self.dns_worker is not None:
            return
        names = [name.strip() for name in self.names_input.text().replace(";", ",").split(",") if name.strip()]
        bad = [name for name in names if not HOSTNAME_PATTERN.match(name)]
        if not names or bad:
            set_invalid(self.names_input, True)
            set_hint(self.dns_status, f"'{bad[0]}' is not a host name." if bad else "Enter one or more names to "
                                                                                     "look up.", "error")
            return
        set_invalid(self.names_input, False)
        servers = [(self.dns_table.item(row, COL_SERVER).text(), self.dns_table.item(row, COL_SOURCE).text())
                   for row in range(self.dns_table.rowCount())
                   if self.dns_table.item(row, COL_SERVER).checkState() == Qt.Checked]
        if not servers:
            set_hint(self.dns_status, "Tick at least one server to test.", "error")
            return
        for server, _ in servers:
            row = self.row_for_server(server)
            for column in range(COL_AVERAGE, len(DNS_COLUMNS)):
                self.dns_table.setItem(row, column, SortableTableItem("…" if column == COL_RESULT else "",
                                                                      NO_ANSWER_SORT_KEY))
        self.dns_done = 0
        self.dns_total = len(servers)
        set_hint(self.dns_status, f"Testing {len(servers)} server{'' if len(servers) == 1 else 's'}...", "info")
        self.dns_worker = DnsBenchmarkThread(servers, names, self.rounds_input.value(),
                                             self.dns_timeout_input.value(), self)
        self.dns_worker.result.connect(self.show_dns_result)
        self.dns_worker.finished.connect(self.on_dns_finished)
        self.dns_worker.start()
        self.window.set_busy("dns_test", "Testing DNS servers")
        self.update_buttons()

    def show_dns_result(self, result):
        self.dns_done += 1
        row = self.row_for_server(result.server)
        if row is None:
            return
        self.dns_table.setSortingEnabled(False)
        average = result.average
        cells = {COL_AVERAGE: (format_ms(average), NO_ANSWER_SORT_KEY if average is None else average),
                 COL_MEDIAN: (format_ms(result.median), NO_ANSWER_SORT_KEY if result.median is None else result.median),
                 COL_FIRST: (format_ms(result.first_rtt), result.first_rtt or NO_ANSWER_SORT_KEY),
                 COL_ANSWERED: (f"{result.answered} of {result.sent}", result.answered),
                 COL_RESULT: (result.status, result.status)}
        for column, (text, sort_key) in cells.items():
            item = SortableTableItem(text, sort_key)
            if column == COL_RESULT:
                color = COLORS["success"] if not result.failures else \
                    COLORS["warning"] if result.answered else COLORS["error"]
                item.setForeground(QColor(color))
                meanings = [f"{code}: {meaning}" for code, meaning in RCODE_MEANINGS.items()
                            if code in result.failures]
                if meanings:
                    item.setToolTip("\n".join(meanings))
            self.dns_table.setItem(row, column, item)
        self.dns_table.setSortingEnabled(True)
        set_hint(self.dns_status, f"Tested {self.dns_done} of {self.dns_total} servers...", "info")

    def stop_dns_test(self):
        if self.dns_worker is not None:
            self.dns_worker.stop()
            self.dns_stop_button.setEnabled(False)

    def on_dns_finished(self):
        stopped = self.dns_worker.stopping
        self.dns_worker.deleteLater()
        self.dns_worker = None
        self.window.clear_busy("dns_test")
        self.dns_table.sortByColumn(COL_AVERAGE, Qt.AscendingOrder)
        fastest = self.dns_table.item(0, COL_AVERAGE)
        if stopped:
            set_hint(self.dns_status, "Stopped.", "warning")
        elif fastest is not None and fastest.text():
            set_hint(self.dns_status, f"Done. Fastest: {self.dns_table.item(0, COL_SERVER).text()} "
                                      f"({fastest.text()} average).", "success")
        else:
            set_hint(self.dns_status, "Done. None of the servers answered.", "warning")
        self.update_buttons()

    # ----------------------------------------------------------------- Forward / reverse

    def start_forward_reverse(self):
        name, server = self.fr_name_input.text().strip(), self.fr_server_combo.currentText()
        if not name or not HOSTNAME_PATTERN.match(name):
            set_invalid(self.fr_name_input, True)
            set_hint(self.fr_status, "Enter a host name to check.", "error")
            return
        set_invalid(self.fr_name_input, False)
        if not server:
            set_hint(self.fr_status, "There's no DNS server to ask.", "error")
            return
        self.fr_button.setEnabled(False)
        self.fr_table.setRowCount(0)
        set_hint(self.fr_status, f"Checking {name} on {server}...", "info")
        run_in_background(lambda: forward_reverse(name, server, self.dns_timeout_input.value()),
                          lambda result: self.show_forward_reverse(name, result), self.forward_reverse_failed)

    def show_forward_reverse(self, name, result):
        self.fr_button.setEnabled(True)
        _, checks = result
        self.fr_table.setRowCount(len(checks))
        for row, check in enumerate(checks):
            status = "Matches" if check.matches else check.problem
            values = [check.address, ", ".join(check.ptr_names), status]
            for column, value in enumerate(values):
                item = SortableTableItem(value)
                if column == 2:
                    item.setForeground(QColor(COLORS["success"] if check.matches else COLORS["warning"]))
                self.fr_table.setItem(row, column, item)
        good = all(check.matches for check in checks)
        set_hint(self.fr_status, f"{name}: every address's PTR record points back to it." if good else
                 f"{name}: some addresses' PTR records don't point back to it.", "success" if good else "warning")

    def forward_reverse_failed(self, error):
        self.fr_button.setEnabled(True)
        set_hint(self.fr_status, str(error), "error")

    # ----------------------------------------------------------------- Buttons

    def update_buttons(self):
        dns_running = self.dns_worker is not None
        self.dns_start_button.setEnabled(not dns_running)
        self.dns_stop_button.setEnabled(dns_running and not self.dns_worker.stopping)
        rows = self.dns_table.selectionModel().selectedRows()
        selected = self.dns_table.item(rows[0].row(), COL_SERVER).text() if rows else None
        self.remove_server_button.setEnabled(not dns_running and selected is not None)
        built_in = {server for server, _ in self.built_in_servers()}
        self.restore_servers_button.setEnabled(not dns_running and bool(self.removed_servers & built_in))
        self.add_server_button.setEnabled(not dns_running)
