"""Syslog page: receive log messages from switches, firewalls and access points, and filter or save them.

The messages come from one of two places:
- The NOMAD Syslog Collector service on this computer, when it runs: it keeps every message (90 days by default),
  so the page shows the latest as they come and can search everything kept (Search Kept).
- This NOMAD listening on the port itself (Start Listening), only while it's open.
"""
import collections
import itertools
import logging
import os
import threading
import time

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, \
    QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QSpinBox, QTableWidget, QVBoxLayout, QWidget

from ..syslog import SEVERITIES, SYSLOG_PORT, format_line, hub
from ..syslogs.api import SyslogServiceSource, SyslogSourceError
from ..syslogs.feed import ServiceFeed
from ..system import allow_inbound_port
from .common import ColumnFitter, SortableTableItem, fitting_held, run_in_background, set_hint
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

COLUMNS = ["Time", "From", "Severity", "Facility", "Host", "App", "Message"]
COL_MESSAGE = COLUMNS.index("Message")
MAX_MESSAGES = 20000  # Older messages are dropped from the list (the log file, if on, keeps everything)
FLUSH_MILLISECONDS = 250
FIREWALL_RULE = "NOMAD syslog"
BACKLOG = 2000  # Kept messages shown at once when the page starts reading the Syslog Collector service
HISTORY_LIMIT = 5000  # Most kept messages one search shows
SINCE_CHOICES = [("Last hour", 3600), ("Last 24 hours", 86400), ("Last 7 days", 7 * 86400),
                 ("Last 30 days", 30 * 86400), ("Everything kept", 0)]
SEVERITY_COLORS = {0: COLORS["error"], 1: COLORS["error"], 2: COLORS["error"], 3: COLORS["error"],
                   4: COLORS["warning"], 7: COLORS["muted"]}


def service_state():
    """The Syslog Collector service's state as Windows has it ("Not installed", "Stopped", "Running"...), or "" when
    it can't be asked (then the service's API is asked instead)."""
    try:
        from ..syslogs.service import status
        return status()
    except Exception:
        return ""


class SyslogTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.receiver = None
        self.messages = collections.deque(maxlen=MAX_MESSAGES)
        self.incoming = collections.deque()  # Filled by the receiver's threads, emptied by the timer
        self.incoming_lock = threading.Lock()
        self.total_received = 0
        self.log_file = None
        self.feed = None  # Reading the Syslog Collector service (a ServiceFeed)
        self.service_source = None
        self.service_status = {}
        self.feed_problem = self.shown_problem = ""  # Set by the feed's thread, shown by the timer
        self.history = None  # Kept messages found by Search Kept, while they're shown
        self.searching = False
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.flush)
        window.snapshot_changed.connect(lambda _: self.fill_addresses())
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Receive syslog messages from network devices. Point the device's logging at this computer's "
                       "address (for example, \"logging host 10.0.0.5\" on Cisco). To keep every message all the "
                       "time, whether NOMAD is open or not, install the Syslog Collector service.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        listen_row = QHBoxLayout()
        self.address_combo = QComboBox()
        self.address_combo.setToolTip("Which of this computer's addresses to listen on.")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(SYSLOG_PORT)
        self.port_input.setButtonSymbols(QSpinBox.NoButtons)
        self.tcp_check = QCheckBox("Also TCP")
        self.tcp_check.setToolTip("Also accept syslog over TCP on the same port (most devices use UDP).")
        listen_row.addWidget(self.address_combo, 1)
        listen_row.addWidget(QLabel("Port:"))
        listen_row.addWidget(self.port_input)
        listen_row.addWidget(self.tcp_check)

        file_row = QHBoxLayout()
        self.file_check = QCheckBox("Also write to:")
        self.file_input = QLineEdit(os.path.join(os.path.expanduser("~"), "Documents", "NOMAD syslog.log"))
        self.file_browse = QPushButton("Browse...")
        file_row.addWidget(self.file_check)
        file_row.addWidget(self.file_input, 1)
        file_row.addWidget(self.file_browse)

        form = QFormLayout()
        form.addRow("Listen on:", listen_row)
        form.addRow("Log file:", file_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Listening")
        self.stop_button = QPushButton("Stop")
        self.firewall_button = QPushButton("Open Firewall Port")
        self.firewall_button.setToolTip("Allow syslog messages in through Windows Firewall on this port.")
        buttons.addWidget(self.start_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        buttons.addWidget(self.firewall_button)
        self.service_button = QPushButton("Collector Service...")
        self.service_button.setToolTip("Install the NOMAD Syslog Collector service: keeps every message whether NOMAD "
                                       "is open or not, for everyone using NOMAD on this computer.")
        buttons.addWidget(self.service_button)
        layout.addLayout(buttons)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        view_row = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter by address, host, app or text... (Ctrl+F)")
        self.filter_input.setClearButtonEnabled(True)
        self.severity_combo = QComboBox()
        for index, name in enumerate(SEVERITIES):
            self.severity_combo.addItem(f"{name} and worse" if index < len(SEVERITIES) - 1 else "Everything", index)
        self.severity_combo.setCurrentIndex(len(SEVERITIES) - 1)
        self.follow_check = QCheckBox("Follow new messages")
        self.follow_check.setChecked(True)
        self.clear_button = QPushButton("Clear")
        self.save_button = QPushButton("Save...")
        self.since_combo = QComboBox()
        for text, seconds in SINCE_CHOICES:
            self.since_combo.addItem(text, seconds)
        self.since_combo.setCurrentIndex(1)
        self.since_combo.setToolTip("How far back Search Kept looks.")
        self.search_button = QPushButton("Search Kept")
        self.search_button.setToolTip("Search every message the Syslog Collector service kept for the filter's "
                                      "words, at the severity chosen (the newest 5,000 found are shown).")
        view_row.addWidget(self.filter_input, 1)
        view_row.addWidget(self.severity_combo)
        view_row.addWidget(self.since_combo)
        view_row.addWidget(self.search_button)
        view_row.addWidget(self.follow_check)
        view_row.addWidget(self.clear_button)
        view_row.addWidget(self.save_button)
        layout.addLayout(view_row)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        ColumnFitter(self.table, stretch=COL_MESSAGE)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        layout.addWidget(self.table, 1)
        self.count_label = QLabel()
        layout.addWidget(self.count_label)

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        self.firewall_button.clicked.connect(self.open_firewall)
        self.service_button.clicked.connect(self.show_service)
        self.search_button.clicked.connect(self.toggle_search)
        self.filter_input.returnPressed.connect(self.search_on_enter)
        self.file_browse.clicked.connect(self.browse_log_file)
        self.filter_input.textChanged.connect(self.refill)
        self.severity_combo.currentIndexChanged.connect(self.refill)
        self.clear_button.clicked.connect(self.clear)
        self.save_button.clicked.connect(self.save)
        self.table.customContextMenuRequested.connect(self.show_context_menu)
        self.fill_addresses()

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        """Ctrl+F on this page."""
        self.filter_input.setFocus()
        self.filter_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("syslog/address", self.address_combo.currentData())
        settings.setValue("syslog/port", self.port_input.value())
        settings.setValue("syslog/tcp", self.tcp_check.isChecked())
        settings.setValue("syslog/write_file", self.file_check.isChecked())
        settings.setValue("syslog/file", self.file_input.text())
        settings.setValue("syslog/severity", self.severity_combo.currentData())

    def restore_settings(self, settings):
        self.saved_address = settings.value("syslog/address", "0.0.0.0", str)
        self.fill_addresses()
        self.port_input.setValue(settings.value("syslog/port", SYSLOG_PORT, int))
        self.tcp_check.setChecked(settings.value("syslog/tcp", False, bool))
        self.file_check.setChecked(settings.value("syslog/write_file", False, bool))
        self.file_input.setText(settings.value("syslog/file", self.file_input.text(), str))
        index = self.severity_combo.findData(settings.value("syslog/severity", len(SEVERITIES) - 1, int))
        self.severity_combo.setCurrentIndex(max(index, 0))

    def shutdown(self):
        self.stop()
        self.stop_feed()

    def showEvent(self, event):
        super().showEvent(event)
        if self.feed is None and self.receiver is None:
            self.check_source()

    # ----------------------------------------------------------------- The Syslog Collector service

    def check_source(self):
        """Read the Syslog Collector service if it runs here (unless this NOMAD listens itself)."""
        if self.feed is not None or self.receiver is not None:
            return
        run_in_background(self.ask_service, self.on_service_answer)

    @staticmethod
    def ask_service():
        """(the service, its status), or None when it isn't running (not an error: it's usually not installed).
        Windows' service manager is asked first: it answers at once, where connecting to a port nothing listens on
        takes Windows two seconds."""
        if service_state() in ("Not installed", "Stopped"):
            return None
        source = SyslogServiceSource(timeout=2)
        try:
            return source, source.status()
        except SyslogSourceError:
            return None

    def on_service_answer(self, answer):
        if answer is None or self.feed is not None or self.receiver is not None:
            return
        self.use_service(*answer)

    def use_service(self, source, status, feed_factory=ServiceFeed):
        self.service_source, self.service_status = source, status
        self.messages.clear()
        self.history = None
        self.table.setRowCount(0)
        self.feed_problem = self.shown_problem = ""
        self.feed = feed_factory(self.on_message, backlog=BACKLOG, source=SyslogServiceSource(source.port),
                                 on_problem=self.on_feed_problem)
        self.feed.start()
        self.timer.start(FLUSH_MILLISECONDS)
        log.info("Syslog page reading the Syslog Collector service")
        self.update_service_label()
        self.update_count()

    def stop_feed(self):
        if self.feed is None:
            return
        self.feed.stop()
        self.feed = None
        self.service_source = None
        self.timer.stop()

    def on_feed_problem(self, text):
        """From the feed's thread: shown by the timer."""
        self.feed_problem = text

    def update_service_label(self):
        status = self.service_status
        port = status.get("port", SYSLOG_PORT)
        protocols = "UDP and TCP" if status.get("tcp") else "UDP"
        senders = len(status.get("senders") or {})
        text = (f"Messages from the NOMAD Syslog Collector service on this computer, listening on port {port} "
                f"({protocols}) and keeping them {status.get('keep_days', 90)} days. ")
        kind = "success"
        if self.feed_problem:
            text = f"{self.feed_problem} Showing what came before it stopped answering."
            kind = "warning"
        elif status.get("error"):
            text += status["error"]
            kind = "warning"
        elif senders:
            text += f"{senders} device{'s' if senders != 1 else ''} sent messages since it started."
        else:
            text += "Nothing received since it started: point the devices' logging at this computer."
            kind = "info"
        set_hint(self.status_label, text, kind)

    def show_service(self):
        from .syslog_service_dialog import SyslogCollectorDialog  # Loads pywin32 only when it's needed
        SyslogCollectorDialog(self.window, self).exec_()
        self.service_changed()

    def service_changed(self):
        """The service was set up, started, stopped or removed from this NOMAD."""
        if self.feed is not None and service_state() != "Running":
            self.stop_feed()
            self.history = None
            self.search_button.setText("Search Kept")
            set_hint(self.status_label, "The Syslog Collector service isn't running. Click Start Listening to "
                                        "listen while NOMAD is open.", "info")
            self.update_buttons()
        self.check_source()

    # ----------------------------------------------------------------- Searching what the service kept

    def search_on_enter(self):
        if self.feed is not None:
            self.search_kept()

    def toggle_search(self):
        if self.history is not None:
            self.back_to_live()
        else:
            self.search_kept()

    def search_kept(self):
        if self.service_source is None or self.searching:
            return
        seconds = self.since_combo.currentData()
        text, severity = self.filter_input.text().strip(), self.severity_combo.currentData()
        start = time.time() - seconds if seconds else None
        source = SyslogServiceSource(self.service_source.port, timeout=60)
        self.searching = True
        self.search_button.setText("Searching...")
        self.update_buttons()
        run_in_background(lambda: source.search(text, severity, start=start, limit=HISTORY_LIMIT),
                          self.on_history, self.on_history_failed)

    def on_history(self, messages):
        self.searching = False
        if self.feed is None:  # The service went away meanwhile
            return
        self.history = messages
        self.search_button.setText("Back to Live")
        self.refill()

    def on_history_failed(self, error):
        self.searching = False
        self.search_button.setText("Search Kept")
        set_hint(self.status_label, f"Couldn't search the kept messages: {error}", "error")
        self.update_buttons()

    def back_to_live(self):
        self.history = None
        self.search_button.setText("Search Kept")
        self.refill()

    # ----------------------------------------------------------------- Listening

    def fill_addresses(self):
        current = self.address_combo.currentData() or getattr(self, "saved_address", "0.0.0.0")
        self.address_combo.blockSignals(True)
        self.address_combo.clear()
        self.address_combo.addItem("All addresses (0.0.0.0)", "0.0.0.0")
        for adapter in self.window.snapshot.real_adapters():
            for address in adapter.ipv4:
                self.address_combo.addItem(f"{address.ip}  ({adapter.name})", str(address.ip))
        index = self.address_combo.findData(current)
        self.address_combo.setCurrentIndex(max(index, 0))
        self.address_combo.blockSignals(False)

    def start(self):
        if self.receiver is not None or self.feed is not None:
            return
        if self.file_check.isChecked():
            path = self.file_input.text().strip()
            try:
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                self.log_file = open(path, "a", encoding="utf-8")
            except OSError as error:
                set_hint(self.status_label, f"Couldn't open the log file {path}: {error}", "error")
                return
        port = self.port_input.value()
        try:  # Shared with the Map Watcher, if it's listening on the same port
            hub.subscribe(self.on_message, port, self.address_combo.currentData(), self.tcp_check.isChecked())
        except OSError as error:
            self.close_log_file()
            reason = "another program (probably another syslog server) is using it" \
                if getattr(error, "winerror", None) == 10048 else (error.strerror or str(error))
            set_hint(self.status_label, f"Couldn't listen on port {self.port_input.value()}: {reason}.", "error")
            return
        self.receiver = port  # The port subscribed to
        self.timer.start(FLUSH_MILLISECONDS)
        protocols = "UDP and TCP" if self.tcp_check.isChecked() else "UDP"
        where = self.address_combo.currentData()
        set_hint(self.status_label, f"Listening for syslog on {where} port {self.port_input.value()} ({protocols})."
                 + (f" Also writing to {self.file_input.text()}." if self.log_file else ""), "success")
        log.info("Syslog receiver listening on %s:%s", where, self.port_input.value())
        self.update_buttons()

    def stop(self):
        if self.receiver is None:
            return
        hub.unsubscribe(self.on_message, self.receiver)
        self.receiver = None
        self.flush()
        self.timer.stop()
        self.close_log_file()
        set_hint(self.status_label, f"Stopped. {self.total_received:,} messages received.", "info")
        self.update_buttons()

    def close_log_file(self):
        if self.log_file is not None:
            self.log_file.close()
            self.log_file = None

    def on_message(self, message):
        """Called from the receiver's threads."""
        with self.incoming_lock:
            self.incoming.append(message)

    def flush(self):
        if self.feed is not None and self.feed_problem != self.shown_problem:
            self.shown_problem = self.feed_problem
            self.update_service_label()
        with self.incoming_lock:
            batch = list(self.incoming)
            self.incoming.clear()
        if not batch:
            return
        self.total_received += len(batch)
        if self.history is not None:  # Search results are shown: the new ones wait for Back to Live
            self.messages.extend(batch)
            return
        if self.log_file is not None:
            try:
                self.log_file.write("".join(format_line(message) + "\n" for message in batch))
                self.log_file.flush()
            except OSError as error:
                set_hint(self.status_label, f"Couldn't write to the log file: {error}. Stopped writing to it.",
                         "warning")
                self.close_log_file()
        dropped = max(0, len(self.messages) + len(batch) - MAX_MESSAGES)
        if dropped > len(self.messages):  # More came at once than are kept: start again from the newest
            self.messages.extend(batch)
            self.refill()
            return
        gone = list(itertools.islice(self.messages, dropped))
        self.messages.extend(batch)
        if gone:
            self.drop_rows(gone)  # The oldest fell off the end: their rows go, the rest stay
        shown = [message for message in batch if self.matches(message)]
        if shown:
            self.append_rows(shown)
        self.update_count()

    # ----------------------------------------------------------------- Table

    def matches(self, message):
        if message.severity > self.severity_combo.currentData():
            return False
        words = self.filter_input.text().lower().split()
        text = message.search_text()
        return all(word in text for word in words)

    def append_rows(self, messages):
        table = self.table
        at_bottom = table.verticalScrollBar().value() >= table.verticalScrollBar().maximum() - 2
        start = table.rowCount()
        with fitting_held(table):
            table.setRowCount(start + len(messages))
            for offset, message in enumerate(messages):
                cells = [message.received.strftime("%H:%M:%S"), message.source, message.severity_name,
                         message.facility, message.host, message.app, message.message]
                color = SEVERITY_COLORS.get(message.severity)
                for column, text in enumerate(cells):
                    item = SortableTableItem(text, data=message)
                    if color and column in (2, COL_MESSAGE):
                        item.setForeground(QColor(color))
                    if column == COL_MESSAGE:
                        item.setToolTip(message.raw)
                    table.setItem(start + offset, column, item)
        if self.follow_check.isChecked() and at_bottom:
            table.scrollToBottom()

    def drop_rows(self, gone):
        """Take the rows of messages no longer kept (the oldest, so at the top) off the table, instead of filling
        it again: 20,000 rows filled again for each new message froze the window."""
        gone = {id(message) for message in gone}
        table, count = self.table, 0
        while count < table.rowCount():
            item = table.item(count, 0)
            if item is None or id(getattr(item, "data_object", None)) not in gone:
                break
            count += 1
        if count:
            table.model().removeRows(0, count)

    def refill(self):
        self.table.setRowCount(0)
        messages = self.history if self.history is not None else self.messages
        self.append_rows([message for message in messages if self.matches(message)])
        self.update_count()

    def update_count(self):
        if self.history is not None:
            found, shown = len(self.history), self.table.rowCount()
            text = f"{shown:,} of {found:,} kept messages found shown" if shown != found \
                else f"{found:,} kept messages found"
            if found >= HISTORY_LIMIT:
                text += f" (the newest {HISTORY_LIMIT:,}: narrow the search to see older ones)"
            self.count_label.setText(text + ". Click Back to Live to see new messages again.")
            self.update_buttons()
            return
        shown, stored = self.table.rowCount(), len(self.messages)
        text = f"{shown:,} of {stored:,} messages shown" if shown != stored else f"{stored:,} messages"
        if self.total_received > stored:
            text += f" (only the latest {MAX_MESSAGES:,} are kept here)"
        self.count_label.setText(text)
        self.update_buttons()

    def clear(self):
        if self.history is not None:
            self.history = None
            self.search_button.setText("Search Kept")
        self.messages.clear()
        self.table.setRowCount(0)
        self.update_count()

    def show_context_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        message = item.data_object
        menu = QMenu(self)
        actions = {
            menu.addAction("Copy Message"): lambda: QApplication.clipboard().setText(format_line(message)),
            menu.addAction("Copy Raw Message"): lambda: QApplication.clipboard().setText(message.raw),
            menu.addAction(f"Show Only {message.source}"): lambda: self.filter_input.setText(message.source),
        }
        if self.feed is not None:
            actions[menu.addAction(f"Search Kept from {message.source}")] = lambda: self.search_source(message.source)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def search_source(self, address):
        self.filter_input.setText(address)
        self.history = None
        self.search_kept()

    # ----------------------------------------------------------------- Files and firewall

    def browse_log_file(self):
        path, _ = QFileDialog.getSaveFileName(self, "Log File", self.file_input.text(),
                                              "Log files (*.log *.txt);;All files (*)")
        if path:
            self.file_input.setText(path)

    def save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Messages", "syslog.log",
                                              "Log files (*.log *.txt);;All files (*)")
        if not path:
            return
        messages = [self.table.item(row, 0).data_object for row in range(self.table.rowCount())]
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write("".join(format_line(message) + "\n" for message in messages))
        except OSError as error:
            QMessageBox.critical(self, "Save Failed", f"Couldn't save {path}:\n\n{error}")
            return
        self.window.show_status(f"Saved {len(messages):,} messages to {path}.")

    def open_firewall(self):
        port = self.port_input.value()
        protocols = ("UDP", "TCP") if self.tcp_check.isChecked() else ("UDP",)
        self.window.run_change(f"Opening port {port} in Windows Firewall",
                               lambda: allow_inbound_port(FIREWALL_RULE, port, protocols),
                               on_success=lambda _: self.window.show_status(
                                   f"Windows Firewall now lets syslog in on port {port}."))

    def update_buttons(self):
        listening = self.receiver is not None
        service = self.feed is not None
        self.start_button.setEnabled(not listening and not service)
        self.start_button.setToolTip("The Syslog Collector service listens on this computer already: its messages "
                                     "are shown here." if service else "")
        self.stop_button.setEnabled(listening)
        for widget in (self.address_combo, self.port_input, self.tcp_check, self.file_check, self.file_input,
                       self.file_browse, self.firewall_button):
            widget.setEnabled(not listening and not service)
        self.save_button.setEnabled(self.table.rowCount() > 0)
        self.since_combo.setVisible(service)
        self.search_button.setVisible(service)
        self.search_button.setEnabled(service and not self.searching)
