"""NetFlow page: who and what is using each router interface, from the flows Cisco routers send (Flexible NetFlow),
with the interface's live rate read over SNMP beside it.

Where the flows come from:
- The NOMAD Flow Collector service on this computer, when it runs (everyone using NOMAD here reads the same one: on a
  shared Remote Desktop server only one program can listen for flows), or
- a collector inside this NOMAD (Collect Here), listening while NOMAD is open.

The flows are about a minute behind (routers send a long flow every minute, as NetFlow Config sets them up), so the
live rate comes from the interface's SNMP counters every few seconds, with the Network Map's SNMP credentials.
"""
import collections
import logging
import re
import time

from PyQt5.QtCore import QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMenu, \
    QPushButton, QSizePolicy, QSpinBox, QSplitter, QTableWidget, QTabWidget, QVBoxLayout, QWidget

from ..flows import store
from ..flows.api import FlowSourceError, LocalSource, ServiceSource
from ..flows.collector import FLOW_PORT, FlowCollector, port_problem
from ..netmap.model import port_key, short_port
from ..system import allow_inbound_port, log_dir
from .common import ColumnFitter, SortableTableItem, StoppableThread, format_size, release_thread, \
    run_in_background, set_hint
from .table_filter import TableFilter
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

RANGES = [("Last 5 minutes", 300), ("Last 15 minutes", 900), ("Last hour", 3600), ("Last 6 hours", 6 * 3600),
          ("Last 24 hours", 86400), ("Last 7 days", 7 * 86400), ("Last 14 days", 14 * 86400)]
DIRECTIONS = [("In and out", store.BOTH), ("In (arriving on it)", store.IN), ("Out (leaving by it)", store.OUT)]
REFRESH_MS = 15000
SOURCE_CHECK_MS = 30000
LIVE_SECONDS = 5
LIVE_KEPT = 720  # An hour of live samples
FIREWALL_RULE = "NOMAD NetFlow"
EVERY_INTERFACE = -1
ROW_LIMIT = 25
IN_COLOR, OUT_COLOR = "#3b82f6", "#f59e0b"


def format_rate(bits_per_second):
    """Bits per second for display, such as "12.3 Mb/s"."""
    value = float(bits_per_second or 0)
    for unit in ("b/s", "kb/s", "Mb/s", "Gb/s"):
        if value < 1000 or unit == "Gb/s":
            return f"{value:.0f} {unit}" if unit == "b/s" else f"{value:.1f} {unit}"
        value /= 1000
    return ""


def nice_ceiling(value):
    """The axis top for value: 1, 2 or 5 times a power of ten."""
    if value <= 0:
        return 1.0
    power = 1.0
    while power * 10 <= value:
        power *= 10
    while power > value:
        power /= 10
    for step in (1, 2, 5, 10):
        if power * step >= value:
            return power * step
    return power * 10


def flows_db_path():
    return log_dir() / "flows.db"


def service_state():
    """The Flow Collector service's state as Windows has it ("Not installed", "Stopped", "Running"...), or "" when
    it can't be asked (then the service's API is asked instead)."""
    try:
        from ..flows.service import status
        return status()
    except Exception:
        return ""


# --------------------------------------------------------------------- The graph


class RateGraph(QWidget):
    """An interface's rate in and out: a minute at a time from the flows (filled), and every few seconds from SNMP
    (lines), over the range chosen."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.minutes = []  # [(start, in b/s, out b/s)] from the flows
        self.live = []  # [(time, in b/s, out b/s)] from SNMP
        self.start, self.end = time.time() - 3600, time.time()
        self.note = ""
        self.setMinimumHeight(170)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_data(self, minutes, live, start, end, note=""):
        self.minutes, self.live, self.start, self.end, self.note = list(minutes), list(live), start, end, note
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(COLORS["input"]))
        metrics = painter.fontMetrics()
        left = metrics.horizontalAdvance("000.0 Mb/s") + 10
        plot = QRectF(left, 8, max(1, self.width() - left - 12), max(1, self.height() - metrics.height() - 22))
        visible_live = [item for item in self.live if item[0] >= self.start]
        peak = max([max(item[1], item[2]) for item in self.minutes] + [max(item[1], item[2]) for item in visible_live]
                   + [0])
        top = nice_ceiling(peak * 1.1)
        grid = QPen(QColor(COLORS["border"]), 1)
        for step in range(5):
            y = plot.top() + plot.height() * step / 4
            painter.setPen(grid)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(QRectF(0, y - 10, left - 6, 20), Qt.AlignRight | Qt.AlignVCenter,
                             format_rate(top * (4 - step) / 4))
        span = max(1.0, self.end - self.start)

        def x_of(when):
            return plot.left() + (when - self.start) / span * plot.width()

        def y_of(rate):
            return plot.bottom() - max(0.0, min(1.0, rate / top)) * plot.height()

        if not self.minutes and not visible_live:
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(plot, Qt.AlignCenter | Qt.TextWordWrap, self.note or "No flows in this time.")
        painter.setClipRect(plot)
        for index, color in ((1, IN_COLOR), (2, OUT_COLOR)):
            fill = QColor(color)
            fill.setAlpha(70)
            for item in self.minutes:
                x1, x2 = x_of(item[0]), x_of(item[0] + 60)
                rectangle = QRectF(x1, y_of(item[index]), max(1.0, x2 - x1), plot.bottom() - y_of(item[index]))
                painter.fillRect(rectangle, fill)
        for index, color in ((1, IN_COLOR), (2, OUT_COLOR)):
            if len(visible_live) < 2:
                continue
            path = QPainterPath(QPointF(x_of(visible_live[0][0]), y_of(visible_live[0][index])))
            for item in visible_live[1:]:
                path.lineTo(QPointF(x_of(item[0]), y_of(item[index])))
            painter.setPen(QPen(QColor(color), 2))
            painter.drawPath(path)
        painter.setClipping(False)
        painter.setPen(QColor(COLORS["muted"]))
        labels = QRectF(plot.left(), plot.bottom() + 4, plot.width(), metrics.height())
        stamp = "%H:%M" if span <= 86400 else "%d %b %H:%M"
        painter.drawText(labels, Qt.AlignLeft, time.strftime(stamp, time.localtime(self.start)))
        painter.drawText(labels, Qt.AlignRight, time.strftime(stamp, time.localtime(self.end)))
        legend = "■ In   ■ Out    filled: a minute at a time from the flows    lines: live, from SNMP"
        painter.drawText(labels, Qt.AlignHCenter, legend)
        width = metrics.horizontalAdvance(legend)
        x = plot.left() + (plot.width() - width) / 2
        painter.fillRect(QRectF(x, labels.top() + 3, metrics.horizontalAdvance("■"), metrics.height() - 6),
                         QColor(IN_COLOR))
        x2 = x + metrics.horizontalAdvance("■ In   ")
        painter.fillRect(QRectF(x2, labels.top() + 3, metrics.horizontalAdvance("■"), metrics.height() - 6),
                         QColor(OUT_COLOR))


# --------------------------------------------------------------------- Live rate over SNMP


class LiveRateThread(StoppableThread):
    """Reads one interface's octet counters every LIVE_SECONDS."""
    sampled = pyqtSignal(object)  # (time, in octets, out octets, speed Mb/s)
    failed = pyqtSignal(str)

    def __init__(self, address, credential, version, timeout, ifindex, client_factory=None, parent=None):
        super().__init__(parent)
        self.address, self.credential, self.version = address, credential, version
        self.timeout, self.ifindex = timeout, ifindex
        self.client_factory = client_factory

    def run(self):
        from ..netmap import counters
        from ..snmp import SnmpClient, SnmpError
        factory = self.client_factory or SnmpClient
        try:
            client = factory(self.address, self.credential, self.version, timeout=self.timeout, retries=0)
        except (SnmpError, OSError, ValueError) as error:
            self.failed.emit(str(error))
            return
        while not self.stopping:
            try:
                samples = counters.read_samples(client, {"port": self.ifindex}, clock=time.time)
            except (SnmpError, OSError, ValueError) as error:
                self.failed.emit(str(error))
                samples = {}
            sample = samples.get("port")
            if sample is not None:
                self.sampled.emit((sample.when, sample.in_octets, sample.out_octets, sample.speed))
            self.stop_event.wait(LIVE_SECONDS)


# --------------------------------------------------------------------- The page


def table(columns):
    widget = QTableWidget(0, len(columns))
    widget.setHorizontalHeaderLabels(columns)
    widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
    widget.setSelectionBehavior(QAbstractItemView.SelectRows)
    widget.verticalHeader().setVisible(False)
    widget.setWordWrap(False)
    widget.setContextMenuPolicy(Qt.CustomContextMenu)
    ColumnFitter(widget)
    return widget


KIND_COLUMNS = {
    store.SOURCES: ["Source", "Known As", "Bytes", "Share", "Average", "Packets", "Flows"],
    store.DESTINATIONS: ["Destination", "Known As", "Bytes", "Share", "Average", "Packets", "Flows"],
    store.APPLICATIONS: ["Application", "Bytes", "Share", "Average", "Packets", "Flows"],
    store.CONVERSATIONS: ["Source", "Destination", "Service", "Bytes", "Share", "Average", "Packets", "Flows"],
}
KIND_TITLES = {store.SOURCES: "Top Talkers", store.DESTINATIONS: "Top Destinations",
               store.APPLICATIONS: "Applications", store.CONVERSATIONS: "Conversations"}
FIND_COLUMNS = ["Ended", "Lasted", "Router", "In", "Out", "Source", "Port", "Destination", "Port", "Protocol",
                "Application", "Bytes", "Packets"]


class FlowsTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.source = None  # api.FlowSource the page reads, or None
        self.local = None  # collector.FlowCollector running in this NOMAD
        self.service_seen = False
        self.generation = 0  # Answers from an earlier question are dropped
        self.fetching = False
        self.exporters = []  # [{exporter, ...}] as last read
        self.interface_rows = []
        self.last_status = {}
        self.live = collections.deque(maxlen=LIVE_KEPT)  # (time, in b/s, out b/s) for the interface chosen
        self.live_where = None  # (exporter, ifindex) the live rate is of
        self.live_thread = None
        self.last_sample = None
        self.live_speed = 0
        self.live_note = ""
        self.wanted = None  # (addresses, port name) to choose once the routers are read (from the map)
        self.saved_exporter, self.saved_ifindex = "", None
        self.port, self.raw_hours, self.summary_days = FLOW_PORT, store.RAW_SECONDS / 3600, store.SUMMARY_DAYS
        self.collect_here_wanted = False
        self.init_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(REFRESH_MS)
        self.source_timer = QTimer(self)
        self.source_timer.timeout.connect(self.check_source)
        self.source_timer.start(SOURCE_CHECK_MS)
        self.update_buttons()

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Who and what is using each router interface, from the flows Cisco routers send (Flexible "
                       "NetFlow). Set a router up on the NetFlow Config page. The flows are about a minute behind; "
                       "the live rate comes from SNMP.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        source_row = QHBoxLayout()
        self.source_label = QLabel()
        self.source_label.setWordWrap(True)
        source_row.addWidget(self.source_label, 1)
        self.collect_button = accent_button("Collect Here")
        self.collect_button.setToolTip("Listen for flows in this NOMAD while it's open. On a computer several people "
                                       "use, install the Flow Collector service instead.")
        self.collect_button.clicked.connect(self.toggle_collect_here)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(FLOW_PORT)
        self.port_input.setButtonSymbols(QSpinBox.NoButtons)
        self.port_input.setToolTip("The UDP port to listen on here (routers send to 2055 as NetFlow Config sets "
                                   "them up)")
        self.firewall_button = QPushButton("Open Firewall Port")
        self.firewall_button.setToolTip("Let flows in through Windows Firewall on this port (needs administrator "
                                        "rights).")
        self.firewall_button.clicked.connect(self.open_firewall)
        self.service_button = QPushButton("Collector Service...")
        self.service_button.setToolTip("Install the NOMAD Flow Collector service: collects whether NOMAD is open or "
                                       "not, for everyone using NOMAD on this computer.")
        self.service_button.clicked.connect(self.show_service)
        self.config_button = QPushButton("Set Up a Router...")
        self.config_button.setToolTip("The NetFlow Config page, sending flows to this computer.")
        self.config_button.clicked.connect(self.set_up_router)
        source_row.addWidget(QLabel("UDP port:"))
        source_row.addWidget(self.port_input)
        for widget in (self.collect_button, self.firewall_button, self.service_button, self.config_button):
            source_row.addWidget(widget)
        layout.addLayout(source_row)

        pick_row = QHBoxLayout()
        self.exporter_combo = QComboBox()
        self.exporter_combo.setMinimumWidth(220)
        self.exporter_combo.setToolTip("The routers sending flows")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(260)
        self.direction_combo = QComboBox()
        for text, value in DIRECTIONS:
            self.direction_combo.addItem(text, value)
        self.range_combo = QComboBox()
        for text, seconds in RANGES:
            self.range_combo.addItem(text, seconds)
        self.range_combo.setCurrentIndex(1)
        self.refresh_button = QPushButton("Refresh")
        pick_row.addWidget(QLabel("Router:"))
        pick_row.addWidget(self.exporter_combo, 1)
        pick_row.addWidget(QLabel("Interface:"))
        pick_row.addWidget(self.interface_combo, 1)
        pick_row.addWidget(self.direction_combo)
        pick_row.addWidget(self.range_combo)
        pick_row.addWidget(self.refresh_button)
        layout.addLayout(pick_row)

        splitter = QSplitter(Qt.Vertical)
        top = QWidget()
        top_layout = QVBoxLayout(top)
        top_layout.setContentsMargins(0, 0, 0, 0)
        self.rate_label = QLabel()
        self.rate_label.setWordWrap(True)
        top_layout.addWidget(self.rate_label)
        self.total_label = QLabel()  # What the flows add up to in the time chosen, in and out
        self.total_label.setWordWrap(True)
        self.total_label.setToolTip("Added up from the flows the router sent in the time chosen. Average: over the "
                                    "whole time. Peak: the busiest minute.")
        top_layout.addWidget(self.total_label)
        self.graph = RateGraph()
        top_layout.addWidget(self.graph, 1)
        splitter.addWidget(top)

        self.tabs = QTabWidget()
        self.tables = {}
        self.table_filters = {}  # Table -> its column filters (and sorting), as on the map's tables
        self.table_tabs = {}  # Table -> (the page it's on in the tabs, the tab's name)
        for kind in (store.SOURCES, store.DESTINATIONS, store.APPLICATIONS, store.CONVERSATIONS):
            widget = table(KIND_COLUMNS[kind])
            widget.customContextMenuRequested.connect(self.show_table_menu)
            self.tables[kind] = widget
            self.tabs.addTab(widget, KIND_TITLES[kind])
            self.add_filter(widget, widget, KIND_TITLES[kind], len(KIND_COLUMNS[kind]) - 5, Qt.DescendingOrder)
        find_page = QWidget()
        find_layout = QVBoxLayout(find_page)
        find_row = QHBoxLayout()
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("An address or subnet, such as 10.1.2.30 or 10.1.2.0/24 (empty: every "
                                           "flow)")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.returnPressed.connect(self.find_flows)
        self.find_button = QPushButton("Find Flows")
        self.find_button.clicked.connect(self.find_flows)
        find_row.addWidget(self.find_input, 1)
        find_row.addWidget(self.find_button)
        find_layout.addLayout(find_row)
        self.find_label = QLabel("Each flow the routers sent in the last hours (kept 2 hours unless set otherwise), "
                                 "newest first, in the time chosen above.")
        self.find_label.setWordWrap(True)
        find_layout.addWidget(self.find_label)
        self.find_table = table(FIND_COLUMNS)
        self.find_table.customContextMenuRequested.connect(self.show_find_menu)
        find_layout.addWidget(self.find_table, 1)
        self.tabs.addTab(find_page, "Find Flows")
        self.add_filter(self.find_table, find_page, "Find Flows", 0, Qt.DescendingOrder)  # Newest first
        splitter.addWidget(self.tabs)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        self.exporter_combo.currentIndexChanged.connect(self.on_exporter_changed)
        self.interface_combo.currentIndexChanged.connect(self.on_choice_changed)
        self.direction_combo.currentIndexChanged.connect(self.on_choice_changed)
        self.range_combo.currentIndexChanged.connect(self.on_choice_changed)
        self.refresh_button.clicked.connect(self.refresh)

    def add_filter(self, widget, page, name, column, order):
        """Excel-style filters on the table's columns, as on the map's tables. Sorted by column until the user sorts
        it otherwise; filters and sorting are kept when the table is filled again."""
        table_filter = TableFilter(widget, self.on_filtered)
        table_filter.header.setSortIndicator(column, order)
        self.table_filters[widget] = table_filter
        self.table_tabs[widget] = (page, name)

    def on_filtered(self, shown, total):
        """"Top Talkers (3 of 25)" on each tab whose table is filtered."""
        for widget, table_filter in self.table_filters.items():
            page, name = self.table_tabs[widget]
            if table_filter.active:
                rows = widget.rowCount()
                name += f" ({sum(not widget.isRowHidden(row) for row in range(rows))} of {rows})"
            self.tabs.setTabText(self.tabs.indexOf(page), name)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.tabs.setCurrentIndex(self.tabs.count() - 1)
        self.find_input.setFocus()
        self.find_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("flows/port", self.port_input.value())
        settings.setValue("flows/range", self.range_combo.currentData())
        settings.setValue("flows/direction", self.direction_combo.currentData())
        settings.setValue("flows/exporter", self.exporter_combo.currentData() or self.saved_exporter)
        ifindex = self.interface_combo.currentData()
        settings.setValue("flows/ifindex", ifindex if ifindex is not None else -1)
        settings.setValue("flows/collect_here", self.local is not None)
        settings.setValue("flows/raw_hours", self.raw_hours)
        settings.setValue("flows/summary_days", self.summary_days)

    def restore_settings(self, settings):
        self.port_input.setValue(settings.value("flows/port", FLOW_PORT, int))
        index = self.range_combo.findData(settings.value("flows/range", 900, int))
        self.range_combo.setCurrentIndex(max(0, index))
        index = self.direction_combo.findData(settings.value("flows/direction", store.BOTH, str))
        self.direction_combo.setCurrentIndex(max(0, index))
        self.saved_exporter = settings.value("flows/exporter", "", str)
        ifindex = settings.value("flows/ifindex", -1, int)
        self.saved_ifindex = None if ifindex < 0 else ifindex
        self.raw_hours = settings.value("flows/raw_hours", store.RAW_SECONDS / 3600, float)
        self.summary_days = settings.value("flows/summary_days", store.SUMMARY_DAYS, int)
        self.collect_here_wanted = settings.value("flows/collect_here", False, bool)
        QTimer.singleShot(0, self.check_source)

    def shutdown(self):
        self.refresh_timer.stop()
        self.source_timer.stop()
        self.stop_live()
        if self.source is not None:
            self.source.close()
            self.source = None
        if self.local is not None:
            self.local.stop()
            self.local = None

    def showEvent(self, event):
        super().showEvent(event)
        if self.source is None:
            self.check_source()
        else:
            self.refresh()
        self.update_live()

    def hideEvent(self, event):
        super().hideEvent(event)
        self.update_live()

    # ----------------------------------------------------------------- Where the flows come from

    def check_source(self):
        """Use the service if it answers (unless collecting here); start collecting here if it was on last time."""
        if self.local is not None:
            return
        run_in_background(self.ask_service, self.on_service_answer, self.on_service_silent)

    @staticmethod
    def ask_service():
        """(the service, its status), or None when it isn't running (not an error: it's usually not installed).
        Windows' service manager is asked first: it answers at once, where connecting to a port nothing listens on
        takes Windows two seconds."""
        if service_state() in ("Not installed", "Stopped"):
            return None
        source = ServiceSource(timeout=2)
        try:
            return source, source.status()
        except FlowSourceError:
            return None

    def on_service_answer(self, answer):
        if answer is None:
            self.on_service_silent(None)
            return
        if self.local is not None:
            return
        source, status = answer
        first = not self.service_seen or self.source is None
        self.service_seen = True
        self.source = source
        self.last_status = status
        self.collect_here_wanted = False
        self.update_source_label()
        self.update_buttons()
        if first:
            self.refresh()

    def on_service_silent(self, _error):
        if self.local is not None:
            return
        was_service = isinstance(self.source, ServiceSource)
        self.service_seen = False
        if was_service:
            self.source = None
            self.clear_results("The Flow Collector service stopped answering.")
        if self.collect_here_wanted and self.local is None:
            self.collect_here_wanted = False
            self.start_collect_here(quiet=True)
            return
        self.update_source_label()
        self.update_buttons()

    def toggle_collect_here(self):
        if self.local is not None:
            self.stop_collect_here()
        else:
            self.start_collect_here()

    def start_collect_here(self, quiet=False):
        if isinstance(self.source, ServiceSource):
            set_hint(self.source_label, "The Flow Collector service collects on this computer already: its flows "
                                        "are shown here.", "info")
            return
        path = flows_db_path()
        port = self.port_input.value()
        local = FlowCollector(path, port, raw_seconds=self.raw_hours * 3600, summary_days=self.summary_days)
        try:
            local.start()
        except OSError as error:
            log.warning("Couldn't collect NetFlow here: %s", error)
            if not quiet:
                set_hint(self.source_label, port_problem(error, port), "error")
            return
        self.local = local
        self.source = LocalSource(local)
        log.info("Collecting NetFlow in NOMAD on UDP %s", port)
        self.update_source_label()
        self.update_buttons()
        self.refresh()

    def stop_collect_here(self):
        if self.local is None:
            return
        if self.source is not None:
            self.source.close()
        self.local.stop()
        self.local = None
        self.source = None
        self.update_buttons()
        self.clear_results("Stopped collecting here.")
        self.update_source_label()
        self.check_source()

    def update_source_label(self):
        status = self.last_status if isinstance(self.source, ServiceSource) else (
            self.local.status() if self.local is not None else {})
        if self.source is None:
            set_hint(self.source_label, "Not collecting flows. Click Collect Here to listen while NOMAD is open, or "
                                        "install the Flow Collector service (Collector Service...) so it collects "
                                        "all the time, for everyone using NOMAD on this computer.", "warning")
            return
        where = ("the NOMAD Flow Collector service on this computer" if isinstance(self.source, ServiceSource)
                 else "this NOMAD (only while it's open)")
        port = status.get("port", self.port_input.value())
        senders = status.get("exporters", {}) or {}
        text = f"Flows from {where}, listening on UDP {port}. "
        kind = "success"
        if not senders:
            text += ("Nothing received yet: set a router up to send flows to this computer (Set Up a Router...), "
                     "and let them in through Windows Firewall.")
            kind = "info"
        else:
            text += f"{len(senders)} router{'s' if len(senders) != 1 else ''} sending."
            notes = [f"{address}: {item['problem']}" for address, item in senders.items() if item.get("problem")]
            waiting = [address for address, item in senders.items() if item.get("waiting")]
            if waiting:
                notes.append(f"waiting for the templates of {', '.join(waiting)} (they come within a minute)")
            if status.get("dropped"):
                notes.append(f"{status['dropped']:,} packets dropped (more than this computer could read)")
            if status.get("error"):
                notes.append(status["error"])
            if notes:
                text += " " + "; ".join(notes) + "."
                kind = "warning"
        set_hint(self.source_label, text, kind)

    def update_buttons(self):
        service = isinstance(self.source, ServiceSource)
        self.collect_button.setText("Stop Collecting Here" if self.local is not None else "Collect Here")
        self.collect_button.setEnabled(not service)
        self.port_input.setEnabled(self.local is None and not service)
        self.find_button.setEnabled(self.source is not None)
        self.refresh_button.setEnabled(self.source is not None)

    def show_service(self):
        from .flow_service_dialog import FlowCollectorDialog  # Loads pywin32 only when it's needed
        FlowCollectorDialog(self.window, self).exec_()
        self.check_source()

    def set_up_router(self):
        show = getattr(self.window, "show_flow_config", None)
        if show is not None:
            show()

    def open_firewall(self):
        port = self.port_input.value()
        self.window.run_change(f"Opening UDP {port} in Windows Firewall",
                               lambda: allow_inbound_port(FIREWALL_RULE, port, ("UDP",)),
                               on_success=lambda _: self.window.show_status(
                                   f"Windows Firewall now lets flows in on UDP {port}."))

    # ----------------------------------------------------------------- Choosing

    def on_exporter_changed(self, _index=None):
        self.fill_interfaces([])
        self.on_choice_changed()

    def on_choice_changed(self, _index=None):
        ifindex = self.interface_combo.currentData()
        every = ifindex is None
        self.direction_combo.setEnabled(not every)
        self.direction_combo.setToolTip("With every interface, each flow counts once, as it came in." if every else
                                        "In: arriving on this interface. Out: leaving the router by it.")
        if self.exporter_combo.currentData():
            self.saved_exporter = self.exporter_combo.currentData()
        if self.interface_combo.count():
            self.saved_ifindex = ifindex
        self.update_live()
        self.refresh()

    def chosen(self):
        """(exporter, ifindex or None, direction, start, end)"""
        end = time.time()
        return (self.exporter_combo.currentData() or "", self.interface_combo.currentData(),
                self.direction_combo.currentData(), end - self.range_combo.currentData(), end)

    def device_label(self, address):
        """The Network Map's name for the device with this address, or ""."""
        network_map = getattr(getattr(self.window, "netmap_tab", None), "network_map", None)
        if network_map is None or not address:
            return ""
        for device in network_map.devices.values():
            if device.mgmt_ip == address or address in (device.addresses or []) or \
                    any(item and item[0] == address for item in device.interfaces_l3 or []):
                return device.label
        return ""

    def fill_exporters(self, exporters):
        self.exporters = exporters
        current = self.exporter_combo.currentData() or self.saved_exporter
        wanted = self.wanted_exporter(exporters)
        if wanted:
            current = wanted
        self.exporter_combo.blockSignals(True)
        self.exporter_combo.clear()
        for item in exporters:
            label = self.device_label(item["exporter"])
            self.exporter_combo.addItem(f"{label} ({item['exporter']})" if label else item["exporter"],
                                        item["exporter"])
        index = self.exporter_combo.findData(current)
        self.exporter_combo.setCurrentIndex(index if index >= 0 else (0 if exporters else -1))
        self.exporter_combo.blockSignals(False)

    def wanted_exporter(self, exporters):
        if self.wanted is None:
            return ""
        addresses, _ = self.wanted
        for item in exporters:
            if item["exporter"] in addresses:
                return item["exporter"]
        return ""

    def fill_interfaces(self, interfaces):
        self.interface_rows = interfaces
        current = self.interface_combo.currentData() if self.interface_combo.count() else self.saved_ifindex
        if self.wanted is not None and self.wanted_exporter(self.exporters) == self.exporter_combo.currentData():
            _, port = self.wanted
            match = [item["ifindex"] for item in interfaces if port and item["name"] and
                     port_key(item["name"]) == port_key(port)]
            if match:
                current = match[0]
            if interfaces:
                self.wanted = None
        self.interface_combo.blockSignals(True)
        self.interface_combo.clear()
        self.interface_combo.addItem("Every interface", None)
        for item in interfaces:
            name = short_port(item["name"]) if item["name"] else f"ifIndex {item['ifindex']}"
            description = item["description"]
            if description and item["name"] and same_interface(description, item["name"]):
                description = ""  # IOS sends the long name as the description
            text = name + (f" - {description}" if description else "")
            if item["name"]:
                text += f"  (ifIndex {item['ifindex']})"
            self.interface_combo.addItem(text, item["ifindex"])
        index = self.interface_combo.findData(current) if current is not None else 0
        self.interface_combo.setCurrentIndex(max(0, index))
        self.interface_combo.blockSignals(False)
        self.direction_combo.setEnabled(self.interface_combo.currentData() is not None)

    def show_flows_for(self, addresses, port=""):
        """From the Network Map: the router with one of addresses, on its port (a short or long name)."""
        self.wanted = (set(addresses), port)
        if self.exporters:
            self.fill_exporters(self.exporters)
            self.on_exporter_changed()
        if self.source is None:
            self.check_source()
        self.tabs.setCurrentIndex(0)

    # ----------------------------------------------------------------- Asking the source

    def refresh(self):
        if self.source is None or self.fetching or not self.isVisible():
            if self.local is not None:
                self.update_source_label()
            return
        self.generation += 1
        self.fetching = True
        source, chosen, generation = self.source, self.chosen(), self.generation
        selected_exporter = chosen[0]

        def fetch():
            answer = {"generation": generation, "status": source.status(), "exporters": source.exporters()}
            exporter = selected_exporter
            if not exporter and answer["exporters"]:
                exporter = answer["exporters"][0]["exporter"]
            answer["exporter"] = exporter
            answer["interfaces"] = source.interfaces(exporter) if exporter else []
            if exporter:
                _, ifindex, direction, start, end = chosen
                answer["chosen"] = (exporter, ifindex, direction, start, end)
                answer["tops"] = {kind: source.top(exporter, ifindex, direction, kind, start, end, ROW_LIMIT)
                                  for kind in store.KINDS}
                answer["series"] = source.series(exporter, ifindex, start, end)
            return answer

        run_in_background(fetch, self.on_fetched, self.on_fetch_failed)

    def on_fetch_failed(self, error):
        self.fetching = False
        if isinstance(error, FlowSourceError) and isinstance(self.source, ServiceSource):
            self.on_service_silent(error)
            return
        log.warning("NetFlow page: %s", error)
        set_hint(self.total_label, f"Couldn't read the flows: {error}", "error")

    def on_fetched(self, answer):
        self.fetching = False
        if answer["generation"] != self.generation or self.source is None:
            return
        self.last_status = answer["status"]
        self.update_source_label()
        self.fill_exporters(answer["exporters"])
        if answer["exporter"] == self.exporter_combo.currentData():
            names_before = [(item["ifindex"], item["name"]) for item in self.interface_rows]
            names_now = [(item["ifindex"], item["name"]) for item in answer["interfaces"]]
            if names_before != names_now or self.wanted is not None:
                self.fill_interfaces(answer["interfaces"])
        if "tops" not in answer:
            return  # No router has sent flows yet
        if answer["chosen"][:3] != self.chosen()[:3]:  # Asked about another router or interface than now chosen
            self.update_live()
            QTimer.singleShot(0, self.refresh)
            return
        self.show_results(answer)

    def clear_results(self, note=""):
        for widget in self.tables.values():
            widget.setRowCount(0)
            self.table_filters[widget].apply()
        self.graph.set_data([], self.live_points(), *self.chosen()[3:], note=note)
        self.total_label.setText(note)

    # ----------------------------------------------------------------- Showing

    def show_results(self, answer):
        exporter, ifindex, direction, start, end = answer["chosen"]
        seconds = max(1.0, end - start)
        for kind, top in answer["tops"].items():
            self.fill_table(kind, top, seconds)
        minutes = [(row[0], row[1] * 8 / 60, row[2] * 8 / 60) for row in answer["series"]]
        note = "No flows from this router in this time." if not minutes else ""
        self.graph.set_data(minutes, self.live_points(), start, end, note)
        self.show_totals(answer["series"], answer["tops"][store.SOURCES]["total"], ifindex, direction, seconds)
        self.update_rate_label()

    def show_totals(self, series, total, ifindex, direction, seconds):
        """In and out side by side (bytes, average and busiest minute, from the graph's minutes), then the flows in
        the tables (which follow the direction chosen)."""
        in_bytes = sum(row[1] for row in series)
        out_bytes = sum(row[2] for row in series) if ifindex is not None else 0
        if not in_bytes and not out_bytes and not total[0]:
            set_hint(self.total_label, "No flows in this time" + (
                " on this interface (is the monitor on it? NetFlow Config puts it on input)." if ifindex is not None
                else "."), "info")
            return

        def part(title, color, octets, column):
            peak = max((row[column] for row in series), default=0) * 8 / 60
            return (f'<span style="color: {color};">■</span> <b>{title}</b> {format_size(octets)}'
                    f" &nbsp;·&nbsp; average {format_rate(octets * 8 / seconds)}"
                    f" &nbsp;·&nbsp; peak {format_rate(peak)}")

        parts = [part("In", IN_COLOR, in_bytes, 1), part("Out", OUT_COLOR, out_bytes, 2)] if ifindex is not None \
            else [part("Through the router", IN_COLOR, in_bytes, 1)]
        flows = f"{total[2]:,} flow{'' if total[2] == 1 else 's'}" + (
            {store.IN: " arriving", store.OUT: " leaving"}.get(direction, "") if ifindex is not None else "")
        parts.append(f"{flows} over the {self.range_combo.currentText().lower()}")
        set_hint(self.total_label, " &nbsp;&nbsp;&nbsp; ".join(parts), "info")

    def fill_table(self, kind, top, seconds):
        widget = self.tables[kind]
        widget.setSortingEnabled(False)
        total = top["total"][0] or 1
        rows = [(row[0], row[1], row[2], row[3]) for row in top["rows"]]
        if top["other"][0]:
            rows.append((None, *top["other"]))
        widget.setRowCount(len(rows))
        for number, (key, octets, packets, flows) in enumerate(rows):
            if kind == store.CONVERSATIONS:
                if key is None:
                    first = ["Other conversations", "", ""]
                else:
                    src, dst, proto, port = store.split_conversation(key)
                    service = store.port_application(proto, port) if proto in (store.TCP, store.UDP) else \
                        store.protocol_name(proto)
                    first = [src, dst, service]
            elif kind == store.APPLICATIONS:
                first = [key if key is not None else "Other applications"]
            else:
                first = [key, self.device_label(key)] if key is not None else ["Other addresses", ""]
            numbers = [(format_size(octets), octets), (f"{octets * 100 / total:.1f}%", octets),
                       (format_rate(octets * 8 / seconds), octets), (f"{packets:,}", packets), (f"{flows:,}", flows)]
            cells = [(text, None) for text in first] + numbers
            for column, (text, sort_key) in enumerate(cells):
                item = SortableTableItem(text, sort_key=sort_key if sort_key is not None else
                                         (address_sort(text) if column < len(first) else None), data=key)
                if key is None:
                    item.setForeground(QColor(COLORS["muted"]))
                    item.sort_key = -1 if sort_key is not None else item.sort_key
                if sort_key is not None:
                    item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                widget.setItem(number, column, item)
        widget.setSortingEnabled(True)  # Sorts as the header shows: by Bytes, or as the user sorted it
        self.table_filters[widget].apply()

    # ----------------------------------------------------------------- Live rate

    def live_points(self):
        exporter, ifindex = self.exporter_combo.currentData(), self.interface_combo.currentData()
        return list(self.live) if self.live_where == (exporter, ifindex) else []

    def update_live(self):
        """Read the chosen interface's counters over SNMP while the page shows (with the map's credentials)."""
        exporter, ifindex = self.exporter_combo.currentData(), self.interface_combo.currentData()
        where = (exporter, ifindex) if exporter and ifindex is not None and self.isVisible() else None
        if where == self.live_where and (where is None or self.live_thread is not None):
            return
        self.stop_live()
        if where != self.live_where:
            self.live.clear()
            self.last_sample = None
            self.live_speed = 0
        self.live_where = where
        self.live_note = ""
        if where is None:
            self.update_rate_label()
            return
        page = getattr(self.window, "netmap_tab", None)
        credential, version = page.snmp_access(exporter) if page is not None and hasattr(page, "snmp_access") \
            else (None, None)
        if credential is None:
            self.live_note = ("No live rate: NOMAD reads it over SNMP with the Network Map's credentials, and the "
                              "map has none (SNMP Credentials... on the Network Map page).")
            self.update_rate_label()
            return
        timeout = getattr(page, "timeout", 2000)
        self.live_thread = LiveRateThread(exporter, credential, version, timeout, ifindex, parent=self)
        self.live_thread.sampled.connect(self.on_live_sample)
        self.live_thread.failed.connect(self.on_live_failed)
        self.live_thread.start()
        self.update_rate_label()

    def stop_live(self):
        if self.live_thread is not None:
            self.live_thread.stop()
            release_thread(self.live_thread, 2000)
            self.live_thread = None

    def on_live_sample(self, sample):
        when, in_octets, out_octets, speed = sample
        before, self.last_sample = self.last_sample, sample
        self.live_speed = speed
        self.live_note = ""
        if before is not None and when > before[0] and in_octets >= before[1] and out_octets >= before[2]:
            seconds = when - before[0]
            self.live.append((when, (in_octets - before[1]) * 8 / seconds, (out_octets - before[2]) * 8 / seconds))
            exporter, ifindex, _, start, end = self.chosen()
            self.graph.set_data(self.graph.minutes, self.live_points(), start, end, self.graph.note)
        self.update_rate_label()

    def on_live_failed(self, message):
        self.live_note = f"No live rate: SNMP didn't answer ({message})."
        self.update_rate_label()

    def update_rate_label(self):
        if self.interface_combo.currentData() is None:
            set_hint(self.rate_label, "Every interface: what came in to the router, a minute at a time. Choose an "
                                      "interface for its rate in and out, live.", "info")
            return
        if self.live_note:
            set_hint(self.rate_label, self.live_note, "warning")
            return
        points = self.live_points()
        if not points:
            set_hint(self.rate_label, "Reading the interface's live rate over SNMP...", "info")
            return
        _, in_rate, out_rate = points[-1]
        text = f"Now: in {format_rate(in_rate)}, out {format_rate(out_rate)}"
        if self.live_speed:
            speed = self.live_speed * 1_000_000
            text += (f" of {format_rate(speed)} ({in_rate * 100 / speed:.0f}% in, {out_rate * 100 / speed:.0f}% "
                     "out)")
        set_hint(self.rate_label, text + f" (from SNMP every {LIVE_SECONDS} s).", "success")

    # ----------------------------------------------------------------- Finding flows

    def find_flows(self):
        if self.source is None:
            return
        text = self.find_input.text().strip()
        exporter, _, _, start, end = self.chosen()
        source = self.source
        self.find_button.setEnabled(False)
        set_hint(self.find_label, "Looking...", "info")
        run_in_background(lambda: source.flows(text, start, end + 60, "", 1000), self.on_found, self.on_find_failed)

    def on_find_failed(self, error):
        self.find_button.setEnabled(self.source is not None)
        set_hint(self.find_label, str(error), "error")

    def on_found(self, flows):
        self.find_button.setEnabled(self.source is not None)
        widget = self.find_table
        widget.setSortingEnabled(False)
        widget.setRowCount(len(flows))
        names = {}
        for row, item in enumerate(flows):
            exporter = item["exporter"]
            if exporter not in names:
                names[exporter] = self.device_label(exporter) or exporter
            lasted = max(0.0, item["end"] - item["start"])
            cells = [(time.strftime("%H:%M:%S", time.localtime(item["end"])), item["end"]),
                     (f"{lasted:.0f} s", lasted), (names[exporter], None),
                     (str(item["in_if"] or ""), item["in_if"]), (str(item["out_if"] or ""), item["out_if"]),
                     (item["src"], address_sort(item["src"])), (str(item["sport"] or ""), item["sport"]),
                     (item["dst"], address_sort(item["dst"])), (str(item["dport"] or ""), item["dport"]),
                     (store.protocol_name(item["proto"]), None), (item["app"], None),
                     (format_size(item["bytes"]), item["bytes"]), (f"{item['packets']:,}", item["packets"])]
            for column, (text, sort_key) in enumerate(cells):
                cell = SortableTableItem(text, sort_key=sort_key, data=item)
                widget.setItem(row, column, cell)
        widget.setSortingEnabled(True)
        self.table_filters[widget].apply()
        shown =f"{len(flows):,} flow{'s' if len(flows) != 1 else ''}"
        set_hint(self.find_label, (shown + " (the newest 1,000)" if len(flows) >= 1000 else shown) +
                 f" in the {self.range_combo.currentText().lower()} (raw flows are kept "
                 f"{self.kept_text()}).", "info")

    def kept_text(self):
        seconds = self.last_status.get("raw_seconds") if self.last_status else None
        if seconds is None and self.local is not None:
            seconds = self.local.raw_seconds
        hours = (seconds or store.RAW_SECONDS) / 3600
        return f"{hours:g} hour{'s' if hours != 1 else ''}"

    # ----------------------------------------------------------------- Right-click

    def show_table_menu(self, position):
        widget = self.sender()
        item = widget.itemAt(position) if widget is not None else None
        if item is None:
            return
        row = item.row()
        key = widget.item(row, 0).data_object
        menu = QMenu(self)
        actions = {}
        line = "\t".join(widget.item(row, column).text() for column in range(widget.columnCount()))
        actions[menu.addAction("Copy")] = lambda: QApplication.clipboard().setText(line)
        addresses = []
        if widget is self.tables[store.CONVERSATIONS] and key:
            src, dst, _, _ = store.split_conversation(key)
            addresses = [src, dst]
        elif widget in (self.tables[store.SOURCES], self.tables[store.DESTINATIONS]) and key:
            addresses = [key]
        for address in addresses:
            actions[menu.addAction(f"Find Flows to or from {address}")] = \
                lambda address=address: self.find_address(address)
        chosen = menu.exec_(widget.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def show_find_menu(self, position):
        item = self.find_table.itemAt(position)
        if item is None:
            return
        flow = self.find_table.item(item.row(), 0).data_object
        menu = QMenu(self)
        actions = {}
        line = "\t".join(self.find_table.item(item.row(), column).text()
                         for column in range(self.find_table.columnCount()))
        actions[menu.addAction("Copy")] = lambda: QApplication.clipboard().setText(line)
        for address in dict.fromkeys((flow["src"], flow["dst"])):
            actions[menu.addAction(f"Find Flows to or from {address}")] = \
                lambda address=address: self.find_address(address)
        chosen = menu.exec_(self.find_table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def find_address(self, address):
        self.find_input.setText(address)
        self.tabs.setCurrentIndex(self.tabs.count() - 1)
        self.find_flows()


def same_interface(long_name, short_name):
    """Whether IOS's long interface name is the short one written out: GigabitEthernet0/1 and Gi0/1, Loopback0 and
    Lo0, BDI96 and BD96."""
    if port_key(long_name) == port_key(short_name):
        return True
    long_name, short_name = long_name.strip().lower(), short_name.strip().lower()
    number, long_number = re.search(r"[\d/.:]+$", short_name), re.search(r"[\d/.:]+$", long_name)
    return bool(number and long_number and " " not in long_name and long_name[:2] == short_name[:2]
                and long_number.group(0) == number.group(0))


def address_sort(text):
    """A sort key that puts addresses in numeric order (names after them)."""
    import ipaddress
    try:
        address = ipaddress.ip_address(text)
        return (address.version, int(address))
    except (TypeError, ValueError):
        return (9, str(text or "").lower())
