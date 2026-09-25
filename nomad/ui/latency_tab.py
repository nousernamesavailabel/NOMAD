"""Latency tab: ping several targets continuously, with a gauge each, a shared graph and per-target stats."""
import json
import logging
import time

from PyQt5.QtCore import QTimer, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QIcon, QPixmap
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog, QGroupBox, \
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSpinBox, QSplitter, \
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..icmp import IcmpClient, resolve_host
from ..latency import DEFAULT_WINDOW_SECONDS, WINDOW_OPTIONS, CsvLog, LatencyTarget, autoscale, targets_from_dicts
from ..system import log_dir
from .common import StoppableThread, set_hint, set_invalid
from .latency_charts import GaugePanel, LatencyGauge, LatencyGraph, series_color
from .theme import COLORS, accent_button, monospace_font

log = logging.getLogger(__name__)

DEFAULTS = {"interval": 1.0, "timeout": 1000}
COLUMNS = ["On", "Name", "Host", "Last", "Avg", "Min", "Max", "Loss"]
COL_ON, COL_NAME, COL_HOST, COL_LAST = 0, 1, 2, 3
MAX_LIVE_LINES = 500
REFRESH_MILLISECONDS = 500


class LatencyThread(StoppableThread):
    """Pings one target every interval until stopped."""
    sample = pyqtSignal(object, float, object, object, str)  # (target, time, rtt ms or None, ttl, error)

    def __init__(self, target, interval, timeout, parent=None):
        super().__init__(parent)
        self.target, self.host, self.interval, self.timeout = target, target.host, interval, timeout

    def run(self):
        address, client = None, None
        try:
            while not self.stopping:
                started = time.monotonic()
                rtt, ttl, error = None, None, ""
                try:
                    if client is None:  # Resolved on first use, and retried while the name doesn't resolve
                        address, family = resolve_host(self.host)
                        client = IcmpClient(family)
                    reply = client.echo(address, timeout=self.timeout)
                    if reply.ok:
                        rtt, ttl = float(reply.rtt), reply.ttl
                    else:
                        error = reply.message.rstrip(".")
                except (OSError, ValueError) as problem:
                    error = str(problem).rstrip(".")
                if self.stopping:
                    break
                self.sample.emit(self.target, time.time(), rtt, ttl, error)
                self.stop_event.wait(max(0.0, self.interval - (time.monotonic() - started)))
        finally:
            if client is not None:
                client.close()


def swatch_icon(color):
    pixmap = QPixmap(10, 10)
    pixmap.fill(color)
    return QIcon(pixmap)


class LatencyTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.targets = targets_from_dicts(None)
        self.workers = {}  # id(target) -> LatencyThread
        self.gauges = {}  # id(target) -> LatencyGauge
        self.monitoring = False
        self.csv_log = None
        self.dirty = False
        self.init_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.on_refresh_timer)
        self.refresh_timer.start(REFRESH_MILLISECONDS)
        window.adapter_changed.connect(lambda _: self.update_gateway_button())
        window.snapshot_changed.connect(lambda _: self.update_gateway_button())
        self.rebuild_targets()
        self.update_buttons()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        layout = QVBoxLayout(self)

        controls = QHBoxLayout()
        self.start_button = accent_button("Start")
        self.stop_button = QPushButton("Stop")
        self.reset_button = QPushButton("Reset")
        self.reset_button.setToolTip("Stop and clear all history.")
        for button in (self.start_button, self.stop_button, self.reset_button):
            controls.addWidget(button)
        controls.addSpacing(12)
        controls.addWidget(QLabel("Interval (s):"))
        self.interval_input = QDoubleSpinBox()
        self.interval_input.setRange(0.2, 60)
        self.interval_input.setSingleStep(0.5)
        self.interval_input.setDecimals(1)
        self.interval_input.setValue(DEFAULTS["interval"])
        controls.addWidget(self.interval_input)
        controls.addWidget(QLabel("Timeout (ms):"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(100, 10000)
        self.timeout_input.setSingleStep(100)
        self.timeout_input.setValue(DEFAULTS["timeout"])
        controls.addWidget(self.timeout_input)
        for spin_box in (self.interval_input, self.timeout_input):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        controls.addSpacing(12)
        controls.addWidget(QLabel("Show:"))
        self.window_combo = QComboBox()
        for label, seconds in WINDOW_OPTIONS:
            self.window_combo.addItem(label, seconds)
        self.window_combo.setCurrentIndex(self.window_combo.findData(DEFAULT_WINDOW_SECONDS))
        controls.addWidget(self.window_combo)
        controls.addSpacing(12)
        self.autoscale_check = QCheckBox("Auto scale")
        self.autoscale_check.setChecked(True)
        self.autoscale_check.setToolTip("Fit the gauges and graph to the latencies shown. Untick to set the "
                                        "range yourself.")
        controls.addWidget(self.autoscale_check)
        self.scale_min_input = QSpinBox()
        self.scale_max_input = QSpinBox()
        for spin_box, value in ((self.scale_min_input, 0), (self.scale_max_input, 200)):
            spin_box.setRange(0, 10000)
            spin_box.setValue(value)
            spin_box.setSuffix(" ms")
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        controls.addWidget(self.scale_min_input)
        controls.addWidget(QLabel("to"))
        controls.addWidget(self.scale_max_input)
        controls.addStretch()
        self.compact_check = QCheckBox("Compact")
        self.compact_check.setToolTip("Show only the gauges and graph.")
        controls.addWidget(self.compact_check)
        layout.addLayout(controls)

        self.log_row = QWidget()
        log_layout = QHBoxLayout(self.log_row)
        log_layout.setContentsMargins(0, 0, 0, 0)
        self.csv_check = QCheckBox("Log every ping to CSV:")
        self.csv_path_input = QLineEdit(str(log_dir() / "latency_log.csv"))
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_csv)
        log_layout.addWidget(self.csv_check)
        log_layout.addWidget(self.csv_path_input, 1)
        log_layout.addWidget(browse_button)
        layout.addWidget(self.log_row)

        self.status_label = QLabel()
        layout.addWidget(self.status_label)

        # Gauges beside the graph, above the targets and live results
        self.gauge_panel = GaugePanel()
        self.graph = LatencyGraph()
        self.top_splitter = QSplitter(Qt.Horizontal)
        self.top_splitter.addWidget(self.gauge_panel)
        self.top_splitter.addWidget(self.graph)
        self.top_splitter.setStretchFactor(0, 2)
        self.top_splitter.setStretchFactor(1, 3)
        self.top_splitter.setSizes([390, 800])  # Room for two columns of gauges until the user drags it

        targets_box = QGroupBox("Targets")
        targets_layout = QVBoxLayout(targets_box)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(COL_NAME, QHeaderView.Stretch)
        self.table.setToolTip("Tick On to monitor a target; it can be changed while monitoring.")
        # Always leave room for about three targets, however much space the charts take
        self.table.setMinimumHeight(self.table.horizontalHeader().sizeHint().height()
                                    + 3 * self.table.verticalHeader().defaultSectionSize() + 4)
        targets_layout.addWidget(self.table, 1)
        form = QHBoxLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Name")
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Host name or IP address")
        self.add_button = QPushButton("Add / Update")
        self.add_button.setToolTip("Add a target, or change the host of the target with this name.")
        self.remove_button = QPushButton("Remove")
        self.gateway_button = QPushButton("Add Gateway")
        self.gateway_button.setToolTip("Monitor the selected adapter's default gateway.")
        form.addWidget(self.name_input, 1)
        form.addWidget(self.host_input, 1)
        for button in (self.add_button, self.remove_button, self.gateway_button):
            form.addWidget(button)
        targets_layout.addLayout(form)

        live_box = QGroupBox("Live Results")
        live_layout = QVBoxLayout(live_box)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(monospace_font())
        self.output.setMaximumBlockCount(MAX_LIVE_LINES)
        self.output.setLineWrapMode(QPlainTextEdit.NoWrap)
        live_layout.addWidget(self.output)

        self.bottom_splitter = QSplitter(Qt.Horizontal)
        self.bottom_splitter.addWidget(targets_box)
        self.bottom_splitter.addWidget(live_box)
        self.bottom_splitter.setStretchFactor(0, 3)
        self.bottom_splitter.setStretchFactor(1, 2)

        self.main_splitter = QSplitter(Qt.Vertical)
        self.main_splitter.addWidget(self.top_splitter)
        self.main_splitter.addWidget(self.bottom_splitter)
        # Gauges and graph get most of the height; targets and live results the rest
        self.main_splitter.setStretchFactor(0, 3)
        self.main_splitter.setStretchFactor(1, 1)
        self.main_splitter.setSizes([700, 250])
        layout.addWidget(self.main_splitter, 1)

        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(self.stop)
        self.reset_button.clicked.connect(self.reset)
        self.window_combo.currentIndexChanged.connect(self.refresh_views)
        self.autoscale_check.toggled.connect(self.on_autoscale_toggled)
        self.scale_min_input.valueChanged.connect(self.refresh_views)
        self.scale_max_input.valueChanged.connect(self.refresh_views)
        self.compact_check.toggled.connect(self.apply_compact)
        self.table.itemChanged.connect(self.on_item_changed)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        self.add_button.clicked.connect(self.add_or_update_target)
        self.host_input.returnPressed.connect(self.add_or_update_target)
        self.remove_button.clicked.connect(self.remove_selected_target)
        self.gateway_button.clicked.connect(self.add_gateway)
        self.on_autoscale_toggled(True)

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("latency/targets", json.dumps([target.to_dict() for target in self.targets]))
        settings.setValue("latency/interval", self.interval_input.value())
        settings.setValue("latency/timeout", self.timeout_input.value())
        settings.setValue("latency/window", self.window_combo.currentData())
        settings.setValue("latency/autoscale", self.autoscale_check.isChecked())
        settings.setValue("latency/scale_min", self.scale_min_input.value())
        settings.setValue("latency/scale_max", self.scale_max_input.value())
        settings.setValue("latency/compact", self.compact_check.isChecked())
        settings.setValue("latency/csv", self.csv_check.isChecked())
        settings.setValue("latency/csv_path", self.csv_path_input.text())
        settings.setValue("latency/charts_splitter", self.main_splitter.saveState())
        settings.setValue("latency/top_splitter", self.top_splitter.saveState())
        settings.setValue("latency/bottom_splitter", self.bottom_splitter.saveState())

    def restore_settings(self, settings):
        try:
            saved = json.loads(settings.value("latency/targets", "null", str))
        except ValueError:
            saved = None
        self.targets = targets_from_dicts(saved)
        self.interval_input.setValue(settings.value("latency/interval", DEFAULTS["interval"], float))
        self.timeout_input.setValue(settings.value("latency/timeout", DEFAULTS["timeout"], int))
        index = self.window_combo.findData(settings.value("latency/window", DEFAULT_WINDOW_SECONDS, int))
        self.window_combo.setCurrentIndex(max(index, 0))
        self.scale_min_input.setValue(settings.value("latency/scale_min", 0, int))
        self.scale_max_input.setValue(settings.value("latency/scale_max", 200, int))
        self.autoscale_check.setChecked(settings.value("latency/autoscale", True, bool))
        self.compact_check.setChecked(settings.value("latency/compact", False, bool))
        self.csv_check.setChecked(settings.value("latency/csv", False, bool))
        self.csv_path_input.setText(settings.value("latency/csv_path", self.csv_path_input.text(), str))
        for key, splitter in (("charts", self.main_splitter), ("top", self.top_splitter),
                              ("bottom", self.bottom_splitter)):
            state = settings.value(f"latency/{key}_splitter")
            if state is not None:
                splitter.restoreState(state)
        self.rebuild_targets()

    def shutdown(self):
        workers = list(self.workers.values())
        self.stop()
        for worker in workers:
            worker.wait(self.timeout_input.value() + 2000)

    # ----------------------------------------------------------------- Targets

    def enabled_targets(self):
        return [target for target in self.targets if target.enabled]

    def rebuild_targets(self):
        """Refill the targets table and gauges after targets are added, removed or switched on or off."""
        self.table.blockSignals(True)
        self.table.setRowCount(len(self.targets))
        for row, target in enumerate(self.targets):
            on_item = QTableWidgetItem()
            on_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            on_item.setCheckState(Qt.Checked if target.enabled else Qt.Unchecked)
            self.table.setItem(row, COL_ON, on_item)
            name_item = QTableWidgetItem(swatch_icon(series_color(target.color_index)), target.name)
            self.table.setItem(row, COL_NAME, name_item)
            self.table.setItem(row, COL_HOST, QTableWidgetItem(target.host))
            for column in range(COL_LAST, len(COLUMNS)):
                item = QTableWidgetItem()
                item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
                self.table.setItem(row, column, item)
        self.table.blockSignals(False)

        self.gauges = {id(target): LatencyGauge(target.name, series_color(target.color_index))
                       for target in self.enabled_targets()}
        if self.gauges:
            self.gauge_panel.set_widgets(self.gauges.values())
        else:
            empty = QLabel("No targets are on.\nTick On for a target in the table below.")
            empty.setAlignment(Qt.AlignCenter)
            set_hint(empty, empty.text(), "info")
            self.gauge_panel.set_widgets([empty])
        self.refresh_views()

    def next_color_index(self):
        used = {target.color_index for target in self.targets}
        return next(index for index in range(len(self.targets) + 1) if index not in used)

    def target_named(self, name):
        return next((target for target in self.targets if target.name.lower() == name.lower()), None)

    def add_target(self, name, host):
        """Add a target (or point an existing one with this name at host) and switch it on."""
        target = self.target_named(name)
        changed = target is None or target.host != host
        if target is None:
            target = LatencyTarget(name, host, True, self.next_color_index())
            self.targets.append(target)
            self.append_line(f"Added {name} ({host})")
        elif changed or not target.enabled:
            target.name, target.host, target.enabled = name, host, True
            target.reset()
            self.append_line(f"Updated {name} -> {host}")
        if self.monitoring and (changed or id(target) not in self.workers):
            self.start_worker(target)  # Replaces any worker still pinging the old host
        self.rebuild_targets()
        return target

    def add_or_update_target(self):
        name, host = self.name_input.text().strip(), self.host_input.text().strip()
        set_invalid(self.name_input, not name)
        set_invalid(self.host_input, not host)
        if name and host:
            self.add_target(name, host)
            self.name_input.clear()
            self.host_input.clear()

    def remove_selected_target(self):
        target = self.selected_target()
        if target is not None:
            self.stop_worker(target)
            self.targets = [other for other in self.targets if other is not target]
            self.append_line(f"Removed {target.name} ({target.host})")
            self.rebuild_targets()

    def selected_target(self):
        rows = self.table.selectionModel().selectedRows()
        return self.targets[rows[0].row()] if rows else None

    def on_selection_changed(self):
        target = self.selected_target()
        if target is not None:
            self.name_input.setText(target.name)
            self.host_input.setText(target.host)
        self.update_buttons()

    def on_item_changed(self, item):
        if item.column() != COL_ON:
            return
        target = self.targets[item.row()]
        target.enabled = item.checkState() == Qt.Checked
        if self.monitoring:
            if target.enabled:
                target.reset()
                self.start_worker(target)
                self.append_line(f"Started {target.name} ({target.host})")
            else:
                self.stop_worker(target)
                self.append_line(f"Stopped {target.name} ({target.host})")
        QTimer.singleShot(0, self.rebuild_targets)  # Not while the table is still handling the click

    def gateway(self):
        adapter = self.window.current_adapter()
        return (adapter.gateways4 + adapter.gateways6 or [None])[0] if adapter is not None else None

    def update_gateway_button(self):
        gateway = self.gateway()
        self.gateway_button.setEnabled(gateway is not None)
        self.gateway_button.setText(f"Add Gateway ({gateway})" if gateway else "Add Gateway")

    def add_gateway(self):
        gateway = self.gateway()
        if gateway:
            self.add_target("Gateway", gateway)

    # ----------------------------------------------------------------- Monitoring

    def start(self):
        if self.monitoring:
            return
        enabled = self.enabled_targets()
        if not enabled:
            set_hint(self.status_label, "Tick On for at least one target first.", "error")
            return
        if self.csv_check.isChecked():
            try:
                self.csv_log = CsvLog(self.csv_path_input.text().strip())
            except OSError as error:
                QMessageBox.critical(self, "CSV Log", f"Couldn't open the log file:\n\n{error}")
                return
        for target in enabled:
            target.reset()
            self.start_worker(target)
        self.monitoring = True
        self.window.set_busy("latency", "Monitoring latency")
        interval, timeout = self.interval_input.value(), self.timeout_input.value()
        self.append_line(f"Started {len(enabled)} target(s), every {interval:g} s, timeout {timeout} ms")
        set_hint(self.status_label, f"Monitoring {len(enabled)} target(s)." +
                 (f" Logging to {self.csv_log.path}" if self.csv_log else ""), "info")
        self.update_buttons()
        self.refresh_views()

    def stop(self):
        for target in list(self.targets):
            self.stop_worker(target)
        if self.monitoring:
            self.append_line("Stopped")
            set_hint(self.status_label, "Stopped.", "info")
        self.monitoring = False
        if self.csv_log is not None:
            self.csv_log.close()
            self.csv_log = None
        self.window.clear_busy("latency")
        self.update_buttons()

    def reset(self):
        self.stop()
        for target in self.targets:
            target.reset()
        self.output.clear()
        self.status_label.clear()
        self.refresh_views()

    def start_worker(self, target):
        self.stop_worker(target)
        worker = LatencyThread(target, self.interval_input.value(), self.timeout_input.value(), self)
        worker.sample.connect(self.on_sample)
        worker.finished.connect(worker.deleteLater)
        self.workers[id(target)] = worker
        worker.start()

    def stop_worker(self, target):
        worker = self.workers.pop(id(target), None)
        if worker is not None:
            worker.stop()

    def on_sample(self, target, timestamp, rtt, ttl, error):
        if self.workers.get(id(target)) is not self.sender():
            return  # From a worker that has since been stopped or replaced
        target.add(timestamp, rtt, error)
        clock = time.strftime("%H:%M:%S", time.localtime(timestamp))
        result = f"OK   {rtt:7.1f} ms" if rtt is not None else f"LOST {error}"
        self.append_line(f"{clock}  {result}   {target.name} ({target.host})")
        if self.csv_log is not None:
            try:
                self.csv_log.write(timestamp, target, rtt, ttl, error)
            except OSError as problem:
                log.error("Latency CSV log failed: %s", problem)
                set_hint(self.status_label, f"Stopped logging to CSV: {problem}", "error")
                self.csv_log.close()
                self.csv_log = None
        self.dirty = True

    def append_line(self, text):
        self.output.appendPlainText(text)

    # ----------------------------------------------------------------- Views

    def on_refresh_timer(self):
        if self.dirty or self.monitoring:  # While monitoring the graph scrolls even without new samples
            self.refresh_views()

    def window_seconds(self):
        return self.window_combo.currentData() or DEFAULT_WINDOW_SECONDS

    def on_autoscale_toggled(self, checked):
        self.scale_min_input.setEnabled(not checked)
        self.scale_max_input.setEnabled(not checked)
        self.refresh_views()

    def current_scale(self, now):
        if self.autoscale_check.isChecked():
            values = [rtt for target in self.enabled_targets()
                      for _, rtt in target.window(self.window_seconds(), now) if rtt is not None]
            low, high = autoscale(values)
            for spin_box, value in ((self.scale_min_input, low), (self.scale_max_input, high)):
                spin_box.blockSignals(True)
                spin_box.setValue(round(value))
                spin_box.blockSignals(False)
            return low, high
        low, high = self.scale_min_input.value(), self.scale_max_input.value()
        invalid = high <= low
        set_invalid(self.scale_min_input, invalid)
        set_invalid(self.scale_max_input, invalid)
        return (low, low + 1) if invalid else (low, high)

    def refresh_views(self):
        self.dirty = False
        now, seconds = time.time(), self.window_seconds()
        scale = self.current_scale(now)
        series = []
        for row, target in enumerate(self.targets):
            stats = target.stats(seconds, now)
            cells = ["LOST" if stats.last_lost else "" if stats.last is None else f"{stats.last:.0f}"]
            cells += ["" if value is None else f"{value:.1f}" for value in (stats.average, stats.minimum,
                                                                             stats.maximum)]
            cells.append(f"{stats.loss_percent:.1f}%" if stats.sent else "")
            for offset, text in enumerate(cells):
                item = self.table.item(row, COL_LAST + offset)
                if item is not None and item.text() != text:
                    item.setText(text)
            last_item = self.table.item(row, COL_LAST)
            if last_item is not None:
                last_item.setForeground(QColor(COLORS["error"] if stats.last_lost else COLORS["text"]))
            gauge = self.gauges.get(id(target))
            if gauge is not None:
                gauge.update_value(stats, target.last_error, scale)
            if target.enabled:
                series.append((target.name, series_color(target.color_index), target.window(seconds, now)))
        self.graph.set_series(series, scale, seconds)

    def apply_compact(self, compact):
        self.log_row.setVisible(not compact)
        self.bottom_splitter.setVisible(not compact)

    def browse_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Latency Log File", self.csv_path_input.text(),
                                              "CSV files (*.csv);;All files (*)")
        if path:
            self.csv_path_input.setText(path)

    def update_buttons(self):
        self.start_button.setEnabled(not self.monitoring)
        self.stop_button.setEnabled(self.monitoring)
        self.csv_check.setEnabled(not self.monitoring)
        self.csv_path_input.setEnabled(not self.monitoring)
        self.interval_input.setEnabled(not self.monitoring)
        self.timeout_input.setEnabled(not self.monitoring)
        self.remove_button.setEnabled(self.selected_target() is not None)
