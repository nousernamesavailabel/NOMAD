"""Traffic Graphs page: the traffic on a switch's, router's or firewall's port over time, from its SNMP counters, for
any device on the Network Map open (NetFlow not needed).

Where the readings come from (traffic_history.py):
- the Map Watcher, which reads the ports at the ends of links and the ports ticked to keep all the time, and keeps
  them on its computer and on the tribe server: the same readings as the NOMAD Dashboard's graph (solid lines);
- this computer, which keeps the same ports' readings while the Network Map's Monitor is on (dashed, where the Watcher
  has none);
- and any port read live every few seconds while the page shows it (dashed): kept in this computer's history too,
  unless the Monitor is keeping that port already, so coming back to the page still shows what was read.
"""
import collections
import logging
import time

from PyQt5.QtCore import QTimer, pyqtSignal
from PyQt5.QtWidgets import QButtonGroup, QCheckBox, QComboBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, \
    QWidget

from ..netmap import traffic_history
from ..netmap.model import NETWORK_KINDS, port_key
from .common import StoppableThread, release_thread, run_in_background, set_hint
from .graph_ports_dialog import device_ports
from .theme import COLORS
from .traffic_graph import TrafficGraph, format_rate

log = logging.getLogger(__name__)
LIVE_SECONDS = 5
LIVE_KEPT = 4320  # Six hours of live readings
REFRESH_MS = 60000
DEFAULT_SPAN = "24h"


class PortRateThread(StoppableThread):
    """Reads one port's octet counters every LIVE_SECONDS (finding its ifIndex first, unless it's known)."""
    sampled = pyqtSignal(object)  # (time, in octets, out octets, speed Mb/s)
    failed = pyqtSignal(str)
    indexed = pyqtSignal(object)  # The device's {port key: ifIndex}, when it had to be read

    def __init__(self, address, credential, version, timeout, port, index=None, client_factory=None, parent=None):
        super().__init__(parent)
        self.address, self.credential, self.version = address, credential, version
        self.timeout, self.port, self.index = timeout, port, index
        self.client_factory = client_factory

    def run(self):
        from ..netmap import counters
        from ..snmp import SnmpClient, SnmpError
        factory = self.client_factory or SnmpClient
        try:
            client = factory(self.address, self.credential, self.version, timeout=self.timeout, retries=0)
            index = self.index
            if not index:
                index = counters.interface_index(client)
                self.indexed.emit(index)
        except (SnmpError, OSError, ValueError) as error:
            self.failed.emit(str(error))
            return
        ifindex = index.get(port_key(self.port))
        if ifindex is None:
            self.failed.emit(f"{self.address} has no interface called {self.port}")
            return
        while not self.stopping:
            try:
                samples = counters.read_samples(client, {"port": ifindex}, clock=time.time)
            except (SnmpError, OSError, ValueError) as error:
                self.failed.emit(str(error))
                samples = {}
            sample = samples.get("port")
            if sample is not None:
                self.sampled.emit((sample.when, sample.in_octets, sample.out_octets, sample.speed))
            self.stop_event.wait(LIVE_SECONDS)


class TrafficTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.span = DEFAULT_SPAN
        self.map_seen = None  # The NetworkMap the device list was filled from
        self.wanted = None  # (device key, port) to choose (from the Network Map)
        self.generation = 0  # Answers to an earlier question are dropped
        self.history = traffic_history.PortHistory()
        self.history_of = None  # (map record, device key, port key) the history is of
        self.indexes = {}  # Device key -> {port key: ifIndex}, read for the live readings
        self.live = collections.deque(maxlen=LIVE_KEPT)  # (time, in b/s, out b/s) of the port chosen
        self.live_where = None  # (device key, port) the live readings are of
        self.live_thread = None
        self.last_sample = None
        self.live_speed = 0
        self.live_note = ""
        self.init_ui()
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.refresh)
        self.refresh_timer.start(REFRESH_MS)

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("The traffic on a port of a switch, router or firewall on the Network Map, over time, from its "
                       "SNMP counters (no NetFlow needed). The Map Watcher keeps the ports at the ends of links all "
                       "the time, the same as the NOMAD Dashboard shows; this computer keeps them while the map's "
                       "Monitor is on; and the port chosen here is read live while the page shows (kept on this "
                       "computer too). Tick Keep Its History to keep any other port's all the time.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        row = QHBoxLayout()
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(240)
        self.device_combo.setToolTip("The switches, routers and firewalls on the Network Map open")
        self.port_combo = QComboBox()
        self.port_combo.setMinimumWidth(260)
        self.port_combo.setToolTip("Its ports: those whose history is kept first (links, and ports ticked to keep)")
        row.addWidget(QLabel("Device:"))
        row.addWidget(self.device_combo, 1)
        row.addWidget(QLabel("Port:"))
        row.addWidget(self.port_combo, 1)
        self.span_group = QButtonGroup(self)
        self.span_group.setExclusive(True)
        self.span_buttons = {}
        for code in traffic_history.SPANS:
            button = QPushButton(code)
            button.setCheckable(True)
            button.setToolTip(f"The last {traffic_history.SPAN_NAMES[code]}")
            button.setChecked(code == self.span)
            button.setStyleSheet(f"QPushButton:checked {{ color: {COLORS['accent']}; border: 1px solid "
                                 f"{COLORS['accent']}; }}")
            self.span_group.addButton(button)
            self.span_buttons[button] = code
            row.addWidget(button)
        self.keep_check = QCheckBox("Keep Its History")
        self.keep_check.setToolTip("Read this port's traffic all the time, as for the ports at the ends of links: the "
                                   "Map Watcher keeps it (for the NOMAD Dashboard and every NOMAD), and so does this "
                                   "computer while Monitor is on. Saved with the map.")
        self.refresh_button = QPushButton("Refresh")
        row.addWidget(self.keep_check)
        row.addWidget(self.refresh_button)
        layout.addLayout(row)

        self.source_label = QLabel()
        self.source_label.setWordWrap(True)
        layout.addWidget(self.source_label)
        self.rate_label = QLabel()
        self.rate_label.setWordWrap(True)
        layout.addWidget(self.rate_label)
        self.graph = TrafficGraph()
        layout.addWidget(self.graph, 1)

        self.device_combo.currentIndexChanged.connect(self.on_device_changed)
        self.port_combo.currentIndexChanged.connect(self.on_port_changed)
        self.span_group.buttonClicked.connect(self.on_span_clicked)
        self.keep_check.clicked.connect(self.on_keep_clicked)
        self.refresh_button.clicked.connect(self.on_refresh_clicked)
        self.update_keep_check()
        self.update_rate_label()

    # ----------------------------------------------------------------- Page interface

    def save_settings(self, settings):
        settings.setValue("traffic/span", self.span)

    def restore_settings(self, settings):
        span = settings.value("traffic/span", DEFAULT_SPAN, str)
        self.set_span(span if span in traffic_history.SPANS else DEFAULT_SPAN)

    def shutdown(self):
        self.refresh_timer.stop()
        self.stop_live()

    def showEvent(self, event):
        super().showEvent(event)
        if self.map_page_map() is not self.map_seen:
            self.fill_devices()
        self.refresh()
        self.update_live()

    def hideEvent(self, event):
        super().hideEvent(event)
        self.update_live()

    # ----------------------------------------------------------------- The Network Map

    def map_page(self):
        return getattr(self.window, "netmap_tab", None)

    def map_page_map(self):
        page = self.map_page()
        return getattr(page, "network_map", None) if page is not None else None

    def show_port(self, key, port=""):
        """From the Network Map: this device's port (its first link's when no port's given)."""
        self.wanted = (key, port)
        self.fill_devices()

    def fill_devices(self):
        network_map = self.map_page_map()
        self.map_seen = network_map
        current = self.wanted[0] if self.wanted else self.device_combo.currentData()
        self.device_combo.blockSignals(True)
        self.device_combo.clear()
        if network_map is not None:
            devices = sorted(((key, device) for key, device in network_map.devices.items()
                              if device.kind in NETWORK_KINDS and device.mgmt_ip),
                             key=lambda item: item[1].label.lower())
            for key, device in devices:
                self.device_combo.addItem(f"{device.label} ({device.mgmt_ip})", key)
        index = self.device_combo.findData(current) if current is not None else -1
        self.device_combo.setCurrentIndex(max(0, index) if self.device_combo.count() else -1)
        self.device_combo.blockSignals(False)
        self.fill_ports()

    def fill_ports(self):
        network_map, key = self.map_seen, self.device_combo.currentData()
        wanted = self.wanted[1] if self.wanted and self.wanted[0] == key else None
        current = wanted if wanted is not None else self.port_combo.currentData()
        self.wanted = None
        self.port_combo.blockSignals(True)
        self.port_combo.clear()
        if network_map is not None and key in network_map.devices:
            ports, linked = device_ports(network_map, key)
            graphed = {port_key(port) for port in network_map.graphed.get(key, [])}
            far = {}
            for link in network_map.links_of(key):
                other = network_map.devices.get(link.other(key))
                if other is not None:
                    far[port_key(link.port_on(key))] = f"to {other.label} {link.port_on(other.key)}".strip()
            kept = [port for port in ports if port_key(port) in linked or port_key(port) in graphed]
            for port in kept + [port for port in ports if port not in kept]:
                text = port
                if port_key(port) in far:
                    text += f"  {far[port_key(port)]}"
                elif port_key(port) in graphed:
                    text += "  (history kept)"
                self.port_combo.addItem(text, port)
        index = -1
        if current:
            index = next((row for row in range(self.port_combo.count())
                          if port_key(self.port_combo.itemData(row)) == port_key(current)), -1)
            if index < 0 and wanted:  # A port the crawl didn't list (a tunnel, say): it can still be read
                self.port_combo.addItem(wanted, wanted)
                index = self.port_combo.count() - 1
        self.port_combo.setCurrentIndex(max(0, index) if self.port_combo.count() else -1)
        self.port_combo.blockSignals(False)
        self.on_port_changed()

    def chosen(self):
        """(device key, port), or (None, None)."""
        key, port = self.device_combo.currentData(), self.port_combo.currentData()
        if self.map_seen is None or key not in self.map_seen.devices or not port:
            return None, None
        return key, port

    def kept(self, key, port):
        """Whether the port's history is kept: (kept, at the end of a link)."""
        network_map = self.map_seen
        linked = any(port_key(link.port_on(key)) == port_key(port) for link in network_map.links_of(key))
        graphed = any(port_key(item) == port_key(port) for item in network_map.graphed.get(key, []))
        return linked or graphed, linked

    # ----------------------------------------------------------------- Choosing

    def on_device_changed(self):
        self.fill_ports()

    def on_port_changed(self):
        self.update_keep_check()
        self.history = traffic_history.PortHistory()
        self.history_of = None
        self.redraw()
        self.refresh()
        self.update_live()

    def set_span(self, span):
        self.span = span
        for button, code in self.span_buttons.items():
            button.setChecked(code == span)

    def on_span_clicked(self, button):
        self.set_span(self.span_buttons[button])
        self.history = traffic_history.PortHistory()
        self.redraw()
        self.refresh()

    def on_refresh_clicked(self):
        if self.map_page_map() is not self.map_seen:
            self.fill_devices()
        self.refresh()

    def update_keep_check(self):
        key, port = self.chosen()
        self.keep_check.blockSignals(True)
        if key is None:
            self.keep_check.setChecked(False)
            self.keep_check.setEnabled(False)
        else:
            kept, linked = self.kept(key, port)
            self.keep_check.setChecked(kept)
            page = self.map_page()
            self.keep_check.setEnabled(not linked and page is not None and page.network_map is self.map_seen
                                       and page.worker is None)
            self.keep_check.setToolTip(
                "A port at the end of a link: its history is always kept." if linked else
                "Read this port's traffic all the time, as for the ports at the ends of links: the Map Watcher keeps "
                "it (for the NOMAD Dashboard and every NOMAD), and so does this computer while Monitor is on. Saved "
                "with the map.")
        self.keep_check.blockSignals(False)

    def on_keep_clicked(self, on):
        key, port = self.chosen()
        page = self.map_page()
        if key is None or page is None:
            return
        ok, message = page.set_graphed(key, port, on)
        set_hint(self.source_label, message, "success" if ok else "warning")
        self.fill_ports()

    # ----------------------------------------------------------------- The history

    def refresh(self):
        if not self.isVisible():
            return
        if self.map_page_map() is not self.map_seen:
            self.fill_devices()
            return  # Filling chose a port, which refreshed
        key, port = self.chosen()
        if key is None:
            self.history = traffic_history.PortHistory()
            self.redraw()
            self.update_source_label()
            return
        page = self.map_page()
        record = getattr(page, "record_shown", None)
        map_id = getattr(page, "tribe_map_id", None)
        tribe = getattr(page, "tribe", None)
        maps = tribe.maps if map_id is not None and tribe is not None else None
        start, end = traffic_history.span_range(self.span)
        self.generation += 1
        generation, where = self.generation, (record, key, port_key(port))

        def fetch():
            return generation, where, traffic_history.history_for(record, key, port, start, end, maps=maps,
                                                                  map_id=map_id)

        run_in_background(fetch, self.on_history, self.on_history_failed)

    def on_history(self, result):
        generation, where, history = result
        if generation != self.generation:
            return
        self.history, self.history_of = history, where
        self.redraw()
        self.update_source_label()

    def on_history_failed(self, error):
        set_hint(self.source_label, f"Couldn't read the port's history: {error}", "error")

    def redraw(self):
        start, end = traffic_history.span_range(self.span)
        key, port = self.chosen()
        if key is None:
            note = ("Open a map on the Network Map page first." if self.map_seen is None else
                    "Choose a switch, router or firewall, and one of its ports." if self.device_combo.count() else
                    "The map open has no switch, router or firewall with an address.")
        else:
            note = "Reading..." if self.history_of is None else "No readings of this port in this time."
        history = self.history
        self.graph.set_data(history.watcher, history.own, self.live_points(), start, end, history.hourly, note)

    def update_source_label(self):
        key, port = self.chosen()
        if key is None:
            self.source_label.setText("")
            return
        history, page = self.history, self.map_page()
        kept, _ = self.kept(key, port)
        parts, kind = [], "info"
        if history.watcher:
            where = "on this computer" if history.watcher_here else "through the tribe server"
            parts.append(f"Solid: the Map Watcher's readings ({where}), the same as the NOMAD Dashboard's graph.")
        elif history.note:
            parts.append(history.note)
            kind = "warning"
        elif kept:
            parts.append("The Map Watcher has no readings of this port in this time (is it watching this map, with "
                         "monitoring on?).")
        else:
            parts.append("This port is only read while this page shows it: the Map Watcher and the Monitor keep "
                         "the ports at the ends of links and those ticked Keep Its History. Tick it to keep this "
                         "one's all the time.")
            kind = "warning"
        monitoring = page is not None and getattr(page.monitor, "running", False)
        if history.own:
            parts.append("Dashed: this computer's readings where the Map Watcher has none (kept while Monitor is on, "
                         "and while this page shows the port), and the live readings.")
        elif kept and not monitoring:
            parts.append("Tick Monitor on the Network Map to keep this computer's readings too.")
        set_hint(self.source_label, " ".join(parts), kind)

    # ----------------------------------------------------------------- Live

    def live_points(self):
        key, port = self.chosen()
        return list(self.live) if key is not None and self.live_where == (key, port_key(port)) else []

    def update_live(self):
        """Read the chosen port's counters over SNMP while the page shows (with the map's credentials)."""
        key, port = self.chosen()
        where = (key, port_key(port)) if key is not None and self.isVisible() else None
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
        page = self.map_page()
        address = self.map_seen.devices[key].mgmt_ip
        credential, version = page.snmp_access(address) if hasattr(page, "snmp_access") else (None, None)
        if credential is None:
            self.live_note = ("No live readings: NOMAD reads them over SNMP with the Network Map's credentials, and "
                              "the map has none (SNMP Credentials... on the Network Map page).")
            self.update_rate_label()
            return
        counters = getattr(page, "counters", None)
        index = self.indexes.get(key) or (counters.indexes.get(key) if counters is not None else None)
        self.live_thread = PortRateThread(address, credential, version, getattr(page, "timeout", 2000), port,
                                          index, parent=self)
        self.live_thread.sampled.connect(self.on_live_sample)
        self.live_thread.failed.connect(self.on_live_failed)
        self.live_thread.indexed.connect(self.on_indexed)
        self.live_thread.start()
        self.update_rate_label()

    def stop_live(self):
        if self.live_thread is not None:
            self.live_thread.stop()
            release_thread(self.live_thread, 2000)
            self.live_thread = None

    def on_indexed(self, index):
        if self.live_where is not None:
            self.indexes[self.live_where[0]] = index

    def on_live_sample(self, sample):
        when, in_octets, out_octets, speed = sample
        before, self.last_sample = self.last_sample, sample
        self.live_speed = speed
        self.live_note = ""
        if before is not None and when > before[0] and in_octets >= before[1] and out_octets >= before[2]:
            seconds = when - before[0]
            point = (when, (in_octets - before[1]) * 8 / seconds, (out_octets - before[2]) * 8 / seconds)
            self.live.append(point)
            self.keep_live(point, speed)
            self.redraw()
        self.update_rate_label()

    def keep_live(self, point, speed):
        """Keep a live reading in this computer's traffic history, under the map's record, so it's still there after
        leaving the page; not when the Monitor is keeping the port's readings already (they'd count twice in the
        hour)."""
        key, port = self.chosen()
        page = self.map_page()
        name = getattr(page, "record_shown", None)
        if key is None or not name or self.live_where != (key, port_key(port)) or page.network_map is not self.map_seen:
            return
        link_counters = getattr(page, "counters", None)
        monitor = getattr(page, "monitor", None)
        if (getattr(monitor, "running", False) and link_counters is not None
                and (key, port_key(port)) in link_counters.port_names):
            return
        store = traffic_history.own_store()
        if store is None:
            return
        when, rate_in, rate_out = point
        try:
            store.add(name, [{"device": key, "port": port, "at": when, "in_bps": rate_in, "out_bps": rate_out,
                              "speed": speed}])
            store.prune()
        except Exception as error:  # The graph still shows it: the history just misses this reading
            log.warning("Couldn't keep the port's live traffic: %s", error)

    def on_live_failed(self, message):
        self.live_note = f"No live readings: SNMP didn't answer ({message})."
        self.update_rate_label()

    def update_rate_label(self):
        if self.chosen()[0] is None:
            self.rate_label.setText("")
            return
        if self.live_note:
            set_hint(self.rate_label, self.live_note, "warning")
            return
        points = self.live_points()
        if not points:
            set_hint(self.rate_label, "Reading the port's live rate over SNMP...", "info")
            return
        _, in_rate, out_rate = points[-1]
        text = f"Now: in {format_rate(in_rate)}, out {format_rate(out_rate)}"
        if self.live_speed:
            speed = self.live_speed * 1_000_000
            text += (f" of {format_rate(speed)} ({in_rate * 100 / speed:.0f}% in, {out_rate * 100 / speed:.0f}% "
                     "out)")
        set_hint(self.rate_label, text + f" (from SNMP every {LIVE_SECONDS} s).", "success")
