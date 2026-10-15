"""Monitoring the Network Map's devices: ping them every so often on a background thread, and log when one goes down
or comes back. Runs while NOMAD is open, whichever page is showing.

Devices with an IP SLA probe on one of the map's routers (netmap/probes.py) are checked from that router instead: the
routers are looked over for NOMAD's probes when monitoring starts, every DISCOVER_EVERY seconds after, and when asked
(after a probe is added), and each poll reads the probes' latest results over SNMP."""
import datetime
import time

from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, \
    QPushButton, QVBoxLayout, QWidget

from ..netmap import monitor, probes
from ..netmap.monitor import DOWN, UNKNOWN, UP
from ..snmp import SnmpClient
from .theme import monospace_font

LOG_LINES = 20000
CANT = "cant"  # In counts(): unknown because it can't be checked (its router isn't answering)
DISCOVER_EVERY = 600  # Seconds between looks for probes others have added or taken away, while monitoring


class PollThread(QThread):
    finished_poll = pyqtSignal(object, object)  # {key: rtt or None} pinged, probes.poll's {router key: readings or why}

    def __init__(self, targets, pinger, probe_targets=(), client_factory=SnmpClient, parent=None):
        super().__init__(parent)
        self.targets, self.pinger = targets, pinger
        self.probe_targets, self.client_factory = list(probe_targets), client_factory

    def run(self):
        pinged = monitor.poll(self.targets, self.pinger)
        self.finished_poll.emit(pinged, probes.poll(self.probe_targets, self.client_factory))


class DiscoverThread(QThread):
    discovered = pyqtSignal(object)  # probes.Discovery

    def __init__(self, routers, client_factory, parent=None):
        super().__init__(parent)
        self.routers, self.client_factory = routers, client_factory

    def run(self):
        self.discovered.emit(probes.discover(self.routers, self.client_factory))


class NetworkMonitor(QObject):
    """Owns the polling timer, each device's status and the Monitor tab."""
    statuses_changed = pyqtSignal()  # After every poll, to redraw the dots and response times
    polled = pyqtSignal()  # After each poll's results are in (the map then reads its links' counters)
    history_added = pyqtSignal(list)  # [history entries] for the map to keep
    probes_changed = pyqtSignal()  # After a look over the routers for probes

    def __init__(self, parent=None, pinger=monitor.ping):
        super().__init__(parent)
        self.pinger = pinger
        self.client_factory = SnmpClient  # Tests swap in the fake network's
        self.access = None  # access(address) -> (credential, version, timeout) to read a router over SNMP, or None
        self.tracker = monitor.StatusTracker()
        self.targets, self.labels = {}, {}  # key -> address, key -> label
        self.interval = monitor.DEFAULT_INTERVAL
        self.thread = None
        self.last_poll = None
        self.lines = []
        self.network_map = None
        self.discovery = None  # The last probes.Discovery (None: not looked yet)
        self.discovered_at = 0.0
        self.discovered_routers = None  # The (key, address) of the routers looked over
        self.discover_thread = None
        self.discover_again = False
        self.probes = {}  # Device key -> its probes.Probe
        self.last_results = {}  # Device key -> (router, entry, time of the probe result used last)
        self.no_access = set()  # Routers with probes the last poll couldn't ask (no community or user for them)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_now)

        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)
        top = QHBoxLayout()
        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        top.addWidget(self.summary_label, 1)
        self.probes_button = QPushButton("Router Probes...")
        self.probes_button.setToolTip("Devices this computer can't reach (behind a VRF, or no route back here) can be "
                                      "checked from a router on the map that can, with an IP SLA ping on the router: "
                                      "see and manage them here, or right-click a device > Monitor from a Router.")
        self.copy_button = QPushButton("Copy Log")
        self.save_button = QPushButton("Save Log...")
        top.addWidget(self.probes_button)
        top.addWidget(self.copy_button)
        top.addWidget(self.save_button)
        layout.addLayout(top)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(LOG_LINES)
        self.log_view.setFont(monospace_font())
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.log_view, 1)
        self.copy_button.clicked.connect(self.copy_log)
        self.save_button.clicked.connect(self.save_log)
        self.update_summary()

    # ----------------------------------------------------------------- What to watch

    @property
    def running(self):
        return self.timer.isActive()

    def set_map(self, network_map):
        """Watch the devices on this map (those with an address to ping, or a probe on a router), and show its
        history in the log."""
        if network_map is not self.network_map:
            self.discovery, self.discovered_routers, self.last_results = None, None, {}
        self.network_map = network_map
        self.apply_probes()
        if self.running and self.routers_to_read() != self.discovered_routers:
            self.discover()

    def apply_probes(self):
        """Match the probes found to the map's devices, and what to watch with them."""
        network_map = self.network_map
        if network_map is None:
            return
        found = self.discovery.probes if self.discovery is not None else []
        found = [probe for probe in found if probe.router in network_map.devices
                 and network_map.devices[probe.router].mgmt_ip == probe.address]
        self.probes = probes.assign(network_map, found)
        self.targets = {key: device.mgmt_ip for key, device in network_map.devices.items() if device.mgmt_ip}
        for key, probe in self.probes.items():
            self.targets.setdefault(key, probe.target)
        self.labels = {key: device.label for key, device in network_map.devices.items()}
        self.tracker.forget_others(set(self.targets))
        self.update_summary()

    def via(self, key):
        """"R5 (vrf MGMT-B)": the router a device is checked from, or "" (pinged from this computer)."""
        probe = self.probes.get(key)
        return probe.where(self.labels.get(probe.router, probe.router)) if probe is not None else ""

    def load_history(self, entries):
        """Show a map's saved status changes in the log (from when it was last watched)."""
        self.lines = []
        self.log_view.clear()
        for when, _key, _label, _status, text in entries[-LOG_LINES:]:
            try:
                stamp = datetime.datetime.fromisoformat(when).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                stamp = when
            self.add_line(f"{stamp}  {text}")

    def status(self, key):
        """The DeviceStatus of a watched device, or None if it isn't being watched."""
        if key not in self.targets or not (self.running or key in self.tracker.devices):
            return None
        return self.tracker.get(key)

    def status_text(self, key):
        """For the Devices table's Status column (plain, so it filters well)."""
        state = self.status(key)
        if state is None:
            return ""
        if state.status == UNKNOWN and state.problem:
            return "Can't check"
        return monitor.STATUS_NAMES[state.status] + (f" (from {state.via})" if state.via else "")

    # ----------------------------------------------------------------- Looking for probes on the routers

    def routers_to_read(self):
        network_map = self.network_map
        if network_map is None:
            return frozenset()
        return frozenset((key, network_map.devices[key].mgmt_ip) for key in probes.readable_routers(network_map))

    def discover(self):
        """Look over the map's routers for NOMAD's probes (in the background)."""
        if self.discover_thread is not None:
            self.discover_again = True
            return
        wanted = self.routers_to_read()
        routers = []
        for key, address in sorted(wanted):
            access = self.access(address) if self.access is not None else None
            if access is not None and access[0] is not None:
                routers.append((key, address, *access))
        self.discovered_routers = wanted
        self.discovered_at = time.time()
        self.discover_again = False
        thread = DiscoverThread(routers, self.client_factory, self)
        thread.discovered.connect(self.on_discovered)
        thread.finished.connect(self.on_discover_finished)
        self.discover_thread = thread
        thread.start()

    @property
    def discovering(self):
        return self.discover_thread is not None

    def on_discover_finished(self):
        self.discover_thread = None
        if self.discover_again:
            self.discover()
        else:
            self.probes_changed.emit()  # So a wait for the look to finish ends

    def on_discovered(self, discovery):
        before = {key: (probe.router, probe.entry) for key, probe in self.probes.items()}
        self.discovery = discovery
        self.apply_probes()
        after = {key: (probe.router, probe.entry) for key, probe in self.probes.items()}
        if self.running and after != before:
            if after:
                names = ", ".join(f"{self.labels.get(key, key)} from {self.via(key)}"
                                  for key in sorted(after, key=lambda item: self.labels.get(item, item).lower()))
                self.log(f"Checking {len(after)} device{'' if len(after) == 1 else 's'} from routers (IP SLA): "
                         f"{names}")
            else:
                self.log("No device is checked from a router now: every one is pinged from this computer")
        self.probes_changed.emit()
        self.statuses_changed.emit()

    # ----------------------------------------------------------------- Running

    def start(self, interval=None):
        self.interval = interval or self.interval
        self.timer.start(self.interval * 1000)
        self.log(f"Monitoring {len(self.targets)} device{'' if len(self.targets) == 1 else 's'} every "
                 f"{monitor.duration_text(self.interval)}")
        self.discover()
        self.poll_now()
        self.update_summary()

    def stop(self):
        if self.running:
            self.timer.stop()
            self.log("Stopped monitoring")
        self.tracker.devices = {}  # Stale once nobody's checking
        self.last_results = {}
        self.update_summary()
        self.statuses_changed.emit()

    def set_interval(self, seconds):
        self.interval = seconds
        if self.running:
            self.timer.start(seconds * 1000)
            self.log(f"Now checking every {monitor.duration_text(seconds)}")
            self.update_summary()

    def poll_now(self):
        if self.thread is not None or not self.targets:
            return  # The last poll is still going (a big map with many devices down), or nothing to watch
        if self.running and time.time() - self.discovered_at > DISCOVER_EVERY:
            self.discover()
        pings = {key: address for key, address in self.targets.items() if key not in self.probes}
        self.thread = PollThread(pings, self.pinger, self.probe_targets(), self.client_factory, self)
        self.thread.finished_poll.connect(self.on_results)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()

    def probe_targets(self):
        """For probes.poll: each router with probes to read, and how to read it (the routers NOMAD has no way to
        read go in no_access)."""
        entries = {}
        for probe in self.probes.values():
            entries.setdefault((probe.router, probe.address), []).append(probe.entry)
        targets = []
        self.no_access = set()
        for (router, address), numbers in sorted(entries.items()):
            access = self.access(address) if self.access is not None else None
            if access is not None and access[0] is not None:
                targets.append((router, address, *access, sorted(numbers)))
            else:
                self.no_access.add(router)
        return targets

    def on_thread_finished(self):
        self.thread = None

    def on_results(self, pinged, read=None):
        if not self.running:
            return  # Stopped while it was polling
        results = {key: rtt for key, rtt in pinged.items() if key in self.targets and key not in self.probes}
        via, problems = {}, {}
        for key, probe in self.probes.items():
            router = self.labels.get(probe.router, probe.router)
            via[key] = probe.where(router)
            got = (read or {}).get(probe.router)
            if got is None:
                if probe.router in self.no_access:
                    problems[key] = f"NOMAD has no SNMP community or user for {router}"
                continue  # Found after this poll started: read from the next
            if isinstance(got, str):
                problems[key] = f"{router} isn't answering SNMP"
            elif probe.entry not in got:
                problems[key] = f"{router} didn't give IP SLA {probe.entry}'s result"
            else:
                reading = got[probe.entry]
                why = probes.stale(probe, reading)
                if why:
                    problems[key] = f"{why} (IP SLA {probe.entry} on {router})"
                    continue
                stamp = (probe.router, probe.entry, reading.time)
                if self.last_results.get(key) == stamp:
                    continue  # No new result since the last poll: it counts once
                self.last_results[key] = stamp
                results[key] = reading.rtt if reading.ok else None
        changes = self.tracker.update(results, via) + self.tracker.cannot_check(problems, via)
        self.last_poll = time.time()
        history = []
        for change in changes:
            if change.status == UP and change.lasted is None:
                continue  # Answered the first poll: nothing's happened to it
            label = self.labels.get(change.key, change.key)
            text = monitor.change_text(change, label, self.targets.get(change.key, ""))
            self.log(text, change.when)
            history.append(monitor.history_entry(change, label, text))
        if history:
            self.history_added.emit(history)
        self.update_summary()
        self.statuses_changed.emit()
        self.polled.emit()

    def shutdown(self):
        self.timer.stop()
        if self.thread is not None:
            self.thread.wait(monitor.PING_TIMEOUT_MS * monitor.PING_TRIES * 4)
        if self.discover_thread is not None:
            self.discover_thread.wait(10000)

    # ----------------------------------------------------------------- Showing it

    def counts(self):
        """{up, down, unknown, CANT: how many}, CANT being the unknown that can't be checked."""
        counts = {UP: 0, DOWN: 0, UNKNOWN: 0, CANT: 0}
        for key in self.targets:
            state = self.tracker.get(key)
            counts[CANT if state.status == UNKNOWN and state.problem else state.status] += 1
        return counts

    def summary(self):
        """"12 up · 2 down" for beside the Monitor switch, or "" when not monitoring."""
        if not self.running:
            return ""
        counts = self.counts()
        parts = [f"{counts[UP]} up"]
        if counts[DOWN]:
            parts.append(f"{counts[DOWN]} down")
        if counts[UNKNOWN]:
            parts.append(f"{counts[UNKNOWN]} checking")
        if counts[CANT]:
            parts.append(f"{counts[CANT]} can't check")
        return " · ".join(parts)

    def update_summary(self):
        if not self.running:
            text = ("Not monitoring. Tick Monitor to ping the devices on the map every so often and log when one "
                    "goes down or comes back.")
        else:
            checked = (f", last checked {datetime.datetime.fromtimestamp(self.last_poll):%H:%M:%S}"
                       if self.last_poll else "")
            routers = (f" {len(self.probes)} of them {'is' if len(self.probes) == 1 else 'are'} checked from "
                       "routers (IP SLA)." if self.probes else "")
            text = (f"Monitoring {len(self.targets)} devices every {monitor.duration_text(self.interval)}: "
                    f"{self.summary()}{checked}. A device is down after missing {monitor.FAILS_FOR_DOWN} checks "
                    f"in a row.{routers}")
        self.summary_label.setText(text)

    def log(self, text, when=None):
        stamp = datetime.datetime.fromtimestamp(when or time.time()).strftime("%Y-%m-%d %H:%M:%S")
        self.add_line(f"{stamp}  {text}")

    def add_line(self, line):
        self.lines.append(line)
        self.lines = self.lines[-LOG_LINES:]
        self.log_view.appendPlainText(line)

    def copy_log(self):
        QApplication.clipboard().setText("\n".join(self.lines))

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self.tab, "Save Monitor Log", "Network monitor.txt",
                                              "Text files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write("\n".join(self.lines) + "\n")
        except OSError as error:
            QMessageBox.critical(self.tab, "Save Monitor Log", f"Couldn't save the log:\n\n{error}")
