"""Monitoring the Network Map's devices: ping them every so often on a background thread, and log when one goes down
or comes back. Runs while NOMAD is open, whichever page is showing.

What it finds goes in the map's monitoring record on this computer (monitor_record.LocalRecord): each device's status,
its changes and the gaps while nothing was monitoring, so it picks up where it left off when NOMAD starts again, and
knows each device's uptime. A map the Map Watcher service monitors shows the Watcher's monitoring while this isn't on
(set_watcher): it's always on, so its record is the fuller one.

Devices with an IP SLA probe on one of the map's routers (netmap/probes.py) are checked from that router instead: the
routers are looked over for NOMAD's probes when monitoring starts, every DISCOVER_EVERY seconds after, and when asked
(after a probe is added), and each poll reads the probes' latest results over SNMP."""
import datetime
import time

from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, \
    QPushButton, QVBoxLayout, QWidget

from ..netmap import checks, monitor, monitor_record, probes
from ..netmap.monitor import DOWN, UNKNOWN, UP
from ..snmp import SnmpClient
from .common import release_thread
from .theme import monospace_font

LOG_LINES = 20000
CANT = "cant"  # In counts(): unknown because it can't be checked (its router isn't answering)
DISCOVER_EVERY = 600  # Seconds between looks for probes others have added or taken away, while monitoring
CATCH_UP_SECONDS = 300  # At least this long, this computer's newer up/down outranks the Map Watcher's (status())


class PollThread(QThread):
    # {key: rtt or None} pinged (or checked on a port or web address), probes.poll's {router key: readings or why},
    # {key: note} of the devices checked on a port or web address (why there was no answer, or a warning)
    finished_poll = pyqtSignal(object, object, object)

    def __init__(self, targets, pinger, probe_targets=(), client_factory=SnmpClient, parent=None, checks=None,
                 runner=None):
        super().__init__(parent)
        self.targets, self.pinger = targets, pinger
        self.probe_targets, self.client_factory = list(probe_targets), client_factory
        self.checks, self.runner = dict(checks or {}), runner

    def run(self):
        notes = {}
        pinged = monitor.poll(self.targets, self.pinger, checks=self.checks, notes=notes, runner=self.runner)
        self.finished_poll.emit(pinged, probes.poll(self.probe_targets, self.client_factory), notes)


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
    probes_changed = pyqtSignal()  # After a look over the routers for probes

    def __init__(self, parent=None, pinger=monitor.ping):
        super().__init__(parent)
        self.pinger = pinger
        self.runner = None  # Runs a check on a port or web address (checks.run); tests swap in their own
        self.checks = {}  # Device key -> its checks.CheckSpec, for those not pinged (a web server's TCP 443)
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
        self.record = None  # The map's monitor_record.LocalRecord on this computer
        self.shown = {}  # Key -> DeviceStatus as shown (since from the record, uptimes), after each poll
        self.watcher = {}  # Key -> DeviceStatus as the Map Watcher has it (see set_watcher)
        self.watcher_source = ""
        self.watcher_interval = float(monitor.DEFAULT_INTERVAL)  # The Map Watcher's seconds between checks
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
        self.checks = {key: spec for key, spec in ((key, checks.spec_of(device))
                                                   for key, device in network_map.devices.items()) if not spec.pings}
        self.tracker.forget_others(set(self.targets))
        self.update_summary()

    def how(self, key):
        """"TCP 443": what checks a device that isn't pinged, or "" (ping)."""
        probe = self.probes.get(key)
        if probe is not None:
            return f"TCP {probe.port}" if probe.port else ""
        spec = self.checks.get(key)
        return checks.short_text(spec) if spec is not None else ""

    def via(self, key):
        """"R5 (vrf MGMT-B)": the router a device is checked from, or "" (pinged from this computer)."""
        probe = self.probes.get(key)
        return probe.where(self.labels.get(probe.router, probe.router)) if probe is not None else ""

    def set_record(self, record, old_log=()):
        """Keep the map's monitoring in this record (a LocalRecord, or None), and show its changes in the log. The
        map's status log from before (old_log) goes into the record the first time."""
        if record is self.record:
            return
        if self.record is not None:
            self.record.close()
        self.record = record
        self.tracker.devices = {}
        self.shown = {}
        self.lines = []
        self.log_view.clear()
        if record is None:
            return
        record.import_log(list(old_log))
        for row in record.recent_changes(0, LOG_LINES):
            self.log(row["text"], row["at"])
        if self.running:
            self.pick_up()

    def pick_up(self):
        """Carry on from the record: the statuses saved last, and the time since its last check noted as a gap."""
        if self.record is None:
            return
        monitor_record.restore(self.tracker, self.record.saved_statuses(0))
        self.tracker.forget_others(set(self.targets))
        gap = self.record.note_restart(time.time(), self.interval)
        if gap is not None:
            self.log(f"Not monitored for {monitor.duration_text(gap[1] - gap[0])} (left out of the uptime)")
        self.work_out_shown()

    def work_out_shown(self):
        if self.record is None:
            self.shown = {}
            return
        self.shown = self.record.view(0, {key: state for key, state in self.tracker.devices.items()
                                          if key in self.targets})

    def set_watcher(self, states, source="", interval=None):
        """The Map Watcher's monitoring of this map ({key: DeviceStatus}, {} for none): what the map shows of the
        devices it monitors, so NOMAD and the NOMAD Dashboard show the same. interval: the Watcher's seconds between
        checks (how long it may take to catch up with a change this computer saw first)."""
        self.watcher, self.watcher_source = dict(states or {}), source
        self.watcher_interval = float(interval or monitor.DEFAULT_INTERVAL)
        self.statuses_changed.emit()
        self.update_summary()

    def status(self, key):
        """The DeviceStatus of a monitored device as shown (the Map Watcher's when it monitors the device, as the
        NOMAD Dashboard has it; else this computer's while it monitors), or None if neither monitors it. While this
        computer has seen it go down or come back and the Watcher hasn't yet, this computer's: the map says so at
        once instead of a minute or two later."""
        watcher = self.watcher.get(key)
        if watcher is None:
            return self.own_status(key)
        own = self.own_status(key) if self.running else None
        return own if own is not None and self.ahead_of_watcher(own, watcher) else watcher

    def ahead_of_watcher(self, own, watcher, now=None):
        """This computer saw the device change (up to down, or back) after the Watcher's last change of it, recently
        enough that the Watcher just hasn't caught up (it takes FAILS_FOR_DOWN of its checks to call one down). A
        disagreement that lasts longer than that is a real one (the Watcher can't reach it from where it is): the
        Watcher's is shown then, as the dashboard has it, and the details pane shows both."""
        if own.status not in (UP, DOWN) or own.status == watcher.status or not own.exact or not own.since:
            return False
        now = time.time() if now is None else now
        catch_up = max(CATCH_UP_SECONDS, (monitor.FAILS_FOR_DOWN + 2) * self.watcher_interval)
        return own.since > watcher.since and now - own.since < catch_up

    def own_status(self, key):
        """This computer's monitoring of a device (its DeviceStatus while Monitor is on), or None."""
        if key not in self.targets or not (self.running or key in self.tracker.devices):
            return None
        return self.shown.get(key) or self.tracker.get(key)

    def watcher_status(self, key):
        """The Map Watcher's DeviceStatus of a device, or None."""
        return self.watcher.get(key)

    def status_text(self, key):
        """For the Devices table's Status column (plain, so it filters well)."""
        state = self.status(key)
        if state is None:
            return ""
        if state.stale_at:
            return f"{monitor.STATUS_NAMES[state.status]} ({monitor_record.not_checked_text(state).lower()})"
        if state.status == UNKNOWN and state.problem:
            return "Can't check"
        warning = " with a warning" if state.status == UP and state.problem else ""
        return monitor.STATUS_NAMES[state.status] + warning + (f" (from {state.via})" if state.via else "")

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
        self.pick_up()
        self.discover()
        self.poll_now()
        self.update_summary()

    def stop(self):
        if self.running:
            self.timer.stop()
            self.log("Stopped monitoring")
        self.tracker.devices = {}  # Stale once nobody's checking (the record has them for next time)
        self.shown = {}
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
        self.thread = PollThread(pings, self.pinger, self.probe_targets(), self.client_factory, self, self.checks,
                                 self.runner)
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

    def on_results(self, pinged, read=None, notes=None):
        if not self.running:
            return  # Stopped while it was polling
        results = {key: rtt for key, rtt in pinged.items() if key in self.targets and key not in self.probes}
        notes = {key: note for key, note in (notes or {}).items() if key in results}
        if any(rtt is None for rtt in results.values()) and \
                time.time() - self.discovered_at > probes.LOOK_AGAIN_AFTER_MISS:
            self.discover()  # Someone may have just given one a probe: the next poll reads it, if so
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
                results[key], notes[key] = probes.reading_result(probe, reading)
        changes = self.tracker.update(results, via, notes) + self.tracker.cannot_check(problems, via)
        self.last_poll = time.time()
        logged = []
        for change in changes:
            if change.status == UP and change.lasted is None and not change.problem:
                continue  # Answered the first poll: nothing's happened to it
            label = self.labels.get(change.key, change.key)
            text = monitor.change_text(change, label, self.targets.get(change.key, ""), self.how(change.key))
            self.log(text, change.when)
            logged.append((change, label, text))
        self.keep(logged)
        self.update_summary()
        self.statuses_changed.emit()
        self.polled.emit()

    def keep(self, logged):
        """A poll's changes [(Change, label, text)] and the statuses after it, into the map's record."""
        if self.record is None:
            return
        try:
            record = self.record
            record.add_changes(0, logged)
            network_map = self.network_map
            devices = network_map.devices if network_map is not None else {}
            record.write_statuses(0, [(key, self.labels.get(key, key), address, devices[key].kind,
                                       self.tracker.get(key)) for key, address in self.targets.items()
                                      if key in devices and key in self.tracker.devices])
            record.fill_in(0, self.labels, {key: state for key, state in self.tracker.devices.items()
                                            if key in self.targets})
            record.checked(self.last_poll or time.time())
            record.prune(monitor_record.LocalRecord.KEEP_SECONDS)
            self.work_out_shown()
        except Exception:  # A record that can't be written (disk full, locked) mustn't stop the monitoring
            import logging
            logging.getLogger(__name__).exception("Couldn't keep the monitoring record")

    def shutdown(self):
        self.timer.stop()
        if self.thread is not None:
            release_thread(self.thread, monitor.PING_TIMEOUT_MS * monitor.PING_TRIES * 4)
        if self.discover_thread is not None:
            release_thread(self.discover_thread, 10000)

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

    def watcher_stopped_text(self):
        """" It hasn't checked since 14:02: is the service running?" when the Map Watcher stopped, else ""."""
        stopped = max((state.stale_at for state in self.watcher.values()), default=0.0)
        if not stopped:
            return ""
        return (f" It hasn't checked since {monitor_record.clock_text(stopped)}: is the Map Watcher service "
                "running? The devices are grayed, as they were then.")

    def update_summary(self):
        if not self.running and self.watcher:
            text = (f"Showing the monitoring of {self.watcher_source or 'the Map Watcher'}."
                    f"{self.watcher_stopped_text()} Tick Monitor to ping the devices from this computer too, and log "
                    "when one goes down or comes back.")
        elif not self.running:
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
            if self.watcher:
                text += (f" The map shows {self.watcher_source or 'the Map Watcher'}'s monitoring of the devices it "
                         "monitors, the same as the NOMAD Dashboard, except for a device this computer has seen go "
                         "down or come back first: that shows at once, until the Watcher catches up. The details "
                         "pane shows both."
                         f"{self.watcher_stopped_text()}")
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
