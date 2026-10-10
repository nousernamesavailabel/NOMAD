"""Watching the Network Map for new devices and hosts while NOMAD is open: the timers, the reading on background
threads, the syslog and trap listeners, who's watching a tribe map, and the Watch tab with its log."""
import datetime
import logging
import os
import socket
import threading
import time

from PyQt5.QtCore import QObject, Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication, QCheckBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QMessageBox, \
    QPlainTextEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget

from ..netmap import triggers, watch
from ..netmap.monitor import duration_text
from ..snmp import TRAP_PORT
from ..syslog import SYSLOG_PORT, hub
from .common import release_thread
from .theme import monospace_font

log = logging.getLogger(__name__)

LOG_LINES = 20000
TICK_MS = 5000  # Checking for switches a syslog message or trap asked to be read
LEASE_RENEW_SECONDS = 60
UNKNOWN_SENDERS_LOGGED = 50


# The timers on the Watch tab (and in the Map Watcher service's settings): name -> (label, unit seconds, text,
# tooltip)
TIMER_FIELDS = {
    "neighbor_interval": ("New neighbors:", 60, "every {} min",
                          "How often each switch is asked for its CDP and LLDP neighbors (quick: two short tables). "
                          "A switch with a new neighbor is read again at once."),
    "host_interval": ("New hosts:", 60, "every {} min",
                      "How often every switch's MAC table is read again, for hosts plugged in where nothing "
                      "announced it (slower: like mapping again)."),
    "recheck_interval": ("SNMP re-check:", 60, "every {} min",
                         "How often devices on the map that don't answer SNMP are asked again with the map's "
                         "credentials. One that answers now is read (Crawl from Here). Changing the credentials "
                         "asks them at once."),
    "trigger_delay": ("After a trap or syslog:", 1, "read the switch {} s later",
                      "How long after a switch says a port came up (or a neighbor appeared) it's read: CDP needs a "
                      "little time to see a new neighbor."),
}


class WatchTimers(QWidget):
    """The watch timers as a form of spin boxes. values() is {name: seconds}, as watch.TIMERS has them."""
    changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        form = QFormLayout(self)
        form.setContentsMargins(0, 0, 0, 0)
        self.boxes = {}
        for name, (label, unit, text, tip) in TIMER_FIELDS.items():
            default, least, most = watch.TIMERS[name]
            box = QSpinBox()
            box.setRange(max(least // unit, 0), most // unit)
            prefix, _, suffix = text.partition("{}")
            box.setPrefix(prefix)
            box.setSuffix(suffix)
            box.setValue(default // unit)
            box.setToolTip(tip)
            box.valueChanged.connect(lambda _: self.changed.emit())
            self.boxes[name] = box
            form.addRow(label, box)

    def values(self):
        return {name: box.value() * TIMER_FIELDS[name][1] for name, box in self.boxes.items()}

    def set_values(self, values):
        for name, seconds in watch.timer_values(values).items():
            self.boxes[name].setValue(seconds // TIMER_FIELDS[name][1])


class RecheckThread(QThread):
    done = pyqtSignal(object, int)  # {key: (address, Check)} of those that answer SNMP now, how many were asked

    def __init__(self, targets, options, client_factory, parent=None):
        super().__init__(parent)
        self.targets, self.options, self.client_factory = targets, options, client_factory
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        try:
            self.done.emit(watch.recheck(self.targets, self.options, self.client_factory, self.stop_event.is_set,
                                         self.options.workers), len(self.targets))
        except Exception:
            log.exception("Asking devices that don't answer SNMP again failed")
            self.done.emit({}, 0)


class SignatureThread(QThread):
    done = pyqtSignal(object, object)  # {key: signature or None}, {key: (old address, address it answers at)}

    def __init__(self, targets, options, client_factory, parent=None, fallbacks=None):
        super().__init__(parent)
        self.targets, self.options, self.client_factory = targets, options, client_factory
        self.fallbacks = fallbacks or {}
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        try:
            self.done.emit(*watch.read_switches(self.targets, self.fallbacks, self.options, self.client_factory,
                                                self.stop_event.is_set, self.options.workers))
        except Exception:
            log.exception("Asking switches for their neighbors failed")
            self.done.emit({}, {})


class RefreshThread(QThread):
    done = pyqtSignal(object, object)  # The crawl's map (or None), the map it was added to
    failed = pyqtSignal(str)

    def __init__(self, network_map, options, seeds, crawl, parent=None):
        super().__init__(parent)
        self.network_map, self.options, self.seeds, self.crawl = network_map, options, seeds, crawl
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    def run(self):
        try:
            crawled = self.crawl(watch.copy_for_thread(self.network_map), self.options, self.seeds,
                                 should_stop=self.stop_event.is_set)
        except Exception as error:
            log.exception("Reading switches for new devices failed")
            self.failed.emit(str(error))
            return
        self.done.emit(crawled, self.network_map)


class LeaseThread(QThread):
    done = pyqtSignal(object, object)  # Map id, the lease (or None when the server couldn't be reached)

    def __init__(self, maps, map_id, holder, release=False, parent=None):
        super().__init__(parent)
        self.maps, self.map_id, self.holder, self.release = maps, map_id, holder, release

    def run(self):
        try:
            lease = self.maps.lease(self.map_id, self.holder, "gui", release=self.release)
        except Exception as error:
            log.info("Couldn't claim the watching of a tribe map: %s", error)
            lease = None
        self.done.emit(self.map_id, lease)


def default_crawl(network_map, options, seeds, should_stop):
    return watch.crawl_from(network_map, options, seeds, should_stop=should_stop)


class MapWatcher(QObject):
    """Owns watching: page is the NetworkMapTab (for the map, how to read it, and what to do with what's found)."""
    applied = pyqtSignal(object)  # A WatchResult added to the map
    status_changed = pyqtSignal()

    def __init__(self, page, client_factory=None, crawl=default_crawl, listen_ports=(SYSLOG_PORT, TRAP_PORT)):
        super().__init__(page)
        from ..snmp import SnmpClient
        self.page = page
        self.client_factory = client_factory or SnmpClient
        self.crawl = crawl
        self.syslog_port, self.trap_port = listen_ports
        self.running = False
        self.active = False  # Reading the network from this computer (not standing by, or waiting to hear)
        self.standing_by = ""  # Who's watching instead ("" when it's this computer)
        self.baseline = watch.NeighborBaseline()
        self.queue = triggers.TriggerQueue()
        self.to_refresh = {}  # Address -> reasons, waiting for the reading going on to finish
        self.signature_thread = self.refresh_thread = self.lease_thread = self.recheck_thread = None
        self.releasing = []  # Threads giving up the watching of a tribe map (stopping, or another map opened)
        self.recheck_again = False  # The credentials changed while devices were being asked: ask again after
        self.trap_receiver = None
        self.listening = []  # What's being listened on, for the tab
        self.unknown_senders = set()
        self.lines = []
        self.lease_checked = 0.0
        self.holder = f"{socket.gethostname()}-{os.getpid()}"
        self.neighbor_interval, self.host_interval = watch.NEIGHBOR_INTERVAL, watch.HOST_INTERVAL
        self.recheck_interval = watch.RECHECK_INTERVAL
        self.last_neighbors = self.last_hosts = None
        self.neighbor_timer = QTimer(self)
        self.neighbor_timer.timeout.connect(self.poll_neighbors)
        self.host_timer = QTimer(self)
        self.host_timer.timeout.connect(self.refresh_all)
        self.recheck_timer = QTimer(self)
        self.recheck_timer.timeout.connect(self.recheck_unread)
        self.tick_timer = QTimer(self)
        self.tick_timer.timeout.connect(self.tick)
        self.build_tab()

    # ----------------------------------------------------------------- The Watch tab

    def build_tab(self):
        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)
        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        layout.addWidget(self.summary_label)
        form = QFormLayout()
        self.timers = WatchTimers()
        self.listen_check = QCheckBox(f"Listen for syslog (UDP {self.syslog_port}) and SNMP traps "
                                      f"(UDP {self.trap_port}) from the switches")
        self.listen_check.setChecked(True)
        self.listen_check.setToolTip("Read a switch as soon as it says a port came up, a CDP neighbor appeared or "
                                     "a MAC address was learned, instead of waiting for the next check. The "
                                     "switches have to be set up to send to this computer (see below).")
        form.addRow(self.timers)
        form.addRow("", self.listen_check)
        layout.addLayout(form)
        config_row = QHBoxLayout()
        self.config_label = QLabel()
        self.config_label.setWordWrap(True)
        self.config_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.config_button = QPushButton("Generate SNMP Config")
        self.config_button.setToolTip("Build the configuration that lets the switches be read and has them send traps "
                                      "and syslog here, and send it to a switch.")
        self.config_button.clicked.connect(self.open_config_builder)
        config_row.addWidget(self.config_label, 1)
        config_row.addWidget(self.config_button)
        layout.addLayout(config_row)
        buttons = QHBoxLayout()
        self.check_now_button = QPushButton("Check Now")
        self.check_now_button.setToolTip("Ask every switch for its neighbors now, and read again any with new ones.")
        self.seen_button = QPushButton("Mark All as Seen")
        self.seen_button.setToolTip("Clear the NEW tags: everything found so far has been looked at.")
        self.copy_button = QPushButton("Copy Log")
        self.save_button = QPushButton("Save Log...")
        buttons.addWidget(self.check_now_button)
        buttons.addWidget(self.seen_button)
        buttons.addStretch(1)
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.save_button)
        layout.addLayout(buttons)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(LOG_LINES)
        self.log_view.setFont(monospace_font())
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.log_view, 1)
        self.timers.changed.connect(self.set_intervals)
        self.listen_check.toggled.connect(lambda _: self.update_listening())
        self.check_now_button.clicked.connect(self.poll_neighbors)
        self.seen_button.clicked.connect(lambda: self.page.mark_seen(None))
        self.copy_button.clicked.connect(lambda: QApplication.clipboard().setText("\n".join(self.lines)))
        self.save_button.clicked.connect(self.save_log)
        self.update_summary()

    def log(self, text):
        line = f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}  {text}"
        self.lines = (self.lines + [line])[-LOG_LINES:]
        self.log_view.appendPlainText(line)

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self.tab, "Save Watch Log", "Network watch.txt", "Text files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write("\n".join(self.lines) + "\n")
        except OSError as error:
            QMessageBox.critical(self.tab, "Save Watch Log", f"Couldn't save the log:\n\n{error}")

    def summary(self):
        """For beside the Watch switch."""
        if not self.running:
            return ""
        if self.standing_by:
            return f"watched by {self.standing_by}"
        news = len(self.page.network_map.news) if self.page.network_map is not None else 0
        busy = self.refresh_thread is not None or self.signature_thread is not None
        return ("checking · " if busy else "") + (f"{news} new" if news else "nothing new")

    def update_summary(self):
        if not self.running:
            text = ("Not watching. Tick Watch to have new switches, access points and hosts added to the map as "
                    "they're plugged in (CDP/LLDP neighbors and MAC tables, read over SNMP).")
        elif self.standing_by:
            text = (f"{self.standing_by} is watching this tribe map, so this computer isn't (the network would "
                    "be read twice). What it finds shows here as it's added. If it stops, this computer takes over.")
        else:
            parts = [f"Watching {len(watch.switches(self.page.network_map))} switches: neighbors every "
                     f"{duration_text(self.neighbor_interval)}, hosts every {duration_text(self.host_interval)}; "
                     f"devices that don't answer SNMP asked again every {duration_text(self.recheck_interval)}."]
            if self.last_neighbors:
                parts.append(f"Last checked {datetime.datetime.fromtimestamp(self.last_neighbors):%H:%M:%S}.")
            if self.listening:
                parts.append("Listening for " + " and ".join(self.listening) + ".")
            text = " ".join(parts)
        self.summary_label.setText(text)
        self.config_label.setText(f"So a switch tells this computer at once, it has to send its traps and syslog "
                                  f"here ({self.local_address()}), with link-status logging on its access ports.")
        self.status_changed.emit()

    def open_config_builder(self):
        """The SNMP Config page, set up for this computer and the map's credentials."""
        address = self.local_address()
        self.page.window.show_snmp_config(destination=address if not address.startswith("<") else "", from_map=True)

    def local_address(self):
        adapter = self.page.window.current_adapter() if hasattr(self.page.window, "current_adapter") else None
        for address in getattr(adapter, "ipv4", []) or []:
            return str(getattr(address, "ip", address))
        return "<this computer's address>"

    # ----------------------------------------------------------------- Starting and stopping

    def start(self):
        if self.running or self.page.network_map is None:
            return
        self.running, self.active = True, False
        self.standing_by = ""
        self.baseline = watch.NeighborBaseline()
        watch.mark_hosts_seen(self.page.network_map)  # What's on the map now isn't news
        self.log(f"Started watching {self.page.map_name()} for new devices and hosts")
        self.set_intervals()
        self.tick_timer.start(TICK_MS)
        if self.page.tribe_map_id is not None:
            self.claim()
        else:
            self.go_active()

    def stop(self, quiet=False):
        if not self.running:
            return
        self.running = self.active = False
        for timer in (self.neighbor_timer, self.host_timer, self.recheck_timer, self.tick_timer):
            timer.stop()
        self.stop_listening()
        self.recheck_again = False
        for thread in (self.signature_thread, self.refresh_thread, self.recheck_thread):
            if thread is not None:
                thread.stop()
        if self.page.tribe_map_id is not None and self.page.tribe.maps is not None and not self.standing_by:
            # Owned by the watcher, as its other threads are, and waited for on shutdown
            thread = LeaseThread(self.page.tribe.maps, self.page.tribe_map_id, self.holder, release=True, parent=self)
            self.releasing.append(thread)
            thread.finished.connect(self.on_release_finished)
            thread.start()
        self.standing_by = ""
        self.to_refresh = {}
        if not quiet:
            self.log("Stopped watching")
        self.update_summary()

    def map_changed(self):
        """Another map was opened: start again on it (or stop when there's none)."""
        if not self.running:
            return
        self.stop(quiet=True)
        if self.page.network_map is not None:
            self.start()

    def set_intervals(self):
        values = self.timers.values()
        changed = (values["neighbor_interval"], values["host_interval"], values["recheck_interval"]) != \
            (self.neighbor_interval, self.host_interval, self.recheck_interval)
        self.neighbor_interval, self.host_interval = values["neighbor_interval"], values["host_interval"]
        self.recheck_interval = values["recheck_interval"]
        self.queue.delay = values["trigger_delay"]
        if self.running and self.active and (changed or not self.neighbor_timer.isActive()):
            self.neighbor_timer.start(self.neighbor_interval * 1000)
            self.host_timer.start(self.host_interval * 1000)
            self.recheck_timer.start(self.recheck_interval * 1000)
        self.update_summary()

    def go_active(self):
        first = not self.active
        self.active, self.standing_by = True, ""
        self.set_intervals()
        self.update_listening()
        if first:
            self.poll_neighbors()
            self.recheck_unread()
        self.update_summary()

    def stand_by(self, who):
        if self.standing_by != who:
            self.log(f"{who} is watching this map: standing by")
        self.standing_by, self.active = who, False
        self.neighbor_timer.stop()
        self.host_timer.stop()
        self.recheck_timer.stop()
        self.stop_listening()
        self.update_summary()

    # ----------------------------------------------------------------- Who's watching a tribe map

    def claim(self):
        maps = self.page.tribe.maps
        if maps is None or self.lease_thread is not None or self.releasing:  # Claimed once the last one's let go
            return
        self.lease_checked = time.time()
        self.lease_thread = LeaseThread(maps, self.page.tribe_map_id, self.holder, parent=self)
        self.lease_thread.done.connect(self.on_lease)
        self.lease_thread.finished.connect(self.on_claim_finished)
        self.lease_thread.start()

    # Threads' signals go to methods, never lambdas: a lambda's signal still waiting to be delivered when the watcher
    # (and so its threads) is freed crashes Qt, where a method's is dropped

    def on_claim_finished(self):
        if self.lease_thread is self.sender():
            self.lease_thread = None

    def on_release_finished(self):
        if self.sender() in self.releasing:
            self.releasing.remove(self.sender())

    def on_lease(self, map_id, lease):
        if not self.running or map_id != self.page.tribe_map_id:
            return
        if lease is None:  # Server not reachable (or too old): watch here, and say so once
            if not self.active:
                self.log("The tribe server can't be reached: watching from this computer meanwhile")
            self.go_active()
        elif lease.get("yours"):
            self.go_active()
        else:
            kind = "the Map Watcher service" if lease.get("kind") == "service" else "NOMAD"
            self.stand_by(f"{lease.get('computer') or 'another computer'} ({kind})")

    # ----------------------------------------------------------------- Listening for syslog and traps

    def update_listening(self):
        if self.running and self.active and self.listen_check.isChecked():
            self.start_listening()
        else:
            self.stop_listening()
        self.update_summary()

    def start_listening(self):
        if self.listening:
            return
        try:
            hub.subscribe(self.on_syslog, self.syslog_port)
            self.listening.append(f"syslog on UDP {self.syslog_port}")
        except OSError as error:
            self.log(f"Couldn't listen for syslog on UDP {self.syslog_port}: {error.strerror or error} (another "
                     "syslog server may have it). Watching by checking every so often only.")
        receiver = triggers.TrapReceiver(self.on_trap, port=self.trap_port, v3_users=lambda: list(self.page.v3_users))
        try:
            receiver.start()
            self.trap_receiver = receiver
            self.listening.append(f"traps on UDP {self.trap_port}")
        except OSError as error:
            self.log(f"Couldn't listen for SNMP traps on UDP {self.trap_port}: {error.strerror or error} (Windows' "
                     "SNMP Trap service or another trap receiver may have it).")
        if self.listening:
            self.log("Listening for " + " and ".join(self.listening))

    def stop_listening(self):
        if any(item.startswith("syslog") for item in self.listening):
            hub.unsubscribe(self.on_syslog, self.syslog_port)
        if self.trap_receiver is not None:
            self.trap_receiver.stop()
            self.trap_receiver = None
        self.listening = []

    def on_syslog(self, message):
        """From the syslog receiver's thread."""
        reason = triggers.syslog_reason(message.raw or message.message)
        if reason:
            self.queue.add(message.source, reason)

    def on_trap(self, trap, sender):
        """From the trap receiver's thread."""
        reason = triggers.trap_reason(trap)
        if reason:
            self.queue.add(trap.agent or sender, reason)

    # ----------------------------------------------------------------- Reading

    def tick(self):
        if not self.running:
            return
        if self.page.tribe_map_id is not None and time.time() - self.lease_checked >= LEASE_RENEW_SECONDS:
            self.claim()
        network_map = self.page.network_map
        for address, reasons in self.queue.due():
            if not self.active or network_map is None:
                continue
            key = triggers.device_for_address(network_map, address)
            if key is None or network_map.devices[key].source != "snmp":
                if address not in self.unknown_senders and len(self.unknown_senders) < UNKNOWN_SENDERS_LOGGED:
                    self.unknown_senders.add(address)
                    self.log(f"{address} sent {', '.join(reasons)}, but it isn't a switch read on this map")
                continue
            device = network_map.devices[key]
            self.log(f"{device.label}: {', '.join(reasons)}: reading it")
            self.queue_refresh(device.mgmt_ip or address, reasons)
        self.run_refresh()

    def poll_neighbors(self):
        if not self.active or self.signature_thread is not None or self.page.network_map is None:
            return
        targets = watch.switches(self.page.network_map)
        if not targets:
            return
        options = self.page.watch_options()
        fallbacks = watch.fallback_addresses(self.page.network_map, targets, options.scope)
        self.signature_thread = SignatureThread(targets, options, self.client_factory, self, fallbacks)
        self.signature_thread.done.connect(self.on_signatures)
        self.signature_thread.finished.connect(self.on_signature_thread_finished)
        self.signature_thread.start()
        self.update_summary()

    def on_signature_thread_finished(self):
        self.signature_thread = None
        self.update_summary()

    def on_signatures(self, signatures, moved=None):
        if not self.running or self.page.network_map is None:
            return
        self.last_neighbors = time.time()
        network_map = self.page.network_map
        lines = watch.adopt_addresses(network_map, moved or {})
        for line in lines:
            self.log(line)
        if lines:
            self.applied.emit(watch.WatchResult(lines=lines))  # Saves the map with the new addresses
        silent = [key for key, signature in signatures.items() if signature is None and key in network_map.devices]
        if silent and len(silent) == len(signatures):
            self.log("No switch answered SNMP: check the network and the community strings")
        for key in self.baseline.changed(network_map, signatures):
            device = network_map.devices.get(key)
            if device is not None:
                self.log(f"{device.label}: new CDP/LLDP neighbor: reading it")
                self.queue_refresh(device.mgmt_ip, ["new neighbor"])
        self.run_refresh()

    def recheck_unread(self):
        """Ask the devices that don't answer SNMP again, in the background."""
        if not self.active or self.page.network_map is None:
            return
        if self.recheck_thread is not None:
            self.recheck_again = True
            return
        options = self.page.watch_options()
        targets = watch.unread_devices(self.page.network_map, options.scope)
        if not targets:
            return
        self.recheck_thread = RecheckThread(targets, options, self.client_factory, self)
        self.recheck_thread.done.connect(self.on_rechecked)
        self.recheck_thread.finished.connect(self.on_recheck_thread_finished)
        self.recheck_thread.start()
        self.update_summary()

    def recheck_now(self):
        """The credentials changed: ask the devices that don't answer SNMP with them now."""
        if self.running and self.active:
            self.recheck_unread()

    def on_recheck_thread_finished(self):
        self.recheck_thread = None
        if self.recheck_again:
            self.recheck_again = False
            self.recheck_unread()
        self.update_summary()

    def on_rechecked(self, found, asked):
        if not self.running or self.page.network_map is None:
            return
        network_map = self.page.network_map
        answering = []
        for key, (address, check) in found.items():
            device = network_map.devices.get(key)
            if device is None or device.source == "snmp":
                continue  # Gone, or read meanwhile
            answering.append(device.label)
            self.page.answered[address] = check.community
            self.log(f"{device.label} answers SNMP now ({watch.credential_text(check.community)}): reading it")
            self.queue_refresh(address, ["answers SNMP now"])
        if asked and not answering:
            what = "the device that doesn't" if asked == 1 else f"the {asked} devices that don't"
            self.log(f"Asked {what} answer SNMP again: none do yet")
        self.run_refresh()

    def refresh_all(self):
        """Read every switch again (for new hosts)."""
        if not self.active or self.page.network_map is None:
            return
        targets = watch.switches(self.page.network_map)
        if targets:
            self.log(f"Reading {len(targets)} switches' MAC tables for new hosts")
        for address in targets.values():
            self.queue_refresh(address, [])
        self.run_refresh()

    def queue_refresh(self, address, reasons):
        if address:
            self.to_refresh.setdefault(address, [])
            self.to_refresh[address] += [reason for reason in reasons if reason not in self.to_refresh[address]]

    def run_refresh(self):
        """Read the switches waiting, unless a reading (or the user's own crawl) is going on."""
        if not self.to_refresh or self.refresh_thread is not None or self.page.network_map is None \
                or not self.page.can_watch_now():
            return
        seeds, self.to_refresh = list(self.to_refresh), {}
        self.refresh_thread = RefreshThread(self.page.network_map, self.page.watch_options(), seeds, self.crawl,
                                            self)
        self.refresh_thread.done.connect(self.on_refreshed)
        self.refresh_thread.failed.connect(self.on_refresh_failed)
        self.refresh_thread.finished.connect(self.on_refresh_thread_finished)
        self.refresh_thread.start()
        self.update_summary()

    def on_refresh_failed(self, message):
        self.log(f"Reading the switches failed: {message}")

    def on_refresh_thread_finished(self):
        self.refresh_thread = None
        self.update_summary()
        self.run_refresh()  # Any that came in meanwhile

    def on_refreshed(self, crawled, network_map):
        if not self.running or crawled is None or crawled.stopped:
            return
        if network_map is not self.page.network_map or not self.page.can_watch_now():
            for seed in crawled.seeds:  # The map changed under it (mapped again, another opened): read again
                self.queue_refresh(seed, [])
            return
        result = watch.apply_refresh(network_map, crawled, by=socket.gethostname())
        self.last_hosts = time.time()
        for line in result.lines:
            self.log(line)
        self.applied.emit(result)
        self.update_summary()

    def shutdown(self):
        self.stop(quiet=True)
        for thread in [self.signature_thread, self.refresh_thread, self.lease_thread, self.recheck_thread] \
                + self.releasing:
            if thread is not None:
                if hasattr(thread, "stop"):
                    thread.stop()
                release_thread(thread, 2000)
