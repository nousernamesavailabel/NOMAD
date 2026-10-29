"""Monitor from a Router: put IP SLA probes on the map's routers for devices this computer can't reach (behind a VRF,
or with no route back here), and see or take away the probes already there. The probes are found again by everyone
monitoring the map (netmap/probes.py), so nothing about them is saved here."""
import logging
from dataclasses import dataclass, field

import paramiko
from PyQt5.QtCore import QSettings, Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QGroupBox, QHBoxLayout, \
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, \
    QVBoxLayout, QWidget

from ..netmap import monitor, probes
from ..terminal.transports import Cancelled, ConnectionFailed
from .common import StoppableThread, set_hint
from .ssh_push import LoginRow
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

ADD_COLUMNS = ["Device", "Address", "Check From", "VRF", "Source Interface", "Justification", "Status"]
ADDRESS_COLUMN, ROUTER_COLUMN, VRF_COLUMN, SOURCE_COLUMN, WHY_COLUMN, STATUS_COLUMN = range(1, 7)
PROBE_COLUMNS = ["Device", "Address", "Router", "IP SLA", "VRF", "Source Interface", "Every", "Status", "Owner"]
PROBE_STATUS_COLUMN = PROBE_COLUMNS.index("Status")
ROUTER_PICKS = "Router picks"  # No source: the router pings from the interface on its way to the device
PING_TIMEOUT = 20  # Seconds for the router's test ping (two tries, a second each, plus a slow prompt)


@dataclass
class Item:
    """One probe to add or take away."""
    row: int
    device: str  # Device key ("" for a probe whose target isn't on the map)
    label: str
    target: str
    vrf: str = ""
    entry: int = 0  # Taking away: its number
    tag: str = ""
    owner: str = ""
    frequency: int = probes.DEFAULT_FREQUENCY
    source: str = ""  # The interface (or address) the router pings from; "" for the one on its way there


@dataclass
class Job:
    """Everything for one router."""
    router: str
    label: str
    address: str
    names: list = field(default_factory=list)
    items: list = field(default_factory=list)


class ProbeThread(StoppableThread):
    """Logs in to each router once, reads its IP SLA configuration, then adds (or takes away) its probes: a probe
    already pinging the same address in the same VRF is used, not made again."""
    item_done = pyqtSignal(object, bool, str)  # Item, ok, what happened
    note = pyqtSignal(str)

    def __init__(self, jobs, make_pusher, adding, save, parent=None):
        super().__init__(parent)
        self.jobs, self.make_pusher, self.adding, self.save = jobs, make_pusher, adding, save

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for job in self.jobs:
                if self.stopping:
                    break
                try:
                    self.send(pusher, job)
                except Exception as error:
                    log.exception("IP SLA probes on %s failed", job.address)
                    for item in job.items:
                        self.item_done.emit(item, False, f"Failed: {error}")
        finally:
            pusher.close()

    def send(self, pusher, job):
        shell = pusher.shell(job.address, job.names)
        if shell is None:
            for item in job.items:
                self.item_done.emit(item, False, f"Couldn't log in to {job.label}: "
                                                 f"{pusher.problems.get(job.address, 'no reason given')}")
            return
        try:
            config = probes.parse_sla_config(shell.run("show running-config | section ip sla"))
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            pusher.forget(job.address)
            for item in job.items:
                self.item_done.emit(item, False, f"Couldn't read {job.label}'s IP SLA configuration: {error}")
            return
        changed = False
        for item in job.items:
            if self.stopping:
                break
            done = self.add(pusher, shell, job, item, config) if self.adding else \
                self.take_away(pusher, job, item, config)
            changed = changed or done
        if changed and self.save:
            ok, said = pusher.save_config(job.address, job.names)
            self.note.emit(f"{job.label}: configuration saved (write memory)." if ok else
                           f"{job.label}: write memory didn't work: {said or 'no answer'}")

    def add(self, pusher, shell, job, item, config):
        entry = probes.existing_entry(config, item.target, item.vrf)
        if entry is not None:
            held = config[entry].get("source", "")
            if item.source and not probes.same_source(held, item.source):
                self.item_done.emit(item, False, f"{job.label} already has IP SLA {entry} for it, pinging from "
                                                 f"{held or 'the interface the router picks'}: take that away first "
                                                 f"to ping from {item.source}")
                return False
            self.item_done.emit(item, True, f"{job.label} already has IP SLA {entry} for it: using that")
            return False
        try:
            ping = probes.ping_summary(shell.run(probes.ping_command(item.target, item.vrf, item.source),
                                                 timeout=PING_TIMEOUT))
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError):
            ping = ""
        entry = probes.free_entry(set(config))
        outcome = pusher.set_up(job.address, probes.setup_text(entry, item.target, item.vrf, item.tag, item.owner,
                                                               item.frequency, source=item.source))
        if outcome.transcript:
            log.info("Monitor from a Router, %s:\n%s", job.label, outcome.transcript)
        if not outcome.ok:
            if outcome.transcript:  # Part of it went in: don't leave a probe that never runs
                pusher.take_away(job.address, probes.removal_text(entry), job.names)
            self.item_done.emit(item, False, f"{job.label} refused it: {outcome.first_error}" if outcome.refused
                                else outcome.problem or "Failed")
            return False
        config[entry] = {"target": item.target, "source": item.source, "vrf": item.vrf, "tag": item.tag,
                         "scheduled": True}
        if ping.startswith("0 of"):
            text = (f"Added IP SLA {entry} on {job.label}, but its test ping got no answer ({ping}): check the "
                    f"router, VRF{' and source interface' if item.source else ''}, or the device is down")
            self.item_done.emit(item, True, text)
        else:
            self.item_done.emit(item, True, f"Added IP SLA {entry} on {job.label}" +
                                (f" (test ping: {ping})" if ping else ""))
        return True

    def take_away(self, pusher, job, item, config):
        if item.entry not in config:
            self.item_done.emit(item, True, f"IP SLA {item.entry} isn't on {job.label} any more")
            return False
        outcome = pusher.take_away(job.address, probes.removal_text(item.entry), job.names)
        if outcome.transcript:
            log.info("Monitor from a Router, removing from %s:\n%s", job.label, outcome.transcript)
        self.item_done.emit(item, outcome.ok, f"Took IP SLA {item.entry} off {job.label}" if outcome.ok
                            else outcome.first_error or "Failed")
        return outcome.ok


class ProbeDialog(QDialog):
    """Kept by the map page and shown again: devices to check from routers (top), and the probes on the routers
    (bottom)."""

    def __init__(self, page):
        super().__init__(page)
        self.page = page
        self.setWindowTitle("Monitor from a Router")
        self.resize(1000, 640)
        self.thread = None
        self.saved_logins = None
        self.items = {}  # Add table row -> device key
        self.choices = {}  # Add table row -> [(router key, VRF, why)]
        self.statuses = {}  # Device key -> what happened when last sent
        layout = QVBoxLayout(self)
        intro = QLabel("For devices this computer can't reach (behind a VRF, or with no route back here): a router on "
                       "the map that can reach one pings it with an IP SLA probe, and NOMAD reads the result over "
                       "SNMP. The probes are tagged NOMAD on the router, so everyone monitoring this map uses the "
                       "same ones. Cisco IOS / IOS XE routers and L3 switches only.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)

        adding = QGroupBox("Check from a router")
        add_layout = QVBoxLayout(adding)
        self.add_table = QTableWidget(0, len(ADD_COLUMNS))
        self.add_table.setHorizontalHeaderLabels(ADD_COLUMNS)
        self.add_table.verticalHeader().hide()
        self.add_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.add_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.add_table.horizontalHeader().setStretchLastSection(True)
        add_layout.addWidget(self.add_table, 1)
        options = QHBoxLayout()
        options.addWidget(QLabel("Ping every"))
        self.frequency_combo = QComboBox()
        for seconds in probes.FREQUENCIES:
            self.frequency_combo.addItem(monitor.duration_text(seconds), seconds)
        self.frequency_combo.setToolTip("How often the router pings each device. NOMAD reads the latest answer at "
                                        "each of its own checks, so a device is down after missing "
                                        f"{monitor.FAILS_FOR_DOWN} of the router's pings in a row.")
        options.addWidget(self.frequency_combo)
        self.save_check = QCheckBox("Save each router's configuration afterwards (write memory)")
        self.save_check.setToolTip("Unticked, a router that reloads comes back without the probes. Ticked, write "
                                   "memory also saves anything else changed on the router and not yet saved.")
        options.addWidget(self.save_check)
        options.addStretch(1)
        add_layout.addLayout(options)
        self.login_row = LoginRow(self, getattr(page.window, "session_store", None), "Monitor from a Router")
        self.login_row.changed.connect(self.on_login_changed)
        add_layout.addWidget(self.login_row)
        add_buttons = QHBoxLayout()
        self.send_button = accent_button("Add Probes over SSH")
        self.send_button.setToolTip("Log in to each router, check it doesn't already have a probe for the device, "
                                    "ping the device from it once as a test, then add the probe.")
        self.copy_button = QPushButton("Copy Configuration")
        self.copy_button.setToolTip("Each router's lines, to paste in yourself. The probe numbers are NOMAD's guess "
                                    "of free ones: check with show ip sla summary first.")
        self.clear_button = QPushButton("Clear List")
        for button in (self.send_button, self.copy_button, self.clear_button):
            add_buttons.addWidget(button)
        add_buttons.addStretch(1)
        add_layout.addLayout(add_buttons)
        splitter.addWidget(adding)

        existing = QWidget()
        existing_layout = QVBoxLayout(existing)
        existing_layout.setContentsMargins(0, 0, 0, 0)
        heading = QHBoxLayout()
        self.found_label = QLabel()
        self.found_label.setWordWrap(True)
        heading.addWidget(self.found_label, 1)
        self.look_button = QPushButton("Look Again")
        self.look_button.setToolTip("Read the map's routers over SNMP for NOMAD's probes (anyone's).")
        self.remove_button = QPushButton("Take Away over SSH...")
        self.remove_button.setToolTip("Delete the selected probes from their routers (no ip sla N): the devices are "
                                      "then pinged from this computer again.")
        heading.addWidget(self.look_button)
        heading.addWidget(self.remove_button)
        existing_layout.addLayout(heading)
        self.probe_table = QTableWidget(0, len(PROBE_COLUMNS))
        self.probe_table.setHorizontalHeaderLabels(PROBE_COLUMNS)
        self.probe_table.verticalHeader().hide()
        self.probe_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.probe_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.probe_table.horizontalHeader().setStretchLastSection(True)
        existing_layout.addWidget(self.probe_table, 1)
        splitter.addWidget(existing)
        splitter.setSizes([360, 240])

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        bottom.addWidget(close)
        layout.addLayout(bottom)

        self.send_button.clicked.connect(self.send)
        self.copy_button.clicked.connect(self.copy_config)
        self.clear_button.clicked.connect(self.clear_list)
        self.look_button.clicked.connect(self.look_again)
        self.remove_button.clicked.connect(self.remove_selected)
        self.probe_table.itemSelectionChanged.connect(self.update_buttons)
        self.probe_table.cellDoubleClicked.connect(self.on_probe_double_clicked)
        page.monitor.probes_changed.connect(self.fill_probes)
        page.monitor.statuses_changed.connect(self.show_probe_statuses)
        self.restore_settings()
        self.fill_probes()

    # ----------------------------------------------------------------- Settings

    def restore_settings(self):
        settings = QSettings()
        frequency = settings.value("netmap/probe_frequency", probes.DEFAULT_FREQUENCY, int)
        index = self.frequency_combo.findData(frequency)
        self.frequency_combo.setCurrentIndex(index if index >= 0 else
                                             self.frequency_combo.findData(probes.DEFAULT_FREQUENCY))
        self.save_check.setChecked(settings.value("netmap/probe_save", False, bool))
        self.login_row.restore_settings(settings, "netmap/probes")

    def save_settings(self):
        settings = QSettings()
        settings.setValue("netmap/probe_frequency", self.frequency_combo.currentData())
        settings.setValue("netmap/probe_save", self.save_check.isChecked())
        self.login_row.save_settings(settings, "netmap/probes")

    def closeEvent(self, event):
        self.save_settings()
        super().closeEvent(event)

    # ----------------------------------------------------------------- Devices to add

    @property
    def network_map(self):
        return self.page.network_map

    def add_devices(self, keys):
        """Put these devices in the list to check from a router (each with the routers that should reach it)."""
        network_map = self.network_map
        if network_map is None:
            return
        present = set(self.items.values())
        for key in keys:
            device = network_map.devices.get(key)
            if device is None or key in present:
                continue
            address = device.mgmt_ip or next(iter(device.addresses), "")
            if not address:
                continue
            row = self.add_table.rowCount()
            self.add_table.insertRow(row)
            self.items[row] = key
            name = QTableWidgetItem(device.label)
            name.setFlags(name.flags() & ~Qt.ItemIsEditable)
            self.add_table.setItem(row, 0, name)
            self.add_table.setCellWidget(row, ADDRESS_COLUMN, QLineEdit(address))
            combo = QComboBox()
            choices = [(candidate.router, candidate.vrf, candidate.why)
                       for candidate in probes.candidates(network_map, address)]
            known = {(router, vrf) for router, vrf, _ in choices}
            for router in sorted(probes.readable_routers(network_map),
                                 key=lambda item: network_map.devices[item].label.lower()):
                if router != key and (router, "") not in known and not any(item[0] == router for item in choices):
                    choices.append((router, "", "picked by hand (no route to it was read)"))
            self.choices[row] = choices
            for router, vrf, _ in choices:
                label = network_map.devices[router].label
                combo.addItem(f"{label} (vrf {vrf})" if vrf else label)
            current = self.page.monitor.probes.get(key)
            if current is not None:
                index = next((index for index, (router, vrf, _) in enumerate(choices)
                              if router == current.router and vrf == current.vrf), 0)
                combo.setCurrentIndex(index)
            combo.currentIndexChanged.connect(self.on_router_changed)
            self.add_table.setCellWidget(row, ROUTER_COLUMN, combo)
            vrf_input = QLineEdit()
            vrf_input.textChanged.connect(self.on_vrf_changed)
            self.add_table.setCellWidget(row, VRF_COLUMN, vrf_input)
            source = QComboBox()
            source.setEditable(True)
            source.setToolTip("The interface the router pings from (the device answers to its address): one of the "
                              "router's in the VRF, or type another interface or address. Router picks: the "
                              "interface on its way to the device.")
            self.add_table.setCellWidget(row, SOURCE_COLUMN, source)
            for column in (WHY_COLUMN, STATUS_COLUMN):
                item = QTableWidgetItem("")
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.add_table.setItem(row, column, item)
            self.show_choice(row)
            if current is not None and current.source:
                self.set_source(row, current.source)
            if current is not None:
                self.set_row_status(row, f"Checked from {self.page.monitor.via(key)} already (IP SLA "
                                         f"{current.entry})", "muted")
            elif not choices:
                self.set_row_status(row, "No router on the map that NOMAD can put a probe on (Cisco, read over "
                                         "SNMP)", "error")
        self.add_table.resizeColumnsToContents()
        self.add_table.horizontalHeader().setSectionResizeMode(WHY_COLUMN, QHeaderView.Interactive)
        self.update_buttons()

    def sender_row(self, column):
        widget = self.sender()
        return next((row for row in self.items if self.add_table.cellWidget(row, column) is widget), None)

    def on_router_changed(self, _index):
        row = self.sender_row(ROUTER_COLUMN)
        if row is not None:
            self.show_choice(row)

    def on_vrf_changed(self, _text):
        row = self.sender_row(VRF_COLUMN)
        if row is not None:
            self.fill_sources(row)

    def show_choice(self, row):
        choice = self.choice(row)
        vrf_input = self.add_table.cellWidget(row, VRF_COLUMN)
        why = self.add_table.item(row, WHY_COLUMN)
        if choice is None:
            vrf_input.setText("")
            why.setText("")
            self.fill_sources(row)
            return
        _, vrf, reason = choice
        vrf_input.setText(vrf)
        vrf_input.setPlaceholderText("global")
        why.setText(reason)
        why.setToolTip(reason)
        self.fill_sources(row)  # Also when the VRF was already that: another router's interfaces

    def fill_sources(self, row):
        """The Source Interface list: Router picks, then the router's interfaces in the row's VRF. One typed in is kept."""
        combo = self.add_table.cellWidget(row, SOURCE_COLUMN)
        if combo is None:
            return
        typed = self.source(row)
        choice = self.choice(row)
        network_map = self.network_map
        device = network_map.devices.get(choice[0]) if choice is not None and network_map is not None else None
        vrf = self.add_table.cellWidget(row, VRF_COLUMN).text().strip()
        combo.blockSignals(True)
        combo.clear()
        combo.addItem(ROUTER_PICKS, "")
        for port, ip in (probes.source_choices(device, vrf) if device is not None else []):
            combo.addItem(f"{port} ({ip})", port)
        combo.setCurrentIndex(0)
        combo.blockSignals(False)
        if typed:
            self.set_source(row, typed)

    def set_source(self, row, source):
        """Show this interface or address in Source Interface: its entry in the list (by name or address), else as typed."""
        combo = self.add_table.cellWidget(row, SOURCE_COLUMN)
        for index in range(1, combo.count()):
            if probes.same_source(combo.itemData(index), source) or combo.itemText(index).endswith(f"({source})"):
                combo.setCurrentIndex(index)
                return
        combo.setEditText(source)

    def source(self, row):
        """The interface (or address) the row's probe pings from, or "" for the router to pick."""
        combo = self.add_table.cellWidget(row, SOURCE_COLUMN)
        text = combo.currentText().strip() if combo is not None else ""
        index = combo.findText(text) if text else -1
        return (combo.itemData(index) or "") if index >= 0 else text

    def choice(self, row):
        combo = self.add_table.cellWidget(row, ROUTER_COLUMN)
        choices = self.choices.get(row, [])
        index = combo.currentIndex() if combo is not None else -1
        return choices[index] if 0 <= index < len(choices) else None

    def set_row_status(self, row, text, kind="info"):
        item = self.add_table.item(row, STATUS_COLUMN)
        if item is not None:
            item.setText(text)
            item.setToolTip(text)
            item.setForeground(QColor(COLORS[kind if kind in ("error", "warning", "success", "muted") else "text"]))

    def clear_list(self):
        if self.thread is not None:
            return
        self.add_table.setRowCount(0)
        self.items, self.choices = {}, {}
        self.update_buttons()

    def planned(self):
        """[Job] for the list's rows, grouped by router; or None after saying what's wrong."""
        network_map = self.network_map
        jobs = {}
        owner = probes.make_owner()
        frequency = self.frequency_combo.currentData()
        for row, key in sorted(self.items.items()):
            device = network_map.devices.get(key) if network_map is not None else None
            choice = self.choice(row)
            if device is None or choice is None:
                continue
            router, _, _ = choice
            target = self.add_table.cellWidget(row, ADDRESS_COLUMN).text().strip()
            vrf = self.add_table.cellWidget(row, VRF_COLUMN).text().strip()
            source = self.source(row)
            if not probes.address_ok(target):
                set_hint(self.status_label, f"{device.label}: '{target}' isn't an IP address.", "error")
                return None
            if " " in vrf:
                set_hint(self.status_label, f"{device.label}: a VRF name has no spaces.", "error")
                return None
            if " " in source:
                set_hint(self.status_label, f"{device.label}: write the interface to ping from without spaces "
                                            "(Loopback0, Gi0/1), or give its address.", "error")
                return None
            holder = network_map.devices[router]
            job = jobs.get(router)
            if job is None:
                job = jobs[router] = probes_job(router, holder)
            job.items.append(Item(row, key, device.label, target, vrf, tag=probes.make_tag(device.label),
                                  owner=owner, frequency=frequency, source=source))
        return list(jobs.values())

    def copy_config(self):
        jobs = self.planned()
        if not jobs:
            return
        used = {}
        for probe in self.discovered():
            used.setdefault(probe.router, set()).add(probe.entry)
        parts = []
        for job in jobs:
            taken = used.setdefault(job.router, set())
            lines = [f"! {job.label} ({job.address})"]
            for item in job.items:
                entry = probes.free_entry(taken)
                taken.add(entry)
                lines.append(probes.setup_text(entry, item.target, item.vrf, item.tag, item.owner, item.frequency,
                                               source=item.source))
            parts.append("\n".join(lines))
        QApplication.clipboard().setText("\n\n".join(parts) + "\n")
        set_hint(self.status_label, "Copied each router's lines. Check the probe numbers are free (show ip sla "
                                    "summary) before pasting.", "info")

    # ----------------------------------------------------------------- Sending

    def on_login_changed(self):
        self.saved_logins = None

    def logins(self):
        if self.saved_logins is None:
            self.saved_logins = self.login_row.logins(self.status_label)
        return self.saved_logins

    def send(self):
        if self.thread is not None:
            self.thread.stop()
            set_hint(self.status_label, "Stopping after the router being sent to now...", "warning")
            return
        jobs = self.planned()
        if jobs is None:
            return
        if not jobs:
            set_hint(self.status_label, "Right-click devices on the map > Monitor from a Router to list them here.",
                     "warning")
            return
        lines = []
        for job in jobs:
            for item in job.items:
                lines.append(f"{item.label} ({item.target}) from {job.label}" +
                             (f" in vrf {item.vrf}" if item.vrf else "") +
                             (f", pinging from {item.source}" if item.source else ""))
        saved = ("Each router's configuration is saved afterwards (write memory)." if self.save_check.isChecked()
                 else "Nothing is saved (write memory is off): a router that reloads comes back without them.")
        question = (f"Add {'these probes' if len(lines) > 1 else 'this probe'} over SSH?\n\n" + "\n".join(lines) +
                    f"\n\nEach router pings its devices every "
                    f"{monitor.duration_text(self.frequency_combo.currentData())}. {saved}")
        if QMessageBox.question(self, "Add Probes over SSH", question,
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self.start(jobs, True)

    def remove_selected(self):
        if self.thread is not None:
            return
        rows = sorted({index.row() for index in self.probe_table.selectedIndexes()})
        chosen, keys = [], {}
        for row in rows:
            probe = self.probe_table.item(row, 0).data(Qt.UserRole)
            if probe is not None:
                chosen.append(probe)
                keys[id(probe)] = self.probe_table.item(row, 0).data(Qt.UserRole + 1) or ""
        if not chosen:
            return
        network_map = self.network_map
        if network_map is None:
            return
        jobs = {}
        lines = []
        for probe in chosen:
            holder = network_map.devices.get(probe.router)
            if holder is None:
                continue
            job = jobs.get(probe.router)
            if job is None:
                job = jobs[probe.router] = probes_job(probe.router, holder)
            device = keys.get(id(probe), "")
            label = network_map.devices[device].label if device in network_map.devices else                 probe.device_label or probe.target
            job.items.append(Item(-1, device, label, probe.target, probe.vrf, entry=probe.entry))
            lines.append(f"IP SLA {probe.entry} on {holder.label}: {label} ({probe.target})")
        question = ("Take these probes off their routers over SSH (no ip sla N)?\n\n" + "\n".join(lines) +
                    "\n\nThe devices are then pinged from this computer again, for everyone monitoring the map.")
        if QMessageBox.question(self, "Take Away over SSH", question,
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self.start(list(jobs.values()), False)

    def start(self, jobs, adding):
        logins = self.logins()
        if logins is None:
            return
        self.save_settings()
        thread = ProbeThread(jobs, self.login_row.pusher_maker(logins), adding,
                             adding and self.save_check.isChecked(), self)
        thread.item_done.connect(self.on_item_done)
        thread.note.connect(self.on_note)
        thread.finished.connect(self.on_finished)
        self.thread = thread
        self.page.check_threads.append(thread)
        count = sum(len(job.items) for job in jobs)
        what = "Adding" if adding else "Taking away"
        set_hint(self.status_label, f"{what} {count} probe{'s' if count != 1 else ''} on {len(jobs)} "
                                    f"router{'s' if len(jobs) != 1 else ''} over SSH...", "info")
        self.update_buttons()
        thread.start()

    def on_item_done(self, item, ok, text):
        if item.row >= 0 and self.items.get(item.row) == item.device:
            warning = "no answer" in text
            self.set_row_status(item.row, text, "error" if not ok else "warning" if warning else "success")
        set_hint(self.status_label, f"{item.label}: {text}", "info" if ok else "error")

    def on_note(self, text):
        set_hint(self.status_label, text, "error" if "didn't" in text else "info")

    def on_finished(self):
        thread = self.thread
        self.thread = None
        if thread in self.page.check_threads:
            self.page.check_threads.remove(thread)
        self.update_buttons()
        self.look_again()

    # ----------------------------------------------------------------- Probes on the routers

    def look_again(self):
        if self.network_map is None:
            return
        self.page.monitor.discover()
        self.fill_probes()

    def discovered(self):
        discovery = self.page.monitor.discovery
        network_map = self.network_map
        if discovery is None or network_map is None:
            return []
        return [probe for probe in discovery.probes if probe.router in network_map.devices
                and network_map.devices[probe.router].mgmt_ip == probe.address]

    def fill_probes(self):
        monitor_ = self.page.monitor
        network_map = self.network_map
        self.probe_table.setRowCount(0)
        if network_map is None:
            self.found_label.setText("No map open.")
            self.update_buttons()
            return
        found = self.discovered()
        devices = {(item.router, item.entry): key for key, item in monitor_.probes.items()}
        for probe in sorted(found, key=lambda item: (network_map.devices[item.router].label.lower(), item.entry)):
            row = self.probe_table.rowCount()
            self.probe_table.insertRow(row)
            key = devices.get((probe.router, probe.entry), "")
            if key:
                device = network_map.devices[key].label
            else:
                owner = next((item.label for item in network_map.devices.values() if item.owns(probe.target)), "")
                device = (f"{owner} (another probe is used for it)" if owner else
                          f"Not on the map ({probe.device_label or 'no tag'})")
            values = [device, probe.target, network_map.devices[probe.router].label, str(probe.entry),
                      probe.vrf or "global", probe.source or ROUTER_PICKS,
                      monitor.duration_text(probe.frequency) if probe.frequency else "",
                      "", probe.owner]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.UserRole, probe)
                    item.setData(Qt.UserRole + 1, key)
                self.probe_table.setItem(row, column, item)
        discovery = monitor_.discovery
        if monitor_.discovering:
            text = "Reading the map's routers for probes..."
        elif discovery is None:
            text = "Not looked yet: Look Again reads the map's routers for NOMAD's probes."
        else:
            text = (f"{len(found)} NOMAD probe{'' if len(found) == 1 else 's'} on {len(discovery.read)} router"
                    f"{'' if len(discovery.read) == 1 else 's'} read over SNMP.")
            if discovery.problems:
                names = ", ".join(sorted(network_map.devices[key].label for key in discovery.problems
                                         if key in network_map.devices))
                text += f" Couldn't read {names}."
        self.found_label.setText(text)
        self.show_probe_statuses()
        self.probe_table.resizeColumnsToContents()
        self.update_buttons()

    def show_probe_statuses(self):
        monitor_ = self.page.monitor
        for row in range(self.probe_table.rowCount()):
            key = self.probe_table.item(row, 0).data(Qt.UserRole + 1)
            state = monitor_.status(key) if key else None
            if state is None:
                text = "" if key else "Not used"
                if key and not monitor_.running:
                    text = "Tick Monitor to check"
            elif state.status == monitor.UNKNOWN:
                text = f"Can't check: {state.problem}" if state.problem else "Being checked"
            elif state.status == monitor.DOWN:
                text = "Down"
            else:
                text = f"Up ({'<1' if (state.rtt or 0) < 1 else state.rtt} ms)" if state.rtt is not None else "Up"
            item = self.probe_table.item(row, PROBE_STATUS_COLUMN)
            if item is not None and item.text() != text:
                item.setText(text)
                item.setToolTip(text)

    def on_probe_double_clicked(self, row, _column):
        key = self.probe_table.item(row, 0).data(Qt.UserRole + 1)
        if key:
            self.page.show_in(self.page.view, [key])

    def update_buttons(self):
        busy = self.thread is not None
        self.send_button.setText("Stop" if busy else "Add Probes over SSH")
        self.send_button.setEnabled(busy or bool(self.items))
        self.copy_button.setEnabled(not busy and bool(self.items))
        self.clear_button.setEnabled(not busy and bool(self.items))
        self.remove_button.setEnabled(not busy and bool(self.probe_table.selectedIndexes()))
        self.look_button.setEnabled(not busy and self.network_map is not None)


def probes_job(router, device):
    return Job(router, device.label, device.mgmt_ip, [name for name in [device.name, *device.addresses] if name])
