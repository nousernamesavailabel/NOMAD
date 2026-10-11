"""Port Mirroring page: SPAN, RSPAN and ERSPAN on Cisco IOS / IOS-XE switches, set up and taken away in a click.

Choose what to mirror (ports or VLANs of a switch, or a host's port) and where to (a port, this PC, or an address),
and NOMAD picks the kind: SPAN on one switch, RSPAN over switched links (its VLAN carried along the way), ERSPAN
through routers. Plan reads the switches' own sessions over SSH first, so a free session number is used and a port
that's busy isn't, and lists what each switch gets. Set Up sends it all over SSH (or Send to Session types one
switch's lines into a terminal session while you watch). Each switch can take its part away itself after a while
(an EEM applet), and every mirror set up is listed below with what takes it away again.

The map's right-click menus fill this page in (Mirror This Port, Mirror to This Port, Mirror This Host).
"""
import datetime
import functools
import logging
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, \
    QDialogButtonBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, \
    QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, \
    QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget

from ..netmap import configpush, macfind, mirror
from ..netmap.mirror import BOTH, DIRECTION_NAMES, DIRECTIONS, ERSPAN, KIND_TITLES, ROLE_NAMES, RSPAN, SPAN, \
    TO_ADDRESS, TO_PORT, Request, Source
from ..netmap.model import ROUTER, SWITCH, port_key, port_sort_key
from ..netmap.vlans import ERROR, INFO, WARNING, port_info
from ..oui import format_mac, normalize_mac
from ..terminal.hostkeys import KnownHosts
from ..terminal.sessions import AUTH_PASSWORD, SSH, Session
from .common import StoppableThread, read_only_table, release_thread, set_hint
from .credential_dialogs import CredentialPicker
from .prompts import SecretDialog
from .session_send import SessionSender
from .theme import COLORS, accent_button, monospace_font
from .vault_dialog import ensure_unlocked

log = logging.getLogger(__name__)

READ_WORKERS = 4
CHECK_EVERY = 30000  # ms between looks for mirrors past their time that NOMAD has to take away
ASK_LOGIN = "A user name and password asked for"
DEFAULT_MINUTES = 60
SEVERITY_COLORS = {ERROR: "error", WARNING: "warning", INFO: "muted"}
KIND_CHOICES = [("Auto", ""), ("SPAN (same device)", SPAN), ("RSPAN (over switched links)", RSPAN),
                ("ERSPAN (over IP)", ERSPAN)]
STEP_COLUMNS = ["Device", "Role", "Session", "Changes", "Status", ""]
RECORD_COLUMNS = ["Name", "Kind", "What", "Devices", "Set Up", "Removes Itself", "State"]
SESSION_COLUMNS = ["Device", "Session", "Type", "Details", "Made By"]
SETUP, UNDO = "setup", "undo"


def local_address_toward(address):
    """This PC's address that reaches address (no packet is sent), or ""."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect((address, 9))
            return probe.getsockname()[0]
    except OSError:
        return ""


def is_wireless(adapter):
    """A Wi-Fi adapter: its MAC is behind an access point, never on a switch port of its own."""
    text = f"{adapter.name} {getattr(adapter, 'description', '')}".lower()
    return bool(re.search(r"wi-?fi|wireless|wlan|802\.11", text))


def can_capture_here(record):
    """Whether a mirror sends its copies to this PC: over ERSPAN, or out of a port this PC's adapter is on."""
    return record.to_this_pc and ((record.kind == ERSPAN and bool(record.origin_ip)) or bool(record.adapter))


def when_text(iso):
    if not iso:
        return ""
    try:
        moment = datetime.datetime.fromisoformat(iso)
    except ValueError:
        return iso
    today = datetime.date.today()
    return moment.strftime("%H:%M") if moment.date() == today else moment.strftime("%Y-%m-%d %H:%M")


@dataclass
class Job:
    """One switch's lines to send, for PushThread."""
    index: int  # The plan's step, or the record's
    address: str
    names: list
    text: str
    applet: str = ""


class ReadThread(StoppableThread):
    """Reads a few switches' mirror sessions over SSH at once."""
    state_read = pyqtSignal(str, object)  # Device key, mirror.SwitchState

    def __init__(self, targets, make_pusher, parent=None):
        super().__init__(parent)
        self.targets, self.make_pusher = targets, make_pusher  # targets: [(key, address, names)]

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            def read(target):
                key, address, names = target
                if self.stopping:
                    return
                try:
                    state = pusher.read_state(address, names) if address else \
                        mirror.SwitchState(problem="it has no address.")
                except Exception as error:  # One switch's trouble shouldn't stop the rest
                    log.exception("Reading %s's mirror sessions failed", address)
                    state = mirror.SwitchState(problem=str(error))
                if not self.stopping:
                    self.state_read.emit(key, state)
            with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(self.targets)))) as executor:
                list(executor.map(read, self.targets))
        finally:
            pusher.close()


class PushThread(StoppableThread):
    """Sends each switch its lines in turn: setting up stops at the first switch that refuses; taking away carries
    on."""
    step_started = pyqtSignal(int)
    step_done = pyqtSignal(int, object)  # Job index, configpush.Outcome

    def __init__(self, jobs, make_pusher, setting_up, parent=None):
        super().__init__(parent)
        self.jobs, self.make_pusher, self.setting_up = jobs, make_pusher, setting_up
        self.failed = False

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for job in self.jobs:
                if self.stopping:
                    break
                self.step_started.emit(job.index)
                try:
                    if self.setting_up:
                        outcome = pusher.set_up(job.address, job.text, job.applet, job.names)
                    else:
                        outcome = pusher.take_away(job.address, job.text, job.names)
                except Exception as error:
                    log.exception("Sending to %s failed", job.address)
                    outcome = configpush.Outcome(problem=str(error))
                self.step_done.emit(job.index, outcome)
                if self.setting_up and not outcome.ok:
                    self.failed = True
                    break
        finally:
            pusher.close()


class PortPicker(QDialog):
    """The ports of a switch to choose from, each with what NOMAD knows about it."""

    def __init__(self, parent, network_map, key, title, multiple=True, chosen=()):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(560, 480)
        layout = QVBoxLayout(self)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find a port, VLAN or device")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.textChanged.connect(self.filter)
        layout.addWidget(self.find_input)
        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection if multiple
                                   else QAbstractItemView.SingleSelection)
        wanted = {port_key(port) for port in chosen}
        for port, text in switch_ports(network_map, key):
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, port)
            self.list.addItem(item)
            if port_key(port) in wanted:
                item.setSelected(True)
        self.list.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.list, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.find_input.setFocus()

    def filter(self, text):
        text = text.strip().lower()
        for row in range(self.list.count()):
            item = self.list.item(row)
            item.setHidden(bool(text) and text not in item.text().lower())

    def ports(self):
        return [item.data(Qt.UserRole) for item in self.list.selectedItems()]


def switch_ports(network_map, key):
    """[(port, "Gi1/0/5 - access VLAN 10 - printer")] for a switch, from what the map knows of its ports."""
    device = network_map.devices.get(key)
    if device is None:
        return []
    ports = {}
    for name in list(device.port_vlans) + list(device.port_status):
        ports.setdefault(port_key(name), name)
    links = {}
    for link in network_map.links_of(key):
        other = network_map.devices.get(link.other(key))
        port = link.port_on(key)
        ports.setdefault(port_key(port), port)
        links[port_key(port)] = other.label if other is not None else link.other(key)
    hosts = {}
    for host in network_map.hosts:
        if host.device == key:
            ports.setdefault(port_key(host.port), host.port)
            hosts.setdefault(port_key(host.port), []).append(host.name or host.ip or host.mac)
    found = []
    for port in sorted(ports.values(), key=port_sort_key):
        if port_key(port).startswith(("vl", "lo", "tu", "nu")):
            continue  # VLAN interfaces, loopbacks, tunnels: not ports that can be mirrored to
        parts = [port]
        info = port_info(device, port)
        if info.get("mode") == "trunk":
            parts.append("trunk")
        elif info.get("vlan"):
            parts.append(f"VLAN {info['vlan']}")
        status = mirror.port_oper(device, port)
        if status and status != "up":
            parts.append(status)
        if port_key(port) in links:
            parts.append(f"to {links[port_key(port)]}")
        names = hosts.get(port_key(port), [])
        if names:
            parts.append(", ".join(names[:3]) + (f" and {len(names) - 3} more" if len(names) > 3 else ""))
        found.append((port, " - ".join(parts)))
    return found


class MirrorTab(QWidget):
    def __init__(self, window, store=None):
        super().__init__(window)
        self.window = window
        self.sessions = getattr(window, "session_store", None)  # Saved sessions and credentials, for SSH
        self.mirrors = store if store is not None else mirror.MirrorStore.default()
        self.shell_factory = configpush.ConfigShell  # Tests swap in fake switches
        self.ssh_user = ""
        self.request = None
        self.plan = None
        self.plan_tag = ""
        self.pc_note = ""  # How This PC was turned into a destination
        self.states = {}  # Device key -> SwitchState, read for the plan
        self.statuses = {}  # Plan step index -> status text
        self.record = None  # The MirrorRecord of the plan, once anything of it was sent
        self.reader = None
        self.reader_purpose = ""
        self.reader_states = {}
        self.pusher_thread = None
        self.push_record = None  # The record PushThread is sending for
        self.push_kind = SETUP
        self.push_indexes = []  # Its jobs' record step indexes
        self.saved_logins = None  # (logins, enable secret) of the last Plan, for Set Up straight after
        self.switch_states = {}  # Device key -> SwitchState from the last Check Now
        self.session_sender = SessionSender(self, window, None)
        self.step_menus = {}
        self.record_menus = {}
        self.init_ui()
        self.session_sender.status_label = self.status_label
        self.timer = QTimer(self)
        self.timer.setInterval(CHECK_EVERY)
        self.timer.timeout.connect(self.check_overdue)
        self.timer.start()
        page = self.map_page()
        if page is not None:
            page.map_shown.connect(self.on_map_shown)
        self.fill_records()
        self.on_map_shown()

    # ----------------------------------------------------------------- Building the page

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Copy a port's traffic (or a VLAN's) to where it can be captured, on Cisco IOS / IOS-XE "
                       "switches and routers: SPAN to a port of the same device, RSPAN to another switch over switched "
                       "links, or ERSPAN over IP to an address, another device or this PC. NOMAD picks the kind, "
                       "checks the ports, sends it, and takes it away again (or the devices do, when the time's up).")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.map_label = QLabel()
        self.map_label.setWordWrap(True)
        layout.addWidget(self.map_label)

        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.make_new_box())
        splitter.addWidget(self.make_mirrors_box())
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.update_buttons()

    def make_new_box(self):
        box = QGroupBox("New Mirror")
        layout = QVBoxLayout(box)
        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        # What to mirror
        grid.addWidget(QLabel("Mirror on:"), 0, 0)
        self.source_combo = QComboBox()
        self.source_combo.setToolTip("The switch or router whose ports (or VLANs) are copied")
        self.source_combo.currentIndexChanged.connect(self.on_source_changed)
        grid.addWidget(self.source_combo, 0, 1)
        self.sources_table = QTableWidget(0, 2)
        self.sources_table.setHorizontalHeaderLabels(["Port or VLAN", "Traffic"])
        self.sources_table.verticalHeader().setVisible(False)
        self.sources_table.horizontalHeader().setStretchLastSection(True)
        self.sources_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.sources_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.sources_table.setMaximumHeight(110)
        self.sources_table.setColumnWidth(0, 160)
        grid.addWidget(self.sources_table, 1, 0, 1, 2)
        source_buttons = QHBoxLayout()
        for text, slot, tip in (("Add Ports...", self.add_ports, "Choose ports of the device to mirror"),
                                ("Add VLAN...", self.add_vlan, "Mirror a VLAN's traffic on the device (all its ports)"),
                                ("Add Host...", self.add_host, "Mirror the port a device is on: its MAC, IP address "
                                                               "or name, as the map has it"),
                                ("Remove", self.remove_sources, "")):
            button = QPushButton(text)
            button.setToolTip(tip)
            button.clicked.connect(slot)
            source_buttons.addWidget(button)
            if text == "Remove":
                self.remove_source_button = button
        source_buttons.addStretch()
        grid.addLayout(source_buttons, 2, 0, 1, 2)

        # Where to
        grid.addWidget(QLabel("Copies go to:"), 0, 2)
        to_box = QWidget()
        to_layout = QGridLayout(to_box)
        to_layout.setContentsMargins(0, 0, 0, 0)
        self.to_group = QButtonGroup(self)
        self.to_port_radio = QRadioButton("A switch port")
        self.to_pc_radio = QRadioButton("This PC")
        self.to_address_radio = QRadioButton("An address (ERSPAN)")
        for index, radio in enumerate((self.to_port_radio, self.to_pc_radio, self.to_address_radio)):
            self.to_group.addButton(radio, index)
            to_layout.addWidget(radio, index, 0)
        self.to_port_radio.setChecked(True)
        self.to_group.buttonClicked.connect(self.on_to_changed)
        port_row = QHBoxLayout()
        self.dest_combo = QComboBox()
        self.dest_combo.currentIndexChanged.connect(self.on_dest_changed)
        self.dest_port_combo = QComboBox()
        self.dest_port_combo.setEditable(True)
        self.dest_port_combo.setToolTip("An edge port with nothing on it (or the capture box): it stops being a "
                                        "normal port while it's a mirror destination")
        self.dest_port_combo.currentTextChanged.connect(self.plan_outdated)
        port_row.addWidget(self.dest_combo, 1)
        port_row.addWidget(self.dest_port_combo, 1)
        to_layout.addLayout(port_row, 0, 1)
        self.adapter_combo = QComboBox()
        self.adapter_combo.setToolTip("This PC's network adapter to send the copies to. Plugged into a free port of "
                                      "its own (a second adapter), the copies go to that port; on the adapter this "
                                      "PC reaches the devices through, ERSPAN sends them to its address, so the port "
                                      "keeps working.")
        self.adapter_combo.currentIndexChanged.connect(self.plan_outdated)
        to_layout.addWidget(self.adapter_combo, 1, 1)
        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("The capture box's IP address, such as 10.1.1.50")
        self.address_input.textChanged.connect(self.plan_outdated)
        to_layout.addWidget(self.address_input, 2, 1)
        grid.addWidget(to_box, 1, 2, 1, 2)

        layout.addLayout(grid)

        options = QHBoxLayout()
        options.addWidget(QLabel("Kind:"))
        self.kind_combo = QComboBox()
        for text, value in KIND_CHOICES:
            self.kind_combo.addItem(text, value)
        self.kind_combo.currentIndexChanged.connect(self.plan_outdated)
        options.addWidget(self.kind_combo)
        options.addWidget(QLabel("Name:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Optional, such as printer trace")
        self.name_input.setMaximumWidth(200)
        options.addWidget(self.name_input)
        self.remove_check = QCheckBox("Remove after")
        self.remove_check.setChecked(True)
        self.remove_check.setToolTip("Each device takes its part away itself when the time's up (an EEM applet with a "
                                     "countdown), even if this PC has gone. A device that refuses the applet has "
                                     "NOMAD take it away when the time's up, while NOMAD is open.")
        self.minutes_input = QSpinBox()
        self.minutes_input.setRange(1, mirror.MAX_MINUTES)
        self.minutes_input.setValue(DEFAULT_MINUTES)
        self.minutes_input.setSuffix(" min")
        self.remove_check.toggled.connect(self.minutes_input.setEnabled)
        self.remove_check.toggled.connect(self.plan_outdated)
        self.minutes_input.valueChanged.connect(self.plan_outdated)
        options.addWidget(self.remove_check)
        options.addWidget(self.minutes_input)
        self.more_button = QToolButton()
        self.more_button.setText("More Options")
        self.more_button.setCheckable(True)
        self.more_button.toggled.connect(self.show_more)
        options.addWidget(self.more_button)
        options.addStretch()
        layout.addLayout(options)

        self.more_panel = QWidget()
        more = QGridLayout(self.more_panel)
        more.setContentsMargins(0, 0, 0, 0)
        self.session_input = self.number_input(0, mirror.MAX_SESSION, "Auto",
                                               "The session number on every device (Auto: the first free one on each, "
                                               "from what Plan reads)")
        self.rspan_input = self.number_input(0, 4094, "Auto", "RSPAN's VLAN: one used for nothing else (Auto: the "
                                                              "first VLAN no device on the map has, from 999 down)")
        self.erspan_input = self.number_input(0, mirror.MAX_ERSPAN_ID, "Auto", "The ERSPAN ID (session ID) both ends "
                                                                               "use")
        self.ingress_input = self.number_input(0, 4094, "Off", "The device on the destination port still reaches the "
                                                               "network in this VLAN (ingress untagged vlan), as well "
                                                               "as getting the copies")
        self.origin_combo = QComboBox()
        self.origin_combo.setEditable(True)
        self.origin_combo.setToolTip("ERSPAN: the source device's address its GRE packets come from (a loopback or "
                                     "VLAN interface it has; blank: its management address)")
        self.origin_combo.currentTextChanged.connect(self.plan_outdated)
        self.vrf_input = QLineEdit()
        self.vrf_input.setPlaceholderText("Global")
        self.vrf_input.setToolTip("ERSPAN: the VRF the GRE packets go in (blank: the global routing table)")
        self.vrf_input.textChanged.connect(self.plan_outdated)
        self.replicate_check = QCheckBox("Keep VLAN tags (encapsulation replicate)")
        self.replicate_check.setToolTip("SPAN: copies keep their 802.1Q tags, and CDP, STP and the like are copied too")
        self.replicate_check.toggled.connect(self.plan_outdated)
        for row, (label, widget) in enumerate((("Session number:", self.session_input),
                                               ("RSPAN VLAN:", self.rspan_input),
                                               ("ERSPAN ID:", self.erspan_input))):
            more.addWidget(QLabel(label), row, 0)
            more.addWidget(widget, row, 1)
        for row, (label, widget) in enumerate((("Origin address:", self.origin_combo), ("VRF:", self.vrf_input),
                                               ("Destination device on VLAN:", self.ingress_input))):
            more.addWidget(QLabel(label), row, 2)
            more.addWidget(widget, row, 3)
        more.addWidget(self.replicate_check, 3, 0, 1, 4)
        more.setColumnStretch(4, 1)
        self.more_panel.setVisible(False)
        layout.addWidget(self.more_panel)

        login = QHBoxLayout()
        self.read_check = QCheckBox("Read the devices first")
        self.read_check.setChecked(True)
        self.read_check.setToolTip("Plan logs in over SSH and reads each device's mirror sessions (show monitor "
                                   "session all), so a free session number is used and a busy port isn't")
        login.addWidget(self.read_check)
        login.addWidget(QLabel("Log in with:"))
        if self.sessions is not None:
            default = self.sessions.credentials.default
            self.login_picker = CredentialPicker(self, self.sessions, SSH, default.id if default else "", ASK_LOGIN)
            self.login_picker.combo.setToolTip("For devices without a saved SSH session: a saved credential "
                                               "(Manage... to add one), or a user name and password asked for once.")
            login.addWidget(self.login_picker, 2)
        else:
            self.login_picker = None
        login.addWidget(QLabel("Enable password:"))
        self.enable_input = QLineEdit()
        self.enable_input.setEchoMode(QLineEdit.Password)
        self.enable_input.setPlaceholderText("If they log in at >")
        self.enable_input.setToolTip("For devices that log in at the > prompt. Kept only while NOMAD is open.")
        login.addWidget(self.enable_input, 1)
        self.trust_check = QCheckBox("Trust new SSH keys")
        self.trust_check.setChecked(True)
        login.addWidget(self.trust_check)
        layout.addLayout(login)

        buttons = QHBoxLayout()
        self.plan_button = accent_button("Plan")
        self.plan_button.setToolTip("Read the devices and work out what each one gets (nothing is changed)")
        self.plan_button.clicked.connect(self.start_plan)
        buttons.addWidget(self.plan_button)
        self.setup_button = QPushButton("Set Up")
        self.setup_button.setToolTip("Send every device its lines over SSH, then check they took")
        self.setup_button.clicked.connect(self.set_up)
        buttons.addWidget(self.setup_button)
        self.copy_all_button = QPushButton("Copy All")
        self.copy_all_button.setToolTip("Every device's lines and what takes them away, to paste somewhere")
        self.copy_all_button.clicked.connect(self.copy_all)
        buttons.addWidget(self.copy_all_button)
        self.export_button = QPushButton("Export...")
        self.export_button.clicked.connect(self.export_all)
        buttons.addWidget(self.export_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        plan_split = QSplitter(Qt.Horizontal)
        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.why_label = QLabel()
        self.why_label.setWordWrap(True)
        left_layout.addWidget(self.why_label)
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        self.findings_list.setMaximumHeight(80)
        left_layout.addWidget(self.findings_list)
        self.steps_table = read_only_table(STEP_COLUMNS)
        self.steps_table.setMinimumHeight(110)
        self.steps_table.itemSelectionChanged.connect(self.show_preview)
        left_layout.addWidget(self.steps_table, 1)
        plan_split.addWidget(left)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        preview_row = QHBoxLayout()
        self.preview_combo = QComboBox()
        self.preview_combo.addItem("Lines to set it up", SETUP)
        self.preview_combo.addItem("Lines to take it away", UNDO)
        self.preview_combo.currentIndexChanged.connect(self.show_preview)
        preview_row.addWidget(self.preview_combo, 1)
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_preview)
        preview_row.addWidget(self.copy_button)
        right_layout.addLayout(preview_row)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        right_layout.addWidget(self.preview, 1)
        plan_split.addWidget(right)
        plan_split.setStretchFactor(0, 3)
        plan_split.setStretchFactor(1, 2)
        layout.addWidget(plan_split, 1)
        return box

    def number_input(self, low, high, special, tip):
        spin = QSpinBox()
        spin.setRange(low, high)
        spin.setSpecialValueText(special)
        spin.setToolTip(tip)
        spin.valueChanged.connect(self.plan_outdated)
        return spin

    def make_mirrors_box(self):
        box = QGroupBox("Mirrors")
        layout = QVBoxLayout(box)
        self.records_table = read_only_table(RECORD_COLUMNS)
        self.records_table.itemSelectionChanged.connect(self.on_record_selected)
        self.records_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.records_table.customContextMenuRequested.connect(self.show_record_menu)
        layout.addWidget(self.records_table, 1)
        buttons = QHBoxLayout()
        self.check_button = QPushButton("Check Now")
        self.check_button.setToolTip("Read the devices of the mirrors listed: whether each is still there, and every "
                                     "session they have (NOMAD's or not)")
        self.check_button.clicked.connect(self.check_now)
        buttons.addWidget(self.check_button)
        self.check_all_button = QPushButton("Read All Devices")
        self.check_all_button.setToolTip("Read every switch and router on the map: the mirror sessions each one has")
        self.check_all_button.clicked.connect(self.check_all)
        buttons.addWidget(self.check_all_button)
        self.take_away_button = QPushButton("Take Away")
        self.take_away_button.setToolTip("Send each device the lines that take the mirror away, over SSH")
        self.take_away_button.clicked.connect(self.take_away)
        buttons.addWidget(self.take_away_button)
        self.session_button = QToolButton()
        self.session_button.setText("Take Away in a Session")
        self.session_button.setPopupMode(QToolButton.InstantPopup)
        session_menu = QMenu(self.session_button)
        session_menu.aboutToShow.connect(self.fill_record_session_menu)
        self.session_button.setMenu(session_menu)
        buttons.addWidget(self.session_button)
        self.capture_button = QPushButton("Capture Here")
        self.capture_button.setToolTip("Packet Capture, ready to capture (and unwrap) what the mirror sends this PC")
        self.capture_button.clicked.connect(self.capture_here)
        buttons.addWidget(self.capture_button)
        self.forget_button = QPushButton("Forget")
        self.forget_button.setToolTip("Take it off this list without touching the devices")
        self.forget_button.clicked.connect(self.forget)
        buttons.addWidget(self.forget_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.switch_label = QLabel("On the devices (from Check Now):")
        layout.addWidget(self.switch_label)
        self.sessions_table = read_only_table(SESSION_COLUMNS)
        self.sessions_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.sessions_table.customContextMenuRequested.connect(self.show_session_menu)
        layout.addWidget(self.sessions_table, 1)
        return box

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.source_combo.setFocus()

    def save_settings(self, settings):
        settings.setValue("mirror/remove", self.remove_check.isChecked())
        settings.setValue("mirror/minutes", self.minutes_input.value())
        settings.setValue("mirror/read", self.read_check.isChecked())
        settings.setValue("mirror/trust", self.trust_check.isChecked())
        settings.setValue("mirror/user", self.ssh_user)
        settings.setValue("mirror/more", self.more_button.isChecked())
        if self.login_picker is not None:
            settings.setValue("mirror/login", self.login_picker.credential_id())

    def restore_settings(self, settings):
        self.remove_check.setChecked(settings.value("mirror/remove", True, bool))
        self.minutes_input.setValue(settings.value("mirror/minutes", DEFAULT_MINUTES, int))
        self.read_check.setChecked(settings.value("mirror/read", True, bool))
        self.trust_check.setChecked(settings.value("mirror/trust", True, bool))
        self.ssh_user = settings.value("mirror/user", "", str)
        self.more_button.setChecked(settings.value("mirror/more", False, bool))
        if self.login_picker is not None and settings.contains("mirror/login"):
            self.login_picker.fill(settings.value("mirror/login", "", str))

    def shutdown(self):
        self.timer.stop()
        self.session_sender.stop_waiting()
        for thread in (self.reader, self.pusher_thread):
            if thread is not None:
                thread.stop()
                release_thread(thread)
        self.reader = self.pusher_thread = None

    def showEvent(self, event):
        super().showEvent(event)
        self.fill_adapters()

    # ----------------------------------------------------------------- The map

    def map_page(self):
        return getattr(self.window, "netmap_tab", None)

    def network_map(self):
        page = self.map_page()
        return getattr(page, "network_map", None) if page is not None else None

    def map_name(self):
        page = self.map_page()
        try:
            return page.map_name() if page is not None else ""
        except AttributeError:
            return ""

    def switches(self, kinds=(SWITCH, ROUTER)):
        """The map's devices that can mirror: switches and routers (only switches for a destination port)."""
        network_map = self.network_map()
        if network_map is None:
            return []
        return sorted((device for device in network_map.devices.values() if device.kind in kinds),
                      key=lambda device: device.label.lower())

    def on_map_shown(self):
        network_map = self.network_map()
        if network_map is None:
            set_hint(self.map_label, "No map is open on the Network Map page: crawl or open one there first. Port "
                                     "Mirroring works from the map's switches, routers, ports and links.", "warning")
        else:
            count = len(self.switches())
            set_hint(self.map_label, f"Map: {self.map_name() or 'the open map'}, {count} switches and routers.", "info")
        self.fill_switch_combo(self.source_combo)
        self.fill_switch_combo(self.dest_combo)
        self.update_buttons()

    def fill_switch_combo(self, combo):
        current = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        source = combo is self.source_combo
        combo.addItem("Choose a switch or router" if source else "Choose a switch", "")
        for device in self.switches((SWITCH, ROUTER) if source else (SWITCH,)):  # A destination port is on a switch
            label = device.label + (f" ({device.mgmt_ip})" if device.mgmt_ip and device.mgmt_ip != device.label else "")
            combo.addItem(label, device.key)
        index = combo.findData(current)
        combo.setCurrentIndex(max(0, index))
        combo.blockSignals(False)
        if source:
            self.fill_origins()
        else:
            self.fill_dest_ports()

    def fill_adapters(self):
        current = self.adapter_combo.currentData()
        snapshot = getattr(self.window, "snapshot", None)
        adapters = [adapter for adapter in (snapshot.real_adapters() if snapshot is not None else [])
                    if adapter.ipv4 and adapter.mac]
        self.adapter_combo.blockSignals(True)
        self.adapter_combo.clear()
        for adapter in adapters:
            self.adapter_combo.addItem(f"{adapter.name} ({adapter.ipv4[0].ip}, {adapter.mac})", adapter.name)
        if not adapters:
            self.adapter_combo.addItem("No adapter with an IPv4 address", "")
        self.adapter_combo.setCurrentIndex(max(0, self.adapter_combo.findData(current)))
        self.adapter_combo.blockSignals(False)

    def adapter(self):
        snapshot = getattr(self.window, "snapshot", None)
        name = self.adapter_combo.currentData()
        if snapshot is None or not name:
            return None
        return next((adapter for adapter in snapshot.real_adapters() if adapter.name == name), None)

    def on_source_changed(self, *_):
        key = self.source_combo.currentData()
        sources = self.sources()
        if sources and any(item.port for item in sources):
            self.sources_table.setRowCount(0)  # Another switch's ports
        if self.to_port_radio.isChecked() and key and not self.dest_combo.currentData():
            self.select_data(self.dest_combo, key)
        self.fill_origins()
        self.plan_outdated()

    def fill_origins(self):
        network_map, key = self.network_map(), self.source_combo.currentData()
        device = network_map.devices.get(key) if network_map is not None and key else None
        self.origin_combo.blockSignals(True)
        self.origin_combo.clear()
        self.origin_combo.addItem("")
        if device is not None:
            addresses = [device.mgmt_ip] + [item[0] for item in device.interfaces_l3]
            for address in dict.fromkeys(address for address in addresses if address):
                port = next((item[2] for item in device.interfaces_l3 if item[0] == address), "")
                self.origin_combo.addItem(address, port)
        self.origin_combo.blockSignals(False)

    def on_dest_changed(self, *_):
        self.fill_dest_ports()
        self.plan_outdated()

    def fill_dest_ports(self):
        network_map, key = self.network_map(), self.dest_combo.currentData()
        current = self.dest_port_combo.currentText()
        self.dest_port_combo.blockSignals(True)
        self.dest_port_combo.clear()
        if network_map is not None and key:
            for port, text in switch_ports(network_map, key):
                self.dest_port_combo.addItem(port, port)
                self.dest_port_combo.setItemData(self.dest_port_combo.count() - 1, text, Qt.ToolTipRole)
        self.dest_port_combo.setCurrentText(current)
        self.dest_port_combo.blockSignals(False)

    @staticmethod
    def select_data(combo, data):
        index = combo.findData(data)
        if index >= 0:
            combo.setCurrentIndex(index)

    def on_to_changed(self, *_):
        self.update_buttons()
        self.plan_outdated()

    def show_more(self, shown):
        self.more_panel.setVisible(shown)

    # ----------------------------------------------------------------- Sources

    def sources(self):
        found = []
        for row in range(self.sources_table.rowCount()):
            item = self.sources_table.item(row, 0)
            combo = self.sources_table.cellWidget(row, 1)
            source = item.data(Qt.UserRole) if item is not None else None
            if source is None:
                continue
            found.append(Source(source.port, source.vlan, combo.currentData() if combo is not None else BOTH))
        return found

    def add_source(self, source):
        for existing in self.sources():
            if (existing.vlan and existing.vlan == source.vlan) or \
                    (existing.port and port_key(existing.port) == port_key(source.port)):
                return
        row = self.sources_table.rowCount()
        self.sources_table.insertRow(row)
        item = QTableWidgetItem(f"VLAN {source.vlan}" if source.vlan else source.port)
        item.setData(Qt.UserRole, source)
        self.sources_table.setItem(row, 0, item)
        combo = QComboBox()
        for direction in DIRECTIONS:
            combo.addItem(DIRECTION_NAMES[direction], direction)
        self.select_data(combo, source.direction)
        combo.currentIndexChanged.connect(self.plan_outdated)
        self.sources_table.setCellWidget(row, 1, combo)
        self.plan_outdated()

    def add_ports(self):
        network_map, key = self.network_map(), self.source_combo.currentData()
        if network_map is None or not key:
            set_hint(self.status_label, "Choose the device to mirror on first.", "warning")
            return
        dialog = PortPicker(self, network_map, key, "Ports to Mirror",
                            chosen=[item.port for item in self.sources() if item.port])
        if dialog.exec_() != QDialog.Accepted:
            return
        for port in dialog.ports():
            self.add_source(Source(port))

    def add_vlan(self):
        if not self.source_combo.currentData():
            set_hint(self.status_label, "Choose the device to mirror on first.", "warning")
            return
        vlan, ok = QInputDialog.getInt(self, "Mirror a VLAN", "VLAN to mirror (every port of the device in it):", 1,
                                       1, 4094)
        if ok:
            self.add_source(Source(vlan=vlan, direction=mirror.RX))

    def add_host(self):
        network_map = self.network_map()
        if network_map is None:
            set_hint(self.status_label, "Open a map first: hosts are found on its devices' ports.", "warning")
            return
        text, ok = QInputDialog.getText(self, "Mirror a Host", "The device's MAC address, IP address or name:")
        if ok and text.strip():
            self.mirror_host(text.strip())

    def mirror_host(self, text):
        """Mirror the port the map has a host on: by MAC, IP address or name."""
        network_map = self.network_map()
        try:
            query = macfind.parse_query(text)
        except ValueError as error:
            set_hint(self.status_label, str(error), "error")
            return False
        found = [location for location in macfind.search_map(network_map, query) if location.device]
        if not found:
            set_hint(self.status_label, f"The map doesn't have {text} on a port. Find it with MAC Finder's "
                                        "Locate Now, then add its port here.", "warning")
            return False
        location = found[0]
        self.prefill(source=location.device, ports=[location.port])
        set_hint(self.status_label, f"{text} is on {location.switch} {location.port} (as the map last had it).",
                 "info")
        return True

    def remove_sources(self):
        rows = sorted({index.row() for index in self.sources_table.selectionModel().selectedRows()}, reverse=True)
        for row in rows:
            self.sources_table.removeRow(row)
        self.plan_outdated()

    # ----------------------------------------------------------------- Filled in from elsewhere

    def prefill(self, source=None, ports=(), vlan=0, dest=None, dest_port="", clear=True):
        """From the map: mirror ports (or a VLAN) of source, or to dest's dest_port."""
        self.on_map_shown()
        if source:
            if clear or self.source_combo.currentData() != source:
                self.sources_table.setRowCount(0)
            self.select_data(self.source_combo, source)
            for port in ports:
                self.add_source(Source(port))
            if vlan:
                self.add_source(Source(vlan=vlan, direction=mirror.RX))
        if dest:
            self.to_port_radio.setChecked(True)
            self.select_data(self.dest_combo, dest)
            self.dest_port_combo.setCurrentText(dest_port)
        self.on_to_changed()
        if source and not dest:
            set_hint(self.status_label, "Now choose where the copies go, then Plan.", "info")
        elif dest and not source:
            set_hint(self.status_label, "Now choose the device and ports to mirror, then Plan.", "info")

    # ----------------------------------------------------------------- Planning

    def plan_outdated(self, *_):
        if self.plan is not None:
            self.plan = None
            self.statuses = {}
            self.record = None
            self.fill_plan()
        self.update_buttons()

    def build_request(self):
        """The Request from the page, or None (and why in the status line)."""
        network_map = self.network_map()
        if network_map is None:
            set_hint(self.status_label, "Open a map on the Network Map page first.", "error")
            return None
        source = self.source_combo.currentData()
        if not source:
            set_hint(self.status_label, "Choose the device to mirror on.", "error")
            return None
        request = Request(source, self.sources(), kind=self.kind_combo.currentData(),
                          name=self.name_input.text().strip(), session=self.session_input.value(),
                          rspan_vlan=self.rspan_input.value(), erspan_id=self.erspan_input.value(),
                          origin_ip=self.origin_combo.currentText().strip(), vrf=self.vrf_input.text().strip(),
                          replicate=self.replicate_check.isChecked(), ingress_vlan=self.ingress_input.value(),
                          remove_after=self.minutes_input.value() if self.remove_check.isChecked() else 0)
        self.pc_note = ""
        if self.to_port_radio.isChecked():
            request.dest_device = self.dest_combo.currentData() or ""
            request.dest_port = self.dest_port_combo.currentText().strip()
        elif self.to_address_radio.isChecked():
            request.to, request.dest_ip = TO_ADDRESS, self.address_input.text().strip()
        elif not self.to_this_pc(network_map, request):
            return None
        return request

    def to_this_pc(self, network_map, request):
        """Fill in request's destination for This PC: its adapter's port if the map has it on one of its own (ERSPAN
        to its address when that's the port it reaches the switches through, so it keeps working), else ERSPAN to its
        address (on Wi-Fi, or a port the map doesn't know)."""
        adapter = self.adapter()
        if adapter is None:
            set_hint(self.status_label, "Choose this PC's adapter to send the copies to.", "error")
            return False
        request.to_this_pc = True
        request.adapter = adapter.name
        address = str(adapter.ipv4[0].ip)
        mac = format_mac(normalize_mac(adapter.mac))
        wireless = is_wireless(adapter)
        host = None if wireless else next(
            (host for host in network_map.hosts if host.mac and format_mac(normalize_mac(host.mac)) == mac
             and host.device in network_map.devices and not mirror.shared_port(network_map, host.device, host.port)),
            None)
        source = network_map.devices[request.source_device]
        reaching = local_address_toward(source.mgmt_ip) == address if source.mgmt_ip else False
        if host is not None:
            switch = network_map.devices[host.device].label
            if reaching and request.kind in ("", ERSPAN) and mirror.is_ios_xe(source) is not False:
                request.to, request.dest_ip = TO_ADDRESS, address
                self.pc_note = (f"This PC ({adapter.name}) is on {switch} {host.port} and reaches the devices "
                                f"through it, so the copies go to its address ({address}) over ERSPAN, and the port "
                                "keeps working.")
                return True
            request.dest_device, request.dest_port, request.own_port = host.device, host.port, reaching
            if reaching and not request.ingress_vlan:
                request.ingress_vlan = port_info(network_map.devices[host.device], host.port).get("vlan", 0) or 0
            self.pc_note = f"This PC ({adapter.name}) is on {switch} {host.port}: the copies go out of that port."
            return True
        if request.kind in ("", ERSPAN):
            request.to, request.dest_ip = TO_ADDRESS, address
            where = "is on Wi-Fi" if wireless else "isn't on a port the map has"
            self.pc_note = f"{adapter.name} ({address}) {where}, so the copies go to its address over ERSPAN."
            if wireless:
                self.pc_note += " They cross the Wi-Fi too: a busy port can mirror more than it carries."
            return True
        where = "is on Wi-Fi, so it has no port of its own" if wireless else f"({mac}) isn't on a port the map has"
        set_hint(self.status_label, f"{adapter.name} {where}: {KIND_TITLES[request.kind]} needs one. Choose Auto or "
                                    "ERSPAN to send the copies to its address, or A switch port.", "error")
        return False

    def involved(self, request):
        """The switches to read before planning: the source, and the destination switch."""
        keys = [request.source_device]
        if request.to == TO_PORT and request.dest_device and request.dest_device not in keys:
            keys.append(request.dest_device)
        return keys

    def start_plan(self):
        if self.busy():
            return
        request = self.build_request()
        if request is None:
            return
        self.request = request
        self.plan_tag = mirror.new_id()
        network_map = self.network_map()
        if not self.read_check.isChecked() or self.sessions is None:
            self.states = {}
            self.make_plan()
            return
        logins = self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        targets = [self.target(network_map, key) for key in self.involved(request)]
        self.start_read(targets, "plan")

    def target(self, network_map, key):
        device = network_map.devices.get(key)
        if device is None:
            return key, "", []
        names = [name for name in (device.name, *device.addresses) if name]
        return key, device.mgmt_ip, names

    def make_plan(self):
        network_map = self.network_map()
        if network_map is None or self.request is None:
            return
        try:
            self.plan = mirror.plan(network_map, self.request, self.states, applet_tag=self.plan_tag)
        except Exception as error:  # A slot that raises takes the whole program down
            log.exception("Planning the mirror failed")
            set_hint(self.status_label, f"Couldn't plan it: {error}", "error")
            return
        self.statuses = {}
        self.record = None
        self.fill_plan()
        self.show_plan_overlay()
        if self.plan.ok:
            set_hint(self.status_label, f"{KIND_TITLES[self.plan.kind]}: {len(self.plan.steps)} device"
                                        f"{'' if len(self.plan.steps) == 1 else 's'} to change. Set Up sends it all "
                                        "over SSH, or send each device's lines to a terminal session.", "success")
        else:
            set_hint(self.status_label, "It can't be set up as it is: see the problems above.", "error")
        self.update_buttons()

    def fill_plan(self):
        plan, network_map = self.plan, self.network_map()
        self.findings_list.clear()
        self.steps_table.setRowCount(0)
        self.step_menus = {}
        if plan is None or network_map is None:
            self.why_label.clear()
            self.preview.clear()
            return
        why = f"{KIND_TITLES.get(plan.kind, 'Mirror')}: {plan.why}." if plan.kind else ""
        details = []
        if plan.rspan_vlan:
            details.append(f"RSPAN VLAN {plan.rspan_vlan} through {' > '.join(mirror.device_label(network_map, key) for key in plan.route)}")
        if plan.kind == ERSPAN and plan.dest_ip:
            details.append(f"ERSPAN ID {plan.erspan_id}, from {plan.origin_ip} to {plan.dest_ip}")
        text = " ".join(filter(None, [why, "; ".join(details) + ("." if details else ""), self.pc_note]))
        set_hint(self.why_label, text, "info")
        for finding in plan.findings:
            item = QListWidgetItem(f"{ {ERROR: 'Problem', WARNING: 'Warning', INFO: 'Note'}[finding.severity]}: "
                                   f"{finding.text}")
            item.setForeground(QColor(COLORS[SEVERITY_COLORS[finding.severity]]))
            self.findings_list.addItem(item)
        steps = plan.steps if plan.ok else []
        self.steps_table.setRowCount(len(steps))
        for row, step in enumerate(steps):
            device = network_map.devices.get(step.device)
            self.steps_table.setItem(row, 0, QTableWidgetItem(f"{row + 1}. {mirror.device_label(network_map, step.device)}"
                                                              + (f" ({device.mgmt_ip})" if device is not None and device.mgmt_ip else "")))
            self.steps_table.setItem(row, 1, QTableWidgetItem(ROLE_NAMES[step.role]))
            self.steps_table.setItem(row, 2, QTableWidgetItem(str(step.session) if step.session else ""))
            changes = QTableWidgetItem(self.changes_text(step))
            changes.setToolTip(changes.text())
            self.steps_table.setItem(row, 3, changes)
            self.steps_table.setItem(row, 4, QTableWidgetItem(""))
            button = QToolButton()
            button.setText("Send")
            button.setToolTip("Type its lines into a terminal session (to watch, or for a device with Telnet only)")
            button.setPopupMode(QToolButton.InstantPopup)
            menu = QMenu(button)
            menu.aboutToShow.connect(self.fill_step_menu)
            button.setMenu(menu)
            self.step_menus[menu] = row
            self.steps_table.setCellWidget(row, 5, button)
            self.show_status(row)
        if steps:
            self.steps_table.selectRow(0)
        self.show_preview()

    def changes_text(self, step):
        parts = []
        if step.session:
            parts.append(f"session {step.session}")
        if any(line.startswith("vlan ") for line in step.lines):
            parts.append(f"VLAN {self.plan.rspan_vlan} (remote-span)")
        trunks = sum(1 for line in step.lines if "allowed vlan add" in line)
        if trunks:
            parts.append(f"{trunks} trunk{'' if trunks == 1 else 's'}")
        if step.applet:
            parts.append("removes itself")
        return ", ".join(parts)

    def show_status(self, row):
        item = self.steps_table.item(row, 4)
        if item is None:
            return
        text = self.statuses.get(row, "Not sent")
        item.setText(text)
        item.setToolTip(text)
        color = COLORS["success"] if text.startswith(("Done", "Set up")) else \
            COLORS["error"] if text.startswith(("Refused", "Failed", "Not done", "Couldn't")) else \
            COLORS["text"] if text.startswith(("Sent", "Sending", "Taken")) else COLORS["muted"]
        item.setForeground(QColor(color))

    def step(self, row):
        if self.plan is None or not self.plan.ok or not 0 <= row < len(self.plan.steps):
            return None
        return self.plan.steps[row]

    def step_text(self, row, kind):
        step = self.step(row)
        if step is None:
            return ""
        return mirror.undo_text(step) if kind == UNDO else mirror.config_text(step)

    def selected_step_row(self):
        rows = self.steps_table.selectionModel().selectedRows() if self.steps_table.selectionModel() else []
        return rows[0].row() if rows else -1

    def show_preview(self, *_):
        row = self.selected_step_row()
        text = self.step_text(row, self.preview_combo.currentData()) if row >= 0 else ""
        self.preview.setPlainText(text)
        self.copy_button.setEnabled(bool(text))

    def copy_preview(self):
        text = self.preview.toPlainText()
        if text:
            QApplication.clipboard().setText(text)
            set_hint(self.status_label, "Copied. Paste it at the device's enable (#) prompt.", "success")

    def copy_all(self):
        if self.plan is not None and self.plan.ok:
            QApplication.clipboard().setText(mirror.export_text(self.network_map(), self.plan))
            set_hint(self.status_label, "Copied every device's lines, and what takes them away.", "success")

    def export_all(self):
        if self.plan is None or not self.plan.ok:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Mirror", f"mirror {self.plan_tag}.txt",
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(mirror.export_text(self.network_map(), self.plan))
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save {path}: {error}", "error")
            return
        set_hint(self.status_label, f"Saved to {path}.", "success")

    def show_plan_overlay(self):
        """RSPAN's way drawn on the map, as Carry VLAN draws its path."""
        page = self.map_page()
        view = getattr(page, "view", None)
        if view is None or not hasattr(view, "set_path_overlay"):
            return
        plan = self.plan
        if plan is None or plan.kind != RSPAN or not plan.hops:
            return
        try:
            from .netmap_view import PATH_PLANNED
            links = {}
            for hop in plan.hops:
                for link in hop.links:
                    links[link.key] = (PATH_PLANNED, f"RSPAN VLAN {plan.rspan_vlan}")
            view.set_path_overlay({"vlan": plan.rspan_vlan, "devices": set(plan.route), "links": links})
        except Exception:  # Only a drawing: never worth taking the page down
            log.exception("Drawing the RSPAN way failed")

    # ----------------------------------------------------------------- Logging in

    def logins(self):
        """(macssh.SshLogins, enable secret) for the switches, asking what's needed now; None if cancelled."""
        from ..netmap import macssh
        store = self.sessions
        if store is None:
            set_hint(self.status_label, "Saved sessions aren't available, so NOMAD can't log in to the devices.",
                     "error")
            return None
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions if session.protocol == SSH]
        credential = self.login_picker.credential() if self.login_picker is not None else None
        password = None
        if credential is None:
            asked = self.ask_login()
            if asked is None:
                return None
            username, password = asked
            fallback, label = Session("", username=username), f"user {username} (typed)"
        else:
            fallback = store.credentials.apply(Session("", credential_id=credential.id))
            label = f"credential {credential.name}"
            if credential.auth == AUTH_PASSWORD and not credential.saved_password:
                dialog = SecretDialog(self, "Password", f"Password for {credential.username} (the credential "
                                                       f"{credential.name}):", False)
                if dialog.exec_() != QDialog.Accepted:
                    return None
                password = dialog.field.text()
        secrets = any(item.saved_password or item.saved_passphrase for item in sessions + [fallback])
        if secrets and not ensure_unlocked(self, store, "Port Mirroring logs in to devices with saved passwords."):
            return None
        return macssh.SshLogins(sessions, fallback, password, label), self.enable_input.text()

    def ask_login(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("Log In to Devices")
        layout = QVBoxLayout(dialog)
        label = QLabel("For devices without a saved SSH session (kept only while NOMAD is open):")
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        username = QLineEdit(self.ssh_user)
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        form.addRow("User name:", username)
        form.addRow("Password:", password)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        (password if self.ssh_user else username).setFocus()
        if dialog.exec_() != QDialog.Accepted or not username.text().strip():
            return None
        self.ssh_user = username.text().strip()
        return self.ssh_user, password.text()

    def quiet_logins(self):
        """Logins that need nothing typed (for NOMAD's own timer), or None."""
        from ..netmap import macssh
        if self.saved_logins is not None:
            return self.saved_logins
        store = self.sessions
        if store is None or (store.vault.enabled and not store.vault.unlocked):
            return None
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions if session.protocol == SSH]
        credential = self.login_picker.credential() if self.login_picker is not None else None
        fallback = store.credentials.apply(Session("", credential_id=credential.id)) if credential is not None and \
            credential.saved_password else None
        return macssh.SshLogins(sessions, fallback, None, "saved"), self.enable_input.text()

    def pusher_maker(self, logins):
        login, secret = logins
        vault = self.sessions.vault if self.sessions is not None else None
        trust, factory = self.trust_check.isChecked(), self.shell_factory

        def make(should_stop):
            return configpush.Pusher(login, vault, KnownHosts(), trust, secret, should_stop, shell_factory=factory)
        return make

    # ----------------------------------------------------------------- Reading the switches

    def busy(self):
        return self.reader is not None or self.pusher_thread is not None

    def start_read(self, targets, purpose, logins=None):
        logins = logins or self.saved_logins
        self.reader_purpose = purpose
        self.reader_states = {}
        self.reader = ReadThread(targets, self.pusher_maker(logins), self)
        self.reader.state_read.connect(self.on_state_read)
        self.reader.finished.connect(self.on_read_finished)
        self.reader.start()
        what = {"plan": "Reading the devices' mirror sessions", "check": "Checking the devices",
                "verify": "Checking the devices took it"}.get(purpose, "Reading the devices")
        set_hint(self.status_label, f"{what} ({len(targets)} over SSH)...", "info")
        self.set_busy(what)
        self.update_buttons()

    def on_state_read(self, key, state):
        self.reader_states[key] = state

    def on_read_finished(self):
        thread = self.sender()
        if thread is not self.reader:
            return
        self.reader = None
        thread.deleteLater()
        self.clear_busy()
        try:
            purpose, states = self.reader_purpose, self.reader_states
            if purpose == "plan":
                self.states = states
                self.make_plan()
            elif purpose == "verify":
                self.verify(states)
            else:
                self.show_switch_states(states)
        except Exception as error:
            log.exception("Showing what the switches said failed")
            set_hint(self.status_label, f"Something went wrong: {error}", "error")
        self.update_buttons()

    # ----------------------------------------------------------------- Setting up

    def set_up(self):
        plan, network_map = self.plan, self.network_map()
        if plan is None or not plan.ok or self.busy() or network_map is None:
            return
        labels = ", ".join(mirror.device_label(network_map, step.device) for step in plan.steps)
        question = (f"Set up this {KIND_TITLES[plan.kind]} over SSH on {labels}?\n\n"
                    f"{mirror.describe_request(network_map, plan.request)}")
        if plan.request.remove_after:
            question += f"\n\nThe devices take it away after {mirror.minutes_text(plan.request.remove_after)}."
        if QMessageBox.question(self, "Set Up Mirror", question, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        logins = self.saved_logins if self.saved_logins is not None else self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        record = self.ensure_record()
        jobs = []
        for index, step in enumerate(plan.steps):
            record_step = record.steps[index]
            if record_step.state == mirror.STEP_SET:
                continue
            applet = "\n".join(["configure terminal", *step.applet, "end"]) if step.applet else ""
            jobs.append(Job(index, record_step.address, record_step.names, mirror.config_text(step, applet=False),
                            applet))
        self.start_push(record, jobs, SETUP, logins)

    def ensure_record(self):
        if self.record is None:
            self.record = mirror.record_from(self.network_map(), self.plan, self.plan_tag, self.map_name())
            self.mirrors.put(self.record)
            self.fill_records()
        return self.record

    def start_push(self, record, jobs, kind, logins):
        if not jobs:
            return
        self.push_record, self.push_kind = record, kind
        self.pusher_thread = PushThread(jobs, self.pusher_maker(logins), kind == SETUP, self)
        self.pusher_thread.step_started.connect(self.on_step_started)
        self.pusher_thread.step_done.connect(self.on_step_done)
        self.pusher_thread.finished.connect(self.on_push_finished)
        self.pusher_thread.start()
        what = "Setting up the mirror" if kind == SETUP else "Taking the mirror away"
        set_hint(self.status_label, f"{what} ({len(jobs)} device{'' if len(jobs) == 1 else 's'})...", "info")
        self.set_busy(what)
        self.update_buttons()

    def on_step_started(self, index):
        if self.push_record is self.record and self.push_record is not None:
            self.statuses[index] = "Sending..." if self.push_kind == SETUP else "Taking away..."
            self.show_status(index)

    def on_step_done(self, index, outcome):
        record = self.push_record
        if record is None or not 0 <= index < len(record.steps):
            return
        step = record.steps[index]
        if self.push_kind == SETUP:
            step.state = mirror.STEP_SET if outcome.ok else mirror.STEP_FAILED
            step.applet_ok = outcome.applet_ok
            step.problem = outcome.problem
            if outcome.applet_ok is False:
                record.nomad_timer = True
            status = "Set up" + (" (refused the applet: NOMAD's timer takes it away)" if outcome.applet_ok is False
                                 else "") if outcome.ok else f"Refused: {outcome.problem}"
        else:
            if outcome.ok:
                step.state, step.problem = mirror.STEP_REMOVED, ""
            else:
                step.problem = outcome.problem
            status = "Taken away" if outcome.ok else f"Couldn't take it away: {outcome.problem}"
        if outcome.transcript:
            log.info("Port Mirroring, %s on %s:\n%s", self.push_kind, step.label, outcome.transcript)
        record.update_state()
        if record.state == mirror.REMOVED and not record.removed:
            record.removed = mirror.now_text()
        self.mirrors.put(record)
        if record is self.record:
            self.statuses[index] = status
            self.show_status(index)
        self.fill_records()

    def on_push_finished(self):
        thread = self.sender()
        if thread is not self.pusher_thread:
            return
        self.pusher_thread = None
        thread.deleteLater()
        self.clear_busy()
        record, kind = self.push_record, self.push_kind
        self.push_record = None
        try:
            if record is not None and kind == SETUP:
                self.after_set_up(record, thread.failed)
            elif record is not None:
                left = [step for step in record.steps if step.state != mirror.STEP_REMOVED]
                if left:
                    set_hint(self.status_label, f"{len(left)} device{'' if len(left) == 1 else 's'} still "
                                                f"{'has' if len(left) == 1 else 'have'} it ({left[0].label}: "
                                                f"{left[0].problem or 'not sent'}). Try again, or take it away in a "
                                                "session.", "error")
                else:
                    set_hint(self.status_label, f"Taken away from {len(record.steps)} device"
                                                f"{'' if len(record.steps) == 1 else 's'}.", "success")
        except Exception as error:
            log.exception("Finishing the mirror failed")
            set_hint(self.status_label, f"Something went wrong: {error}", "error")
        self.update_buttons()

    def after_set_up(self, record, failed):
        if failed:
            done = [index for index, step in enumerate(record.steps) if step.state == mirror.STEP_SET]
            problem = next((step for step in record.steps if step.state == mirror.STEP_FAILED), None)
            text = f"{problem.label} refused it ({problem.problem})." if problem is not None else "It failed."
            if done:
                box = QMessageBox(QMessageBox.Warning, "Set Up Mirror",
                                  f"{text}\n\nTake away what was already set up on {len(done)} device"
                                  f"{'' if len(done) == 1 else 's'}?", QMessageBox.Yes | QMessageBox.No, self)
                if box.exec_() == QMessageBox.Yes:
                    self.take_away_record(record, done)
                    return
            set_hint(self.status_label, text + " See View Log for what the device said.", "error")
            return
        refused = [step.label for step in record.steps if step.applet_ok is False]
        text = f"Set up on {len(record.steps)} device{'' if len(record.steps) == 1 else 's'}."
        if refused:
            text += (f" {', '.join(refused)} refused the applet that takes it away, so NOMAD takes it away when the "
                     "time's up (while NOMAD is open).")
        set_hint(self.status_label, text + " Checking it took...", "success")
        targets = [(step.device, step.address, step.names) for step in record.steps]
        self.start_read(targets, "verify")
        if can_capture_here(record):
            text = (f"The copies are on their way to this PC as ERSPAN from {record.origin_ip}. Open Packet "
                    "Capture, ready to capture and unwrap them?" if record.kind == ERSPAN else
                    f"The copies are on their way to this PC's {record.adapter}. Open Packet Capture, ready to "
                    "capture them (with the adapter in promiscuous mode)?")
            box = QMessageBox(QMessageBox.Question, "Capture Here", text, QMessageBox.Yes | QMessageBox.No, self)
            if box.exec_() == QMessageBox.Yes:
                self.capture_record(record)

    def verify(self, states):
        """After setting up: whether each switch has its session."""
        record, plan = self.record, self.plan
        self.merge_switch_states(states)
        if record is None or plan is None:
            return
        problems = []
        for index, step in enumerate(plan.steps):
            state = states.get(step.device)
            found = mirror.check_step(step, plan.kind, state, plan.rspan_vlan, plan.erspan_id)
            if record.steps[index].state != mirror.STEP_SET:
                continue
            self.statuses[index] = "Done" if not found else f"Not done: {found[0]}"
            self.show_status(index)
            problems += found
        if problems:
            set_hint(self.status_label, f"Set up, but a device doesn't show it as planned: {problems[0]}", "warning")
        else:
            expires = f" It goes at {when_text(record.expires)}." if record.expires else ""
            set_hint(self.status_label, f"Done: the devices show the mirror.{expires}", "success")

    # ----------------------------------------------------------------- Sent to terminal sessions

    def fill_step_menu(self):
        menu = self.sender()
        row = self.step_menus.get(menu)
        step = self.step(row) if row is not None else None
        if step is None:
            return
        hints = self.device_hints(step.device)
        self.session_sender.fill_menu(menu, functools.partial(self.step_text, row, SETUP), device=hints,
                                      tag=("plan", row, SETUP))
        menu.addSeparator()
        undo = menu.addMenu("Send the Lines That Take It Away")
        self.session_sender.fill_menu(undo, functools.partial(self.step_text, row, UNDO), device=hints,
                                      tag=("plan", row, UNDO))

    def device_hints(self, key):
        network_map, page = self.network_map(), self.map_page()
        device = network_map.devices.get(key) if network_map is not None else None
        if device is None or not device.mgmt_ip:
            return {}
        hints = {}
        if page is not None and hasattr(page, "session_hints"):
            hints = page.session_hints(network_map, device)
        return dict(hints, address=device.mgmt_ip)

    def lines_sent(self, view, tag):
        """SessionSender: lines went to a session."""
        if not tag:
            return
        where, index, kind = tag
        if where == "plan":
            if self.plan is None:
                return
            record = self.ensure_record()
            self.statuses[index] = f"Sent{' the undo' if kind == UNDO else ''} to {view.title}"
            self.show_status(index)
        else:
            record = self.mirrors.get(where)
            if record is None:
                return
        if not 0 <= index < len(record.steps):
            return
        step = record.steps[index]
        step.state = mirror.STEP_REMOVED if kind == UNDO else mirror.STEP_SENT
        record.update_state()
        if record.state == mirror.REMOVED and not record.removed:
            record.removed = mirror.now_text()
        self.mirrors.put(record)
        self.fill_records()

    # ----------------------------------------------------------------- The mirrors set up

    def fill_records(self):
        selected = self.selected_record()
        selected_id = selected.id if selected is not None else None
        table = self.records_table
        table.setRowCount(0)
        for record in self.mirrors.records:
            row = table.rowCount()
            table.insertRow(row)
            name = QTableWidgetItem(record.name or record.id)
            name.setData(Qt.UserRole, record.id)
            table.setItem(row, 0, name)
            table.setItem(row, 1, QTableWidgetItem(KIND_TITLES.get(record.kind, record.kind)))
            what = QTableWidgetItem(record.what)
            what.setToolTip(record.what)
            table.setItem(row, 2, what)
            table.setItem(row, 3, QTableWidgetItem(", ".join(step.label for step in record.steps)))
            table.setItem(row, 4, QTableWidgetItem(when_text(record.created)))
            expires = when_text(record.expires) if record.expires else "Never"
            if record.nomad_timer and record.expires:
                expires += " (NOMAD's timer)"
            table.setItem(row, 5, QTableWidgetItem(expires))
            state = mirror.STATE_NAMES.get(record.state, record.state)
            if record.state == mirror.REMOVED and record.removed:
                state += f" {when_text(record.removed)}"
            elif record.expired and record.state != mirror.REMOVED:
                state += " (past its time)"
            state_item = QTableWidgetItem(state)
            problem = next((step.problem for step in record.steps if step.problem), "")
            state_item.setToolTip(problem or state)
            color = COLORS["muted"] if record.state == mirror.REMOVED else COLORS["error"] if \
                record.state in (mirror.FAILED, mirror.PARTIAL) else COLORS["success"]
            state_item.setForeground(QColor(color))
            table.setItem(row, 6, state_item)
            if record.id == selected_id:
                table.selectRow(row)
        self.update_buttons()

    def selected_record(self):
        if not hasattr(self, "records_table"):
            return None
        rows = self.records_table.selectionModel().selectedRows() if self.records_table.selectionModel() else []
        if not rows:
            return None
        item = self.records_table.item(rows[0].row(), 0)
        return self.mirrors.get(item.data(Qt.UserRole)) if item is not None else None

    def on_record_selected(self):
        record = self.selected_record()
        if record is not None and record.steps:
            kind = self.preview_combo.currentData()
            text = "\n!\n".join(f"! {step.label} ({mirror.ROLE_NAMES.get(step.role, step.role)})\n"
                                + (step.undo if kind == UNDO else step.setup) for step in record.steps)
            self.preview.setPlainText(text)
            self.copy_button.setEnabled(True)
        self.update_buttons()

    def show_record_menu(self, position):
        record = self.selected_record()
        if record is None:
            return
        menu = QMenu(self)
        actions = {}
        if record.state != mirror.REMOVED:
            actions[menu.addAction("Take Away")] = self.take_away
        if can_capture_here(record):
            actions[menu.addAction("Capture Here")] = self.capture_here
        actions[menu.addAction("Copy the Lines That Take It Away")] = self.copy_record_undo
        actions[menu.addAction("Forget")] = self.forget
        chosen = menu.exec_(self.records_table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def copy_record_undo(self):
        record = self.selected_record()
        if record is not None:
            QApplication.clipboard().setText("\n!\n".join(f"! {step.label}\n{step.undo}" for step in record.steps))
            set_hint(self.status_label, "Copied what takes it away, device by device.", "success")

    def take_away(self):
        record = self.selected_record()
        if record is None or self.busy():
            return
        indexes = [index for index, step in enumerate(record.steps) if step.state != mirror.STEP_REMOVED]
        if not indexes:
            set_hint(self.status_label, "It's taken away already.", "info")
            return
        labels = ", ".join(record.steps[index].label for index in indexes)
        if QMessageBox.question(self, "Take Away Mirror", f"Take {record.name or record.id} away from {labels}?",
                                QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        self.take_away_record(record, indexes)

    def take_away_record(self, record, indexes, logins=None):
        logins = logins or self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        # The source first (so copies stop), then the destination, then the way
        order = sorted(indexes, key=lambda index: {mirror.SOURCE: 0, mirror.DESTINATION: 1}.get(
            record.steps[index].role, 2))
        jobs = [Job(index, record.steps[index].address, record.steps[index].names, record.steps[index].undo)
                for index in order]
        self.start_push(record, jobs, UNDO, logins)

    def fill_record_session_menu(self):
        menu = self.sender()
        menu.clear()
        record = self.selected_record()
        self.record_menus = {}
        if record is None:
            menu.addAction("Choose a mirror first").setEnabled(False)
            return
        for index, step in enumerate(record.steps):
            submenu = menu.addMenu(f"{step.label} ({mirror.ROLE_NAMES.get(step.role, step.role)})")
            hints = self.device_hints(step.device) or ({"address": step.address} if step.address else {})
            self.session_sender.fill_menu(submenu, functools.partial(self.record_undo, record.id, index),
                                          device=hints, tag=(record.id, index, UNDO))

    def record_undo(self, record_id, index):
        record = self.mirrors.get(record_id)
        return record.steps[index].undo if record is not None and 0 <= index < len(record.steps) else ""

    def forget(self):
        record = self.selected_record()
        if record is None:
            return
        if record.state != mirror.REMOVED:
            box = QMessageBox(QMessageBox.Warning, "Forget Mirror",
                              f"{record.name or record.id} hasn't been taken away. Forget it anyway? The devices keep "
                              "it" + (" until their timers take it away." if record.expires and not record.nomad_timer
                                      else ".") + " Copy what takes it away first if you'll want it.",
                              QMessageBox.Yes | QMessageBox.No, self)
            if box.exec_() != QMessageBox.Yes:
                return
        self.mirrors.forget(record.id)
        self.fill_records()

    def capture_here(self):
        record = self.selected_record()
        if record is not None:
            self.capture_record(record)

    def capture_record(self, record):
        capture = getattr(self.window, "capture_tab", None)
        if capture is None:
            return
        if record.kind == ERSPAN and record.origin_ip:
            capture.capture_erspan(record.origin_ip, record.erspan_id)
        elif record.to_this_pc and record.adapter:
            capture.capture_span(record.adapter)
        else:
            set_hint(self.status_label, "NOMAD doesn't know which of this PC's adapters the copies go to (set up "
                                        "before it kept that): in Packet Capture, tick SPAN copies on and choose "
                                        "it.", "warning")
            return
        navigator = getattr(self.window, "navigator", None)
        if navigator is not None:
            navigator.setCurrentWidget(capture)

    # ----------------------------------------------------------------- Checking

    def check_now(self):
        if self.busy():
            return
        targets = {}
        for record in self.mirrors.live():
            for step in record.steps:
                if step.address:
                    targets.setdefault(step.address, (step.device, step.address, step.names))
        if not targets:
            set_hint(self.status_label, "No mirrors to check: Read All Devices reads every switch and router on the "
                                        "map.", "info")
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        self.start_read(list(targets.values()), "check")

    def check_all(self):
        if self.busy():
            return
        network_map = self.network_map()
        if network_map is None:
            set_hint(self.status_label, "Open a map first.", "warning")
            return
        targets = [self.target(network_map, device.key) for device in self.switches() if device.mgmt_ip]
        if not targets:
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        self.start_read(targets, "check")

    def merge_switch_states(self, states):
        self.switch_states.update(states)
        self.fill_sessions()

    def show_switch_states(self, states):
        """After Check Now: what each switch has, and whether each mirror is still there."""
        self.merge_switch_states(states)
        gone, missing = 0, []
        for record in self.mirrors.live():
            changed = False
            for step in record.steps:
                state = states.get(step.device)
                if state is None or not state.read or not step.session or step.state == mirror.STEP_REMOVED:
                    continue
                if step.session not in state.sessions:
                    if record.expires and record.expired:
                        step.state, step.problem = mirror.STEP_REMOVED, ""
                        changed = True
                    else:
                        missing.append(f"{record.name or record.id} on {step.label}")
                        step.problem = f"Session {step.session} wasn't there at {when_text(mirror.now_text())}."
                        changed = True
            if changed:
                if record.update_state() == mirror.REMOVED and not record.removed:
                    record.removed = record.expires or mirror.now_text()
                    gone += 1
                self.mirrors.put(record)
        self.fill_records()
        failed = [state.problem for state in states.values() if not state.read]
        text = f"Read {sum(1 for state in states.values() if state.read)} of {len(states)} devices."
        if gone:
            text += f" {gone} mirror{'' if gone == 1 else 's'} the devices took away when the time was up."
        if missing:
            text += f" Not there: {', '.join(missing[:3])}."
        if failed:
            text += f" Couldn't read {len(failed)} ({failed[0]})."
        set_hint(self.status_label, text, "warning" if missing or failed else "success")

    def fill_sessions(self):
        network_map = self.network_map()
        table = self.sessions_table
        table.setRowCount(0)
        made = {}
        for record in self.mirrors.live():
            for step in record.steps:
                if step.session:
                    made[(step.device, step.session)] = record
        for key, state in sorted(self.switch_states.items(),
                                 key=lambda item: mirror.device_label(network_map, item[0]).lower()
                                 if network_map is not None else item[0]):
            label = mirror.device_label(network_map, key) if network_map is not None else key
            if not state.read:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(label))
                problem = QTableWidgetItem(f"Couldn't read it: {state.problem}")
                problem.setForeground(QColor(COLORS["error"]))
                table.setItem(row, 3, problem)
                continue
            if not state.sessions:
                row = table.rowCount()
                table.insertRow(row)
                table.setItem(row, 0, QTableWidgetItem(label))
                table.setItem(row, 3, QTableWidgetItem("No mirror sessions"))
            for number, session in sorted(state.sessions.items()):
                row = table.rowCount()
                table.insertRow(row)
                first = QTableWidgetItem(label)
                first.setData(Qt.UserRole, (key, number))
                table.setItem(row, 0, first)
                table.setItem(row, 1, QTableWidgetItem(str(number)))
                table.setItem(row, 2, QTableWidgetItem(session.type))
                details = QTableWidgetItem(session.summary())
                details.setToolTip(session.text)
                table.setItem(row, 3, details)
                record = made.get((key, number))
                table.setItem(row, 4, QTableWidgetItem(f"NOMAD ({record.name or record.id})" if record is not None
                                                       else "Not NOMAD"))
            for name in state.applets:
                if not any(step.applet_name == name for record in self.mirrors.live() for step in record.steps):
                    row = table.rowCount()
                    table.insertRow(row)
                    table.setItem(row, 0, QTableWidgetItem(label))
                    table.setItem(row, 2, QTableWidgetItem("EEM applet"))
                    table.setItem(row, 3, QTableWidgetItem(f"{name}: an applet of a mirror not on this list"))
                    table.setItem(row, 4, QTableWidgetItem("NOMAD (another PC?)"))

    def show_session_menu(self, position):
        item = self.sessions_table.itemAt(position)
        if item is None:
            return
        first = self.sessions_table.item(item.row(), 0)
        data = first.data(Qt.UserRole) if first is not None else None
        if not data:
            return
        key, number = data
        menu = QMenu(self)
        take = menu.addAction(f"Take Away Session {number}...")
        chosen = menu.exec_(self.sessions_table.viewport().mapToGlobal(position))
        if chosen is take:
            self.take_away_session(key, number)

    def take_away_session(self, key, number):
        """Take away a session found on a switch (NOMAD's or not)."""
        network_map = self.network_map()
        if network_map is None or self.busy():
            return
        state = self.switch_states.get(key)
        session = state.sessions.get(number) if state is not None else None
        label = mirror.device_label(network_map, key)
        text = f"Take session {number} away from {label}?" + (f"\n\n{session.summary()}" if session else "")
        if QMessageBox.question(self, "Take Away Session", text, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        _, address, names = self.target(network_map, key)
        record = mirror.MirrorRecord(f"S{number}-{mirror.new_id()}", name=f"Session {number} on {label}",
                                     kind=session.kind if session else mirror.SPAN, what=session.summary() if session
                                     else "", created=mirror.now_text(), map_name=self.map_name())
        record.steps = [mirror.RecordStep(key, label, address, mirror.SOURCE, number,
                                          undo=f"configure terminal\nno monitor session {number}\nend",
                                          state=mirror.STEP_SET, names=names)]
        self.mirrors.put(record)
        self.fill_records()
        self.take_away_record(record, [0])

    # ----------------------------------------------------------------- NOMAD's own timer

    def check_overdue(self):
        """Mirrors past their time that a switch refused to take away itself: take them away now."""
        if self.busy():
            return
        try:
            overdue = self.mirrors.overdue()
            if not overdue:
                return
            logins = self.quiet_logins()
            if logins is None:
                set_hint(self.status_label, f"{overdue[0].name or overdue[0].id} is past its time: Take Away (NOMAD "
                                            "needs a saved login to do it itself).", "warning")
                return
            record = overdue[0]
            indexes = [index for index, step in enumerate(record.steps)
                       if step.state != mirror.STEP_REMOVED and step.applet_ok is False]
            if not indexes:
                record.nomad_timer = False
                self.mirrors.put(record)
                return
            log.info("Port Mirroring: taking %s away (its time is up)", record.id)
            set_hint(self.status_label, f"{record.name or record.id}'s time is up: taking it away from the devices "
                                        "that refused its applet.", "info")
            record.nomad_timer = False  # Tried once; Take Away by hand if it fails
            self.mirrors.put(record)
            self.take_away_record(record, indexes, logins)
        except Exception:
            log.exception("Taking an overdue mirror away failed")

    # ----------------------------------------------------------------- Busy

    def set_busy(self, text):
        busy = getattr(self.window, "set_busy", None)
        if busy is not None:
            busy("mirror", text)

    def clear_busy(self):
        clear = getattr(self.window, "clear_busy", None)
        if clear is not None:
            clear("mirror")

    def stop(self):
        for thread in (self.reader, self.pusher_thread):
            if thread is not None:
                thread.stop()
        set_hint(self.status_label, "Stopping...", "info")

    def update_buttons(self):
        if not hasattr(self, "records_table"):
            return
        busy = self.busy()
        has_map = self.network_map() is not None
        planned = self.plan is not None and self.plan.ok
        self.plan_button.setEnabled(not busy and has_map)
        self.setup_button.setEnabled(not busy and planned)
        self.copy_all_button.setEnabled(planned)
        self.export_button.setEnabled(planned)
        self.stop_button.setEnabled(busy)
        self.dest_combo.setEnabled(self.to_port_radio.isChecked())
        self.dest_port_combo.setEnabled(self.to_port_radio.isChecked())
        self.adapter_combo.setEnabled(self.to_pc_radio.isChecked())
        self.address_input.setEnabled(self.to_address_radio.isChecked())
        record = self.selected_record()
        live = record is not None and record.state != mirror.REMOVED
        self.take_away_button.setEnabled(live and not busy)
        self.session_button.setEnabled(live)
        self.capture_button.setEnabled(record is not None and can_capture_here(record) and live)
        self.forget_button.setEnabled(record is not None and not busy)
        self.check_button.setEnabled(not busy and bool(self.mirrors.live()))
        self.check_all_button.setEnabled(not busy and has_map)
        self.remove_source_button.setEnabled(self.sources_table.rowCount() > 0)
