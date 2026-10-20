"""Carry VLAN (Network Map): get a VLAN to a switch over the map's links on Cisco IOS / IOS-XE switches.

Choose the VLAN and B (and A, or let NOMAD start from where the VLAN already is), or set the whole route by hand,
switch by switch. Plan reads the switches involved again (their VLANs, and how spanning tree has their ports for
the VLAN), then lists what each switch needs: send it all over SSH with no one watching (Send All over SSH, in order,
stopping at the first switch that refuses a line, then Verify), send each to a terminal session (typed in while you
watch), copy it, or export all of it with the undo. Verify reads them again and says what's done. Undo Sent over SSH
takes back out what was sent. Gateways are only checked."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import functools
import html
import logging

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QAction, QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, \
    QFileDialog, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, QInputDialog, QLabel, QLineEdit, QListWidget, \
    QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSplitter, \
    QStyledItemDelegate, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget

from ..netmap import configpush, vlan_path, vlans, watch
from ..netmap.crawl import apply_vlans
from ..netmap.model import SNMP, SWITCH
from .common import StoppableThread, set_hint
from .netmap_view import PATH_BLOCKED, PATH_CARRIES, PATH_CHOSEN, PATH_OFFERED, PATH_PLANNED, PATH_ROUTE
from .session_send import SessionSender
from .ssh_push import Job, LoginRow, PushThread
from .theme import COLORS, accent_button, monospace_font

log = logging.getLogger(__name__)

READ_WORKERS = 4  # Switches read at once
MAX_ROUNDS = 3  # Reading more switches when the way moved onto ones not read yet
AUTOMATIC = ""  # A: start from wherever the VLAN already is
SEVERITY_COLORS = {vlans.ERROR: "error", vlans.WARNING: "warning", vlans.INFO: "muted"}
STEP_COLUMNS = ["Switch", "Changes", "Status", ""]
ROUTE_COLUMNS = ["Switch", "Link to the next", "Check"]
CONFIG, UNDO = "config", "undo"
NAME_ROLE = Qt.UserRole + 1  # The VLAN list: each VLAN's name, shown beside its number in the list only


class VlanNameDelegate(QStyledItemDelegate):
    """The VLAN list shows each VLAN's name after its number; the box itself shows only the number."""

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        name = index.data(NAME_ROLE)
        if name:
            option.text = f"{option.text}  {name}"


@dataclass
class Sent:
    """A step sent to a switch (over SSH or into a session), with what takes it back out: kept when planning again,
    so Undo Sent over SSH still knows."""
    device: str
    label: str
    address: str
    vlan: int
    redundant: bool
    undo: str
    names: list = field(default_factory=list)

    @property
    def key(self):
        return self.device, self.redundant, self.vlan


class PathReadThread(StoppableThread):
    """Reads the VLANs (and spanning tree, for the VLAN) of a few switches at once."""
    read = pyqtSignal(str, str, object)  # Device key, the address asked, (DeviceTables, community) or (None, None)

    def __init__(self, settings, targets, reader, parent=None):
        super().__init__(parent)
        self.settings, self.targets, self.reader = settings, targets, reader  # targets: [(key, address)]

    def run(self):
        def ask(target):
            key, address = target
            if self.stopping:
                return
            try:
                result = self.reader(self.settings, address)
            except Exception:  # One switch's trouble shouldn't stop the rest
                log.exception("Reading %s's VLANs for Carry VLAN failed", address)
                result = (None, None)
            if not self.stopping:
                self.read.emit(key, address, result)

        with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(self.targets)))) as executor:
            list(executor.map(ask, self.targets))


def changes_text(step, vlan, network_map):
    parts = []
    if step.create_vlan:
        parts.append(f"create VLAN {vlan}" + (f" ({'; '.join(step.notes)})" if step.notes and not step.redundant
                                              else ""))
    if step.trunks:
        parts.append(f"allow it on {', '.join(step.trunks)}")
    if step.edge:
        parts.append(f"put {', '.join(port for port, _ in step.edge)} in it")
    if step.redundant:
        parts.append("(redundant links)")
    return "; ".join(parts) or "nothing"


class VlanPathDialog(QDialog):
    def __init__(self, page):
        super().__init__(page)
        self.page = page
        self.network_map = page.network_map
        self.plan = None
        self.stp = {}  # Device key -> vlan_path.StpView, from the read before planning
        self.read_keys = set()  # Read for this plan
        self.failed = []  # Labels of the switches that didn't answer
        self.results = {}  # Device key -> (address, result), while reading
        self.thread = None
        self.purpose = ""  # What the read is for: "plan" or "verify"
        self.rounds = 0
        self.route = []  # A route set by hand: device keys
        self.hop_choices = {}  # frozenset of two device keys -> Hop.key chosen between them
        self.chosen = set()  # Hop.keys of the redundant links chosen
        self.statuses = {}  # Index in plan.changes -> status text
        self.step_menus = {}  # The Send menu of each step's row -> its index in plan.changes
        self.name_edited = False
        self.after_send = []  # Findings from Verify
        self.previous_vlan = None  # The VLAN the map highlighted before, put back on closing
        self.picking = False  # Picking the route's switches on the map
        self.edge_key = None  # The switch the edge ports listed are on
        self.push_thread = None  # Sending over SSH
        self.push_kind = CONFIG
        self.push_plan = None  # The plan push_thread is sending (its rows mean nothing in another)
        self.push_sent = {}  # Config push: plan row -> Sent, kept once the switch got lines
        self.push_keys = []  # Undo push: Job.index -> Sent.key
        self.push_failed = []  # Rows of the config push that failed
        self.sent = {}  # Sent.key -> Sent, in the order sent
        self.saved_logins = None  # (logins, enable secret), asked once until the login row changes
        self.shell_factory = configpush.ConfigShell  # Tests swap in fake switches
        self.route_errors = []  # Problems with the route set by hand
        self.setWindowTitle("Carry VLAN")
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.resize(1200, 760)
        self.init_ui()
        self.session_sender = SessionSender(self, page.window, self.status_label)
        page.map_shown.connect(self.on_map_shown)
        page.view.device_picked.connect(self.on_picked)
        page.view.picking_stopped.connect(self.on_picking_stopped)

    # ----------------------------------------------------------------- Building it

    def init_ui(self):
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Horizontal)
        layout.addWidget(splitter, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 6, 0)
        form = QGridLayout()
        self.vlan_combo = QComboBox()
        self.vlan_combo.setEditable(True)
        self.vlan_combo.setInsertPolicy(QComboBox.NoInsert)
        self.vlan_combo.lineEdit().setPlaceholderText("VLAN number")
        self.vlan_combo.setToolTip("The VLAN to carry: one on the map, or a new number.")
        self.vlan_delegate = VlanNameDelegate(self.vlan_combo)
        self.vlan_combo.setItemDelegate(self.vlan_delegate)
        self.vlan_combo.currentTextChanged.connect(self.on_vlan_changed)
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Its name, where it's created")
        self.name_input.textEdited.connect(self.on_name_edited)
        form.addWidget(QLabel("VLAN:"), 0, 0)
        form.addWidget(self.vlan_combo, 0, 1)
        form.addWidget(QLabel("Name:"), 1, 0)
        form.addWidget(self.name_input, 1, 1)
        left_layout.addLayout(form)

        self.auto_radio = QRadioButton("Let NOMAD choose the way (fewest changes)")
        self.hand_radio = QRadioButton("Through these switches (set the route by hand)")
        self.auto_radio.setChecked(True)
        group = QButtonGroup(self)
        group.addButton(self.auto_radio)
        group.addButton(self.hand_radio)
        self.route_group = group
        self.auto_radio.toggled.connect(self.on_mode_changed)
        left_layout.addWidget(self.auto_radio)

        self.auto_box = QWidget()
        auto_form = QGridLayout(self.auto_box)
        auto_form.setContentsMargins(18, 0, 0, 0)
        self.a_combo = QComboBox()
        self.a_combo.setToolTip("Where the VLAN starts from: automatically, the nearest switch already carrying it "
                                "(the part of the VLAN with its gateway first).")
        self.b_combo = QComboBox()
        self.b_combo.setToolTip("The switch the VLAN is carried to.")
        self.b_combo.currentIndexChanged.connect(self.on_b_changed)
        self.a_combo.currentIndexChanged.connect(self.plan_outdated)
        auto_form.addWidget(QLabel("A (from):"), 0, 0)
        auto_form.addWidget(self.a_combo, 0, 1)
        auto_form.addWidget(QLabel("B (to):"), 1, 0)
        auto_form.addWidget(self.b_combo, 1, 1)
        auto_form.setColumnStretch(1, 1)
        left_layout.addWidget(self.auto_box)

        left_layout.addWidget(self.hand_radio)
        self.route_box = QWidget()
        route_layout = QVBoxLayout(self.route_box)
        route_layout.setContentsMargins(18, 0, 0, 0)
        self.route_table = QTableWidget(0, len(ROUTE_COLUMNS))
        self.route_table.setHorizontalHeaderLabels(ROUTE_COLUMNS)
        self.route_table.verticalHeader().setVisible(True)
        self.route_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.route_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.route_table.setSelectionMode(QAbstractItemView.SingleSelection)
        header = self.route_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setStretchLastSection(True)
        route_layout.addWidget(self.route_table)
        route_buttons = QGridLayout()
        self.add_switch_button = QPushButton("Add Switch...")
        self.add_switch_button.setToolTip("Add a switch after the one selected (or at the end).")
        self.pick_button = QPushButton("Pick on Map")
        self.pick_button.setToolTip("Click switches on the physical view in order, A first. Esc, a right-click or a "
                                    "click on the background stops.")
        self.up_button = QPushButton("Move Up")
        self.down_button = QPushButton("Move Down")
        self.remove_button = QPushButton("Remove")
        self.fill_button = QPushButton("Fill In Between")
        self.fill_button.setToolTip("Where two switches next to each other on the route have no link between them, "
                                    "add the switches between them (the way needing the fewest changes).")
        self.clear_button = QPushButton("Clear")
        for index, button in enumerate((self.add_switch_button, self.pick_button, self.fill_button, self.up_button,
                                        self.down_button, self.remove_button, self.clear_button)):
            route_buttons.addWidget(button, index // 4, index % 4)
        route_layout.addLayout(route_buttons)
        self.add_switch_button.clicked.connect(self.add_switch)
        self.pick_button.clicked.connect(self.toggle_picking)
        self.up_button.clicked.connect(self.move_up)
        self.down_button.clicked.connect(self.move_down)
        self.remove_button.clicked.connect(self.remove_switch)
        self.fill_button.clicked.connect(self.fill_in_between)
        self.clear_button.clicked.connect(self.clear_route)

        edge_box = QWidget()
        edge_layout = QVBoxLayout(edge_box)
        edge_layout.setContentsMargins(0, 0, 0, 0)
        self.edge_label = QLabel("B's edge ports to put in the VLAN too (optional):")
        edge_layout.addWidget(self.edge_label)
        self.edge_list = QListWidget()
        self.edge_list.setToolTip("Access ports are put in the VLAN; trunks get it allowed. Links to other network "
                                  "devices are listed last.")
        self.edge_list.itemChanged.connect(self.plan_outdated)
        edge_layout.addWidget(self.edge_list)
        route_split = QSplitter(Qt.Vertical)  # The route gets most of the height: its table shares it with buttons
        route_split.setChildrenCollapsible(False)
        route_split.addWidget(self.route_box)
        route_split.addWidget(edge_box)
        route_split.setStretchFactor(0, 2)
        route_split.setStretchFactor(1, 1)
        route_split.setSizes([400, 200])
        left_layout.addWidget(route_split, 1)
        self.save_check = QCheckBox("Save each switch's configuration afterwards (write memory)")
        self.save_check.toggled.connect(self.show_preview)
        left_layout.addWidget(self.save_check)
        ssh_box = QGroupBox("Send over SSH: switches without a saved SSH session")
        ssh_layout = QVBoxLayout(ssh_box)
        self.login_row = LoginRow(self, getattr(self.page.window, "session_store", None), "Carry VLAN", stacked=True)
        self.login_row.changed.connect(self.on_login_changed)
        ssh_layout.addWidget(self.login_row)
        left_layout.addWidget(ssh_box)
        splitter.addWidget(left)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(6, 0, 0, 0)
        buttons = QHBoxLayout()
        self.plan_button = accent_button("Plan")
        self.plan_button.setToolTip("Read the switches involved again (their VLANs, and spanning tree for this VLAN), "
                                    "then work out what each needs.")
        self.send_button = QPushButton("Send All over SSH")
        self.send_button.setToolTip("Log in to each switch over SSH and send its lines, in order, stopping at the "
                                    "first switch that refuses one; then Verify.")
        self.undo_button = QPushButton("Undo Sent over SSH")
        self.undo_button.setToolTip("Take back out what was sent (over SSH or into a session), last first.")
        self.verify_button = QPushButton("Verify")
        self.verify_button.setToolTip("Read the switches again and check what's done.")
        self.edit_route_button = QPushButton("Edit This Route")
        self.edit_route_button.setToolTip("Copy the way NOMAD chose into the route set by hand, to change it.")
        self.export_button = QPushButton("Export All...")
        self.export_button.setToolTip("Save every switch's configuration, and its undo, to a text file.")
        for button in (self.plan_button, self.send_button, self.undo_button, self.verify_button,
                       self.edit_route_button, self.export_button):
            buttons.addWidget(button)
        buttons.addStretch(1)
        right_layout.addLayout(buttons)
        self.plan_button.clicked.connect(self.start_plan)
        self.send_button.clicked.connect(self.send_all_over_ssh)
        self.undo_button.clicked.connect(self.undo_sent_over_ssh)
        self.verify_button.clicked.connect(self.start_verify)
        self.edit_route_button.clicked.connect(self.edit_route)
        self.export_button.clicked.connect(self.export_all)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        right_layout.addWidget(self.status_label)
        self.route_label = QLabel()
        self.route_label.setWordWrap(True)
        self.route_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        right_layout.addWidget(self.route_label)
        self.gateway_label = QLabel()
        self.gateway_label.setWordWrap(True)
        right_layout.addWidget(self.gateway_label)
        results = QSplitter(Qt.Vertical)
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        results.addWidget(self.findings_list)
        redundant = QGroupBox("Redundant links: tick to carry the VLAN on them too (sent last)")
        redundant_layout = QVBoxLayout(redundant)
        self.redundant_list = QListWidget()
        self.redundant_list.setWordWrap(True)
        self.redundant_list.itemChanged.connect(self.on_redundant_changed)
        redundant_layout.addWidget(self.redundant_list)
        results.addWidget(redundant)
        self.steps_table = QTableWidget(0, len(STEP_COLUMNS))
        self.steps_table.setHorizontalHeaderLabels(STEP_COLUMNS)
        self.steps_table.verticalHeader().setVisible(False)
        self.steps_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.steps_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.steps_table.setSelectionMode(QAbstractItemView.SingleSelection)
        header = self.steps_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.steps_table.itemSelectionChanged.connect(self.show_preview)
        results.addWidget(self.steps_table)
        preview_box = QWidget()
        preview_layout = QVBoxLayout(preview_box)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        preview_buttons = QHBoxLayout()
        self.preview_combo = QComboBox()
        self.preview_combo.addItem("Configuration", "config")
        self.preview_combo.addItem("Undo", "undo")
        self.preview_combo.currentIndexChanged.connect(self.show_preview)
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_preview)
        preview_buttons.addWidget(QLabel("Show:"))
        preview_buttons.addWidget(self.preview_combo)
        preview_buttons.addWidget(self.copy_button)
        preview_buttons.addStretch(1)
        preview_layout.addLayout(preview_buttons)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        self.preview.setPlaceholderText("Select a switch above to see what's sent to it.")
        preview_layout.addWidget(self.preview)
        results.addWidget(preview_box)
        results.setSizes([120, 110, 200, 200])
        right_layout.addWidget(results, 1)
        splitter.addWidget(right)
        splitter.setSizes([430, 770])
        close = QPushButton("Close")
        close.clicked.connect(self.close)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(close)
        layout.addLayout(bottom)
        self.on_mode_changed()

    # ----------------------------------------------------------------- What it's for

    def set_target(self, vlan=None, a=None, b=None, port=None, route=None):
        """Fill in what to carry (from the map's menus) and show it."""
        if self.page.network_map is not self.network_map:
            self.network_map = self.page.network_map
            self.route, self.hop_choices = [], {}
        self.fill_choices()
        if vlan:
            self.set_vlan(vlan)
        if route:
            self.route = [key for key in route if key in self.network_map.devices]
            self.hand_radio.setChecked(True)
        elif b:
            self.auto_radio.setChecked(True)
            self.select_data(self.a_combo, a or AUTOMATIC)
            self.select_data(self.b_combo, b)
        self.refresh_route()
        self.fill_edge_ports(port)
        self.clear_plan()
        if self.previous_vlan is None:
            self.previous_vlan = ("set", self.page.vlan_shown)
        self.show()
        self.raise_()
        self.activateWindow()
        if not self.vlan_combo.currentText().strip():
            self.vlan_combo.setFocus()

    def fill_choices(self):
        network_map = self.network_map
        vlan_text = self.vlan_combo.currentText()
        self.vlan_combo.blockSignals(True)
        self.vlan_combo.clear()
        seen = set()
        for item in vlans.map_vlans(network_map) if network_map is not None else []:
            if item.vlan in seen:
                continue
            seen.add(item.vlan)
            self.vlan_combo.addItem(str(item.vlan), item.vlan)
            self.vlan_combo.setItemData(self.vlan_combo.count() - 1, item.name, NAME_ROLE)
        self.vlan_combo.setEditText(vlan_text)
        self.vlan_combo.blockSignals(False)
        devices = network_map.devices if network_map is not None else {}
        for combo, kinds, first in ((self.a_combo, vlan_path.ENDPOINT_KINDS, "Nearest switch already carrying it "
                                     "(automatic)"), (self.b_combo, {SWITCH}, None)):
            current = combo.currentData()
            combo.blockSignals(True)
            combo.clear()
            if first:
                combo.addItem(first, AUTOMATIC)
            for key in sorted((key for key, device in devices.items() if device.kind in kinds),
                              key=lambda key: devices[key].label.lower()):
                combo.addItem(devices[key].label, key)
            self.select_data(combo, current)
            combo.blockSignals(False)

    @staticmethod
    def select_data(combo, data):
        index = combo.findData(data)
        if index >= 0:
            combo.setCurrentIndex(index)

    def set_vlan(self, vlan):
        index = self.vlan_combo.findData(vlan)
        if index >= 0:
            self.vlan_combo.setCurrentIndex(index)
        else:
            self.vlan_combo.setEditText(str(vlan))
        self.on_vlan_changed()

    def vlan(self):
        """The VLAN number entered, or None."""
        text = self.vlan_combo.currentText().strip().split(" ")[0]
        try:
            number = int(text)
        except ValueError:
            return None
        return number if 1 <= number <= vlans.MAX_VLAN else None

    def on_vlan_changed(self, *_):
        vlan = self.vlan()
        if not self.name_edited:
            name = ""
            if vlan is not None and self.network_map is not None:
                name = next((item.name for item in vlans.map_vlans(self.network_map) if item.vlan == vlan), "")
            self.name_input.setText(name)
        self.plan_outdated()
        self.refresh_route()

    def on_name_edited(self, _text):
        self.name_edited = True
        self.plan_outdated()

    def by_hand(self):
        return self.hand_radio.isChecked()

    def on_mode_changed(self, *_):
        self.auto_box.setEnabled(not self.by_hand())
        self.route_box.setEnabled(self.by_hand())
        if not self.by_hand() and self.picking:
            self.page.view.stop_picking()
        self.fill_edge_ports()
        self.plan_outdated()
        if self.plan is None:
            self.show_route_preview()

    def b_key(self):
        if self.by_hand():
            return self.route[-1] if len(self.route) > 1 else None
        return self.b_combo.currentData()

    def on_b_changed(self, *_):
        self.fill_edge_ports()
        self.plan_outdated()

    def fill_edge_ports(self, select=None):
        """B's ports, ticked ones kept ticked while B is the same switch (and select ticked)."""
        key = self.b_key()
        ticked = set(self.edge_ports()) if key == self.edge_key else set()  # Not another switch's same-named port
        self.edge_key = key
        if select:
            ticked.add(select)
        self.edge_list.blockSignals(True)
        self.edge_list.clear()
        device = self.network_map.devices.get(key) if self.network_map is not None and key else None
        if device is not None:
            select_key = vlan_path.logical_port(device, select) if select else None
            neighbors = {vlan_path.port_key(link.port_on(key)): link.b if link.a == key else link.a
                         for link in self.network_map.links_of(key)}
            for port, entry in vlan_path.edge_port_choices(self.network_map, key):
                item = QListWidgetItem(f"{port}  ({vlan_path.describe_entry(entry)})")
                if entry.get("mode") == vlan_path.TRUNK:
                    self.warn_trunk(item, port, neighbors.get(vlan_path.port_key(port)))
                item.setData(Qt.UserRole, port)
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if port in ticked or port == select_key else Qt.Unchecked)
                self.edge_list.addItem(item)
        self.edge_list.blockSignals(False)
        self.edge_label.setText(f"<b>{html.escape(device.label)}</b>'s edge ports to put in the VLAN too (optional):"
                                if device is not None else "B's edge ports to put in the VLAN too (optional):")

    def warn_trunk(self, item, port, neighbor):
        """An edge port that's a trunk: ticked, it keeps being a trunk and the VLAN is added to what it allows."""
        other = vlan_path.label_of(self.network_map, neighbor) if neighbor else ""
        item.setText(item.text() + f"  Warning: Trunk{f' to {other}' if other else ''}")
        item.setForeground(QColor(COLORS["warning"]))
        item.setToolTip(f"{port} is a trunk{f' to {other}' if other else ''}. Ticked, it stays a trunk and the VLAN "
                        f"is added to the VLANs it allows (switchport trunk allowed vlan add), so whatever is at its "
                        f"other end gets the VLAN tagged. It isn't made an access port. Leave it unticked unless "
                        f"that's what you want.")

    def edge_ports(self):
        return [self.edge_list.item(row).data(Qt.UserRole) for row in range(self.edge_list.count())
                if self.edge_list.item(row).checkState() == Qt.Checked]

    # ----------------------------------------------------------------- The route set by hand

    def graph(self):
        return vlan_path.Graph(self.network_map)

    def route_hops(self, graph=None):
        """The hop chosen between each two switches of the route (None: the only one, or none chosen)."""
        graph = graph or self.graph()
        hops = []
        for one, other in zip(self.route, self.route[1:]):
            wanted = self.hop_choices.get(frozenset([one, other]))
            hops.append(next((hop for hop in graph.between(one, other) if hop.key == wanted), None))
        return hops

    def refresh_route(self):
        """Show the route set by hand, with each step's link and what's wrong with it."""
        if self.network_map is None:
            return
        graph = self.graph()
        self.route = [key for key in self.route if key in graph.devices]
        _, findings = vlan_path.check_route(graph, self.route, self.route_hops(graph))
        selected = self.route_table.currentRow()
        self.route_table.setRowCount(len(self.route))
        for row, key in enumerate(self.route):
            self.route_table.setItem(row, 0, QTableWidgetItem(graph.label(key)))
            self.route_table.removeCellWidget(row, 1)
            if row < len(self.route) - 1:
                other = self.route[row + 1]
                between = graph.between(key, other)
                if len(between) > 1:
                    combo = QComboBox()
                    combo.addItem("(choose the link)", None)
                    for hop in between:
                        combo.addItem(hop.text(self.network_map, start=key), hop.key)
                    self.select_data(combo, self.hop_choices.get(frozenset([key, other])))
                    combo.setProperty("pair", row)
                    combo.currentIndexChanged.connect(self.on_hop_chosen)
                    self.route_table.setItem(row, 1, QTableWidgetItem(""))
                    self.route_table.setCellWidget(row, 1, combo)
                else:
                    text = between[0].text(self.network_map, start=key) if between else "(no link)"
                    self.route_table.setItem(row, 1, QTableWidgetItem(text))
            else:
                self.route_table.setItem(row, 1, QTableWidgetItem("B" if row else ""))
            problems = [finding for finding in findings
                        if finding.device == key and (not finding.other or (row < len(self.route) - 1
                                                                            and finding.other == self.route[row + 1]))]
            check = QTableWidgetItem("; ".join(finding.text for finding in problems) or "OK")
            check.setForeground(QColor(COLORS["error"] if problems else COLORS["muted"]))
            check.setToolTip(check.text())
            self.route_table.setItem(row, 2, check)
        if 0 <= selected < len(self.route):
            self.route_table.selectRow(selected)
        self.route_errors = [finding for finding in findings if finding.severity == vlans.ERROR]
        if self.by_hand():
            self.fill_edge_ports()
        if self.plan is None:
            self.show_route_preview()

    def on_hop_chosen(self, _index):
        combo = self.sender()
        row = combo.property("pair")
        if row is None or row >= len(self.route) - 1:
            return
        pair = frozenset([self.route[row], self.route[row + 1]])
        if combo.currentData() is None:
            self.hop_choices.pop(pair, None)
        else:
            self.hop_choices[pair] = combo.currentData()
        self.plan_outdated()
        self.refresh_route()

    def selected_route_row(self):
        row = self.route_table.currentRow()
        return row if 0 <= row < len(self.route) else None

    def switch_choices(self):
        devices = self.network_map.devices
        return sorted((key for key, device in devices.items() if device.kind in vlan_path.ENDPOINT_KINDS),
                      key=lambda key: devices[key].label.lower())

    def add_switch(self):
        if self.network_map is None:
            return
        keys = self.switch_choices()
        labels = [self.network_map.devices[key].label for key in keys]
        if not labels:
            return
        label, ok = QInputDialog.getItem(self, "Add Switch", "Switch to add to the route:", labels, 0, False)
        if ok and label in labels:
            row = self.selected_route_row()
            self.insert_route(keys[labels.index(label)], len(self.route) if row is None else row + 1)

    def insert_route(self, key, index):
        self.route.insert(index, key)
        self.plan_outdated()
        self.refresh_route()
        self.route_table.selectRow(index)

    def toggle_picking(self):
        view = self.page.view
        if self.picking:
            view.stop_picking()
            return
        if self.network_map is None:
            return
        self.picking = True
        self.pick_button.setText("Stop Picking")
        self.page.tabs.setCurrentWidget(view)
        view.start_picking(self.route[-1] if self.route else None)
        set_hint(self.page.status_label, "Carry VLAN: click the switches of the route in order, A first. Esc, a "
                                         "right-click or a click on the background stops.", "info")
        set_hint(self.status_label, "Click the switches on the map in order, A first.", "info")

    def on_picked(self, key):
        if not self.picking or self.network_map is None:
            return
        device = self.network_map.devices.get(key)
        if device is None or device.kind not in vlan_path.ENDPOINT_KINDS:
            set_hint(self.status_label, f"{device.label if device else key} isn't a switch, router or firewall.",
                     "warning")
            return
        if self.route and self.route[-1] == key:
            return
        self.insert_route(key, len(self.route))
        set_hint(self.status_label, f"Added {device.label}: {len(self.route)} on the route.", "info")

    def on_picking_stopped(self):
        if not self.picking:
            return
        self.picking = False
        self.pick_button.setText("Pick on Map")
        set_hint(self.page.status_label, "Stopped picking the route.", "info")
        self.show()
        self.raise_()

    def move_up(self):
        row = self.selected_route_row()
        if row:
            self.route[row - 1], self.route[row] = self.route[row], self.route[row - 1]
            self.plan_outdated()
            self.refresh_route()
            self.route_table.selectRow(row - 1)

    def move_down(self):
        row = self.selected_route_row()
        if row is not None and row < len(self.route) - 1:
            self.route[row + 1], self.route[row] = self.route[row], self.route[row + 1]
            self.plan_outdated()
            self.refresh_route()
            self.route_table.selectRow(row + 1)

    def remove_switch(self):
        row = self.selected_route_row()
        if row is not None:
            del self.route[row]
            self.plan_outdated()
            self.refresh_route()

    def clear_route(self):
        self.route, self.hop_choices = [], {}
        self.plan_outdated()
        self.refresh_route()

    def fill_in_between(self):
        """Where two switches next to each other have no link, add the switches between them."""
        vlan = self.vlan()
        if vlan is None:
            set_hint(self.status_label, "Enter the VLAN first: the switches between are the ones needing the fewest "
                                        "changes for it.", "warning")
            return
        graph = self.graph()
        filled, missing, index = 0, [], 0
        while index < len(self.route) - 1:
            one, other = self.route[index], self.route[index + 1]
            if graph.between(one, other):
                index += 1
                continue
            found = vlan_path.fill_between(self.network_map, vlan, one, other, avoid=self.route, stp=self.stp)
            if found is None:
                missing.append(f"{graph.label(one)} and {graph.label(other)}")
                index += 1
                continue
            between = found[0][1:-1]
            self.route[index + 1:index + 1] = between
            filled += len(between)
            index += len(between) + 1
        self.plan_outdated()
        self.refresh_route()
        if missing:
            set_hint(self.status_label, f"No way between {'; '.join(missing)} that can carry VLAN {vlan}.", "warning")
        else:
            set_hint(self.status_label, f"Added {filled} switch{'es' if filled != 1 else ''} between." if filled
                     else "Every switch on the route is linked to the next.", "info")

    def copy_plan_route(self):
        """Put the way NOMAD chose in the route table, the same as if it had been set by hand."""
        plan = self.plan
        self.route = list(plan.route)
        for hop in plan.hops:
            if hop is not None:
                self.hop_choices[frozenset([hop.a, hop.b])] = hop.key
        self.refresh_route()

    def edit_route(self):
        plan = self.plan
        if plan is None or not plan.route:
            return
        self.copy_plan_route()
        self.hand_radio.setChecked(True)
        self.refresh_route()
        set_hint(self.status_label, "The way NOMAD chose is now the route set by hand: change it, then Plan.", "info")

    # ----------------------------------------------------------------- Reading and planning

    def check_ready(self):
        """Why it can't plan now (or "")."""
        if self.network_map is None or self.page.network_map is not self.network_map:
            return "Open the map first."
        if self.page.worker is not None:
            return "Wait for the crawl to finish."
        if self.thread is not None:
            return "Still reading the switches."
        if self.push_thread is not None:
            return "Still sending to the switches."
        if self.vlan() is None:
            return f"Enter a VLAN number (1 to {vlans.MAX_VLAN})."
        if self.by_hand():
            if len(self.route) < 2:
                return "Add the switches of the route, A first and B last."
            if self.route_errors:
                return "Fix the route first: " + self.route_errors[0].text
        elif not self.b_combo.currentData():
            return "Choose B, the switch to carry it to."
        return ""

    def start_plan(self):
        problem = self.check_ready()
        if problem:
            set_hint(self.status_label, problem, "warning")
            return
        vlan = self.vlan()
        self.stp, self.read_keys, self.failed, self.rounds = {}, set(), [], 0
        if self.by_hand():
            keys = vlan_path.candidates(self.network_map, route=self.route)
        else:
            keys = vlan_path.candidates(self.network_map, a=self.a_combo.currentData() or None,
                                        b=self.b_combo.currentData(), vlan=vlan)
        self.read(keys, "plan")

    def start_verify(self):
        plan = self.plan
        if plan is None or self.busy():
            return
        keys = list(dict.fromkeys([step.device for step in plan.changes] + plan.route))
        self.read(keys, "verify")

    def read(self, keys, purpose):
        devices = self.network_map.devices
        done = self.read_keys if purpose == "plan" else set()  # Verify reads them all again
        targets = [(key, devices[key].mgmt_ip) for key in keys
                   if key in devices and devices[key].source == SNMP and devices[key].mgmt_ip and key not in done]
        self.purpose = purpose
        self.results = {}
        if not targets:
            self.finish_read()
            return
        self.read_keys |= {key for key, _ in targets}
        vlan = self.vlan()
        reader = functools.partial(self.page.read_vlans, stp_vlan=vlan) if purpose == "plan" else self.page.read_vlans
        thread = PathReadThread(self.page.crawl_settings([address for _, address in targets]), targets, reader, self)
        thread.read.connect(self.on_read)
        thread.finished.connect(self.on_read_finished)
        self.thread = thread
        self.page.check_threads.append(thread)
        self.set_busy(True)
        set_hint(self.status_label, f"Reading {len(targets)} switch{'es' if len(targets) != 1 else ''} "
                                    f"({'VLANs and spanning tree' if purpose == 'plan' else 'VLANs'})...", "info")
        thread.start()

    def on_read(self, key, address, result):
        self.results[key] = (address, result)

    def on_read_finished(self):
        thread = self.thread
        self.thread = None
        if thread in self.page.check_threads:
            self.page.check_threads.remove(thread)
        self.set_busy(False)
        if self.page.network_map is not self.network_map:
            set_hint(self.status_label, "Another map was opened meanwhile: Plan again.", "warning")
            return
        lines, applied = [], 0
        for key, (address, (tables, community)) in self.results.items():
            device = self.network_map.devices.get(key)
            if device is None:
                continue
            if tables is None:
                self.failed.append(device.label)
                continue
            if community:
                self.page.answered[address] = community
            before = (vlans.vlan_names(device), dict(device.port_vlans))
            apply_vlans(device, tables)
            lines += watch.vlan_changes(device, *before)
            view = vlan_path.stp_view(tables)
            if view is not None:
                self.stp[key] = view
            applied += 1
        self.results = {}
        if applied:
            self.page.map_changed()
            for line in lines:
                self.page.watcher.log(line)
        self.finish_read()

    def finish_read(self):
        if self.purpose == "verify":
            self.verify()
            return
        self.make_plan()
        plan = self.plan
        if not self.by_hand() and plan is not None and plan.route and self.rounds < MAX_ROUNDS:
            devices = self.network_map.devices
            unread = [key for key in plan.route if key not in self.read_keys and key in devices
                      and devices[key].source == SNMP and devices[key].mgmt_ip]
            if unread:  # The way moved onto switches not read yet: read them (and their neighbors) too
                self.rounds += 1
                self.read(vlan_path.candidates(self.network_map, route=plan.route), "plan")

    def make_plan(self):
        vlan = self.vlan()
        if vlan is None or self.network_map is None:
            return
        if self.by_hand():
            self.plan = vlan_path.plan(self.network_map, vlan, self.name_input.text(), edge_ports=self.edge_ports(),
                                       stp=self.stp, route=self.route, route_hops=self.route_hops(),
                                       chosen=self.chosen)
        else:
            self.plan = vlan_path.plan(self.network_map, vlan, self.name_input.text(),
                                       a=self.a_combo.currentData() or None, b=self.b_combo.currentData(),
                                       edge_ports=self.edge_ports(), stp=self.stp, chosen=self.chosen)
        self.statuses, self.after_send = {}, []
        self.show_plan()

    def on_redundant_changed(self, item):
        hop_key = item.data(Qt.UserRole)
        if item.checkState() == Qt.Checked:
            self.chosen.add(hop_key)
        else:
            self.chosen.discard(hop_key)
        if self.plan is not None:
            self.make_plan()  # The switches were read already: no need to read them again

    def plan_outdated(self, *_):
        if self.plan is not None:
            self.clear_plan()
            set_hint(self.status_label, "Changed: Plan again.", "info")

    def clear_plan(self):
        self.plan = None
        self.chosen = set()
        self.statuses, self.after_send = {}, []
        self.findings_list.clear()
        self.redundant_list.blockSignals(True)
        self.redundant_list.clear()
        self.redundant_list.blockSignals(False)
        self.steps_table.setRowCount(0)
        self.step_menus = {}
        self.preview.clear()
        self.route_label.clear()
        self.gateway_label.clear()
        self.update_buttons()
        self.show_route_preview()

    # ----------------------------------------------------------------- Showing the plan

    def show_plan(self):
        plan, network_map = self.plan, self.network_map
        labels = [vlan_path.label_of(network_map, key) for key in plan.route]
        if plan.route and not plan.by_hand:
            self.copy_plan_route()
        if plan.route:
            how = " (set by hand)" if plan.by_hand else ""
            already = f" VLAN {plan.vlan} already reaches {labels[-1]}." if plan.already else ""
            self.route_label.setText(f"<b>Route{how}:</b> {' &gt; '.join(labels)}.{already}")
        else:
            self.route_label.setText("<b>No route.</b>")
        if plan.gateway is not None:
            color = COLORS[SEVERITY_COLORS[plan.gateway.severity]] if plan.gateway.severity != vlans.INFO \
                else COLORS["text"]
            self.gateway_label.setText(f"<span style='color:{color}'><b>Gateway:</b> {plan.gateway.text}</span>")
        else:
            self.gateway_label.clear()
        self.fill_findings()
        self.redundant_list.blockSignals(True)
        self.redundant_list.clear()
        for item in plan.redundant:
            row = QListWidgetItem(f"{item.hop.text(network_map)}: {item.note}")
            row.setData(Qt.UserRole, item.hop.key)
            row.setFlags(row.flags() | Qt.ItemIsUserCheckable)
            row.setCheckState(Qt.Checked if item.hop.key in self.chosen else Qt.Unchecked)
            row.setForeground(QColor(COLORS[SEVERITY_COLORS[item.severity]] if item.severity == vlans.WARNING
                                     else COLORS["text"]))
            self.redundant_list.addItem(row)
        if not plan.redundant:
            row = QListWidgetItem("None: no other link joins switches that will carry the VLAN.")
            row.setFlags(Qt.NoItemFlags)
            self.redundant_list.addItem(row)
        self.redundant_list.blockSignals(False)
        self.fill_steps()
        self.update_buttons()
        self.show_highlights()
        changes = plan.changes
        if not plan.ok:
            set_hint(self.status_label, "Can't be done as it is: see the problems listed.", "error")
        elif not changes:
            set_hint(self.status_label, f"Nothing to change: VLAN {plan.vlan} already gets there.", "success")
        else:
            failed = f" {len(self.failed)} didn't answer: {', '.join(self.failed[:4])}." if self.failed else ""
            set_hint(self.status_label, f"{len(changes)} switch{'es' if len(changes) != 1 else ''} to change. Send All "
                                        f"over SSH, or send each in order (the Send button on its row), then "
                                        f"Verify.{failed}",
                     "warning" if self.failed else "success")

    def fill_findings(self):
        self.findings_list.clear()
        findings = list(self.plan.findings) + list(self.after_send)
        if self.failed:
            findings.append(vlans.Finding(vlans.WARNING, f"Didn't answer SNMP, so planned from the map as it was: "
                                                         f"{', '.join(self.failed)}."))
        for finding in findings:
            label = vlans.SEVERITY_LABELS[finding.severity]
            item = QListWidgetItem(f"{label}: {finding.text}")
            item.setForeground(QColor(COLORS[SEVERITY_COLORS[finding.severity]] if finding.severity != vlans.INFO
                                      else COLORS["text"]))
            self.findings_list.addItem(item)
        if not findings:
            item = QListWidgetItem("No problems found.")
            item.setForeground(QColor(COLORS["muted"]))
            self.findings_list.addItem(item)

    def fill_steps(self):
        plan, network_map = self.plan, self.network_map
        changes = plan.changes if plan.ok else []
        self.steps_table.setRowCount(len(changes))
        self.step_menus = {}
        for row, step in enumerate(changes):
            name = QTableWidgetItem(f"{row + 1}. {vlan_path.label_of(network_map, step.device)}")
            self.steps_table.setItem(row, 0, name)
            what = QTableWidgetItem(changes_text(step, plan.vlan, network_map))
            what.setToolTip(what.text())
            self.steps_table.setItem(row, 1, what)
            self.steps_table.setItem(row, 2, QTableWidgetItem(""))
            button = QToolButton()
            button.setText("Send")
            button.setPopupMode(QToolButton.InstantPopup)
            menu = QMenu(button)
            menu.aboutToShow.connect(self.fill_step_menu)
            button.setMenu(menu)
            self.step_menus[menu] = row
            self.steps_table.setCellWidget(row, 3, button)
            self.show_status(row)
        if changes:
            self.steps_table.selectRow(0)
        self.show_preview()

    def show_status(self, row):
        text = self.statuses.get(row, "Not sent")
        item = self.steps_table.item(row, 2)
        if item is None:
            return
        item.setText(text)
        item.setToolTip(text)
        color = COLORS["success"] if text.startswith("Done") else COLORS["error"] if text.startswith(
            ("Not done", "Refused", "Couldn't")) else COLORS["text"] if text.startswith(("Sent", "Undone")) \
            else COLORS["muted"]
        item.setForeground(QColor(color))

    def step(self, row):
        if self.plan is None or not self.plan.ok or not 0 <= row < len(self.plan.changes):
            return None
        return self.plan.changes[row]

    def step_text(self, row, kind):
        step = self.step(row)
        if step is None:
            return ""
        make = vlan_path.undo if kind == "undo" else vlan_path.config
        return make(step, self.plan.vlan, self.save_check.isChecked())

    def fill_step_menu(self):
        menu = self.sender()
        row = self.step_menus.get(menu)
        step = self.step(row) if row is not None else None
        if step is None:
            return
        device = self.network_map.devices.get(step.device)
        hints = {}
        if device is not None and device.mgmt_ip:
            hints = dict(self.page.session_hints(self.network_map, device), address=device.mgmt_ip)
        self.session_sender.fill_menu(menu, functools.partial(self.step_text, row, CONFIG), device=hints,
                                      tag=(row, CONFIG))
        self.add_ssh_action(menu, menu, row, CONFIG)
        menu.addSeparator()
        undo = menu.addMenu("Send Undo")
        self.session_sender.fill_menu(undo, functools.partial(self.step_text, row, UNDO), device=hints,
                                      tag=(row, UNDO))
        self.add_ssh_action(menu, undo, row, UNDO)

    def add_ssh_action(self, owner, menu, row, kind):
        """Over SSH, first in menu (made in Python and owned by owner, so no stale wrapper is kept)."""
        actions = menu.actions()
        first = actions[0] if actions else None
        action = QAction("Over SSH (no one watching)", owner)
        action.setData((row, kind))
        action.setEnabled(not self.busy())
        action.triggered.connect(self.on_ssh_action)
        menu.insertAction(first, action)
        menu.insertSeparator(first)

    def lines_sent(self, view, tag):
        """SessionSender: lines went to a session."""
        if not tag or self.plan is None:
            return
        row, kind = tag
        self.statuses[row] = f"Sent{' undo' if kind == UNDO else ''} to {view.title}"
        self.show_status(row)
        sent = self.sent_for(row)
        if sent is not None:
            if kind == UNDO:
                self.sent.pop(sent.key, None)
            else:
                self.sent[sent.key] = sent
            self.update_buttons()

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
            set_hint(self.status_label, "Copied. Paste it at the switch's enable (#) prompt.", "success")

    def export_all(self):
        plan = self.plan
        if plan is None or not plan.ok or not plan.changes:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Carry VLAN", f"carry-vlan-{plan.vlan}.txt",
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(vlan_path.export_text(self.network_map, plan, self.save_check.isChecked()))
        except OSError as error:
            QMessageBox.critical(self, "Export Carry VLAN", f"Couldn't save it:\n\n{error}")
            return
        set_hint(self.status_label, f"Saved every switch's configuration and undo to {path}.", "success")

    def busy(self):
        return self.thread is not None or self.push_thread is not None

    def update_buttons(self):
        plan = self.plan
        reading, pushing = self.thread is not None, self.push_thread is not None
        self.plan_button.setEnabled(not reading and not pushing)
        ready = plan is not None and plan.ok and bool(plan.changes) and not reading
        self.verify_button.setEnabled(ready and not pushing)
        self.export_button.setEnabled(ready)
        self.send_button.setText("Stop" if pushing else "Send All over SSH")
        self.send_button.setEnabled(pushing or ready)
        self.undo_button.setEnabled(bool(self.sent) and not reading and not pushing)
        self.edit_route_button.setEnabled(plan is not None and bool(plan.route) and not plan.by_hand and not reading)

    def set_busy(self, busy):
        self.plan_button.setText("Reading..." if busy else "Plan")
        self.update_buttons()

    # ----------------------------------------------------------------- Sending over SSH

    def on_login_changed(self):
        self.saved_logins = None

    def logins(self):
        """(macssh.SshLogins, enable secret), asked for the first time they're needed; None if cancelled."""
        if self.saved_logins is None:
            self.saved_logins = self.login_row.logins(self.status_label)
        return self.saved_logins

    def sent_for(self, row):
        """A Sent for the plan's step on row (with its undo as it would be sent now), or None."""
        step = self.step(row)
        device = self.network_map.devices.get(step.device) if step is not None else None
        if device is None:
            return None
        names = [name for name in [device.name, *device.addresses] if name]
        return Sent(step.device, device.label, device.mgmt_ip or "", self.plan.vlan, step.redundant,
                    self.step_text(row, UNDO), names)

    def send_all_over_ssh(self):
        if self.push_thread is not None:
            self.push_thread.stop()
            set_hint(self.status_label, "Stopping after the switch being sent to now...", "warning")
            return
        plan = self.plan
        if plan is None or not plan.ok or not plan.changes or self.busy():
            return
        rows = [row for row in range(len(plan.changes))
                if not self.statuses.get(row, "").startswith(("Done", "Sent over SSH"))]
        if not rows:
            set_hint(self.status_label, "Every switch has been sent its lines: Verify to check.", "info")
            return
        self.send_rows(rows)

    def on_ssh_action(self):
        action = self.sender()
        data = action.data() if action is not None else None
        if not data or self.busy():
            return
        row, kind = data
        sent = self.sent_for(row)
        if sent is None:
            return
        if kind == UNDO:
            self.undo_over_ssh([self.sent.get(sent.key, sent)])
        else:
            self.send_rows([row])

    def send_rows(self, rows):
        """Send the plan's steps on rows over SSH, in order, after asking."""
        plan = self.plan
        sents = {row: self.sent_for(row) for row in rows}
        if None in sents.values():
            return
        missing = [sent.label for sent in sents.values() if not sent.address]
        if missing:
            set_hint(self.status_label, f"NOMAD has no address to log in to {', '.join(missing)} over SSH.", "error")
            return
        labels = "\n".join(sent.label + (" (redundant links)" if sent.redundant else "") for sent in sents.values())
        saved = ("Each switch's configuration is saved afterwards (write memory)." if self.save_check.isChecked()
                 else "Nothing is saved (write memory is off): a switch that reloads comes back without it.")
        where = f"these {len(rows)} switches, one at a time in this order" if len(rows) > 1 else "this switch"
        question = (f"Send VLAN {plan.vlan} to {where} over SSH?\n\n{labels}\n\nIt stops at the first line a switch "
                    f"refuses. {saved}")
        if QMessageBox.question(self, "Send over SSH", question, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        logins = self.logins()
        if logins is None:
            return
        self.push_sent, self.push_failed = sents, []
        jobs = [Job(row, sent.address, sent.names, self.step_text(row, CONFIG)) for row, sent in sents.items()]
        self.start_push(jobs, CONFIG, logins)

    def undo_sent_over_ssh(self):
        if self.sent and not self.busy():
            self.undo_over_ssh(list(reversed(self.sent.values())))

    def undo_over_ssh(self, items):
        """Send each Sent's undo, in the order given (after asking), carrying on past switches that refuse."""
        missing = [item.label for item in items if not item.address]
        if missing:
            set_hint(self.status_label, f"NOMAD has no address to log in to {', '.join(missing)} over SSH.", "error")
            return
        numbers = ", ".join(str(vlan) for vlan in sorted({item.vlan for item in items}))
        labels = "\n".join(item.label + (" (redundant links)" if item.redundant else "") for item in items)
        question = (f"Take VLAN {numbers} back out over SSH, in this order?\n\n{labels}\n\nEach switch gets the undo "
                    "of what it was sent: the trunks lose the VLAN, edge ports go back to the VLAN they were in, and a "
                    "VLAN NOMAD created is deleted.")
        if QMessageBox.question(self, "Undo over SSH", question, QMessageBox.Yes | QMessageBox.No) != QMessageBox.Yes:
            return
        logins = self.logins()
        if logins is None:
            return
        for item in items:  # Undoing a step only typed in by hand still needs a place to come off
            self.sent.setdefault(item.key, item)
        self.push_keys = [item.key for item in items]
        jobs = [Job(index, item.address, item.names, item.undo) for index, item in enumerate(items)]
        self.start_push(jobs, UNDO, logins)

    def start_push(self, jobs, kind, logins):
        self.push_kind, self.push_plan = kind, self.plan
        thread = PushThread(jobs, self.login_row.pusher_maker(logins, self.shell_factory), kind == CONFIG, self)
        thread.step_started.connect(self.on_push_started)
        thread.step_done.connect(self.on_push_done)
        thread.finished.connect(self.on_push_finished)
        self.push_thread = thread
        self.page.check_threads.append(thread)
        what = "Sending to" if kind == CONFIG else "Taking it back out of"
        set_hint(self.status_label, f"{what} {len(jobs)} switch{'es' if len(jobs) != 1 else ''} over SSH...", "info")
        self.update_buttons()
        thread.start()

    def row_of(self, key):
        """The plan's row for a Sent.key (while it's the plan being sent for), or None."""
        plan = self.plan
        if plan is None or plan is not self.push_plan or not plan.ok:
            return None
        device, redundant, vlan = key
        if vlan != plan.vlan:
            return None
        return next((row for row, step in enumerate(plan.changes)
                     if step.device == device and step.redundant == redundant), None)

    def set_row_status(self, row, text):
        if row is not None and self.plan is not None and self.plan is self.push_plan:
            self.statuses[row] = text
            self.show_status(row)

    def on_push_started(self, index):
        if self.push_kind == CONFIG:
            self.set_row_status(index, "Sending over SSH...")
        elif 0 <= index < len(self.push_keys):
            self.set_row_status(self.row_of(self.push_keys[index]), "Undoing over SSH...")

    def on_push_done(self, index, outcome):
        if outcome.transcript:
            log.info("Carry VLAN, %s:\n%s", self.push_kind, outcome.transcript)
        if self.push_kind == CONFIG:
            sent = self.push_sent.get(index)
            if sent is not None and (outcome.ok or outcome.transcript):  # Lines went in, even if one was refused
                self.sent[sent.key] = sent
            if not outcome.ok:
                self.push_failed.append(index)
            if outcome.ok:
                status = "Sent over SSH"
            elif outcome.refused:
                status = f"Refused: {outcome.first_error}"
            else:
                status = f"Couldn't send: {outcome.problem or 'no reason given'}"
            self.set_row_status(index, status)
        elif 0 <= index < len(self.push_keys):
            key = self.push_keys[index]
            if outcome.ok:
                self.sent.pop(key, None)
            self.set_row_status(self.row_of(key), "Undone over SSH" if outcome.ok else
                                f"Couldn't undo: {outcome.problem or 'no reason given'}")

    def on_push_finished(self):
        thread = self.sender()
        if thread is not self.push_thread:
            return
        self.push_thread = None
        if thread in self.page.check_threads:
            self.page.check_threads.remove(thread)
        thread.deleteLater()
        self.update_buttons()
        if self.push_kind == UNDO:
            left = [self.sent[key].label for key in self.push_keys if key in self.sent]
            total = len(self.push_keys)
            if left:
                set_hint(self.status_label, f"Couldn't take it back out of {', '.join(left)}: see the Status column "
                                            "(and View Log for what the switch said).", "error")
            elif thread.stopping:
                set_hint(self.status_label, "Stopped.", "warning")
            else:
                set_hint(self.status_label, f"Taken back out of {total} switch{'es' if total != 1 else ''}. Verify "
                                            "(or Plan) reads them again.", "success")
            return
        sent_now = [sent for sent in self.push_sent.values() if self.sent.get(sent.key) is sent]
        count = f"{len(sent_now)} switch{'es' if len(sent_now) != 1 else ''}"
        if thread.failed:
            failed = self.push_sent.get(self.push_failed[0]) if self.push_failed else None
            label = failed.label if failed is not None else "A switch"
            text = f"{label} didn't take it, so nothing more was sent."
            if sent_now:
                names = ", ".join(sent.label for sent in sent_now)
                partly = f" (with what {label} took before it refused)" if failed in sent_now else ""
                box = QMessageBox(QMessageBox.Warning, "Send over SSH",
                                  f"{text}\n\nTake back out what was already sent to {names}{partly}?",
                                  QMessageBox.Yes | QMessageBox.No, self)
                if box.exec_() == QMessageBox.Yes:
                    self.undo_over_ssh(list(reversed(sent_now)))
                    return
            set_hint(self.status_label, text + " See the Status column (and View Log for what the switch said).",
                     "error")
        elif thread.stopping:
            set_hint(self.status_label, f"Stopped after {count}.", "warning")
        elif self.plan is not None and self.plan is self.push_plan:
            set_hint(self.status_label, f"Sent to {count} over SSH. Checking it took...", "success")
            self.start_verify()
        else:
            set_hint(self.status_label, f"Sent to {count} over SSH. Plan again to check it.", "success")

    # ----------------------------------------------------------------- Checking it worked

    def verify(self):
        plan = self.plan
        if plan is None:
            return
        outcome, others = vlan_path.verify(self.network_map, plan)
        done = 0
        for row, problems in outcome.items():
            if problems:
                self.statuses[row] = "Not done: " + " ".join(problems)
            else:
                self.statuses[row] = "Done"
                done += 1
            self.show_status(row)
        hop_ends = {(key, vlan_path.port_key(hop.port_on(key))) for hop in plan.hops if hop is not None
                    for key in (hop.a, hop.b)}
        hop_ends |= {(key, vlan_path.port_key(item.hop.port_on(key))) for item in plan.chosen
                     for key in (item.hop.a, item.hop.b)}
        mistakes = [finding for finding in vlans.check_map(self.network_map)
                    if (finding.device, vlan_path.port_key(finding.port)) in hop_ends
                    or (finding.other, vlan_path.port_key(finding.other_port)) in hop_ends]
        self.after_send = [vlans.Finding(vlans.WARNING, text) for text in others] + \
            [vlans.Finding(finding.severity, "After sending: " + finding.text, finding.device, finding.port)
             for finding in mistakes]
        self.fill_findings()
        self.show_highlights()
        total = len(outcome)
        failed = f" {len(self.failed)} didn't answer: {', '.join(self.failed[:4])}." if self.failed else ""
        if done == total and not others:
            set_hint(self.status_label, f"Verified: VLAN {plan.vlan} is carried to "
                                        f"{vlan_path.label_of(self.network_map, plan.b)} on every switch.{failed}",
                     "success" if not failed else "warning")
        else:
            set_hint(self.status_label, f"{done} of {total} switch{'es' if total != 1 else ''} done. See the Status "
                                        f"column (send the rest, or Verify again in a moment).{failed}", "warning")
        self.failed = []

    # ----------------------------------------------------------------- The map

    def show_highlights(self):
        plan = self.plan
        if plan is None:
            self.show_route_preview()
            return
        if self.page.network_map is not self.network_map:
            return
        if self.page.vlan_shown != (plan.vlan, None):
            self.page.highlight_vlan(plan.vlan, None)
        changing = {step.device for step in plan.changes} if plan.ok else set()
        colors = {key: COLORS["success"] for key in plan.route}
        colors.update({key: COLORS["warning"] for key in changing})
        for row, text in self.statuses.items():
            step = self.step(row)
            if step is not None and text == "Done":
                colors[step.device] = COLORS["success"]
        self.page.view.set_highlights(colors)
        self.page.view.set_path_overlay(self.path_overlay())

    def path_overlay(self):
        """The route and redundant links to draw over the map's links (MapView.set_path_overlay)."""
        plan, graph = self.plan, self.graph()
        links = {}

        def note(hop):
            ends = [f"{graph.label(key)} {hop.port_on(key)}" for key in (hop.a, hop.b)
                    if key in graph.devices and vlan_path.end_state(graph.devices[key], hop.port_on(key),
                                                                     plan.vlan) == vlan_path.ADD]
            return f"allowed vlan add {plan.vlan} on {' and '.join(ends)}" if ends else ""

        def put(hop, kind, text):
            for link in hop.links:
                links[link.key] = (kind, text)

        chosen = {item.hop.key for item in plan.chosen}
        for item in plan.redundant:
            if vlan_path.carries(graph, item.hop, plan.vlan):
                put(item.hop, PATH_CARRIES, "a redundant link: carries it")
            elif item.hop.key in chosen:
                put(item.hop, PATH_CHOSEN, "a redundant link, ticked: " + (note(item.hop) or "to carry it"))
            else:
                put(item.hop, PATH_OFFERED, "a redundant link, not ticked: left as it is")
        for hop in plan.hops:
            if hop is None:
                continue
            states = vlan_path.hop_states(graph, hop, plan.vlan)
            if vlan_path.BLOCKED in states:
                put(hop, PATH_BLOCKED, "can't carry it (an access port in another VLAN, or a router port without a "
                                       "subinterface for it)")
            elif vlan_path.carries(graph, hop, plan.vlan):
                put(hop, PATH_CARRIES, "on the route: carries it")
            else:
                put(hop, PATH_PLANNED, "on the route: " + (note(hop) or "the switches need the VLAN"))
        devices = set(plan.route) | {step.device for step in plan.changes}
        return {"vlan": plan.vlan, "devices": devices, "links": links, "order": list(plan.route)}

    def show_route_preview(self):
        """Before Plan, the route set by hand on the map as it's being set: its switches ringed and numbered in
        order, the link chosen between each two (or every link that could be, until one is chosen), a red line where
        two have no link between them, and while picking, a line from the last one picked to the mouse."""
        view = self.page.view
        if self.network_map is None or self.page.network_map is not self.network_map:
            return
        if not self.by_hand() or not self.route:
            view.set_highlights({})
            view.set_path_overlay(None)
            view.set_pick_anchor(None)
            return
        graph = self.graph()
        links, gaps = {}, []
        for index, (one, other) in enumerate(zip(self.route, self.route[1:])):
            step = f"{index + 1} to {index + 2}, {graph.label(one)} to {graph.label(other)}"
            between = graph.between(one, other)
            if not between:
                gaps.append((one, other, f"No link between {graph.label(one)} and {graph.label(other)} ({step}): "
                                         "Fill In Between adds the switches between them."))
                continue
            wanted = self.hop_choices.get(frozenset([one, other]))
            chosen = [hop for hop in between if hop.key == wanted] or (between if len(between) == 1 else [])
            for hop in between:
                entry = (PATH_ROUTE, f"the route set by hand ({step})") if hop in chosen else \
                    (PATH_OFFERED, f"one of {len(between)} links for {step}: choose one in the route")
                for link in hop.links:
                    links[link.key] = entry
        view.set_highlights({key: COLORS["accent"] for key in self.route})
        view.set_path_overlay({"vlan": self.vlan(), "devices": set(self.route), "links": links,
                               "order": list(self.route), "gaps": gaps})
        view.set_pick_anchor(self.route[-1] if self.picking else None)

    def on_map_shown(self):
        if self.page.network_map is not self.network_map:
            if self.isVisible():
                self.network_map = self.page.network_map
                self.route, self.hop_choices = [], {}
                self.fill_choices()
                self.refresh_route()
                self.fill_edge_ports()
                self.clear_plan()
                set_hint(self.status_label, "Another map was opened: choose what to carry on it.", "info")
            return
        if self.isVisible():
            self.show_highlights()

    def closeEvent(self, event):
        if self.picking:
            self.page.view.stop_picking()
        if self.thread is not None:
            self.thread.stop()
        self.session_sender.stop_waiting()
        self.page.view.set_highlights({})
        self.page.view.set_path_overlay(None)
        if self.previous_vlan is not None:
            _, shown = self.previous_vlan
            self.previous_vlan = None
            if self.page.network_map is self.network_map and self.page.vlan_shown != shown:
                self.page.vlan_shown = shown
                self.page.apply_vlan_focus()
        super().closeEvent(event)
