"""ACLs & Route Maps page: read the ACLs, prefix lists and route maps of Cisco IOS / IOS-XE devices, edit them, and
send the changes back safely.

Pick a device (the open map's switches and routers, saved SSH sessions, or an address) and Read: NOMAD logs in over
SSH and reads its ACLs (IPv4 standard and extended, numbered and named; IPv6), object groups, time ranges, where each
ACL is applied, and how many packets each rule has matched. Edit rules (add, change, move, delete), make ACLs, apply
them to interfaces or VTY lines or take them off; nothing goes to the device until Send. The Changes box always shows
the exact lines (and what undoes them): rules changed by sequence number, a changed rule added before the old one is
taken out, so there's never a moment without it.

Checks as you go: rules that can never match (an earlier rule takes everything they would), rules not needed,
subnet masks written where a wildcard goes, an IPv6 deny that kills neighbor discovery, and whether this PC could
still log in after the change (VTY access-class, and the ACL on the interface its packets come in on). The packet
tester says which rule a packet matches.

Send over SSH puts the changes in with a revert timer (configure terminal revert timer N): NOMAD then logs in again
and only if that works says configure confirm (or leaves that to you: the device waits, counting down, for Confirm or
Put Back Now); a refused line or a failed login has it put back right away. Send to Session types the same lines into
a terminal session (Confirm and Put Back Now are then typed there).

Prefix lists and route maps (routepolicy.py, policy_editors.py) are edited the same way, entry by entry, and put on
BGP neighbors, redistributions, policy routing and distribute lists; a route tester says what one does with a route.
Once a change touching a BGP neighbor's policy is confirmed, the neighbors it affects are offered for a soft clear
(none ticked), since BGP only applies a new policy to routes already learned after one.

The Library keeps ACLs on this PC (with the object groups and time ranges they name), prefix lists, and route maps
(with the prefix lists and ACLs they match) to put on other devices; the Scratch Pad is a device that isn't one, to
build from nothing. Changes Sent lists every change sent from this PC with what undoes it.
"""
import datetime
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from PyQt5.QtCore import QDateTime, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QDateTimeEdit, QDialog, \
    QFileDialog, QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, \
    QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox, QSplitter, \
    QStackedWidget, QTableWidgetItem, QTabWidget, QTimeEdit, QToolButton, QTreeWidget, QTreeWidgetItem, \
    QVBoxLayout, QWidget

from ..netmap import acl, aclcheck, configpush, routepolicy
from ..netmap.acl import INTERFACE, LINE, NETWORK, OTHER, SERVICE, STANDARD, V4, V6, DeviceAcls, ObjectGroup, \
    TimeRange
from ..netmap.model import ROUTER, SWITCH, port_key
from ..netmap.vlans import ERROR, WARNING
from ..terminal.sessions import SSH
from .acl_dialogs import AddressPicker, ApplyDialog, DevicePicker, ImportDialog, NewAclDialog, RuleDialog, \
    TextDialog, severity_color
from .common import StoppableThread, local_address_toward, read_only_table, release_thread, set_hint
from .policy_dialogs import NewPolicyDialog
from .policy_editors import PrefixListEditor, RouteMapEditor, SeqTable
from .session_send import SessionSender
from .ssh_push import Job, LoginRow
from .theme import COLORS, accent_button, monospace_font

log = logging.getLogger(__name__)

READ_WORKERS = 4
DEFAULT_MINUTES = 5
SCRATCH = "scratch"
RULE_COLUMNS = ["Seq", "Action", "Protocol", "Source", "Src Ports", "Destination", "Dst Ports", "Options", "Hits",
                "Remark"]
STANDARD_HIDDEN = (2, 4, 5, 6, 7)
LIBRARY_COLUMNS = ["Name", "What", "Entries", "Saved", "Notes"]
HISTORY_COLUMNS = ["When", "Device", "Change", "How", "Outcome"]
KIND_ACL, KIND_GROUP, KIND_RANGE, KIND_PLIST, KIND_RMAP = "acl", "group", "range", "plist", "rmap"
SEND, SAVE, CONFIRM, REVERT, SOFT = "", "save", "confirm", "revert", "soft"  # What a SendJob does
CONFIRM_AUTO, CONFIRM_MANUAL = "auto", "manual"
EXPIRY_GRACE = 20  # Seconds past the revert time before NOMAD takes it the device has put it back
DAY_CHOICES = ["weekdays", "weekend", "daily", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday",
               "Sunday"]
MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October",
               "November", "December"]


@dataclass
class Target:
    """A device ACLs can be read from."""
    key: str
    label: str
    address: str = ""
    names: list = field(default_factory=list)
    source: str = "map"  # "map", "session", "address" or SCRATCH
    map_key: str = ""


class ReadThread(StoppableThread):
    """Reads a few devices' ACLs over SSH at once."""
    device_read = pyqtSignal(str, object)  # Target key, acl.DeviceAcls

    def __init__(self, targets, make_pusher, parent=None):
        super().__init__(parent)
        self.targets, self.make_pusher = targets, make_pusher  # [(key, address, names, pc_ip)]

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            def read(target):
                key, address, names, pc_ip = target
                if self.stopping:
                    return
                try:
                    device = pusher.read_acls(address, names, pc_ip) if address else \
                        DeviceAcls(problem="it has no address.")
                except Exception as error:  # One device's trouble shouldn't stop the rest
                    log.exception("Reading %s's ACLs failed", address)
                    device = DeviceAcls(problem=str(error))
                if not self.stopping:
                    self.device_read.emit(key, device)
            with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(self.targets)))) as executor:
                list(executor.map(read, self.targets))
        finally:
            pusher.close()


@dataclass
class SendJob(Job):
    key: str = ""
    undo: str = ""
    title: str = ""
    action: str = SEND  # SEND the text, or SAVE (write memory), CONFIRM (configure confirm), REVERT (revert now),
    # SOFT (the text's lines are exec commands: BGP soft clears)


@dataclass
class Waiting:
    """Changes in with the revert timer, waiting for the user to confirm them (or put them back)."""
    deadline: object  # When the device puts its old configuration back (datetime)
    view: object = None  # The terminal view they were typed into (None: sent over SSH)
    entry_id: str = ""  # Their Changes Sent entry

    @property
    def at(self):
        return self.deadline.strftime("%H:%M")


class SendThread(StoppableThread):
    """Sends each device its changes in turn (with the revert timer when minutes), stopping at the first that
    doesn't take them."""
    step_started = pyqtSignal(int)
    step_done = pyqtSignal(int, object)  # Job index, configpush.Outcome

    def __init__(self, jobs, make_pusher, minutes, confirm=True, parent=None):
        super().__init__(parent)
        self.jobs, self.make_pusher, self.minutes, self.confirm = jobs, make_pusher, minutes, confirm

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for job in self.jobs:
                if self.stopping:
                    break
                self.step_started.emit(job.index)
                try:
                    if job.action == SOFT:
                        results = pusher.run_commands(job.address, job.text.splitlines(), job.names)
                        said = "\n".join(f"{command}\n{answer}".strip() for command, answer, _ in results)
                        problem = next((f"{command}: {answer}" for command, answer, took in results if not took),
                                       "")
                        outcome = configpush.Outcome(ok=not problem, transcript=said, problem=problem)
                    elif job.action in (SAVE, CONFIRM, REVERT):
                        do = {SAVE: pusher.save_config, CONFIRM: pusher.confirm, REVERT: pusher.revert}[job.action]
                        ok, said = do(job.address, job.names)
                        outcome = configpush.Outcome(ok=ok, transcript=said, problem="" if ok else said)
                    elif self.minutes:
                        outcome = pusher.set_up_guarded(job.address, job.text, self.minutes, job.names,
                                                        self.confirm)
                    else:
                        outcome = pusher.set_up(job.address, job.text, "", job.names)
                except Exception as error:
                    log.exception("Sending to %s failed", job.address)
                    outcome = configpush.Outcome(problem=str(error))
                self.step_done.emit(job.index, outcome)
                if not outcome.ok:
                    break
        finally:
            pusher.close()


class RulesTable(SeqTable):
    """The rules, which can be dragged to a new place."""

    def __init__(self):
        super().__init__(RULE_COLUMNS)


class AclTab(QWidget):
    def __init__(self, window, store=None):
        super().__init__(window)
        self.window = window
        self.sessions = getattr(window, "session_store", None)
        self.store = store if store is not None else acl.AclStore.default()
        self.shell_factory = configpush.ConfigShell  # Tests swap in fake devices
        self.targets = {}  # key -> Target
        self.read = {}  # key -> DeviceAcls as read from the device
        self.working = {}  # key -> DeviceAcls as edited
        self.notes = {}  # key -> what happened to it last (shown under its name)
        self.current_key = ""
        self.current_item = None  # (KIND_ACL, (family, name)) / (KIND_GROUP, name) / (KIND_RANGE, name)
        self.reader = None
        self.sender_thread = None
        self.send_jobs = []
        self.saved_logins = None
        self.waiting = {}  # key -> Waiting: changes in with the revert timer, for the user to confirm
        self.saveable = set()  # keys whose changes were confirmed over SSH (Save to Startup Config offered)
        self.after_read = None  # A callable to run once a read is done
        self.pending_library = None  # (LibraryEntry, keys) to put on devices once they're read
        self.send_results = {}  # Job index -> whether it took
        self.selecting = ""  # An ACL (or "port:NAME") to show once the device is read
        self.scratch_key = SCRATCH
        self.pending_soft = {}  # key -> [routepolicy.SoftClear] for changes sent, offered once they're confirmed
        self.soft_offers = {}  # key -> ([SoftClear], the terminal view the changes went to, or None)
        self.filling_rules = False  # The rules table is being filled (its itemChanged isn't the user typing)
        self.pending_number = None  # (row, text) typed into a Seq cell, taken once the editor has closed
        self.session_sender = SessionSender(self, window, None)
        self.tick = QTimer(self)
        self.tick.setInterval(1000)
        self.tick.timeout.connect(self.on_tick)
        self.init_ui()
        self.session_sender.status_label = self.status_label
        page = self.map_page()
        if page is not None and hasattr(page, "map_shown"):
            page.map_shown.connect(self.on_map_shown)
        self.add_scratch()
        self.on_map_shown()
        self.fill_library()
        self.fill_history()

    # ----------------------------------------------------------------- Building the page

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Read, build and edit ACLs (IPv4 and IPv6, object groups, time ranges), prefix lists and "
                       "route maps on Cisco IOS / IOS-XE devices, see entries that never match and whether a change "
                       "would lock you out, test packets and routes, and send the changes entry by entry with a "
                       "revert timer, so a mistake puts itself back.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.make_edit_tab(), "Edit")
        self.tabs.addTab(self.make_library_tab(), "Library")
        self.tabs.addTab(self.make_history_tab(), "Changes Sent")
        layout.addWidget(self.tabs, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.update_buttons()

    def make_edit_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        splitter = QSplitter(Qt.Vertical)
        top = QSplitter(Qt.Horizontal)
        top.addWidget(self.make_devices_box())
        top.addWidget(self.make_items_box())
        top.addWidget(self.make_editor())
        top.setStretchFactor(0, 2)
        top.setStretchFactor(1, 2)
        top.setStretchFactor(2, 6)
        splitter.addWidget(top)
        splitter.addWidget(self.make_changes_box())
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter, 1)
        return page

    def make_devices_box(self):
        box = QGroupBox("Devices")
        layout = QVBoxLayout(box)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find a device")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.textChanged.connect(self.filter_devices)
        layout.addWidget(self.find_input)
        self.device_list = QListWidget()
        self.device_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.device_list.currentItemChanged.connect(self.on_device_chosen)
        self.device_list.itemDoubleClicked.connect(self.read_chosen)
        layout.addWidget(self.device_list, 1)
        row = QHBoxLayout()
        self.read_button = accent_button("Read")
        self.read_button.setToolTip("Log in over SSH and read the selected devices' ACLs")
        self.read_button.clicked.connect(self.read_chosen)
        row.addWidget(self.read_button)
        self.add_button = QPushButton("Add Address...")
        self.add_button.clicked.connect(self.add_address)
        row.addWidget(self.add_button)
        layout.addLayout(row)
        self.login_row = LoginRow(self, self.sessions, "The ACLs page", stacked=True)
        layout.addWidget(self.login_row)
        return box

    def make_items_box(self):
        box = QGroupBox("On the Device")
        layout = QVBoxLayout(box)
        self.device_label = QLabel()
        self.device_label.setWordWrap(True)
        layout.addWidget(self.device_label)
        self.items_tree = QTreeWidget()
        self.items_tree.setHeaderLabels(["Name", "About"])
        self.items_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.items_tree.customContextMenuRequested.connect(self.show_item_menu)
        self.items_tree.currentItemChanged.connect(self.on_item_chosen)
        layout.addWidget(self.items_tree, 1)
        row = QHBoxLayout()
        self.new_acl_button = QPushButton("New ACL...")
        self.new_acl_button.clicked.connect(self.new_acl)
        row.addWidget(self.new_acl_button)
        self.new_button = QToolButton()
        self.new_button.setText("New")
        self.new_button.setPopupMode(QToolButton.InstantPopup)
        new_menu = QMenu(self.new_button)
        new_menu.addAction("Prefix List...", self.new_prefix_list)
        new_menu.addAction("Route Map...", self.new_route_map)
        new_menu.addSeparator()
        new_menu.addAction("Network Object Group...", self.new_network_group)
        new_menu.addAction("Service Object Group...", self.new_service_group)
        new_menu.addAction("Time Range...", self.new_time_range)
        self.new_button.setMenu(new_menu)
        row.addWidget(self.new_button)
        row.addStretch(1)
        layout.addLayout(row)
        return box

    def make_editor(self):
        self.editor = QStackedWidget()
        self.empty_label = QLabel("Read a device (or use the Scratch Pad), then pick an ACL, prefix list, route "
                                  "map, object group or time range here.")
        self.empty_label.setAlignment(Qt.AlignCenter)
        self.empty_label.setWordWrap(True)
        self.editor.addWidget(self.empty_label)
        self.editor.addWidget(self.make_acl_editor())
        self.editor.addWidget(self.make_group_editor())
        self.editor.addWidget(self.make_range_editor())
        self.plist_editor = PrefixListEditor(self)
        self.editor.addWidget(self.plist_editor)
        self.rmap_editor = RouteMapEditor(self)
        self.editor.addWidget(self.rmap_editor)
        return self.editor

    def make_acl_editor(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.acl_title = QLabel()
        font = self.acl_title.font()
        font.setBold(True)
        self.acl_title.setFont(font)
        head.addWidget(self.acl_title, 1)
        self.library_button = QPushButton("Save to Library...")
        self.library_button.clicked.connect(self.save_to_library)
        head.addWidget(self.library_button)
        self.compare_button = QPushButton("Compare...")
        self.compare_button.setToolTip("Compare with the same ACL on the other devices read")
        self.compare_button.clicked.connect(self.compare_across)
        head.addWidget(self.compare_button)
        self.delete_acl_button = QPushButton("Delete ACL")
        self.delete_acl_button.clicked.connect(self.delete_acl)
        head.addWidget(self.delete_acl_button)
        layout.addLayout(head)
        applied = QHBoxLayout()
        self.applied_label = QLabel()
        self.applied_label.setWordWrap(True)
        applied.addWidget(self.applied_label, 1)
        self.apply_button = accent_button("Apply To...")
        self.apply_button.setToolTip("Put this ACL on an interface (in or out) or on the VTY lines (access-class)")
        self.apply_button.clicked.connect(self.apply_acl)
        applied.addWidget(self.apply_button)
        self.take_off_button = QToolButton()
        self.take_off_button.setText("Take Off")
        self.take_off_button.setToolTip("Take this ACL off an interface or lines it's on")
        self.take_off_button.setPopupMode(QToolButton.InstantPopup)
        self.take_off_menu = QMenu(self.take_off_button)
        self.take_off_menu.aboutToShow.connect(self.fill_take_off_menu)
        self.take_off_button.setMenu(self.take_off_menu)
        applied.addWidget(self.take_off_button)
        layout.addLayout(applied)
        split = QSplitter(Qt.Vertical)
        rules = QWidget()
        rules_layout = QVBoxLayout(rules)
        rules_layout.setContentsMargins(0, 0, 0, 0)
        self.rules_table = RulesTable()
        self.rules_table.rows_moved.connect(self.move_rows)
        self.rules_table.itemDoubleClicked.connect(self.edit_rule)
        self.rules_table.itemChanged.connect(self.on_rule_cell_changed)
        self.rules_table.itemSelectionChanged.connect(self.update_buttons)
        self.rules_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.rules_table.customContextMenuRequested.connect(self.show_rule_menu)
        rules_layout.addWidget(self.rules_table, 1)
        row = QHBoxLayout()
        self.add_rule_button = accent_button("Add Rule...")
        self.add_rule_button.clicked.connect(self.add_rule)
        row.addWidget(self.add_rule_button)
        self.edit_rule_button = QPushButton("Edit...")
        self.edit_rule_button.clicked.connect(self.edit_rule)
        row.addWidget(self.edit_rule_button)
        self.duplicate_button = QPushButton("Duplicate")
        self.duplicate_button.clicked.connect(self.duplicate_rules)
        row.addWidget(self.duplicate_button)
        self.delete_rule_button = QPushButton("Delete")
        self.delete_rule_button.clicked.connect(self.delete_rules)
        row.addWidget(self.delete_rule_button)
        self.up_button = QPushButton("Move Up")
        self.up_button.clicked.connect(self.move_up)
        row.addWidget(self.up_button)
        self.down_button = QPushButton("Move Down")
        self.down_button.clicked.connect(self.move_down)
        row.addWidget(self.down_button)
        row.addStretch(1)
        rules_layout.addLayout(row)
        split.addWidget(rules)
        lower = QWidget()
        lower_layout = QHBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        findings_box = QGroupBox("Checks")
        findings_layout = QVBoxLayout(findings_box)
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        self.findings_list.itemClicked.connect(self.on_finding_clicked)
        findings_layout.addWidget(self.findings_list)
        lower_layout.addWidget(findings_box, 3)
        lower_layout.addWidget(self.make_tester(), 2)
        split.addWidget(lower)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        return page

    def make_tester(self):
        box = QGroupBox("Packet Tester")
        grid = QGridLayout(box)
        self.test_src = QLineEdit()
        self.test_src.setPlaceholderText("10.1.1.5")
        self.test_dst = QLineEdit()
        self.test_dst.setPlaceholderText("10.2.2.10")
        self.test_protocol = QComboBox()
        self.test_protocol.setEditable(True)
        self.test_protocol.addItems(["tcp", "udp", "icmp", "ip", "gre", "esp", "ospf"])
        self.test_src_port = QLineEdit()
        self.test_src_port.setPlaceholderText("any")
        self.test_dst_port = QLineEdit()
        self.test_dst_port.setPlaceholderText("443, www, or ICMP: echo")
        self.test_flags = QLineEdit()
        self.test_flags.setPlaceholderText("syn (a new connection); ack for a reply")
        self.test_now = QCheckBox("Now")
        self.test_now.setChecked(True)
        self.test_when = QDateTimeEdit(QDateTime.currentDateTime())
        self.test_when.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.test_when.setEnabled(False)
        self.test_now.toggled.connect(self.on_test_now)
        test_button = QPushButton("Test")
        test_button.clicked.connect(self.run_test)
        for edit in (self.test_src, self.test_dst, self.test_dst_port):
            edit.returnPressed.connect(self.run_test)
        self.test_result = QLabel()
        self.test_result.setWordWrap(True)
        grid.addWidget(QLabel("From:"), 0, 0)
        grid.addWidget(self.test_src, 0, 1)
        grid.addWidget(QLabel("To:"), 0, 2)
        grid.addWidget(self.test_dst, 0, 3)
        grid.addWidget(QLabel("Protocol:"), 1, 0)
        grid.addWidget(self.test_protocol, 1, 1)
        grid.addWidget(QLabel("Flags:"), 1, 2)
        grid.addWidget(self.test_flags, 1, 3)
        grid.addWidget(QLabel("From port:"), 2, 0)
        grid.addWidget(self.test_src_port, 2, 1)
        grid.addWidget(QLabel("To port:"), 2, 2)
        grid.addWidget(self.test_dst_port, 2, 3)
        when = QHBoxLayout()
        when.addWidget(self.test_now)
        when.addWidget(self.test_when, 1)
        grid.addWidget(QLabel("When:"), 3, 0)
        grid.addLayout(when, 3, 1, 1, 2)
        grid.addWidget(test_button, 3, 3)
        grid.addWidget(self.test_result, 4, 0, 1, 4)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)
        grid.setRowStretch(5, 1)
        return box

    def make_group_editor(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.group_title = QLabel()
        font = self.group_title.font()
        font.setBold(True)
        self.group_title.setFont(font)
        head.addWidget(self.group_title)
        head.addStretch(1)
        self.delete_group_button = QPushButton("Delete Group")
        self.delete_group_button.clicked.connect(self.delete_group)
        head.addWidget(self.delete_group_button)
        layout.addLayout(head)
        self.group_users_label = QLabel()
        self.group_users_label.setWordWrap(True)
        layout.addWidget(self.group_users_label)
        description = QHBoxLayout()
        description.addWidget(QLabel("Description:"))
        self.group_description = QLineEdit()
        self.group_description.editingFinished.connect(self.set_group_description)
        description.addWidget(self.group_description, 1)
        layout.addLayout(description)
        self.group_entries = QListWidget()
        self.group_entries.setFont(monospace_font())
        self.group_entries.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.group_entries, 1)
        row = QHBoxLayout()
        self.group_input = QLineEdit()
        self.group_input.returnPressed.connect(self.add_group_entry)
        row.addWidget(self.group_input, 1)
        self.group_pick_button = QPushButton("Pick...")
        self.group_pick_button.clicked.connect(self.pick_group_entry)
        row.addWidget(self.group_pick_button)
        add = QPushButton("Add")
        add.clicked.connect(self.add_group_entry)
        row.addWidget(add)
        remove = QPushButton("Remove")
        remove.clicked.connect(self.remove_group_entries)
        row.addWidget(remove)
        layout.addLayout(row)
        self.group_hint = QLabel()
        self.group_hint.setWordWrap(True)
        layout.addWidget(self.group_hint)
        return page

    def make_range_editor(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.range_title = QLabel()
        font = self.range_title.font()
        font.setBold(True)
        self.range_title.setFont(font)
        head.addWidget(self.range_title)
        head.addStretch(1)
        self.delete_range_button = QPushButton("Delete Time Range")
        self.delete_range_button.clicked.connect(self.delete_range)
        head.addWidget(self.delete_range_button)
        layout.addLayout(head)
        self.range_users_label = QLabel()
        self.range_users_label.setWordWrap(True)
        layout.addWidget(self.range_users_label)
        self.range_entries = QListWidget()
        self.range_entries.setFont(monospace_font())
        self.range_entries.setSelectionMode(QAbstractItemView.ExtendedSelection)
        layout.addWidget(self.range_entries, 1)
        periodic = QHBoxLayout()
        periodic.addWidget(QLabel("Every:"))
        self.range_days = QComboBox()
        self.range_days.addItems(DAY_CHOICES)
        periodic.addWidget(self.range_days)
        periodic.addWidget(QLabel("from"))
        self.range_from = QTimeEdit()
        self.range_from.setDisplayFormat("HH:mm")
        self.range_from.setTime(self.range_from.time().fromString("08:00", "HH:mm"))
        periodic.addWidget(self.range_from)
        periodic.addWidget(QLabel("to"))
        self.range_to = QTimeEdit()
        self.range_to.setDisplayFormat("HH:mm")
        self.range_to.setTime(self.range_to.time().fromString("17:00", "HH:mm"))
        periodic.addWidget(self.range_to)
        add_periodic = QPushButton("Add")
        add_periodic.clicked.connect(self.add_periodic)
        periodic.addWidget(add_periodic)
        periodic.addStretch(1)
        layout.addLayout(periodic)
        absolute = QHBoxLayout()
        self.range_start_check = QCheckBox("Starting")
        self.range_start = QDateTimeEdit(QDateTime.currentDateTime())
        self.range_start.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.range_end_check = QCheckBox("Ending")
        self.range_end_check.setChecked(True)
        self.range_end = QDateTimeEdit(QDateTime.currentDateTime().addDays(30))
        self.range_end.setDisplayFormat("yyyy-MM-dd HH:mm")
        add_absolute = QPushButton("Add")
        add_absolute.clicked.connect(self.add_absolute)
        for widget in (self.range_start_check, self.range_start, self.range_end_check, self.range_end, add_absolute):
            absolute.addWidget(widget)
        absolute.addStretch(1)
        layout.addLayout(absolute)
        row = QHBoxLayout()
        remove = QPushButton("Remove Selected")
        remove.clicked.connect(self.remove_range_entries)
        row.addWidget(remove)
        row.addStretch(1)
        layout.addLayout(row)
        note = QLabel("Time ranges follow the device's clock, not this PC's: check it's right (show clock), with "
                      "NTP.")
        note.setWordWrap(True)
        set_hint(note, note.text(), "info")
        layout.addWidget(note)
        return page

    def make_changes_box(self):
        box = QGroupBox("Changes")
        self.changes_box = box
        layout = QVBoxLayout(box)
        top = QHBoxLayout()
        self.lines_radio = QRadioButton("Lines to send")
        self.undo_radio = QRadioButton("Lines that undo them")
        self.lines_radio.setChecked(True)
        self.lines_radio.toggled.connect(self.show_preview)
        top.addWidget(self.lines_radio)
        top.addWidget(self.undo_radio)
        top.addStretch(1)
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_preview)
        top.addWidget(self.copy_button)
        self.export_button = QPushButton("Export...")
        self.export_button.clicked.connect(self.export_preview)
        top.addWidget(self.export_button)
        self.discard_button = QPushButton("Discard Changes")
        self.discard_button.clicked.connect(self.discard_changes)
        top.addWidget(self.discard_button)
        layout.addLayout(top)
        middle = QHBoxLayout()
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        middle.addWidget(self.preview, 3)
        side = QVBoxLayout()
        self.lockout_label = QLabel()
        self.lockout_label.setWordWrap(True)
        self.lockout_label.setAlignment(Qt.AlignTop)
        side.addWidget(self.lockout_label, 1)
        self.console_check = QCheckBox("I can reach it another way (console): send anyway")
        self.console_check.toggled.connect(self.update_buttons)
        side.addWidget(self.console_check)
        middle.addLayout(side, 2)
        layout.addLayout(middle, 1)
        self.waiting_box = QWidget()
        waiting = QHBoxLayout(self.waiting_box)
        waiting.setContentsMargins(0, 0, 0, 0)
        self.waiting_label = QLabel()
        self.waiting_label.setWordWrap(True)
        waiting.addWidget(self.waiting_label, 1)
        self.confirm_button = accent_button("Confirm")
        self.confirm_button.setToolTip("configure confirm: keep the changes (over SSH from a new login, or typed "
                                       "into the session they went to)")
        self.confirm_button.clicked.connect(self.confirm_waiting)
        waiting.addWidget(self.confirm_button)
        self.put_back_button = QPushButton("Put Back Now")
        self.put_back_button.setToolTip("configure revert now: the device puts its old configuration back now")
        self.put_back_button.clicked.connect(self.put_back_now)
        waiting.addWidget(self.put_back_button)
        self.waiting_box.setVisible(False)
        layout.addWidget(self.waiting_box)
        layout.addWidget(self.make_soft_box())
        row = QHBoxLayout()
        self.revert_check = QCheckBox("Put it back after")
        self.revert_check.setChecked(True)
        self.revert_check.setToolTip("configure terminal revert timer: the device puts its configuration back by "
                                     "itself unless NOMAD (or you, in a session) says configure confirm. Needs an "
                                     "archive path, which NOMAD sets if there isn't one.")
        self.revert_check.toggled.connect(self.refresh_changes)
        row.addWidget(self.revert_check)
        self.minutes_input = QSpinBox()
        self.minutes_input.setRange(1, 120)
        self.minutes_input.setValue(DEFAULT_MINUTES)
        self.minutes_input.setSuffix(" min")
        self.minutes_input.valueChanged.connect(self.refresh_changes)
        row.addWidget(self.minutes_input)
        row.addWidget(QLabel("unless"))
        self.confirm_combo = QComboBox()
        self.confirm_combo.addItem("NOMAD can log in again (it confirms)", CONFIRM_AUTO)
        self.confirm_combo.addItem("I click Confirm", CONFIRM_MANUAL)
        self.confirm_combo.setToolTip("Who says configure confirm after Send over SSH: NOMAD, as soon as a new login "
                                      "works; or you, once you've checked what you need to (a new login is still "
                                      "tried first, and a failed one puts it back)")
        row.addWidget(self.confirm_combo)
        row.addStretch(1)
        self.send_button = accent_button("Send over SSH")
        self.send_button.setToolTip("Send the changes, log in again to check this PC still can, then confirm them")
        self.send_button.clicked.connect(self.send_current)
        row.addWidget(self.send_button)
        self.session_button = QToolButton()
        self.session_button.setText("Send to Session")
        self.session_button.setPopupMode(QToolButton.InstantPopup)
        self.session_menu = QMenu(self.session_button)
        self.session_menu.aboutToShow.connect(self.fill_session_menu)
        self.session_button.setMenu(self.session_menu)
        row.addWidget(self.session_button)
        self.send_all_button = QPushButton("Send All Devices")
        self.send_all_button.setToolTip("Send every device with changes waiting, one after the other, stopping at "
                                        "the first that doesn't take them")
        self.send_all_button.clicked.connect(self.send_all)
        row.addWidget(self.send_all_button)
        self.save_button = QPushButton("Save to Startup Config")
        self.save_button.setToolTip("write memory: only offered once the changes are confirmed")
        self.save_button.clicked.connect(self.save_startup)
        row.addWidget(self.save_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        row.addWidget(self.stop_button)
        layout.addLayout(row)
        return box

    def make_soft_box(self):
        self.soft_box = QWidget()
        soft = QHBoxLayout(self.soft_box)
        soft.setContentsMargins(0, 0, 0, 0)
        self.soft_label = QLabel()
        self.soft_label.setWordWrap(True)
        soft.addWidget(self.soft_label, 3)
        self.soft_list = QListWidget()
        self.soft_list.setFixedHeight(64)
        self.soft_list.itemChanged.connect(self.update_buttons)
        soft.addWidget(self.soft_list, 3)
        self.soft_button = accent_button("Soft Clear Ticked")
        self.soft_button.setToolTip("clear ip bgp NEIGHBOR soft in/out: the neighbor's routes go through the new "
                                    "policy again (the session stays up)")
        self.soft_button.clicked.connect(self.soft_clear)
        soft.addWidget(self.soft_button)
        self.soft_copy_button = QPushButton("Copy Commands")
        self.soft_copy_button.clicked.connect(self.copy_soft)
        soft.addWidget(self.soft_copy_button)
        self.soft_dismiss_button = QPushButton("Not Now")
        self.soft_dismiss_button.clicked.connect(self.dismiss_soft)
        soft.addWidget(self.soft_dismiss_button)
        self.soft_box.setVisible(False)
        return self.soft_box

    def make_library_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        label = QLabel("ACLs (with the object groups and time ranges they name), prefix lists and route maps (with "
                       "the prefix lists and ACLs they match) kept on this PC: put one on a device (it's merged entry "
                       "by entry into the one of the same name there, or made), on several, or build one on the "
                       "Scratch Pad and save it here.")
        label.setWordWrap(True)
        layout.addWidget(label)
        split = QSplitter(Qt.Horizontal)
        self.library_table = read_only_table(LIBRARY_COLUMNS)
        self.library_table.itemSelectionChanged.connect(self.on_library_selected)
        self.library_table.itemDoubleClicked.connect(self.use_library_here)
        split.addWidget(self.library_table)
        self.library_view = QPlainTextEdit()
        self.library_view.setReadOnly(True)
        self.library_view.setFont(monospace_font())
        split.addWidget(self.library_view)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        row = QHBoxLayout()
        self.use_here_button = accent_button("Use on This Device")
        self.use_here_button.setToolTip("Into the device chosen on the Edit tab (nothing is sent until Send)")
        self.use_here_button.clicked.connect(self.use_library_here)
        row.addWidget(self.use_here_button)
        self.put_on_button = QPushButton("Put on Devices...")
        self.put_on_button.clicked.connect(self.put_on_devices)
        row.addWidget(self.put_on_button)
        self.import_button = QPushButton("Import Text...")
        self.import_button.clicked.connect(self.import_text)
        row.addWidget(self.import_button)
        self.notes_button = QPushButton("Notes...")
        self.notes_button.clicked.connect(self.edit_library_notes)
        row.addWidget(self.notes_button)
        self.library_export_button = QPushButton("Export...")
        self.library_export_button.clicked.connect(self.export_library)
        row.addWidget(self.library_export_button)
        self.library_delete_button = QPushButton("Delete")
        self.library_delete_button.clicked.connect(self.delete_library)
        row.addWidget(self.library_delete_button)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    def make_history_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        split = QSplitter(Qt.Horizontal)
        self.history_table = read_only_table(HISTORY_COLUMNS)
        self.history_table.itemSelectionChanged.connect(self.on_history_selected)
        split.addWidget(self.history_table)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.history_lines_radio = QRadioButton("Lines sent")
        self.history_undo_radio = QRadioButton("Lines that undo them")
        self.history_lines_radio.setChecked(True)
        self.history_lines_radio.toggled.connect(self.on_history_selected)
        radios = QHBoxLayout()
        radios.addWidget(self.history_lines_radio)
        radios.addWidget(self.history_undo_radio)
        radios.addStretch(1)
        right_layout.addLayout(radios)
        self.history_view = QPlainTextEdit()
        self.history_view.setReadOnly(True)
        self.history_view.setFont(monospace_font())
        right_layout.addWidget(self.history_view, 1)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)
        row = QHBoxLayout()
        self.undo_ssh_button = QPushButton("Undo over SSH")
        self.undo_ssh_button.setToolTip("Send what undoes the change (with the revert timer, when it's on)")
        self.undo_ssh_button.clicked.connect(self.undo_over_ssh)
        row.addWidget(self.undo_ssh_button)
        self.undo_session_button = QToolButton()
        self.undo_session_button.setText("Undo in Session")
        self.undo_session_button.setPopupMode(QToolButton.InstantPopup)
        self.undo_session_menu = QMenu(self.undo_session_button)
        self.undo_session_menu.aboutToShow.connect(self.fill_undo_session_menu)
        self.undo_session_button.setMenu(self.undo_session_menu)
        row.addWidget(self.undo_session_button)
        self.copy_undo_button = QPushButton("Copy Undo")
        self.copy_undo_button.clicked.connect(self.copy_undo)
        row.addWidget(self.copy_undo_button)
        self.forget_button = QPushButton("Forget")
        self.forget_button.clicked.connect(self.forget_history)
        row.addWidget(self.forget_button)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.find_input.setFocus()

    def save_settings(self, settings):
        settings.setValue("acls/revert", self.revert_check.isChecked())
        settings.setValue("acls/minutes", self.minutes_input.value())
        settings.setValue("acls/confirm", self.confirm_combo.currentData())
        self.login_row.save_settings(settings, "acls")

    def restore_settings(self, settings):
        self.revert_check.setChecked(settings.value("acls/revert", True, bool))
        self.minutes_input.setValue(settings.value("acls/minutes", DEFAULT_MINUTES, int))
        index = self.confirm_combo.findData(settings.value("acls/confirm", CONFIRM_AUTO))
        self.confirm_combo.setCurrentIndex(max(0, index))
        self.login_row.restore_settings(settings, "acls")

    def shutdown(self):
        self.tick.stop()
        self.session_sender.stop_waiting()
        for thread in (self.reader, self.sender_thread):
            if thread is not None:
                thread.stop()
                release_thread(thread)
        self.reader = self.sender_thread = None

    # ----------------------------------------------------------------- Devices

    def map_page(self):
        return getattr(self.window, "netmap_tab", None)

    def network_map(self):
        page = self.map_page()
        return getattr(page, "network_map", None) if page is not None else None

    def add_scratch(self):
        self.targets[SCRATCH] = Target(SCRATCH, "Scratch Pad (not a device)", source=SCRATCH)
        self.read[SCRATCH] = DeviceAcls(read=True, hostname="Scratch Pad")
        self.working[SCRATCH] = DeviceAcls(read=True, hostname="Scratch Pad")

    def on_map_shown(self):
        keep = {key: target for key, target in self.targets.items() if target.source in ("address", SCRATCH) or
                key in self.read}
        targets = dict(keep)
        network_map = self.network_map()
        devices = sorted((device for device in network_map.devices.values() if device.kind in (SWITCH, ROUTER)),
                         key=lambda device: device.label.lower()) if network_map is not None else []
        for device in devices:
            key = f"map:{device.key}"
            label = device.label + (f" ({device.mgmt_ip})" if device.mgmt_ip and device.mgmt_ip != device.label
                                    else "")
            names = [name for name in (device.name, *device.addresses) if name]
            targets[key] = Target(key, label, device.mgmt_ip, names, "map", device.key)
        addresses = {target.address for target in targets.values() if target.address}
        for session in (self.sessions.sessions if self.sessions is not None else []):
            if session.protocol != SSH or not session.host or session.host in addresses:
                continue
            key = f"session:{session.name}@{session.host}"
            targets[key] = Target(key, f"{session.name} ({session.host}, saved session)", session.host,
                                  [session.name], "session")
        self.targets = targets
        self.fill_devices()

    def fill_devices(self):
        current = self.current_key
        self.device_list.blockSignals(True)
        self.device_list.clear()
        order = sorted(self.targets.values(), key=lambda target: (target.source != SCRATCH, target.key not in self.read,
                                                                   target.label.lower()))
        for target in order:
            text = target.label
            device = self.read.get(target.key)
            if target.key in self.read and target.source != SCRATCH:
                text = ("✓ " if device.read else "✗ ") + text
            count = len(self.changes_for(target.key)) if target.key in self.working else 0
            if count:
                text += f"   [{count} change{'s' if count != 1 else ''} waiting]"
            if target.key in self.waiting:
                text += f"   [to confirm by {self.waiting[target.key].at}]"
            if self.soft_offers.get(target.key):
                text += "   [BGP soft clear offered]"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, target.key)
            note = self.notes.get(target.key, "")
            item.setToolTip(note or target.address)
            if count:
                item.setForeground(QColor(COLORS["accent"]))
            elif device is not None and not device.read:
                item.setForeground(QColor(COLORS["error"]))
            self.device_list.addItem(item)
            if target.key == current:
                self.device_list.setCurrentItem(item)
        self.device_list.blockSignals(False)
        self.filter_devices(self.find_input.text())

    def filter_devices(self, text):
        words = text.lower().split()
        for row in range(self.device_list.count()):
            item = self.device_list.item(row)
            item.setHidden(not all(word in item.text().lower() for word in words))

    def add_address(self):
        address, ok = QInputDialog.getText(self, "Add a Device", "Address (or name) to log in to over SSH:")
        address = address.strip()
        if not ok or not address:
            return
        key = f"address:{address}"
        self.targets.setdefault(key, Target(key, address, address, [], "address"))
        self.current_key = key
        self.fill_devices()
        self.on_device_chosen()

    def chosen_keys(self):
        return [item.data(Qt.UserRole) for item in self.device_list.selectedItems()] or \
            ([self.current_key] if self.current_key else [])

    def on_device_chosen(self, *_):
        item = self.device_list.currentItem()
        key = item.data(Qt.UserRole) if item is not None else ""
        if key != self.current_key:
            self.current_item = None
        self.current_key = key
        self.fill_items()
        self.refresh_changes()

    def target(self, key):
        return self.targets.get(key)

    def device_hints(self, key):
        """For Send to Session: the device's address and names."""
        target = self.target(key)
        if target is None or not target.address:
            return {}
        hints = {"name": target.names[0] if target.names else target.label, "aliases": list(target.names)}
        network_map, page = self.network_map(), self.map_page()
        device = network_map.devices.get(target.map_key) if network_map is not None and target.map_key else None
        if device is not None and page is not None and hasattr(page, "session_hints"):
            hints = page.session_hints(network_map, device)
        return dict(hints, address=target.address)

    # ----------------------------------------------------------------- Reading

    def logins(self):
        return self.login_row.logins(self.status_label)

    def pusher_maker(self, logins):
        return self.login_row.pusher_maker(logins, self.shell_factory)

    def busy(self):
        return self.reader is not None or self.sender_thread is not None

    def read_chosen(self, *_):
        keys = [key for key in self.chosen_keys() if key != SCRATCH]
        if not keys:
            set_hint(self.status_label, "Pick a device to read (the Scratch Pad isn't one).", "warning")
            return
        self.start_read(keys)

    def start_read(self, keys, then=None, logins=None):
        if self.busy():
            return False
        waiting = [key for key in keys if self.changes_for(key)]
        if waiting and then is None:
            names = ", ".join(self.targets[key].label for key in waiting[:4])
            answer = QMessageBox.question(self, "Read Again", f"Reading again drops the changes not sent yet on "
                                                              f"{names}. Read anyway?")
            if answer != QMessageBox.Yes:
                return False
        logins = logins or self.logins()
        if logins is None:
            return False
        self.saved_logins = logins
        targets = []
        for key in keys:
            target = self.targets.get(key)
            if target is None:
                continue
            pc_ip = local_address_toward(target.address) if target.address else ""
            targets.append((key, target.address, target.names, pc_ip))
        if not targets:
            return False
        self.after_read = then
        self.reader = ReadThread(targets, self.pusher_maker(logins), self)
        self.reader.device_read.connect(self.on_device_read)
        self.reader.finished.connect(self.on_read_finished)
        self.reader.start()
        set_hint(self.status_label, f"Reading the ACLs of {len(targets)} device(s) over SSH...", "info")
        self.set_busy("Reading ACLs")
        self.update_buttons()
        return True

    def on_device_read(self, key, device):
        self.read[key] = device
        self.working[key] = device.copy()
        if device.read:
            counts = [(len(device.acls), "ACL"), (len(device.prefix_lists), "prefix list"),
                      (len(device.route_maps), "route map")]
            self.notes[key] = f"Read at {device.when[11:16]}: " + ", ".join(
                f"{count} {word}{'s' if count != 1 else ''}" for count, word in counts) + "."
        else:
            self.notes[key] = f"Couldn't read it: {device.problem}"

    def on_read_finished(self):
        reader, self.reader = self.reader, None
        if reader is not None:
            reader.deleteLater()
        self.clear_busy()
        then, self.after_read = self.after_read, None
        problems = [f"{self.targets[key].label}: {self.read[key].problem}" for key in self.read
                    if key in self.targets and not self.read[key].read]
        self.fill_devices()
        self.fill_items()
        self.refresh_changes()
        if problems:
            set_hint(self.status_label, "Couldn't read " + "; ".join(problems[:3]), "error")
        else:
            set_hint(self.status_label, "Read.", "success")
        if then is not None:
            then()
        elif self.selecting:
            self.select_wanted()

    # ----------------------------------------------------------------- The device's items

    def device(self, key=None):
        """The current (or key's) device as edited, or None until it's read."""
        key = key or self.current_key
        device = self.working.get(key)
        return device if device is not None and device.read else None

    def fill_items(self):
        device = self.device()
        target = self.target(self.current_key)
        if target is None:
            self.device_label.setText("Pick a device on the left.")
        elif self.current_key not in self.read:
            set_hint(self.device_label, f"{target.label}: not read yet. Read logs in over SSH.", "info")
        elif device is None:
            set_hint(self.device_label, f"{target.label}: {self.notes.get(self.current_key, '')}", "error")
        else:
            text = f"{device.hostname or target.label}: " + self.notes.get(self.current_key, "") \
                if target.source != SCRATCH else "Build ACLs here, then save them to the Library, copy or export them."
            set_hint(self.device_label, text, "info")
        self.items_tree.blockSignals(True)
        self.items_tree.clear()
        if device is not None:
            before = self.read.get(self.current_key)
            sections = [("IPv4 ACLs", [item for item in device.acls.values() if item.family == V4]),
                        ("IPv6 ACLs", [item for item in device.acls.values() if item.family == V6])]
            for title, acls in sections:
                section = QTreeWidgetItem([title, str(len(acls))])
                self.items_tree.addTopLevelItem(section)
                for item in sorted(acls, key=lambda value: value.name.lower()):
                    uses = device.uses_of(item)
                    about = f"{len(item.rules)} rules" + (f", on {', '.join(use.label() for use in uses[:3])}"
                                                           if uses else "")
                    child = QTreeWidgetItem([item.name, about])
                    child.setData(0, Qt.UserRole, (KIND_ACL, item.key))
                    child.setToolTip(1, about)
                    self.mark_changed(child, before.acls.get(item.key) if before else None, item)
                    section.addChild(child)
                    if self.current_item == (KIND_ACL, item.key):
                        self.items_tree.setCurrentItem(child)
            self.fill_policy_items(device, before)
            for title, kind, items in (("Object Groups", KIND_GROUP, device.groups),
                                       ("Time Ranges", KIND_RANGE, device.ranges)):
                section = QTreeWidgetItem([title, str(len(items))])
                self.items_tree.addTopLevelItem(section)
                for name, item in sorted(items.items(), key=lambda pair: pair[0].lower()):
                    about = (f"{item.keyword}, " if kind == KIND_GROUP else "") + f"{len(item.entries)} entries"
                    child = QTreeWidgetItem([name, about])
                    child.setData(0, Qt.UserRole, (kind, name))
                    old = (before.groups if kind == KIND_GROUP else before.ranges).get(name) if before else None
                    if old is None or old.entries != item.entries or \
                            getattr(old, "description", "") != getattr(item, "description", ""):
                        self.paint_changed(child)
                    section.addChild(child)
                    if self.current_item == (kind, name):
                        self.items_tree.setCurrentItem(child)
            self.items_tree.expandAll()
            self.items_tree.resizeColumnToContents(0)
        self.items_tree.blockSignals(False)
        self.show_item()

    def fill_policy_items(self, device, before):
        """The tree's prefix lists (IPv4, IPv6) and route maps."""
        sections = [("IPv4 Prefix Lists", V4), ("IPv6 Prefix Lists", V6)]
        for title, family in sections:
            items = [item for item in device.prefix_lists.values() if item.family == family]
            if family == V6 and not items:
                continue
            section = QTreeWidgetItem([title, str(len(items))])
            self.items_tree.addTopLevelItem(section)
            for item in sorted(items, key=lambda value: value.name.lower()):
                uses = routepolicy.uses_of(device, routepolicy.PREFIX_LIST, item.name, family)
                maps = {rmap.name for rmap, _ in routepolicy.maps_naming(device, routepolicy.PREFIX_LIST, item.name,
                                                                         family)}
                places = [use.label() for use in uses[:2]] + [f"route map {name}" for name in sorted(maps)[:2]]
                about = f"{len(item.entries)} entries" + (f", {', '.join(places)}" if places else "")
                child = QTreeWidgetItem([item.name, about])
                child.setData(0, Qt.UserRole, (KIND_PLIST, item.key))
                child.setToolTip(1, about)
                old = before.prefix_lists.get(item.key) if before else None
                if old is None or routepolicy.prefix_differs(old, item):
                    self.paint_changed(child)
                section.addChild(child)
                if self.current_item == (KIND_PLIST, item.key):
                    self.items_tree.setCurrentItem(child)
        section = QTreeWidgetItem(["Route Maps", str(len(device.route_maps))])
        self.items_tree.addTopLevelItem(section)
        for name, item in sorted(device.route_maps.items(), key=lambda pair: pair[0].lower()):
            uses = routepolicy.uses_of(device, routepolicy.ROUTE_MAP, name)
            about = f"{len(item.entries)} entries" + (f", on {', '.join(use.label() for use in uses[:2])}"
                                                      if uses else "")
            child = QTreeWidgetItem([name, about])
            child.setData(0, Qt.UserRole, (KIND_RMAP, name))
            child.setToolTip(1, about)
            old = before.route_maps.get(name) if before else None
            if old is None or routepolicy.map_differs(old, item):
                self.paint_changed(child)
            section.addChild(child)
            if self.current_item == (KIND_RMAP, name):
                self.items_tree.setCurrentItem(child)

    def mark_changed(self, tree_item, before, after):
        if before is None or acl.acl_differs(before, after):
            self.paint_changed(tree_item)

    @staticmethod
    def paint_changed(tree_item):
        tree_item.setForeground(0, QColor(COLORS["accent"]))
        font = tree_item.font(0)
        font.setBold(True)
        tree_item.setFont(0, font)

    def on_item_chosen(self, item, *_):
        data = item.data(0, Qt.UserRole) if item is not None else None
        if data is not None:
            self.current_item = data
        self.show_item()

    def current_acl(self):
        device = self.device()
        if device is None or self.current_item is None or self.current_item[0] != KIND_ACL:
            return None
        return device.acls.get(self.current_item[1])

    def current_group(self):
        device = self.device()
        if device is None or self.current_item is None or self.current_item[0] != KIND_GROUP:
            return None
        return device.groups.get(self.current_item[1])

    def current_range(self):
        device = self.device()
        if device is None or self.current_item is None or self.current_item[0] != KIND_RANGE:
            return None
        return device.ranges.get(self.current_item[1])

    def current_plist(self):
        device = self.device()
        if device is None or self.current_item is None or self.current_item[0] != KIND_PLIST:
            return None
        return device.prefix_lists.get(tuple(self.current_item[1]))

    def current_rmap(self):
        device = self.device()
        if device is None or self.current_item is None or self.current_item[0] != KIND_RMAP:
            return None
        return device.route_maps.get(self.current_item[1])

    def show_item(self):
        if self.current_plist() is not None:
            self.editor.setCurrentWidget(self.plist_editor)
            self.plist_editor.fill()
        elif self.current_rmap() is not None:
            self.editor.setCurrentWidget(self.rmap_editor)
            self.rmap_editor.fill()
        elif self.current_acl() is not None:
            self.editor.setCurrentIndex(1)
            self.fill_acl()
        elif self.current_group() is not None:
            self.editor.setCurrentIndex(2)
            self.fill_group()
        elif self.current_range() is not None:
            self.editor.setCurrentIndex(3)
            self.fill_range()
        else:
            self.editor.setCurrentIndex(0)
        self.update_buttons()

    def edited(self, focus=None):
        """Something was changed in the working copy: show it again."""
        self.fill_devices()
        self.fill_items()
        self.refresh_changes()
        if focus is not None:
            self.select_rows(focus)

    # ----------------------------------------------------------------- An ACL's rules

    def fill_acl(self):
        item = self.current_acl()
        device = self.device()
        before = self.read.get(self.current_key)
        before_acl = before.acls.get(item.key) if before is not None else None
        kind = "IPv6" if item.family == V6 else f"IPv4 {item.kind}" + (", numbered" if item.numbered else "")
        self.acl_title.setText(f"{item.name}  ({kind})" + ("  - new, not on the device yet" if before_acl is None
                                                          and self.current_key != SCRATCH else ""))
        uses = device.uses_of(item)
        if uses:
            set_hint(self.applied_label, "Applied: " + "; ".join(use.label() for use in uses), "info")
        else:
            set_hint(self.applied_label, "Not applied anywhere: it does nothing until it's applied (Apply To... puts "
                                         "it on an interface or the VTY lines) or named by something.", "warning")
        checks = aclcheck.findings(item, device.groups, device.ranges)
        flagged = {}
        for finding in checks:
            if finding.index >= 0 and finding.index not in flagged:
                flagged[finding.index] = finding
        selected = self.selected_rows()
        numbers = self.planned_numbers(item)
        table = self.rules_table
        self.filling_rules = True
        table.setRowCount(len(item.rules))
        for row, rule in enumerate(item.rules):
            state = acl.edited_rule_state(before_acl, rule, item.family, item.kind) \
                if self.current_key != SCRATCH else ""
            planned = numbers.get(row)
            if planned is None:
                number = str(rule.seq) if rule.seq else ("new" if state == "new" else "")
            elif rule.seq and planned != rule.seq and self.current_key != SCRATCH:
                number = f"{planned} (was {rule.seq})"
            else:
                number = str(planned)
            cells = [number, rule.action,
                     rule.service_group and f"object-group {rule.service_group}" or rule.protocol,
                     rule.src.short(), rule.src_ports.text(rule.protocol, names=True), rule.dst.short(),
                     rule.dst_ports.text(rule.protocol, names=True), rule.options_text(),
                     "" if rule.hits is None else str(rule.hits), rule.remark.replace("\n", " | ")]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                if column == 0:
                    cell.setFlags(cell.flags() | Qt.ItemIsEditable)
                    cell.setToolTip(self.number_tip(rule, planned, state))
                else:
                    cell.setFlags(cell.flags() & ~Qt.ItemIsEditable)
                if state:
                    cell.setForeground(QColor(COLORS["accent"]))
                    font = cell.font()
                    font.setBold(True)
                    cell.setFont(font)
                if column == 1:
                    cell.setForeground(QColor(COLORS["success"] if rule.action == acl.PERMIT else COLORS["error"]))
                table.setItem(row, column, cell)
            finding = flagged.get(row)
            if finding is not None:
                for column in (3, 5):
                    table.item(row, column).setToolTip(finding.text)
                table.item(row, 0).setToolTip(finding.text + "\n" + table.item(row, 0).toolTip())
                table.item(row, 0).setBackground(severity_color(finding.severity).darker(250))
        self.filling_rules = False
        for column in range(len(RULE_COLUMNS)):
            table.setColumnHidden(column, item.kind == STANDARD and column in (2, 4, 5, 6))
        table.resizeColumnsToContents()
        self.select_rows(selected)
        self.findings_list.clear()
        for finding in checks:
            entry = QListWidgetItem(finding.text)
            entry.setForeground(severity_color(finding.severity))
            entry.setData(Qt.UserRole, finding.index)
            self.findings_list.addItem(entry)
        if not checks:
            entry = QListWidgetItem("Nothing found: no rule hides another, no mask where a wildcard goes.")
            entry.setForeground(QColor(COLORS["muted"]))
            self.findings_list.addItem(entry)

    def selected_rows(self):
        return sorted({index.row() for index in self.rules_table.selectedIndexes()})

    def planned_numbers(self, item=None):
        """{row: the number each rule of the ACL shown has once the changes are sent}."""
        item = item or self.current_acl()
        if item is None:
            return {}
        before = self.read.get(self.current_key) if self.current_key != SCRATCH else None
        before_acl = before.acls.get(item.key) if before is not None else None
        try:
            return acl.acl_change(before_acl, item).numbers
        except Exception:  # A rule the planner can't take shouldn't stop the table showing
            log.exception("Planning %s's numbers failed", item.name)
            return {}

    @staticmethod
    def number_tip(rule, planned, state):
        if rule.want_seq and planned is not None and planned != rule.want_seq:
            tip = f"Number {rule.want_seq} was typed in, but it can't have it: it gets {planned}."
        elif rule.want_seq:
            tip = "A number typed in."
        elif state == "new":
            tip = "New: the number it gets when sent."
        elif rule.seq and planned is not None and planned != rule.seq:
            tip = f"Renumbered when sent (it's {rule.seq} on the device now)."
        else:
            tip = "Its number on the device." if rule.seq else ""
        return (tip + "\n" if tip else "") + "Double-click (or F2) to type a number: the rule goes to its place " \
                                                "by it. Nothing typed: an automatic one."

    def on_rule_cell_changed(self, cell):
        if self.filling_rules or cell.column() != 0:
            return
        self.pending_number = (cell.row(), cell.text())
        QTimer.singleShot(0, self.take_pending_number)  # Not while the table's editor is still closing

    def take_pending_number(self):
        if self.pending_number is None:
            return
        (row, text), self.pending_number = self.pending_number, None
        text = text.strip()
        found = re.match(r"(\d+)", text)
        if text and not found:
            set_hint(self.status_label, "Type a sequence number (or nothing, for an automatic one).", "error")
            self.fill_acl()
            return
        self.set_number(row, int(found.group(1)) if found else None)

    def set_number(self, row, number):
        """Give the rule on row number (None: an automatic one), moving it to its place by that number."""
        item = self.current_acl()
        if item is None or not 0 <= row < len(item.rules):
            return
        rule = item.rules[row]
        if number is None:
            if rule.want_seq:
                rule.want_seq = 0
                self.edited([row])
            else:
                self.fill_acl()
            return
        if not 1 <= number <= acl.MAX_SEQ:
            set_hint(self.status_label, f"A sequence number is 1 to {acl.MAX_SEQ}.", "error")
            self.fill_acl()
            return
        numbers = self.planned_numbers(item)
        for other_row, other in enumerate(item.rules):
            staying = other.want_seq or (other.seq if numbers.get(other_row) == other.seq else 0)
            if other_row != row and staying == number:
                set_hint(self.status_label, f"Line {other_row + 1} has number {number} already: give that one "
                                            "another first.", "error")
                self.fill_acl()
                return
        others = [(other_row, other) for other_row, other in enumerate(item.rules) if other_row != row]
        at = next((place for place, (other_row, other) in enumerate(others)
                   if (other.want_seq or numbers.get(other_row) or other.seq) > number), len(others))
        item.rules.insert(at, item.rules.pop(row))
        rule.want_seq = number
        self.edited([at])
        got = self.planned_numbers(item).get(at)
        if got is not None and got != number:
            set_hint(self.status_label, f"It can't have {number} (see Changes): it gets {got}.", "warning")
        elif at != row:
            set_hint(self.status_label, f"Moved to line {at + 1}: a rule's number is its place in the ACL.", "info")

    def select_rows(self, rows):
        table = self.rules_table
        table.clearSelection()
        mode = table.selectionMode()
        table.setSelectionMode(QAbstractItemView.MultiSelection)
        for row in rows:
            if 0 <= row < table.rowCount():
                table.selectRow(row)
        table.setSelectionMode(mode)
        if rows and 0 <= rows[0] < table.rowCount():
            table.scrollToItem(table.item(rows[0], 0))

    def on_finding_clicked(self, item):
        index = item.data(Qt.UserRole)
        if index is not None and index >= 0:
            self.select_rows([index])

    def address_choices(self):
        """[(section, label, text)] for AddressPicker: object groups, the map's devices, IPAM subnets and addresses."""
        choices = []
        device = self.device()
        if device is not None:
            for group in device.groups.values():
                if group.kind == NETWORK:
                    choices.append(("Object group", f"{group.name} ({len(group.entries)} entries)",
                                    f"object-group {group.name}"))
        network_map = self.network_map()
        if network_map is not None:
            for item in sorted(network_map.devices.values(), key=lambda value: value.label.lower()):
                if item.mgmt_ip:
                    choices.append(("Map device", f"{item.label} {item.mgmt_ip}", item.mgmt_ip))
                for address, length, port in getattr(item, "interfaces_l3", []) or []:
                    if address and address != item.mgmt_ip:
                        choices.append(("Map device", f"{item.label} {port} {address}/{length}", address))
                        choices.append(("Map subnet", f"{item.label} {port} subnet", f"{address}/{length}"))
        integration = getattr(self.window, "integration", None)
        if integration is not None:
            try:
                for _, label, store, network in integration.networks():
                    for subnet in store.subnets(network.id):
                        name = f" {subnet.name}" if subnet.name else ""
                        choices.append((f"IPAM {network.name}", f"{subnet.cidr}{name}", subnet.cidr))
                    for address in store.addresses(network.id):
                        name = f" {address.name}" if address.name else ""
                        choices.append((f"IPAM {network.name}", f"{address.ip}{name}", address.ip))
            except Exception:  # IPAM unreachable or locked: pick from the rest
                log.exception("Reading IPAM for the address picker failed")
        return choices

    def rule_dialog(self, rule=None, number=""):
        """(the rule as filled in, the number typed: None when left as it was, "" for an automatic one), or
        (None, None) when cancelled."""
        item, device = self.current_acl(), self.device()
        dialog = RuleDialog(self, item, rule, device.groups, device.ranges, self.address_choices, number=number)
        if dialog.exec_() != QDialog.Accepted:
            return None, None
        typed = dialog.number_input.text().strip()
        return dialog.rule, (None if typed == str(number) else typed)

    def add_rule(self):
        item = self.current_acl()
        if item is None:
            return
        rule, number = self.rule_dialog()
        if rule is None:
            return
        rule.seq, rule.hits, rule.want_seq = 0, None, 0
        rows = self.selected_rows()
        if rows:
            at = rows[-1] + 1
        else:  # Above a last rule that takes everything (deny ip any any), not after it where it'd never match
            at = len(item.rules)
            if item.rules and aclcheck.covers(item.rules[-1], rule, item.family, item.kind, self.device().groups):
                at -= 1
        item.rules.insert(at, rule)
        self.edited([at])
        if number:
            self.set_number(at, int(number))

    def edit_rule(self, *args):
        if args and isinstance(args[0], QTableWidgetItem) and args[0].column() == 0:
            return  # A double-click on the number types a number in
        item = self.current_acl()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        row = rows[0]
        old = item.rules[row]
        shown = self.planned_numbers(item).get(row) or old.want_seq or old.seq or ""
        rule, number = self.rule_dialog(old, shown)
        if rule is None:
            return
        if not acl.same_rule(rule, old, item.family, item.kind):
            rule.hits = None
            item.rules[row] = rule
            self.edited([row])
        if number is not None:
            self.set_number(row, int(number) if number else None)

    def duplicate_rules(self):
        item = self.current_acl()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        copies = [item.rules[row].copy(seq=0, hits=None, want_seq=0) for row in rows]
        at = rows[-1] + 1
        item.rules[at:at] = copies
        self.edited(list(range(at, at + len(copies))))

    def delete_rules(self):
        item = self.current_acl()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        for row in reversed(rows):
            del item.rules[row]
        self.edited([min(rows[0], len(item.rules) - 1)] if item.rules else [])

    def move_rows(self, rows, target):
        item = self.current_acl()
        if item is None or not rows:
            return
        moving = [item.rules[row] for row in rows]
        for rule in moving:  # Put where they're dropped: numbers typed in before would pull them back
            rule.want_seq = 0
        before = sum(1 for row in rows if row < target)
        rest = [rule for row, rule in enumerate(item.rules) if row not in rows]
        at = max(0, min(len(rest), target - before))
        item.rules = rest[:at] + moving + rest[at:]
        self.edited(list(range(at, at + len(moving))))

    def move_up(self):
        rows = self.selected_rows()
        if rows and rows[0] > 0:
            self.move_rows(rows, rows[0] - 1)

    def move_down(self):
        rows = self.selected_rows()
        item = self.current_acl()
        if item is not None and rows and rows[-1] < len(item.rules) - 1:
            self.move_rows(rows, rows[-1] + 2)

    def show_rule_menu(self, position):
        if self.current_acl() is None:
            return
        menu = QMenu(self)
        actions = {menu.addAction("Add Rule..."): self.add_rule}
        if self.selected_rows():
            actions[menu.addAction("Edit...")] = self.edit_rule
            actions[menu.addAction("Duplicate")] = self.duplicate_rules
            actions[menu.addAction("Delete")] = self.delete_rules
            menu.addSeparator()
            actions[menu.addAction("Move Up")] = self.move_up
            actions[menu.addAction("Move Down")] = self.move_down
            menu.addSeparator()
            actions[menu.addAction("Test a Packet Like This")] = self.test_like_rule
        chosen = menu.exec_(self.rules_table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    # ----------------------------------------------------------------- The packet tester

    def on_test_now(self, now):
        self.test_when.setEnabled(not now)

    def test_like_rule(self):
        item = self.current_acl()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        rule = item.rules[rows[0]]

        def sample(address):
            if address.kind in (acl.HOST, acl.WILDCARD, acl.PREFIX):
                return acl.stored_address(address) if address.kind == acl.WILDCARD else address.address
            return ""
        self.test_src.setText(sample(rule.src))
        self.test_dst.setText(sample(rule.dst))
        if rule.protocol and not rule.service_group:
            self.test_protocol.setCurrentText(rule.protocol if rule.protocol not in ("ip", "ipv6") else "tcp")
        if rule.dst_ports.values:
            self.test_dst_port.setText(str(rule.dst_ports.values[0]))
        elif rule.icmp_name:
            self.test_dst_port.setText(rule.icmp_name)

    def run_test(self):
        item, device = self.current_acl(), self.device()
        if item is None:
            return
        protocol = self.test_protocol.currentText().strip().lower()
        icmp = self.test_dst_port.text() if protocol == "icmp" else ""
        when = None if self.test_now.isChecked() else self.test_when.dateTime().toPyDateTime()
        try:
            packet = aclcheck.packet_from_text(self.test_src.text(), self.test_dst.text(), protocol,
                                               self.test_src_port.text(), "" if icmp else self.test_dst_port.text(),
                                               icmp, self.test_flags.text(), when)
        except ValueError as error:
            set_hint(self.test_result, str(error), "error")
            return
        if packet.family != item.family:
            set_hint(self.test_result, f"{item.name} is an {acl.FAMILY_NAMES[item.family]} ACL.", "error")
            return
        verdict = aclcheck.evaluate(item, packet, device.groups, device.ranges)
        text = verdict.text
        before = self.read.get(self.current_key)
        old = before.acls.get(item.key) if before is not None and self.current_key != SCRATCH else None
        if old is not None:
            was = aclcheck.evaluate(old, packet, before.groups, before.ranges)
            if was.permitted != verdict.permitted:
                text += f"  (On the device now: {'permitted' if was.permitted else 'denied'}.)"
        if verdict.notes:
            text += "  " + " ".join(dict.fromkeys(verdict.notes))
        set_hint(self.test_result, text, "success" if verdict.permitted else "error")
        if verdict.rule is not None:
            self.select_rows([item.rules.index(verdict.rule)])

    # ----------------------------------------------------------------- Making, applying and deleting ACLs

    def new_acl(self):
        device = self.device()
        if device is None:
            set_hint(self.status_label, "Read a device first (or use the Scratch Pad).", "warning")
            return
        starts = [(f"A copy of {item.title}", item) for item in device.acls.values()]
        for entry in self.store.library:
            library_acl = entry.acl()
            if library_acl is not None:
                starts.append((f"Library: {entry.name}", library_acl))
        dialog = NewAclDialog(self, device.acls, starts)
        if dialog.exec_() != QDialog.Accepted:
            return
        made = dialog.made()
        device.acls[made.key] = made
        self.current_item = (KIND_ACL, made.key)
        self.edited()

    def apply_acl(self):
        item, device = self.current_acl(), self.device()
        if item is None:
            return
        if self.current_key == SCRATCH:
            set_hint(self.status_label, "The Scratch Pad has no interfaces: save the ACL to the Library and use it on "
                                        "a device.", "warning")
            return
        dialog = ApplyDialog(self, device, item)
        if dialog.exec_() != QDialog.Accepted or not dialog.target:
            return
        acl.set_applied(device, item.family, dialog.where, dialog.target, item.name, dialog.direction)
        self.edited()

    def fill_take_off_menu(self):
        menu = self.take_off_menu
        menu.clear()
        item, device = self.current_acl(), self.device()
        uses = [use for use in device.uses_of(item) if use.where in (INTERFACE, LINE)] if item is not None else []
        for use in uses:
            menu.addAction(use.label(), lambda use=use: self.take_off(use))
        if not uses:
            menu.addAction("It isn't on any interface or lines").setEnabled(False)

    def take_off(self, use):
        device = self.device()
        acl.take_off(device, use.family, use.where, use.target, use.acl, use.direction)
        self.edited()

    def delete_acl(self):
        item, device = self.current_acl(), self.device()
        if item is None:
            return
        uses = device.uses_of(item)
        placed = [use for use in uses if use.where in (INTERFACE, LINE)]
        others = [use for use in uses if use.where == OTHER]
        text = f"Delete {item.title}?"
        if placed:
            text += "\n\nIt's taken off " + ", ".join(use.label() for use in placed) + " first."
        if others:
            text += ("\n\nThese still name it, and IOS treats a missing ACL as permit-everything (or deny, for some "
                     "features): " + "; ".join(use.text for use in others))
        if QMessageBox.question(self, "Delete ACL", text) != QMessageBox.Yes:
            return
        for use in placed:
            acl.take_off(device, use.family, use.where, use.target, use.acl, use.direction)
        del device.acls[item.key]
        self.current_item = None
        self.edited()

    # ----------------------------------------------------------------- New prefix lists and route maps

    def new_prefix_list(self):
        self.new_policy(routepolicy.PREFIX_LIST)

    def new_route_map(self):
        self.new_policy(routepolicy.ROUTE_MAP)

    def new_policy(self, kind):
        device = self.device()
        if device is None:
            set_hint(self.status_label, "Read a device first (or use the Scratch Pad).", "warning")
            return
        plist = kind == routepolicy.PREFIX_LIST
        items = device.prefix_lists if plist else device.route_maps
        starts = [(f"A copy of {item.title}", item) for item in items.values()]
        for entry in self.store.library:
            found = entry.main() if entry.item.startswith(kind) else None
            if found is not None:
                starts.append((f"Library: {entry.name}", found))
        dialog = NewPolicyDialog(self, kind, items, starts)
        if dialog.exec_() != QDialog.Accepted:
            return
        made = dialog.made()
        items[made.key] = made
        self.current_item = (KIND_PLIST if plist else KIND_RMAP, made.key)
        self.edited()

    # ----------------------------------------------------------------- Object groups and time ranges

    def new_network_group(self):
        self.new_group(NETWORK)

    def new_service_group(self):
        self.new_group(SERVICE)

    def new_group(self, kind):
        device = self.device()
        if device is None:
            set_hint(self.status_label, "Read a device first (or use the Scratch Pad).", "warning")
            return
        name, ok = QInputDialog.getText(self, "New Object Group", f"Name of the new {kind} object group:")
        name = name.strip()
        if not ok or not name:
            return
        if " " in name or name in device.groups:
            set_hint(self.status_label, f"{name} can't be used: it has a space, or the device has it already.",
                     "error")
            return
        family = V4
        if QMessageBox.question(self, "New Object Group", "Is it for IPv6 ACLs?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) == QMessageBox.Yes:
            family = V6
        device.groups[name] = ObjectGroup(name, kind, family)
        self.current_item = (KIND_GROUP, name)
        self.edited()

    def fill_group(self):
        group, device = self.current_group(), self.device()
        self.group_title.setText(f"Object group {group.name}  ({group.keyword})")
        users = device.group_users(group.name)
        names = ", ".join(getattr(user, "title", getattr(user, "name", "")) for user in users)
        set_hint(self.group_users_label, f"Used by: {names}" if users else "Not used by any ACL.", "info")
        self.group_description.setText(group.description)
        self.group_entries.clear()
        self.group_entries.addItems(group.entries)
        if group.kind == NETWORK:
            self.group_input.setPlaceholderText("host 10.1.1.5, 10.1.2.0 255.255.255.0 (a mask, not a wildcard), "
                                                "range 10.1.3.1 10.1.3.20, group-object OTHER")
        else:
            self.group_input.setPlaceholderText("tcp eq 443, udp range 1000 2000, tcp-udp eq 53, icmp echo, gre, "
                                                "group-object OTHER")
        self.group_pick_button.setEnabled(group.kind == NETWORK)

    def check_group_entry(self, group, text):
        """The entry as IOS writes it, or raises ValueError."""
        words = text.split()
        if not words:
            raise ValueError("Type an entry.")
        if words[0] == "group-object":
            if len(words) != 2:
                raise ValueError("group-object takes a group's name.")
            return text
        if group.kind == SERVICE:
            if words[0] not in ("tcp", "udp", "tcp-udp", "icmp", "ip") and acl.protocol_number(words[0]) is None:
                raise ValueError(f"{words[0]} isn't a protocol.")
            return " ".join(words)
        if words[0] == "range" and len(words) == 3:
            for word in words[1:]:
                acl.ipaddress.ip_address(word)
            return text
        if words[0] == "host" and len(words) == 2:
            acl.ipaddress.ip_address(words[1])
            return text
        if group.family == V6:
            network = acl.ipaddress.IPv6Network(words[0], strict=False)
            return f"host {network.network_address}" if network.prefixlen == 128 else str(network)
        address = acl.parse_address_text(text, V4)
        if address.kind == acl.HOST:
            return f"host {address.address}"
        if address.kind == acl.WILDCARD:
            mask = acl.ipaddress.IPv4Address(acl.ip_int(address.wildcard) ^ 0xFFFFFFFF)
            return f"{acl.stored_address(address)} {mask}"
        raise ValueError("A host, a subnet (10.1.2.0/24 or 10.1.2.0 255.255.255.0), a range, or group-object.")

    def add_group_entry(self):
        group = self.current_group()
        if group is None:
            return
        try:
            entry = self.check_group_entry(group, self.group_input.text().strip())
        except ValueError as error:
            set_hint(self.group_hint, str(error), "error")
            return
        if entry in group.entries:
            set_hint(self.group_hint, "It has that already.", "warning")
            return
        group.entries.append(entry)
        self.group_input.clear()
        set_hint(self.group_hint, "", "info")
        self.edited()

    def pick_group_entry(self):
        picker = AddressPicker(self, [choice for choice in self.address_choices() if choice[0] != "Object group"])
        if picker.exec_() == QDialog.Accepted and picker.chosen():
            self.group_input.setText(picker.chosen())
            self.add_group_entry()

    def remove_group_entries(self):
        group = self.current_group()
        if group is None:
            return
        doomed = {item.text() for item in self.group_entries.selectedItems()}
        group.entries = [entry for entry in group.entries if entry not in doomed]
        self.edited()

    def set_group_description(self):
        group = self.current_group()
        if group is not None and group.description != self.group_description.text().strip():
            group.description = self.group_description.text().strip()
            self.edited()

    def delete_group(self):
        group, device = self.current_group(), self.device()
        if group is None:
            return
        users = device.group_users(group.name)
        if users:
            names = ", ".join(getattr(user, "title", getattr(user, "name", "")) for user in users)
            QMessageBox.information(self, "Delete Object Group", f"{group.name} is used by {names}: change them "
                                                                 "first.")
            return
        del device.groups[group.name]
        self.current_item = None
        self.edited()

    def new_time_range(self):
        device = self.device()
        if device is None:
            set_hint(self.status_label, "Read a device first (or use the Scratch Pad).", "warning")
            return
        name, ok = QInputDialog.getText(self, "New Time Range", "Name of the new time range:")
        name = name.strip()
        if not ok or not name:
            return
        if " " in name or name in device.ranges:
            set_hint(self.status_label, f"{name} can't be used: it has a space, or the device has it already.",
                     "error")
            return
        device.ranges[name] = TimeRange(name)
        self.current_item = (KIND_RANGE, name)
        self.edited()

    def fill_range(self):
        item, device = self.current_range(), self.device()
        self.range_title.setText(f"Time range {item.name}")
        users = device.range_users(item.name)
        set_hint(self.range_users_label, "Used by: " + ", ".join(user.title for user in users) if users
                 else "Not used by any ACL.", "info")
        self.range_entries.clear()
        self.range_entries.addItems(item.entries)

    def add_periodic(self):
        item = self.current_range()
        if item is None:
            return
        entry = (f"periodic {self.range_days.currentText()} {self.range_from.time().toString('H:mm')} to "
                 f"{self.range_to.time().toString('H:mm')}")
        if entry not in item.entries:
            item.entries.append(entry)
            self.edited()

    def add_absolute(self):
        item = self.current_range()
        if item is None:
            return

        def moment(edit):
            value = edit.dateTime().toPyDateTime()
            return f"{value:%H:%M} {value.day} {MONTH_NAMES[value.month - 1]} {value.year}"
        parts = ["absolute"]
        if self.range_start_check.isChecked():
            parts.append(f"start {moment(self.range_start)}")
        if self.range_end_check.isChecked():
            parts.append(f"end {moment(self.range_end)}")
        if len(parts) == 1:
            set_hint(self.status_label, "Tick Starting, Ending or both.", "warning")
            return
        item.entries = [entry for entry in item.entries if not entry.startswith("absolute")] + [" ".join(parts)]
        self.edited()

    def remove_range_entries(self):
        item = self.current_range()
        if item is None:
            return
        doomed = {entry.text() for entry in self.range_entries.selectedItems()}
        item.entries = [entry for entry in item.entries if entry not in doomed]
        self.edited()

    def delete_range(self):
        item, device = self.current_range(), self.device()
        if item is None:
            return
        users = device.range_users(item.name)
        if users and QMessageBox.question(self, "Delete Time Range", f"{', '.join(user.title for user in users)} "
                                          f"name {item.name}: without it, their rules with it never match. Delete "
                                          "anyway?") != QMessageBox.Yes:
            return
        del device.ranges[item.name]
        self.current_item = None
        self.edited()

    def show_item_menu(self, position):
        tree_item = self.items_tree.itemAt(position)
        data = tree_item.data(0, Qt.UserRole) if tree_item is not None else None
        menu = QMenu(self)
        actions = {menu.addAction("New ACL..."): self.new_acl,
                   menu.addAction("New Prefix List..."): self.new_prefix_list,
                   menu.addAction("New Route Map..."): self.new_route_map,
                   menu.addAction("New Network Object Group..."): self.new_network_group,
                   menu.addAction("New Service Object Group..."): self.new_service_group,
                   menu.addAction("New Time Range..."): self.new_time_range}
        if data is not None and data[0] == KIND_ACL:
            menu.addSeparator()
            actions[menu.addAction("Apply To...")] = self.apply_acl
            actions[menu.addAction("Save to Library...")] = self.save_to_library
            actions[menu.addAction("Compare Across Devices...")] = self.compare_across
            actions[menu.addAction("Delete ACL")] = self.delete_acl
        elif data is not None and data[0] in (KIND_PLIST, KIND_RMAP):
            editor = self.plist_editor if data[0] == KIND_PLIST else self.rmap_editor
            menu.addSeparator()
            actions[menu.addAction("Apply To...")] = editor.apply_to
            actions[menu.addAction("Save to Library...")] = editor.save_to_library
            actions[menu.addAction("Compare Across Devices...")] = editor.compare
            actions[menu.addAction("Delete")] = editor.delete_item
        chosen = menu.exec_(self.items_tree.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    # ----------------------------------------------------------------- The changes

    def changes_for(self, key):
        before, after = self.read.get(key), self.working.get(key)
        if before is None or after is None or not before.read:
            return []
        return [change for change in acl.device_changes(before, after) if change]

    def all_notes(self, key):
        before, after = self.read.get(key), self.working.get(key)
        if before is None or after is None or not before.read:
            return []
        return [note for change in acl.device_changes(before, after) for note in change.notes]

    def revert_minutes(self):
        return self.minutes_input.value() if self.revert_check.isChecked() else 0

    def lines_text(self, key=None):
        changes = self.changes_for(key or self.current_key)
        return acl.config_text(changes, self.revert_minutes()) if changes else ""

    def undo_lines_text(self, key=None):
        changes = self.changes_for(key or self.current_key)
        return acl.undo_text(changes) if changes else ""

    def lockout_findings(self, key=None):
        key = key or self.current_key
        target, after = self.target(key), self.working.get(key)
        if target is None or after is None or key == SCRATCH or not target.address:
            return []
        pc_ip = local_address_toward(target.address)
        return aclcheck.lockout_change(self.read.get(key), after, pc_ip, target.address)

    def refresh_changes(self, *_):
        key = self.current_key
        target = self.target(key)
        changes = self.changes_for(key) if target is not None else []
        title = f"Changes to {target.label}" if target is not None else "Changes"
        if changes:
            title += f": {len(changes)}"
        self.changes_box.setTitle(title)
        self.show_preview()
        lockout = self.lockout_findings() if changes else []
        errors = [item for item in lockout if item.severity == ERROR]
        notes = [note for change in changes for note in change.notes]
        if key == SCRATCH:
            set_hint(self.lockout_label, "The Scratch Pad isn't a device: copy, export, or save to the Library.",
                     "info")
        elif not changes:
            set_hint(self.lockout_label, "No changes waiting.", "info")
        else:
            text = "\n".join(item.text for item in lockout) + ("\n" + "\n".join(notes) if notes else "")
            set_hint(self.lockout_label, text.strip(), "error" if errors else "warning" if any(
                item.severity == WARNING for item in lockout) else "success")
        self.console_check.setVisible(bool(errors))
        if not errors:
            self.console_check.setChecked(False)
        self.show_waiting()
        self.show_soft()
        self.update_buttons()

    def show_preview(self, *_):
        self.preview.setPlainText(self.lines_text() if self.lines_radio.isChecked() else self.undo_lines_text())

    def copy_preview(self):
        QApplication.clipboard().setText(self.preview.toPlainText())
        set_hint(self.status_label, "Copied.", "success")

    def export_preview(self):
        text = self.preview.toPlainText()
        if not text:
            return
        target = self.target(self.current_key)
        name = (target.names[0] if target and target.names else "acl-changes").replace(" ", "_")
        path, _ = QFileDialog.getSaveFileName(self, "Export Changes", f"{name}.txt", "Text files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as file:
                file.write(text + "\n")
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save it: {error}", "error")
            return
        set_hint(self.status_label, f"Saved to {path}.", "success")

    def discard_changes(self):
        key = self.current_key
        if key not in self.read or not self.changes_for(key):
            return
        if QMessageBox.question(self, "Discard Changes", "Forget every change not sent yet on this device?") != \
                QMessageBox.Yes:
            return
        self.working[key] = self.read[key].copy()
        self.edited()

    def blocked(self, key):
        """Why the changes can't go to key over SSH, or ""."""
        if key == SCRATCH:
            return "The Scratch Pad isn't a device."
        if not self.changes_for(key):
            return "No changes waiting."
        if key in self.waiting:
            return (f"{self.targets[key].label} has changes in waiting to be confirmed: Confirm or Put Back Now "
                    "first.")
        errors = [item for item in self.lockout_findings(key) if item.severity == ERROR]
        if errors and not (key == self.current_key and self.console_check.isChecked()):
            return f"{self.targets[key].label}: {errors[0].text} Fix it, or tick that you can reach it another way."
        problems = [note for note in self.all_notes(key) if "aren't enough" in note]
        if problems:
            return problems[0]
        return ""

    # ----------------------------------------------------------------- Sending over SSH

    def send_current(self):
        self.send_keys([self.current_key])

    def send_all(self):
        keys = [key for key in self.working if key != SCRATCH and self.changes_for(key)]
        if not keys:
            set_hint(self.status_label, "No device has changes waiting.", "info")
            return
        names = ", ".join(self.targets[key].label for key in keys)
        if QMessageBox.question(self, "Send All Devices", f"Send the changes waiting on {len(keys)} devices, one "
                                                          f"after the other ({names})?") != QMessageBox.Yes:
            return
        self.send_keys(keys)

    def send_keys(self, keys):
        if self.busy():
            return
        for key in keys:
            why = self.blocked(key)
            if why:
                set_hint(self.status_label, why, "error")
                return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        jobs = []
        for index, key in enumerate(keys):
            target = self.targets[key]
            changes = self.changes_for(key)
            self.pending_soft[key] = routepolicy.bgp_affected(self.read[key], self.working[key])
            title = "; ".join(change.title for change in changes)
            jobs.append(SendJob(index, target.address, list(target.names), self.lines_text(key), key=key,
                                undo=self.undo_lines_text(key), title=title))
        self.start_send(jobs, self.revert_minutes(), logins)

    def confirm_mode(self):
        return self.confirm_combo.currentData()

    def start_send(self, jobs, minutes, logins):
        self.send_jobs = jobs
        self.send_results = {}
        self.sender_thread = SendThread(jobs, self.pusher_maker(logins), minutes,
                                        self.confirm_mode() != CONFIRM_MANUAL, self)
        self.sender_thread.step_started.connect(self.on_send_started)
        self.sender_thread.step_done.connect(self.on_send_done)
        self.sender_thread.finished.connect(self.on_send_finished)
        self.sender_thread.start()
        self.set_busy("Sending ACL changes")
        self.update_buttons()

    def on_send_started(self, index):
        job = self.send_jobs[index]
        what = {SAVE: "Saving the configuration on", CONFIRM: "Confirming the changes on",
                REVERT: "Putting the old configuration back on"}.get(job.action, "Sending the changes to")
        set_hint(self.status_label, f"{what} {self.targets.get(job.key, Target(job.key, job.address)).label} over "
                                    "SSH...", "info")

    def on_send_done(self, index, outcome):
        job = self.send_jobs[index]
        target = self.targets.get(job.key) or Target(job.key, job.address, job.address)
        self.send_results[index] = outcome.ok
        if job.action == SAVE:
            self.notes[job.key] = "Saved to its startup config." if outcome.ok else \
                f"write memory failed: {outcome.problem}"
            if outcome.ok:
                self.saveable.discard(job.key)
            return
        if job.action in (CONFIRM, REVERT):
            self.waiting_done(job.key, job.action, outcome.ok, outcome.problem)
            return
        if job.action == SOFT:
            self.soft_done(job, target, outcome)
            return
        if outcome.waiting:
            result = f"Sent; waiting to be confirmed (the device puts it back at {outcome.reverts_at} unless it is)"
        elif outcome.ok:
            result = "Confirmed" if outcome.confirmed else "Sent"
        elif outcome.reverted:
            result = f"Put back: {outcome.problem}"
        elif outcome.reverts_at:
            result = f"Not confirmed: {outcome.problem} The device puts it back at {outcome.reverts_at}."
        else:
            result = f"Not sent: {outcome.problem}"
        if outcome.archive_added:
            result += f" (NOMAD set archive path {outcome.archive_added} for the revert timer.)"
        entry = None
        if outcome.transcript.strip() or outcome.ok:
            entry = self.store.record(target.label, job.address, job.title or "ACL changes", job.text, job.undo,
                                      "SSH", result)
        self.notes[job.key] = result
        if outcome.waiting:
            deadline = outcome.reverts_by or datetime.datetime.now() + datetime.timedelta(
                minutes=self.minutes_input.value())
            self.waiting[job.key] = Waiting(deadline, None, entry.id if entry is not None else "")
            self.tick.start()
        elif outcome.ok:
            self.saveable.add(job.key)
            self.offer_soft(job.key, None)
        else:
            self.pending_soft.pop(job.key, None)

    def on_send_finished(self):
        thread, self.sender_thread = self.sender_thread, None
        if thread is not None:
            thread.deleteLater()
        self.clear_busy()
        jobs, self.send_jobs = self.send_jobs, []
        self.fill_history()
        done = [job.key for job in jobs if job.action in (SEND, REVERT) and self.send_results.get(job.index)]
        failed = [job for job in jobs if self.send_results.get(job.index) is False]
        waiting = [key for key in done if key in self.waiting]
        if failed:
            job = failed[0]
            set_hint(self.status_label, f"{self.targets[job.key].label}: {self.notes[job.key]}", "error")
        elif jobs and jobs[0].action != SEND:
            set_hint(self.status_label, self.notes.get(jobs[0].key, ""), "success")
        elif waiting:
            names = ", ".join(self.targets[key].label for key in waiting)
            set_hint(self.status_label, f"Sent to {names}, and a new login works. Check what you need to, then "
                                        f"Confirm (or Put Back Now): the device puts it back at "
                                        f"{self.waiting[waiting[0]].at} unless it's confirmed. Reading it again...",
                     "warning")
        elif done:
            set_hint(self.status_label, f"Sent and confirmed on {len(done)} device(s). Reading them again...",
                     "success")
        self.fill_devices()
        self.refresh_changes()
        if done:  # Read them again: the numbers and counts shown are then the device's own
            self.start_read(done, then=self.after_send_read, logins=self.saved_logins)

    def after_send_read(self):
        if self.waiting.get(self.current_key) is not None:
            item = self.waiting[self.current_key]
            set_hint(self.status_label, f"Read again: the changes are in, waiting to be confirmed by {item.at}.",
                     "warning")
        elif self.saveable:
            set_hint(self.status_label, "Sent, confirmed and read again. Save to Startup Config keeps it after a "
                                        "reload.", "success")

    # ----------------------------------------------------------------- Waiting to be confirmed

    def show_waiting(self):
        item = self.waiting.get(self.current_key)
        self.waiting_box.setVisible(item is not None)
        if item is None:
            return
        left = max(0, int((item.deadline - datetime.datetime.now()).total_seconds()))
        where = f"typed into {item.view.title}" if item.view is not None else "sent over SSH"
        set_hint(self.waiting_label, f"Waiting to be confirmed ({where}): the device puts its old configuration "
                                     f"back at {item.at} ({left // 60}:{left % 60:02d} left) unless it's confirmed. "
                                     "Check what you need to, then Confirm, or Put Back Now.", "warning")

    def on_tick(self):
        now = datetime.datetime.now()
        gone = [key for key, item in self.waiting.items()
                if now >= item.deadline + datetime.timedelta(seconds=EXPIRY_GRACE)]
        for key in gone:
            item = self.waiting.pop(key)
            self.pending_soft.pop(key, None)
            self.notes[key] = f"Not confirmed: the device put its old configuration back at {item.at}."
            self.set_entry_outcome(item, f"Not confirmed: the device put it back at {item.at}")
        if not self.waiting:
            self.tick.stop()
        if gone:
            names = ", ".join(self.targets[key].label for key in gone if key in self.targets)
            set_hint(self.status_label, f"Not confirmed in time: {names} put the old configuration back.", "warning")
            self.fill_devices()
            self.refresh_changes()
            again = [key for key in gone if key in self.read and not self.changes_for(key)]
            if again and self.saved_logins is not None and not self.busy():
                self.start_read(again, then=self.after_put_back_read, logins=self.saved_logins)
        else:
            self.show_waiting()

    def after_put_back_read(self):
        set_hint(self.status_label, "Read again after the device put its old configuration back.", "info")

    def set_entry_outcome(self, item, text):
        entry = next((entry for entry in self.store.history if entry.id == item.entry_id), None) \
            if item is not None and item.entry_id else None
        if entry is not None:
            entry.outcome = text
            self.store.update(entry)
            self.fill_history()

    def confirm_waiting(self):
        self.end_waiting(CONFIRM)

    def put_back_now(self):
        self.end_waiting(REVERT)

    def end_waiting(self, action):
        key = self.current_key
        item = self.waiting.get(key)
        if item is None:
            return
        if item.view is not None:  # Typed into a session: say it there
            line = "configure confirm" if action == CONFIRM else "configure revert now"
            what = "keep the changes" if action == CONFIRM else "put the old configuration back"
            if self.session_sender.send_to(item.view, line, what=what):
                self.waiting_done(key, action, True, "", typed=item.view.title)
            return
        if self.busy():
            return
        target = self.targets[key]
        if action == REVERT and QMessageBox.question(self, "Put Back Now", f"Have {target.label} put its old "
                                                                           "configuration back now?") != QMessageBox.Yes:
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        self.start_send([SendJob(0, target.address, list(target.names), key=key, action=action)], 0, logins)

    def waiting_done(self, key, action, ok, problem, typed=""):
        item = self.waiting.get(key)
        how = f" in {typed}" if typed else ""
        if ok:
            self.waiting.pop(key, None)
            if action == CONFIRM:
                text = f"Confirmed{how} (configure confirm)."
                if not typed:
                    self.saveable.add(key)
                self.offer_soft(key, item.view if item is not None else None)
            else:
                text = f"Put back{how} (configure revert now)."
                self.pending_soft.pop(key, None)
            self.set_entry_outcome(item, text.rstrip("."))
        elif "no rollback" in problem.lower() or "nothing waiting" in problem:
            self.waiting.pop(key, None)
            text = ("Nothing was waiting on the device any more: the revert timer had run out (so it put the old "
                    "configuration back), or it was confirmed another way. Read it again to see.")
            self.set_entry_outcome(item, "Not confirmed: nothing was waiting any more")
        else:
            what = "configure confirm" if action == CONFIRM else "configure revert now"
            text = f"{what} didn't work: {problem}"
            if item is not None:
                text += f" Unless it's confirmed, the device puts it back at {item.at}."
        self.notes[key] = text
        if not self.waiting:
            self.tick.stop()
        self.fill_devices()
        self.refresh_changes()
        if typed:
            set_hint(self.status_label, text, "success")

    # ----------------------------------------------------------------- BGP soft clears

    def offer_soft(self, key, view):
        """Changes went in (and are confirmed): offer the BGP neighbors they touch a soft clear."""
        clears = self.pending_soft.pop(key, [])
        if clears:
            self.soft_offers[key] = (clears, view)
        self.show_soft()

    def show_soft(self):
        offer = self.soft_offers.get(self.current_key)
        self.soft_box.setVisible(bool(offer))
        if not offer:
            return
        clears, view = offer
        where = f" (typed into {view.title})" if view is not None else " (over SSH)"
        set_hint(self.soft_label, f"BGP puts routes it already has through a changed policy only after a soft "
                                  f"clear (the session stays up). Tick the neighbors to clear{where}:", "info")
        self.soft_list.blockSignals(True)
        ticked = {self.soft_list.item(row).data(Qt.UserRole) for row in range(self.soft_list.count())
                  if self.soft_list.item(row).checkState() == Qt.Checked}
        self.soft_list.clear()
        for clear in clears:
            item = QListWidgetItem(f"{clear.label}:  {clear.command}")
            item.setData(Qt.UserRole, clear.command)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if clear.command in ticked else Qt.Unchecked)
            self.soft_list.addItem(item)
        self.soft_list.blockSignals(False)

    def ticked_soft(self):
        return [self.soft_list.item(row).data(Qt.UserRole) for row in range(self.soft_list.count())
                if self.soft_list.item(row).checkState() == Qt.Checked]

    def soft_clear(self):
        key = self.current_key
        offer = self.soft_offers.get(key)
        commands = self.ticked_soft()
        if offer is None or not commands:
            return
        clears, view = offer
        if view is not None:
            if self.session_sender.send_to(view, "\n".join(commands), what="soft clear the BGP neighbors"):
                self.store.record(self.targets[key].label, self.targets[key].address, "BGP soft clear",
                                  "\n".join(commands), "", view.title, f"Typed into {view.title}")
                self.soft_cleared(key, commands)
            return
        if self.busy():
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        target = self.targets[key]
        job = SendJob(0, target.address, list(target.names), "\n".join(commands), key=key, title="BGP soft clear",
                      action=SOFT)
        self.start_send([job], 0, logins)

    def soft_done(self, job, target, outcome):
        commands = job.text.splitlines()
        result = "Soft cleared" if outcome.ok else f"Soft clear failed: {outcome.problem}"
        self.store.record(target.label, job.address, job.title, job.text, "", "SSH", result)
        self.notes[job.key] = result + "."
        if outcome.ok:
            self.soft_cleared(job.key, commands)

    def soft_cleared(self, key, commands):
        clears, view = self.soft_offers.get(key, ([], None))
        left = [clear for clear in clears if clear.command not in commands]
        if left:
            self.soft_offers[key] = (left, view)
        else:
            self.soft_offers.pop(key, None)
        self.fill_history()
        self.fill_devices()
        self.show_soft()
        self.update_buttons()

    def copy_soft(self):
        offer = self.soft_offers.get(self.current_key)
        if offer is not None:
            QApplication.clipboard().setText("\n".join(self.ticked_soft() or [clear.command for clear in offer[0]]))
            set_hint(self.status_label, "Copied the soft clear commands.", "success")

    def dismiss_soft(self):
        self.soft_offers.pop(self.current_key, None)
        self.fill_devices()
        self.show_soft()

    def save_startup(self):
        key = self.current_key
        if key not in self.saveable or self.busy():
            return
        target = self.targets[key]
        if QMessageBox.question(self, "Save to Startup Config", f"Save {target.label}'s running configuration to "
                                                                "its startup configuration (write memory)?") != \
                QMessageBox.Yes:
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.start_send([SendJob(0, target.address, list(target.names), key=key, action=SAVE)], 0, logins)

    # ----------------------------------------------------------------- Terminal sessions

    def fill_session_menu(self):
        key = self.current_key
        if not self.changes_for(key) or key == SCRATCH:
            self.session_menu.clear()
            self.session_menu.addAction("No changes to send").setEnabled(False)
            return
        self.session_sender.fill_menu(self.session_menu, self.session_text, device=self.device_hints(key),
                                      tag=("changes", key))

    def session_text(self):
        return self.lines_text()

    def lines_sent(self, view, tag):
        """SessionSender: lines went to a session."""
        if not tag:
            return
        what, key = tag[0], tag[1]
        target = self.targets.get(key)
        if what == "changes" and target is not None:
            changes = self.changes_for(key)
            title = "; ".join(change.title for change in changes)
            minutes = self.revert_minutes()
            self.pending_soft[key] = routepolicy.bgp_affected(self.read[key], self.working[key])
            if not minutes:
                self.offer_soft(key, view)
            outcome = f"Typed into {view.title}" + (f" with a {minutes}-minute revert timer: Confirm once you've "
                                                    "checked you can still log in" if minutes else "")
            entry = self.store.record(target.label, target.address, title, self.lines_text(key),
                                      self.undo_lines_text(key), view.title, outcome)
            self.notes[key] = outcome + ". Read it again to see what it has."
            if minutes:
                deadline = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
                self.waiting[key] = Waiting(deadline, view, entry.id)
                self.tick.start()
                self.refresh_changes()
            self.fill_history()
            self.fill_devices()
            self.update_buttons()
        elif what == "undo":
            entry = next((item for item in self.store.history if item.id == key), None)
            if entry is not None:
                entry.outcome = f"Undone in {view.title}"
                self.store.update(entry)
                self.fill_history()

    # ----------------------------------------------------------------- The library

    def save_to_library(self):
        item, device = self.current_acl(), self.device()
        if item is None:
            return
        name, ok = QInputDialog.getText(self, "Save to Library", "Name in the library:", text=item.name)
        name = name.strip()
        if not ok or not name:
            return
        if any(entry.name == name for entry in self.store.library) and QMessageBox.question(
                self, "Save to Library", f"The library has {name} already. Replace it?") != QMessageBox.Yes:
            return
        groups, ranges = acl.needed(item, device)
        self.store.add_to_library(name, acl.library_config(item, groups, ranges))
        self.fill_library()
        set_hint(self.status_label, f"Saved {item.name} to the library as {name}.", "success")

    def fill_library(self):
        table = self.library_table
        table.setRowCount(len(self.store.library))
        for row, entry in enumerate(self.store.library):
            item = entry.main()
            count = len(getattr(item, "rules", getattr(item, "entries", []))) if item is not None else 0
            title = item.title if item is not None else "?"
            cells = [entry.name, title[:1].upper() + title[1:], str(count) if item is not None else "",
                     entry.saved.replace("T", " ")[:16], entry.notes]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, entry.id)
                table.setItem(row, column, cell)
        table.resizeColumnsToContents()
        self.on_library_selected()

    def library_entry(self):
        rows = sorted({index.row() for index in self.library_table.selectedIndexes()})
        if not rows:
            return None
        entry_id = self.library_table.item(rows[0], 0).data(Qt.UserRole)
        return next((entry for entry in self.store.library if entry.id == entry_id), None)

    def on_library_selected(self):
        entry = self.library_entry()
        self.library_view.setPlainText(entry.config if entry is not None else "")
        self.update_buttons()

    def use_library(self, key, entry):
        """Merge the library's ACL (and its groups, time ranges), prefix list or route map (and the prefix lists and
        ACLs it matches) into key's working copy: ((the tree's kind, its key), what happened)."""
        device = self.working.get(key)
        if device is None or not device.read:
            return None, "not read"
        if entry.item:
            return self.use_library_policy(device, entry)
        acl_key, what = self.merge_library_acl(device, entry.device())
        return ((KIND_ACL, acl_key) if acl_key is not None else None), what

    def use_library_policy(self, device, entry):
        source = entry.device()
        wanted = entry.main()
        if wanted is None:
            return None, "nothing in it"
        for acl_key in list(source.acls):  # The ACLs and prefix lists a route map matches go in first
            single = source.copy()
            single.acls = {acl_key: source.acls[acl_key]}
            self.merge_library_acl(device, single)
        had = set(device.prefix_lists)
        for plist_key, plist in source.prefix_lists.items():
            device.prefix_lists[plist_key] = routepolicy.align_prefix(device.prefix_lists.get(plist_key), plist)
        if isinstance(wanted, routepolicy.RouteMap):
            existing = device.route_maps.get(wanted.name)
            device.route_maps[wanted.name] = routepolicy.align_map(existing, wanted)
            return (KIND_RMAP, wanted.name), "merged" if existing is not None else "made"
        return (KIND_PLIST, wanted.key), "merged" if wanted.key in had else "made"

    def merge_library_acl(self, device, source):
        """Merge source's ACL (and its groups, time ranges) into device: (ACL key, what happened)."""
        library_acl = next(iter(source.acls.values()), None)
        if library_acl is None:
            return None, "nothing in it"
        for name, group in source.groups.items():
            device.groups[name] = ObjectGroup(group.name, group.kind, group.family, list(group.entries),
                                              group.description)
        for name, item in source.ranges.items():
            device.ranges[name] = TimeRange(item.name, list(item.entries))
        existing = device.acls.get(library_acl.key)
        if existing is not None:
            if existing.kind != library_acl.kind:
                return None, f"it has {existing.title}, a different kind"
            device.acls[library_acl.key] = acl.align(existing, library_acl).copy(trailing_remark=
                                                                                 library_acl.trailing_remark)
            return library_acl.key, "merged"
        device.acls[library_acl.key] = library_acl.copy(rules=[rule.copy(seq=0, hits=None, want_seq=0)
                                                               for rule in library_acl.rules])
        return library_acl.key, "made"

    def use_library_here(self, *_):
        entry = self.library_entry()
        key = self.current_key
        if entry is None:
            return
        if self.device(key) is None:
            set_hint(self.status_label, "Pick a device that's been read (or the Scratch Pad) on the Edit tab first.",
                     "warning")
            return
        item_key, what = self.use_library(key, entry)
        if item_key is None:
            set_hint(self.status_label, f"Couldn't use {entry.name}: {what}.", "error")
            return
        self.current_item = item_key
        self.tabs.setCurrentIndex(0)
        self.edited()
        set_hint(self.status_label, f"{entry.name} {what} into {self.targets[key].label}: check the changes, then "
                                    "send.", "success")

    def put_on_devices(self):
        entry = self.library_entry()
        if entry is None:
            return
        devices = [(key, target.label) for key, target in self.targets.items() if key != SCRATCH]
        picker = DevicePicker(self, f"Put {entry.name} on Devices", devices,
                              "NOMAD reads each one, merges the ACL into what it has (nothing is sent yet), and "
                              "lists the changes. Then Send All Devices.")
        if picker.exec_() != QDialog.Accepted or not picker.chosen():
            return
        keys = picker.chosen()
        unread = [key for key in keys if key not in self.read or not self.read[key].read]
        self.pending_library = (entry, keys)
        if unread:
            if not self.start_read(unread, then=self.finish_put_on):
                self.pending_library = None
        else:
            self.finish_put_on()

    def finish_put_on(self):
        entry, keys = self.pending_library or (None, [])
        self.pending_library = None
        if entry is None:
            return
        results = []
        for key in keys:
            _, what = self.use_library(key, entry)
            results.append(f"{self.targets[key].label}: {what}")
        self.tabs.setCurrentIndex(0)
        self.edited()
        set_hint(self.status_label, f"{entry.name}: " + "; ".join(results) + ". Check each device's changes, then "
                                    "Send All Devices.", "info")

    def import_text(self):
        dialog = ImportDialog(self)
        if dialog.exec_() != QDialog.Accepted:
            return
        source = dialog.device()
        for item in source.acls.values():
            groups, ranges = acl.needed(item, source)
            self.store.add_to_library(item.name, acl.library_config(item, groups, ranges))
        self.fill_library()
        set_hint(self.status_label, f"Added {len(source.acls)} ACL(s) to the library.", "success")

    def edit_library_notes(self):
        entry = self.library_entry()
        if entry is None:
            return
        text, ok = QInputDialog.getMultiLineText(self, "Notes", f"Notes about {entry.name}:", entry.notes)
        if ok:
            entry.notes = text.strip()
            self.store.save()
            self.fill_library()

    def export_library(self):
        entry = self.library_entry()
        if entry is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export ACL", f"{entry.name}.txt", "Text files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as file:
                file.write(entry.config + "\n")
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save it: {error}", "error")
            return
        set_hint(self.status_label, f"Saved to {path}.", "success")

    def delete_library(self):
        entry = self.library_entry()
        if entry is None:
            return
        if QMessageBox.question(self, "Delete", f"Delete {entry.name} from the library?") == QMessageBox.Yes:
            self.store.remove_from_library(entry.id)
            self.fill_library()

    # ----------------------------------------------------------------- Comparing across devices

    def compare_across(self):
        item = self.current_acl()
        if item is None:
            return
        others = [(key, device) for key, device in self.read.items() if key not in (self.current_key, SCRATCH)
                  and device.read and item.key in device.acls]
        here = self.targets[self.current_key].label
        if not others:
            set_hint(self.status_label, f"No other device read has {item.name}: read more devices first.", "info")
            return
        lines = [f"{item.title} on {here} (as edited here) against the others read:", ""]
        mine = [rule.body(item.family, item.kind) for rule in item.rules]
        for key, device in others:
            theirs_acl = device.acls[item.key]
            theirs = [rule.body(theirs_acl.family, theirs_acl.kind) for rule in theirs_acl.rules]
            label = self.targets[key].label if key in self.targets else key
            only_here = [rule for rule in mine if rule not in theirs]
            only_there = [rule for rule in theirs if rule not in mine]
            if not only_here and not only_there:
                order = "the same rules" + (" in the same order" if mine == theirs else ", in another order")
                lines.append(f"{label}: {order}.")
            else:
                lines.append(f"{label}:")
                lines += [f"  only on {here}:   {rule}" for rule in only_here]
                lines += [f"  only on {label}:  {rule}" for rule in only_there]
            lines.append("")
        TextDialog(self, f"Compare {item.name}", "\n".join(lines)).exec_()

    # ----------------------------------------------------------------- Changes sent

    def fill_history(self):
        table = self.history_table
        table.setRowCount(len(self.store.history))
        for row, entry in enumerate(self.store.history):
            cells = [entry.when.replace("T", " ")[:16], entry.device, entry.title, entry.how, entry.outcome]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, entry.id)
                cell.setToolTip(text)
                if column == 4:
                    good = text.startswith(("Confirmed", "Sent", "Typed", "Undone"))
                    cell.setForeground(QColor(COLORS["success" if good else "warning"]))
                table.setItem(row, column, cell)
        table.resizeColumnsToContents()
        self.on_history_selected()

    def history_entry(self):
        rows = sorted({index.row() for index in self.history_table.selectedIndexes()})
        if not rows:
            return None
        entry_id = self.history_table.item(rows[0], 0).data(Qt.UserRole)
        return next((entry for entry in self.store.history if entry.id == entry_id), None)

    def on_history_selected(self, *_):
        entry = self.history_entry()
        text = "" if entry is None else entry.lines if self.history_lines_radio.isChecked() else entry.undo
        self.history_view.setPlainText(text)
        self.update_buttons()

    def undo_over_ssh(self):
        entry = self.history_entry()
        if entry is None or self.busy():
            return
        if QMessageBox.question(self, "Undo over SSH", f"Send what undoes \"{entry.title}\" to {entry.device} "
                                                       f"({entry.address})?") != QMessageBox.Yes:
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        key = next((key for key, target in self.targets.items() if target.address == entry.address),
                   f"address:{entry.address}")
        self.targets.setdefault(key, Target(key, entry.device, entry.address, [], "address"))
        minutes = self.revert_minutes()
        text = entry.undo
        if minutes:
            text = text.replace("configure terminal", f"configure terminal revert timer {minutes}", 1)
        job = SendJob(0, entry.address, list(self.targets[key].names), text, key=key, undo=entry.lines,
                      title=f"Undo: {entry.title}")
        self.start_send([job], minutes, logins)

    def fill_undo_session_menu(self):
        entry = self.history_entry()
        if entry is None:
            self.undo_session_menu.clear()
            return
        key = next((key for key, target in self.targets.items() if target.address == entry.address), "")
        self.session_sender.fill_menu(self.undo_session_menu, lambda: entry.undo,
                                      device=self.device_hints(key) if key else {"address": entry.address},
                                      tag=("undo", entry.id))

    def copy_undo(self):
        entry = self.history_entry()
        if entry is not None:
            QApplication.clipboard().setText(entry.undo)
            set_hint(self.status_label, "Copied what undoes it.", "success")

    def forget_history(self):
        entry = self.history_entry()
        if entry is None:
            return
        self.store.history = [item for item in self.store.history if item.id != entry.id]
        self.store.save()
        self.fill_history()

    # ----------------------------------------------------------------- From the map

    def prefill(self, map_key="", acl_name="", port=""):
        """From the Network Map: the device's ACLs (read now if they weren't), showing acl_name, or the ACL applied
        on port (in)."""
        if not map_key:
            return
        self.on_map_shown()
        key = f"map:{map_key}"
        if key not in self.targets:
            set_hint(self.status_label, "That device isn't a switch or router on the map.", "warning")
            return
        self.current_key = key
        self.current_item = None
        self.selecting = f"port:{port}" if port else acl_name
        self.fill_devices()
        self.on_device_chosen()
        if self.device(key) is None:
            self.start_read([key])
        else:
            self.select_wanted()

    def select_wanted(self):
        wanted, self.selecting = self.selecting, ""
        device = self.device()
        if device is None or not wanted:
            return
        if wanted.startswith("port:"):
            port = port_key(wanted[5:])
            uses = [use for use in device.applied if use.where == INTERFACE and port_key(use.target) == port]
            if not uses:
                set_hint(self.status_label, f"No ACL is applied on {wanted[5:]}. Pick one and Apply To... to put "
                                            "one there.", "info")
                return
            use = sorted(uses, key=lambda item: item.direction != acl.IN)[0]
            self.current_item = (KIND_ACL, (use.family, use.acl))
            if len(uses) > 1:
                set_hint(self.status_label, f"{wanted[5:]} has " + ", ".join(item.label() for item in uses) + ".",
                         "info")
        else:
            found = next((item.key for item in device.acls.values() if item.name == wanted), None)
            if found is None:
                return
            self.current_item = (KIND_ACL, found)
        self.fill_items()

    # ----------------------------------------------------------------- Busy

    def set_busy(self, text):
        busy = getattr(self.window, "set_busy", None)
        if busy is not None:
            busy("acls", text)

    def clear_busy(self):
        clear = getattr(self.window, "clear_busy", None)
        if clear is not None:
            clear("acls")

    def stop(self):
        for thread in (self.reader, self.sender_thread):
            if thread is not None:
                thread.stop()
        set_hint(self.status_label, "Stopping...", "info")

    def update_buttons(self):
        if not hasattr(self, "history_table"):
            return
        busy = self.busy()
        key = self.current_key
        device = self.device()
        has_changes = bool(self.changes_for(key)) if key else False
        if hasattr(self, "soft_button"):
            offer = self.soft_offers.get(key)
            self.soft_button.setEnabled(bool(offer) and bool(self.ticked_soft()) and
                                        (offer[1] is not None or not busy))
        real = key not in ("", SCRATCH)
        self.read_button.setEnabled(not busy)
        self.stop_button.setEnabled(busy)
        self.new_acl_button.setEnabled(device is not None)
        self.new_button.setEnabled(device is not None)
        item = self.current_acl()
        rows = self.selected_rows() if item is not None else []
        self.add_rule_button.setEnabled(item is not None)
        for button in (self.edit_rule_button, self.duplicate_button, self.delete_rule_button):
            button.setEnabled(bool(rows))
        self.up_button.setEnabled(bool(rows) and rows[0] > 0)
        self.down_button.setEnabled(bool(rows) and item is not None and rows[-1] < len(item.rules) - 1)
        self.apply_button.setEnabled(item is not None and real)
        self.take_off_button.setEnabled(item is not None and real)
        waiting = self.waiting.get(key)
        self.send_button.setEnabled(not busy and real and has_changes and not self.blocked(key))
        self.session_button.setEnabled(real and has_changes and waiting is None)
        for button in (self.confirm_button, self.put_back_button):
            button.setEnabled(waiting is not None and (waiting.view is not None or not busy))
        self.confirm_combo.setEnabled(self.revert_check.isChecked())
        self.save_button.setEnabled(not busy and key in self.saveable and not has_changes and waiting is None)
        self.send_all_button.setEnabled(not busy and any(self.changes_for(other) for other in self.working
                                                         if other != SCRATCH))
        self.discard_button.setEnabled(has_changes)
        self.copy_button.setEnabled(bool(self.preview.toPlainText()))
        self.export_button.setEnabled(bool(self.preview.toPlainText()))
        entry = self.library_entry() if hasattr(self, "library_table") else None
        for button in (self.use_here_button, self.put_on_button, self.notes_button, self.library_export_button,
                       self.library_delete_button):
            button.setEnabled(entry is not None)
        history = self.history_entry()
        self.undo_ssh_button.setEnabled(history is not None and not busy and bool(history.undo))
        self.undo_session_button.setEnabled(history is not None)
        self.copy_undo_button.setEnabled(history is not None)
        self.forget_button.setEnabled(history is not None)
