"""Network Map settings: the SNMP credentials to try, and how far the crawl may go; and the dialogs for
hosts added by hand and for sites, buildings and rooms."""
import ipaddress
from dataclasses import replace

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, \
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox, QTableWidget, \
    QTableWidgetItem, QVBoxLayout

from ..netmap import diff
from ..netmap.crawl import MAX_WORKERS, WORKERS, parse_networks
from ..netmap.model import AP, CORRECTED_NAMES, FIREWALL, GROUP_KINDS, KIND_NAMES, PARENT_KIND, ROUTER, SERVER, \
    SITE, SWITCH, UNCHECKED, UNKNOWN, Device, Host, Link, normalize_name, port_sort_key, short_port
from ..oui import format_mac, vendor
from ..snmp import VERSIONS, community_is_valid
from ..snmpv3 import AUTH_NAMES, PRIV_NAMES, V3User, is_v3
from .common import ColumnFitter
from .theme import COLORS

CHANGE_COLORS = {diff.ADDED: "success", diff.REMOVED: "error", diff.CHANGED: "warning", diff.MOVED: "link"}


class V3UsersTable(QTableWidget):
    """SNMPv3 users, one per row: name, authentication protocol and password, privacy protocol and password. Used by
    the map's SNMP Credentials and the SNMP Config page."""
    COLUMNS = ["User", "Authentication", "Auth Password", "Privacy", "Privacy Password"]

    def __init__(self, users=(), parent=None):
        super().__init__(0, len(self.COLUMNS), parent)
        self.setHorizontalHeaderLabels(self.COLUMNS)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self)
        for user in users:
            self.add_user(user)

    def add_user(self, user=None):
        user = user or V3User("", "sha", "", "aes128", "")
        row = self.rowCount()
        self.insertRow(row)
        name = QLineEdit(user.user)
        auth, priv = QComboBox(), QComboBox()
        for key, label in AUTH_NAMES.items():
            auth.addItem(label, key)
        for key, label in PRIV_NAMES.items():
            priv.addItem(label, key)
        auth.setCurrentIndex(max(0, auth.findData(user.auth)))
        priv.setCurrentIndex(max(0, priv.findData(user.priv)))
        passwords = []
        for text in (user.auth_password, user.priv_password):
            password = QLineEdit(text)
            password.setEchoMode(QLineEdit.Password)
            passwords.append(password)
        for column, widget in enumerate((name, auth, passwords[0], priv, passwords[1])):
            self.setCellWidget(row, column, widget)
        auth.currentIndexChanged.connect(lambda _: self.update_enabled())
        priv.currentIndexChanged.connect(lambda _: self.update_enabled())
        self.update_enabled()
        if not user.user:
            name.setFocus()

    def update_enabled(self):
        for row in range(self.rowCount()):
            auth = self.cellWidget(row, 1).currentData()
            self.cellWidget(row, 2).setEnabled(auth != "none")
            self.cellWidget(row, 3).setEnabled(auth != "none")
            self.cellWidget(row, 4).setEnabled(auth != "none" and self.cellWidget(row, 3).currentData() != "none")

    def remove_selected(self):
        for row in sorted({index.row() for index in self.selectedIndexes()}, reverse=True):
            self.removeRow(row)

    def users(self):
        """The users, without empty rows. Raises ValueError for one that isn't valid."""
        users = []
        for row in range(self.rowCount()):
            name = self.cellWidget(row, 0).text().strip()
            auth = self.cellWidget(row, 1).currentData()
            priv = self.cellWidget(row, 3).currentData() if auth != "none" else "none"
            user = V3User(name, auth, self.cellWidget(row, 2).text() if auth != "none" else "", priv,
                          self.cellWidget(row, 4).text() if priv != "none" else "")
            if not name and not user.auth_password and not user.priv_password:
                continue
            problem = user.problem()
            if problem:
                raise ValueError(problem)
            if any(other.user == name for other in users):
                raise ValueError(f"There are two SNMPv3 users named {name}.")
            users.append(user)
        return users


V3_PREFIX = "v3:"  # A per-subnet entry naming an SNMPv3 user instead of a community string


class CommunitiesDialog(QDialog):
    """The map's SNMP credentials: community strings, SNMPv3 users, and which to try first for some subnets."""

    def __init__(self, communities, overrides, version, timeout, parent=None, v3_users=(), v3_first=True,
                 tribe_map=None):
        """tribe_map: the name of the tribe map open (its credentials are shared with the tribe), or None."""
        super().__init__(parent)
        self.setWindowTitle("SNMP Credentials" if tribe_map is None else f"SNMP Credentials: Tribe Map {tribe_map}")
        self.resize(680, 640)
        layout = QVBoxLayout(self)
        if tribe_map is not None:
            shared = QLabel(f"These are the tribe map {tribe_map}'s credentials, shared with everyone in the tribe: "
                            "changing them here changes them for everyone who opens or watches it.")
            shared.setWordWrap(True)
            shared.setStyleSheet(f"color: {COLORS['accent']};")
            layout.addWidget(shared)
        layout.addWidget(QLabel("Community strings (v1/v2c) to try on each device, in order, one per line. The first "
                                "one that answers is used for that device."))
        self.communities_input = QPlainTextEdit("\n".join(communities))
        self.communities_input.setTabChangesFocus(True)
        layout.addWidget(self.communities_input, 1)

        layout.addWidget(QLabel("SNMPv3 users to try:"))
        self.users_table = V3UsersTable(v3_users)
        layout.addWidget(self.users_table, 1)
        user_buttons = QHBoxLayout()
        add_user = QPushButton("Add User")
        remove_user = QPushButton("Remove User")
        add_user.clicked.connect(lambda: self.users_table.add_user())
        remove_user.clicked.connect(self.users_table.remove_selected)
        self.v3_first_check = QCheckBox("Try SNMPv3 users before community strings")
        self.v3_first_check.setToolTip("A device that doesn't have the user says so at once, while a wrong community "
                                       "string waits for the timeout, so users first is usually faster.")
        self.v3_first_check.setChecked(v3_first)
        user_buttons.addWidget(add_user)
        user_buttons.addWidget(remove_user)
        user_buttons.addStretch()
        user_buttons.addWidget(self.v3_first_check)
        layout.addLayout(user_buttons)

        layout.addWidget(QLabel(f"Per-subnet credentials, tried first for addresses in the subnet (a community "
                                f"string, or {V3_PREFIX}user for an SNMPv3 user above):"))
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Subnet", "Community or v3:user"])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)
        for subnet, community in overrides:
            self.add_row(subnet, V3_PREFIX + community.user if is_v3(community) else community)
        layout.addWidget(self.table, 1)
        row_buttons = QHBoxLayout()
        add_button = QPushButton("Add")
        remove_button = QPushButton("Remove")
        add_button.clicked.connect(lambda: self.add_row("", "", edit=True))
        remove_button.clicked.connect(self.remove_rows)
        row_buttons.addWidget(add_button)
        row_buttons.addWidget(remove_button)
        row_buttons.addStretch()
        layout.addLayout(row_buttons)

        form = QFormLayout()
        self.version_combo = QComboBox()
        self.version_combo.addItems(list(VERSIONS))
        self.version_combo.setCurrentText(next((name for name, value in VERSIONS.items() if value == version), "v2c"))
        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(200, 20000)
        self.timeout_input.setSingleStep(500)
        self.timeout_input.setValue(timeout)
        self.timeout_input.setSuffix(" ms")
        self.timeout_input.setToolTip("How long to wait for each SNMP answer. Devices that don't answer are tried "
                                      "with each credential, so a long timeout slows the crawl down.")
        form.addRow("Community string version:", self.version_combo)
        form.addRow("Timeout:", self.timeout_input)
        layout.addLayout(form)
        where = ("Kept encrypted on the tribe server, and on each computer for when the server can't be reached."
                 if tribe_map is not None else "Saved encrypted for your Windows account.")
        note = QLabel(f"{where} Generate SNMP Config builds the switch configuration that sets them up.")
        note.setWordWrap(True)
        note.setEnabled(False)
        layout.addWidget(note)
        self.build_config = False  # Whether Generate SNMP Config closed it
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        config_button = buttons.addButton("Generate SNMP Config", QDialogButtonBox.ActionRole)
        config_button.setToolTip("Keep these, and build the Cisco configuration that sets the switches up with them "
                                 "on the SNMP Config page.")
        config_button.clicked.connect(self.accept_and_build)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def add_row(self, subnet, community, edit=False):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(subnet))
        self.table.setItem(row, 1, QTableWidgetItem(community))
        if edit:
            self.table.editItem(self.table.item(row, 0))

    def remove_rows(self):
        for row in sorted({index.row() for index in self.table.selectedIndexes()}, reverse=True):
            self.table.removeRow(row)

    def values(self):
        """(communities, overrides, version, timeout, v3 users, v3 first). Raises ValueError for anything that isn't
        valid."""
        communities = [line.strip() for line in self.communities_input.toPlainText().splitlines() if line.strip()]
        users = self.users_table.users()
        if not communities and not users:
            raise ValueError("Enter at least one community string (such as public) or SNMPv3 user.")
        by_name = {user.user: user for user in users}
        overrides = []
        for row in range(self.table.rowCount()):
            subnet = (self.table.item(row, 0).text() if self.table.item(row, 0) else "").strip()
            community = (self.table.item(row, 1).text() if self.table.item(row, 1) else "").strip()
            if not subnet and not community:
                continue
            try:
                subnet = str(ipaddress.ip_network(subnet, strict=False))
            except ValueError:
                raise ValueError(f"'{subnet}' isn't a subnet. Use CIDR notation, such as 10.20.0.0/16.") from None
            if not community:
                raise ValueError(f"Enter the community string (or {V3_PREFIX}user) for {subnet}.")
            if community.lower().startswith(V3_PREFIX):
                name = community[len(V3_PREFIX):].strip()
                if name not in by_name:
                    raise ValueError(f"{subnet} uses SNMPv3 user {name}, who isn't in the users list.")
                overrides.append((subnet, by_name[name]))
            else:
                overrides.append((subnet, community))
        for community in communities + [community for _, community in overrides if not is_v3(community)]:
            if not community_is_valid(community):
                raise ValueError("Community strings can't be longer than 255 bytes or contain control characters.")
        return (communities, overrides, VERSIONS[self.version_combo.currentText()], self.timeout_input.value(),
                users, self.v3_first_check.isChecked())

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            self.build_config = False
            QMessageBox.warning(self, "SNMP Credentials", str(error))
            return
        super().accept()

    def accept_and_build(self):
        self.build_config = True
        self.accept()


class ScopeDialog(QDialog):
    def __init__(self, scope, max_hops, max_devices, collect_hosts, trace, workers=WORKERS, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Crawl Scope")
        self.resize(460, 380)
        layout = QVBoxLayout(self)
        label = QLabel("Only ask devices in these subnets (one per line). Leave empty for any private address "
                       "(10.x, 172.16-31.x, 192.168.x). Devices outside still appear as neighbors.")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.scope_input = QPlainTextEdit("\n".join(scope))
        self.scope_input.setPlaceholderText("10.0.0.0/8")
        self.scope_input.setTabChangesFocus(True)
        layout.addWidget(self.scope_input, 1)
        form = QFormLayout()
        self.hops_input = QSpinBox()
        self.hops_input.setRange(0, 50)
        self.hops_input.setValue(max_hops)
        self.hops_input.setToolTip("How many links away from the starting devices to go. 0 reads only the "
                                   "starting devices.")
        self.devices_input = QSpinBox()
        self.devices_input.setRange(1, 10000)
        self.devices_input.setValue(max_devices)
        self.devices_input.setToolTip("Stop asking new devices after this many.")
        self.hosts_check = QCheckBox("Read MAC and ARP tables to show the hosts on each switch port")
        self.hosts_check.setChecked(collect_hosts)
        self.trace_check = QCheckBox("Traceroute to what SNMP can't show (for the logical view)")
        self.trace_check.setToolTip("After the crawl, trace from this computer to devices that didn't answer SNMP, "
                                    "next hops that aren't on the map, and static routes' destinations.")
        self.trace_check.setChecked(trace)
        form.addRow("Hops:", self.hops_input)
        form.addRow("Devices to ask, at most:", self.devices_input)
        self.workers_input = QSpinBox()
        self.workers_input.setRange(1, MAX_WORKERS)
        self.workers_input.setValue(workers)
        self.workers_input.setToolTip("How many devices to read at the same time. More is faster on a big network; "
                                      "fewer is gentler on slow links and busy devices.")
        form.addRow("Devices read at once:", self.workers_input)
        form.addRow(self.hosts_check)
        form.addRow(self.trace_check)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self):
        """(scope lines, max hops, max devices, collect hosts, trace, devices at once). Raises ValueError for a bad
        subnet."""
        lines = [line.strip() for line in self.scope_input.toPlainText().splitlines() if line.strip()]
        parse_networks(lines)
        return (lines, self.hops_input.value(), self.devices_input.value(), self.hosts_check.isChecked(),
                self.trace_check.isChecked(), self.workers_input.value())

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            QMessageBox.warning(self, "Crawl Scope", str(error))
            return
        super().accept()


class CompareDialog(QDialog):
    """What changed since an earlier map. Double-click a row to see it on the map; not modal, so the map can be
    looked at alongside."""
    show_change = pyqtSignal(object)  # diff.Change

    def __init__(self, changes, older_name, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"Compared with {older_name}")
        self.setAttribute(Qt.WA_DeleteOnClose)
        self.resize(760, 480)
        self.changes = changes
        layout = QVBoxLayout(self)
        counts = {}
        for change in changes:
            counts[(change.what, change.change)] = counts.get((change.what, change.change), 0) + 1
        summary = ", ".join(f"{count} {what.lower()}{'' if count == 1 else 's'} {change.lower()}"
                            for (what, change), count in sorted(counts.items())) or "No differences."
        label = QLabel(f"Since {older_name}: {summary}")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.churn_check = QCheckBox("Show hosts that appeared or went away (computers are turned on and off, so "
                                     "these are often not a real change)")
        self.churn_check.toggled.connect(self.fill)
        layout.addWidget(self.churn_check)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Change", "What", "Name", "Details"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)
        self.table.itemDoubleClicked.connect(self.on_double_click)
        layout.addWidget(self.table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.fill()

    def shown_changes(self):
        churn = self.churn_check.isChecked()
        return [change for change in self.changes if churn or change.what != diff.HOST
                or change.change not in (diff.ADDED, diff.REMOVED)]

    def fill(self):
        self.shown = self.shown_changes()
        self.table.setRowCount(len(self.shown))
        for row, change in enumerate(self.shown):
            for column, text in enumerate((change.change, change.what, change.name, change.detail)):
                item = QTableWidgetItem(text)
                if column == 0:
                    item.setForeground(QColor(COLORS[CHANGE_COLORS.get(change.change, "text")]))
                self.table.setItem(row, column, item)

    def on_double_click(self, item):
        change = self.shown[item.row()]
        if change.device or change.mac:
            self.show_change.emit(change)


class DeletedDevicesDialog(QDialog):
    """The devices the crawl found that were deleted from the map, to pick some to bring back."""

    def __init__(self, deleted, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Deleted Devices")
        self.resize(520, 360)
        layout = QVBoxLayout(self)
        label = QLabel("Mapping again leaves these off the map, and doesn't crawl through them. Select the ones to "
                       "bring back: they're on the map again after the next crawl that reaches them.")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.keys = sorted(deleted, key=lambda key: deleted[key][0].lower())
        self.table = QTableWidget(len(self.keys), 2)
        self.table.setHorizontalHeaderLabels(["Device", "Addresses"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.table)
        for row, key in enumerate(self.keys):
            name, addresses = deleted[key]
            self.table.setItem(row, 0, QTableWidgetItem(name))
            self.table.setItem(row, 1, QTableWidgetItem(", ".join(addresses)))
        layout.addWidget(self.table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.bring_back_button = buttons.addButton("Bring Back", QDialogButtonBox.AcceptRole)
        self.bring_back_button.setEnabled(False)
        self.table.itemSelectionChanged.connect(lambda: self.bring_back_button.setEnabled(bool(self.chosen())))
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def chosen(self):
        return [self.keys[row] for row in sorted({index.row() for index in self.table.selectionModel().selectedRows()})]


class HostDialog(QDialog):
    """Add a host by hand (one that's off or unplugged while mapping), or edit one."""

    def __init__(self, network_map, host=None, device=None, port="", parent=None):
        super().__init__(parent)
        self.network_map, self.host = network_map, host
        self.setWindowTitle("Edit Host" if host else "Add Host")
        self.resize(420, 0)
        layout = QVBoxLayout(self)
        if host is None:
            note = QLabel("For a device that's turned off or unplugged: it's kept on the map, marked as added by "
                          "hand, and carried over when you map again.")
            note.setWordWrap(True)
            layout.addWidget(note)
        form = QFormLayout()
        self.device_combo = QComboBox()
        for item in sorted(network_map.devices.values(), key=lambda item: item.label.lower()):
            self.device_combo.addItem(item.label, item.key)
        chosen = host.device if host else device
        if chosen:
            self.device_combo.setCurrentIndex(max(0, self.device_combo.findData(chosen)))
        self.port_combo = QComboBox()
        self.port_combo.setEditable(True)
        self.device_combo.currentIndexChanged.connect(self.fill_ports)
        self.fill_ports()
        self.port_combo.setEditText(host.port if host else port)
        self.name_input = QLineEdit(host.name if host else "")
        self.ip_input = QLineEdit(host.ip if host else "")
        self.mac_input = QLineEdit(host.mac if host else "")
        self.mac_input.setPlaceholderText("Such as 00-1A-2B-3C-4D-5E")
        self.vlan_input = QSpinBox()
        self.vlan_input.setRange(0, 4094)
        self.vlan_input.setSpecialValueText("None")
        self.vlan_input.setValue(host.vlan if host else 0)
        self.note_input = QLineEdit(host.note if host else "")
        form.addRow("Switch:", self.device_combo)
        form.addRow("Port:", self.port_combo)
        form.addRow("Name:", self.name_input)
        form.addRow("IP address:", self.ip_input)
        form.addRow("MAC address:", self.mac_input)
        form.addRow("VLAN:", self.vlan_input)
        form.addRow("Note:", self.note_input)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def fill_ports(self):
        fill_ports(self.port_combo, self.network_map, self.device_combo.currentData())

    def values(self):
        """The host as entered. Raises ValueError for anything that isn't valid."""
        key = self.device_combo.currentData()
        if not key:
            raise ValueError("Choose the switch it's plugged into.")
        port = short_port(self.port_combo.currentText().strip())
        if not port:
            raise ValueError("Enter the port it's plugged into, such as Gi1/0/12.")
        name, ip, mac_text = (self.name_input.text().strip(), self.ip_input.text().strip(),
                              self.mac_input.text().strip())
        if not (name or ip or mac_text):
            raise ValueError("Enter at least a name, an IP address or a MAC address.")
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                raise ValueError(f"'{ip}' isn't an IP address.") from None
        mac = format_mac(mac_text)
        if mac_text and not mac:
            raise ValueError(f"'{mac_text}' isn't a MAC address.")
        for other in self.network_map.hosts:
            if other is not self.host and mac and other.mac == mac:
                device = self.network_map.devices.get(other.device)
                raise ValueError(f"{mac} is already on the map, on {device.label if device else other.device} "
                                 f"{other.port}.")
        host = Host(mac=mac, device=key, port=port, ip=ip, vendor=vendor(mac) if mac else "",
                    vlan=self.vlan_input.value(), name=name, note=self.note_input.text().strip(),
                    manual=self.host.manual if self.host else True)
        if self.host is not None:
            host.platform = self.host.platform
        return host

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            QMessageBox.warning(self, self.windowTitle(), str(error))
            return
        super().accept()


def fill_ports(combo, network_map, key):
    """Offer the ports a device is known to have (its links and the ports hosts are on), keeping what's typed."""
    text = combo.currentText()
    ports = {link.port_on(key) for link in network_map.links_of(key)} if key else set()
    ports |= set(network_map.hosts_by_port(key)) if key else set()
    combo.clear()
    combo.addItems(sorted((port for port in ports if port), key=port_sort_key))
    combo.setEditText(text)


def device_combo(network_map, chosen="", blank="", leave_out=""):
    """A list of the map's devices by name, with an entry for none at the top when blank names it."""
    combo = QComboBox()
    if blank:
        combo.addItem(blank, "")
    for item in sorted(network_map.devices.values(), key=lambda item: item.label.lower()):
        if item.key != leave_out:
            combo.addItem(item.label, item.key)
    if chosen:
        combo.setCurrentIndex(max(0, combo.findData(chosen)))
    return combo


def port_combo(network_map, key, text=""):
    combo = QComboBox()
    combo.setEditable(True)
    fill_ports(combo, network_map, key)
    combo.setEditText(text)
    combo.lineEdit().setPlaceholderText("Such as Gi1/0/24 (optional)")
    return combo


def shown_value(attribute, value):
    """How a value the crawl found reads: a kind's name, or "nothing"."""
    if attribute == "kind":
        return KIND_NAMES.get(value, value)
    return value or "nothing"


class DeviceDialog(QDialog):
    """Add a device by hand (an unmanaged switch, or one the crawl can't reach), or edit one: one added by hand, or
    correct one the crawl found (an address CDP didn't give or got wrong, the wrong kind). Adding, it can be linked to
    a device already on the map."""

    def __init__(self, network_map, device=None, linked_to="", parent=None, address="", name="", title=""):
        """address, name: filled in for a new device (one added from another page); title: the window's, for one
        not added on the map page."""
        super().__init__(parent)
        self.network_map, self.device = network_map, device
        self.setWindowTitle(title or ("Edit Device" if device else "Add Device"))
        self.resize(440, 0)
        layout = QVBoxLayout(self)
        if device is None:
            note = QLabel("For a device the crawl didn't find: an unmanaged switch, or one SNMP can't reach. It's "
                          "marked as added by hand and kept when you map again. With an address, it's checked over "
                          "SNMP with the map's community strings, and pinged while monitoring, like the others.")
            note.setWordWrap(True)
            layout.addWidget(note)
        elif not device.manual:
            text = ("Found by the crawl. What you correct here is kept when you map again, over what the crawl "
                    "finds. With an address, the crawl asks it there over SNMP, and monitoring pings it there.")
            if device.corrected:
                text += "\n\nCorrected so far: " + "; ".join(
                    f"{CORRECTED_NAMES[attribute].lower()} (the crawl found {shown_value(attribute, found)})"
                    for attribute, (found, _) in device.corrected.items())
            note = QLabel(text)
            note.setWordWrap(True)
            layout.addWidget(note)
        form = QFormLayout()
        self.name_input = QLineEdit(device.name if device else name)
        self.name_input.setPlaceholderText("Such as closet-sw3")
        self.ip_input = QLineEdit(device.mgmt_ip if device else address)
        self.ip_input.setPlaceholderText("To ping and check over SNMP (optional)")
        self.kind_combo = QComboBox()
        for kind in (SWITCH, ROUTER, FIREWALL, AP, SERVER, UNKNOWN):
            self.kind_combo.addItem(KIND_NAMES[kind], kind)
        if device is not None and self.kind_combo.findData(device.kind) < 0:  # Kept as it is unless changed
            self.kind_combo.addItem(KIND_NAMES.get(device.kind, device.kind), device.kind)
        self.kind_combo.setCurrentIndex(max(0, self.kind_combo.findData(device.kind if device else SWITCH)))
        self.platform_input = QLineEdit(device.platform if device else "")
        self.platform_input.setPlaceholderText("Such as Netgear GS108 (optional)")
        self.note_input = QLineEdit(device.note if device else "")
        form.addRow("Name:", self.name_input)
        form.addRow("IP address:", self.ip_input)
        form.addRow("Kind:", self.kind_combo)
        form.addRow("Model:", self.platform_input)
        form.addRow("Note:", self.note_input)
        self.link_combo = self.there_port = self.here_port = None
        if device is None and network_map.devices:
            self.link_combo = device_combo(network_map, linked_to, blank="(Not linked to anything yet)")
            self.there_port = port_combo(network_map, linked_to)
            self.here_port = port_combo(network_map, "")
            self.link_combo.currentIndexChanged.connect(self.on_link_changed)
            form.addRow("Linked to:", self.link_combo)
            form.addRow("Its port:", self.there_port)
            form.addRow("This device's port:", self.here_port)
            self.on_link_changed()
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def on_link_changed(self):
        key = self.link_combo.currentData()
        fill_ports(self.there_port, self.network_map, key)
        self.there_port.setEnabled(bool(key))
        self.here_port.setEnabled(bool(key))

    def values(self):
        """(Device, Link or None) as entered: the device keeps its key when edited, and has none ("") when new; the
        link's end on it has that key too. Raises ValueError for anything that isn't valid."""
        name, ip = self.name_input.text().strip(), self.ip_input.text().strip()
        if not (name or ip):
            raise ValueError("Enter a name or an IP address for it.")
        if ip:
            try:
                ip = str(ipaddress.ip_address(ip))
            except ValueError:
                raise ValueError(f"'{ip}' isn't an IP address.") from None
        for other in self.network_map.devices.values():
            if self.device is not None and other.key == self.device.key:
                continue
            if ip and other.owns(ip):
                raise ValueError(f"{ip} is already on the map: it's {other.label}'s.")
            if name and normalize_name(other.name) == normalize_name(name):
                raise ValueError(f"There's already a device called {other.label} on the map.")
        key = self.device.key if self.device else ""
        old = self.device
        if old is not None and not old.manual:  # Found by the crawl: corrected, not replaced
            device = replace(old, addresses=list(old.addresses), corrected=dict(old.corrected))
            entered = {"name": name, "mgmt_ip": ip, "kind": self.kind_combo.currentData(),
                       "platform": self.platform_input.text().strip(), "note": self.note_input.text().strip()}
            for attribute, value in entered.items():
                if value != getattr(old, attribute):
                    device.correct(attribute, value)
            return device, None
        device = Device(key=key, name=name, mgmt_ip=ip, kind=self.kind_combo.currentData(),
                        platform=self.platform_input.text().strip(), note=self.note_input.text().strip(),
                        manual=True, source=UNCHECKED)
        if old is not None and old.mgmt_ip == ip:  # Same address: what was found asking it still holds
            device.source, device.error = old.source, old.error
            device.sys_descr, device.sys_object_id = old.sys_descr, old.sys_object_id
        link = None
        there = self.link_combo.currentData() if self.link_combo is not None else ""
        if there:
            link = Link(there, short_port(self.there_port.currentText().strip()), key,
                        short_port(self.here_port.currentText().strip()), manual=True)
        return device, link

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            QMessageBox.warning(self, self.windowTitle(), str(error))
            return
        super().accept()


class MapChoiceDialog(QDialog):
    """Add Device to Map, from an address on another page: which map it goes on (the one open on the Network Map
    page, a saved one, a tribe map, a new one or another file), and whether to go and see it there afterwards."""

    def __init__(self, address, choices, parent=None):
        """choices: [(text, kind, value)], the first chosen to start with."""
        super().__init__(parent)
        self.setWindowTitle("Add Device to Map")
        self.resize(420, 0)
        layout = QVBoxLayout(self)
        note = QLabel(f"Add {address} to a network map as a device added by hand. Next you can name it, say what "
                      "kind it is and link it to a device already on that map.")
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.map_combo = QComboBox()
        for text, kind, value in choices:
            self.map_combo.addItem(text, (kind, value))
        form.addRow("Map:", self.map_combo)
        layout.addLayout(form)
        self.show_check = QCheckBox("Show it on the Network Map page afterwards")
        layout.addWidget(self.show_check)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def choice(self):
        """(kind, value) of the map chosen."""
        return self.map_combo.currentData()


class LinkDialog(QDialog):
    """Draw a link by hand between two devices (one the crawl couldn't see: a port with CDP and LLDP off, or to an
    unmanaged switch), or change the ports of one drawn by hand."""

    def __init__(self, network_map, a="", b="", link=None, parent=None):
        super().__init__(parent)
        self.network_map, self.link = network_map, link
        self.setWindowTitle("Edit Link" if link else "Add Link")
        self.resize(440, 0)
        layout = QVBoxLayout(self)
        if link is None:
            note = QLabel("A link the crawl couldn't see. It's drawn dotted, kept when you map again, and dropped "
                          "once the crawl finds a link between the two devices. The ports are optional.")
            note.setWordWrap(True)
            layout.addWidget(note)
        if link is not None:
            a, b = link.a, link.b
        form = QFormLayout()
        self.a_combo = device_combo(network_map, a)
        self.a_port = port_combo(network_map, a, link.a_port if link else "")
        self.b_combo = device_combo(network_map, b)
        self.b_port = port_combo(network_map, b, link.b_port if link else "")
        self.a_combo.currentIndexChanged.connect(lambda _: fill_ports(self.a_port, network_map,
                                                                      self.a_combo.currentData()))
        self.b_combo.currentIndexChanged.connect(lambda _: fill_ports(self.b_port, network_map,
                                                                      self.b_combo.currentData()))
        form.addRow("From:", self.a_combo)
        form.addRow("Its port:", self.a_port)
        form.addRow("To:", self.b_combo)
        form.addRow("Its port:", self.b_port)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def values(self):
        """The Link as entered. Raises ValueError for anything that isn't valid."""
        a, b = self.a_combo.currentData(), self.b_combo.currentData()
        if not a or not b:
            raise ValueError("Choose the devices at both ends.")
        if a == b:
            raise ValueError("Choose two different devices.")
        link = Link(a, short_port(self.a_port.currentText().strip()), b, short_port(self.b_port.currentText().strip()),
                    manual=True)
        for other in self.network_map.links:
            if other is not self.link and other.key == link.key:
                raise ValueError("That link is already on the map.")
        return link

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            QMessageBox.warning(self, self.windowTitle(), str(error))
            return
        super().accept()


class GroupDialog(QDialog):
    """New site, building or room for the devices selected, or renaming one."""

    def __init__(self, network_map, group=None, count=0, inside="", parent=None):
        super().__init__(parent)
        self.network_map, self.group = network_map, group
        self.setWindowTitle(f"Rename {GROUP_KINDS[group.kind]}" if group else "New Group")
        self.resize(380, 0)
        layout = QVBoxLayout(self)
        if group is None:
            note = QLabel(f"Put the {count} device{'' if count == 1 else 's'} selected in a new site, building or "
                          "room. It's drawn as a box round them; drag devices into or out of the box to change "
                          "what's in it.")
            note.setWordWrap(True)
            layout.addWidget(note)
        form = QFormLayout()
        self.name_input = QLineEdit(group.name if group else "")
        self.name_input.setPlaceholderText("Such as Head Office, Building 2 or Room 114")
        form.addRow("Name:", self.name_input)
        self.kind_radios = {kind: QRadioButton(name) for kind, name in GROUP_KINDS.items()}
        self.inside_label = QLabel()
        self.inside_combo = QComboBox()
        if group is None:
            kinds = QHBoxLayout()
            for radio in self.kind_radios.values():
                kinds.addWidget(radio)
                radio.toggled.connect(lambda on: on and self.fill_inside())
            kinds.addStretch(1)
            form.addRow("Kind:", kinds)
            form.addRow(self.inside_label, self.inside_combo)
            outer = network_map.group(inside)
            kind = next((kind for kind, parent_kind in PARENT_KIND.items()
                         if outer is not None and parent_kind == outer.kind), SITE)
            self.kind_radios[kind].setChecked(True)
            self.fill_inside()
            self.inside_combo.setCurrentIndex(max(0, self.inside_combo.findData(inside)))
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def kind(self):
        return next((kind for kind, radio in self.kind_radios.items() if radio.isChecked()), SITE)

    def fill_inside(self):
        """The groups the chosen kind can go in: sites for a building, buildings for a room."""
        parent_kind = PARENT_KIND.get(self.kind())
        self.inside_combo.clear()
        self.inside_label.setText(f"In {GROUP_KINDS[parent_kind].lower()}:" if parent_kind else "In:")
        if parent_kind:
            self.inside_combo.addItem(f"(Not in a {GROUP_KINDS[parent_kind].lower()})", "")
            for item in sorted((item for item in self.network_map.groups if item.kind == parent_kind),
                               key=lambda item: self.network_map.group_label(item).lower()):
                self.inside_combo.addItem(self.network_map.group_label(item), item.key)
        self.inside_combo.setEnabled(bool(parent_kind))

    def values(self):
        """(name, kind, key of the group it's in). Raises ValueError for a name that's missing or taken."""
        name = self.name_input.text().strip()
        if not name:
            raise ValueError("Enter a name for it.")
        if self.group is not None:
            kind, inside = self.group.kind, self.group.parent
        else:
            kind = self.kind()
            inside = (self.inside_combo.currentData() or "") if kind in PARENT_KIND else ""
        for other in self.network_map.groups:
            if other is not self.group and other.parent == inside and other.name.lower() == name.lower():
                where = f" in {self.network_map.group(inside).name}" if inside else ""
                raise ValueError(f"There's already a group called {other.name}{where}.")
        return name, kind, inside

    def accept(self):
        try:
            self.values()
        except ValueError as error:
            QMessageBox.warning(self, self.windowTitle(), str(error))
            return
        super().accept()
