"""SNMP Config page: build the Cisco IOS / IOS-XE configuration that sets a switch up for NOMAD (SNMP read access,
traps and syslog to the computers watching, CDP and LLDP, link-status logging on the access ports), then copy it,
save it, or have NOMAD type it into a terminal session to the switch."""
import json
import logging
import secrets

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, \
    QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, \
    QPlainTextEdit, QPushButton, QScrollArea, QSplitter, QToolButton, QVBoxLayout, QWidget

from ..snmpv3 import AUTH_NAMES, PRIV_NAMES, V3User, credential_from_json, credential_label, credential_to_json, \
    is_v3
from ..switchconfig import SYSLOG_LEVELS, TRAP_CATEGORIES, ConfigOptions, build, problems, undo
from ..terminal.credentials import CredentialError, protect, unprotect
from .common import set_hint
from .session_send import SessionSender
from .theme import accent_button, monospace_font

log = logging.getLogger(__name__)

FORM_ROOM = 1.2  # The form starts this much wider than it needs at least, so nothing in it is cramped
MIN_PREVIEW = 380  # The preview keeps at least this many pixels when the form gets its room
SECRET_SETTINGS = "snmpconfig/secrets"
WELL_KNOWN = {"public", "private"}  # Community strings everyone tries: not chosen for the switches unless asked


def split_items(text):
    return [item for item in text.replace(",", " ").split() if item]


def default_choice(entries):
    """Which of the map's credentials ([(credential, subnet or "")]) go on the switches unless chosen otherwise: those
    tried everywhere, leaving out public and private when there's anything else."""
    chosen = [credential for credential, subnet in entries if not subnet]
    others = [credential for credential in chosen if is_v3(credential) or credential not in WELL_KNOWN]
    return others or chosen


class MapCredentialsDialog(QDialog):
    """Which of the Network Map's community strings and SNMPv3 users the switches are set up with."""

    def __init__(self, entries, chosen, parent=None):
        """entries: [(credential, the subnet it's for or "")]; chosen: those ticked to begin with."""
        super().__init__(parent)
        self.setWindowTitle("Use the Map's Credentials")
        self.resize(460, 360)
        layout = QVBoxLayout(self)
        intro = QLabel("Set the switches up with these of the Network Map's credentials, so it can read them. Traps "
                       "are sent with the first community string or SNMPv3 user.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.list = QListWidget()
        for credential, subnet in entries:
            text = f"Community {credential}" if not is_v3(credential) else credential_label(credential)
            item = QListWidgetItem(text + (f"  (for {subnet})" if subnet else ""))
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if credential in chosen else Qt.Unchecked)
            item.setData(Qt.UserRole, credential)
            self.list.addItem(item)
        layout.addWidget(self.list, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def chosen(self):
        items = [self.list.item(row) for row in range(self.list.count())]
        return list(dict.fromkeys(item.data(Qt.UserRole) for item in items if item.checkState() == Qt.Checked))

    def accept(self):
        if not self.chosen():
            QMessageBox.warning(self, self.windowTitle(), "Choose at least one community string or SNMPv3 user.")
            return
        super().accept()


class SnmpConfigTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.lines = []
        self.more_credentials = []  # More of the map's community strings and SNMPv3 users allowed to read
        self.init_ui()
        self.session_sender = SessionSender(self, window, self.status_label)
        self.update_preview()

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Builds the Cisco IOS / IOS-XE configuration that lets NOMAD read a switch and has it tell "
                       "the computers watching the map when something is plugged in. Send it to a switch from a "
                       "terminal session at the enable (#) prompt, or copy it.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        splitter = QSplitter()
        self.splitter = splitter
        self.sized = False  # The form's starting width is set when the page is first shown
        layout.addWidget(splitter, 1)

        form_widget = QWidget()
        form_layout = QVBoxLayout(form_widget)
        form_layout.addWidget(self.make_access_group())
        form_layout.addWidget(self.make_destinations_group())
        form_layout.addWidget(self.make_traps_group())
        form_layout.addWidget(self.make_syslog_group())
        form_layout.addWidget(self.make_other_group())
        form_layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(form_widget)
        scroll.setMinimumWidth(form_widget.sizeHint().width() + scroll.verticalScrollBar().sizeHint().width() + 4)
        self.form_scroll = scroll
        splitter.addWidget(scroll)

        preview = QWidget()
        preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        show_row = QHBoxLayout()
        show_row.addWidget(QLabel("Show:"))
        self.show_combo = QComboBox()
        self.show_combo.addItem("Configuration to add", "add")
        self.show_combo.addItem("Commands to take it out again", "undo")
        show_row.addWidget(self.show_combo)
        show_row.addStretch(1)
        preview_layout.addLayout(show_row)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        self.preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        preview_layout.addWidget(self.preview, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        preview_layout.addWidget(self.status_label)
        buttons = QHBoxLayout()
        self.send_button = QToolButton()
        self.send_button.setText("Send to Session")
        self.send_button.setPopupMode(QToolButton.InstantPopup)
        self.send_menu = QMenu(self.send_button)
        self.send_menu.aboutToShow.connect(self.fill_send_menu)
        self.send_button.setMenu(self.send_menu)
        self.send_button.setToolTip("Type the configuration into a terminal session to the switch, a line at a time.")
        self.copy_button = QPushButton("Copy")
        self.save_button = QPushButton("Save As...")
        self.add_button = QPushButton("Add to Network Map")
        self.add_button.setToolTip("Add the community string and SNMPv3 user to the ones the Network Map tries.")
        buttons.addWidget(self.send_button)
        buttons.addWidget(self.copy_button)
        buttons.addWidget(self.save_button)
        buttons.addStretch(1)
        buttons.addWidget(self.add_button)
        preview_layout.addLayout(buttons)
        check = QLabel("Check it on the switch with show snmp community, show snmp user, show snmp host and "
                       "show logging.")
        check.setWordWrap(True)
        check.setEnabled(False)
        preview_layout.addWidget(check)
        splitter.addWidget(preview)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.show_combo.currentIndexChanged.connect(lambda _: self.update_preview())
        self.copy_button.clicked.connect(self.copy)
        self.save_button.clicked.connect(self.save_as)
        self.add_button.clicked.connect(self.add_to_map)
        for widget in self.findChildren(QLineEdit):
            widget.textChanged.connect(lambda _: self.update_preview())
        for widget in self.findChildren(QCheckBox):
            widget.toggled.connect(lambda _: self.update_preview())
        for widget in self.findChildren(QGroupBox):
            widget.toggled.connect(lambda _: self.update_preview())
        for widget in self.findChildren(QComboBox):
            if widget is not self.show_combo:
                widget.currentIndexChanged.connect(lambda _: self.update_preview())

    def make_access_group(self):
        group = QGroupBox("Read access for NOMAD")
        group.setCheckable(True)
        self.access_group = group
        form = QFormLayout(group)
        self.use_map_button = QPushButton("Use the Map's Credentials...")
        self.use_map_button.setToolTip("Set the switches up with the community strings and SNMPv3 users saved for the "
                                       "open Network Map, so it can read them.")
        self.use_map_button.clicked.connect(self.choose_map_credentials)
        map_row = QHBoxLayout()
        map_row.addWidget(self.use_map_button)
        map_row.addStretch(1)
        form.addRow(map_row)
        self.community_check = QCheckBox("Community string (v2c, read-only):")
        self.community_input = QLineEdit()
        self.community_input.setPlaceholderText("Not public: make one up, or Generate")
        generate = QPushButton("Generate")
        generate.clicked.connect(lambda: self.community_input.setText(secrets.token_urlsafe(12)))
        self.map_community_button, self.map_community_menu = self.map_button(
            "Use a community string the Network Map tries.", self.fill_map_community_menu)
        row = QHBoxLayout()
        row.addWidget(self.community_input, 1)
        row.addWidget(self.map_community_button)
        row.addWidget(generate)
        form.addRow(self.community_check, row)

        self.v3_check = QCheckBox("SNMPv3 user:")
        self.user_input = QLineEdit("nomad")
        self.auth_combo, self.priv_combo = QComboBox(), QComboBox()
        for key, label in AUTH_NAMES.items():
            if key != "sha224":  # IOS doesn't offer it
                self.auth_combo.addItem(label, key)
        for key, label in PRIV_NAMES.items():
            self.priv_combo.addItem(label, key)
        self.auth_combo.setCurrentIndex(self.auth_combo.findData("sha"))
        self.priv_combo.setCurrentIndex(self.priv_combo.findData("aes128"))
        self.auth_password_input, self.priv_password_input = QLineEdit(), QLineEdit()
        for widget, text in ((self.auth_password_input, "Authentication password"),
                             (self.priv_password_input, "Privacy password")):
            widget.setEchoMode(QLineEdit.Password)
            widget.setPlaceholderText(text)
        self.show_passwords = QCheckBox("Show")
        self.show_passwords.toggled.connect(self.update_echo)
        generate_passwords = QPushButton("Generate")
        generate_passwords.clicked.connect(self.generate_passwords)
        user_row, protocol_row, password_row = QHBoxLayout(), QHBoxLayout(), QHBoxLayout()
        self.map_user_button, self.map_user_menu = self.map_button(
            "Use an SNMPv3 user the Network Map tries, with its protocols and passwords.", self.fill_map_user_menu)
        user_row.addWidget(self.user_input, 1)
        user_row.addWidget(self.map_user_button)
        protocol_row.addWidget(QLabel("Authentication:"))
        protocol_row.addWidget(self.auth_combo)
        protocol_row.addWidget(QLabel("Privacy:"))
        protocol_row.addWidget(self.priv_combo)
        protocol_row.addStretch(1)
        for widget in (self.auth_password_input, self.priv_password_input):
            password_row.addWidget(widget, 1)
        password_row.addWidget(self.show_passwords)
        password_row.addWidget(generate_passwords)
        form.addRow(self.v3_check, user_row)
        form.addRow("", protocol_row)
        form.addRow("", password_row)

        self.more_widget = QWidget()  # The rest of the map's credentials chosen, when there are more
        more_row = QHBoxLayout(self.more_widget)
        more_row.setContentsMargins(0, 0, 0, 0)
        self.more_label = QLabel()
        self.more_label.setWordWrap(True)
        clear_more = QPushButton("Leave Out")
        clear_more.setToolTip("Only the community string and SNMPv3 user above.")
        clear_more.clicked.connect(self.clear_more)
        more_row.addWidget(self.more_label, 1)
        more_row.addWidget(clear_more)
        form.addRow(self.more_widget)
        self.more_widget.setVisible(False)

        self.permit_input = QLineEdit()
        self.permit_input.setPlaceholderText("Addresses and subnets, such as 10.0.0.50 10.20.0.0/24")
        self.permit_same = QCheckBox("Same as where traps and syslog go")
        self.permit_same.setChecked(True)
        self.permit_same.toggled.connect(lambda on: self.permit_input.setEnabled(not on))
        self.permit_input.setEnabled(False)
        form.addRow("Allowed to read:", self.permit_input)
        form.addRow("", self.permit_same)
        names = QHBoxLayout()
        self.acl_input, self.group_input, self.view_input = QLineEdit("NOMAD-SNMP"), QLineEdit("NOMAD"), \
            QLineEdit("NOMAD-VIEW")
        for label, widget in (("Access list", self.acl_input), ("v3 group", self.group_input),
                              ("v3 view", self.view_input)):
            names.addWidget(QLabel(label + ":"))
            names.addWidget(widget, 1)
        form.addRow("Names:", names)
        self.location_input, self.contact_input = QLineEdit(), QLineEdit()
        self.location_input.setPlaceholderText("Such as HQ, building 2, IDF 3")
        form.addRow("Location:", self.location_input)
        form.addRow("Contact:", self.contact_input)
        self.ifindex_check = QCheckBox("Keep interface numbers across reloads (snmp-server ifindex persist)")
        self.ifindex_check.setChecked(True)
        form.addRow("", self.ifindex_check)
        self.community_check.setChecked(True)
        self.auth_combo.currentIndexChanged.connect(lambda _: self.update_enabled())
        self.priv_combo.currentIndexChanged.connect(lambda _: self.update_enabled())
        self.community_check.toggled.connect(lambda _: self.update_enabled())
        self.v3_check.toggled.connect(lambda _: self.update_enabled())
        self.update_enabled()
        return group

    def map_button(self, tip, fill):
        """A From the Map button whose menu fill() fills as it opens."""
        button = QToolButton()
        button.setText("From the Map")
        button.setToolTip(tip)
        button.setPopupMode(QToolButton.InstantPopup)
        menu = QMenu(button)
        menu.aboutToShow.connect(fill)
        button.setMenu(menu)
        return button, menu

    def make_destinations_group(self):
        group = QGroupBox("Where traps and syslog go")
        form = QFormLayout(group)
        row = QHBoxLayout()
        self.destinations_input = QLineEdit()
        self.destinations_input.setPlaceholderText("This computer, and the Map Watcher's if one runs")
        self.this_computer_button = QToolButton()
        self.this_computer_button.setText("Add This Computer")
        self.this_computer_button.setPopupMode(QToolButton.InstantPopup)
        self.this_computer_menu = QMenu(self.this_computer_button)
        self.this_computer_menu.aboutToShow.connect(self.fill_address_menu)
        self.this_computer_button.setMenu(self.this_computer_menu)
        row.addWidget(self.destinations_input, 1)
        row.addWidget(self.this_computer_button)
        form.addRow("Send to:", row)
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("Recommended: the management VLAN or loopback, such as Vlan10")
        self.source_input.setToolTip("The interface whose address traps and syslog come from. Without it the switch "
                                     "uses whichever interface faces this computer, which may not be the address "
                                     "NOMAD reads it at, so the watcher may not recognize it.")
        form.addRow("From interface:", self.source_input)
        return group

    def make_traps_group(self):
        group = QGroupBox("SNMP traps")
        group.setCheckable(True)
        self.traps_group = group
        layout = QVBoxLayout(group)
        row = QHBoxLayout()
        row.addWidget(QLabel("Send as:"))
        self.trap_version_combo = QComboBox()
        self.trap_version_combo.addItem("v2c, with the community string", "v2c")
        self.trap_version_combo.addItem("SNMPv3, as the user", "v3")
        row.addWidget(self.trap_version_combo)
        row.addStretch(1)
        layout.addLayout(row)
        self.trap_checks = {}
        for key, (_, text, used) in TRAP_CATEGORIES.items():
            check = QCheckBox(text + (" (the Map Watcher acts on these)" if used else " (logged only)"))
            check.setChecked(used)
            self.trap_checks[key] = check
            layout.addWidget(check)
        return group

    def make_syslog_group(self):
        group = QGroupBox("Syslog")
        group.setCheckable(True)
        self.syslog_group = group
        form = QFormLayout(group)
        self.level_combo = QComboBox()
        for key, text in SYSLOG_LEVELS.items():
            self.level_combo.addItem(text, key)
        form.addRow("Level:", self.level_combo)
        self.timestamps_check = QCheckBox("Timestamps in local time with milliseconds")
        form.addRow("", self.timestamps_check)
        return group

    def make_other_group(self):
        group = QGroupBox("Neighbors, access ports and saving")
        form = QFormLayout(group)
        self.cdp_check = QCheckBox("CDP")
        self.lldp_check = QCheckBox("LLDP (access points, phones and other makers' devices)")
        self.cdp_check.setChecked(True)
        self.lldp_check.setChecked(True)
        neighbors = QHBoxLayout()
        neighbors.addWidget(self.cdp_check)
        neighbors.addWidget(self.lldp_check)
        neighbors.addStretch(1)
        form.addRow("Turn on:", neighbors)
        self.ports_input = QLineEdit()
        self.ports_input.setPlaceholderText("Such as Gi1/0/1 - 48, Gi2/0/1 - 48 (leave empty to skip)")
        self.ports_input.setToolTip("Turns link-status logging and MAC address notifications on for these ports, "
                                    "so the switch says when something is plugged in. Configurations often turn "
                                    "link-status logging off on access ports.")
        form.addRow("Access ports:", self.ports_input)
        self.poe_check = QCheckBox("Log PoE power changes on them (PoE switches only: others refuse it)")
        self.poe_check.setChecked(True)
        form.addRow("", self.poe_check)
        self.write_check = QCheckBox("Save it (write memory)")
        form.addRow("", self.write_check)
        return group

    # ----------------------------------------------------------------- The form

    def update_enabled(self):
        community = self.community_check.isChecked()
        v3 = self.v3_check.isChecked()
        self.community_input.setEnabled(community)
        auth = self.auth_combo.currentData() != "none"
        for widget in (self.user_input, self.auth_combo, self.show_passwords):
            widget.setEnabled(v3)
        self.auth_password_input.setEnabled(v3 and auth)
        self.priv_combo.setEnabled(v3 and auth)
        self.priv_password_input.setEnabled(v3 and auth and self.priv_combo.currentData() != "none")
        for widget in (self.group_input, self.view_input):
            widget.setEnabled(v3)
        self.update_more()

    def update_more(self):
        """Show the rest of the map's credentials chosen, those that go on the switches with the boxes ticked."""
        used = [item for item in self.more_credentials
                if (self.v3_check.isChecked() if is_v3(item) else self.community_check.isChecked())]
        names = [credential_label(item) if is_v3(item) else f"community {item}" for item in used]
        self.more_label.setText("Also from the map: " + ", ".join(names) + ".")
        self.more_widget.setVisible(bool(used))

    def clear_more(self):
        self.more_credentials = []
        self.update_more()
        self.update_preview()

    def update_echo(self, show):
        for widget in (self.auth_password_input, self.priv_password_input):
            widget.setEchoMode(QLineEdit.Normal if show else QLineEdit.Password)

    def generate_passwords(self):
        self.auth_password_input.setText(secrets.token_urlsafe(15))
        self.priv_password_input.setText(secrets.token_urlsafe(15))
        self.show_passwords.setChecked(True)

    def v3_user(self):
        if not self.v3_check.isChecked():
            return None
        auth = self.auth_combo.currentData()
        priv = self.priv_combo.currentData() if auth != "none" else "none"
        return V3User(self.user_input.text().strip(), auth,
                      self.auth_password_input.text() if auth != "none" else "", priv,
                      self.priv_password_input.text() if priv != "none" else "")

    def set_v3_user(self, user):
        self.v3_check.setChecked(True)
        self.user_input.setText(user.user)
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(user.auth)))
        self.priv_combo.setCurrentIndex(max(0, self.priv_combo.findData(user.priv)))
        self.auth_password_input.setText(user.auth_password)
        self.priv_password_input.setText(user.priv_password)

    def options(self):
        destinations = split_items(self.destinations_input.text())
        return ConfigOptions(
            access=self.access_group.isChecked(),
            community=self.community_input.text().strip() if self.community_check.isChecked() else "",
            v3_user=self.v3_user(),
            more_communities=[item for item in self.more_credentials if not is_v3(item)]
            if self.community_check.isChecked() else [],
            more_users=[item for item in self.more_credentials if is_v3(item)] if self.v3_check.isChecked() else [],
            group=self.group_input.text().strip(), view=self.view_input.text().strip(),
            acl=self.acl_input.text().strip(),
            permit=destinations if self.permit_same.isChecked() else split_items(self.permit_input.text()),
            location=self.location_input.text().strip(), contact=self.contact_input.text().strip(),
            ifindex_persist=self.ifindex_check.isChecked(), destinations=destinations,
            traps=self.traps_group.isChecked(), trap_version=self.trap_version_combo.currentData(),
            trap_categories=[key for key, check in self.trap_checks.items() if check.isChecked()],
            syslog=self.syslog_group.isChecked(), syslog_level=self.level_combo.currentData(),
            timestamps=self.timestamps_check.isChecked(), source_interface=self.source_input.text().strip(),
            cdp=self.cdp_check.isChecked(), lldp=self.lldp_check.isChecked(),
            access_ports=self.ports_input.text().strip(), poe=self.poe_check.isChecked(),
            write_memory=self.write_check.isChecked())

    def update_preview(self):
        options = self.options()
        found = problems(options)
        if found:
            self.lines = []
            self.preview.setPlainText("")
            set_hint(self.status_label, " ".join(found[:3]) + (" ..." if len(found) > 3 else ""), "warning")
        else:
            self.lines = build(options) if self.show_combo.currentData() == "add" else undo(options)
            self.preview.setPlainText("\n".join(self.lines))
            set_hint(self.status_label, f"{len(self.lines)} lines, from the enable (#) prompt.", "info")
        has_lines = bool(self.lines)
        for widget in (self.send_button, self.copy_button, self.save_button):
            widget.setEnabled(has_lines)
        self.add_button.setEnabled(not found and (bool(options.community) or options.v3_user is not None))

    def fill_address_menu(self):
        self.this_computer_menu.clear()
        addresses = self.local_addresses()
        for address in addresses:
            self.this_computer_menu.addAction(address, lambda address=address: self.add_destination(address))
        if not addresses:
            self.this_computer_menu.addAction("No IPv4 address on this computer").setEnabled(False)

    def local_addresses(self):
        found = []
        snapshot = getattr(self.window, "snapshot", None)
        adapters = snapshot.real_adapters() if snapshot is not None and hasattr(snapshot, "real_adapters") else []
        current = self.window.current_adapter() if hasattr(self.window, "current_adapter") else None
        for adapter in ([current] if current is not None else []) + list(adapters):
            for address in getattr(adapter, "ipv4", []) or []:
                ip = getattr(address, "ip", address)
                if not ip.is_link_local and not ip.is_loopback and str(ip) not in found:
                    found.append(str(ip))
        return found

    def add_destination(self, address):
        items = split_items(self.destinations_input.text())
        if address not in items:
            self.destinations_input.setText(" ".join(items + [address]))

    # ----------------------------------------------------------------- The map's credentials

    def showEvent(self, event):
        super().showEvent(event)
        if not self.sized:
            QTimer.singleShot(0, self.size_form)  # Once the splitter has its width

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if not self.sized and self.isVisible():
            QTimer.singleShot(0, self.size_form)

    def size_form(self):
        """Give the form FORM_ROOM times the width it needs, leaving the preview at least MIN_PREVIEW."""
        total = sum(self.splitter.sizes())
        if self.sized or total <= 0:
            return
        self.sized = True
        form = int(self.form_scroll.minimumWidth() * FORM_ROOM)
        form = max(self.form_scroll.minimumWidth(), min(form, total - MIN_PREVIEW))
        self.splitter.setSizes([form, total - form])

    def map_credentials(self):
        """The community strings and SNMPv3 users the Network Map tries, those for particular subnets too."""
        page = getattr(self.window, "netmap_tab", None)
        if page is None or not hasattr(page, "credentials"):
            return []
        return list(dict.fromkeys(page.credentials() + [item for _, item in getattr(page, "overrides", [])]))

    def fill_map_community_menu(self):
        menu = self.map_community_menu
        menu.clear()
        for community in [item for item in self.map_credentials() if not is_v3(item)]:
            menu.addAction(community, lambda community=community: self.use_credential(community))
        if menu.isEmpty():
            menu.addAction("The Network Map has no community strings").setEnabled(False)

    def fill_map_user_menu(self):
        menu = self.map_user_menu
        menu.clear()
        for user in [item for item in self.map_credentials() if is_v3(item)]:
            menu.addAction(user.label, lambda user=user: self.use_credential(user))
        if menu.isEmpty():
            menu.addAction("The Network Map has no SNMPv3 users (add them with SNMP Credentials... on its page)") \
                .setEnabled(False)

    def use_credential(self, credential):
        if is_v3(credential):
            self.set_v3_user(credential)
        else:
            self.community_check.setChecked(True)
            self.community_input.setText(credential)

    def map_credential_entries(self):
        """The map's credentials as [(credential, the subnet it's for or "")]: those tried everywhere, in the order
        they're tried, then those for particular subnets."""
        page = getattr(self.window, "netmap_tab", None)
        if page is None or not hasattr(page, "credentials"):
            return []
        entries = [(credential, "") for credential in dict.fromkeys(page.credentials())]
        for subnet, credential in getattr(page, "overrides", []):
            if all(credential != other for other, _ in entries):
                entries.append((credential, subnet))
        return entries

    def chosen_credentials(self):
        """The community strings and SNMPv3 users the switches are set up with now, those traps go with first."""
        options = self.options()
        primary = ([options.community] if options.community else []) + \
            ([options.v3_user] if options.v3_user is not None else [])
        return list(dict.fromkeys(primary + options.more_communities + options.more_users))

    def choose_map_credentials(self):
        entries = self.map_credential_entries()
        if not entries:
            QMessageBox.information(self, "Use the Map's Credentials", "The Network Map has no SNMP credentials yet: "
                                    "add them with SNMP Credentials... on its page.")
            return
        current = [credential for credential in self.chosen_credentials()
                   if any(credential == other for other, _ in entries)]
        dialog = MapCredentialsDialog(entries, current or default_choice(entries), self)
        if dialog.exec_() == QDialog.Accepted:
            self.use_map_credentials(dialog.chosen())

    def use_map_credentials(self, chosen):
        """Set the switches up with chosen (community strings and V3Users): traps go with the first of each."""
        communities = [item for item in chosen if not is_v3(item)]
        users = [item for item in chosen if is_v3(item)]
        self.community_check.setChecked(bool(communities))
        if communities:
            self.community_input.setText(communities[0])
        if users:
            self.set_v3_user(users[0])
        else:
            self.v3_check.setChecked(False)
        self.more_credentials = communities[1:] + users[1:]
        trap_version = self.trap_version_combo.currentData()
        if trap_version == "v2c" and not communities or trap_version == "v3" and not users:
            self.trap_version_combo.setCurrentIndex(self.trap_version_combo.findData("v3" if users else "v2c"))
        self.update_enabled()
        self.update_preview()

    def prefill(self, destination="", credential=None, from_map=False):
        """From the Network Map: send to this computer, with the map's credential, or (from_map) with the map's
        credentials as default_choice picks them."""
        if destination:
            self.add_destination(destination)
        if from_map:
            chosen = default_choice(self.map_credential_entries())
            if chosen:
                self.use_map_credentials(chosen)
        elif credential is not None:
            self.use_credential(credential)
            if is_v3(credential):
                self.trap_version_combo.setCurrentIndex(self.trap_version_combo.findData("v3"))

    def add_to_map(self):
        page = getattr(self.window, "netmap_tab", None)
        options = self.options()
        if page is None or problems(options):
            return
        added = [credential for credential in (options.community or None, options.v3_user)
                 if credential is not None and page.add_credential(credential)]
        if added:
            names = " and ".join(credential.label if is_v3(credential) else f"community {credential}"
                                 for credential in added)
            set_hint(self.status_label, f"The Network Map now tries {names} first.", "success")
        else:
            set_hint(self.status_label, "The Network Map already tries these.", "info")

    # ----------------------------------------------------------------- Copy, save and send

    def text(self):
        return "\n".join(self.lines) + "\n"

    def copy(self):
        QApplication.clipboard().setText(self.text())
        set_hint(self.status_label, "Copied. Paste it at the switch's enable (#) prompt.", "success")

    def save_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "nomad-snmp-config.txt",
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(self.text())
        except OSError as error:
            QMessageBox.critical(self, "Save Configuration", f"Couldn't save it:\n\n{error}")
            return
        set_hint(self.status_label, f"Saved to {path}. It has the passwords in it: keep it safe.", "success")

    def fill_send_menu(self):
        self.session_sender.fill_menu(self.send_menu, self.text)

    def send_to(self, view):
        """Type the lines into view's session, after asking. Returns whether they're being sent."""
        return bool(self.lines) and self.session_sender.send_to(view, self.text())

    def open_new_session(self):
        self.session_sender.open_new_session(self.text)

    def open_saved(self, session):
        self.session_sender.open_saved(session, self.text)

    @property
    def waiting(self):
        return self.session_sender.waiting

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        # Leave configuration choices alone; Space on the toggle enables the field when needed.
        target = (self.community_input if self.community_input.isEnabled() else
                  self.community_check if self.community_check.isEnabled() else self.access_group)
        self.form_scroll.ensureWidgetVisible(target)
        target.setFocus()
        if target is self.community_input:
            target.selectAll()

    def save_settings(self, settings):
        options = self.options()
        settings.setValue("snmpconfig/form", json.dumps({
            "access": options.access, "use_community": self.community_check.isChecked(),
            "use_v3": self.v3_check.isChecked(), "user": self.user_input.text(),
            "auth": self.auth_combo.currentData(), "priv": self.priv_combo.currentData(),
            "permit_same": self.permit_same.isChecked(), "permit": self.permit_input.text(),
            "acl": options.acl, "group": options.group, "view": options.view, "location": options.location,
            "contact": options.contact, "ifindex": options.ifindex_persist,
            "destinations": self.destinations_input.text(), "source": self.source_input.text(),
            "traps": options.traps, "trap_version": options.trap_version, "trap_categories": options.trap_categories,
            "syslog": options.syslog, "level": options.syslog_level, "timestamps": options.timestamps,
            "cdp": options.cdp, "lldp": options.lldp, "ports": self.ports_input.text(), "poe": options.poe,
            "write": options.write_memory}))
        try:
            settings.setValue(SECRET_SETTINGS, protect(json.dumps({
                "community": self.community_input.text(), "auth_password": self.auth_password_input.text(),
                "priv_password": self.priv_password_input.text(),
                "more": [credential_to_json(item) for item in self.more_credentials]})))
        except CredentialError as error:
            log.warning("Couldn't save the SNMP Config page's passwords: %s", error)

    def restore_settings(self, settings):
        try:
            form = json.loads(settings.value("snmpconfig/form", "", str) or "{}")
        except ValueError:
            form = {}
        stored = settings.value(SECRET_SETTINGS, "", str)
        saved = {}
        if stored:
            try:
                saved = json.loads(unprotect(stored))
            except (CredentialError, ValueError) as error:
                log.warning("Couldn't read the SNMP Config page's saved passwords: %s", error)
        self.access_group.setChecked(form.get("access", True))
        self.community_check.setChecked(form.get("use_community", True))
        self.community_input.setText(saved.get("community", ""))
        self.v3_check.setChecked(form.get("use_v3", False))
        self.user_input.setText(form.get("user", "nomad"))
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(form.get("auth", "sha"))))
        self.priv_combo.setCurrentIndex(max(0, self.priv_combo.findData(form.get("priv", "aes128"))))
        self.auth_password_input.setText(saved.get("auth_password", ""))
        self.priv_password_input.setText(saved.get("priv_password", ""))
        self.more_credentials = [credential_from_json(item) for item in saved.get("more") or []]
        self.permit_same.setChecked(form.get("permit_same", True))
        self.permit_input.setText(form.get("permit", ""))
        for key, widget, default in (("acl", self.acl_input, "NOMAD-SNMP"), ("group", self.group_input, "NOMAD"),
                                     ("view", self.view_input, "NOMAD-VIEW"), ("location", self.location_input, ""),
                                     ("contact", self.contact_input, ""),
                                     ("destinations", self.destinations_input, ""),
                                     ("source", self.source_input, ""), ("ports", self.ports_input, "")):
            widget.setText(str(form.get(key, default)))
        self.ifindex_check.setChecked(form.get("ifindex", True))
        self.traps_group.setChecked(form.get("traps", True))
        self.trap_version_combo.setCurrentIndex(max(0, self.trap_version_combo.findData(
            form.get("trap_version", "v2c"))))
        categories = form.get("trap_categories")
        for key, check in self.trap_checks.items():
            check.setChecked(key in categories if categories is not None else TRAP_CATEGORIES[key][2])
        self.syslog_group.setChecked(form.get("syslog", True))
        self.level_combo.setCurrentIndex(max(0, self.level_combo.findData(form.get("level", "notifications"))))
        self.timestamps_check.setChecked(form.get("timestamps", False))
        self.cdp_check.setChecked(form.get("cdp", True))
        self.lldp_check.setChecked(form.get("lldp", True))
        self.poe_check.setChecked(form.get("poe", True))
        self.write_check.setChecked(form.get("write", False))
        self.update_enabled()
        self.update_preview()

    def shutdown(self):
        self.session_sender.stop_waiting()
