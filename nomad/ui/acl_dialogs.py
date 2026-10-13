"""Dialogs of the ACLs page: a rule, an address picked from IPAM or the map, a new ACL, where to apply one, which
devices, and text to read."""
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QApplication, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, \
    QGridLayout, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QPlainTextEdit, QPushButton, \
    QRadioButton, QToolButton, QVBoxLayout

from ..netmap import acl
from ..netmap.acl import DENY, EXTENDED, ICMP_NAMES, ICMPV6_NAMES, INTERFACE, LINE, PERMIT, STANDARD, V4, V6, Ports, \
    Rule, numbered_kind, parse_address_text, port_number, protocol_number
from .common import set_hint
from .theme import COLORS, monospace_font

PROTOCOL_CHOICES = ["tcp", "udp", "icmp", "gre", "esp", "ahp", "ospf", "eigrp", "pim", "igmp", "sctp"]
PORT_OPS = [("any port", ""), ("eq", "eq"), ("not", "neq"), ("below", "lt"), ("above", "gt"), ("range", "range")]
LOG_CHOICES = [("No logging", ""), ("log", "log"), ("log-input", "log-input")]


def port_values(op, text, protocol):
    """Ports(op, numbers) from what's typed (numbers or names). Raises ValueError."""
    if not op:
        return Ports()
    words = text.replace(",", " ").replace("-", " ").split() if op == "range" else text.replace(",", " ").split()
    values = []
    for word in words:
        number = port_number(word, protocol)
        if number is None:
            raise ValueError(f"{word} isn't a port number or a name IOS knows.")
        values.append(number)
    wanted = {"range": 2, "lt": 1, "gt": 1}.get(op)
    if wanted and len(values) != wanted:
        raise ValueError("A range takes two ports (1000 2000)." if op == "range" else "Give one port.")
    if not values:
        raise ValueError("Give at least one port.")
    if op in ("eq", "neq") and len(values) > 10:
        raise ValueError("IOS takes at most 10 ports in one rule.")
    return Ports(op, values)


class AddressPicker(QDialog):
    """Addresses to choose from: IPAM subnets and addresses, the map's devices, object groups."""

    def __init__(self, parent, choices):
        super().__init__(parent)
        self.setWindowTitle("Pick an Address")
        self.resize(560, 520)
        layout = QVBoxLayout(self)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find a subnet, address, device or group")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.textChanged.connect(self.filter)
        layout.addWidget(self.find_input)
        self.list = QListWidget()
        for section, label, text in choices:  # (section, what's shown, what goes in the box)
            item = QListWidgetItem(f"{label}    [{section}]")
            item.setData(Qt.UserRole, text)
            item.setToolTip(text)
            self.list.addItem(item)
        if not choices:
            item = QListWidgetItem("Nothing to pick from: open a map, or an IP Addresses network.")
            item.setFlags(Qt.NoItemFlags)
            self.list.addItem(item)
        self.list.itemDoubleClicked.connect(self.accept)
        layout.addWidget(self.list, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.find_input.setFocus()

    def filter(self, text):
        words = text.lower().split()
        for row in range(self.list.count()):
            item = self.list.item(row)
            item.setHidden(not all(word in item.text().lower() for word in words))

    def chosen(self):
        item = self.list.currentItem()
        return item.data(Qt.UserRole) if item is not None and not item.isHidden() else ""


class AddressField(QHBoxLayout):
    """An address box with a Pick... button."""

    def __init__(self, dialog, choices):
        super().__init__()
        self.dialog, self.choices = dialog, choices
        self.input = QLineEdit()
        self.input.setPlaceholderText("any, 10.1.1.5, 10.1.0.0/16, 10.1.0.0 0.0.255.255, object-group NAME")
        self.addWidget(self.input, 1)
        self.button = QToolButton()
        self.button.setText("Pick...")
        self.button.setToolTip("From IP Addresses (subnets and addresses), the map's devices, or an object group")
        self.button.clicked.connect(self.pick)
        self.addWidget(self.button)

    def pick(self):
        picker = AddressPicker(self.dialog, self.choices() if callable(self.choices) else self.choices)
        if picker.exec_() == QDialog.Accepted and picker.chosen():
            self.input.setText(picker.chosen())


class PortsField(QHBoxLayout):
    def __init__(self):
        super().__init__()
        self.op = QComboBox()
        for label, op in PORT_OPS:
            self.op.addItem(label, op)
        self.addWidget(self.op)
        self.input = QLineEdit()
        self.input.setPlaceholderText("80 443, www, 1000 2000")
        self.addWidget(self.input, 1)
        self.op.currentIndexChanged.connect(self.on_op)
        self.on_op()

    def on_op(self, *_):
        self.input.setEnabled(bool(self.op.currentData()))

    def set(self, ports, protocol):
        self.op.setCurrentIndex(max(0, self.op.findData(ports.op)))
        self.input.setText(" ".join(acl.port_name(value, protocol) if protocol in ("tcp", "udp") else str(value)
                                    for value in ports.values))

    def get(self, protocol):
        return port_values(self.op.currentData(), self.input.text(), protocol)

    def set_enabled(self, enabled):
        self.op.setEnabled(enabled)
        self.input.setEnabled(enabled and bool(self.op.currentData()))


class RuleDialog(QDialog):
    """One rule of an ACL: what it matches and whether it's permitted, shown as IOS will have it."""

    def __init__(self, parent, the_acl, rule=None, groups=None, ranges=None, choices=(), number=""):
        super().__init__(parent)
        self.acl = the_acl
        self.rule = rule.copy() if rule is not None else Rule(protocol="ipv6" if the_acl.family == V6 else "ip")
        self.groups, self.ranges = groups or {}, ranges or {}
        self.standard = the_acl.kind == STANDARD
        self.setWindowTitle(("Edit Rule" if rule is not None else "Add Rule") + f" - {the_acl.title}")
        self.resize(720, 0)
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        row = 0
        self.number_input = QLineEdit(str(number) if number else "")
        self.number_input.setPlaceholderText("Automatic: a free one between the rules around it")
        self.number_input.setToolTip("Its sequence number, which is also its place: the ACL goes in number order")
        grid.addWidget(QLabel("Number:"), row, 0)
        grid.addWidget(self.number_input, row, 1)
        row += 1
        self.action_combo = QComboBox()
        self.action_combo.addItems([PERMIT, DENY])
        grid.addWidget(QLabel("Action:"), row, 0)
        grid.addWidget(self.action_combo, row, 1)
        row += 1
        self.protocol_combo = QComboBox()
        self.protocol_combo.setEditable(True)
        self.protocol_combo.addItem("ipv6" if the_acl.family == V6 else "ip")
        self.protocol_combo.addItems(PROTOCOL_CHOICES)
        for group in self.groups.values():
            if group.kind == acl.SERVICE and (group.family == V6) == (the_acl.family == V6):
                self.protocol_combo.addItem(f"object-group {group.name}")
        self.protocol_combo.setToolTip("A protocol (a name or number 0-255), or a service object group (which "
                                       "names protocols and ports itself)")
        if not self.standard:
            grid.addWidget(QLabel("Protocol:"), row, 0)
            grid.addWidget(self.protocol_combo, row, 1)
            row += 1
        self.src = AddressField(self, choices)
        grid.addWidget(QLabel("Source:"), row, 0)
        grid.addLayout(self.src, row, 1)
        row += 1
        self.src_ports = PortsField()
        self.dst = AddressField(self, choices)
        self.dst_ports = PortsField()
        self.icmp_combo = QComboBox()
        self.icmp_combo.setEditable(True)
        self.icmp_combo.addItem("")
        self.icmp_combo.addItems(sorted(ICMPV6_NAMES if the_acl.family == V6 else ICMP_NAMES))
        self.icmp_combo.setToolTip("An ICMP message by name, or its type (and code) as numbers: 3 13")
        self.established_check = QCheckBox("Established (replies to connections from the other side: ACK or RST "
                                           "set)")
        self.fragments_check = QCheckBox("Fragments (non-initial fragments only)")
        self.range_combo = QComboBox()
        self.range_combo.addItem("Always", "")
        for name in sorted(self.ranges):
            self.range_combo.addItem(f"time-range {name}", name)
        self.extra_input = QLineEdit()
        self.extra_input.setPlaceholderText("dscp ef, precedence 5, ttl eq 1, match-any +syn +rst ...")
        if not self.standard:
            grid.addWidget(QLabel("Source ports:"), row, 0)
            grid.addLayout(self.src_ports, row, 1)
            row += 1
            grid.addWidget(QLabel("Destination:"), row, 0)
            grid.addLayout(self.dst, row, 1)
            row += 1
            grid.addWidget(QLabel("Destination ports:"), row, 0)
            grid.addLayout(self.dst_ports, row, 1)
            row += 1
            grid.addWidget(QLabel("ICMP message:"), row, 0)
            grid.addWidget(self.icmp_combo, row, 1)
            row += 1
            grid.addWidget(self.established_check, row, 1)
            row += 1
            grid.addWidget(self.fragments_check, row, 1)
            row += 1
            grid.addWidget(QLabel("Active:"), row, 0)
            grid.addWidget(self.range_combo, row, 1)
            row += 1
            grid.addWidget(QLabel("More:"), row, 0)
            grid.addWidget(self.extra_input, row, 1)
            row += 1
        self.log_combo = QComboBox()
        for label, value in LOG_CHOICES:
            if value == "log-input" and self.standard:
                continue
            self.log_combo.addItem(label, value)
        grid.addWidget(QLabel("Logging:"), row, 0)
        grid.addWidget(self.log_combo, row, 1)
        row += 1
        self.remark_input = QPlainTextEdit()
        self.remark_input.setPlaceholderText("Why it's there (a remark line above it; one per line)")
        self.remark_input.setFixedHeight(56)
        grid.addWidget(QLabel("Remark:"), row, 0)
        grid.addWidget(self.remark_input, row, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        self.preview = QLabel()
        self.preview.setFont(monospace_font())
        self.preview.setWordWrap(True)
        self.preview.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.preview)
        self.problem_label = QLabel()
        self.problem_label.setWordWrap(True)
        layout.addWidget(self.problem_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.fill()
        for widget in (self.action_combo, self.protocol_combo, self.icmp_combo, self.range_combo, self.log_combo,
                       self.src_ports.op, self.dst_ports.op):
            widget.currentIndexChanged.connect(self.update_preview)
        self.protocol_combo.editTextChanged.connect(self.update_preview)
        self.icmp_combo.editTextChanged.connect(self.update_preview)
        for edit in (self.src.input, self.dst.input, self.src_ports.input, self.dst_ports.input, self.extra_input,
                     self.number_input):
            edit.textChanged.connect(self.update_preview)
        for check in (self.established_check, self.fragments_check):
            check.toggled.connect(self.update_preview)
        self.remark_input.textChanged.connect(self.update_preview)
        self.update_preview()

    def fill(self):
        rule = self.rule
        self.action_combo.setCurrentText(rule.action)
        self.protocol_combo.setCurrentText(f"object-group {rule.service_group}" if rule.service_group
                                           else rule.protocol)
        self.src.input.setText("" if rule.src.kind == acl.ANY else rule.src.short())
        self.dst.input.setText("" if rule.dst.kind == acl.ANY else rule.dst.short())
        self.src_ports.set(rule.src_ports, rule.protocol)
        self.dst_ports.set(rule.dst_ports, rule.protocol)
        if rule.icmp_name:
            self.icmp_combo.setCurrentText(rule.icmp_name)
        elif rule.icmp_type is not None:
            self.icmp_combo.setCurrentText(f"{rule.icmp_type}" + (f" {rule.icmp_code}" if rule.icmp_code is not None
                                                                   else ""))
        self.established_check.setChecked(rule.established)
        self.fragments_check.setChecked(rule.fragments)
        index = self.range_combo.findData(rule.time_range)
        if index < 0 and rule.time_range:
            self.range_combo.addItem(f"time-range {rule.time_range} (not on the device)", rule.time_range)
            index = self.range_combo.count() - 1
        self.range_combo.setCurrentIndex(max(0, index))
        self.extra_input.setText(" ".join(rule.tcp_flags + rule.extra))
        self.log_combo.setCurrentIndex(max(0, self.log_combo.findData(rule.log)))
        self.remark_input.setPlainText(rule.remark)

    def build(self):
        """The Rule as filled in. Raises ValueError."""
        family = self.acl.family
        number = self.number_input.text().strip()
        if number and (not number.isdigit() or not 1 <= int(number) <= acl.MAX_SEQ):
            raise ValueError(f"The number is 1 to {acl.MAX_SEQ}, or nothing for an automatic one.")
        rule = self.rule.copy()
        rule.action = self.action_combo.currentText()
        rule.src = parse_address_text(self.src.input.text(), family)
        rule.log = self.log_combo.currentData()
        rule.remark = "\n".join(line.strip() for line in self.remark_input.toPlainText().splitlines() if line.strip())
        if self.standard:
            if rule.src.kind == acl.GROUP:
                raise ValueError("A standard ACL can't name an object group.")
            return rule
        protocol = self.protocol_combo.currentText().strip().lower()
        if protocol.startswith("object-group "):
            rule.protocol, rule.service_group = "", protocol.split(None, 1)[1].strip()
        else:
            if protocol_number(protocol) is None:
                raise ValueError(f"{protocol or 'Nothing'} isn't a protocol IOS knows (a name, or a number 0-255).")
            if family == V6 and protocol == "ip":
                protocol = "ipv6"
            if family == V4 and protocol == "ipv6":
                raise ValueError("ipv6 is for IPv6 ACLs: ip means any protocol here.")
            rule.protocol, rule.service_group = protocol, ""
        rule.dst = parse_address_text(self.dst.input.text(), family)
        ported = protocol in ("tcp", "udp")
        rule.src_ports = self.src_ports.get(protocol) if ported else Ports()
        rule.dst_ports = self.dst_ports.get(protocol) if ported else Ports()
        icmp = self.icmp_combo.currentText().strip() if protocol == "icmp" else ""
        names = ICMPV6_NAMES if family == V6 else ICMP_NAMES
        rule.icmp_name, rule.icmp_type, rule.icmp_code = "", None, None
        if icmp:
            if icmp in names:
                rule.icmp_name = icmp
                rule.icmp_type, rule.icmp_code = names[icmp]
            else:
                words = icmp.split()
                if not all(word.isdigit() and int(word) <= 255 for word in words) or len(words) > 2:
                    raise ValueError(f"{icmp} isn't an ICMP message name or type (and code) number.")
                rule.icmp_type = int(words[0])
                rule.icmp_code = int(words[1]) if len(words) > 1 else None
        rule.established = self.established_check.isChecked() and protocol == "tcp"
        rule.fragments = self.fragments_check.isChecked()
        rule.time_range = self.range_combo.currentData() or ""
        parsed = acl.parse_rule(f"permit ip any any {self.extra_input.text()}", family, EXTENDED)
        rule.tcp_flags, rule.extra = (parsed.tcp_flags, parsed.extra) if parsed is not None else ([], [])
        if self.extra_input.text().strip() and (parsed.log or parsed.time_range or parsed.established or
                                                parsed.fragments):
            raise ValueError("Use the boxes above for logging, time ranges, established and fragments.")
        if rule.tcp_flags and protocol != "tcp":
            raise ValueError("TCP flags only go with tcp.")
        return rule

    def update_preview(self, *_):
        protocol = self.protocol_combo.currentText().strip().lower()
        ported = protocol in ("tcp", "udp")
        self.src_ports.set_enabled(ported)
        self.dst_ports.set_enabled(ported)
        self.icmp_combo.setEnabled(protocol == "icmp")
        self.established_check.setEnabled(protocol == "tcp")
        try:
            rule = self.build()
        except ValueError as error:
            self.preview.setText("")
            set_hint(self.problem_label, str(error), "error")
            self.buttons.button(QDialogButtonBox.Ok).setEnabled(False)
            return
        remark = "".join(f"remark {line}\n" for line in rule.remark.splitlines())
        number = self.number_input.text().strip()
        self.preview.setText(remark + (f"{number} " if number else "") + rule.body(self.acl.family, self.acl.kind))
        notes = []
        for side, address in (("source", rule.src), ("destination", rule.dst)):
            if address.kind == acl.WILDCARD and acl.stored_address(address) != address.address:
                notes.append(f"The {side} has bits set under the wildcard: IOS keeps it as "
                             f"{acl.stored_address(address)} {address.wildcard}.")
            if address.kind == acl.GROUP and address.group not in self.groups:
                notes.append(f"Object group {address.group} isn't on the device (yet).")
        typed = (self.src.input.text() + " " + self.dst.input.text()).split()
        if any(acl.looks_like_mask(word) for word in typed if acl.is_ipv4(word)):
            notes.append("A subnet mask was typed: it's been turned into its wildcard.")
        set_hint(self.problem_label, " ".join(notes), "warning" if notes else "info")
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(True)

    def accept(self):
        try:
            self.rule = self.build()
        except ValueError as error:
            set_hint(self.problem_label, str(error), "error")
            return
        super().accept()


class NewAclDialog(QDialog):
    """A new ACL's name and kind, and what it starts with."""

    def __init__(self, parent, existing, starts=()):
        super().__init__(parent)
        self.existing = set(existing)  # (family, name)
        self.setWindowTitle("New ACL")
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("WEB-IN, or a number: 1-99 standard, 100-199 extended")
        grid.addWidget(QLabel("Name:"), 0, 0)
        grid.addWidget(self.name_input, 0, 1)
        self.v4_radio, self.v6_radio = QRadioButton("IPv4"), QRadioButton("IPv6")
        self.v4_radio.setChecked(True)
        family = QHBoxLayout()
        family.addWidget(self.v4_radio)
        family.addWidget(self.v6_radio)
        family.addStretch(1)
        self.family_group = QButtonGroup(self)
        self.family_group.addButton(self.v4_radio)
        self.family_group.addButton(self.v6_radio)
        grid.addWidget(QLabel("Family:"), 1, 0)
        grid.addLayout(family, 1, 1)
        self.kind_combo = QComboBox()
        self.kind_combo.addItem("Extended (protocol, source, destination, ports)", EXTENDED)
        self.kind_combo.addItem("Standard (source address only)", STANDARD)
        grid.addWidget(QLabel("Kind:"), 2, 0)
        grid.addWidget(self.kind_combo, 2, 1)
        self.start_combo = QComboBox()
        self.start_combo.addItem("No rules", None)
        for label, item in starts:
            self.start_combo.addItem(label, item)
        grid.addWidget(QLabel("Start with:"), 3, 0)
        grid.addWidget(self.start_combo, 3, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        self.problem_label = QLabel()
        self.problem_label.setWordWrap(True)
        layout.addWidget(self.problem_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.name_input.textChanged.connect(self.check)
        self.v6_radio.toggled.connect(self.check)
        self.kind_combo.currentIndexChanged.connect(self.check)
        self.check()

    @property
    def family(self):
        return V6 if self.v6_radio.isChecked() else V4

    @property
    def kind(self):
        return EXTENDED if self.family == V6 else self.kind_combo.currentData()

    def problem(self):
        name = self.name_input.text().strip()
        if not name:
            return "Give it a name."
        if any(char.isspace() for char in name) or "?" in name:
            return "A name can't have spaces or a question mark."
        if (self.family, name) in self.existing:
            return f"The device has {name} already."
        if name.isdigit():
            if self.family == V6:
                return "An IPv6 ACL needs a name, not a number."
            kind = numbered_kind(name)
            if not kind:
                return "IPv4 ACL numbers are 1-99 and 1300-1999 (standard), 100-199 and 2000-2699 (extended)."
            if kind != self.kind:
                return f"{name} is a {kind} ACL's number."
        start = self.start_combo.currentData()
        if start is not None and (start.family != self.family or (self.family == V4 and start.kind != self.kind)):
            return f"{start.title} is {'IPv6' if start.family == V6 else start.kind}: make the new one the same."
        return ""

    def check(self, *_):
        self.kind_combo.setEnabled(self.family == V4)
        problem = self.problem()
        set_hint(self.problem_label, problem, "error" if problem else "info")
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(not problem)

    def made(self):
        """The new Acl (its rules not on the device: seq 0)."""
        start = self.start_combo.currentData()
        rules = [rule.copy(seq=0, hits=None, want_seq=0) for rule in start.rules] if start is not None else []
        return acl.Acl(self.name_input.text().strip(), self.family, self.kind, rules)


class ApplyDialog(QDialog):
    """Where to put an ACL: an interface or lines, which way."""

    def __init__(self, parent, device, the_acl):
        super().__init__(parent)
        self.device, self.acl = device, the_acl
        self.setWindowTitle(f"Apply {the_acl.name}")
        self.resize(560, 0)
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.interface_radio = QRadioButton("Interface:")
        self.line_radio = QRadioButton("Lines:")
        self.interface_radio.setChecked(True)
        self.interface_combo = QComboBox()
        for name, interface in device.interfaces.items():
            parts = [f"{address}/{length}" for address, length in interface.addresses + interface.addresses6]
            if interface.description:
                parts.append(interface.description)
            if interface.shutdown:
                parts.append("shut down")
            self.interface_combo.addItem(name + (f"  ({', '.join(parts)})" if parts else ""), name)
        self.line_combo = QComboBox()
        for name in device.lines:
            self.line_combo.addItem(f"line {name}", name)
        if not device.lines:
            self.line_combo.addItem("line vty 0 4", "vty 0 4")
        self.direction_combo = QComboBox()
        self.direction_combo.addItem("In (packets coming in)", acl.IN)
        self.direction_combo.addItem("Out (packets going out)", acl.OUT)
        grid.addWidget(self.interface_radio, 0, 0)
        grid.addWidget(self.interface_combo, 0, 1)
        grid.addWidget(self.line_radio, 1, 0)
        grid.addWidget(self.line_combo, 1, 1)
        grid.addWidget(QLabel("Direction:"), 2, 0)
        grid.addWidget(self.direction_combo, 2, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        self.now_label = QLabel()
        self.now_label.setWordWrap(True)
        layout.addWidget(self.now_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        if not device.interfaces:  # None read (a device without them, or a Scratch Pad copy): lines only
            self.interface_radio.setEnabled(False)
            self.interface_combo.addItem("No interfaces read")
            self.line_radio.setChecked(True)
        for widget in (self.interface_combo, self.line_combo, self.direction_combo):
            widget.currentIndexChanged.connect(self.update_now)
        self.interface_radio.toggled.connect(self.update_now)
        self.update_now()

    @property
    def where(self):
        return INTERFACE if self.interface_radio.isChecked() else LINE

    @property
    def target(self):
        combo = self.interface_combo if self.where == INTERFACE else self.line_combo
        return combo.currentData() or ""

    @property
    def direction(self):
        return self.direction_combo.currentData()

    def update_now(self, *_):
        self.interface_combo.setEnabled(self.where == INTERFACE)
        self.line_combo.setEnabled(self.where == LINE)
        current = next((item for item in self.device.applied if item.where == self.where and
                        item.target == self.target and item.direction == self.direction and
                        item.family == self.acl.family), None)
        if current is None:
            set_hint(self.now_label, "Nothing is applied there that way now.", "info")
        elif current.acl == self.acl.name:
            set_hint(self.now_label, f"{self.acl.name} is applied there already.", "warning")
        else:
            set_hint(self.now_label, f"{current.acl} is applied there now: {self.acl.name} takes its place.",
                     "warning")


class DevicePicker(QDialog):
    """Devices to tick."""

    def __init__(self, parent, title, devices, text=""):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(480, 480)
        layout = QVBoxLayout(self)
        if text:
            label = QLabel(text)
            label.setWordWrap(True)
            layout.addWidget(label)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find a device")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.textChanged.connect(self.filter)
        layout.addWidget(self.find_input)
        self.list = QListWidget()
        for key, label in devices:
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, key)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            self.list.addItem(item)
        layout.addWidget(self.list, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def filter(self, text):
        for row in range(self.list.count()):
            item = self.list.item(row)
            item.setHidden(text.lower() not in item.text().lower())

    def chosen(self):
        return [self.list.item(row).data(Qt.UserRole) for row in range(self.list.count())
                if self.list.item(row).checkState() == Qt.Checked]


class TextDialog(QDialog):
    """Text to read and copy (lines sent, a comparison)."""

    def __init__(self, parent, title, text, colored=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(760, 520)
        layout = QVBoxLayout(self)
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setFont(monospace_font())
        self.view.setPlainText(text)
        layout.addWidget(self.view, 1)
        row = QHBoxLayout()
        copy = QPushButton("Copy")
        copy.clicked.connect(self.copy)
        row.addWidget(copy)
        row.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        row.addWidget(close)
        layout.addLayout(row)

    def copy(self):
        QApplication.clipboard().setText(self.view.toPlainText())


class ImportDialog(QDialog):
    """ACL configuration pasted in (ip access-list ..., access-list N ..., object-group, time-range)."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Import ACLs from Text")
        self.resize(720, 520)
        layout = QVBoxLayout(self)
        label = QLabel("Paste ACLs as a running-config shows them (ip access-list ..., ipv6 access-list ..., "
                       "access-list 101 ...), with any object-group and time-range they need:")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.text = QPlainTextEdit()
        self.text.setFont(monospace_font())
        self.text.textChanged.connect(self.check)
        layout.addWidget(self.text, 1)
        self.found_label = QLabel()
        self.found_label.setWordWrap(True)
        layout.addWidget(self.found_label)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.check()

    def device(self):
        return acl.parse_running(self.text.toPlainText())

    def check(self):
        found = self.device()
        names = [item.title for item in found.acls.values()]
        if names:
            set_hint(self.found_label, f"Found {len(names)}: {', '.join(names)}.", "success")
        else:
            set_hint(self.found_label, "No ACLs found yet.", "info")
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(bool(names))


def severity_color(severity):
    return QColor(COLORS.get({"error": "error", "warning": "warning"}.get(severity, "muted")))

