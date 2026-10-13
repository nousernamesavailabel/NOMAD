"""Dialogs of the ACLs page's prefix lists and route maps: an entry of each, where to apply one, and a new one."""
import ipaddress

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QGridLayout, \
    QHBoxLayout, QLabel, QLineEdit, QListWidget, QPlainTextEdit, QPushButton, QRadioButton, QSpinBox, \
    QStackedWidget, QVBoxLayout, QWidget

from ..netmap import routepolicy
from ..netmap.acl import DENY, PERMIT, V4, V6
from ..netmap.routepolicy import BGP, DISTRIBUTE, IN, OUT, PBR, PREFIX_LIST, REDIST, ROUTE_MAP, MapEntry, \
    PolicyUse, PrefixEntry, PrefixList, RouteMap
from .acl_dialogs import AddressField
from .common import set_hint
from .theme import monospace_font

ROUTE_TYPES = ["internal", "external", "external type-1", "external type-2", "local", "nssa-external"]
METRIC_TYPES = ["type-1", "type-2", "internal", "external"]
ORIGINS = ["igp", "incomplete"]


def ok_button(buttons):
    return buttons.button(QDialogButtonBox.Ok)


class PrefixEntryDialog(QDialog):
    """One entry of a prefix list: the prefix, how much longer ones it takes too, permit or deny."""

    def __init__(self, parent, plist, entry=None, choices=(), number=""):
        super().__init__(parent)
        self.plist = plist
        self.entry = entry.copy() if entry is not None else PrefixEntry(prefix="::/0" if plist.family == V6
                                                                        else "0.0.0.0/0")
        self.top = 128 if plist.family == V6 else 32
        self.setWindowTitle(("Edit Entry" if entry is not None else "Add Entry") + f" - {plist.title}")
        self.resize(620, 0)
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.number_input = QLineEdit(str(number) if number else "")
        self.number_input.setPlaceholderText("Automatic: a free one between the entries around it")
        self.number_input.setToolTip("Its sequence number, which is also its place: the list goes in number order")
        grid.addWidget(QLabel("Number:"), 0, 0)
        grid.addWidget(self.number_input, 0, 1)
        self.action_combo = QComboBox()
        self.action_combo.addItems([PERMIT, DENY])
        grid.addWidget(QLabel("Action:"), 1, 0)
        grid.addWidget(self.action_combo, 1, 1)
        self.prefix = AddressField(self, [choice for choice in choices if choice[0] != "Object group"])
        self.prefix.input.setPlaceholderText("2001:db8::/32" if plist.family == V6 else "10.1.0.0/16")
        grid.addWidget(QLabel("Prefix:"), 2, 0)
        grid.addLayout(self.prefix, 2, 1)
        lengths = QHBoxLayout()
        self.ge_input = QSpinBox()
        self.le_input = QSpinBox()
        for spin in (self.ge_input, self.le_input):
            spin.setRange(0, self.top)
            spin.setSpecialValueText("-")
            spin.setPrefix("/")
        lengths.addWidget(QLabel("ge (at least)"))
        lengths.addWidget(self.ge_input)
        lengths.addWidget(QLabel("le (at most)"))
        lengths.addWidget(self.le_input)
        lengths.addStretch(1)
        grid.addWidget(QLabel("Longer ones:"), 3, 0)
        grid.addLayout(lengths, 3, 1)
        grid.setColumnStretch(1, 1)
        layout.addLayout(grid)
        self.explain_label = QLabel()
        self.explain_label.setWordWrap(True)
        layout.addWidget(self.explain_label)
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
        self.action_combo.setCurrentText(self.entry.action)
        self.prefix.input.setText(self.entry.prefix if entry is not None else "")
        self.ge_input.setValue(self.entry.ge)
        self.le_input.setValue(self.entry.le)
        self.action_combo.currentIndexChanged.connect(self.update_preview)
        for edit in (self.prefix.input, self.number_input):
            edit.textChanged.connect(self.update_preview)
        for spin in (self.ge_input, self.le_input):
            spin.valueChanged.connect(self.update_preview)
        self.update_preview()

    def build(self):
        """The PrefixEntry as filled in. Raises ValueError."""
        number = self.number_input.text().strip()
        if number and (not number.isdigit() or not 1 <= int(number) <= routepolicy.MAX_PREFIX_SEQ):
            raise ValueError(f"The number is 1 to {routepolicy.MAX_PREFIX_SEQ}, or nothing for an automatic one.")
        text = self.prefix.input.text().strip()
        if not text:
            raise ValueError("Type a prefix (or pick one).")
        if "/" not in text:  # An address: just it
            text += f"/{self.top}"
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            raise ValueError(f"{text} isn't a prefix (10.1.0.0/16).") from None
        if (network.version == 6) != (self.plist.family == V6):
            raise ValueError(f"This is an {'IPv6' if self.plist.family == V6 else 'IPv4'} prefix list.")
        entry = self.entry.copy(action=self.action_combo.currentText(), prefix=str(network),
                                ge=self.ge_input.value(), le=self.le_input.value())
        problem = routepolicy.prefix_problem(entry, self.plist.family)
        if problem:
            raise ValueError(problem)
        return entry

    def update_preview(self, *_):
        try:
            entry = self.build()
        except ValueError as error:
            self.preview.setText("")
            self.explain_label.setText("")
            set_hint(self.problem_label, str(error), "error")
            ok_button(self.buttons).setEnabled(False)
            return
        number = self.number_input.text().strip()
        self.preview.setText(self.plist.entry_line(entry, int(number) if number else 0))
        set_hint(self.explain_label, f"It {entry.action}s {entry.explain()}.", "info")
        typed = self.prefix.input.text().strip()
        note = ""
        try:
            if "/" in typed and ipaddress.ip_interface(typed).ip != entry.network.network_address:
                note = f"Host bits are set: IOS keeps it as {entry.network}."
        except ValueError:
            pass
        set_hint(self.problem_label, note, "warning" if note else "info")
        ok_button(self.buttons).setEnabled(True)

    def accept(self):
        try:
            self.entry = self.build()
        except ValueError as error:
            set_hint(self.problem_label, str(error), "error")
            return
        super().accept()


class ClauseList(QWidget):
    """A route-map entry's match (or set) lines: a list, and a keyword and value to add."""

    def __init__(self, word, choices, suggest):
        super().__init__()
        self.word, self.suggest = word, suggest
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.list = QListWidget()
        self.list.setFont(monospace_font())
        self.list.setFixedHeight(84)
        layout.addWidget(self.list)
        row = QHBoxLayout()
        self.keyword_combo = QComboBox()
        self.keyword_combo.setEditable(True)
        self.keyword_combo.addItems(choices)
        self.keyword_combo.currentTextChanged.connect(self.on_keyword)
        row.addWidget(self.keyword_combo, 2)
        self.value_combo = QComboBox()
        self.value_combo.setEditable(True)
        self.value_combo.lineEdit().returnPressed.connect(self.add)
        row.addWidget(self.value_combo, 3)
        add = QPushButton("Add")
        add.clicked.connect(self.add)
        row.addWidget(add)
        remove = QPushButton("Remove")
        remove.clicked.connect(self.remove)
        row.addWidget(remove)
        layout.addLayout(row)
        self.on_keyword(self.keyword_combo.currentText())

    def on_keyword(self, keyword):
        self.value_combo.clear()
        values, hint = self.suggest(self.word, keyword.strip())
        self.value_combo.addItems(values)
        self.value_combo.setCurrentText("")
        self.value_combo.lineEdit().setPlaceholderText(hint)

    def lines(self):
        return [self.list.item(row).text()[len(self.word) + 1:] for row in range(self.list.count())]

    def set_lines(self, lines):
        self.list.clear()
        self.list.addItems([f"{self.word} {text}" for text in lines])

    def add(self):
        keyword = " ".join(self.keyword_combo.currentText().split())
        value = " ".join(self.value_combo.currentText().split())
        if not keyword:
            return
        text = f"{keyword} {value}".strip()
        head, values = routepolicy.split_clause(text)
        lines = self.lines()
        if values is not None:  # Values of one keyword go on one line (IOS adds them up anyway)
            for at, line in enumerate(lines):
                other_head, other_values = routepolicy.split_clause(line)
                if other_head == head and other_values is not None:
                    lines[at] = " ".join([head] + other_values + [value for value in values
                                                                  if value not in other_values])
                    break
            else:
                lines.append(text)
        elif text not in lines:
            lines.append(text)
        self.set_lines([routepolicy.normal_clause(self.word, line) for line in lines])
        self.value_combo.setCurrentText("")
        self.changed()

    def remove(self):
        for item in self.list.selectedItems():
            self.list.takeItem(self.list.row(item))
        self.changed()

    def changed(self):
        dialog = self.window()
        if hasattr(dialog, "update_preview"):
            dialog.update_preview()


class MapEntryDialog(QDialog):
    """One entry of a route map: what it matches, what it sets, permit or deny, and where it goes on to."""

    def __init__(self, parent, rmap, entry=None, device=None, number="", later=()):
        super().__init__(parent)
        self.rmap, self.device = rmap, device
        self.entry = entry.copy() if entry is not None else MapEntry()
        self.setWindowTitle(("Edit Entry" if entry is not None else "Add Entry") + f" - {rmap.title}")
        self.resize(720, 0)
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.number_input = QLineEdit(str(number) if number else "")
        self.number_input.setPlaceholderText("Automatic: a free one between the entries around it")
        self.number_input.setToolTip("Its sequence number, which is also its place: a route goes through the "
                                     "entries in number order")
        grid.addWidget(QLabel("Number:"), 0, 0)
        grid.addWidget(self.number_input, 0, 1)
        self.action_combo = QComboBox()
        self.action_combo.addItem("permit (a route it matches is taken, with the set lines)", PERMIT)
        self.action_combo.addItem("deny (a route it matches is dropped)", DENY)
        grid.addWidget(QLabel("Action:"), 1, 0)
        grid.addWidget(self.action_combo, 1, 1)
        self.description_input = QPlainTextEdit()
        self.description_input.setPlaceholderText("What it's for (one description line per line)")
        self.description_input.setFixedHeight(48)
        grid.addWidget(QLabel("Description:"), 2, 0)
        grid.addWidget(self.description_input, 2, 1)
        self.matches = ClauseList("match", routepolicy.MATCH_CHOICES, self.suggest)
        grid.addWidget(QLabel("Match\n(all of them;\nvalues on a line:\nany of them):"), 3, 0, Qt.AlignTop)
        grid.addWidget(self.matches, 3, 1)
        self.sets = ClauseList("set", routepolicy.SET_CHOICES, self.suggest)
        grid.addWidget(QLabel("Set:"), 4, 0, Qt.AlignTop)
        grid.addWidget(self.sets, 4, 1)
        self.continue_combo = QComboBox()
        self.continue_combo.setEditable(True)
        self.continue_combo.addItem("No (stop at this entry)", "")
        self.continue_combo.addItem("To the next entry", "next")
        for seq in later:
            self.continue_combo.addItem(f"To entry {seq}", str(seq))
        self.continue_combo.setToolTip("continue (BGP only): after this entry's set lines, go on to another entry "
                                       "(further down) and take its set lines too if it matches")
        grid.addWidget(QLabel("Continue:"), 5, 0)
        grid.addWidget(self.continue_combo, 5, 1)
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
        self.action_combo.setCurrentIndex(max(0, self.action_combo.findData(self.entry.action)))
        self.description_input.setPlainText(self.entry.description)
        self.matches.set_lines(self.entry.matches)
        self.sets.set_lines(self.entry.sets)
        index = self.continue_combo.findData(self.entry.cont)
        if index < 0:
            self.continue_combo.addItem(f"To entry {self.entry.cont}", self.entry.cont)
            index = self.continue_combo.count() - 1
        self.continue_combo.setCurrentIndex(index)
        self.action_combo.currentIndexChanged.connect(self.update_preview)
        self.continue_combo.currentIndexChanged.connect(self.update_preview)
        self.continue_combo.editTextChanged.connect(self.update_preview)
        self.description_input.textChanged.connect(self.update_preview)
        self.number_input.textChanged.connect(self.update_preview)
        self.update_preview()

    def suggest(self, word, keyword):
        """([values to pick], a hint) for a match / set keyword."""
        device = self.device
        if device is None:
            return [], ""
        if word == "match":
            if keyword.endswith("prefix-list"):
                family = V6 if keyword.startswith("ipv6") else V4
                return sorted(name for key_family, name in device.prefix_lists if key_family == family), \
                    "a prefix list (several: any of them)"
            if keyword in ("ip address", "ipv6 address", "ip next-hop", "ip route-source"):
                family = V6 if keyword.startswith("ipv6") else V4
                return sorted(name for key_family, name in device.acls if key_family == family), \
                    "an ACL (several: any of them)"
            if keyword == "as-path":
                return sorted(device.as_paths), "an AS-path list number"
            if keyword == "community":
                return sorted(device.communities), "a community list (add exact-match for exactly these)"
            if keyword == "interface":
                return sorted(device.interfaces), "an interface"
            if keyword == "route-type":
                return ROUTE_TYPES, "internal, external type-2, local..."
            if keyword == "source-protocol":
                return ["connected", "static"] + [line[len("router "):] for line in device.processes], \
                    "connected, static, ospf 1, bgp 65000..."
            if keyword in ("tag", "local-preference"):
                return [], "a number (several: any of them)"
            if keyword == "metric":
                return [], "a number (and +- a deviation)"
            if keyword == "length":
                return [], "shortest longest (packet length, policy routing)"
            return [], ""
        hints = {"local-preference": "100-4294967295 (higher wins)", "weight": "0-65535 (higher wins, this router "
                 "only)", "metric": "a number (BGP MED; or bandwidth delay reliability load mtu for EIGRP)",
                 "as-path prepend": "65000 65000 (AS numbers put in front)", "community": "65000:100 no-export "
                 "(add additive to keep the ones there)", "comm-list": "NAME delete", "tag": "a number",
                 "ip next-hop": "an address (policy routing, or BGP)", "ipv6 next-hop": "an address",
                 "ip default next-hop": "an address (only when there's no route)", "interface": "an interface",
                 "default interface": "an interface", "ip precedence": "0-7 or a name", "ip dscp": "a DSCP value",
                 "vrf": "a VRF name"}
        if keyword == "metric-type":
            return METRIC_TYPES, "type-1 / type-2 (OSPF), internal / external (BGP)"
        if keyword == "origin":
            return ORIGINS, "igp, incomplete"
        if keyword in ("interface", "default interface"):
            return sorted(device.interfaces), hints[keyword]
        if keyword == "comm-list":
            return [f"{name} delete" for name in sorted(device.communities)], hints[keyword]
        return [], hints.get(keyword, "")

    def build(self):
        """The MapEntry as filled in. Raises ValueError."""
        number = self.number_input.text().strip()
        if number and (not number.isdigit() or not 0 <= int(number) <= routepolicy.MAX_MAP_SEQ):
            raise ValueError(f"The number is 0 to {routepolicy.MAX_MAP_SEQ}, or nothing for an automatic one.")
        text = self.continue_combo.currentText().strip()
        index = self.continue_combo.findText(text)
        cont = (self.continue_combo.itemData(index) if index >= 0 else text) or ""
        if cont.lower().startswith("to entry "):
            cont = cont[len("to entry "):].strip()
        if cont and cont != "next" and not cont.isdigit():
            raise ValueError("Continue goes to an entry's number (or the next entry).")
        description = "\n".join(line.strip() for line in self.description_input.toPlainText().splitlines()
                                if line.strip())
        return self.entry.copy(action=self.action_combo.currentData(), matches=self.matches.lines(),
                               sets=self.sets.lines(), cont=cont, description=description)

    def update_preview(self, *_):
        try:
            entry = self.build()
        except ValueError as error:
            self.preview.setText("")
            set_hint(self.problem_label, str(error), "error")
            ok_button(self.buttons).setEnabled(False)
            return
        number = self.number_input.text().strip() or "N"
        self.preview.setText("\n".join([f"route-map {self.rmap.name} {entry.action} {number}"] +
                                       [f" {line}" for line in entry.clauses()]))
        notes = []
        if not entry.matches:
            notes.append("No match lines: it matches every route.")
        if entry.action == DENY and entry.sets:
            notes.append("It denies, so the set lines do nothing.")
        heads = [routepolicy.split_clause(text)[0] for text in entry.matches]
        if any(routepolicy.CLASHING.get(head) in heads for head in heads):
            notes.append("IOS won't take an ACL and a prefix list in one entry's match ip address.")
        set_hint(self.problem_label, " ".join(notes), "warning" if notes else "info")
        ok_button(self.buttons).setEnabled(True)

    def accept(self):
        try:
            self.entry = self.build()
        except ValueError as error:
            set_hint(self.problem_label, str(error), "error")
            return
        super().accept()


class NewPolicyDialog(QDialog):
    """A new prefix list's or route map's name (and a prefix list's family), and what it starts with."""

    def __init__(self, parent, kind, existing, starts=()):
        super().__init__(parent)
        self.kind, self.existing = kind, set(existing)  # (family, name) for prefix lists, names for route maps
        self.setWindowTitle("New Prefix List" if kind == PREFIX_LIST else "New Route Map")
        layout = QVBoxLayout(self)
        grid = QGridLayout()
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("CUSTOMER-IN" if kind == PREFIX_LIST else "FROM-ISP")
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
        if kind == PREFIX_LIST:
            grid.addWidget(QLabel("Family:"), 1, 0)
            grid.addLayout(family, 1, 1)
        self.start_combo = QComboBox()
        self.start_combo.addItem("Nothing in it", None)
        for label, item in starts:
            self.start_combo.addItem(label, item)
        grid.addWidget(QLabel("Start with:"), 2, 0)
        grid.addWidget(self.start_combo, 2, 1)
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
        self.start_combo.currentIndexChanged.connect(self.check)
        self.check()

    @property
    def family(self):
        return V6 if self.v6_radio.isChecked() else V4

    def problem(self):
        name = self.name_input.text().strip()
        if not name:
            return "Give it a name."
        if any(char.isspace() for char in name) or "?" in name:
            return "A name can't have spaces or a question mark."
        if (self.family, name) in self.existing if self.kind == PREFIX_LIST else name in self.existing:
            return f"The device has {name} already."
        start = self.start_combo.currentData()
        if self.kind == PREFIX_LIST and start is not None and start.family != self.family:
            return f"{start.title} is {'IPv6' if start.family == V6 else 'IPv4'}: make the new one the same."
        return ""

    def check(self, *_):
        problem = self.problem()
        set_hint(self.problem_label, problem, "error" if problem else "info")
        ok_button(self.buttons).setEnabled(not problem)

    def made(self):
        """The new PrefixList or RouteMap (its entries not on the device: seq 0, the old numbers wanted)."""
        name, start = self.name_input.text().strip(), self.start_combo.currentData()
        if self.kind == PREFIX_LIST:
            entries = [entry.copy(seq=0, hits=None, want_seq=entry.want_seq or entry.seq) for entry in start.entries] \
                if start is not None else []
            return PrefixList(name, self.family, entries, start.description if start is not None else "")
        entries = [entry.copy(seq=0, hits=None, want_seq=entry.want_seq or entry.seq) for entry in start.entries] \
            if start is not None else []
        return RouteMap(name, entries)


class PolicyApplyDialog(QDialog):
    """Where to put a route map or prefix list: a BGP neighbor, a redistribution, policy routing, a distribute
    list."""

    def __init__(self, parent, device, kind, item):
        super().__init__(parent)
        self.device, self.kind, self.item = device, kind, item
        self.setWindowTitle(f"Apply {item.name}")
        self.resize(640, 0)
        layout = QVBoxLayout(self)
        choices = QHBoxLayout()
        self.radios = {}
        self.pages = QStackedWidget()
        wheres = [BGP, REDIST, PBR, DISTRIBUTE] if kind == ROUTE_MAP else [BGP, DISTRIBUTE]
        group = QButtonGroup(self)
        for where in wheres:
            radio = QRadioButton({BGP: "BGP neighbor", REDIST: "Redistribution", PBR: "Policy routing",
                                  DISTRIBUTE: "Distribute list"}[where])
            radio.toggled.connect(self.on_where)
            group.addButton(radio)
            choices.addWidget(radio)
            self.radios[where] = radio
        choices.addStretch(1)
        layout.addLayout(choices)
        self.bgp_page = self.make_bgp_page()
        self.redist_page = self.make_redist_page() if kind == ROUTE_MAP else QWidget()
        self.pbr_page = self.make_pbr_page() if kind == ROUTE_MAP else QWidget()
        self.distribute_page = self.make_distribute_page()
        for page in (self.bgp_page, self.redist_page, self.pbr_page, self.distribute_page):
            self.pages.addWidget(page)
        layout.addWidget(self.pages)
        self.now_label = QLabel()
        self.now_label.setWordWrap(True)
        layout.addWidget(self.now_label)
        self.preview = QLabel()
        self.preview.setFont(monospace_font())
        self.preview.setWordWrap(True)
        layout.addWidget(self.preview)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        has_bgp = self.neighbor_combo.count() > 0
        first = BGP if has_bgp else (REDIST if kind == ROUTE_MAP else DISTRIBUTE)
        self.radios[first].setChecked(True)
        self.on_where()

    # ----------------------------------------------------------------- The pages

    def processes(self, protocols=None):
        return [process for process in self.device.processes.values()
                if protocols is None or process.protocol in protocols]

    def make_bgp_page(self):
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        self.neighbor_combo = QComboBox()
        for process in self.processes(("bgp",)):
            for name, neighbor in process.neighbors.items():
                about = "peer group" if neighbor.group else f"AS {neighbor.remote_as or neighbor.member_of or '?'}"
                if neighbor.description:
                    about += f", {neighbor.description}"
                if neighbor.member_of and not neighbor.group:
                    about += f", in {neighbor.member_of}"
                self.neighbor_combo.addItem(f"{name}  ({about})  - {process.line}", (process.line, name))
        self.bgp_family_combo = QComboBox()
        self.bgp_direction_combo = QComboBox()
        self.bgp_direction_combo.addItem("In (routes it sends us)", IN)
        self.bgp_direction_combo.addItem("Out (routes we send it)", OUT)
        grid.addWidget(QLabel("Neighbor:"), 0, 0)
        grid.addWidget(self.neighbor_combo, 0, 1)
        grid.addWidget(QLabel("Address family:"), 1, 0)
        grid.addWidget(self.bgp_family_combo, 1, 1)
        grid.addWidget(QLabel("Direction:"), 2, 0)
        grid.addWidget(self.bgp_direction_combo, 2, 1)
        grid.setColumnStretch(1, 1)
        if not self.neighbor_combo.count():
            self.neighbor_combo.addItem("No BGP neighbors read", None)
        self.neighbor_combo.currentIndexChanged.connect(self.fill_bgp_families)
        self.bgp_family_combo.currentIndexChanged.connect(self.update_now)
        self.bgp_direction_combo.currentIndexChanged.connect(self.update_now)
        self.fill_bgp_families()
        return page

    def fill_bgp_families(self, *_):
        self.bgp_family_combo.blockSignals(True)
        self.bgp_family_combo.clear()
        data = self.neighbor_combo.currentData()
        process = self.device.processes.get(data[0]) if data else None
        if process is not None:
            neighbor = process.neighbors.get(data[1])
            for path, label in process.bgp_paths():
                active = neighbor is not None and len(path) > 1 and path[1] in neighbor.afs
                self.bgp_family_combo.addItem(label + ("  (active)" if active else ""), path)
            wanted = V6 if self.item_family() == V6 else V4
            for index in range(self.bgp_family_combo.count()):
                if self.bgp_family_combo.itemText(index).startswith("IPv6" if wanted == V6 else "IPv4"):
                    self.bgp_family_combo.setCurrentIndex(index)
                    break
        self.bgp_family_combo.blockSignals(False)
        self.update_now()

    def make_redist_page(self):
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        self.redist_process_combo = QComboBox()
        for process in self.processes(routepolicy.ROUTING):
            paths = [((process.line,), process.line)]
            if process.protocol == "bgp":
                paths = [(path, f"{process.line}, {label}") for path, label in process.bgp_paths()]
            for path, label in paths:
                self.redist_process_combo.addItem(label, path)
        if not self.redist_process_combo.count():
            self.redist_process_combo.addItem("No routing processes read", None)
        self.redist_what_combo = QComboBox()
        self.redist_new_input = QLineEdit()
        self.redist_new_input.setPlaceholderText("static, connected, ospf 1, eigrp 10, bgp 65000 (then subnets, "
                                                 "metric 20... if wanted)")
        grid.addWidget(QLabel("Into:"), 0, 0)
        grid.addWidget(self.redist_process_combo, 0, 1)
        grid.addWidget(QLabel("Routes from:"), 1, 0)
        grid.addWidget(self.redist_what_combo, 1, 1)
        grid.addWidget(QLabel("New:"), 2, 0)
        grid.addWidget(self.redist_new_input, 2, 1)
        grid.setColumnStretch(1, 1)
        self.redist_process_combo.currentIndexChanged.connect(self.fill_redist_what)
        self.redist_what_combo.currentIndexChanged.connect(self.update_now)
        self.redist_new_input.textChanged.connect(self.update_now)
        self.fill_redist_what()
        return page

    def fill_redist_what(self, *_):
        self.redist_what_combo.blockSignals(True)
        self.redist_what_combo.clear()
        path = self.redist_process_combo.currentData()
        if path:
            for use in self.device.policy_uses:
                if use.where == REDIST and use.path == path:
                    self.redist_what_combo.addItem(f"{use.line}" + (f"  (has {use.name} now)" if use.name else ""),
                                                   use.slot)
            if not any(use.slot == "default-information originate" and use.path == path
                       for use in self.device.policy_uses) and not path[0].startswith("router bgp"):
                self.redist_what_combo.addItem("default-information originate (new: a default route)",
                                               "default-information originate")
        self.redist_what_combo.addItem("A new redistribution (type it below)", "")
        self.redist_what_combo.blockSignals(False)
        self.update_now()

    def make_pbr_page(self):
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        self.pbr_combo = QComboBox()
        self.pbr_combo.addItem("This router's own traffic (ip local policy)", "")
        for name, interface in self.device.interfaces.items():
            parts = [f"{address}/{length}" for address, length in interface.addresses + interface.addresses6]
            self.pbr_combo.addItem(name + (f"  ({', '.join(parts)})" if parts else ""), name)
        if len(self.device.interfaces):
            self.pbr_combo.setCurrentIndex(1)
        self.pbr_v6_check = QCheckBox("IPv6 (ipv6 policy route-map)")
        grid.addWidget(QLabel("Packets coming in on:"), 0, 0)
        grid.addWidget(self.pbr_combo, 0, 1)
        grid.addWidget(self.pbr_v6_check, 1, 1)
        grid.setColumnStretch(1, 1)
        self.pbr_combo.currentIndexChanged.connect(self.update_now)
        self.pbr_v6_check.toggled.connect(self.update_now)
        return page

    def make_distribute_page(self):
        page = QWidget()
        grid = QGridLayout(page)
        grid.setContentsMargins(0, 0, 0, 0)
        self.distribute_process_combo = QComboBox()
        for process in self.processes(("ospf", "ospfv3", "eigrp", "rip")):
            self.distribute_process_combo.addItem(process.line, (process.line,))
        if not self.distribute_process_combo.count():
            self.distribute_process_combo.addItem("No OSPF, EIGRP or RIP read", None)
        self.distribute_direction_combo = QComboBox()
        self.distribute_direction_combo.addItem("In (routes learned, into the routing table)", IN)
        if self.kind == PREFIX_LIST:
            self.distribute_direction_combo.addItem("Out (routes advertised; not OSPF)", OUT)
        self.distribute_interface_combo = QComboBox()
        self.distribute_interface_combo.addItem("All interfaces", "")
        for name in self.device.interfaces:
            self.distribute_interface_combo.addItem(name, name)
        self.area_check = QCheckBox("OSPF area filter (ABR, type-3 summaries) instead: area")
        self.area_input = QLineEdit()
        self.area_input.setPlaceholderText("0")
        grid.addWidget(QLabel("Routing process:"), 0, 0)
        grid.addWidget(self.distribute_process_combo, 0, 1)
        grid.addWidget(QLabel("Direction:"), 1, 0)
        grid.addWidget(self.distribute_direction_combo, 1, 1)
        grid.addWidget(QLabel("Interface:"), 2, 0)
        grid.addWidget(self.distribute_interface_combo, 2, 1)
        area = QHBoxLayout()
        area.addWidget(self.area_check)
        area.addWidget(self.area_input)
        if self.kind == PREFIX_LIST:
            grid.addLayout(area, 3, 1)
        grid.setColumnStretch(1, 1)
        for widget in (self.distribute_process_combo, self.distribute_direction_combo,
                       self.distribute_interface_combo):
            widget.currentIndexChanged.connect(self.update_now)
        self.area_check.toggled.connect(self.update_now)
        self.area_input.textChanged.connect(self.update_now)
        return page

    # ----------------------------------------------------------------- What's chosen

    def item_family(self):
        return getattr(self.item, "family", V4)

    @property
    def where(self):
        return next((where for where, radio in self.radios.items() if radio.isChecked()), BGP)

    def on_where(self, *_):
        page = {BGP: self.bgp_page, REDIST: self.redist_page, PBR: self.pbr_page,
                DISTRIBUTE: self.distribute_page}[self.where]
        self.pages.setCurrentWidget(page)
        self.update_now()

    def use(self):
        """The PolicyUse chosen, or raises ValueError."""
        name, kind = self.item.name, self.kind
        family = self.item_family()
        if self.where == BGP:
            data, path = self.neighbor_combo.currentData(), self.bgp_family_combo.currentData()
            if not data or not path:
                raise ValueError("The device has no BGP neighbors read.")
            direction = self.bgp_direction_combo.currentData()
            slot = f"neighbor {data[1]} {kind} {direction}"
            return PolicyUse(kind, name, BGP, tuple(path), slot, routepolicy.use_line(kind, name, BGP, slot),
                             direction, V6 if "ipv6" in " ".join(path) else family)
        if self.where == REDIST:
            path = self.redist_process_combo.currentData()
            if not path:
                raise ValueError("The device has no routing processes read.")
            slot = self.redist_what_combo.currentData()
            if slot:
                current = next((use for use in self.device.policy_uses if use.where == REDIST and use.path == path
                                and use.slot == slot), None)
                line = routepolicy.redistribution_line(current.line if current is not None else slot, name)
                return PolicyUse(ROUTE_MAP, name, REDIST, tuple(path), slot, line)
            words = self.redist_new_input.text().split()
            if not words:
                raise ValueError("Type what to redistribute (static, connected, ospf 1...).")
            if words[0] == "redistribute":
                words = words[1:]
            if not words:
                raise ValueError("Type what to redistribute (static, connected, ospf 1...).")
            proto = words[:2] if words[0] in routepolicy.WITH_ID and len(words) >= 2 else words[:1]
            if words[0] in routepolicy.WITH_ID and len(words) < 2:
                raise ValueError(f"{words[0]} needs its process number (or AS): {words[0]} 1.")
            slot = "redistribute " + " ".join(proto)
            if any(use.where == REDIST and use.path == tuple(path) and use.slot == slot
                   for use in self.device.policy_uses):
                raise ValueError(f"It has {slot} already: pick it above.")
            line = routepolicy.redistribution_line("redistribute " + " ".join(words), name)
            return PolicyUse(ROUTE_MAP, name, REDIST, tuple(path), slot, line)
        if self.where == PBR:
            interface = self.pbr_combo.currentData()
            word = "ipv6" if self.pbr_v6_check.isChecked() else "ip"
            if interface:
                slot = f"{word} policy"
                return PolicyUse(ROUTE_MAP, name, PBR, (f"interface {interface}",), slot,
                                 routepolicy.use_line(ROUTE_MAP, name, PBR, slot), "", V6 if word == "ipv6" else V4)
            slot = f"{word} local policy"
            return PolicyUse(ROUTE_MAP, name, PBR, (), slot, routepolicy.use_line(ROUTE_MAP, name, PBR, slot), "",
                             V6 if word == "ipv6" else V4)
        path = self.distribute_process_combo.currentData()
        if not path:
            raise ValueError("The device has no OSPF, EIGRP or RIP read.")
        direction = self.distribute_direction_combo.currentData()
        if kind == PREFIX_LIST and self.area_check.isChecked():
            area = self.area_input.text().strip()
            if not area:
                raise ValueError("Type the area (0, or 0.0.0.1).")
            slot = f"area {area} filter-list {direction}"
            return PolicyUse(kind, name, DISTRIBUTE, tuple(path), slot,
                             routepolicy.use_line(kind, name, DISTRIBUTE, slot), direction, family)
        if kind == ROUTE_MAP and direction != IN:
            raise ValueError("A route map goes on a distribute list in only.")
        if direction == OUT and path[0].startswith("router ospf"):
            raise ValueError("OSPF's distribute lists go in only (out is for redistributed routes, with "
                             "the process named): use an area filter, or a route map on the redistribution.")
        interface = self.distribute_interface_combo.currentData()
        slot = " ".join(["distribute-list", "prefix" if kind == PREFIX_LIST else ROUTE_MAP, direction] +
                        ([interface] if interface else []))
        return PolicyUse(kind, name, DISTRIBUTE, tuple(path), slot,
                         routepolicy.use_line(kind, name, DISTRIBUTE, slot), direction, family)

    def update_now(self, *_):
        if not hasattr(self, "now_label"):
            return
        try:
            use = self.use()
        except ValueError as error:
            set_hint(self.now_label, str(error), "error")
            self.preview.setText("")
            ok_button(self.buttons).setEnabled(False)
            return
        ok_button(self.buttons).setEnabled(True)
        self.preview.setText("\n".join(routepolicy.enter(use.path) + [" " * len(use.path) + use.line]))
        current = next((item for item in self.device.policy_uses if item.where != routepolicy.OTHER and
                        item.spot == use.spot), None)
        if current is None:
            text = "Nothing is there now." + (" Routes start being redistributed once it's sent." if
                                              use.where == REDIST else "")
            set_hint(self.now_label, text, "warning" if use.where == REDIST else "info")
        elif current.name == self.item.name and current.kind == self.kind:
            set_hint(self.now_label, f"{self.item.name} is there already.", "warning")
        elif current.name:
            set_hint(self.now_label, f"{current.name} is there now: {self.item.name} takes its place.", "warning")
        else:
            set_hint(self.now_label, f"Now: {current.line} (no route map).", "info")

    def accept(self):
        try:
            self.chosen = self.use()
        except ValueError as error:
            set_hint(self.now_label, str(error), "error")
            return
        super().accept()
