"""Dialogs for the VPNs page: a new VPN (its kind and routers), one router's part in it, and enrolling certificates
by hand (pasting the CA's certificate, taking each router's request to the CA, pasting what it signs)."""
import ipaddress

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog, QDialogButtonBox, \
    QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, \
    QPlainTextEdit, QPushButton, QSpinBox, QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout

from ..netmap import vpn
from .common import set_hint
from .theme import accent_button, monospace_font


class NewVpnDialog(QDialog):
    """A new VPN: its name, its kind, and the routers in it (with each one's role in a DMVPN); or only one side of it
    (the far end set up by hand), or a template with no routers at all."""

    def __init__(self, parent, routers, chosen=(), name="", kind=vpn.VTI):
        super().__init__(parent)
        self.setWindowTitle("New VPN")
        self.resize(560, 760)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_input = QLineEdit(name or "VPN1")
        self.name_input.setToolTip("Names the routers' crypto objects (NAME-PROP, NAME-IKE...) and the tunnels' "
                                   "descriptions")
        form.addRow("Name:", self.name_input)
        self.kind_combo = QComboBox()
        for item in vpn.KINDS:
            self.kind_combo.addItem(vpn.KIND_NAMES[item], item)
        self.kind_combo.setCurrentIndex(max(0, self.kind_combo.findData(kind)))
        self.kind_combo.currentIndexChanged.connect(self.on_kind)
        form.addRow("Kind:", self.kind_combo)
        template_row = QHBoxLayout()
        self.template_check = QCheckBox("Template: no routers")
        self.template_check.setToolTip("Lines for each side with <PLACEHOLDERS> (WAN interface and address, LANs...) "
                                       "to fill in: nothing is read or sent")
        self.template_check.toggled.connect(self.on_kind)
        template_row.addWidget(self.template_check)
        self.hubs_label = QLabel("Hubs:")
        template_row.addWidget(self.hubs_label)
        self.hubs_spin = QSpinBox()
        self.hubs_spin.setRange(1, 2)
        template_row.addWidget(self.hubs_spin)
        template_row.addStretch(1)
        form.addRow("", template_row)
        layout.addLayout(form)
        self.about = QLabel()
        self.about.setWordWrap(True)
        layout.addWidget(self.about)
        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(["Router", "Role"])
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionMode(QAbstractItemView.NoSelection)
        for key, label in routers:
            row = self.table.rowCount()
            self.table.insertRow(row)
            item = QTableWidgetItem(label)
            item.setData(Qt.UserRole, key)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if key in chosen else Qt.Unchecked)
            self.table.setItem(row, 0, item)
            role = QComboBox()
            role.addItem("Spoke", vpn.SPOKE)
            role.addItem("Hub", vpn.HUB)
            self.table.setCellWidget(row, 1, role)
        self.table.resizeColumnsToContents()
        self.table.itemChanged.connect(self.check)
        layout.addWidget(self.table, 1)
        self.far_box = QGroupBox("Far end set up by hand")
        far = QFormLayout(self.far_box)
        self.far_about = QLabel()
        self.far_about.setWordWrap(True)
        far.addRow(self.far_about)
        self.far_input = QLineEdit()
        self.far_input.setPlaceholderText("203.0.113.10")
        self.far_input.textChanged.connect(self.check)
        self.far_label = QLabel("Its WAN address:")
        far.addRow(self.far_label, self.far_input)
        layout.addWidget(self.far_box)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.on_kind()

    def kind(self):
        return self.kind_combo.currentData()

    def template(self):
        return self.template_check.isChecked()

    def hubs(self):
        return self.hubs_spin.value()

    def far_wanted(self):
        """Whether the ticked routers leave a side for a far end set up by hand: one router of a two-router kind, or
        DMVPN spokes with no hub."""
        if self.template():
            return False
        chosen = self.chosen()
        if self.kind() == vpn.DMVPN:
            return bool(chosen) and not any(role == vpn.HUB for _, role in chosen)
        return len(chosen) == 1

    def far_end(self):
        """The far end's WAN address, when it's set up by hand ("" otherwise)."""
        return self.far_input.text().strip() if self.far_wanted() else ""

    def on_kind(self, *_):
        kind = self.kind()
        about = {
            vpn.VTI: "Two routers, a routed IPsec tunnel interface between them (tunnel mode ipsec ipv4): the usual "
                     "choice for site to site.",
            vpn.GRE_IPSEC: "Two routers, a GRE tunnel protected by IPsec: carries multicast and other protocols (the "
                           "IPsec in transport mode).",
            vpn.GRE: "Two routers, a plain GRE tunnel: not encrypted.",
            vpn.CRYPTO_MAP: "Two routers, a crypto map on each WAN interface encrypting the traffic between their "
                            "LANs (no tunnel interface): for a far end that only does policy-based IPsec.",
            vpn.DMVPN: "Hubs and spokes on one multipoint GRE tunnel with NHRP and IPsec: spokes register with the "
                       "hub(s), and (phase 2 and 3) build tunnels to each other as they need them. Tick the routers "
                       "and pick each one's role.",
        }[kind]
        self.about.setText(about + ("" if self.template() else
                                    " Tick only one side to build just that side (the far end by hand)."))
        self.table.setColumnHidden(1, kind != vpn.DMVPN)
        self.table.setEnabled(not self.template())
        for widget in (self.hubs_label, self.hubs_spin):
            widget.setVisible(self.template() and kind == vpn.DMVPN)
        self.check()

    def chosen(self):
        """[(router key, role)]."""
        found = []
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item.checkState() == Qt.Checked:
                role = self.table.cellWidget(row, 1).currentData() if self.kind() == vpn.DMVPN else vpn.PEER
                found.append((item.data(Qt.UserRole), role))
        return found

    def check(self, *_):
        chosen = self.chosen()
        dmvpn = self.kind() == vpn.DMVPN
        wanted = self.far_wanted()
        self.far_box.setVisible(wanted)
        self.far_label.setText("The hub's WAN address:" if dmvpn else "Its WAN address:")
        self.far_about.setText(
            "No hub ticked: NOMAD builds the ticked spokes' side; the hub is set up by hand (its lines are shown to "
            "copy)." if dmvpn else "One router ticked: NOMAD builds its side; the far end is set up by hand (its "
            "lines are shown to copy).")
        problem, info = "", "Routers not read yet are read when you click OK."
        if self.template():
            info = "Nothing is read or sent: each side's lines have <PLACEHOLDERS> to fill in."
        elif not chosen:
            problem = "Tick the routers (one is enough: the far end can be set up by hand), or make a template."
        elif not dmvpn and len(chosen) > 2:
            problem = f"Tick two routers ({len(chosen)} ticked): make a DMVPN for more."
        elif wanted and not vpn.ipaddress_like(self.far_end()):
            problem = "Type the hub's WAN address (where the spokes reach it)." if dmvpn else \
                "Type the far end's WAN address (where this router reaches it)."
        elif dmvpn and all(role == vpn.HUB for _, role in chosen):
            info = "Only hubs: spokes can be added later (or set up by hand from a template). " + info
        if not self.name_input.text().strip():
            problem = problem or "Give it a name."
        set_hint(self.hint, problem or info, "warning" if problem else "info")
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(not problem)

    def name(self):
        return self.name_input.text().strip()


class MemberDialog(QDialog):
    """One router's part in a VPN: its role, WAN interface, the address the others reach it at, its tunnel, and the
    LANs it carries across."""

    def __init__(self, parent, design, member, device):
        super().__init__(parent)
        self.design, self.member, self.device = design, member, device
        # Free: a router NOMAD doesn't read (a far end set up by hand, a template's slot): everything is typed
        self.free = device is None and (design.template or member.key.startswith("peer:"))
        self.setWindowTitle(f"{member.title() or 'Far end'} in {design.name}")
        self.resize(560, 560)
        layout = QVBoxLayout(self)
        if self.free:
            about = QLabel("A template's side: type a value or a <PLACEHOLDER> for each." if design.template else
                           "Set up by hand: NOMAD sends nothing to it, but its details go into the other routers' "
                           "lines (and its own lines are shown to copy).")
            about.setWordWrap(True)
            layout.addWidget(about)
        form = QFormLayout()
        self.label_input = QLineEdit(member.label)
        if self.free:
            form.addRow("Name:", self.label_input)
        self.role_combo = QComboBox()
        if design.kind == vpn.DMVPN:
            self.role_combo.addItem("Spoke", vpn.SPOKE)
            self.role_combo.addItem("Hub", vpn.HUB)
            self.role_combo.setCurrentIndex(max(0, self.role_combo.findData(member.role)))
            form.addRow("Role:", self.role_combo)
            self.hub_order = QSpinBox()
            self.hub_order.setRange(1, 2)
            self.hub_order.setValue(member.hub_order or 1)
            self.hub_order.setToolTip("With two hubs: 1 is preferred (listed first on the spokes)")
            form.addRow("Hub order:", self.hub_order)
        self.wan_combo = QComboBox()
        self.wan_combo.setEditable(True)
        for name, address in vpn.wan_choices(device):
            self.wan_combo.addItem(f"{name}  ({address})", name)
        at = self.wan_combo.findData(vpn.full_interface(member.wan)) if member.wan else -1
        if at >= 0:
            self.wan_combo.setCurrentIndex(at)
        elif member.wan:
            self.wan_combo.setEditText(member.wan)
        self.wan_combo.currentIndexChanged.connect(self.on_wan)
        self.wan_combo.setToolTip("Where the VPN's packets leave (the tunnel source, or the crypto map's interface)" +
                                  (": only for its own lines" if self.free else ""))
        form.addRow("WAN interface:", self.wan_combo)
        self.local_label = QLabel(member.local_ip or "")
        self.local_input = QLineEdit(member.local_ip)
        self.local_input.setToolTip("Its address on the WAN interface (its IKE identity; where the others reach it "
                                    "unless NAT changes it)")
        form.addRow("WAN address:", self.local_input if self.free else self.local_label)
        self.public_input = QLineEdit(member.public_ip)
        self.public_input.setPlaceholderText("Only if NAT changes it")
        self.public_input.setToolTip("The address the other routers reach it at, when a NAT device in front of it "
                                     "changes it (its WAN address is then only its IKE identity)")
        form.addRow("Reached at:", self.public_input)
        if design.kind != vpn.CRYPTO_MAP:
            self.tunnel_spin = QSpinBox()
            self.tunnel_spin.setRange(0, 2147483647)
            self.tunnel_spin.setValue(member.tunnel)
            form.addRow("Tunnel interface:", self.tunnel_spin)
            self.tunnel_input = QLineEdit(member.tunnel_ip)
            self.tunnel_input.setToolTip(f"An address in the tunnel subnet ({design.subnet})")
            form.addRow("Tunnel address:", self.tunnel_input)
        self.as_input = QLineEdit(member.bgp_as)
        has_bgp = bool(device.bgp_as()) if device is not None else False
        self.as_input.setEnabled(not has_bgp)
        self.as_input.setToolTip("Its BGP AS (it runs BGP already: that one)" if has_bgp else
                                 "Its BGP AS, for BGP routing across the VPN (a BGP process is made)")
        if design.routing.kind == vpn.BGP:
            form.addRow("BGP AS:", self.as_input)
        layout.addLayout(form)
        lans = QGroupBox("LANs it carries across")
        lans_layout = QVBoxLayout(lans)
        about = QLabel("One prefix a line (10.1.1.0/24). Dynamic routing advertises the ones on its interfaces; a "
                       "crypto map encrypts the traffic between these and the far end's.")
        about.setWordWrap(True)
        lans_layout.addWidget(about)
        self.lans_input = QPlainTextEdit("\n".join(member.lans))
        self.lans_input.setFont(monospace_font())
        lans_layout.addWidget(self.lans_input, 1)
        row = QHBoxLayout()
        self.from_button = QToolButton()
        self.from_button.setText("Add From Its Interfaces")
        self.from_button.setPopupMode(QToolButton.InstantPopup)
        self.from_button.setVisible(not self.free)
        menu = QMenu(self.from_button)
        for name, interface in (device.interfaces().items() if device is not None else []):
            if name.lower().startswith(("tunnel", "nve")) or interface.shutdown:
                continue
            for address, length in interface.addresses:
                prefix = str(ipaddress.IPv4Interface(f"{address}/{length}").network)
                menu.addAction(f"{prefix}  ({name})", lambda prefix=prefix: self.add_lan(prefix))
        if menu.isEmpty():
            menu.addAction("Read the router to see its interfaces").setEnabled(False)
        self.from_button.setMenu(menu)
        row.addWidget(self.from_button)
        row.addStretch(1)
        lans_layout.addLayout(row)
        layout.addWidget(lans, 1)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept_if_valid)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.on_wan()

    def wan(self):
        data = self.wan_combo.currentData()
        text = self.wan_combo.currentText().split("  (")[0].strip()
        return data if data and self.wan_combo.currentText().startswith(data) else vpn.full_interface(text)

    def on_wan(self, *_):
        if self.free:
            return
        address = self.device.interface_address(self.wan())[0] if self.device is not None else ""
        self.local_label.setText(address or "(no address on it)")

    def add_lan(self, prefix):
        lines = [line.strip() for line in self.lans_input.toPlainText().splitlines() if line.strip()]
        if prefix not in lines:
            lines.append(prefix)
        self.lans_input.setPlainText("\n".join(lines))

    def lans(self):
        found = []
        for line in self.lans_input.toPlainText().replace(",", "\n").splitlines():
            text = line.strip()
            if not text:
                continue
            if self.design.template and vpn.is_placeholder(text):
                found.append(text)
                continue
            found.append(str(ipaddress.IPv4Network(text if "/" in text else f"{text}/32", strict=False)))
        return found

    def accept_if_valid(self):
        try:
            self.lans()
        except ValueError as error:
            set_hint(self.hint, f"A LAN isn't a prefix: {error}", "error")
            return
        typed = self.design.template  # A template takes <PLACEHOLDERS> too
        public = self.public_input.text().strip()
        if public and not vpn.ipaddress_like(public) and not (typed and vpn.is_placeholder(public)):
            set_hint(self.hint, "Reached at has to be an IPv4 address.", "error")
            return
        if self.free:
            local = self.local_input.text().strip()
            if not (vpn.ipaddress_like(local) or typed and vpn.is_placeholder(local)):
                set_hint(self.hint, "Type its WAN address (an IPv4 address" +
                         (", or a <PLACEHOLDER>)." if typed else ")."), "error")
                return
        if self.design.kind != vpn.CRYPTO_MAP:
            address = self.tunnel_input.text().strip()
            if address and not vpn.ipaddress_like(address) and not (typed and vpn.is_placeholder(address)):
                set_hint(self.hint, "The tunnel address has to be an IPv4 address.", "error")
                return
        self.accept()

    def apply(self, member):
        """Put what was chosen into member."""
        if self.design.kind == vpn.DMVPN:
            member.role = self.role_combo.currentData()
            member.hub_order = self.hub_order.value() if member.role == vpn.HUB else 0
        member.wan = self.wan() if not self.free else self.wan_combo.currentText().strip()
        if self.free:
            member.label = self.label_input.text().strip() or member.label
            member.local_ip = self.local_input.text().strip()
        elif self.device is not None:
            member.local_ip = self.device.interface_address(member.wan)[0]
        member.public_ip = self.public_input.text().strip()
        if member.public_ip == member.local_ip:
            member.public_ip = ""
        if self.design.kind != vpn.CRYPTO_MAP:
            member.tunnel = self.tunnel_spin.value()
            member.tunnel_ip = self.tunnel_input.text().strip()
        member.lans = self.lans()
        if self.as_input.isEnabled():
            member.bgp_as = self.as_input.text().strip()


class PasteEnrollDialog(QDialog):
    """Enrolling the VPN's routers with a CA that has no SCEP: paste the CA certificate (and its fingerprint) to have
    the routers trust it, have each router make its request (to take to the CA), and paste back what the CA signs."""
    trust_requested = pyqtSignal(str, str)  # CA certificate (PEM), fingerprint
    request_requested = pyqtSignal(str)  # Member key
    import_requested = pyqtSignal(str, str)  # Member key, certificate (PEM)

    def __init__(self, parent, design):
        super().__init__(parent)
        self.design = design
        self.requests = {}
        self.setWindowTitle(f"Certificates for {design.name} (by hand)")
        self.resize(760, 680)
        layout = QVBoxLayout(self)
        first = QGroupBox("1. The CA's certificate")
        first_layout = QVBoxLayout(first)
        self.ca_input = QPlainTextEdit()
        self.ca_input.setFont(monospace_font())
        self.ca_input.setPlaceholderText("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----")
        first_layout.addWidget(self.ca_input, 1)
        row = QHBoxLayout()
        row.addWidget(QLabel("Its fingerprint (as the CA shows it):"))
        self.fingerprint_input = QLineEdit(design.auth.ca_fingerprint)
        self.fingerprint_input.setToolTip("MD5 or SHA-1, as the CA's administrator gives it: a router only trusts the "
                                          "certificate pasted if it shows this fingerprint")
        row.addWidget(self.fingerprint_input, 1)
        self.trust_button = accent_button("Trust It on Every Router")
        self.trust_button.clicked.connect(self.on_trust)
        row.addWidget(self.trust_button)
        first_layout.addLayout(row)
        layout.addWidget(first, 2)
        second = QGroupBox("2. Each router's request, then 3. its certificate")
        grid = QGridLayout(second)
        self.router_list = QListWidget()
        for member in design.members:
            if member.key.startswith("peer:"):
                continue
            item = QListWidgetItem(member.title())
            item.setData(Qt.UserRole, member.key)
            self.router_list.addItem(item)
        self.router_list.currentItemChanged.connect(self.on_router)
        grid.addWidget(self.router_list, 0, 0, 3, 1)
        buttons = QHBoxLayout()
        self.request_button = QPushButton("Make Its Request")
        self.request_button.clicked.connect(self.on_request)
        buttons.addWidget(self.request_button)
        self.copy_button = QPushButton("Copy Request")
        self.copy_button.clicked.connect(self.copy_request)
        buttons.addWidget(self.copy_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, 0, 1)
        self.request_view = QPlainTextEdit()
        self.request_view.setReadOnly(True)
        self.request_view.setFont(monospace_font())
        grid.addWidget(self.request_view, 1, 1)
        self.certificate_input = QPlainTextEdit()
        self.certificate_input.setFont(monospace_font())
        self.certificate_input.setPlaceholderText("Paste the certificate the CA signed for it here")
        grid.addWidget(self.certificate_input, 2, 1)
        self.import_button = accent_button("Put Its Certificate In")
        self.import_button.clicked.connect(self.on_import)
        grid.addWidget(self.import_button, 3, 1, Qt.AlignRight)
        grid.setColumnStretch(1, 3)
        layout.addWidget(second, 3)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        close = QDialogButtonBox(QDialogButtonBox.Close)
        close.rejected.connect(self.reject)
        layout.addWidget(close)
        if self.router_list.count():
            self.router_list.setCurrentRow(0)

    def current_key(self):
        item = self.router_list.currentItem()
        return item.data(Qt.UserRole) if item is not None else ""

    def on_router(self, *_):
        self.request_view.setPlainText(self.requests.get(self.current_key(), ""))
        self.certificate_input.clear()

    def on_trust(self):
        pem, fingerprint = self.ca_input.toPlainText().strip(), self.fingerprint_input.text().strip()
        if "BEGIN CERTIFICATE" not in pem or not fingerprint:
            set_hint(self.status, "Paste the CA certificate (PEM) and its fingerprint.", "warning")
            return
        self.trust_requested.emit(pem, fingerprint)

    def on_request(self):
        if self.current_key():
            self.request_requested.emit(self.current_key())

    def set_request(self, key, text):
        self.requests[key] = text
        if key == self.current_key():
            self.request_view.setPlainText(text)

    def copy_request(self):
        QApplication.clipboard().setText(self.request_view.toPlainText())
        set_hint(self.status, "Copied: take it to the CA, and paste what it signs below.", "success")

    def on_import(self):
        pem = self.certificate_input.toPlainText().strip()
        if "BEGIN CERTIFICATE" not in pem:
            set_hint(self.status, "Paste the signed certificate (PEM).", "warning")
            return
        self.import_requested.emit(self.current_key(), pem)

    def say(self, text, kind="info"):
        set_hint(self.status, text, kind)

    def set_busy(self, busy):
        for button in (self.trust_button, self.request_button, self.import_button):
            button.setEnabled(not busy)


class ChoiceDialog(QDialog):
    """Tick some of a list (the sessions to clear, the routers to read...)."""

    def __init__(self, parent, title, text, items, ticked=False):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(460, 360)
        layout = QVBoxLayout(self)
        label = QLabel(text)
        label.setWordWrap(True)
        layout.addWidget(label)
        self.list = QListWidget()
        for key, label_text in items:
            item = QListWidgetItem(label_text)
            item.setData(Qt.UserRole, key)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Checked if ticked else Qt.Unchecked)
            self.list.addItem(item)
        layout.addWidget(self.list, 1)
        self.all_check = QCheckBox("All")
        self.all_check.setChecked(ticked)
        self.all_check.toggled.connect(self.tick_all)
        layout.addWidget(self.all_check)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def tick_all(self, on):
        for row in range(self.list.count()):
            self.list.item(row).setCheckState(Qt.Checked if on else Qt.Unchecked)

    def chosen(self):
        return [self.list.item(row).data(Qt.UserRole) for row in range(self.list.count())
                if self.list.item(row).checkState() == Qt.Checked]


class IpamBlockDialog(QDialog):
    """A tunnel subnet from the IP Addresses page: a network, a subnet in it, and the first free block of the size the
    VPN needs, which is then added there (named after the VPN)."""

    def __init__(self, parent, store, length, name):
        super().__init__(parent)
        self.store, self.length = store, length
        self.setWindowTitle("Tunnel Subnet from IP Addresses")
        self.resize(520, 260)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.network_combo = QComboBox()
        for network in store.networks():
            self.network_combo.addItem(network.name, network.id)
        self.network_combo.currentIndexChanged.connect(self.fill_subnets)
        form.addRow("Network:", self.network_combo)
        self.subnet_combo = QComboBox()
        self.subnet_combo.currentIndexChanged.connect(self.find_block)
        form.addRow("Take it from:", self.subnet_combo)
        self.block_label = QLabel()
        form.addRow(f"Free /{length}:", self.block_label)
        self.name_input = QLineEdit(f"VPN {name} tunnels")
        form.addRow("Name it:", self.name_input)
        layout.addLayout(form)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Ok).setText("Add It and Use It")
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.block = ""
        self.fill_subnets()

    def fill_subnets(self, *_):
        self.subnet_combo.clear()
        network_id = self.network_combo.currentData()
        if network_id:
            for subnet in self.store.subnets(network_id):
                if subnet.network.version == 4 and subnet.network.prefixlen < self.length and not subnet.loopbacks:
                    self.subnet_combo.addItem(f"{subnet.cidr}  {subnet.name}".strip(), subnet.id)
        self.find_block()

    def find_block(self, *_):
        self.block = ""
        subnet_id = self.subnet_combo.currentData()
        network_id = self.network_combo.currentData()
        subnet = next((item for item in self.store.subnets(network_id) if item.id == subnet_id), None) \
            if network_id and subnet_id else None
        if subnet is not None:
            blocks, _ = self.store.free_blocks(subnet, self.length, limit=1)
            if blocks:
                self.block = f"{blocks[0].network_address}/{blocks[0].prefixlen}"
        self.block_label.setText(self.block or "(none free)")
        self.buttons.button(QDialogButtonBox.Ok).setEnabled(bool(self.block))

    def network_id(self):
        return self.network_combo.currentData()
