"""VLANs page (Manage > VLANs): each VLAN domain's VLANs, their names and status, the IPAM subnets they carry, and
where the network map found them.

Domains come from the same two places as IPAM's networks: the tribe's, shared through the IPAM server (kept in the
copy the IP Addresses page syncs, so they can be read offline, and VLANs can be changed offline: those changes wait
as pending until the server is back), and this computer's own (Local). A domain can belong to one IPAM network,
whose subnets its VLANs carry; linking a subnet to a VLAN is only noted here, never on the subnet, so the IP
Addresses page and its export to the workbook are as they were.
"""
import csv
import html
import logging
import time

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMenu, \
    QMessageBox, QPushButton, QSplitter, QTableWidget, QTextBrowser, QToolButton, QVBoxLayout, QWidget

from ..ipam.client import ServerUnreachable, TeamKeyError
from ..ipam.server import ConflictError
from ..ipam.store import IpamError
from ..ipam.placement import PlacementStore
from ..ipam.roles import subnet_roles
from ..ipam.vlan_team import TeamVlanStore
from ..ipam.vlans import STATUSES, VlanStore, name_problem, range_for
from ..netmap import store as map_store
from ..netmap import vlans as map_vlans
from .common import SortableTableItem, set_hint
from .integration import PLACEMENT, hub, link
from .ipam_tab import ago
from .table_filter import TableFilter
from .theme import COLORS
from .vlan_dialogs import DomainDialog, LinkSuggestionsDialog, MapImportDialog, NextFreeDialog, Source, VlanDialog, \
    VlanRefusedDialog

log = logging.getLogger(__name__)

COLUMNS = ["VLAN", "Name", "Status", "Range", "Subnets", "Gateways (IPAM)", "VLAN Interfaces (Map)", "On the Map",
           "Description", "Last Changed"]
COL_INTERFACES, COL_MAP = 6, 7
LOCAL, TEAM = "local", "team"  # As the IP Addresses page names where networks come from
STATUS_COLORS = {"reserved": "warning", "planned": "link"}


class VlanTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.source_key = None
        self.domain_id = None
        self.saved_domain = ""
        self.no_domain_network = ""  # The network the other pages are on, when it has no VLAN domain here
        self.vlans = []
        self.init_ui()
        window.ipam_tab.tribe_synced.connect(self.on_tribe_synced)

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("Domain:"))
        self.domain_combo = QComboBox()
        self.domain_combo.setMinimumWidth(260)
        self.domain_combo.setToolTip("Where VLAN numbers are unique: a VTP domain, or a site's switches. Tribe "
                                     "domains are shared through the IPAM server; Local ones are this computer's.")
        top.addWidget(self.domain_combo)
        self.new_domain_button = QToolButton()
        self.new_domain_button.setText("New Domain")
        self.new_domain_button.setPopupMode(QToolButton.InstantPopup)
        self.new_domain_menu = QMenu(self.new_domain_button)
        self.new_domain_menu.aboutToShow.connect(self.fill_new_domain_menu)
        self.new_domain_button.setMenu(self.new_domain_menu)
        top.addWidget(self.new_domain_button)
        self.domain_button = QToolButton()
        self.domain_button.setText("Domain")
        self.domain_button.setPopupMode(QToolButton.InstantPopup)
        self.domain_menu = QMenu(self.domain_button)
        self.edit_domain_action = self.domain_menu.addAction("Edit Domain...", self.edit_domain)
        self.delete_domain_action = self.domain_menu.addAction("Delete Domain...", self.delete_domain)
        self.domain_history_action = self.domain_menu.addAction("Domain History...", self.show_domain_history)
        self.domain_menu.addSeparator()
        self.link_action = self.domain_menu.addAction("Link Subnets Named for VLANs...", self.link_from_names)
        self.import_action = self.domain_menu.addAction("Bring in VLANs from a Network Map...", self.bring_in_from_map)
        self.domain_menu.addSeparator()
        self.export_action = self.domain_menu.addAction("Export to CSV...", self.export_csv)
        self.domain_button.setMenu(self.domain_menu)
        top.addWidget(self.domain_button)
        self.network_domain_button = QPushButton()
        self.network_domain_button.setProperty("accent", True)
        self.network_domain_button.clicked.connect(self.new_domain_for_network)
        self.network_domain_button.hide()
        top.addWidget(self.network_domain_button)
        top.addStretch()
        self.refused_button = QPushButton()
        self.refused_button.setVisible(False)
        self.refused_button.clicked.connect(self.review_refused)
        top.addWidget(self.refused_button)
        self.server_label = QLabel()
        top.addWidget(self.server_label)
        layout.addLayout(top)

        self.domain_label = QLabel()
        self.domain_label.setWordWrap(True)
        self.domain_label.setTextFormat(Qt.RichText)
        layout.addWidget(self.domain_label)

        find_row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setPlaceholderText("Filter the VLANs: number, name, subnet or any column (Ctrl+F)")
        find_row.addWidget(self.search_input, 1)
        layout.addLayout(find_row)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table_filter = TableFilter(self.table, self.show_counts)
        self.table_filter.columns.widest = {4: 280, COL_INTERFACES: 300, COL_MAP: 260, 8: 260}
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self.open_link)
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([900, 300])
        layout.addWidget(splitter, 1)

        buttons = QHBoxLayout()
        self.add_button = QPushButton("Add VLAN...")
        self.add_button.setProperty("accent", True)
        self.next_free_button = QPushButton("Next Free...")
        self.next_free_button.setToolTip("Add a VLAN with the lowest number the domain hasn't used, in one of its "
                                         "ranges or anywhere.")
        self.edit_button = QPushButton("Edit...")
        self.delete_button = QPushButton("Delete")
        self.history_button = QPushButton("History...")
        self.ipam_button = QPushButton("Show Subnet in IPAM")
        self.map_button = QPushButton("Highlight on Map")
        self.map_button.setToolTip("Show the VLAN on the Network Map's physical view: the switches and links that "
                                   "carry it stay bright, the rest fades.")
        for button in (self.add_button, self.next_free_button, self.edit_button, self.delete_button,
                       self.history_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.ipam_button)
        buttons.addWidget(self.map_button)
        layout.addLayout(buttons)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.domain_combo.currentIndexChanged.connect(self.on_domain_chosen)
        self.search_input.textChanged.connect(self.table_filter.set_text)
        self.table.itemSelectionChanged.connect(self.on_selection)
        self.table.itemDoubleClicked.connect(self.edit_vlan)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.add_button.clicked.connect(self.add_new_vlan)
        self.next_free_button.clicked.connect(self.add_next_free)
        self.edit_button.clicked.connect(self.edit_vlan)
        self.delete_button.clicked.connect(self.delete_vlans)
        self.history_button.clicked.connect(self.show_vlan_history)
        self.ipam_button.clicked.connect(self.show_in_ipam)
        self.map_button.clicked.connect(self.highlight_on_map)
        self.update_buttons()

    # ----------------------------------------------------------------- Page interface

    def showEvent(self, event):
        super().showEvent(event)
        if self.window.ipam_tab.open_store():
            self.fill_domains()

    def focus_find(self):
        self.search_input.setFocus()
        self.search_input.selectAll()

    def save_settings(self, settings):
        if self.domain_id:
            settings.setValue("vlans/domain", f"{self.source_key}:{self.domain_id}")

    def restore_settings(self, settings):
        self.saved_domain = settings.value("vlans/domain", "", str)

    def shutdown(self):
        pass  # The stores are the IP Addresses page's, which closes them

    # ----------------------------------------------------------------- Where domains come from

    def sources(self):
        """[Source]: the tribe's (when connected) then this computer's."""
        page = self.window.ipam_tab
        if page.local_store is None:
            return []
        found = []
        team = page.team
        if team is not None:
            keeps = team.server_keeps_vlans
            found.append(Source(TEAM, "Tribe", team, TeamVlanStore(team), can_edit_domains=team.online and keeps,
                                can_edit_vlans=keeps and not team.key_rejected))
        found.append(Source(LOCAL, "Local", page.local_store, VlanStore(page.local_store)))
        return found

    def source(self, key=None):
        key = key or self.source_key
        return next((source for source in self.sources() if source.key == key), None)

    def domain(self):
        source = self.source()
        if source is None or not self.domain_id:
            return None
        try:
            return source.vlans.domain(self.domain_id)
        except IpamError:
            return None

    # ----------------------------------------------------------------- Domains

    def fill_domains(self, select=None):
        """Every domain: the tribe's first (marked Tribe), then this computer's (marked Local)."""
        if not select and self.no_domain_network:
            select = self.no_domain_network  # Still on a network with no domain: not the one remembered from before
        select = select or (f"{self.source_key}:{self.domain_id}" if self.domain_id else "") or self.saved_domain
        self.domain_combo.blockSignals(True)
        self.domain_combo.clear()
        for source in self.sources():
            for domain in source.vlans.domains():
                self.domain_combo.addItem(f"{domain.name}  ({source.label})", f"{source.key}:{domain.id}")
        index = self.domain_combo.findData(select)
        if self.no_domain_network and index < 0:
            self.domain_combo.setCurrentIndex(-1)  # The network the pages are on has none: none shown
        elif self.domain_combo.count():
            self.domain_combo.setCurrentIndex(max(index, 0))
        self.domain_combo.blockSignals(False)
        self.on_domain_chosen()

    def on_domain_chosen(self):
        data = self.domain_combo.currentData()
        if data:
            self.no_domain_network = ""  # A domain chosen: of whatever network
            self.source_key, _, self.domain_id = data.partition(":")
        else:
            self.source_key = self.no_domain_network.partition(":")[0] or self.source_key
            self.domain_id = None
        self.network_domain_button.setVisible(bool(self.no_domain_network))
        self.fill_table()
        self.show_status()
        domain, integration = self.domain(), hub(self.window)
        if domain is not None and domain.network_id and integration is not None:
            integration.choose_network(f"{self.source_key}:{domain.network_id}", self)

    def follow_network(self, key):
        """Another page (or the map) chose a network: show a domain of it here, if it has one."""
        integration = hub(self.window)
        if integration is not None and not integration.follows(self):
            return
        domain = self.domain()
        if domain is not None and f"{self.source_key}:{domain.network_id}" == key:
            return
        source_key, _, network_id = key.partition(":")
        source = self.source(source_key)
        if source is None:
            return
        found = next((item for item in source.vlans.domains() if item.network_id == network_id), None)
        if found is not None:
            self.no_domain_network = ""
            self.fill_domains(f"{source_key}:{found.id}")
        else:  # Not another network's domain, which would look like this one's
            self.no_domain_network = key
            name = integration.network_name(key) if integration is not None else "the network"
            self.network_domain_button.setText(f"New Domain for {name}...")
            self.fill_domains(key)

    def new_domain_for_network(self):
        """A domain for the network the other pages are on (which has none)."""
        source_key, _, network_id = self.no_domain_network.partition(":")
        source = self.source(source_key)
        if source is None or not network_id:
            return
        if not source.can_edit_domains:
            set_hint(self.status_label, "Tribe VLAN domains can only be made while the IPAM server can be reached.",
                     "warning")
            return
        integration = hub(self.window)
        dialog = DomainDialog(self, source, name=integration.network_name(self.no_domain_network)
                              if integration is not None else "", network_id=network_id)
        if dialog.exec_():
            self.no_domain_network = ""
            self.after_change(source)
            self.fill_domains(f"{source.key}:{dialog.result_item.id}")

    def go_to_vlan(self, source_key, domain_id, number, vtp="", network=""):
        """Go to a VLAN: in a domain, or else (a number from the map) in the domain of its VTP domain, or of the
        network's (source:id)."""
        self.window.navigator.setCurrentWidget(self)
        if not self.window.ipam_tab.open_store():
            return
        if not domain_id:
            choices = [(source, domain) for source in self.sources() if not source_key or source.key == source_key
                       for domain in source.vlans.domains()]
            vtp = (vtp or "").lower()
            match = [pair for pair in choices if vtp and pair[1].vtp_domain.lower() == vtp] or \
                [pair for pair in choices if network and pair[1].network_id == network] or \
                [pair for pair in choices if pair[0].vlans.vlan(pair[1].id, number) is not None]
            if not match:
                set_hint(self.status_label, f"No VLAN domain here has VLAN {number}"
                         + (f" or is for VTP domain {vtp}" if vtp else "") + ".", "warning")
                return
            source_key, domain_id = match[0][0].key, match[0][1].id
        self.search_input.clear()
        self.no_domain_network = ""
        self.fill_domains(f"{source_key}:{domain_id}")
        self.select_vlans([number])
        if not self.selected_vlans():
            name = self.domain().name if self.domain() else "the domain"
            set_hint(self.status_label, f"VLAN {number} isn't in {name} yet (Add VLAN to record it).", "info")

    def select_vlans(self, numbers):
        self.table.clearSelection()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None and item.data_object.vlan in numbers:
                self.table.selectRow(row)
                self.table.scrollToItem(item)

    def open_link(self, url):
        integration = hub(self.window)
        if integration is not None:
            integration.open_link(url)

    def on_facts_changed(self):
        if self.isVisible():
            self.on_selection()

    def show_in_placement(self):
        vlan, domain, integration = self.selected_vlan(), self.domain(), hub(self.window)
        if vlan is None or not vlan.subnets or not domain.network_id or integration is None:
            return
        cidr = vlan.subnets[0]
        if len(vlan.subnets) > 1:
            menu = QMenu(self)
            for subnet in vlan.subnets:
                menu.addAction(subnet).setData(subnet)
            chosen = menu.exec_(self.cursor().pos())
            if chosen is None:
                return
            cidr = chosen.data()
        integration.open_link(link(PLACEMENT, src=self.source_key, net=domain.network_id, cidr=cidr))

    def fill_new_domain_menu(self):
        self.new_domain_menu.clear()
        for source in self.sources():
            action = self.new_domain_menu.addAction(f"New {source.label} Domain...")
            action.setData(source.key)
            action.setEnabled(source.can_edit_domains)
            action.triggered.connect(self.new_domain)
            if source.key == TEAM and not source.can_edit_domains:
                action.setText("New Tribe Domain... (needs the IPAM server)")

    def new_domain(self):
        key = self.sender().data() if self.sender() is not None else LOCAL
        source = self.source(key)
        if source is None:
            return
        dialog = DomainDialog(self, source)
        if dialog.exec_():
            self.after_change(source)
            self.fill_domains(f"{source.key}:{dialog.result_item.id}")

    def edit_domain(self):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        dialog = DomainDialog(self, source, domain)
        if dialog.exec_():
            self.after_change(source)
            self.fill_domains()

    def delete_domain(self):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        count = len(source.vlans.vlans(domain.id))
        if QMessageBox.question(self, "Delete VLAN Domain",
                                f"Delete {domain.name} and its {count} VLAN{'s' if count != 1 else ''}? IPAM's networks "
                                "and subnets aren't touched. Its history is kept.") != QMessageBox.Yes:
            return
        try:
            source.vlans.delete_domain(domain.id)
        except IpamError as error:
            self.report(error, "Deleting the domain")
            return
        self.after_change(source)
        self.domain_id = None
        self.fill_domains()

    def show_domain_history(self):
        from .ipam_history_dialog import HistoryDialog
        source, domain = self.source(), self.domain()
        if domain is not None:
            HistoryDialog(self, source.ipam, domain.id, "vlan_domain", domain, self.history_note()).exec_()

    def history_note(self):
        team = self.window.ipam_tab.team
        if self.source_key == TEAM and team is not None and not team.history_revision:
            return "The tribe's history arrives with the next sync from the IPAM server."
        return ""

    def link_from_names(self):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        dialog = LinkSuggestionsDialog(self, source, domain, self.roles_of(source)(domain.network_id))
        if dialog.exec_():
            self.after_change(source)
            self.fill_table()
            set_hint(self.status_label, f"Linked {dialog.made} subnet{'s' if dialog.made != 1 else ''}.", "success")

    # ----------------------------------------------------------------- The network map

    def open_map(self):
        """The map open on the Network Map page, or None."""
        page = getattr(self.window, "netmap_tab", None)
        return getattr(page, "network_map", None)

    def map_vlans_for(self, domain):
        """{VLAN: MapVlan} the open map found for the domain (map_vlans_for_domain), or None when the map is of
        another IPAM network than the domain's."""
        if domain is not None and domain.network_id:
            network_map = self.open_map()
            if network_map is not None and network_map.ipam_network and \
                    network_map.ipam_network != f"{self.source_key}:{domain.network_id}":
                return None  # A map of another network
        return self.map_vlans_for_domain(domain)

    def map_vlans_for_domain(self, domain):
        """{VLAN: MapVlan} the open map found in the domain's VTP domain (or, for a domain without one, on switches
        without one), or None when there's no map (or it has none of those switches)."""
        network_map = self.open_map()
        if network_map is None or domain is None:
            return None
        wanted = (domain.vtp_domain or "").lower()
        found = {item.vlan: item for item in map_vlans.map_vlans(network_map) if item.domain.lower() == wanted}
        if not found and not wanted:
            return None
        return found if any(item.switches for item in found.values()) else None

    def import_from_map(self, network_map, map_name=""):
        """From the Network Map's VLANs tab: review its VLANs against a domain here, then bring them in."""
        self.window.navigator.setCurrentWidget(self)
        if not self.window.ipam_tab.open_store():
            return
        sources = self.sources()
        dialog = MapImportDialog(self, sources, network_map, map_name,
                                 (self.source_key, self.domain_id) if self.domain_id else None)
        if dialog.exec_() and dialog.domain_made is not None:
            key, domain_id = dialog.domain_made
            self.after_change(self.source(key))
            self.fill_domains(f"{key}:{domain_id}")
            set_hint(self.status_label, f"Brought in {dialog.made} VLAN{'s' if dialog.made != 1 else ''}.", "success")

    def bring_in_from_map(self):
        network_map = self.open_map()
        name = self.window.netmap_tab.map_name() if network_map is not None else ""
        if network_map is None:
            path, _ = QFileDialog.getOpenFileName(self, "Bring in VLANs from a Network Map", str(map_store.maps_dir()),
                                                  f"NOMAD network maps (*{map_store.EXTENSION});;All files (*)")
            if not path:
                return
            try:
                network_map = map_store.load(path)
            except (OSError, ValueError) as error:
                set_hint(self.status_label, f"Couldn't open the map: {error}", "error")
                return
            name = path.rsplit("/", 1)[-1]
        if not map_vlans.map_vlans(network_map):
            set_hint(self.status_label, "That map has no VLANs. They're read from switches when a map is crawled "
                                        "(maps made by NOMAD before 1.16 don't have them: map again).", "warning")
            return
        self.import_from_map(network_map, name)

    def highlight_on_map(self):
        vlan, domain = self.selected_vlan(), self.domain()
        page = getattr(self.window, "netmap_tab", None)
        if vlan is None or page is None:
            return
        if page.network_map is None:
            set_hint(self.status_label, "Open a map on the Network Map page first.", "warning")
            return
        self.window.navigator.setCurrentWidget(page)
        on_map = self.map_vlans_for(domain)
        # The map's own spelling of the VTP domain (matched without regard to case); any domain if it has none
        mapped = next((item.domain for item in (on_map or {}).values() if item.domain), None)
        page.highlight_vlan(vlan.vlan, mapped)

    def show_in_ipam(self):
        vlan, domain = self.selected_vlan(), self.domain()
        if vlan is None or not vlan.subnets or not domain.network_id:
            return
        cidr = vlan.subnets[0]
        if len(vlan.subnets) > 1:
            menu = QMenu(self)
            for subnet in vlan.subnets:
                menu.addAction(subnet).setData(subnet)
            chosen = menu.exec_(self.ipam_button.mapToGlobal(self.ipam_button.rect().bottomLeft()))
            if chosen is None:
                return
            cidr = chosen.data()
        self.window.ipam_tab.go_to_subnet(self.source_key, domain.network_id, cidr)

    # ----------------------------------------------------------------- VLANs

    def fill_table(self, select=None):
        source, domain = self.source(), self.domain()
        selected = select if select is not None else [vlan.vlan for vlan in self.selected_vlans()]
        self.vlans = source.vlans.vlans(domain.id) if domain is not None else []
        subnets = {}
        if domain is not None and domain.network_id:
            try:
                subnets = {subnet.cidr: subnet for subnet in source.ipam.subnets(domain.network_id)}
            except IpamError:
                subnets = {}
        pending = source.vlans.pending_numbers(domain.id) if domain is not None and source.key == TEAM else set()
        on_map = self.map_vlans_for(domain)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.vlans))
        for row, vlan in enumerate(self.vlans):
            block = range_for(domain, vlan.vlan)
            status = STATUSES.get(vlan.status, vlan.status) + (" (waiting to be sent)" if vlan.vlan in pending else "")
            gateways = [subnets[cidr].gateway for cidr in vlan.subnets if cidr in subnets and subnets[cidr].gateway]
            subnet_text = ", ".join(cidr if cidr in subnets else f"{cidr} (not in IPAM)" for cidr in vlan.subnets)
            map_text, map_color = self.map_text(on_map, vlan)
            interfaces = ", ".join(f"{address} on {device} {port}" for address, _, port, device
                                   in self.interfaces_for(domain, vlan.vlan, on_map))
            values = [(str(vlan.vlan), vlan.vlan), (vlan.name, None), (status, None),
                      (f"{block['first']}-{block['last']} {block['name']}".strip() if block else "", None),
                      (subnet_text, None), (", ".join(gateways), None), (interfaces, None), (map_text, None),
                      (vlan.description, None), (f"{vlan.modified[:16].replace('T', ' ')} by {vlan.modified_by}",
                                                 vlan.modified)]
            for column, (text, sort_key) in enumerate(values):
                item = SortableTableItem(text, sort_key, vlan if column == 0 else None)
                item.setToolTip(text)
                if column == 2 and vlan.status in STATUS_COLORS:
                    item.setForeground(QColor(COLORS[STATUS_COLORS[vlan.status]]))
                if column == 2 and vlan.vlan in pending:
                    item.setForeground(QColor(COLORS["warning"]))
                if column == 1 and name_problem(vlan.name):
                    item.setToolTip(f"{vlan.name}: {name_problem(vlan.name)}")
                if column == COL_MAP and map_color:
                    item.setForeground(QColor(COLORS[map_color]))
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        self.table_filter.apply()
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 0)
            if item is not None and item.data_object.vlan in selected:
                self.table.selectRow(row)
        self.show_domain(source, domain, on_map)
        self.on_selection()

    def interfaces_for(self, domain, number, on_map=None):
        """The open map's VLAN interfaces (SVIs, and routers' subinterfaces) for a VLAN in the domain, as
        [(address, prefix, port, device name)]."""
        on_map = self.map_vlans_for(domain) if on_map is None else on_map
        item = (on_map or {}).get(number)
        if item is None:
            return []
        devices = self.open_map().devices
        return [(gateway.address, gateway.prefix, gateway.port,
                 devices[gateway.device].label if gateway.device in devices else gateway.device)
                for gateway in item.gateways]

    @staticmethod
    def map_text(on_map, vlan):
        """(What the open map says of the VLAN, its color or None)."""
        if on_map is None:
            return "", None
        item = on_map.get(vlan.vlan)
        if item is None or not item.switches:
            return ("not on the switches mapped", "muted") if vlan.status == "active" else ("", None)
        text = f"{len(item.switches)} switch{'es' if len(item.switches) != 1 else ''}"
        if item.access_ports:
            text += f", {len(item.access_ports)} access port{'s' if len(item.access_ports) != 1 else ''}"
        others = [name for name in item.names if name and name != vlan.name]  # What switches call it instead
        if others:
            return f"{text} ({'named' if vlan.name not in item.names else 'also named'} {', '.join(others)})", \
                "warning"
        return text, None

    def show_domain(self, source, domain, on_map):
        if domain is None and self.no_domain_network:
            integration = hub(self.window)
            name = integration.network_name(self.no_domain_network) if integration is not None else ""
            self.domain_label.setText(f"<b>{html.escape(name or 'The network')}</b> (the network the other pages are "
                                      "on) has no VLAN domain yet. New Domain for it makes one, whose VLANs carry its "
                                      "subnets; or choose another network's domain above.")
            return
        if domain is None:
            if source is None or not self.domain_combo.count():
                self.domain_label.setText("No VLAN domains yet. New Domain makes one (a Tribe one is shared with "
                                          "everyone through the IPAM server), or bring in what a network map found "
                                          "with Domain > Bring in VLANs from a Network Map.")
            else:
                self.domain_label.setText("")
            return
        parts = [f"<b>{html.escape(domain.name)}</b> ({source.label})", f"{len(self.vlans)} VLANs"]
        if domain.network_id:
            try:
                parts.append(f"subnets from IPAM network {html.escape(source.ipam.network(domain.network_id).name)}")
            except IpamError:
                parts.append("its IPAM network was deleted")
        else:
            parts.append("no IPAM network")
        if domain.vtp_domain:
            parts.append(f"VTP domain {html.escape(domain.vtp_domain)}")
        if domain.ranges:
            parts.append("ranges " + ", ".join(html.escape(f"{block['first']}-{block['last']} {block['name']}".strip())
                                               for block in domain.ranges))
        if on_map is not None:
            parts.append(f"the open map has {len(on_map)} of its VLANs")
        if domain.description:
            parts.append(html.escape(domain.description))
        self.domain_label.setText(" · ".join(parts))

    def show_counts(self, shown, total):
        if self.table_filter.active:
            set_hint(self.status_label, f"Showing {shown} of {total} VLANs.", "info")

    def selected_vlans(self):
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        found = []
        for row in rows:
            item = self.table.item(row, 0)
            if item is not None and item.data_object is not None:
                found.append(item.data_object)
        return found

    def selected_vlan(self):
        selected = self.selected_vlans()
        return selected[0] if len(selected) == 1 else None

    def on_selection(self):
        self.update_buttons()
        vlan = self.selected_vlan()
        self.details.setHtml(self.vlan_html(vlan) if vlan is not None else self.help_html())

    def help_html(self):
        return ("<p>Select a VLAN to see its subnets (from IPAM) and where the open network map found it.</p>"
                "<p>Domain &gt; Bring in VLANs from a Network Map adds what a crawl found on the switches; Domain "
                "&gt; Link Subnets Named for VLANs links IPAM subnets whose names say which VLAN they're in "
                "(such as Vlan 6), without changing them.</p>"
                "<p>Highlight on Map shows a VLAN on the map: the switches and links carrying it.</p>")

    def vlan_html(self, vlan):
        escape = html.escape
        source, domain = self.source(), self.domain()
        parts = [f"<h3>VLAN {vlan.vlan} {escape(vlan.name)}</h3>",
                 f"<p>{escape(STATUSES.get(vlan.status, vlan.status))}"
                 + (f" &middot; {escape(vlan.description)}" if vlan.description else "") + "</p>"]
        problem = name_problem(vlan.name)
        if problem:
            parts.append(f"<p style='color:{COLORS['warning']}'>{escape(problem)}</p>")
        if vlan.subnets:
            subnets = {}
            if domain.network_id:
                try:
                    subnets = {subnet.cidr: subnet for subnet in source.ipam.subnets(domain.network_id)}
                except IpamError:
                    pass
            integration = hub(self.window)
            key = f"{self.source_key}:{domain.network_id}" if domain.network_id else ""
            facts = integration.facts(key) if integration is not None and key else None
            parts.append("<h4>Subnets</h4><table>")
            for cidr in vlan.subnets:
                subnet = subnets.get(cidr)
                what = "not in IPAM now" if subnet is None else ", ".join(
                    part for part in (subnet.name, f"gateway {subnet.gateway}" if subnet.gateway else "") if part)
                parts.append(f"<tr><td>{escape(cidr)}&nbsp;</td><td>{escape(what)}</td></tr>")
                row = facts.row(cidr) if facts is not None else None
                if row is not None:
                    status = {"problem": "a problem", "warning": "a warning"}.get(row.severity, "OK")
                    color = {"problem": "error", "warning": "warning"}.get(row.severity)
                    status = f"<span style='color:{COLORS[color]}'>{status}</span>" if color else status
                    links = integration.subnet_links(key, cidr, row, skip=("vlan",))
                    parts.append(f"<tr><td></td><td>{escape(row.role.name)} &middot; placement: {status} &middot; "
                                 + " &middot; ".join(links) + "</td></tr>")
            parts.append("</table>")
        on_map = self.map_vlans_for(domain)
        item = on_map.get(vlan.vlan) if on_map is not None else None
        if item is not None:
            network_map = self.open_map()
            label = (lambda key: network_map.devices[key].label if key in network_map.devices else key)
            parts.append("<h4>On the open map</h4><table>")
            rows = [("Switches", ", ".join(label(key) for key in item.switches[:12])
                     + (f" and {len(item.switches) - 12} more" if len(item.switches) > 12 else "")),
                    ("Named", ", ".join(f"{name or '(no name)'} ({len(keys)})" for name, keys in item.names.items())),
                    ("Access ports", str(len(item.access_ports)) if item.access_ports else ""),
                    ("Trunk ports", str(len(item.trunk_ports)) if item.trunk_ports else ""),
                    ("Gateways", ", ".join(f"{gateway.address}/{gateway.prefix} on {label(gateway.device)}"
                                           for gateway in item.gateways)),
                    ("Hosts", str(item.hosts) if item.hosts else "")]
            for title, value in rows:
                if value:
                    parts.append(f"<tr><td><b>{title}</b>&nbsp;</td><td>{escape(value)}</td></tr>")
            parts.append("</table>")
        parts.append(f"<p>Last changed {escape(vlan.modified[:16].replace('T', ' '))} UTC by "
                     f"{escape(vlan.modified_by)}.</p>")
        return "".join(parts)

    def update_buttons(self):
        source, domain = self.source(), self.domain()
        selected = self.selected_vlans()
        vlans_ok = domain is not None and source.can_edit_vlans
        domains_ok = domain is not None and source.can_edit_domains
        self.add_button.setEnabled(vlans_ok)
        self.next_free_button.setEnabled(vlans_ok)
        self.edit_button.setEnabled(vlans_ok and len(selected) == 1)
        self.delete_button.setEnabled(vlans_ok and bool(selected))
        self.history_button.setEnabled(len(selected) == 1)
        single = selected[0] if len(selected) == 1 else None
        self.ipam_button.setEnabled(single is not None and bool(single.subnets) and bool(domain.network_id))
        self.map_button.setEnabled(single is not None and self.open_map() is not None)
        self.domain_button.setEnabled(domain is not None)
        self.edit_domain_action.setEnabled(domains_ok)
        self.delete_domain_action.setEnabled(domains_ok)
        self.link_action.setEnabled(vlans_ok and bool(domain.network_id))
        self.import_action.setEnabled(bool(self.sources()))

    def show_menu(self, position):
        selected = self.selected_vlans()
        if not selected:
            return
        menu = QMenu(self)
        for button in (self.edit_button, self.delete_button, self.history_button, self.ipam_button, self.map_button):
            action = menu.addAction(button.text(), button.click)
            action.setEnabled(button.isEnabled())
        placement = menu.addAction("Show Subnet in Subnet Placement")
        placement.setEnabled(self.ipam_button.isEnabled())
        if menu.exec_(self.table.viewport().mapToGlobal(position)) is placement:
            self.show_in_placement()

    def roles_of(self, source):
        """For the VLAN dialogs: what each subnet of a network is for ({CIDR: roles.RoleInfo}), from the open map and
        the roles set on the Subnet Placement page."""
        def roles(network_id):
            if not network_id:
                return {}
            try:
                return subnet_roles(source.ipam, PlacementStore(getattr(source.ipam, "copy", source.ipam)),
                                    source.vlans, network_id, self.open_map())
            except IpamError:
                return {}
        return roles

    def interface_finder(self, domain):
        """For the VLAN dialog: a VLAN number's interfaces on the open map."""
        on_map = self.map_vlans_for(domain)
        return lambda number: self.interfaces_for(domain, number, on_map)

    def add_new_vlan(self):
        self.add_vlan()

    def add_vlan(self, number=None):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        dialog = VlanDialog(self, source, domain, number=number, interfaces_of=self.interface_finder(domain),
                            roles_of=self.roles_of(source))
        if dialog.exec_():
            self.after_change(source)
            self.fill_table(select=[dialog.result_item.vlan] if dialog.result_item else None)

    def add_next_free(self):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        dialog = NextFreeDialog(self, source, domain)
        if dialog.exec_() and dialog.number() is not None:
            self.add_vlan(dialog.number())

    def edit_vlan(self, *_):
        source, domain, vlan = self.source(), self.domain(), self.selected_vlan()
        if vlan is None or not source.can_edit_vlans:
            return
        dialog = VlanDialog(self, source, domain, vlan, interfaces_of=self.interface_finder(domain),
                            roles_of=self.roles_of(source))
        if dialog.exec_():
            self.after_change(source)
            self.fill_table()

    def delete_vlans(self):
        source, domain = self.source(), self.domain()
        selected = self.selected_vlans()
        if not selected:
            return
        listed = ", ".join(str(vlan.vlan) for vlan in selected[:10]) + ("..." if len(selected) > 10 else "")
        moving = self.moves_using(domain, {vlan.vlan for vlan in selected})
        note = (" A subnet move on the Subnet Placement page uses " + "; ".join(moving) + ": it keeps that VLAN "
                "number.") if moving else ""
        if QMessageBox.question(self, "Delete VLANs", f"Delete VLAN{'s' if len(selected) > 1 else ''} {listed} from "
                                f"{domain.name}? IPAM's subnets aren't touched.{note}") != QMessageBox.Yes:
            return
        try:
            for vlan in selected:
                source.vlans.delete_vlan(domain.id, vlan.vlan)
        except IpamError as error:
            self.report(error, "Deleting")
        self.after_change(source)
        self.fill_table(select=[])

    def moves_using(self, domain, numbers):
        """Subnet moves under way to or from these VLANs of the domain, as text."""
        if not domain.network_id:
            return []
        from ..ipam.placement import PlacementStore
        source = self.source()
        moves = PlacementStore(getattr(source.ipam, "copy", source.ipam)).moves(domain.network_id, open_only=True)
        return [f"{move.cidr} (from VLAN {move.from_vlan} to {move.to_vlan})" for move in moves
                if (move.from_domain_id == domain.id and move.from_vlan in numbers)
                or (move.to_domain_id == domain.id and move.to_vlan in numbers)]

    def show_vlan_history(self):
        from .ipam_history_dialog import HistoryDialog
        source, domain, vlan = self.source(), self.domain(), self.selected_vlan()
        if vlan is not None:
            HistoryDialog(self, source.ipam, domain.id, "vlan", vlan.vlan, self.history_note()).exec_()

    def export_csv(self):
        source, domain = self.source(), self.domain()
        if domain is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export VLANs", f"{domain.name} VLANs.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as file:
                writer = csv.writer(file)
                writer.writerow(["VLAN", "Name", "Status", "Range", "Subnets", "Description", "Last Changed",
                                 "Changed By"])
                for vlan in source.vlans.vlans(domain.id):
                    block = range_for(domain, vlan.vlan)
                    writer.writerow([vlan.vlan, vlan.name, STATUSES.get(vlan.status, vlan.status),
                                     f"{block['first']}-{block['last']} {block['name']}".strip() if block else "",
                                     " ".join(vlan.subnets), vlan.description, vlan.modified, vlan.modified_by])
        except OSError as error:
            set_hint(self.status_label, f"Couldn't export: {error}", "error")
            return
        set_hint(self.status_label, f"Exported {domain.name}'s VLANs to {path}.", "success")

    # ----------------------------------------------------------------- The tribe

    def after_change(self, source):
        """A change was made: tribe ones made offline go with the next sync (which also tells other laptops)."""
        if source is not None and source.key == TEAM:
            self.window.ipam_tab.sync_now()
        self.show_status()
        integration = hub(self.window)
        if integration is not None:
            integration.forget()  # The subnets' VLANs changed

    def on_tribe_synced(self):
        """The IP Addresses page synced with the server: show what came (if this page has been opened)."""
        if self.domain_combo.count() or self.isVisible():
            self.fill_domains()

    def report(self, error, action="That change"):
        if isinstance(error, ServerUnreachable):
            self.show_status()
        QMessageBox.warning(self, "Not Changed", f"{action} wasn't made. {error}")
        if isinstance(error, (ConflictError, TeamKeyError)):
            self.window.ipam_tab.sync_now()

    def review_refused(self):
        source = self.source(TEAM)
        if source is None:
            return
        VlanRefusedDialog(self, source.vlans).exec_()
        self.after_change(source)
        self.fill_table()

    def show_status(self):
        """The tribe's state, as it matters for VLANs: whether tribe domains can be changed now, and changes
        waiting."""
        team = self.window.ipam_tab.team
        self.update_buttons()
        if team is None:
            self.server_label.setText("")
            self.refused_button.setVisible(False)
            return
        vlans = TeamVlanStore(team)
        refused = len(vlans.refused())
        self.refused_button.setText(f"Review Refused VLAN Changes ({refused})")
        self.refused_button.setVisible(bool(refused))
        waiting = vlans.pending_count()
        synced = f"synced {ago(time.time() - team.last_sync)}" if team.last_sync else "not synced yet"
        if waiting:
            synced += f"; {waiting} VLAN change{'s' if waiting != 1 else ''} waiting to be sent"
        if not team.server_keeps_vlans:
            set_hint(self.server_label, "Tribe: the IPAM server needs updating to keep VLANs", "warning")
        elif team.online:
            set_hint(self.server_label, f"● Tribe · {synced}", "success")
        elif team.last_error:
            set_hint(self.server_label, f"● Tribe offline · {synced} (VLANs can still be changed)", "warning")
        else:
            set_hint(self.server_label, f"● Tribe · connecting ({synced})", "info")

