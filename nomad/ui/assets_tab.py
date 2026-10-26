"""Assets page (Network Management > Assets): every piece of hardware on the network, with its hostname, model,
serial number and software version kept together, from the network map's crawls, servers' and phones' own answers,
and what's typed in by hand.

The serial number is what an asset is. Bringing in a map (by itself after each crawl, or by Bring In from Map) finds
each chassis, stack member, phone and (when parts are tracked) module, power supply, fan and transceiver, and keeps
the list in step: renamed and upgraded hardware is changed, new hardware added, and hardware swapped for other
hardware (an RMA) marked Replaced. Every change is in the asset's history.

Assets come from the same two places as IPAM's networks: the tribe's, shared through the IPAM server (kept in the copy
the IP Addresses page syncs, so they can be read and changed offline: changes wait until the server is back), and
this computer's own (Local).
"""
import csv
import datetime
import html
import logging
import re
import time

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, QLabel, \
    QLineEdit, QMenu, QMessageBox, QPushButton, QSplitter, QTableWidget, QTextBrowser, QVBoxLayout, QWidget

from .. import hostinfo
from ..ipam import asset_compare
from ..ipam.asset_team import TeamAssetStore
from ..ipam.assets import DEVICE_KINDS, IN_SERVICE, KINDS, OUT_OF_SERVICE, PHONE, SERVER, STATUSES, AssetStore, \
    asset_history, is_part, label as asset_label, problems
from ..ipam.client import ServerUnreachable, TeamKeyError
from ..ipam.server import ConflictError
from ..ipam.store import IpamError
from ..netmap import hardware, store as map_store
from ..oui import format_mac
from .asset_dialogs import AssetDialog, AssetImportDialog, AssetRefusedDialog, ReadDetailsDialog, Source, ValueDialog
from .common import SortableTableItem, add_action, add_submenu, set_hint
from .integration import MAP_DEVICE, hub, link
from .ipam_tab import ago
from .table_filter import TableFilter
from .theme import COLORS

log = logging.getLogger(__name__)

COLUMNS = ["Hostname", "Slot", "Kind", "Model", "Serial", "Software", "Management IP", "MAC", "Location", "Status",
           "Asset Tag", "Owner", "Warranty Ends", "Last Seen", "Problems"]
(COL_HOSTNAME, COL_SLOT, COL_KIND, COL_MODEL, COL_SERIAL, COL_SOFTWARE, COL_IP, COL_MAC, COL_LOCATION, COL_STATUS,
 COL_TAG, COL_OWNER, COL_WARRANTY, COL_SEEN, COL_PROBLEMS) = range(len(COLUMNS))
# A whole MAC typed in the filter box, written any of the usual ways: 00-1B-17-00-01-00, 00:1b:17:00:01:00,
# 001b.1700.0100, 001b17000100
WHOLE_MAC = re.compile(r"^(?:[0-9A-Fa-f]{2}([-:])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}"
                       r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})$")
LOCAL, TEAM = "local", "team"  # As the IP Addresses page names where networks come from
EVERYTHING, DEVICES, PROBLEMS, SERVING, NOT_SERVING = "all", "devices", "problems", "in", "out"
SHOWS = {EVERYTHING: "Everything", DEVICES: "Devices (no parts)", PROBLEMS: "With problems",
         SERVING: "In service", NOT_SERVING: "Out of service (spare, repair, replaced, retired)"}
STATUS_COLORS = {"spare": "link", "repair": "warning", "replaced": "muted", "retired": "muted"}
HISTORY_SHOWN = 8


class AssetsTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.source_key = ""
        self.saved_source = ""
        self.assets = []
        self.found_problems = {}
        self.review = None  # (Source key, [AssetChange]) left to look at after bringing in a crawl by itself
        self.init_ui()
        window.ipam_tab.tribe_synced.connect(self.on_tribe_synced)
        page = getattr(window, "netmap_tab", None)
        if page is not None:
            page.hardware_found.connect(self.on_hardware_found)
            page.map_shown.connect(self.on_map_shown)

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("Assets:"))
        self.source_combo = QComboBox()
        self.source_combo.setMinimumWidth(180)
        self.source_combo.setToolTip("The tribe's asset list is shared with everyone through the IPAM server; Local is "
                                     "this computer's own.")
        top.addWidget(self.source_combo)
        top.addWidget(QLabel("Show:"))
        self.show_combo = QComboBox()
        for key, name in SHOWS.items():
            self.show_combo.addItem(name, key)
        for key, name in DEVICE_KINDS.items():
            self.show_combo.addItem(f"{name}s" if not name.endswith("s") else name, f"kind:{key}")
        self.show_combo.addItem("Parts", "parts")
        top.addWidget(self.show_combo)
        self.parts_check = QCheckBox("Track parts")
        self.parts_check.setChecked(True)
        self.parts_check.setToolTip("Bring in modules, power supplies, fans and transceivers (each with its own serial "
                                    "number) as assets of their own, in the chassis they're in. Untick to keep just "
                                    "the chassis, phones and servers: parts already listed stay.")
        top.addWidget(self.parts_check)
        self.auto_check = QCheckBox("Bring in after each crawl")
        self.auto_check.setChecked(True)
        self.auto_check.setToolTip("When the Network Map finishes a crawl (or Read Hardware Again), bring its hardware "
                                   "into this asset list by itself: new hardware, renames, upgrades and replacements. "
                                   "Changes that need a look (a location typed by hand, hardware marked spare but "
                                   "seen, a serial number on two devices) wait for Review.")
        top.addWidget(self.auto_check)
        top.addStretch()
        self.review_button = QPushButton()
        self.review_button.setVisible(False)
        self.review_button.clicked.connect(self.show_review)
        top.addWidget(self.review_button)
        self.refused_button = QPushButton()
        self.refused_button.setVisible(False)
        self.refused_button.clicked.connect(self.review_refused)
        top.addWidget(self.refused_button)
        self.server_label = QLabel()
        top.addWidget(self.server_label)
        layout.addLayout(top)

        self.summary_label = QLabel()
        self.summary_label.setWordWrap(True)
        self.summary_label.setTextFormat(Qt.RichText)
        layout.addWidget(self.summary_label)
        self.search_input = QLineEdit()
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setPlaceholderText("Filter the assets: hostname, serial number, model, version, a MAC "
                                             "(any of a switch's own finds it) or any column (Ctrl+F)")
        layout.addWidget(self.search_input)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.mac_owners, self.searched_mac = None, ""  # A MAC searched for: {asset id: how}, see on_search
        self.table_filter = TableFilter(self.table, self.show_counts)
        self.table_filter.columns.widest = {COL_HOSTNAME: 260, COL_SLOT: 260, COL_MODEL: 220, COL_LOCATION: 260,
                                            COL_PROBLEMS: 360}
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.anchorClicked.connect(self.open_link)
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        splitter.addWidget(self.details)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([1000, 320])
        layout.addWidget(splitter, 1)

        buttons = QHBoxLayout()
        self.import_button = QPushButton("Bring In from Map...")
        self.import_button.setProperty("accent", True)
        self.import_button.setToolTip("Compare the asset list with the hardware the open network map found (or a map "
                                      "file), and bring in what's new or changed.")
        self.read_button = QPushButton("Read Hardware Again")
        self.read_button.setToolTip("Ask every device on the open map that answers SNMP for its chassis, parts, "
                                    "serial numbers and software (a map made before NOMAD read them has none), then "
                                    "bring that in.")
        self.details_button = QPushButton("Read Server/Phone Details...")
        self.details_button.setToolTip("Ask Windows servers (WMI), Linux servers (SSH) or Cisco IP phones (their web "
                                       "page) for their maker, model, serial number and software.")
        self.add_button = QPushButton("Add...")
        self.edit_button = QPushButton("Edit...")
        self.delete_button = QPushButton("Delete")
        self.history_button = QPushButton("History...")
        self.changes_button = QPushButton("All Changes...")
        self.changes_button.setToolTip("Every change to the asset list, newest first: what was added, renamed, "
                                       "upgraded or replaced, by whom.")
        self.export_button = QPushButton("Export...")
        self.map_button = QPushButton("Show on Map")
        for button in (self.import_button, self.read_button, self.details_button, self.add_button, self.edit_button,
                       self.delete_button, self.history_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(self.changes_button)
        buttons.addWidget(self.export_button)
        buttons.addWidget(self.map_button)
        layout.addLayout(buttons)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.source_combo.currentIndexChanged.connect(self.on_source_chosen)
        self.show_combo.currentIndexChanged.connect(self.fill_table)
        self.search_input.textChanged.connect(self.on_search)
        self.table.itemSelectionChanged.connect(self.on_selection)
        self.table.itemDoubleClicked.connect(self.edit_asset)
        self.table.customContextMenuRequested.connect(self.show_menu)
        self.import_button.clicked.connect(self.bring_in_from_map)
        self.read_button.clicked.connect(self.read_hardware_again)
        self.details_button.clicked.connect(self.ask_details)
        self.add_button.clicked.connect(self.add_asset)
        self.edit_button.clicked.connect(self.edit_asset)
        self.delete_button.clicked.connect(self.delete_assets)
        self.history_button.clicked.connect(self.show_history)
        self.changes_button.clicked.connect(self.show_changes)
        self.export_button.clicked.connect(self.export)
        self.map_button.clicked.connect(self.show_on_map)
        self.update_buttons()

    # ----------------------------------------------------------------- Page interface

    def showEvent(self, event):
        super().showEvent(event)
        if self.window.ipam_tab.open_store():
            self.fill_sources()

    def focus_find(self):
        self.search_input.setFocus()
        self.search_input.selectAll()

    def save_settings(self, settings):
        if self.source_key:
            settings.setValue("assets/source", self.source_key)
        settings.setValue("assets/track_parts", self.parts_check.isChecked())
        settings.setValue("assets/auto", self.auto_check.isChecked())
        settings.setValue("assets/show", self.show_combo.currentData())

    def restore_settings(self, settings):
        self.saved_source = settings.value("assets/source", "", str)
        self.parts_check.setChecked(settings.value("assets/track_parts", True, bool))
        self.auto_check.setChecked(settings.value("assets/auto", True, bool))
        index = self.show_combo.findData(settings.value("assets/show", EVERYTHING, str))
        self.show_combo.setCurrentIndex(max(0, index))

    def shutdown(self):
        pass  # The stores are the IP Addresses page's, which closes them

    # ----------------------------------------------------------------- Where assets are kept

    def sources(self):
        """[Source]: the tribe's (when connected) then this computer's."""
        page = self.window.ipam_tab
        if page.local_store is None:
            return []
        found = []
        team = page.team
        if team is not None:
            found.append(Source(TEAM, "Tribe", team, TeamAssetStore(team),
                                can_edit=team.server_keeps_assets and not team.key_rejected))
        found.append(Source(LOCAL, "Local", page.local_store, AssetStore(page.local_store)))
        return found

    def source(self, key=None):
        key = key or self.source_key
        return next((source for source in self.sources() if source.key == key), None)

    def fill_sources(self):
        select = self.source_key or self.saved_source
        self.source_combo.blockSignals(True)
        self.source_combo.clear()
        for source in self.sources():
            count = source.assets.count()
            self.source_combo.addItem(f"{source.label}  ({count})", source.key)
        index = self.source_combo.findData(select)
        if index < 0:
            index = self.source_combo.findData(TEAM)  # The tribe's, when there is one
        self.source_combo.setCurrentIndex(max(index, 0))
        self.source_combo.blockSignals(False)
        self.on_source_chosen()

    def on_source_chosen(self):
        self.source_key = self.source_combo.currentData() or ""
        self.fill_table()
        self.show_status()

    def ensure_open(self):
        """Open the IPAM databases (and fill the list) if they aren't yet. Returns whether they're open."""
        if not self.window.ipam_tab.open_store():
            return False
        if not self.source_combo.count():
            self.fill_sources()
        return self.source() is not None

    # ----------------------------------------------------------------- The table

    def chosen_assets(self, assets):
        shown = self.show_combo.currentData() or EVERYTHING
        if shown == DEVICES:
            return [asset for asset in assets if not is_part(asset.kind)]
        if shown == PROBLEMS:
            return [asset for asset in assets if asset.id in self.found_problems]
        if shown == SERVING:
            return [asset for asset in assets if asset.status == IN_SERVICE]
        if shown == NOT_SERVING:
            return [asset for asset in assets if asset.status in OUT_OF_SERVICE]
        if shown == "parts":
            return [asset for asset in assets if is_part(asset.kind)]
        if shown.startswith("kind:"):
            return [asset for asset in assets if asset.kind == shown[5:]]
        return assets

    def fill_table(self, *_, select=None):
        source = self.source()
        selected = select if select is not None else [asset.id for asset in self.selected_assets()]
        everything = source.assets.assets() if source is not None else []
        self.found_problems = problems(everything)
        by_id = {asset.id: asset for asset in everything}
        self.assets = self.chosen_assets(everything)
        pending = source.assets.pending_ids() if source is not None and source.key == TEAM else set()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(self.assets))
        for row, asset in enumerate(self.assets):
            chassis = by_id.get(asset.parent_id)
            hostname = asset.hostname or (chassis.hostname if chassis is not None else "")
            status = STATUSES.get(asset.status, asset.status) + (" (waiting to be sent)" if asset.id in pending else "")
            found = self.found_problems.get(asset.id, [])
            values = [(hostname, (hostname.lower(), is_part(asset.kind), asset.slot)), (asset.slot, None),
                      (KINDS.get(asset.kind, asset.kind), None), (asset.model, None), (asset.serial, None),
                      (asset.software, None), (asset.mgmt_ip, ip_sort_key(asset.mgmt_ip)), (asset.mac, None),
                      (asset.location, None),
                      (status, None), (asset.asset_tag, None), (asset.owner, None), (asset.warranty_end, None),
                      (asset.last_seen, None), ("; ".join(found), None)]
            for column, (text, sort_key) in enumerate(values):
                item = SortableTableItem(text, sort_key, asset if column == 0 else None)
                item.setToolTip(text)
                if column == COL_STATUS and (asset.status in STATUS_COLORS or asset.id in pending):
                    item.setForeground(QColor(COLORS["warning" if asset.id in pending
                                                      else STATUS_COLORS[asset.status]]))
                if column == COL_PROBLEMS and found:
                    item.setForeground(QColor(COLORS["warning"]))
                if column == COL_HOSTNAME and is_part(asset.kind):
                    item.setForeground(QColor(COLORS["muted"]))
                self.table.setItem(row, column, item)
        self.table.setSortingEnabled(True)
        if self.searched_mac:
            self.mac_owners = self.assets_with_mac(self.searched_mac)
        self.table_filter.apply()
        self.select_rows(set(selected))
        self.show_summary(source, everything)
        self.on_selection()

    def show_summary(self, source, everything):
        if source is None:
            self.summary_label.setText("")
            return
        if not everything:
            self.summary_label.setText(
                "No assets yet. <b>Bring In from Map</b> adds the hardware the open network map found (each chassis "
                "and stack member, phone and part, with its serial number and software); after that, each crawl "
                "brings in what changed by itself. Add records hardware by hand (a spare on the shelf).")
            return
        devices = [asset for asset in everything if not is_part(asset.kind)]
        serving = sum(1 for asset in devices if asset.status == IN_SERVICE)
        parts = len(everything) - len(devices)
        text = [f"<b>{len(devices)} devices</b> ({serving} in service)"]
        if parts:
            text.append(f"{parts} parts")
        models = {}
        for asset in devices:
            if asset.model:
                models[asset.model] = models.get(asset.model, 0) + 1
        if models:
            top = sorted(models.items(), key=lambda item: (-item[1], item[0]))[:4]
            text.append("most: " + ", ".join(f"{count} {html.escape(model)}" for model, count in top))
        if self.found_problems:
            text.append(f"<span style='color:{COLORS['warning']}'>{len(self.found_problems)} with problems</span>")
        self.summary_label.setText(" · ".join(text))

    def show_counts(self, shown, total):
        if self.mac_owners is not None:
            if not self.mac_owners:
                set_hint(self.status_label, f"No asset has MAC {self.searched_mac}, and no switch on the open map has "
                                            "it as one of its own.", "info")
            else:
                set_hint(self.status_label, f"MAC {self.searched_mac}: {self.mac_owners_text()}.", "info")
        elif self.table_filter.active:
            set_hint(self.status_label, f"Showing {shown} of {total} assets.", "info")

    # ----------------------------------------------------------------- Searching by MAC

    def on_search(self, text):
        """The filter box: rows with each word, or for a whole MAC (written any way) the assets it's the MAC of: a
        phone's or server's, a chassis' base MAC, or (by the open map) one of a chassis' ports' or VLAN interfaces'."""
        mac = format_mac(text) if WHOLE_MAC.match(text.strip()) else ""
        self.searched_mac = mac
        self.mac_owners = self.assets_with_mac(mac) if mac else None
        self.table_filter.row_test = self.shows_mac_owner if mac else None
        self.table_filter.set_text("" if mac else text)

    def shows_mac_owner(self, row):
        item = self.table.item(row, 0)
        return item is not None and item.data_object is not None and item.data_object.id in (self.mac_owners or {})

    def mac_owners_text(self):
        found = []
        for asset_id, how in self.mac_owners.items():
            asset = self.find_asset(asset_id)
            if asset is not None:
                found.append(f"{asset_label(asset)}{'' if how == 'own' else ' (' + how + ')'}")
        return ", ".join(found)

    def find_asset(self, asset_id):
        source = self.source()
        return source.assets.find(asset_id) if source is not None else None

    def assets_with_mac(self, mac):
        """{asset id: how the MAC is its ("own", or which interface of it)} for a MAC (as format_mac writes it)."""
        source = self.source()
        if source is None:
            return {}
        everything = source.assets.assets()
        found = {asset.id: "own" for asset in everything if asset.mac == mac}
        page = getattr(self.window, "netmap_tab", None)
        network_map = getattr(page, "network_map", None)
        if network_map is None:
            return found
        by_place = {}
        for asset in everything:
            if asset.map_device and not is_part(asset.kind) and asset.status != asset_compare.REPLACED:
                by_place.setdefault((asset.map_device, asset.slot), []).append(asset)
        for key, device in network_map.devices.items():
            members = hardware.chassis(device.parts)
            for part in members:
                if not hardware.owns_mac(part, mac):
                    continue
                how = "own" if mac == part.get("mac") else "one of its ports' or VLAN interfaces' MACs"
                for asset in by_place.get((key, asset_compare.chassis_slot(part, len(members))), []):
                    found.setdefault(asset.id, how)
            if not members and device.mac == mac:  # A device seen only by its neighbors: their LLDP's
                for asset in by_place.get((key, ""), []):
                    found.setdefault(asset.id, "own")
        for host in network_map.hosts:  # A phone or server on the map recorded before its MAC was
            if host.mac == mac and host.serial:
                asset = source.assets.by_serial(host.serial)
                if asset is not None:
                    found.setdefault(asset.id, "own")
        return found

    def selected_assets(self):
        rows = sorted({index.row() for index in self.table.selectedIndexes()})
        found = []
        for row in rows:
            item = self.table.item(row, 0)
            if item is not None and item.data_object is not None and not self.table.isRowHidden(row):
                found.append(item.data_object)
        return found

    def selected_asset(self):
        selected = self.selected_assets()
        return selected[0] if len(selected) == 1 else None

    def select_rows(self, ids):
        """Select the rows of these assets (and only them). Returns the rows."""
        self.table.clearSelection()
        rows = [row for row in range(self.table.rowCount())
                if self.table.item(row, 0) is not None and self.table.item(row, 0).data_object.id in ids]
        mode = self.table.selectionMode()
        self.table.setSelectionMode(QAbstractItemView.MultiSelection)  # So selectRow adds rather than replaces
        for row in rows:
            self.table.selectRow(row)
        self.table.setSelectionMode(mode)
        return rows

    def select_ids(self, ids):
        """Select these assets and scroll to them, clearing a filter that hides them."""
        rows = self.select_rows(ids)
        if any(self.table.isRowHidden(row) for row in rows):
            self.search_input.clear()
            self.table_filter.clear()
        if rows:
            self.table.scrollToItem(self.table.item(rows[0], 0))

    def on_selection(self):
        self.update_buttons()
        asset = self.selected_asset()
        self.details.setHtml(self.asset_html(asset) if asset is not None else self.help_html())

    def help_html(self):
        return ("<p>Select an asset to see everything about it, its parts and its history.</p>"
                "<p>An asset is its serial number: found under another hostname it's renamed, running other software "
                "it was upgraded, and a hostname (or stack member, or slot) with a new serial number had its hardware "
                "replaced (the old one is marked Replaced).</p>"
                "<p>Read Server/Phone Details asks servers and phones for what the map can't read.</p>")

    def asset_html(self, asset):
        escape = html.escape
        source = self.source()
        parts = [f"<h3>{escape(asset_label(asset))}</h3>",
                 f"<p>{escape(KINDS.get(asset.kind, asset.kind))} &middot; "
                 f"{escape(STATUSES.get(asset.status, asset.status))}</p><table>"]
        chassis = source.assets.find(asset.parent_id) if asset.parent_id else None
        replacement = source.assets.find(asset.replaced_by) if asset.replaced_by else None
        rows = [("Model", asset.model), ("Maker", asset.maker), ("Serial", asset.serial),
                ("Software", asset.software), ("Management IP", asset.mgmt_ip), ("MAC", asset.mac),
                ("Slot", asset.slot), ("In", asset_label(chassis) if chassis is not None else ""),
                ("Location", asset.location), ("Asset tag", asset.asset_tag), ("Owner", asset.owner),
                ("Purchased", asset.purchased), ("Warranty ends", asset.warranty_end), ("End of life", asset.eol),
                ("Replaced by", f"{asset_label(replacement)} ({replacement.serial})" if replacement is not None
                 else ""),
                ("On a map", f"{asset.first_seen} to {asset.last_seen}" if asset.last_seen else ""),
                ("Notes", asset.description)]
        for title, value in rows:
            if value:
                parts.append(f"<tr><td><b>{title}</b>&nbsp;</td><td>{escape(value)}</td></tr>")
        parts.append("</table>")
        for problem in self.found_problems.get(asset.id, []):
            parts.append(f"<p style='color:{COLORS['warning']}'>{escape(problem)}</p>")
        inside = source.assets.parts_of(asset.id)
        if inside:
            parts.append(f"<h4>Parts ({len(inside)})</h4><table>")
            for part in inside:
                what = ", ".join(item for item in (KINDS.get(part.kind, part.kind), part.model, part.serial) if item)
                parts.append(f"<tr><td>{escape(part.slot)}&nbsp;</td><td>{escape(what)}</td></tr>")
            parts.append("</table>")
        network_map = self.open_map()
        if asset.map_device and network_map is not None and asset.map_device in network_map.devices:
            target = link(MAP_DEVICE, key=asset.map_device)
            parts.append(f"<p><a href='{escape(target, quote=True)}'>Show on the Network Map</a></p>")
        events = asset_history(source.ipam, asset.id)
        if events:
            parts.append("<h4>History</h4><table>")
            for event in events[:HISTORY_SHOWN]:
                parts.append(f"<tr><td>{escape(event.local_time)}&nbsp;</td><td>{escape(event.action)} by "
                             f"{escape(event.who)}: {escape(event.details)}</td></tr>")
            parts.append("</table>")
            if len(events) > HISTORY_SHOWN:
                parts.append(f"<p>...and {len(events) - HISTORY_SHOWN} more (History...).</p>")
        return "".join(parts)

    def update_buttons(self):
        source = self.source()
        selected = self.selected_assets()
        editable = source is not None and source.can_edit
        page = getattr(self.window, "netmap_tab", None)
        self.import_button.setEnabled(source is not None and editable)
        self.read_button.setEnabled(editable and page is not None and page.network_map is not None
                                    and page.worker is None and not page.reading_hardware())
        self.details_button.setEnabled(editable)
        self.add_button.setEnabled(editable)
        self.edit_button.setEnabled(editable and len(selected) == 1)
        self.delete_button.setEnabled(editable and bool(selected))
        self.history_button.setEnabled(len(selected) == 1)
        self.export_button.setEnabled(source is not None)
        self.changes_button.setEnabled(source is not None)
        single = selected[0] if len(selected) == 1 else None
        network_map = self.open_map()
        self.map_button.setEnabled(single is not None and network_map is not None and
                                   single.map_device in network_map.devices)

    def show_menu(self, position):
        selected = self.selected_assets()
        if not selected:
            return
        source = self.source()
        menu = QMenu(self)
        for button in (self.edit_button, self.delete_button, self.history_button, self.map_button):
            action = add_action(menu, button.text(), button.click)
            action.setEnabled(button.isEnabled())
        menu.addSeparator()
        status_menu = add_submenu(menu, "Set Status")
        for key, name in STATUSES.items():
            action = add_action(status_menu, name)
            action.setData(key)
            action.setEnabled(source.can_edit)
            action.triggered.connect(self.set_status)
        location = add_action(menu, "Set Location...", self.set_location)
        owner = add_action(menu, "Set Owner...", self.set_owner)
        for action in (location, owner):
            action.setEnabled(source.can_edit)
        servers = [asset for asset in selected if asset.mgmt_ip and asset.kind in (SERVER, PHONE)]
        if servers:
            add_action(menu, "Read Their Details..." if len(servers) > 1 else "Read Its Details...",
                       self.read_selected_details)
        menu.addSeparator()
        add_action(menu, "Copy Serial Numbers" if len(selected) > 1 else "Copy Serial Number", self.copy_serials)
        menu.exec_(self.table.viewport().mapToGlobal(position))

    # ----------------------------------------------------------------- The network map

    def open_map(self):
        page = getattr(self.window, "netmap_tab", None)
        return getattr(page, "network_map", None)

    def map_name(self):
        page = getattr(self.window, "netmap_tab", None)
        return page.map_name() if page is not None and page.network_map is not None else ""

    def on_map_shown(self):
        if self.isVisible():
            self.update_buttons()

    def bring_in_from_map(self):
        if not self.ensure_open():
            return
        network_map, name = self.open_map(), self.map_name()
        if network_map is None:
            path, _ = QFileDialog.getOpenFileName(self, "Bring In Hardware from a Network Map",
                                                  str(map_store.maps_dir()),
                                                  f"NOMAD network maps (*{map_store.EXTENSION});;All files (*)")
            if not path:
                return
            try:
                network_map = map_store.load(path)
            except (OSError, ValueError) as error:
                set_hint(self.status_label, f"Couldn't open the map: {error}", "error")
                return
            name = path.rsplit("/", 1)[-1]
        self.review_map(network_map, name)

    def review_map(self, network_map, name=""):
        source = self.source()
        found = asset_compare.sightings(network_map, self.parts_check.isChecked())
        if not found:
            set_hint(self.status_label, "That map has no hardware to bring in. Devices' serial numbers are read when "
                                        "a map is crawled (Read Hardware Again reads them for a map made before).",
                     "warning")
            return
        if not any(device.inventory_read for device in network_map.devices.values()):
            set_hint(self.status_label, "This map was made before NOMAD read serial numbers: Read Hardware Again "
                                        "reads them (only what neighbors' CDP said is known now).", "warning")
        changes = asset_compare.plan(source.assets, found)
        title = f"Bring In Hardware from {name}" if name else "Bring In Hardware"
        dialog = AssetImportDialog(self, source, changes, title)
        if dialog.exec_():
            self.make(source, changes, "from the map")

    def make(self, source, changes, where=""):
        """Make the ticked changes. Returns whether they were made."""
        what = asset_compare.summary(changes)
        try:
            asset_compare.apply(source.assets, changes, user=self.user_name(source))
        except IpamError as error:
            self.report(error, "Bringing that in")
            return False
        self.after_change(source)
        self.fill_sources()
        if what:
            set_hint(self.status_label, f"Brought in {where}: {what}.".replace(" :", ":"), "success")
        else:
            set_hint(self.status_label, "Nothing new: each asset found is noted as seen today.", "success")
        return True

    def user_name(self, source):
        user = getattr(getattr(source.ipam, "client", None), "user", "") or getattr(source.ipam, "user", "")
        return user or ""

    def on_hardware_found(self):
        """The map finished a crawl (or Read Hardware Again): bring its hardware in by itself, when set to, leaving
        the changes that need a look for Review."""
        if not self.auto_check.isChecked() or not self.ensure_open():
            return
        network_map, source = self.open_map(), self.source()
        if network_map is None or source is None or not source.can_edit:
            return
        found = asset_compare.sightings(network_map, self.parts_check.isChecked())
        if not found:
            return
        try:
            changes = asset_compare.plan(source.assets, found)
            asset_compare.apply(source.assets, changes, user=self.user_name(source))
        except IpamError as error:
            log.info("Bringing the crawl's hardware into the assets: %s", error)
            set_hint(self.status_label, f"The crawl's hardware wasn't brought in: {error}", "warning")
            return
        made = asset_compare.summary(changes)
        left = [change for change in changes if not change.chosen and change.action != asset_compare.SAME]
        self.review = (source.key, left) if left else None
        self.after_change(source)
        self.fill_sources()
        parts = [f"Brought in from the crawl: {made}." if made else "The crawl's hardware is as the asset list has it."]
        if left:
            parts.append(f"{len(left)} to look at (Review).")
        set_hint(self.status_label, " ".join(parts), "warning" if left else "success")
        if made:
            log.info("Assets: brought in from the crawl: %s", made)
        self.show_status()

    def show_review(self):
        if self.review is None:
            return
        key, changes = self.review
        source = self.source(key)
        if source is None:
            self.review = None
            self.show_status()
            return
        # Planned again: the list may have changed since
        network_map = self.open_map()
        if network_map is not None:
            fresh = asset_compare.plan(source.assets, asset_compare.sightings(network_map,
                                                                             self.parts_check.isChecked()))
            changes = [change for change in fresh if change.action != asset_compare.SAME]
        dialog = AssetImportDialog(self, source, changes, "Review the Crawl's Hardware",
                                   "What the last crawl found that wasn't brought in by itself: changes that might undo "
                                   "what was said by hand, and conflicts. Tick what to bring in.")
        if dialog.exec_():
            self.make(source, changes, "from the crawl")
        self.review = None
        self.show_status()

    def read_hardware_again(self):
        page = getattr(self.window, "netmap_tab", None)
        if page is None or page.network_map is None:
            set_hint(self.status_label, "Open a map on the Network Map page first.", "warning")
            return
        if page.read_hardware_again():
            if not self.auto_check.isChecked():
                set_hint(self.status_label, "Reading the map's hardware: Bring In from Map when it's done.", "info")
            else:
                set_hint(self.status_label, "Reading the map's hardware: it's brought in when it's done.", "info")
        self.update_buttons()

    def show_on_map(self):
        asset = self.selected_asset()
        page = getattr(self.window, "netmap_tab", None)
        if asset is None or page is None or not asset.map_device:
            return
        page.show_device(asset.map_device)
        self.window.navigator.setCurrentWidget(page)

    def show_map_device(self, key):
        """From the map's Show In > Assets: the device's assets (its stack members and parts), selected here."""
        self.window.navigator.setCurrentWidget(self)
        if not self.ensure_open():
            return
        source = self.source()
        ids = [asset.id for asset in source.assets.assets() if asset.map_device == key]
        if not ids:
            set_hint(self.status_label, "That device isn't in this asset list yet: Bring In from Map adds it.", "info")
            return
        self.show_combo.setCurrentIndex(0)
        self.search_input.clear()
        self.fill_table(select=ids)
        self.select_ids(set(ids))

    def open_link(self, url):
        integration = hub(self.window)
        if integration is not None:
            integration.open_link(url)

    # ----------------------------------------------------------------- Servers and phones

    def ask_details(self):
        """The Read Server/Phone Details button (clicked passes its checked flag, never addresses)."""
        self.read_details()

    def read_details(self, addresses=(), method=hostinfo.WINDOWS):
        if not self.ensure_open():
            return
        dialog = ReadDetailsDialog(self, getattr(self.window, "session_store", None), addresses, method)
        if dialog.exec_():
            answers = dialog.answers()
            if not answers:
                return
            source = self.source()
            kind = dialog.kind()
            changes = asset_compare.plan(source.assets, asset_compare.detail_sightings(answers, kind))
            review = AssetImportDialog(self, source, changes, "Record What They Said",
                                       "What the servers or phones said of themselves, against the asset list. Tick "
                                       "what to record.")
            if review.exec_():
                self.make(source, changes, "from their answers")

    def read_selected_details(self):
        selected = [asset for asset in self.selected_assets() if asset.mgmt_ip and asset.kind in (SERVER, PHONE)]
        if not selected:
            return
        method = hostinfo.PHONE if all(asset.kind == PHONE for asset in selected) else hostinfo.WINDOWS
        self.read_details([asset.mgmt_ip for asset in selected], method)

    # ----------------------------------------------------------------- Changing assets

    def parents(self, source):
        return [asset for asset in source.assets.assets() if not is_part(asset.kind)]

    def add_asset(self):
        if not self.ensure_open():
            return
        source = self.source()
        dialog = AssetDialog(self, source, parents=self.parents(source))
        if dialog.exec_():
            self.after_change(source)
            self.fill_sources()
            if dialog.result_item is not None:
                self.select_ids({dialog.result_item.id})

    def edit_asset(self, *_):
        source, asset = self.source(), self.selected_asset()
        if asset is None or source is None or not source.can_edit:
            return
        dialog = AssetDialog(self, source, asset, parents=self.parents(source))
        if dialog.exec_():
            self.after_change(source)
            self.fill_table()

    def set_many(self, values, what):
        source, selected = self.source(), self.selected_assets()
        if not selected:
            return
        try:
            source.assets.set_assets([dict(values, id=asset.id) for asset in selected])
        except IpamError as error:
            self.report(error, what)
            return
        self.after_change(source)
        self.fill_table()

    def set_status(self):
        action = self.sender()
        if action is not None and action.data() in STATUSES:
            self.set_many({"status": action.data()}, "Setting the status")

    def set_location(self):
        selected = self.selected_assets()
        dialog = ValueDialog(self, "Set Location", "Location:", selected[0].location if selected else "")
        if selected and dialog.exec_():
            self.set_many({"location": dialog.value()}, "Setting the location")

    def set_owner(self):
        selected = self.selected_assets()
        dialog = ValueDialog(self, "Set Owner", "Owner:", selected[0].owner if selected else "")
        if selected and dialog.exec_():
            self.set_many({"owner": dialog.value()}, "Setting the owner")

    def delete_assets(self):
        source, selected = self.source(), self.selected_assets()
        if not selected:
            return
        inside = [part for asset in selected for part in source.assets.parts_of(asset.id)
                  if part.id not in {item.id for item in selected}]
        listed = ", ".join(asset_label(asset) for asset in selected[:6]) + ("..." if len(selected) > 6 else "")
        text = f"Delete {listed}? Hardware taken out of service is better marked Retired (right-click > Set Status), " \
               "which keeps it in the list. Its history is kept either way."
        if inside:
            text += f" The {len(inside)} part{'s' if len(inside) != 1 else ''} in {'them' if len(selected) > 1 else 'it'} " \
                    "are deleted too."
        if QMessageBox.question(self, "Delete Assets", text) != QMessageBox.Yes:
            return
        try:
            for asset in selected + inside:
                source.assets.delete_asset(asset.id)
        except IpamError as error:
            self.report(error, "Deleting")
        self.after_change(source)
        self.fill_sources()

    def show_history(self):
        from .ipam_history_dialog import HistoryDialog
        source, asset = self.source(), self.selected_asset()
        if asset is not None:
            HistoryDialog(self, source.ipam, "", "asset", asset, self.history_note()).exec_()

    def show_changes(self):
        from .ipam_history_dialog import HistoryDialog
        source = self.source()
        if source is not None:
            HistoryDialog(self, source.ipam, "", "assets", None, self.history_note()).exec_()

    def history_note(self):
        team = self.window.ipam_tab.team
        if self.source_key == TEAM and team is not None and not team.history_revision:
            return "The tribe's history arrives with the next sync from the IPAM server."
        return ""

    def copy_serials(self):
        serials = [asset.serial for asset in self.selected_assets() if asset.serial]
        QApplication.clipboard().setText("\n".join(serials))
        set_hint(self.status_label, f"Copied {len(serials)} serial number{'s' if len(serials) != 1 else ''}.",
                 "success")

    # ----------------------------------------------------------------- Exporting

    def export(self):
        source = self.source()
        if source is None:
            return
        stamp = datetime.date.today().isoformat()
        path, chosen = QFileDialog.getSaveFileName(self, "Export Assets", f"Assets {stamp}.xlsx",
                                                   "Excel workbooks (*.xlsx);;CSV files (*.csv)")
        if not path:
            return
        rows = export_rows(source.assets.assets())
        try:
            if path.lower().endswith(".csv") or "CSV" in chosen and not path.lower().endswith(".xlsx"):
                with open(path, "w", newline="", encoding="utf-8-sig") as file:
                    writer = csv.writer(file)
                    writer.writerow(EXPORT_COLUMNS)
                    writer.writerows(rows)
            else:
                write_workbook(path, rows)
        except OSError as error:
            set_hint(self.status_label, f"Couldn't export: {error}", "error")
            return
        set_hint(self.status_label, f"Exported {len(rows)} assets to {path}.", "success")

    # ----------------------------------------------------------------- The tribe

    def after_change(self, source):
        """A change was made: tribe ones made offline go with the next sync (which also tells other laptops)."""
        if source is not None and source.key == TEAM:
            self.window.ipam_tab.sync_now()
        self.show_status()

    def on_tribe_synced(self):
        if self.source_combo.count() or self.isVisible():
            self.fill_sources()

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
        AssetRefusedDialog(self, source.assets).exec_()
        self.after_change(source)
        self.fill_table()

    def show_status(self):
        """The tribe's state, as it matters for assets, and what's left to review."""
        self.update_buttons()
        if self.review is not None:
            self.review_button.setText(f"Review the Crawl's Hardware ({len(self.review[1])})")
        self.review_button.setVisible(self.review is not None)
        team = self.window.ipam_tab.team
        if team is None or self.source_key != TEAM:
            self.server_label.setText("" if team is None else "")
            self.refused_button.setVisible(False)
            return
        assets = TeamAssetStore(team)
        refused = len(assets.refused())
        self.refused_button.setText(f"Review Refused Asset Changes ({refused})")
        self.refused_button.setVisible(bool(refused))
        waiting = assets.pending_count()
        synced = f"synced {ago(time.time() - team.last_sync)}" if team.last_sync else "not synced yet"
        if waiting:
            synced += f"; {waiting} change{'s' if waiting != 1 else ''} waiting to be sent"
        if not team.server_keeps_assets:
            set_hint(self.server_label, "Tribe: the IPAM server needs updating to keep assets", "warning")
        elif team.online:
            set_hint(self.server_label, f"● Tribe · {synced}", "success")
        elif team.last_error:
            set_hint(self.server_label, f"● Tribe offline · {synced} (assets can still be changed)", "warning")
        else:
            set_hint(self.server_label, f"● Tribe · connecting ({synced})", "info")


EXPORT_COLUMNS = ["Hostname", "Slot", "Kind", "Model", "Maker", "Serial", "Software", "Management IP", "MAC",
                  "Location", "Status", "Asset Tag", "Owner", "Purchased", "Warranty Ends", "End of Life",
                  "First Seen", "Last Seen", "Notes"]


def export_rows(assets):
    by_id = {asset.id: asset for asset in assets}
    rows = []
    for asset in sorted(assets, key=lambda item: (
            (item.hostname or (by_id[item.parent_id].hostname if item.parent_id in by_id else "")).lower(),
            is_part(item.kind), item.slot)):
        chassis = by_id.get(asset.parent_id)
        rows.append([asset.hostname or (chassis.hostname if chassis is not None else ""), asset.slot,
                     KINDS.get(asset.kind, asset.kind), asset.model, asset.maker, asset.serial, asset.software,
                     asset.mgmt_ip, asset.mac, asset.location, STATUSES.get(asset.status, asset.status),
                     asset.asset_tag, asset.owner, asset.purchased, asset.warranty_end, asset.eol, asset.first_seen,
                     asset.last_seen, asset.description])
    return rows


def write_workbook(path, rows):
    from openpyxl import Workbook
    from openpyxl.styles import Font
    book = Workbook()
    sheet = book.active
    sheet.title = "Assets"
    sheet.append(EXPORT_COLUMNS)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    for row in rows:
        sheet.append(row)
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for column in sheet.columns:
        width = max(len(str(cell.value or "")) for cell in column)
        sheet.column_dimensions[column[0].column_letter].width = min(max(10, width + 2), 50)
    book.save(path)


def ip_sort_key(text):
    import ipaddress
    try:
        address = ipaddress.ip_address(text)
        return (0, address.version, int(address))
    except ValueError:
        return (1, 0, 0) if text else (2, 0, 0)
