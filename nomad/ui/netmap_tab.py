"""Network Map page: crawl switches, routers and firewalls over SNMP from a starting device, and draw what's
connected to what (CDP/LLDP), with the hosts on each switch port (MAC and ARP tables)."""
import datetime
import functools
import html
import ipaddress
import json
import logging
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from PyQt5.QtCore import QSettings, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QActionGroup, QApplication, QCheckBox, QComboBox, QDialog, \
    QAction, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, \
    QShortcut, QSplitter, QTabWidget, QTextBrowser, QToolButton, QVBoxLayout, QWidget

from ..ipam.client import ADMIN, current_key, is_tribe_server
from ..ipam.map_compare import DEVICE as DEVICE_ADDRESS, compare_map
from ..ipam.reconcile import MAC_DIFFERS, NOT_RECORDED
from ..ipam.store import IpamError
from ..netmap import diff, export, l3, monitor, overlays, shared, store, watch
from ..netmap import vlan_path
from ..netmap import vlans as vlan_info
from ..netmap.crawl import MAX_WORKERS, WORKERS, CrawlSettings, Crawler, apply_vlans, check_device, \
    communities_for, credentials_from_json, credentials_to_json, ordered_credentials, parse_overrides, read_vlans_of
from ..netmap.layout import BOTTOM, CENTER, GROUP_PAD, GROUP_TITLE, HORIZONTAL, LEFT, MIDDLE, \
    NORMAL, RESPACE_MIN_GAP, RIGHT, SPACING_NAMES, SPACINGS, STYLE_NAMES, TOP, TOP_DOWN, VERTICAL, align, arrange, \
    arrange_boxes_in_place, arrange_in_place, distribute, merge_positions, nearest_spacing, respace, spacing_of
from ..netmap.placement import places as subnet_places
from ..netmap.tribe import SECRETS
from ..netmap.model import BUILDING, CORRECTED_NAMES, FIREWALL, GROUP_KINDS, KIND_NAMES, NO_SNMP, PARENT_KIND, \
    ROUTER, SNMP, SWITCH, UNCHECKED, UNREACHABLE, Group, NetworkMap, display_name, port_key, short_port
from ..snmp import V2C
from ..snmpv3 import is_v3
from ..terminal.credentials import CredentialError, protect, unprotect
from .common import OneLineLabel, SortableTableItem, StoppableThread, add_submenu, drop_empty_submenus, \
    read_only_table, set_hint
from .host_menu import HostActions
from .map_ipam_dialog import RecordDialog
from .integration import IPAM, PLACEMENT, VLAN, MapNetworkDialog, hub, split_key
from .integration import link as page_link
from .netmap_key import MapKeyDialog
from .netmap_counters import LinkCounters
from .netmap_monitor import NetworkMonitor
from .netmap_progress import CrawlProgress
from .netmap_dialogs import CommunitiesDialog, CompareDialog, DeletedDevicesDialog, DeviceDialog, GroupDialog, \
    HostDialog, LinkDialog, MapChoiceDialog, ScopeDialog, shown_value
from .netmap_tribe import TribeSync
from .netmap_view import GROUP_BOX, MapView
from .netmap_vlans import VlanPanel, domain_text
from .vlan_path_dialog import VlanPathDialog
from .netmap_watch import MapWatcher
from .table_filter import TableFilter
from .theme import COLORS, accent_button
from .tribe_join_dialog import connect_to_tribe

log = logging.getLogger(__name__)

MAP_FILTER = f"Network maps (*{store.EXTENSION})"
KIND_WEIGHTS = {FIREWALL: 3, ROUTER: 2, SWITCH: 1}  # Breaks ties when choosing the top device
SAVE_DELAY_MS = 1000
UNDO_LIMIT = 100  # Layout changes Undo can go back through
ROUTES_SHOWN = 50
DEFAULTS = {"max_hops": 6, "max_devices": 500, "timeout": 2000}
ALIGNMENTS = [("Align Left", LEFT), ("Align Center", CENTER), ("Align Right", RIGHT), None, ("Align Top", TOP),
              ("Align Middle", MIDDLE), ("Align Bottom", BOTTOM)]
GROUP_LINKS_SHOWN = 20
VLANS_IN_MENU = 60  # A device's Highlight VLAN menu lists this many
OVERLAY_ITEMS = 60  # The Overlay menu lists this many VLANs, VRFs or subnets
VLANS_LISTED = 40  # A device's details name this many of its VLANs
CHECK_WORKERS = 8  # Devices added by hand asked over SNMP at once
OPEN_MAP, FILE_MAP, TRIBE_MAP, NEW_MAP = "open", "file", "tribe", "new"  # Where Add Device to Map puts one


def ip_sort_key(text):
    try:
        return (0, int(ipaddress.ip_address(text.split(",")[0].strip())))
    except ValueError:
        return (1, text.lower())


def parse_seeds(text):
    return [item for item in text.replace(",", " ").split() if item]


class CrawlThread(StoppableThread):
    progress = pyqtSignal(str)
    event = pyqtSignal(str, object)  # A Crawler event: kind, details
    crawled = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, settings, known=None, parent=None):
        super().__init__(parent)
        self.settings, self.known = settings, known  # known: the map Crawl from Here adds to

    def run(self):
        try:
            seeds = []
            for seed in self.settings.seeds:
                try:
                    seeds.append(str(ipaddress.ip_address(seed)))
                except ValueError:
                    try:
                        seeds.append(socket.gethostbyname(seed))
                    except OSError:
                        self.failed.emit(f"Couldn't find '{seed}'. Enter an IP address or a name DNS knows.")
                        return
            self.settings.seeds = seeds
            network_map = Crawler(self.settings, should_stop=lambda: self.stopping, progress=self.progress.emit,
                                  events=lambda kind, *details: self.event.emit(kind, details),
                                  known=self.known).run()
        except Exception as error:  # Shown to the user rather than lost
            log.exception("Network map crawl failed")
            self.failed.emit(f"The crawl failed: {error}")
            return
        self.crawled.emit(network_map)


class CheckThread(StoppableThread):
    """Asks devices added by hand whether they answer SNMP (or only ping), as a crawl would, a few at once."""
    checked = pyqtSignal(str, str, object)  # Device key, the address asked, crawl.Check

    def __init__(self, settings, targets, checker, parent=None):
        super().__init__(parent)
        self.settings, self.targets, self.checker = settings, targets, checker  # targets: [(key, address)]

    def run(self):
        def ask(target):
            key, address = target
            if self.stopping:
                return
            try:
                result = self.checker(self.settings, address)
            except Exception:  # One device's trouble shouldn't stop the rest
                log.exception("Checking %s over SNMP failed", address)
                return
            if not self.stopping:
                self.checked.emit(key, address, result)

        with ThreadPoolExecutor(max_workers=max(1, min(CHECK_WORKERS, len(self.targets)))) as executor:
            list(executor.map(ask, self.targets))


class VlanReadThread(CheckThread):
    """Reads just the VLANs (and IP interfaces) of the switches on the map, a few at once: Read VLANs Again."""


class NetworkMapTab(QWidget):
    map_shown = pyqtSignal()  # The map open was drawn again (another opened, mapped again, changed, read again)
    routes_read = pyqtSignal(int, int)  # Read Routes Again finished: devices read, devices that didn't answer
    ipam_network_changed = pyqtSignal()  # The open map was said to be of another IPAM network

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.network_map = None
        self.map_path = None
        self.communities, self.overrides = ["public"], []
        self.v3_users, self.v3_first = [], True  # SNMPv3 users (V3Users) to try too, and whether before communities
        self.answered = {}  # Address -> the community or V3User it answered to (this session's, never in the map file)
        self.version, self.timeout = V2C, DEFAULTS["timeout"]
        self.scope, self.max_hops, self.max_devices = [], DEFAULTS["max_hops"], DEFAULTS["max_devices"]
        self.collect_hosts = True
        self.trace = True
        self.workers = WORKERS
        self.l3_nodes = {}
        self.l3_links = []
        self.arrange_style = TOP_DOWN
        self.arrange_spacing = NORMAL  # How far apart Re-arrange puts things
        self.last_arranged = None  # ((view, keys, group keys), style, spacing) of the last Arrange Selected
        self.keep_groups = True  # Re-arrange lays out each site, building and room in its own box
        self.compare_dialog = None
        self.key_dialog = None
        self.extending = False  # The crawl running adds to the map open (Crawl from Here)
        self.live_map = None  # The map so far, drawn while a crawl runs
        self.live_positions = {}
        self.crawled_map = False
        self.crawl_progress = CrawlProgress(self)
        self.monitor = NetworkMonitor(self)
        self.counters = LinkCounters(self)  # While monitoring: the links' traffic and errors
        self.stp_reading = None  # While the Spanning Tree overlay's switches are read: {"map", "vlan", "views"...}
        self.tribe_map_id = None  # The tribe map open (None: a map file, or none)
        self.unopened = ""  # The map open last time, when it couldn't be reopened: still the one to try next time
        self.restoring_switches = False  # Turning Monitor and Watch back on as they were: nothing new to note
        self.tribe_seen = None  # Its items as last loaded or saved here: saves send only what changed from them
        self.tribe = TribeSync(self, key_loader=self.tribe_key)
        self.watcher = MapWatcher(self)
        self.history_map = None  # The map whose monitoring history the Monitor log is showing
        self.host_actions = HostActions(window, self)
        self.check_threads = []  # Asking devices added by hand over SNMP
        self.checking = set()  # Keys of the devices being asked
        self.announce = set()  # Of those, the ones to say what was found for (one added or asked again)
        self.show_added = False  # Add Device to Map (from other pages) shows the map afterwards
        self.check_device = check_device  # What asks one (tests swap in the fake network)
        self.read_vlans = read_vlans_of  # What reads one's VLANs (tests swap in the fake network)
        self.vlan_reading = None  # While Read VLANs Again runs: {"map", "read", "failed", "lines"}
        self.carry_dialog = None  # Carry VLAN (made the first time it's used, then kept)
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.setInterval(SAVE_DELAY_MS)
        self.save_timer.timeout.connect(self.save_positions)
        # Undo and Redo: the layout (where everything is on both views, and which group each device is in) before
        # each change, and the changes undone; layout_now is the layout as it is
        self.undo_stack, self.redo_stack = [], []
        self.layout_now = None
        self.restoring = False
        self.vlan_shown = None  # (VLAN, VTP domain) highlighted on the physical view, or None
        self.overlay_shown = None  # (overlays kind, its argument) shown on the physical view instead, or None
        self.init_ui()
        window.adapter_changed.connect(lambda _: self.update_gateway_button())
        window.snapshot_changed.connect(lambda _: self.update_gateway_button())
        self.tribe.synced.connect(self.on_tribe_synced)
        self.tribe.status_changed.connect(self.update_tribe_label)
        self.watcher.applied.connect(self.watch_applied)
        self.watcher.status_changed.connect(self.update_watch_label)
        self.update_gateway_button()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.seeds_input = QLineEdit()
        self.seeds_input.setPlaceholderText("Core switch or gateway to start from (IP addresses, separated by commas)")
        self.gateway_button = QPushButton("Adapter's Gateway")
        self.communities_button = QPushButton("SNMP Credentials...")
        self.communities_button.setToolTip("The SNMP community strings and SNMPv3 users to try, including ones for "
                                           "particular subnets. A tribe map's are shared with everyone in the tribe.")
        self.scope_button = QPushButton("Scope...")
        self.scope_button.setToolTip("Which subnets the crawl may go into, how many hops, and whether to read "
                                     "MAC tables for hosts and traceroute for the logical view.")
        self.start_button = accent_button("Start")
        self.start_button.setToolTip("Read each device's CDP/LLDP neighbors over SNMP, then theirs, and so on.")
        self.stop_button = QPushButton("Stop")
        self.crawl_row = QWidget()  # Where to start from, Start and Stop
        crawl_row = QHBoxLayout(self.crawl_row)
        crawl_row.setContentsMargins(0, 0, 0, 0)
        crawl_row.addWidget(QLabel("Start from:"))
        crawl_row.addWidget(self.seeds_input, 1)
        for widget in (self.gateway_button, self.communities_button, self.scope_button, self.start_button,
                       self.stop_button):
            crawl_row.addWidget(widget)

        self.status_label = OneLineLabel(wraps=True)

        self.new_button = QPushButton("New Map")
        self.new_button.setToolTip("Put the map away and start a new one: enter where to start from and press "
                                   "Start. The map that was open is left as it is (open it again from Recent, or "
                                   "Tribe).")
        self.open_button = QPushButton("Open...")
        self.recent_button = QToolButton()
        self.recent_button.setText("Recent")
        self.recent_button.setPopupMode(QToolButton.InstantPopup)
        self.recent_menu = QMenu(self.recent_button)
        self.recent_menu.aboutToShow.connect(self.fill_recent_menu)
        self.recent_button.setMenu(self.recent_menu)
        self.save_button = QPushButton("Save As...")
        self.export_button = QToolButton()
        self.export_button.setText("Export")
        self.export_button.setPopupMode(QToolButton.InstantPopup)
        self.export_menu = QMenu(self.export_button)
        self.export_menu.addAction("Picture (PNG)...", self.export_png)
        self.export_menu.addAction("Drawing (SVG)...", self.export_svg)
        self.export_menu.addAction("draw.io / Visio (.drawio)...", self.export_drawio)
        self.export_menu.addSeparator()
        self.export_menu.addAction("Devices (CSV)...", lambda: self.export_csv("devices"))
        self.export_menu.addAction("Links (CSV)...", lambda: self.export_csv("links"))
        self.export_menu.addAction("Hosts (CSV)...", lambda: self.export_csv("hosts"))
        self.export_button.setMenu(self.export_menu)
        self.compare_button = QToolButton()
        self.compare_button.setText("Compare")
        self.compare_button.setToolTip("Compare this map with an earlier one: devices and links that appeared or "
                                       "went away, and hosts that moved port.")
        self.compare_button.setPopupMode(QToolButton.InstantPopup)
        self.compare_menu = QMenu(self.compare_button)
        self.compare_menu.aboutToShow.connect(self.fill_compare_menu)
        self.compare_button.setMenu(self.compare_menu)
        self.ipam_network_button = QPushButton("IPAM Network...")
        self.ipam_network_button.setToolTip("Which IPAM network the map is of: the VLANs and Subnet Placement pages "
                                            "check that network against it, and opening the map opens the network "
                                            "on the IP Addresses, VLANs and Subnet Placement pages.")
        self.ipam_network_button.clicked.connect(self.choose_ipam_network)
        self.ipam_record_button = QPushButton("Record in IPAM...")
        self.ipam_record_button.setToolTip("Record the addresses of the map's devices and hosts that its IPAM "
                                           "network doesn't have (or has with another MAC address): you see them "
                                           "first and tick what to record.")
        self.ipam_record_button.clicked.connect(self.record_map_in_ipam)  # Not record_in_ipam: clicked passes False
        self.find_input = QLineEdit()
        self.find_input.setClearButtonEnabled(True)
        self.fit_button = QPushButton("Fit")
        self.fit_button.setToolTip("Zoom to show the whole map. Scroll to zoom, and drag the background to move "
                                   "around.")
        self.arrange_button = QToolButton()
        self.arrange_button.setText("Re-arrange")
        self.arrange_button.setPopupMode(QToolButton.MenuButtonPopup)
        self.arrange_button.setToolTip("Lay the map out again, forgetting where devices were dragged to. The arrow "
                                       "chooses how (top to bottom, bottom to top, left to right, right to left, a "
                                       "grid or a circle, with each site, building and room in its own box) and how "
                                       "far apart, and arranges or lines up just the devices selected.")
        self.arrange_menu = QMenu(self.arrange_button)
        self.arrange_menu.aboutToShow.connect(self.fill_arrange_menu)
        self.arrange_button.setMenu(self.arrange_menu)
        self.tribe_button = QToolButton()
        self.tribe_button.setText("Tribe")
        self.tribe_button.setToolTip("Maps shared with the tribe through the IPAM server: everyone with the tribe key "
                                     "sees the same map, and changes anyone makes reach the others.")
        self.tribe_button.setPopupMode(QToolButton.InstantPopup)
        self.tribe_menu = QMenu(self.tribe_button)
        self.tribe_menu.aboutToShow.connect(self.fill_tribe_menu)
        self.tribe_button.setMenu(self.tribe_menu)
        self.key_button = QPushButton("Key")
        self.key_button.setToolTip("What the map's colors, outlines and line styles mean.")
        self.key_button.clicked.connect(self.show_key)
        self.monitor_check = QCheckBox("Monitor")
        self.monitor_check.setToolTip("Ping the devices on the map every so often, show which are up or down, and "
                                      "log when one goes down or comes back (on the Monitor tab). Keeps going on "
                                      "other pages while NOMAD is open.")
        self.interval_combo = QComboBox()
        for seconds in monitor.INTERVALS:
            self.interval_combo.addItem(f"every {monitor.duration_text(seconds)}", seconds)
        self.interval_combo.setCurrentIndex(monitor.INTERVALS.index(monitor.DEFAULT_INTERVAL))
        self.interval_combo.setToolTip("How often to ping each device.")
        self.monitor_label = OneLineLabel()
        self.monitor_label.hide()  # Until there's something to say
        self.watch_check = QCheckBox("Watch")
        self.watch_check.setToolTip("Watch for devices and hosts plugged into the network, and add them to the map "
                                    "as they appear, tagged NEW (see the Watch tab). Keeps going on other pages "
                                    "while NOMAD is open.")
        self.watch_label = OneLineLabel()
        self.watch_label.hide()
        self.status_slack = QWidget()  # What the news leave of their room on the compact bar (fit_statuses)
        self.status_slack.setFixedWidth(0)
        self.overlay_button = QToolButton()
        self.overlay_button.setText("Overlay")
        self.overlay_button.setToolTip("Show something over the physical view: a VLAN, VRF or subnet, what one "
                                       "failure would cut off, trunk problems, or devices colored by model, software "
                                       "version, site... One at a time; Esc puts the map back.")
        self.overlay_button.setPopupMode(QToolButton.InstantPopup)
        self.overlay_menu = QMenu(self.overlay_button)
        self.overlay_menu.aboutToShow.connect(self.fill_overlay_menu)
        self.overlay_submenus = []
        self.overlay_button.setMenu(self.overlay_menu)
        self.hosts_check = QCheckBox("Show Hosts")
        self.hosts_check.setToolTip("Show every switch's hosts, a box per port with each host's VLAN. Or double-click "
                                    "one switch to show just its hosts.")
        self.undo_button = QPushButton("Undo")
        self.undo_button.setToolTip("Put devices back where they were before the last move, re-arrange or "
                                    "alignment, or the last change to the sites, buildings and rooms (Ctrl+Z).")
        self.redo_button = QPushButton("Redo")
        self.redo_button.setToolTip("Do again what Undo undid (Ctrl+Y or Ctrl+Shift+Z).")
        # The compact bar's: the map file's buttons in one menu, and the crawl row shown when wanted
        self.map_button = QToolButton()
        self.map_button.setText("Map")
        self.map_button.setToolTip("Crawl (start from, credentials, scope), New, Open, Recent, Save As, Export, "
                                   "Compare, the map's IPAM network, and the tribe's maps.")
        self.map_button.setPopupMode(QToolButton.InstantPopup)
        self.map_menu = QMenu(self.map_button)
        self.map_button.setMenu(self.map_menu)
        self.build_map_menu()
        self.crawl_button = QToolButton()
        self.crawl_button.setText("Crawl")
        self.crawl_button.setCheckable(True)
        self.crawl_button.setToolTip("Show where to start from, to map again or crawl from another switch (it's "
                                     "shown anyway while there's no map, or a crawl's running).")
        self.crawl_button.toggled.connect(lambda _: self.update_crawl_row())
        self.tribe_label = QLabel()
        self.tribe_label.hide()
        self.top_bar = QWidget()  # The rows above the map: compact or classic (lay_out_top_bar)
        self.top_bar_layout = QVBoxLayout(self.top_bar)
        self.top_bar_layout.setContentsMargins(0, 0, 0, 0)
        self.spare = QWidget(self)  # Holds the buttons the arrangement showing doesn't use
        self.spare.hide()
        self.compact_top = True
        self.lay_out_top_bar()
        layout.addWidget(self.top_bar)
        # Which IPAM network the map is of, when that's worth saying: none, or not the one the other pages are on
        self.network_bar = QWidget()
        self.network_bar.setObjectName("networkBar")
        self.network_bar.setStyleSheet(f"#networkBar {{ background: {COLORS['warning_background']}; border: 1px "
                                       f"solid {COLORS['warning']}; }}")
        bar = QHBoxLayout(self.network_bar)
        bar.setContentsMargins(8, 3, 8, 3)
        self.network_bar_label = QLabel()
        self.network_bar_label.setWordWrap(True)
        self.network_open_button = QPushButton()
        self.network_open_button.clicked.connect(self.open_network_map)
        self.network_back_button = QPushButton()
        self.network_back_button.setToolTip("Put the IP Addresses, VLANs and Subnet Placement pages back on the "
                                            "map's network.")
        self.network_back_button.clicked.connect(self.back_to_map_network)
        self.network_set_button = QPushButton("IPAM Network...")
        self.network_set_button.clicked.connect(self.choose_ipam_network)
        bar.addWidget(self.network_bar_label, 1)
        for button in (self.network_open_button, self.network_back_button, self.network_set_button):
            bar.addWidget(button)
        self.network_bar.hide()
        self.map_networks = {}  # Saved map file -> (when it was changed, the IPAM network it's of)
        layout.addWidget(self.network_bar)

        self.tabs = QTabWidget()
        self.view = MapView()
        self.l3_view = MapView()
        self.devices_table = read_only_table(export.DEVICE_COLUMNS)
        self.links_table = read_only_table(export.LINK_COLUMNS)
        self.hosts_table = read_only_table(export.HOST_COLUMNS + ["IPAM"])  # IPAM: what the map's network has
        self.vlan_panel = VlanPanel()
        self.tabs.addTab(self.view, "Physical (L2)")
        self.tabs.addTab(self.l3_view, "Logical (L3)")
        self.tabs.addTab(self.devices_table, "Devices")
        self.tabs.addTab(self.links_table, "Links")
        self.tabs.addTab(self.hosts_table, "Hosts")
        self.tabs.addTab(self.vlan_panel, "VLANs")
        self.tabs.addTab(self.crawl_progress.tab, "Crawl")
        self.tabs.addTab(self.monitor.tab, "Monitor")
        self.tabs.addTab(self.watcher.tab, "Watch")
        self.table_names = {self.devices_table: "Devices", self.links_table: "Links", self.hosts_table: "Hosts"}
        self.table_filters = {table: TableFilter(table, lambda shown, total, table=table:
                                                 self.show_filtered_count(table, shown, total))
                              for table in self.table_names}
        self.table_names[self.vlan_panel] = "VLANs"  # Its find box filters its VLANs
        self.table_filters[self.vlan_panel] = TableFilter(self.vlan_panel.table, self.show_vlan_filter_count)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.splitter = QSplitter(Qt.Horizontal)
        self.splitter.addWidget(self.tabs)
        self.splitter.addWidget(self.details)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        self.splitter.setSizes([900, 260])
        self.vlan_bar = QWidget()  # While a VLAN is highlighted: which, and how to stop
        vlan_row = QHBoxLayout(self.vlan_bar)
        vlan_row.setContentsMargins(0, 0, 0, 0)
        self.vlan_label = QLabel()
        self.vlan_label.setWordWrap(True)
        self.vlan_clear_button = QPushButton("Show All")
        self.vlan_clear_button.setToolTip("Stop highlighting the VLAN, or showing the overlay (Esc).")
        vlan_row.addWidget(self.vlan_label, 1)
        vlan_row.addWidget(self.vlan_clear_button)
        self.vlan_bar.hide()
        layout.addWidget(self.vlan_bar)
        layout.addWidget(self.splitter, 1)
        self.show_details(None)
        self.vlan_clear_button.clicked.connect(self.clear_vlan)
        self.vlan_panel.highlight_requested.connect(self.highlight_vlan)
        self.vlan_panel.show_requested.connect(self.show_vlan_finding)
        self.vlan_panel.add_to_database_requested.connect(self.add_vlans_to_database)
        self.vlan_panel.read_requested.connect(self.read_vlans_again)
        self.vlan_panel.vlans_page_requested.connect(self.show_vlans_page)
        self.vlan_panel.carry_requested.connect(self.carry_vlan_from_panel)

        self.gateway_button.clicked.connect(self.use_gateway)
        self.communities_button.clicked.connect(self.edit_communities)
        self.scope_button.clicked.connect(self.edit_scope)
        self.start_button.clicked.connect(lambda: self.start())
        self.seeds_input.returnPressed.connect(lambda: self.start())
        self.stop_button.clicked.connect(self.stop)
        self.new_button.clicked.connect(lambda: self.new_map())
        self.open_button.clicked.connect(self.open_map)
        self.save_button.clicked.connect(self.save_map_as)
        self.find_input.returnPressed.connect(self.on_find_return)
        self.find_input.textChanged.connect(self.on_find_text)
        self.find_texts = {}  # Sub-tab -> what was in the find box there: each tab has its own
        self.find_owner = self.tabs.currentWidget()
        self.tabs.currentChanged.connect(self.on_subtab_changed)
        self.set_find_placeholder()
        self.fit_button.clicked.connect(lambda: self.current_view().fit())
        self.undo_button.clicked.connect(self.undo)
        self.redo_button.clicked.connect(self.redo)
        for keys, handler in ((QKeySequence.Undo, self.undo), ("Ctrl+Y", self.redo), ("Ctrl+Shift+Z", self.redo)):
            QShortcut(QKeySequence(keys), self, context=Qt.WidgetWithChildrenShortcut).activated.connect(handler)
        QShortcut(QKeySequence("Esc"), self, context=Qt.WidgetWithChildrenShortcut).activated.connect(
            self.on_escape)
        self.arrange_button.clicked.connect(lambda: self.rearrange())
        self.hosts_check.toggled.connect(self.view.set_all_hosts_shown)
        self.monitor_check.toggled.connect(self.on_monitor_toggled)
        self.watch_check.toggled.connect(self.on_watch_toggled)
        self.interval_combo.currentIndexChanged.connect(
            lambda _: self.monitor.set_interval(self.interval_combo.currentData()))
        self.monitor.statuses_changed.connect(self.show_statuses)
        self.monitor.polled.connect(self.counters.poll_now)
        self.counters.updated.connect(self.on_counters_updated)
        self.monitor.history_added.connect(self.keep_history)
        for view in (self.view, self.l3_view):
            view.selection_changed.connect(self.show_details)
            view.positions_changed.connect(self.save_timer.start)
            view.positions_changed.connect(self.record_layout)
            view.context_requested.connect(self.show_device_menu)
        self.view.group_context_requested.connect(self.show_group_menu)
        self.view.groups_changed.connect(self.groups_toggled)
        self.view.devices_dropped.connect(self.on_devices_dropped)
        self.devices_table.itemDoubleClicked.connect(lambda item: self.show_on_map("device", item.row()))
        self.links_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        for table, handler in ((self.devices_table, self.show_devices_table_menu),
                               (self.links_table, self.show_links_table_menu)):
            table.setContextMenuPolicy(Qt.CustomContextMenu)
            table.customContextMenuRequested.connect(handler)
        self.hosts_table.itemDoubleClicked.connect(lambda item: self.show_on_map("host", item.row()))
        self.hosts_table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.hosts_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hosts_table.customContextMenuRequested.connect(self.show_hosts_table_menu)
        delete = QShortcut(QKeySequence.Delete, self.hosts_table, context=Qt.WidgetShortcut)
        delete.activated.connect(lambda: self.delete_hosts(self.selected_table_hosts()))
        for widget, selected in ((self.devices_table, self.selected_table_devices),
                                 (self.view, self.view.selected_keys), (self.l3_view, self.l3_view.selected_keys)):
            delete = QShortcut(QKeySequence.Delete, widget, context=Qt.WidgetShortcut)
            delete.activated.connect(lambda selected=selected: self.delete_devices(selected()))
        self.view.port_context_requested.connect(self.show_port_menu)
        self.view.background_context_requested.connect(self.show_background_menu)
        self.view.link_context_requested.connect(self.show_link_menu)
        self.view.link_drawn.connect(lambda a, b: self.add_link(a, b))

    def lay_out_top_bar(self):
        """Put the rows above the map in the compact arrangement (one row of buttons, the map file's in the Map menu;
        the crawl row only while it's wanted; a one-line status, the whole of it in its tooltip) or the classic one
        (the crawl row, the status, the map file's buttons with Monitor and Watch, then the find box and the view's
        tools)."""
        layout = self.top_bar_layout
        old = []
        while layout.count():
            widget = layout.takeAt(0).widget()
            if widget is not None and widget.property("tool_row"):
                old.append(widget)
        rows = []

        def row(*items):
            widget = QWidget(self.top_bar)
            widget.setProperty("tool_row", True)
            line = QHBoxLayout(widget)
            line.setContentsMargins(0, 0, 0, 0)
            for item in items:
                if item is None:
                    line.addStretch(1)
                elif isinstance(item, int):
                    line.addSpacing(item)
                else:
                    line.addWidget(item, 1 if item is self.find_input else 0)
            rows.append(widget)

        file_buttons = [self.new_button, self.open_button, self.recent_button, self.save_button, self.export_button,
                        self.compare_button, self.ipam_network_button, self.ipam_record_button, self.tribe_button,
                        self.key_button]
        watching = [self.monitor_check, self.interval_combo, self.monitor_label, self.watch_check, self.watch_label]
        view_tools = [self.overlay_button, self.hosts_check, self.undo_button, self.redo_button, self.fit_button,
                      self.arrange_button]
        if self.compact_top:
            unused = file_buttons
            row(self.map_button, self.crawl_button, 12, *watching, self.status_slack, 12, self.find_input, *view_tools)
            rows += [self.crawl_row, self.status_label, self.crawl_progress.row, self.tribe_label]
        else:
            unused = [self.map_button, self.crawl_button, self.status_slack]
            rows += [self.crawl_row, self.status_label, self.crawl_progress.row]
            row(*file_buttons, 16, *watching, None)
            row(self.find_input, *view_tools)
            rows.append(self.tribe_label)
        for widget in unused:
            widget.setParent(self.spare)
        for widget in rows:
            layout.addWidget(widget)
        for widget in old:  # Everything in them has moved
            widget.deleteLater()
        self.status_label.set_one_line(self.compact_top)
        self.fit_statuses()
        self.update_crawl_row()

    def show_summary(self, label, text):
        """Monitor's or Watch's news, beside its switch (none: hidden)."""
        label.setText(text)
        label.setVisible(bool(text))
        self.fit_statuses()

    def fit_statuses(self):
        """On the compact bar, Monitor's and Watch's news share a set amount of room (room for "999 up · 99 down" and
        for "checking · 99 new", for those showing), so the find box keeps its width whatever they say: Monitor's
        takes what it needs (leaving Watch's at least what it needs, or its own share) and Watch's the rest, so a long
        one (who's watching a tribe map, say) has the room a short one leaves."""
        monitor_label, watch_label = self.monitor_label, self.watch_label
        if not self.compact_top:
            for label in (monitor_label, watch_label):
                label.set_one_line(False)
            return
        metrics = monitor_label.fontMetrics()
        share = {monitor_label: metrics.horizontalAdvance("999 up · 99 down") + 8,
                 watch_label: metrics.horizontalAdvance("checking · 99 new") + 8}
        shown = [label for label in share if not label.isHidden()]
        budget = sum(share[label] for label in shown)
        need = {label: metrics.horizontalAdvance(label.text()) + 8 for label in shown}
        widths = {}
        if monitor_label in shown:
            watch_needs = min(need[watch_label], share[watch_label]) if watch_label in shown else 0
            widths[monitor_label] = min(need[monitor_label], max(share[monitor_label], budget - watch_needs))
        if watch_label in shown:
            widths[watch_label] = budget - widths.get(monitor_label, 0)
        for label in (monitor_label, watch_label):
            label.set_one_line(True, widths.get(label) or share[label])
        self.status_slack.setFixedWidth(budget - sum(widths.values()))  # Only monitoring: what its news don't use

    def set_compact_top(self, compact):
        self.compact_top = compact
        self.lay_out_top_bar()
        self.update_buttons()

    def update_crawl_row(self):
        """The crawl row: always on the classic bar; on the compact one while there's no map (to start one) or a crawl
        is running (to stop it), or while Crawl is down."""
        needed = self.network_map is None or self.worker is not None
        self.crawl_button.setEnabled(not needed)
        self.crawl_row.setVisible(not self.compact_top or needed or self.crawl_button.isChecked())

    def build_map_menu(self):
        """The compact bar's Map menu: what the classic bar's map file buttons do, each as enabled as its button."""
        # Its actions and submenus are made here, not by addAction(text) or addMenu(text): Qt doesn't tell Python when
        # it deletes ones it made, so those kept below would outlive the menu as wrappers of freed memory, which a
        # later lookup of another object at that address can be handed (ColumnFitter was, crashing the tests)
        menu = self.map_menu
        self.map_entries = []  # (action or submenu, the classic bar's button it stands for)
        self.mirrored = {}  # Submenu -> (the classic bar's button's menu, what fills that, or None)
        # The crawl row (start from, the adapter's gateway, credentials, scope, Start and Stop), as Crawl shows it
        self.crawl_action = QAction("Crawl: Start From, Gateway, Start, Stop", menu)
        menu.addAction(self.crawl_action)
        self.crawl_action.setCheckable(True)
        self.crawl_action.toggled.connect(self.show_crawl_row)
        menu.addSeparator()
        for button, source, fill in ((self.new_button, None, None), (self.open_button, None, None),
                                     (self.recent_button, self.recent_menu, self.fill_recent_menu),
                                     (self.save_button, None, None), (self.export_button, self.export_menu, None),
                                     (self.compare_button, self.compare_menu, self.fill_compare_menu),
                                     (self.ipam_network_button, None, None), (self.ipam_record_button, None, None),
                                     (None, None, None), (self.communities_button, None, None),
                                     (self.scope_button, None, None), (None, None, None),
                                     (self.tribe_button, self.tribe_menu, self.fill_tribe_menu), (None, None, None),
                                     (self.key_button, None, None)):
            if button is None:
                menu.addSeparator()
                continue
            if source is None:
                entry = QAction(button.text(), menu)
                entry.triggered.connect(button.click)
                menu.addAction(entry)
            else:
                entry = QMenu(button.text(), menu)
                menu.addMenu(entry)
                self.mirrored[entry] = source, fill
                entry.aboutToShow.connect(self.mirror_menu)  # A method, as a lambda or partial isn't safe here
            self.map_entries.append((entry, button))
        menu.aboutToShow.connect(self.update_map_menu)

    def show_key(self):
        """The map's key, in a window of its own beside the map."""
        if self.key_dialog is None:
            self.key_dialog = MapKeyDialog(self)
        self.key_dialog.show()
        self.key_dialog.raise_()
        self.key_dialog.activateWindow()

    def show_crawl_row(self, shown):
        """The Map menu's Crawl: as the Crawl button does."""
        self.crawl_button.setChecked(shown)
        if shown:
            self.seeds_input.setFocus()

    def update_map_menu(self):
        self.crawl_action.blockSignals(True)
        self.crawl_action.setChecked(self.crawl_row.isVisibleTo(self) if self.compact_top else True)
        self.crawl_action.setEnabled(self.crawl_button.isEnabled())
        self.crawl_action.blockSignals(False)
        for entry, button in self.map_entries:
            if isinstance(entry, QMenu):
                entry.menuAction().setEnabled(button.isEnabled())  # Its entry in the Map menu
            else:
                entry.setEnabled(button.isEnabled())
                entry.setText(button.text())  # Such as IPAM Network: <the map's>...

    def mirror_menu(self, submenu=None):
        """Fill one of the Map menu's submenus (the one about to show, if None) with what the classic bar's button's
        menu has now."""
        submenu = submenu or self.sender()
        source, fill = self.mirrored[submenu]
        if fill is not None:
            fill()
        submenu.clear()
        submenu.addActions(source.actions())

    # ----------------------------------------------------------------- Page interface

    def save_settings(self, settings):
        settings.setValue("netmap/seeds", self.seeds_input.text())
        try:
            settings.setValue("netmap/communities", protect(json.dumps(credentials_to_json(
                self.communities, self.overrides, self.v3_users, self.v3_first))))
        except CredentialError as error:
            log.warning("Couldn't save the map's community strings: %s", error)
        settings.setValue("netmap/version", self.version)
        settings.setValue("netmap/timeout", self.timeout)
        settings.setValue("netmap/scope", "\n".join(self.scope))
        settings.setValue("netmap/max_hops", self.max_hops)
        settings.setValue("netmap/max_devices", self.max_devices)
        settings.setValue("netmap/collect_hosts", self.collect_hosts)
        settings.setValue("netmap/trace", self.trace)
        settings.setValue("netmap/workers", self.workers)
        if not self.unopened:  # While the map open last time couldn't be reopened, they're kept for when it is
            for key, value in self.switches().items():
                settings.setValue(key, value)
        settings.setValue("netmap/monitor_interval", self.interval_combo.currentData())
        settings.setValue("netmap/last_map", self.open_map_value())
        timers = self.watcher.timers.values()
        settings.setValue("netmap/watch_neighbors", timers["neighbor_interval"])
        settings.setValue("netmap/watch_hosts", timers["host_interval"])
        settings.setValue("netmap/watch_recheck", timers["recheck_interval"])
        settings.setValue("netmap/watch_trigger_delay", timers["trigger_delay"])
        settings.setValue("netmap/watch_listen", self.watcher.listen_check.isChecked())
        settings.setValue("netmap/splitter", self.splitter.saveState())
        settings.setValue("netmap/arrange_style", self.arrange_style)
        settings.setValue("netmap/arrange_spacing", self.arrange_spacing)
        settings.setValue("netmap/keep_groups", self.keep_groups)
        settings.setValue("netmap/compact_top", self.compact_top)

    def restore_settings(self, settings):
        self.seeds_input.setText(settings.value("netmap/seeds", "", str))
        self.communities = [settings.value("snmp/community", "public", str) or "public"]
        stored = settings.value("netmap/communities", "", str)
        if stored:
            try:
                self.communities, self.overrides, self.v3_users, self.v3_first = credentials_from_json(
                    json.loads(unprotect(stored)), self.communities)
            except (CredentialError, ValueError, TypeError) as error:
                log.warning("Couldn't read the map's saved community strings: %s", error)
        self.version = settings.value("netmap/version", V2C, int)
        self.timeout = settings.value("netmap/timeout", DEFAULTS["timeout"], int)
        self.scope = [line for line in settings.value("netmap/scope", "", str).splitlines() if line.strip()]
        self.max_hops = settings.value("netmap/max_hops", DEFAULTS["max_hops"], int)
        self.max_devices = settings.value("netmap/max_devices", DEFAULTS["max_devices"], int)
        self.collect_hosts = settings.value("netmap/collect_hosts", True, bool)
        self.trace = settings.value("netmap/trace", True, bool)
        self.workers = max(1, min(MAX_WORKERS, settings.value("netmap/workers", WORKERS, int)))
        style = settings.value("netmap/arrange_style", TOP_DOWN, str)
        self.arrange_style = style if style in STYLE_NAMES else TOP_DOWN
        spacing = settings.value("netmap/arrange_spacing", NORMAL, str)
        self.arrange_spacing = spacing if spacing in SPACINGS else NORMAL
        self.keep_groups = settings.value("netmap/keep_groups", True, bool)
        if settings.value("netmap/compact_top", True, bool) != self.compact_top:
            self.set_compact_top(not self.compact_top)
        splitter = settings.value("netmap/splitter")
        if splitter is not None:
            self.splitter.restoreState(splitter)
        self.reopen(settings.value("netmap/last_map", "", str))
        interval = settings.value("netmap/monitor_interval", monitor.DEFAULT_INTERVAL, int)
        if interval in monitor.INTERVALS:
            self.interval_combo.setCurrentIndex(monitor.INTERVALS.index(interval))
        self.watcher.timers.set_values({name: settings.value(f"netmap/{key}", default, int) for name, key, default in (
            ("neighbor_interval", "watch_neighbors", watch.NEIGHBOR_INTERVAL),
            ("host_interval", "watch_hosts", watch.HOST_INTERVAL),
            ("recheck_interval", "watch_recheck", watch.RECHECK_INTERVAL),
            ("trigger_delay", "watch_trigger_delay", watch.TRIGGER_DELAY))})
        self.watcher.listen_check.setChecked(settings.value("netmap/watch_listen", True, bool))
        if self.network_map is not None:  # Carry on monitoring and watching from where they were left
            wanted = {key: settings.value(key, False, bool) for key in self.switches()}
            self.restoring_switches = True
            try:
                self.monitor_check.setChecked(wanted["netmap/monitor"])
                self.watch_check.setChecked(wanted["netmap/watch"])
            finally:
                self.restoring_switches = False

    def reopen(self, last):
        """Open the map that was open when NOMAD closed (last: as open_map_value gave it). If it can't be, say why,
        and keep trying it on later starts until another map is opened."""
        if not last:
            return
        problem = ""
        if last.startswith("tribe:"):
            try:
                map_id = int(last[6:])
            except ValueError:
                return
            what = "The tribe map open last time"
            if self.tribe.ensure() is None:
                problem = ("this is the tribe server: restart NOMAD as administrator (File > Restart as "
                           "Administrator) to use its maps"
                           if is_tribe_server() and getattr(self.window, "admin", False) is not True
                           else "this computer isn't connected to the tribe")
            elif not self.open_tribe_map(map_id, quiet=True):
                info = self.tribe.maps.map_info(map_id)
                if info is not None and info.get("deleted"):
                    return  # Deleted for everyone: nothing to come back to
                problem = "it isn't on this computer yet (it arrives once the tribe server has been reached)"
        else:
            what = f"The map open last time ({Path(last).stem})"
            if not Path(last).is_file():
                problem = "the file isn't there any more"
            else:
                try:
                    self.show_map(store.load(last), Path(last), fit=True)
                except (OSError, ValueError) as error:
                    log.warning("Couldn't reopen the last network map %s: %s", last, error)
                    problem = f"it couldn't be read ({error})"
        if problem:
            self.unopened = last
            set_hint(self.status_label, f"{what} wasn't opened: {problem}. It's opened next time NOMAD starts, "
                     "unless another map is opened before then.", "warning")

    def open_map_value(self):
        """The map open, for the settings: "tribe:<id>" for a tribe map, a file's path, or "" for none (or the one
        that couldn't be reopened, while no other has been)."""
        if self.tribe_map_id is not None:
            return f"tribe:{self.tribe_map_id}"
        if self.map_path:
            return str(self.map_path)
        return self.unopened if self.network_map is None else ""

    def remember_open_map(self):
        """Note the map open in the settings straight away (not only on closing), so it's the one opened next time
        even if NOMAD doesn't get to close properly."""
        value = self.open_map_value()
        settings = getattr(self.window, "settings", None)
        if isinstance(settings, QSettings) and value != getattr(self, "remembered", None):
            self.remembered = value
            settings.setValue("netmap/last_map", value)

    def switches(self):
        """Whether Monitor and Watch are on, as saved in the settings."""
        return {"netmap/monitor": self.monitor_check.isChecked(), "netmap/watch": self.watch_check.isChecked()}

    def remember_switches(self):
        """Note Monitor and Watch being turned on or off in the settings straight away, so they're on again when
        NOMAD starts even if it doesn't get to close properly (say, Windows restarting for updates)."""
        settings = getattr(self.window, "settings", None)
        if isinstance(settings, QSettings) and not self.restoring_switches:
            for key, value in self.switches().items():
                settings.setValue(key, value)
            settings.sync()

    def shutdown(self):
        if self.carry_dialog is not None:
            self.carry_dialog.session_sender.stop_waiting()
        self.monitor.shutdown()
        self.counters.shutdown()
        self.watcher.shutdown()
        for thread in list(self.check_threads):
            thread.stop()
            thread.wait(self.timeout * 2 + 3000)
        if self.save_timer.isActive():
            self.save_timer.stop()
            self.save_positions()
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(self.timeout * 2 + 3000)
        self.tribe.shutdown()

    # ----------------------------------------------------------------- Inputs

    def gateway(self):
        adapter = self.window.current_adapter()
        return adapter.gateways4[0] if adapter is not None and adapter.gateways4 else None

    def update_gateway_button(self):
        gateway = self.gateway()
        self.gateway_button.setEnabled(gateway is not None)
        self.gateway_button.setText(f"Adapter's Gateway ({gateway})" if gateway else "Adapter's Gateway")

    def use_gateway(self):
        if self.gateway():
            self.seeds_input.setText(self.gateway())

    def edit_communities(self):
        tribe_map = None
        if self.tribe_map_id is not None and self.tribe.maps is not None:
            tribe_map = (self.tribe.maps.map_info(self.tribe_map_id) or {}).get("name", "")
        dialog = CommunitiesDialog(self.communities, self.overrides, self.version, self.timeout, self,
                                   v3_users=self.v3_users, v3_first=self.v3_first, tribe_map=tribe_map)
        if dialog.exec_() == QDialog.Accepted:
            self.communities, self.overrides, self.version, self.timeout, self.v3_users, self.v3_first = \
                dialog.values()
            self.credentials_changed()
            if dialog.build_config:
                self.watcher.open_config_builder()

    def credentials_changed(self):
        """After the credentials change: ask the devices that don't answer SNMP with them, and share them with the
        tribe map, if it's one (now, or when the server can next be reached)."""
        self.watcher.recheck_now()
        if self.tribe_map_id is not None:
            try:
                sent = self.tribe.maps.set_secrets(self.tribe_map_id, self.tribe_secrets())
            except IpamError as error:
                QMessageBox.warning(self, "SNMP Credentials", "The credentials are changed on this computer, but "
                                    f"couldn't be saved with the tribe map:\n\n{error}")
            else:
                if sent:
                    set_hint(self.status_label, "Shared the SNMP credentials with everyone in the tribe: they're "
                             "used for this map wherever it's opened or watched.", "success")
                else:
                    self.tribe.request_sync()
                    set_hint(self.status_label, "The tribe server can't be reached, so the SNMP credentials are "
                             "used on this computer for now and shared with the tribe once it can be.", "warning")
            self.write_map(self.network_map, None)  # Version and timeout go with the map
            self.update_tribe_label()

    def credentials(self):
        """The community strings and SNMPv3 users a crawl tries, in order."""
        return ordered_credentials(self.communities, self.v3_users, self.v3_first)

    def add_credential(self, credential):
        """Add a community string or V3User (from the SNMP Config page) to those tried, first. A user with the same
        name is replaced. Returns whether anything changed."""
        if is_v3(credential):
            if credential in self.v3_users:
                return False
            self.v3_users = [credential] + [user for user in self.v3_users if user.user != credential.user]
            self.overrides = [(subnet, credential if is_v3(item) and item.user == credential.user else item)
                              for subnet, item in self.overrides]
        else:
            if credential in self.communities:
                return False
            self.communities = [credential] + list(self.communities)
        self.credentials_changed()
        return True

    def edit_scope(self):
        dialog = ScopeDialog(self.scope, self.max_hops, self.max_devices, self.collect_hosts, self.trace,
                             self.workers, self)
        if dialog.exec_() == QDialog.Accepted:
            self.scope, self.max_hops, self.max_devices, self.collect_hosts, self.trace, self.workers = \
                dialog.values()
            if self.tribe_map_id is not None and self.network_map is not None:
                self.write_map(self.network_map, None)  # Kept with the tribe's map

    # ----------------------------------------------------------------- Crawling

    def crawl_from(self, address):
        """Crawl from one device (the map's right-click menu), adding what it finds to the map open: devices
        already read aren't read again, so it reaches out from there. Start still makes a new map."""
        if self.network_map is None:
            self.seeds_input.setText(address)
            self.start()
        else:
            self.start(seeds=[address], extend=True)

    def start(self, seeds=None, extend=False):
        if self.worker is not None:
            return
        if not extend and self.tribe_map_id is not None and self.network_map is not None \
                and not self.confirm_remap_tribe_map():
            return
        self.extending = extend and self.network_map is not None
        seeds = seeds or parse_seeds(self.seeds_input.text())
        if not seeds:
            if self.gateway():
                self.use_gateway()
                seeds = [self.gateway()]
            else:
                set_hint(self.status_label, "Enter the address of a switch or router to start from.", "error")
                return
        self.worker = CrawlThread(self.crawl_settings(seeds), self.network_map if self.extending else None, self)
        self.worker.event.connect(self.on_crawl_event)
        self.worker.crawled.connect(self.on_crawled)
        self.worker.failed.connect(self.on_crawl_failed)
        self.worker.finished.connect(self.on_thread_finished)
        if self.extending:
            set_hint(self.status_label, f"Crawling from {', '.join(seeds)}, adding to this map. Devices already "
                                        "read aren't read again.", "info")
        else:
            set_hint(self.status_label, f"Mapping from {', '.join(seeds)}. The map fills in as devices are read; "
                                        "the Crawl tab shows what each one is doing and a log of what was found.",
                     "info")
        self.live_map = None
        self.live_positions = dict(self.network_map.positions) if self.network_map else {}
        self.crawled_map = False
        if self.tabs.currentWidget() not in (self.view, self.crawl_progress.tab):
            self.tabs.setCurrentWidget(self.view)
        self.crawl_progress.start()
        self.window.set_busy("netmap", "Mapping the network")
        self.worker.start()
        self.crawl_button.setChecked(False)  # The crawl row stays while it runs (for Stop), and goes when it's done
        self.update_buttons()

    def confirm_remap_tribe_map(self):
        """Start, with a tribe map open: map it again (for everyone), or start a new map and leave it be? Returns
        whether to go on."""
        box = QMessageBox(QMessageBox.Question, "Start Mapping",
                          f"The tribe map {self.map_name()} is open. Start a new map and leave the tribe map as it "
                          "is, or map the tribe map again (for everyone in the tribe)?", parent=self)
        new = box.addButton("New Map", QMessageBox.AcceptRole)
        again = box.addButton("Map the Tribe Map Again", QMessageBox.DestructiveRole)
        box.addButton(QMessageBox.Cancel)
        box.setDefaultButton(new)
        box.exec_()
        if box.clickedButton() is new:
            self.new_map(quiet=True)
            return True
        return box.clickedButton() is again

    def new_map(self, quiet=False):
        """Put the map open away (saved, and left as it is) and have none open: Start then makes a new one."""
        if self.worker is not None:
            return
        self.flush_save()
        for check in (self.watch_check, self.monitor_check):  # Watching lets go of the tribe map before it's closed
            check.setChecked(False)
        self.tribe_map_id, self.tribe_seen = None, None
        self.network_map, self.map_path, self.history_map, self.unopened = None, None, None, ""
        self.watched_identity = None
        self.undo_stack, self.redo_stack, self.layout_now = [], [], None
        self.view.clear_map()
        self.l3_view.clear_map()
        self.l3_nodes, self.l3_links = {}, []
        for table in (self.devices_table, self.links_table, self.hosts_table):
            table.setRowCount(0)
        self.vlan_shown, self.overlay_shown = None, None
        self.vlan_panel.set_map(None)
        self.apply_vlan_focus()
        self.monitor.set_map(NetworkMap())
        self.monitor.load_history([])
        self.show_details(None)
        self.update_tribe_label()
        self.update_watch_label()
        self.update_buttons()
        if not quiet:
            set_hint(self.status_label, "New map: enter the switch or router to start from and press Start. The map "
                     "that was open is as it was: open it again from Recent, or Tribe.", "info")

    def crawl_settings(self, seeds):
        devices = self.network_map.devices.values() if self.network_map else []
        return CrawlSettings(seeds=seeds, communities=self.credentials(), overrides=list(self.overrides),
                             scope=list(self.scope), max_hops=self.max_hops, max_devices=self.max_devices,
                             version=self.version, timeout=self.timeout, collect_hosts=self.collect_hosts,
                             trace=self.trace, workers=self.workers,
                             corrections={device.key: device.corrections() for device in devices if device.corrected},
                             deleted={key: list(addresses) for key, (_, addresses)
                                      in (self.network_map.deleted.items() if self.network_map else [])})

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
            set_hint(self.status_label, "Stopping: finishing the devices being read...", "warning")

    def on_thread_finished(self):
        self.worker = None
        self.crawl_progress.finish()
        live, self.live_map = self.live_map, None
        self.view.set_highlights({})
        if live is not None and not self.crawled_map:  # Failed part way: back to the map there was
            if self.network_map is not None:
                self.show_map(self.network_map, self.map_path)
            else:
                self.view.clear_map()
        self.window.clear_busy("netmap")
        self.record_layout()  # Where Undo starts from on the map crawled
        self.update_buttons()

    def on_crawl_event(self, kind, details):
        self.crawl_progress.handle(kind, details)
        if kind == "community":
            self.answered[details[0]] = details[1]
        elif kind == "map":
            self.show_live(details[0])
        elif kind in ("started", "finished") and self.live_map is not None:
            self.ring_devices_being_read()

    def show_live(self, snapshot):
        """Draw the map found so far. Devices already drawn stay where they are (or where they were dragged)."""
        if QApplication.mouseButtons() != Qt.NoButton:
            return  # Mid-drag or mid-pan: the next snapshot is only a moment away
        first = self.live_map is None
        if not first:
            self.live_positions.update(self.view.positions())
        if self.extending:
            # The map with what's been found so far; a device added by hand that's been read is drawn in its place
            snapshot = self.network_map.preview_with(snapshot, self.live_positions)
            self.live_positions = snapshot.positions
            first = False  # Keep the view where it is: the map's already on screen
        nodes = list(snapshot.devices)
        edges = [(link.a, link.b) for link in snapshot.links]
        root = self.network_map.root if self.network_map and self.network_map.root in snapshot.devices else None
        self.live_positions = merge_positions(nodes, edges, self.live_positions, root=root,
                                              weight=lambda key: KIND_WEIGHTS.get(snapshot.devices[key].kind, 0))
        self.live_map = snapshot
        self.view.groups_editable = False
        self.view.set_map(snapshot, self.live_positions)
        self.view.set_statuses(self.monitor.status)
        self.ring_devices_being_read()
        if first:
            self.view.request_fit()
        elif self.view.auto_fit:
            self.view.fit()

    def add_crawl(self, newer):
        """Crawl from Here finished: add what it found to the map open, and save it in the same file."""
        base = self.network_map
        base.positions = self.view.positions() if self.live_map is not None else base.positions
        before = {key for key, device in base.devices.items() if device.source == SNMP}
        added, read = base.merge_crawl(newer)
        base.bring_back(added)  # Started from one that was deleted: it's back
        folded = base.fold_manual_devices(new=set(added))  # Ones added by hand it has now found, kept where they were
        self.live_map = None
        if self.map_path is not None or self.tribe_map_id is not None:
            try:
                self.write_map(base, self.map_path)
            except OSError as error:
                log.warning("Couldn't save the network map: %s", error)
        self.show_map(base, self.map_path)
        newly_read = len(read - before)
        message = (f"{'Stopped' if newer.stopped else 'Done'}: added {len(added)} device"
                   f"{'' if len(added) == 1 else 's'} to this map ({newly_read} read over SNMP for the first time)"
                   f", {len(newer.links)} links and {len(newer.hosts)} hosts from the devices read.")
        problems = sum(1 for key in added if base.devices[key].source in (NO_SNMP, UNREACHABLE))
        if problems:
            message += f" {problems} of the new ones didn't answer SNMP."
        message += folded_text(folded)
        set_hint(self.status_label, message, "warning" if newer.stopped or problems else "success")

    def ring_devices_being_read(self):
        if self.live_map is None:
            return
        by_address = {device.mgmt_ip: key for key, device in self.live_map.devices.items() if device.mgmt_ip}
        self.view.set_highlights({by_address[address]: COLORS["accent"]
                                  for address in self.crawl_progress.reading if address in by_address})

    def displayed_map(self):
        """The map being drawn: the one so far while crawling, otherwise the one open."""
        return self.live_map or self.network_map

    def on_crawled(self, network_map):
        self.crawled_map = True
        if self.extending:
            self.add_crawl(network_map)
            return
        dropped, folded, links_left_out = [], [], 0
        if self.network_map is not None:  # Devices and links added by hand, first: their places are kept below
            network_map.carry_deleted(self.network_map)
            folded, links_left_out = network_map.carry_manual(self.network_map)
        if self.live_positions:  # Where devices were drawn (and dragged) while it crawled
            network_map.positions = {key: position for key, position in self.live_positions.items()
                                     if key in network_map.devices}
            if self.live_map is not None:
                network_map.positions.update({key: position for key, position in self.view.positions().items()
                                              if key in network_map.devices})
        if self.network_map is not None:  # Keep where the user put devices that are still there
            if not self.live_positions:
                network_map.positions = {key: position for key, position in self.network_map.positions.items()
                                         if key in network_map.devices}
            for key, device in network_map.devices.items():  # The live drawing only had what the crawl found
                if device.manual and key in self.network_map.positions:
                    network_map.positions.setdefault(key, self.network_map.positions[key])
            network_map.root = self.network_map.root if self.network_map.root in network_map.devices else ""
            dropped = network_map.carry_manual_hosts(self.network_map)
            network_map.carry_groups(self.network_map, folded)  # Sites and buildings, with the devices still there
            network_map.status_log = self.network_map.status_log  # The same network's monitoring history
            network_map.ipam_network = self.network_map.ipam_network  # And the same IPAM network
            if self.history_map is self.network_map:
                self.history_map = network_map  # So the Monitor log isn't reloaded
        self.live_map = None
        path = None
        try:
            if self.tribe_map_id is not None:  # The tribe's map, mapped again
                self.write_map(network_map, None)
            else:
                path = store.save(network_map)
        except OSError as error:
            log.warning("Couldn't save the network map: %s", error)
        self.show_map(network_map, path, fit=not self.live_positions or self.view.auto_fit)
        snmp_count = sum(1 for device in network_map.devices.values() if device.source == SNMP)
        problems = sum(1 for device in network_map.devices.values() if device.source in (NO_SNMP, UNREACHABLE))
        message = (f"{'Stopped' if network_map.stopped else 'Done'}: {len(network_map.devices)} devices "
                   f"({snmp_count} read over SNMP), {len(network_map.links)} links, {len(network_map.hosts)} hosts"
                   + (f", {len(network_map.traces)} traceroutes" if network_map.traces else "") + ".")
        if problems:
            message += f" {problems} didn't answer SNMP (dashed or red; select one to see why)."
        if dropped:
            message += (" 1 host added by hand wasn't kept: its switch isn't on this map." if len(dropped) == 1
                        else f" {len(dropped)} hosts added by hand weren't kept: their switch isn't on this map.")
        message += folded_text(folded)
        if links_left_out:
            message += (f" {count_text(links_left_out, 'link')} drawn by hand "
                        f"{'was' if links_left_out == 1 else 'were'} left out: a device at the end isn't on this map.")
        if path:
            message += f" Saved as {path.name}."
        elif self.tribe_map_id is not None:
            message += " Saved to the tribe map."
        set_hint(self.status_label, message, "warning" if network_map.stopped or problems or dropped
                 or links_left_out else "success")
        # Ask the devices added by hand again, so whether they answer SNMP is as fresh as the rest
        self.check_devices([key for key, device in network_map.devices.items() if device.manual and device.mgmt_ip])

    # ----------------------------------------------------------------- Showing a map

    def show_map(self, network_map, path=None, fit=False):
        if network_map is not self.network_map:  # Another map: nothing to undo on it yet
            self.undo_stack, self.redo_stack, self.layout_now = [], [], None
        self.network_map, self.map_path = network_map, path
        nodes = list(network_map.devices)
        edges = [(link.a, link.b) for link in network_map.links]
        positions = merge_positions(nodes, edges, network_map.positions, root=network_map.root or None,
                                    weight=lambda key: KIND_WEIGHTS.get(network_map.devices[key].kind, 0))
        network_map.positions = positions
        self.view.groups_editable = True
        self.view.set_map(network_map, positions)
        self.l3_nodes, l3_links = l3.l3_graph(network_map)
        self.l3_links = l3_links
        l3_positions = merge_positions(list(self.l3_nodes), [(link.a, link.b) for link in l3_links],
                                       network_map.l3_positions,
                                       weight=lambda key: 1 if self.l3_nodes[key].kind == l3.DEVICE else 0)
        network_map.l3_positions = l3_positions
        self.l3_view.set_graph(self.l3_nodes, l3_links, l3_positions)
        self.monitor.set_map(network_map)
        if network_map is not self.history_map:
            self.history_map = network_map
            self.monitor.load_history(network_map.status_log)
        self.show_statuses()
        self.fill_tables()
        self.vlan_panel.set_map(network_map)
        self.apply_vlan_focus()
        self.show_details(None)
        if self.hosts_check.isChecked():
            self.view.set_all_hosts_shown(True)
        self.view.set_news(network_map.news)
        identity = (self.tribe_map_id, str(path), network_map.started)
        if identity != getattr(self, "watched_identity", None):
            self.watched_identity = identity
            self.watcher.map_changed()  # Watching carries on, on this map
        if fit:
            self.view.request_fit()
            self.l3_view.request_fit()
        self.record_layout()  # Re-arranged: Undo puts it back
        self.update_buttons()
        self.unopened = ""
        self.remember_open_map()
        self.map_shown.emit()
        self.update_network_bar()

    def current_view(self):
        """The drawing showing (or the physical one while a table is)."""
        return self.l3_view if self.tabs.currentWidget() is self.l3_view else self.view

    def rearrange(self, style=None):
        """Lay out the view showing again (in style, which is remembered, or the last one), forgetting where things
        were dragged to."""
        if self.network_map is None or self.worker is not None:
            return
        self.arrange_style = style or self.arrange_style
        view = self.current_view()
        nodes = list(self.l3_nodes) if view is self.l3_view else list(self.network_map.devices)
        positions = arrange(nodes, style=self.arrange_style, **self.arrange_options(view, nodes))
        if view is self.l3_view:
            self.network_map.l3_positions = positions
        else:
            self.network_map.positions = positions
        self.show_map(self.network_map, self.map_path, fit=True)
        self.save_positions()

    def arrange_options(self, view, keys):
        """What arranging these devices (or the logical view's nodes) needs besides the style."""
        if view is self.l3_view:
            return {"edges": [(link.a, link.b) for link in self.l3_links],
                    "weight": lambda key: 1 if self.l3_nodes[key].kind == l3.DEVICE else 0,
                    "spacing": SPACINGS[self.arrange_spacing]}
        network_map = self.network_map
        options = {"edges": [(link.a, link.b) for link in network_map.links], "root": network_map.root or None,
                   "weight": lambda key: KIND_WEIGHTS.get(network_map.devices[key].kind, 0)}
        if self.keep_groups and network_map.groups:
            options["path_of"] = {key: [group.key for group in network_map.group_path(key)] for key in keys}
            options["order"] = lambda group_key: network_map.group(group_key).name.lower()
        options["spacing"] = SPACINGS[self.arrange_spacing]
        return options

    def fill_arrange_menu(self):
        menu = self.arrange_menu
        menu.clear()
        styles = QActionGroup(menu)
        for style, name in STYLE_NAMES.items():
            action = menu.addAction(name)
            action.setCheckable(True)
            action.setChecked(style == self.arrange_style)
            styles.addAction(action)
            action.triggered.connect(lambda _, style=style: self.rearrange(style))
        view = self.current_view()
        keys, groups = view.selected_keys(), self.selected_groups(view)
        count = len(view.boxes(keys, groups))
        if count > 1 and self.worker is None:  # Spacing what's selected, as Arrange Selected arranges just it
            self.add_spacing_menu(menu, f"Spacing of the {count} {self.selection_name(count, groups)}",
                                  self.measured_spacing(view, keys, groups),
                                  lambda key: self.space_out(view, keys, groups, key))
        else:
            self.add_spacing_menu(menu, "Spacing", self.arrange_spacing, self.set_spacing).setEnabled(self.network_map is not None and self.worker is None)
        menu.addSeparator()
        keep = menu.addAction("Keep Groups Together")
        keep.setCheckable(True)
        keep.setChecked(self.keep_groups)
        keep.toggled.connect(self.set_keep_groups)
        menu.addSeparator()
        self.add_selection_actions(menu, view, keys, always=True, spacing=False)
        if self.network_map is not None and self.network_map.groups and view is self.view:
            menu.addSeparator()
            menu.addAction("Collapse All Groups", lambda: self.view.set_all_collapsed(True))
            menu.addAction("Expand All Groups", lambda: self.view.set_all_collapsed(False))

    def set_spacing(self, key):
        """Space the view showing out this far (keeping it as it's arranged), and re-arrange this far from now on."""
        self.arrange_spacing = key
        if self.network_map is None or self.worker is not None:
            return
        view = self.current_view()
        self.space_out(view, list(view.positions()), (), key)
        view.fit()

    def space_out(self, view, keys, groups=(), spacing=NORMAL):
        """Stretch or shrink the gaps between these devices (and with groups, those groups' boxes, each with everything
        in it) to spacing, keeping them as they're arranged: each stays where it is among the rest."""
        boxes = view.boxes(keys, groups)
        if len(boxes) < 2:
            return
        centers = {key: (x, y) for key, (x, y, _, _) in boxes.items()}
        sizes = {key: (width, height) for key, (_, _, width, height) in boxes.items()}
        view.move_boxes(respace(centers, SPACINGS[spacing], sizes, self.closest_gap(view)))
        # Arranging these again keeps the spacing (and the style they were last arranged in)
        self.last_arranged = ((view, frozenset(keys), frozenset(groups)),
                              self.selection_arrangement(view, keys, groups)[0], spacing)

    def closest_gap(self, view):
        """How close spacing out may bring two devices that were apart: further for two in different sites, buildings
        or rooms, so the boxes drawn round them don't run into each other."""
        group_of = self.network_map.group_of if self.network_map is not None and view is self.view else {}

        def gap(a, b):
            return RESPACE_MIN_GAP + (0 if group_of.get(a) == group_of.get(b) else 2 * GROUP_PAD + GROUP_TITLE)

        return gap

    def measured_spacing(self, view, keys, groups=()):
        """The spacing (key) these are spaced out at now, if they're near enough one: the one to mark in a menu."""
        boxes = view.boxes(keys, groups)
        return nearest_spacing(spacing_of({key: (x, y) for key, (x, y, _, _) in boxes.items()},
                                          {key: (width, height) for key, (_, _, width, height) in boxes.items()}))

    def set_keep_groups(self, on):
        self.keep_groups = on
        set_hint(self.status_label, "Re-arrange lays out each site, building and room in its own box." if on else
                 "Re-arrange lays out the devices without regard to their groups.", "info")

    def add_selection_actions(self, menu, view, keys, always=False, groups=None, spacing=True):
        """Arrange Selected, Spacing (unless not spacing) and Align (with Distribute) for the devices and groups
        (sites, buildings and rooms) selected on a map. groups: their keys (those selected, if None). always: show them
        (disabled) when fewer than two are selected."""
        groups = self.selected_groups(view) if groups is None else groups
        count = len(view.boxes(keys, groups))
        if count < 2 and not always:
            return
        enabled = count > 1 and self.worker is None
        what = self.selection_name(count, groups)
        style = self.selection_arrangement(view, keys, groups)[0]
        arranged = self.add_style_menu(menu, f"Arrange the {count} {what}" if count > 1 else "Arrange Selected",
                                       lambda style: self.arrange_selected(view, keys, groups, style), style)
        arranged.setEnabled(enabled)
        if spacing:
            spaced = self.add_spacing_menu(menu, f"Spacing of the {count} {what}" if count > 1 else
                                           "Spacing of the Selected",
                                           self.measured_spacing(view, keys, groups) if count > 1 else None,
                                           lambda key: self.space_out(view, keys, groups, key))
            spaced.setEnabled(enabled)
        lining = menu.addMenu("Align")
        lining.setEnabled(enabled)
        for entry in ALIGNMENTS + [None, ("Distribute Horizontally", HORIZONTAL), ("Distribute Vertically", VERTICAL)]:
            if entry is None:
                lining.addSeparator()
            else:
                lining.addAction(entry[0]).triggered.connect(
                    lambda _, how=entry[1]: self.align_selected(view, keys, how, groups))

    @staticmethod
    def selection_name(count, groups):
        return "Selected" if not groups else "Selected Groups" if count == len(groups) else "Selected Items"

    def add_style_menu(self, menu, title, chosen, current=None):
        """A submenu of the arrangements, calling chosen(style); current (or the one Re-arrange uses) is marked."""
        submenu = menu.addMenu(title)
        for style, name in STYLE_NAMES.items():
            action = submenu.addAction(name)
            action.setCheckable(True)
            action.setChecked(style == (current or self.arrange_style))
            action.triggered.connect(lambda _, style=style: chosen(style))
        return submenu

    def add_spacing_menu(self, menu, title, current, chosen):
        """A submenu of the spacings (how far apart things are spaced out), calling chosen(key); current (how far
        apart they are now, if it's near enough one) is marked."""
        submenu = menu.addMenu(title)
        for key, name in SPACING_NAMES.items():
            action = submenu.addAction(name)
            action.setCheckable(True)
            action.setChecked(key == current)
            action.triggered.connect(lambda _, key=key: chosen(key))
        return submenu

    def selection_arrangement(self, view, keys, groups=()):
        """(style, spacing) these were last arranged in (so changing one keeps the other), or else Re-arrange's."""
        if self.last_arranged is not None and self.last_arranged[0] == (view, frozenset(keys), frozenset(groups)):
            return self.last_arranged[1:]
        return self.arrange_style, self.arrange_spacing

    def selected_groups(self, view):
        return view.selected_groups() if view is self.view else []

    def arrange_selected(self, view, keys, groups=(), style=None, spacing=None):
        """Lay out just these devices, where they are, in style and spacing (if None, those they were last arranged
        in, or Re-arrange's); with groups, those groups' boxes (each with everything in it) and the devices not in
        them."""
        last_style, last_spacing = self.selection_arrangement(view, keys, groups)
        style, spacing = style or last_style, spacing or last_spacing
        self.last_arranged = ((view, frozenset(keys), frozenset(groups)), style, spacing)
        if groups:
            boxes = view.boxes(keys, groups)
            weight = self.arrange_options(view, [])["weight"]
            view.move_boxes(arrange_boxes_in_place(boxes, view.box_links(boxes), style=style,
                                                   weight=lambda key: 0 if key.startswith(GROUP_BOX) else weight(key),
                                                   spacing=SPACINGS[spacing]))
            return
        where = view.positions()
        positions = {key: where[key] for key in keys if key in where}
        options = self.arrange_options(view, keys)
        options["spacing"] = SPACINGS[spacing]
        view.move_to(arrange_in_place(positions, style=style, **options))

    def align_selected(self, view, keys, how, groups=()):
        """Line up devices (and with groups, those groups' boxes and the devices not in them) by their edges or
        middles, or space them evenly."""
        boxes = view.boxes(keys, groups)
        centers = {key: (x, y) for key, (x, y, _, _) in boxes.items()}
        sizes = {key: (width, height) for key, (_, _, width, height) in boxes.items()}
        line_up = distribute if how in (HORIZONTAL, VERTICAL) else align
        view.move_boxes(line_up(centers, how, sizes))

    def groups_toggled(self):
        """A group was collapsed or expanded. On a tribe map that's this computer's own: kept here now, with nothing
        to send (and no saving the whole layout, which could cross with someone else's move). On a file, saved."""
        if self.tribe_map_id is not None and self.tribe.maps is not None and self.network_map is not None:
            self.tribe.maps.keep_collapsed(self.tribe_map_id, self.network_map)
        else:
            self.save_timer.start()

    def save_positions(self):
        if self.network_map is None or (self.map_path is None and self.tribe_map_id is None):
            return
        self.network_map.positions = self.view.positions()
        self.network_map.l3_positions = self.l3_view.positions()
        try:
            self.write_map(self.network_map, self.map_path)
        except OSError as error:
            log.warning("Couldn't save the network map's layout: %s", error)

    def fill_tables(self):
        network_map = self.network_map
        self.device_keys = [device.key for device in sorted(network_map.devices.values(),
                                                            key=lambda device: device.label.lower())]
        fill_table(self.devices_table, export.device_rows(network_map, self.monitor.status_text), ip_columns={2},
                   keys=self.device_keys)
        fill_table(self.links_table, export.link_rows(network_map),
                   keys=[LinkRow(link) for link in export.sorted_links(network_map)])
        fill_table(self.hosts_table, [row + [""] for row in export.host_rows(network_map)], ip_columns={1},
                   keys=list(range(len(network_map.hosts))))
        self.fill_ipam_column()
        for table_filter in self.table_filters.values():
            table_filter.apply()  # Filters carry over to the new rows

    def show_filtered_count(self, table, shown, total):
        """ "Hosts (12 of 340)" on the tab while its table is filtered."""
        name = self.table_names[table]
        filtered = self.table_filters[table].active if table in getattr(self, "table_filters", {}) else False
        self.tabs.setTabText(self.tabs.indexOf(table), f"{name} ({shown} of {total})" if filtered else name)

    def show_vlan_filter_count(self, shown, total):
        self.show_filtered_count(self.vlan_panel, shown, total)

    # ----------------------------------------------------------------- VLANs

    def highlight_vlan(self, vlan, domain=None):
        """Show one VLAN on the physical view: what carries it stays bright, the rest fades."""
        if self.network_map is None:
            return
        self.vlan_shown, self.overlay_shown = (vlan, domain), None
        self.tabs.setCurrentWidget(self.view)
        self.apply_vlan_focus()

    def show_overlay(self, kind, argument=None):
        """Show an overlay (netmap.overlays) on the physical view, instead of the VLAN or overlay showing."""
        if self.network_map is None:
            return
        self.vlan_shown, self.overlay_shown = None, (kind, argument)
        self.tabs.setCurrentWidget(self.view)
        self.apply_vlan_focus()

    def apply_vlan_focus(self):
        """Highlight the VLAN chosen, or show the overlay chosen (again, after the map was drawn again), or show
        everything."""
        network_map = self.network_map
        overlay = overlays.build(network_map, *self.overlay_shown, rates=self.counters.rates,
                                 monitoring=self.monitor.running) if self.overlay_shown is not None else None
        if overlay is None:
            self.overlay_shown = None  # Of a VRF or device that's gone
        if (self.vlan_shown is None and overlay is None) or network_map is None:
            self.view.set_overlay(None)
            self.view.set_vlan_focus(None)
            self.vlan_bar.hide()
            return
        if overlay is not None:
            self.view.set_vlan_focus(None)
            self.view.set_overlay(overlay)
            self.vlan_label.setText(overlay_text(overlay))
            self.vlan_bar.show()
            return
        self.view.set_overlay(None)
        vlan, domain = self.vlan_shown
        focus = vlan_info.focus(network_map, vlan, domain)
        self.view.set_vlan_focus(focus)
        item = next((item for item in vlan_info.map_vlans(network_map)
                     if item.vlan == vlan and (domain is None or item.domain == domain)), None)
        name = f" {item.name}" if item is not None and item.name else ""
        where = f" in {domain_text(domain)}" if domain is not None and vlan_info.domains(network_map)[1:] else ""
        kinds = list(focus.links.values())
        parts = [f"<b>Highlighting VLAN {vlan}{html.escape(name)}{html.escape(where)}</b>:",
                 f"{count_text(len(focus.devices), 'device')}, {count_text(len(kinds), 'link')} carrying it"]
        if item is not None and item.gateways:
            gateways = ", ".join(f"{gateway.address}/{gateway.prefix}" for gateway in item.gateways[:3])
            parts.append(f"· gateway {html.escape(gateways)}")
        if vlan_info.ONE_END in kinds:
            mismatched = kinds.count(vlan_info.ONE_END)
            parts.append(f"· <span style='color:{COLORS['warning']}'>{count_text(mismatched, 'trunk')} with it "
                         "allowed at one end only (dashed orange)</span>")
        parts.append("· blue: tagged on trunks (dashed: native), green: between access ports")
        self.vlan_label.setText(" ".join(parts))
        self.vlan_bar.show()

    def read_vlans_again(self, routes=False):
        """Read the VLANs of every switch on the map that answered SNMP (not their neighbors or hosts): for a map made
        before NOMAD read VLANs, or to bring them up to date without mapping again. routes: their routing tables
        and VRFs too (Read Routes Again, for the Subnet Placement page). Returns whether it started."""
        network_map = self.network_map
        if network_map is None or self.worker is not None or self.vlan_reading is not None:
            return False
        targets = [(key, device.mgmt_ip) for key, device in network_map.devices.items()
                   if device.source == SNMP and device.mgmt_ip and device.kind in (SWITCH, ROUTER, FIREWALL)]
        if not targets:
            set_hint(self.status_label, "No device on the map answered SNMP, so there's nothing to read.", "warning")
            return False
        self.vlan_reading = {"map": network_map, "read": 0, "failed": [], "lines": [], "routes": routes}
        reader = functools.partial(self.read_vlans, routes=True) if routes else self.read_vlans
        thread = VlanReadThread(self.crawl_settings([address for _, address in targets]), targets, reader, self)
        thread.checked.connect(self.on_vlans_read)
        thread.finished.connect(self.on_vlans_read_finished)
        self.check_threads.append(thread)
        self.vlan_panel.set_reading(True)
        what = "VLANs and routes" if routes else "VLANs"
        set_hint(self.status_label, f"Reading the {what} of {count_text(len(targets), 'device')}...", "info")
        thread.start()
        return True

    def reading_routes(self):
        """Whether Read Routes Again is under way (routes_read says when it's done)."""
        return self.vlan_reading is not None and self.vlan_reading["routes"]

    def read_routes_again(self):
        """Read the VLANs, routing tables and VRFs of every device on the map that answered SNMP (the Subnet Placement
        page's Read Routes Again). Returns whether it started."""
        return self.read_vlans_again(routes=True)

    def on_vlans_read(self, key, address, result):
        reading = self.vlan_reading
        if reading is None or reading["map"] is not self.network_map:
            return  # Another map was opened meanwhile
        device = self.network_map.devices.get(key)
        tables, community = result
        if device is None:
            return
        if tables is None:
            reading["failed"].append(device.label)
            return
        if community:
            self.answered[address] = community
        before = (vlan_info.vlan_names(device), dict(device.port_vlans))
        apply_vlans(device, tables)
        reading["read"] += 1
        reading["lines"] += watch.vlan_changes(device, *before)

    def on_vlans_read_finished(self):
        thread = self.sender()
        if thread in self.check_threads:
            self.check_threads.remove(thread)
        reading, self.vlan_reading = self.vlan_reading, None
        self.vlan_panel.set_reading(False)
        if reading is None:
            return
        if reading["map"] is not self.network_map:
            if reading["routes"]:
                self.routes_read.emit(0, 0)  # Of a map no longer open
            return
        if reading["read"]:
            self.map_changed()
        for line in reading["lines"]:
            self.watcher.log(line)
        what = "VLANs and routes" if reading["routes"] else "VLANs"
        text = f"Read the {what} of {count_text(reading['read'], 'device')}"
        if reading["failed"]:
            listed = ", ".join(reading["failed"][:5]) + ("..." if len(reading["failed"]) > 5 else "")
            text += f"; {len(reading['failed'])} didn't answer SNMP ({listed})"
        changes = [line for line in reading["lines"] if not line.startswith("Read ")]
        text += f". {count_text(len(changes), 'change')} (in the Watch log)." if changes else "."
        set_hint(self.status_label, text, "warning" if reading["failed"] else "success")
        if reading["routes"]:
            self.routes_read.emit(reading["read"], len(reading["failed"]))

    def add_stop_highlight(self, menu):
        """At the top of the physical view's right-click menus while a VLAN is highlighted: an action to stop (the
        caller connects it to clear_vlan). Returns it, or None."""
        if self.tabs.currentWidget() is not self.view:
            return None
        if self.vlan_shown is not None:
            action = menu.addAction(f"Stop Highlighting VLAN {self.vlan_shown[0]} (Show All)")
        elif self.overlay_shown is not None and self.view.overlay is not None:
            action = menu.addAction(f"Stop Showing {self.view.overlay.title} (Show All)")
        else:
            return None
        menu.addSeparator()
        return action

    def clear_vlan(self):
        """Stop highlighting the VLAN, or showing the overlay."""
        self.vlan_shown, self.overlay_shown = None, None
        self.apply_vlan_focus()

    def fill_overlay_menu(self):
        """The Overlay button's menu: every overlay the map can show, the one showing ticked."""
        menu = self.overlay_menu
        menu.clear()
        for submenu in self.overlay_submenus:  # clear() leaves submenus be
            submenu.deleteLater()
        # Made here (not by addMenu(text)), so the Python wrappers kept are of menus Python made
        vlan_menu, vrf_menu, subnet_menu, color_menu, stp_menu = self.overlay_submenus = [
            QMenu(text, menu) for text in ("Highlight VLAN", "Highlight VRF", "Highlight Subnet", "Color By",
                                           "Spanning Tree")]
        network_map = self.network_map
        usable = network_map is not None and bool(network_map.devices) and self.worker is None
        shown = self.overlay_shown
        for submenu in (vlan_menu, vrf_menu, subnet_menu):
            menu.addMenu(submenu)
        if usable:
            items = vlan_info.map_vlans(network_map)
            several = len({item.domain for item in items}) > 1
            for item in items[:OVERLAY_ITEMS]:
                text = f"{item.vlan} {item.name}".strip() + (f"  ({domain_text(item.domain)})" if several else "")
                action = vlan_menu.addAction(text, lambda item=item: self.highlight_vlan(
                    item.vlan, item.domain if several else None))
                action.setCheckable(True)
                action.setChecked(self.vlan_shown is not None and self.vlan_shown[0] == item.vlan
                                  and self.vlan_shown[1] in (None, item.domain))
            if len(items) > OVERLAY_ITEMS:
                vlan_menu.addAction(f"...and {len(items) - OVERLAY_ITEMS} more (see the VLANs tab)").setEnabled(False)
            if not items:
                vlan_menu.addAction("No VLANs read (VLANs tab > Read VLANs Again)").setEnabled(False)
            vrfs = overlays.map_vrfs(network_map)
            for name, count in list(vrfs.items())[:OVERLAY_ITEMS]:
                action = vrf_menu.addAction(f"{name}  ({count_text(count, 'device')})",
                                            lambda name=name: self.show_overlay(overlays.VRF, name))
                action.setCheckable(True)
                action.setChecked(shown == (overlays.VRF, name))
            if not vrfs:
                vrf_menu.addAction("No VRFs read (Subnet Placement > Read Routes Again)").setEnabled(False)
            subnets = overlays.map_subnets(network_map)
            for text in subnets[:OVERLAY_ITEMS]:
                action = subnet_menu.addAction(text, lambda text=text: self.show_overlay(overlays.SUBNET, text))
                action.setCheckable(True)
                action.setChecked(shown == (overlays.SUBNET, text))
            if subnets:
                subnet_menu.addSeparator()
            subnet_menu.addAction("Other Subnet or Address...", self.choose_subnet_overlay)
        for submenu in (vlan_menu, vrf_menu, subnet_menu):
            submenu.menuAction().setEnabled(usable)
        menu.addSeparator()
        for kind, text, tip in (
                (overlays.SPOF, "Single Points of Failure", "The devices and links that are the only way to part of "
                                                            "the network."),
                (overlays.TRUNKS, "Trunk and Port Problems", "Links whose two ends are set up differently (trunk and "
                                                             "access, native VLANs, VLANs allowed), and ports in VLANs "
                                                             "their switch doesn't have."),
                (overlays.SPEED, "Link Speed and Status", "Each link's speed as color and thickness, and links down "
                                                          "at an end or whose ends' speed or duplex differ (as read "
                                                          "when mapped, or by Read VLANs Again)."),
                (overlays.UTIL, "Utilization and Errors", "How busy each link is and whether it's seeing errors: "
                                                          "while Monitor is on, each poll reads the counters of the "
                                                          "linked ports.")):
            action = menu.addAction(text, lambda kind=kind: self.show_overlay(kind))
            action.setToolTip(tip)
            action.setCheckable(True)
            action.setChecked(shown is not None and shown[0] == kind)
            action.setEnabled(usable)
        menu.addMenu(stp_menu)
        if usable:
            numbers = sorted({item.vlan for item in vlan_info.map_vlans(network_map)})
            for vlan in numbers[:OVERLAY_ITEMS]:
                action = stp_menu.addAction(f"VLAN {vlan}", lambda vlan=vlan: self.read_spanning_tree(vlan))
                action.setCheckable(True)
                action.setChecked(shown is not None and shown[0] == overlays.STP and shown[1][0] == vlan)
            if not numbers:
                stp_menu.addAction("No VLANs read (VLANs tab > Read VLANs Again)").setEnabled(False)
        stp_menu.menuAction().setEnabled(usable and self.stp_reading is None)
        menu.setToolTipsVisible(True)
        if shown is not None and shown[0] == overlays.IMPACT and self.view.overlay is not None:
            action = menu.addAction(self.view.overlay.title)
            action.setCheckable(True)
            action.setChecked(True)
            action.setEnabled(False)
        menu.addMenu(color_menu)
        for attribute, text in overlays.COLOR_BY:
            action = color_menu.addAction(text, lambda attribute=attribute: self.show_overlay(overlays.COLOR,
                                                                                               attribute))
            action.setCheckable(True)
            action.setChecked(shown == (overlays.COLOR, attribute))
        color_menu.menuAction().setEnabled(usable)
        menu.addSeparator()
        stop = menu.addAction("Show All (Esc)", self.clear_vlan)
        stop.setEnabled(self.vlan_shown is not None or shown is not None)

    def read_spanning_tree(self, vlan):
        """Spanning Tree > VLAN N: read how each switch with the VLAN has its ports in the VLAN's tree, then show it.
        Returns whether the read started."""
        network_map = self.network_map
        if network_map is None or self.worker is not None or self.stp_reading is not None:
            return False
        switches = [(key, device) for key, device in network_map.devices.items()
                    if device.source == SNMP and device.mgmt_ip and device.kind == SWITCH]
        having = [(key, device) for key, device in switches if vlan in vlan_info.vlan_names(device)]
        targets = [(key, device.mgmt_ip) for key, device in (having or switches)]
        if not targets:
            set_hint(self.status_label, "No switch on the map answered SNMP, so there's no spanning tree to read.",
                     "warning")
            return False
        self.stp_reading = {"map": network_map, "vlan": vlan, "views": {}, "failed": []}
        reader = functools.partial(self.read_vlans, stp_vlan=vlan)
        thread = VlanReadThread(self.crawl_settings([address for _, address in targets]), targets, reader, self)
        thread.checked.connect(self.on_stp_read)
        thread.finished.connect(self.on_stp_read_finished)
        self.check_threads.append(thread)
        set_hint(self.status_label, f"Reading the spanning tree of VLAN {vlan} on "
                                    f"{len(targets)} switch{'' if len(targets) == 1 else 'es'}...", "info")
        thread.start()
        return True

    def on_stp_read(self, key, address, result):
        reading = self.stp_reading
        if reading is None or reading["map"] is not self.network_map:
            return
        tables, community = result
        if tables is None:
            reading["failed"].append(key)
            return
        if community:
            self.answered[address] = community
        view = vlan_path.stp_view(tables)
        if view is not None:
            reading["views"][key] = view

    def on_stp_read_finished(self):
        thread = self.sender()
        if thread in self.check_threads:
            self.check_threads.remove(thread)
        reading, self.stp_reading = self.stp_reading, None
        if reading is None or reading["map"] is not self.network_map:
            return
        failed = reading["failed"]
        read = len(reading["views"])
        text = f"Read the spanning tree of VLAN {reading['vlan']} on {read} switch{'' if read == 1 else 'es'}"
        if failed:
            labels = [self.network_map.devices[key].label for key in failed if key in self.network_map.devices]
            text += f"; {len(failed)} didn't answer ({', '.join(labels[:5])}{'...' if len(labels) > 5 else ''})"
        set_hint(self.status_label, text + ".", "warning" if failed else "success")
        self.show_overlay(overlays.STP, (reading["vlan"], reading["views"], failed))

    def choose_subnet_overlay(self):
        """Highlight Subnet > Other: a subnet (or an address) typed."""
        if self.network_map is None:
            return
        text, ok = QInputDialog.getText(self, "Highlight Subnet", "Subnet (such as 10.1.2.0/24) or address:")
        if not ok or not text.strip():
            return
        try:
            network = overlays.parse_network(text)
        except ValueError:
            QMessageBox.warning(self, "Highlight Subnet", f"'{text.strip()}' isn't a subnet or an IP address.")
            return
        self.show_overlay(overlays.SUBNET, str(network))

    def device_overlay_menu(self, menu, actions, device):
        """Overlay > What If It Fails?, and the device's VRFs and subnets to highlight."""
        if self.network_map is None or device.key not in self.network_map.devices or self.worker is not None:
            return
        actions[menu.addAction("What If It Fails?")] = lambda: self.show_overlay(overlays.IMPACT, device.key)
        names = sorted({name for name in device.port_vrfs.values() if name} | set(device.vrf_routes),
                       key=str.lower)
        for name in names[:OVERLAY_ITEMS]:
            actions[menu.addAction(f"Highlight VRF {name}")] = \
                lambda name=name: self.show_overlay(overlays.VRF, name)
        subnets = []
        for address, prefix, _ in device.interfaces_l3:
            try:
                network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
            except ValueError:
                continue
            if network.prefixlen < network.max_prefixlen and str(network) not in subnets:
                subnets.append(str(network))
        if subnets:
            submenu = menu.addMenu("Highlight Subnet")
            for text in subnets[:OVERLAY_ITEMS]:
                actions[submenu.addAction(text)] = lambda text=text: self.show_overlay(overlays.SUBNET, text)

    def on_escape(self):
        view = self.current_view()
        if view.picking:
            view.stop_picking()
        elif view.drawing is not None:
            view.cancel_drawing()
        else:
            self.clear_vlan()

    # ----------------------------------------------------------------- The IPAM network, and the other pages

    def ipam_key(self):
        """The IPAM network the open map is of, else the one being worked on ("source:id"), or ""."""
        if self.network_map is not None and self.network_map.ipam_network:
            return self.network_map.ipam_network
        integration = hub(self.window)
        return integration.network if integration is not None else ""

    def choose_ipam_network(self):
        integration = hub(self.window)
        if integration is None or self.network_map is None:
            return
        self.window.ipam_tab.open_store()
        dialog = MapNetworkDialog(self, integration, self.network_map, self.map_name())
        if dialog.exec_():
            self.set_ipam_network(dialog.result_item or "")

    def set_ipam_network(self, key):
        """Say which IPAM network the open map is of (saved with it, and shared with a tribe map)."""
        if self.network_map is None or key == self.network_map.ipam_network:
            return
        self.network_map.ipam_network = key
        log.info("The map %s is now of IPAM network %s", self.map_name(), key or "(none)")
        try:
            self.map_path = self.write_map(self.network_map, self.map_path)
        except OSError as error:
            QMessageBox.warning(self, "Save Network Map", f"Couldn't save the map:\n\n{error}")
        self.ipam_network_changed.emit()
        self.update_network_bar()
        integration = hub(self.window)
        name = integration.network_name(key) if integration is not None else ""
        set_hint(self.status_label, f"The map is of the IPAM network {name}." if key else
                 "The map isn't of any IPAM network now: the pages use it with whichever they show.", "success")

    def maps_of_network(self, key):
        """[(name, ("tribe", map id) or ("file", path))] of the maps known here that are of an IPAM network: the
        tribe's, and the recent map files."""
        found = []
        maps = self.tribe.maps
        if maps is not None:
            for info in maps.maps():
                meta = maps.items(info["id"]).get((shared.META, shared.IPAM)) or {}
                if meta.get("network") == key:
                    found.append((f"{info['name']} (tribe)", ("tribe", info["id"])))
        for path in store.recent():
            try:
                changed = path.stat().st_mtime
                cached = self.map_networks.get(str(path))
                if cached is None or cached[0] != changed:
                    cached = (changed, json.loads(path.read_text(encoding="utf-8")).get("ipam_network", ""))
                    self.map_networks[str(path)] = cached
            except (OSError, ValueError, AttributeError):
                continue
            if cached[1] == key:
                found.append((path.stem, ("file", path)))
        return found

    def update_network_bar(self, *_):
        """Say when the map isn't of any IPAM network, or isn't of the one the other pages are on (and offer that
        network's map, or going back to the map's network)."""
        integration = hub(self.window)
        network_map = self.network_map
        name = integration.network_name(network_map.ipam_network) if integration is not None and network_map \
            is not None and network_map.ipam_network else ""
        self.ipam_network_button.setText(f"IPAM Network: {name}..." if name else "IPAM Network...")
        if integration is None or network_map is None or self.worker is not None:
            self.network_bar.hide()
            return
        mine, theirs = network_map.ipam_network, integration.network
        self.network_open_button.hide()
        self.network_back_button.hide()
        if not mine:
            self.network_bar_label.setText(f"{self.map_name()} isn't tied to an IPAM network, so the VLANs and "
                                           "Subnet Placement pages use it with whichever network they're on. Say "
                                           "which it's of:")
            self.network_set_button.show()
        elif theirs and theirs != mine:
            name, other = integration.network_name(mine), integration.network_name(theirs)
            others = self.maps_of_network(theirs)
            self.network_maps = others
            if others:
                text = f"This map is of {name}; the other pages are on {other}, which has its own map."
                self.network_open_button.setText(f"Open {others[0][0]}" if len(others) == 1 else
                                                 f"Open a Map of {other}")
                self.network_open_button.show()
            else:
                text = (f"This map is of {name}; the other pages are on {other}, which has no map yet (map it "
                        "with Start, then IPAM Network... to say it's of that network).")
            self.network_back_button.setText(f"Back to {name}")
            self.network_back_button.show()
            self.network_set_button.hide()
            self.network_bar_label.setText(text)
        else:
            self.network_bar.hide()
            return
        self.network_bar.show()

    def open_network_map(self):
        """Open the map of the network the other pages are on (choosing one if there are several)."""
        choices = getattr(self, "network_maps", [])
        if not choices:
            return
        chosen = choices[0][1]
        if len(choices) > 1:
            menu = QMenu(self)
            for name, where in choices:
                menu.addAction(name).setData(where)
            action = menu.exec_(self.network_open_button.mapToGlobal(self.network_open_button.rect().bottomLeft()))
            if action is None:
                return
            chosen = action.data()
        kind, where = chosen
        if kind == "tribe":
            self.open_tribe_map(where)
        else:
            self.open_path(Path(where))

    def back_to_map_network(self):
        integration = hub(self.window)
        if integration is not None and self.network_map is not None and self.network_map.ipam_network:
            integration.choose_network(self.network_map.ipam_network, self)
        self.update_network_bar()

    # ----------------------------------------------------------------- IPAM on the map

    def ipam_target(self):
        """(source, IPAM store, network id) of the IPAM network the map is compared with, or None."""
        integration, key = hub(self.window), self.ipam_key()
        if integration is None or not key:
            return None
        source, network_id = split_key(key)
        store = integration.stores(source)[0]
        if store is None:
            return None
        try:
            store.network(network_id)
        except IpamError:
            return None
        return source, store, network_id

    def map_ipam_findings(self):
        """{address: map_compare.MapAddress} judged against the map's IPAM network, or {}."""
        target = self.ipam_target()
        if target is None or self.network_map is None:
            return {}
        _, store, network_id = target
        return {item.ip: item for item in compare_map(self.network_map, store, network_id)}

    def fill_ipam_column(self):
        """The Hosts table's IPAM column: whether the map's IPAM network has each host's address."""
        table, network_map = self.hosts_table, self.network_map
        column = table.columnCount() - 1
        if network_map is None:
            return
        found = self.map_ipam_findings()
        table.setSortingEnabled(False)
        for row in range(table.rowCount()):
            first = table.item(row, 0)
            index = first.data_object if first is not None else None
            if index is None or index >= len(network_map.hosts):
                continue
            item = found.get(network_map.hosts[index].ip)
            finding = item.finding if item is not None else None
            text = finding.text if finding is not None else ""
            cell = SortableTableItem(text)
            cell.setToolTip(text)
            if finding is not None and finding.state in (NOT_RECORDED, MAC_DIFFERS):
                cell.setForeground(QColor(COLORS["warning"]))
            table.setItem(row, column, cell)
        table.setSortingEnabled(True)

    def annotate_l3(self):
        """The logical view's subnets: their IPAM name and role, outlined by what Subnet Placement finds."""
        integration = hub(self.window)
        facts = integration.facts(self.ipam_key()) if integration is not None and self.network_map is not None \
            else None
        for key, node in getattr(self, "l3_nodes", {}).items():
            if node.kind != l3.SUBNET:
                continue
            row = facts.row(node.label) if facts is not None else None
            node.detail, node.tone = "", ""
            if row is not None and row.subnet is not None:
                node.detail = " · ".join(part for part in (row.subnet.name, row.role.name) if part)
                node.tone = {"problem": "error", "warning": "warning"}.get(row.severity, "")
            elif row is not None and row.pool is not None:
                node.detail = f"in {row.pool.name or row.pool.cidr}"
            elif facts is not None:
                node.detail, node.tone = "not in IPAM", "muted"
            item = self.l3_view.items_by_key.get(key)
            if item is not None:
                item.setToolTip("\n".join(part for part in (node.label, node.detail) if part))
                item.update()

    def on_facts_changed(self, *_):
        """What IPAM, the VLANs and Subnet Placement know changed (or the network the map's used with)."""
        if self.network_map is None:
            return
        self.annotate_l3()
        self.fill_ipam_column()

    def showEvent(self, event):
        super().showEvent(event)
        if self.network_map is not None:
            self.fill_ipam_column()  # Addresses may have been recorded on the IP Addresses page meanwhile

    def record_map_in_ipam(self):
        """Record in IPAM... on the bar or Map menu: every address on the map."""
        self.record_in_ipam()

    def record_in_ipam(self, device=None, addresses=None):
        """Review the map's addresses its IPAM network doesn't have (or has with another MAC), and record the ones
        ticked. device: only that device's own addresses; addresses: only these (hosts chosen in the table)."""
        integration = hub(self.window)
        if integration is None or self.network_map is None:
            return
        self.window.ipam_tab.open_store()
        if not self.network_map.ipam_network:  # Records go to a network: the one the map is of
            self.choose_ipam_network()
            if not self.network_map.ipam_network:
                return
        target = self.ipam_target()
        if target is None:
            QMessageBox.warning(self, "Record in IPAM", "The map's IPAM network isn't on this computer (connect to "
                                "the tribe, or say which network the map is of with IPAM Network...).")
            return
        source, store, network_id = target
        if not self.window.ipam_tab.can_change_addresses(source):
            QMessageBox.warning(self, "Record in IPAM", "Addresses in that network can't be changed here now.")
            return
        items = list(self.map_ipam_findings().values())
        if device is not None:
            items = [item for item in items if item.kind == DEVICE_ADDRESS and item.device == device]
        if addresses is not None:
            items = [item for item in items if item.ip in addresses]
        name = integration.network_name(self.network_map.ipam_network)
        title = "Record in IPAM" if device is None else \
            f"Record {self.network_map.devices[device].label}'s Addresses in IPAM"
        team = self.window.ipam_tab.team
        dialog = RecordDialog(self, store, network_id, name, items, title,
                              offline=source == "team" and team is not None and not team.online)
        if addresses is not None:
            dialog.show_combo.setCurrentIndex(dialog.show_combo.count() - 1)  # Those chosen, whatever IPAM has
        if dialog.exec_() and (dialog.recorded or dialog.updated):
            self.window.ipam_tab.refresh_after_external_change()
            self.fill_ipam_column()
            set_hint(self.status_label, f"Recorded {count_text(dialog.recorded, 'address')} in {name}"
                     + (f" and updated {count_text(dialog.updated, 'MAC address')}" if dialog.updated else "")
                     + (" (sent to the IPAM server now, or when it's back)." if source == "team" else "."),
                     "success")

    def log_ipam_news(self, result):
        """Watching found new hosts or subnets: note in the Watch log the ones the map's IPAM network lacks."""
        integration = hub(self.window)
        if integration is None or self.network_map is None or not (result.hosts or result.subnets):
            return
        found = self.map_ipam_findings()
        new_hosts = [host for host in self.network_map.hosts if host.mac in set(result.hosts) and host.ip]
        missing = [host for host in new_hosts if host.ip in found and found[host.ip].finding is not None
                   and found[host.ip].finding.state == NOT_RECORDED]
        name = integration.network_name(self.ipam_key())
        if missing:
            listed = ", ".join(f"{host.ip}" + (f" ({host.name})" if host.name else "") for host in missing[:8])
            self.watcher.log(f"Not in IPAM ({name}): {listed}" + (f" and {len(missing) - 8} more" if len(missing) > 8
                                                                   else "") + " (Record in IPAM to add them)")
        integration.forget()  # The map just changed
        facts = integration.facts(self.ipam_key())
        for _, cidr in result.subnets:
            row = facts.row(cidr) if facts is not None else None
            if row is not None and row.found is not None and row.subnet is None and row.pool is None:
                self.watcher.log(f"Subnet {cidr} isn't in IPAM ({name})")

    def show_subnet(self, cidr):
        """Go to a subnet: its node on the logical view, else the devices with addresses in it."""
        self.window.navigator.setCurrentWidget(self)
        if self.network_map is None or not cidr:
            return
        try:
            key = l3.subnet_key(ipaddress.ip_network(cidr))
        except ValueError:
            return
        if key in self.l3_view.items_by_key:
            self.show_in(self.l3_view, [key])
            return
        devices = sorted({place.device for (_, found), group in subnet_places(self.network_map).items()
                          if found == cidr for place in group})
        if devices:
            self.show_in(self.view, devices)
        else:
            set_hint(self.status_label, f"No device on the map has an address in {cidr}.", "info")

    def show_device(self, key):
        self.window.navigator.setCurrentWidget(self)
        if self.network_map is not None and key in self.network_map.devices:
            self.show_in(self.view, [key])

    def add_subnet_links(self, menu, actions, cidr):
        """Show the subnet in IP Addresses, its VLANs on the VLANs page, and in Subnet Placement."""
        integration, key = hub(self.window), self.ipam_key()
        if integration is None or not key:
            return
        source, network_id = split_key(key)
        facts = integration.facts(key)
        row = facts.row(cidr) if facts is not None else None
        if row is not None and row.subnet is not None:
            actions[menu.addAction("Show in IP Addresses")] = lambda: integration.open_link(
                page_link(IPAM, src=source, net=network_id, cidr=cidr))
        for domain, vlan in (row.planned if row is not None else []):
            actions[menu.addAction(f"Show VLAN {vlan.vlan} on the VLANs Page")] = \
                lambda domain=domain, vlan=vlan: integration.open_link(page_link(VLAN, src=source, domain=domain.id,
                                                                            vlan=vlan.vlan))
        actions[menu.addAction("Show in Subnet Placement")] = lambda: integration.open_link(
            page_link(PLACEMENT, src=source, net=network_id, cidr=cidr, vrf=row.vrf if row is not None else ""))

    def add_address_link(self, menu, actions, address):
        """Show an address in IP Addresses (of the map's network)."""
        integration, key = hub(self.window), self.ipam_key()
        if integration is None or not key or not address:
            return
        source, network_id = split_key(key)
        actions[menu.addAction(f"Show {address} in IP Addresses")] = lambda: integration.open_link(
            page_link(IPAM, src=source, net=network_id, ip=address))

    def add_vlan_link(self, menu, actions, number, vtp_domain=""):
        integration, key = hub(self.window), self.ipam_key()
        if integration is None:
            return
        source, network_id = split_key(key)
        actions[menu.addAction(f"Show VLAN {number} on the VLANs Page")] = lambda: integration.open_link(
            page_link(VLAN, src=source, net=network_id, vlan=number, vtp=vtp_domain))

    def device_ipam_menu(self, menu, actions, device):
        """IP Addresses > each of the device's addresses; Subnet Placement for the device's subnets."""
        integration, key = hub(self.window), self.ipam_key()
        if integration is None or not key:
            return
        source, network_id = split_key(key)
        addresses = list(dict.fromkeys([(device.mgmt_ip, "management")] * bool(device.mgmt_ip) +
                                       [(address, port) for address, _, port in device.interfaces_l3]))
        if addresses:
            submenu = menu.addMenu("Show in IP Addresses")
            for address, port in addresses[:30]:
                actions[submenu.addAction(f"{address}  ({port})")] = \
                    lambda address=address: integration.open_link(page_link(IPAM, src=source, net=network_id,
                                                                            ip=address))
        if device.interfaces_l3:
            actions[menu.addAction("Show Its Subnets in Subnet Placement")] = lambda: integration.open_link(
                page_link(PLACEMENT, src=source, net=network_id, find=device.label))

    def show_vlans_page(self, number, vtp_domain):
        """The map's VLANs tab asked for a VLAN on the VLANs page."""
        integration, key = hub(self.window), self.ipam_key()
        if integration is not None:
            source, network_id = split_key(key)
            integration.open_link(page_link(VLAN, src=source, net=network_id, vlan=number, vtp=vtp_domain))

    def show_vlan_finding(self, key, port):
        """A VLAN check double-clicked: show the device on the map."""
        self.tabs.setCurrentWidget(self.view)
        self.view.show_device(key)

    def add_vlans_to_database(self):
        """Bring the map's VLANs into Manage > VLANs (reviewed there first)."""
        page = getattr(self.window, "vlan_tab", None)
        if page is not None and self.network_map is not None:
            page.import_from_map(self.network_map, self.map_name())

    def device_vlan_menu(self, menu, actions, device):
        """Highlight VLAN > each of the device's VLANs (a switch's, or a router's subinterfaces')."""
        names = vlan_info.vlan_names(device)
        numbers = sorted(set(names) | {vlan for vlan, _ in vlan_info.gateways(device)})
        if not numbers or self.network_map is None or device.key not in self.network_map.devices:
            return
        submenu = menu.addMenu("Highlight VLAN")
        domain = device.vtp_domain if device.vlans else None
        for vlan in numbers[:VLANS_IN_MENU]:
            action = submenu.addAction(f"{vlan} {names.get(vlan, '')}".strip())
            actions[action] = lambda vlan=vlan: self.highlight_vlan(vlan, domain)
        if len(numbers) > VLANS_IN_MENU:
            submenu.addAction(f"...and {len(numbers) - VLANS_IN_MENU} more (see the VLANs tab)").setEnabled(False)

    def carry_vlan_menu(self, menu, actions, key, keys):
        """Carry a VLAN Here... on a switch, and Carry a VLAN Between These... with two network devices selected (B
        a switch: the one right-clicked, if it is)."""
        network_map = self.network_map
        if self.worker is not None or network_map is None or key not in network_map.devices:
            return
        devices = network_map.devices
        if devices[key].kind == SWITCH:
            actions[menu.addAction("Carry a VLAN Here...")] = lambda: self.carry_vlan(b=key)
        chosen = [item for item in keys if item in devices and devices[item].kind in (SWITCH, ROUTER, FIREWALL)]
        if len(chosen) == 2:
            b = key if devices[key].kind == SWITCH else next((item for item in chosen if devices[item].kind == SWITCH),
                                                             None)
            if b is not None:
                a = next(item for item in chosen if item != b)
                actions[menu.addAction("Carry a VLAN Between These...")] = lambda: self.carry_vlan(a=a, b=b)

    def carry_vlan(self, vlan=None, a=None, b=None, port=None, route=None):
        """Carry VLAN: get a VLAN to a switch (b) over the map's links, from a or from wherever it already is."""
        if self.network_map is None:
            return
        if self.carry_dialog is None:
            self.carry_dialog = VlanPathDialog(self)
        self.carry_dialog.set_target(vlan, a, b, port, route)

    def carry_vlan_from_panel(self, vlan, _domain):
        self.carry_vlan(vlan=vlan)

    def show_on_map(self, kind, row):
        item = (self.devices_table if kind == "device" else self.hosts_table).item(row, 0)
        if item is None or self.network_map is None:
            return
        self.tabs.setCurrentWidget(self.view)
        if kind == "device":
            self.view.show_device(item.data_object)
        else:
            self.view.show_host(self.network_map.hosts[item.data_object])

    # ----------------------------------------------------------------- Find (Ctrl+F), local to each sub-tab

    def focus_find(self):
        """Ctrl+F: the find box, for whichever sub-tab is showing."""
        self.find_input.setFocus()
        self.find_input.selectAll()

    def on_subtab_changed(self, _index):
        self.find_texts[self.find_owner] = self.find_input.text()
        self.find_owner = self.tabs.currentWidget()
        self.find_input.blockSignals(True)  # The table it now belongs to is already filtered by its own text
        self.find_input.setText(self.find_texts.get(self.find_owner, ""))
        self.find_input.blockSignals(False)
        self.set_find_placeholder()
        self.update_buttons()

    def set_find_placeholder(self):
        here = self.tabs.currentWidget()
        if here in self.table_names:
            name = self.table_names[here]
            text = f"Filter the {name if name[:2].isupper() else name.lower()}: words in any column (Ctrl+F)"
        elif here is self.crawl_progress.tab:
            text = "Find in the crawl log (Enter for the next) (Ctrl+F)"
        elif here is self.l3_view:
            text = "Find a router, subnet or hop: name or address (Enter for the next) (Ctrl+F)"
        else:
            text = "Find a device or host: name, IP, MAC or vendor (Enter for the next) (Ctrl+F)"
        self.find_input.setPlaceholderText(text)

    def on_find_text(self, text):
        here = self.tabs.currentWidget()
        if here in self.table_filters:
            self.table_filters[here].set_text(text)  # Tables filter as you type

    def on_find_return(self):
        """Enter: the next match. Shift+Enter: the one before. Ctrl+Enter: every matching device at once."""
        modifiers = QApplication.keyboardModifiers()
        self.find(backward=bool(modifiers & Qt.ShiftModifier), select_all=bool(modifiers & Qt.ControlModifier))

    def find(self, backward=False, select_all=False):
        text = self.find_input.text().strip()
        here = self.tabs.currentWidget()
        if not text or here in self.table_filters:
            return
        if here is self.crawl_progress.tab:
            if not self.crawl_progress.find(text):
                set_hint(self.status_label, f"'{text}' isn't in the crawl log.", "warning")
            return
        view = self.current_view()
        if select_all:
            count = view.find_all(text)
            if count:
                set_hint(self.status_label, f"Selected {count} device{'' if count == 1 else 's'} matching '{text}'.",
                         "info")
            else:
                set_hint(self.status_label, f"No device on the map matches '{text}'.", "warning")
            return
        found = view.find(text, backward)
        if found is None:
            set_hint(self.status_label, f"Nothing on the map matches '{text}'.", "warning")
            return
        position, count, label = found
        if count == 1:
            set_hint(self.status_label, f"Found {label}, the only match for '{text}'.", "info")
        else:
            set_hint(self.status_label, f"{position} of {count} matching '{text}': {label}. Enter for the next, "
                                        f"Shift+Enter the one before, Ctrl+Enter selects every matching device.",
                     "info")

    def show_details(self, selection):
        network_map = self.displayed_map()
        if network_map is None or selection is None:
            if network_map is None:
                text = ("<p>Start from a core switch or your gateway. Each device's CDP and LLDP neighbors are read "
                        "over SNMP, then theirs, until the whole network (within the scope) is mapped.</p>"
                        "<p>Double-click a switch to show its hosts by port, with each one's VLAN (or tick Show "
                        "Hosts for every switch). Right-click a device for SSH, ping, SNMP and more.</p>"
                        "<p>Drag the background to move around. Hold Shift and drag to draw a box round several "
                        "devices, then drag any of them to move them together.</p>"
                        "<p>Right-click devices > Group to put them in a site, building or room, drawn as a box you "
                        "can collapse. Re-arrange's arrow has other layouts.</p>"
                        "<p>Right-click the background to add a device the crawl can't find (an unmanaged switch, "
                        "say), and a device > Edit > Draw Link from Here to link it.</p>")
            else:
                text = "<p>Select a device to see its details.</p>"
            self.details.setHtml(text)
            return
        if selection[0] == "many":
            self.details.setHtml(f"<p>{selection[1]} selected. Drag any of them to move them all.</p>"
                                 "<p>Shift and drag the background to select several, Ctrl+click a device or a "
                                 "group's title to add or remove it, and Ctrl+A to select every device.</p>"
                                 "<p>Right-click one of them to put them in a site, building or room (Group), arrange "
                                 "just them, or line them up (Align). Sites, buildings and rooms selected are "
                                 "arranged and lined up as whole boxes.</p>")
        elif selection[0] == "group":
            self.details.setHtml(group_html(network_map, selection[1], self.monitor.status))
        elif selection[0] == "device":
            self.details.setHtml(device_html(network_map, selection[1], self.monitor.status(selection[1])))
        elif selection[0] == "node":
            node = self.l3_nodes.get(selection[1])
            if node is not None:
                self.details.setHtml(subnet_html(network_map, node.label) if node.kind == l3.SUBNET
                                     else node_html(network_map, node))
        else:
            self.details.setHtml(port_html(network_map, selection[1], selection[2]))

    def session_hints(self, network_map, device):
        """For a device's Open SSH Session: its other addresses and names (a saved session may use any of them), its
        name for a new session, and its site, building and room as the folder to suggest when that's saved."""
        aliases = [device.name, display_name(device.name), *device.addresses,
                   *(item[0] for item in device.interfaces_l3)]
        folder = "/".join(group.name.replace("/", "-") for group in network_map.group_path(device.key))
        return {"aliases": [alias for alias in aliases if alias], "name": display_name(device.name), "folder": folder}

    def snmp_access(self, address):
        """(community or V3User, version) for SNMP Details on a device: what it answered to on a crawl or check,
        or else the first the map would try for it."""
        community = self.answered.get(address)
        if community is None:
            try:
                candidates = communities_for(address, self.credentials(), parse_overrides(self.overrides))
            except ValueError:
                candidates = self.credentials()
            community = candidates[0] if candidates else None
        return community, self.version

    def host_session_hints(self, host):
        """session_hints for a host learned on a switch port: its announced name, and the folder of its switch."""
        folder = ""
        if self.network_map is not None and host.device:
            folder = "/".join(group.name.replace("/", "-") for group in self.network_map.group_path(host.device))
        return {"aliases": [host.name] if host.name else [], "name": host.name, "folder": folder}

    def show_device_menu(self, key, position):
        """Right-click on a device: its host actions, then the map's own, grouped into submenus of like items so the
        menu fits on the screen."""
        shown = self.displayed_map()
        device = shown.devices.get(key) if shown else None
        if device is None:
            self.show_node_menu(key, position)
            return
        menu = QMenu(self)
        stop = self.add_stop_highlight(menu)
        # Show In has Show on Map's views, and IPAM its addresses (when the map is of an IPAM network); Copy Address
        # is at the bottom
        leave_out = ["Show on Map", "Copy IP Address"]
        if hub(self.window) is not None and self.ipam_key():
            leave_out.append("Show in IPAM")
        actions = self.host_actions.add_to(menu, device.mgmt_ip, **self.session_hints(shown, device),
                                           snmp=self.snmp_access(device.mgmt_ip),
                                           leave_out=leave_out) if device.mgmt_ip else {}
        if stop is not None:
            actions[stop] = self.clear_vlan
        show_in = add_submenu(menu, "Show In")
        self.add_show_in(show_in, actions, key)
        menu.addSeparator()
        if device.mgmt_ip:
            actions[menu.addAction("Crawl from Here")] = lambda: self.crawl_from(device.mgmt_ip)
        if self.worker is None:
            actions[menu.addAction("Put at the Top")] = lambda: self.put_at_top(key)
        if self.current_view() is self.view and self.worker is None:
            actions[menu.addAction("Add Host...")] = lambda: self.add_host(key)
        item = self.view.items_by_key.get(key)
        if item is not None and item.host_count and self.tabs.currentWidget() is self.view:
            label = "Hide Hosts" if item.expanded else "Show Hosts"
            actions[menu.addAction(label)] = lambda: self.view.toggle_hosts(item)
        here = self.tabs.currentWidget()
        selected = here.selected_keys() if here in (self.view, self.l3_view) else []
        keys = selected if key in selected else [key]
        news = self.news_of_devices(keys)
        if news and self.worker is None:
            actions[menu.addAction("Mark as Seen")] = lambda: self.mark_seen(news)
        menu.addSeparator()
        editing = self.worker is None and self.network_map is not None and key in self.network_map.devices
        if editing:
            self.add_group_menu(menu, actions, [item for item in keys if item in self.network_map.devices])
        layout = add_submenu(menu, "Layout") if here in (self.view, self.l3_view) else None
        if layout is not None:
            self.add_selection_actions(layout, here, keys)
        edit = add_submenu(menu, "Edit") if editing else None
        if edit is not None:
            self.add_by_hand_actions(edit, actions, key, keys)
        overlay = add_submenu(menu, "Overlay")
        self.device_overlay_menu(overlay, actions, device)
        vlans = add_submenu(menu, "VLANs")
        self.device_vlan_menu(vlans, actions, device)
        self.carry_vlan_menu(vlans, actions, key, keys)
        ipam = add_submenu(menu, "IPAM")
        self.device_ipam_menu(ipam, actions, device)
        if editing and hub(self.window) is not None:
            actions[ipam.addAction("Record Its Addresses in IPAM...")] = lambda: self.record_in_ipam(device=key)
        drop_empty_submenus(menu, show_in, layout, edit, overlay, vlans, ipam)
        menu.addSeparator()
        actions[menu.addAction("Copy Name")] = lambda: QApplication.clipboard().setText(device.label)
        if device.mgmt_ip:
            actions[menu.addAction("Copy Address")] = lambda: QApplication.clipboard().setText(device.mgmt_ip)
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def add_show_in(self, menu, actions, key):
        """Physical (L2) / Logical (L3) / Devices / Links (for the device menu's Show In), leaving out the one showing
        and any the device isn't in."""
        here = self.tabs.currentWidget()
        crawling = self.worker is not None  # The tables and logical view are the map from before, until it's done
        choices = [(self.view, "Physical (L2)", key in self.view.items_by_key),
                   (self.l3_view, "Logical (L3)", not crawling and key in self.l3_view.items_by_key),
                   (self.devices_table, "Devices", not crawling and bool(self.table_rows(self.devices_table, key))),
                   (self.links_table, "Links", not crawling and bool(self.table_rows(self.links_table, key)))]
        for widget, label, possible in choices:
            if widget is not here and possible:
                actions[menu.addAction(label)] = lambda widget=widget: self.show_in(widget, [key])

    def table_rows(self, table, key):
        """Rows of the Devices or Links table for a device (a link's row names both its ends)."""
        rows = []
        for row in range(table.rowCount()):
            item = table.item(row, 0)
            data = item.data_object if item is not None else None
            if data == key or (isinstance(data, tuple) and key in data):
                rows.append(row)
        return rows

    def show_in(self, widget, keys):
        """Go to the tab and select these devices there."""
        self.tabs.setCurrentWidget(widget)
        if widget in (self.view, self.l3_view):
            widget.show_devices(keys)
            return
        rows = sorted({row for key in keys for row in self.table_rows(widget, key)})
        widget.clearSelection()
        if not rows:
            return
        if any(widget.isRowHidden(row) for row in rows):
            self.table_filters[widget].clear()  # A filter was hiding it
        if any(widget.isRowHidden(row) for row in rows):
            self.find_input.setText("")  # Its find box's words, then (the box is this table's now)
        mode = widget.selectionMode()
        widget.setSelectionMode(QAbstractItemView.MultiSelection)  # So selectRow adds rather than replaces
        for row in rows:
            widget.selectRow(row)
        widget.setSelectionMode(mode)
        widget.scrollToItem(widget.item(rows[0], 0))

    def show_devices_table_menu(self, position):
        item = self.devices_table.itemAt(position)
        if item is None:
            if self.worker is None:
                menu = QMenu(self)
                menu.addAction("Add Device...", lambda: self.add_device())
                menu.exec_(self.devices_table.viewport().mapToGlobal(position))
            return
        self.devices_table.selectRow(item.row())
        key = self.devices_table.item(item.row(), 0).data_object
        self.show_device_menu(key, self.devices_table.viewport().mapToGlobal(position))

    def show_links_table_menu(self, position):
        item = self.links_table.itemAt(position)
        if self.network_map is None:
            return
        if item is None:
            if self.worker is None and len(self.network_map.devices) > 1:
                menu = QMenu(self)
                menu.addAction("Add Link...", lambda: self.add_link())
                menu.exec_(self.links_table.viewport().mapToGlobal(position))
            return
        if not self.links_table.item(item.row(), 0).isSelected():
            self.links_table.clearSelection()
            self.links_table.selectRow(item.row())
        rows = sorted({index.row() for index in self.links_table.selectionModel().selectedRows()
                       if not self.links_table.isRowHidden(index.row())})
        keys = list(dict.fromkeys(key for row in rows for key in self.links_table.item(row, 0).data_object))
        menu = QMenu(self)
        actions = {}
        ends = "Both Ends" if len(rows) == 1 else "Their Ends"
        actions[menu.addAction(f"Show {ends} in Physical (L2)")] = lambda: self.show_in(self.view, keys)
        if any(key in self.l3_view.items_by_key for key in keys):
            actions[menu.addAction(f"Show {ends} in Logical (L3)")] = lambda: self.show_in(
                self.l3_view, [key for key in keys if key in self.l3_view.items_by_key])
        actions[menu.addAction(f"Show {ends} in Devices")] = lambda: self.show_in(self.devices_table, keys)
        menu.addSeparator()
        actions[menu.addAction("Copy")] = lambda: QApplication.clipboard().setText("\n".join(
            "\t".join(self.links_table.item(row, column).text() for column in range(self.links_table.columnCount()))
            for row in rows))
        if self.worker is None:
            menu.addSeparator()
            self.add_link_actions(menu, actions, [self.links_table.item(row, 0).data_object.link for row in rows])
        chosen = menu.exec_(self.links_table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def show_node_menu(self, key, position):
        """Right-click on the logical view's subnets and traceroute hops."""
        node = self.l3_nodes.get(key)
        if node is None:
            return
        menu = QMenu(self)
        actions = {}
        if node.kind == l3.SUBNET:
            actions[menu.addAction("Sweep This Subnet")] = lambda: self.sweep_subnet(node.label)
            actions[menu.addAction("Copy Subnet")] = lambda: QApplication.clipboard().setText(node.label)
            menu.addSeparator()
            self.add_subnet_links(menu, actions, node.label)
        elif node.kind == l3.HOP and key != l3.SELF:
            actions = self.host_actions.add_to(menu, node.label, snmp=self.snmp_access(node.label),
                                               leave_out=("Copy IP Address",))  # Copy Address, below
            menu.addSeparator()
            actions[menu.addAction("Crawl from Here")] = lambda: self.crawl_from(node.label)
            actions[menu.addAction("Copy Address")] = lambda: QApplication.clipboard().setText(node.label)
        if not actions:
            return
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    # ----------------------------------------------------------------- Adding and removing hosts

    def selected_table_hosts(self):
        if self.network_map is None:
            return []
        rows = sorted({index.row() for index in self.hosts_table.selectionModel().selectedRows()
                       if not self.hosts_table.isRowHidden(index.row())})  # Not rows a filter hides (Ctrl+A)
        return [self.network_map.hosts[self.hosts_table.item(row, 0).data_object] for row in rows]

    def show_hosts_table_menu(self, position):
        if self.network_map is None or self.worker is not None:
            return
        item = self.hosts_table.itemAt(position)
        if item is not None and not self.hosts_table.item(item.row(), 0).isSelected():
            self.hosts_table.selectRow(item.row())
        hosts = self.selected_table_hosts() if item is not None else []
        menu = QMenu(self)
        actions = {}
        if len(hosts) == 1:
            host = hosts[0]
            if host.ip:
                actions = self.host_actions.add_to(menu, host.ip, **self.host_session_hints(host),
                                                   leave_out=("Show on Map",))  # The page's own is below
                menu.addSeparator()
            actions[menu.addAction("Show on Map")] = lambda: self.show_on_map("host", item.row())
            self.add_address_link(menu, actions, host.ip)
        addresses = [host.ip for host in hosts if host.ip]
        if addresses and hub(self.window) is not None:
            label = "Record in IPAM..." if len(addresses) == 1 else f"Record {len(addresses)} in IPAM..."
            actions[menu.addAction(label)] = lambda: self.record_in_ipam(addresses=addresses)
        if len(hosts) == 1:
            host = hosts[0]
            actions[menu.addAction("Edit Host...")] = lambda: self.edit_host(host)
        actions[menu.addAction("Add Host...")] = lambda: self.add_host(hosts[0].device if hosts else None,
                                                                        hosts[0].port if hosts else "")
        if hosts:
            label = "Delete Host" if len(hosts) == 1 else f"Delete {len(hosts)} Hosts"
            actions[menu.addAction(label)] = lambda: self.delete_hosts(hosts)
        news = [f"host:{host.mac}" for host in hosts if f"host:{host.mac}" in self.network_map.news]
        if news:
            actions[menu.addAction("Mark as Seen")] = lambda: self.mark_seen(news)
        chosen = menu.exec_(self.hosts_table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def show_port_menu(self, key, port, position):
        """Right-click on a port's box of hosts on the map."""
        if self.worker is not None:
            return
        hosts = self.network_map.hosts_by_port(key).get(port, []) if self.network_map else []
        menu = QMenu(self)
        stop = self.add_stop_highlight(menu)
        actions = {}
        if len(hosts) == 1 and hosts[0].ip:
            actions = self.host_actions.add_to(menu, hosts[0].ip, **self.host_session_hints(hosts[0]))
        if stop is not None:
            actions[stop] = self.clear_vlan
            menu.addSeparator()
        device = self.network_map.devices.get(key) if self.network_map else None
        info = vlan_info.port_info(device, port) if device is not None else {}
        domain = device.vtp_domain if device is not None and device.vlans else None
        numbers = list(dict.fromkeys(number for number in (info.get("vlan"), info.get("voice"), info.get("native"))
                                     if number))
        for number in numbers:
            actions[menu.addAction(f"Highlight VLAN {number}")] = \
                lambda number=number: self.highlight_vlan(number, domain)
        for number in numbers:
            self.add_vlan_link(menu, actions, number, domain or "")
        if device is not None and device.kind == SWITCH and key in self.network_map.devices:
            actions[menu.addAction("Carry a VLAN Here...")] = lambda: self.carry_vlan(b=key, port=port)
        if len(hosts) == 1:
            self.add_address_link(menu, actions, hosts[0].ip)
        if actions:
            menu.addSeparator()
        if len(hosts) == 1:
            actions[menu.addAction("Edit Host...")] = lambda: self.edit_host(hosts[0])
        actions[menu.addAction("Add Host on This Port...")] = lambda: self.add_host(key, port)
        if hosts:
            label = "Delete Host" if len(hosts) == 1 else f"Delete the {len(hosts)} Hosts on This Port"
            actions[menu.addAction(label)] = lambda: self.delete_hosts(hosts)
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def add_host(self, device=None, port=""):
        if self.network_map is None or not self.network_map.devices:
            return
        dialog = HostDialog(self.network_map, device=device, port=port, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            host = dialog.values()
            self.network_map.hosts.append(host)
            self.map_changed(host)
            set_hint(self.status_label, f"Added {host.name or host.ip or host.mac} on "
                     f"{self.network_map.devices[host.device].label} {host.port}. It's kept when you map again.",
                     "success")

    def edit_host(self, host):
        dialog = HostDialog(self.network_map, host=host, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            edited = dialog.values()
            self.network_map.hosts[self.network_map.hosts.index(host)] = edited
            self.map_changed(edited)

    def delete_hosts(self, hosts):
        if not hosts or self.network_map is None or self.worker is not None:
            return
        found = sum(1 for host in hosts if not host.manual)
        what = hosts[0].name or hosts[0].ip or hosts[0].mac if len(hosts) == 1 else f"these {len(hosts)} hosts"
        text = f"Delete {what} from the map?"
        if found:
            text += ("\n\nHosts the crawl found come back the next time you map, if they're still plugged in."
                     if len(hosts) > 1 else "\n\nIt comes back the next time you map, if it's still plugged in.")
        if QMessageBox.question(self, "Delete Hosts", text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        doomed = {id(host) for host in hosts}
        self.network_map.hosts = [host for host in self.network_map.hosts if id(host) not in doomed]
        self.map_changed()
        set_hint(self.status_label, f"Deleted {len(hosts)} host{'' if len(hosts) == 1 else 's'}.", "info")

    def map_changed(self, show=None, place=None, select=None):
        """Redraw after hosts, devices or links were added, edited or deleted, keeping the view where it was (and
        what was selected), and save. show: a Host whose switch to open; place: {device key: (x, y)} for ones put
        somewhere; select: a device key to select instead."""
        network_map = self.network_map
        network_map.hosts.sort(key=lambda host: (network_map.devices[host.device].label.lower(),
                                                 port_key(host.port), host.mac))
        network_map.positions = {key: position for key, position in self.view.positions().items()
                                 if key in network_map.devices}
        network_map.positions.update(place or {})
        network_map.l3_positions = self.l3_view.positions()
        self.redraw_keeping_view(show, select)
        try:
            self.map_path = self.write_map(network_map, self.map_path)
        except OSError as error:
            QMessageBox.warning(self, "Save Network Map", f"Couldn't save the map:\n\n{error}")

    def sweep_subnet(self, subnet):
        """Fill in the subnet on the Sweep page; sweeping needs a deliberate Sweep there."""
        self.window.navigator.setCurrentWidget(self.window.sweep_tab)
        self.window.sweep_tab.subnet_input.setText(subnet)

    def put_at_top(self, key):
        self.network_map.root = key
        self.tabs.setCurrentWidget(self.view)
        self.rearrange()

    # ----------------------------------------------------------------- Devices and links added by hand

    def add_by_hand_actions(self, menu, actions, key, keys):
        """The device menu's links and devices drawn by hand: draw a link from it, add a device linked to it, edit
        it (or correct one the crawl found), ask again over SNMP, and delete it (or the devices selected)."""
        network_map = self.network_map
        device = network_map.devices[key]
        menu.addSeparator()
        if self.current_view() is self.view and self.view.items_by_key.get(key) is not None \
                and self.view.items_by_key[key].isVisible():
            actions[menu.addAction("Draw Link from Here")] = lambda: self.draw_link_from(key)
        if len(network_map.devices) > 1:
            actions[menu.addAction("Add Link...")] = lambda: self.add_link(key)
        actions[menu.addAction("Add Device Linked to This...")] = lambda: self.add_device(linked_to=key)
        edit = menu.addAction("Edit Device..." if device.manual else "Correct Device...")
        actions[edit] = lambda: self.edit_device(key)
        if device.mgmt_ip and (device.manual or "mgmt_ip" in device.corrected or device.source != SNMP):
            check = menu.addAction("Checking SNMP..." if key in self.checking else "Check SNMP Again")
            check.setEnabled(key not in self.checking)
            actions[check] = lambda: self.check_devices([key], announce=True)
        if device.corrected:
            actions[menu.addAction("Forget Corrections")] = lambda: self.forget_corrections(key)
        doomed = [item for item in keys if item in network_map.devices]
        menu.addSeparator()
        label = "Delete Device..." if len(doomed) == 1 else f"Delete {len(doomed)} Devices..."
        actions[menu.addAction(label)] = lambda: self.delete_devices(doomed)

    def add_link_actions(self, menu, actions, links):
        """Edit or delete links drawn by hand, and add another between the same two devices."""
        manual = [link for link in links if link.manual]
        if len(manual) == 1:
            actions[menu.addAction("Edit Link...")] = lambda: self.edit_link(manual[0])
        if manual:
            label = "Delete Link" if len(manual) == 1 else f"Delete the {len(manual)} Links Drawn by Hand"
            actions[menu.addAction(label)] = lambda: self.delete_links(manual)
        if len({frozenset((link.a, link.b)) for link in links}) == 1:
            actions[menu.addAction("Add Another Link Between These...")] = \
                lambda: self.add_link(links[0].a, links[0].b)
        else:
            actions[menu.addAction("Add Link...")] = lambda: self.add_link()

    def show_background_menu(self, scene_position, position):
        """Right-click on the physical view's background."""
        if self.worker is not None:
            return
        menu = QMenu(self)
        actions = {}
        stop = self.add_stop_highlight(menu)
        if stop is not None:
            actions[stop] = self.clear_vlan
        place = (scene_position.x(), scene_position.y())
        actions[menu.addAction("Add Device Here...")] = lambda: self.add_device(place=place)
        if self.network_map is not None and len(self.network_map.devices) > 1:
            actions[menu.addAction("Add Link...")] = lambda: self.add_link()
        if self.network_map is not None and self.network_map.deleted:
            actions[menu.addAction(f"Deleted Devices ({len(self.network_map.deleted)})...")] = \
                self.show_deleted_devices
        if self.network_map is not None and self.network_map.devices:
            menu.addSeparator()
            actions[menu.addAction("Fit")] = self.view.fit
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def show_link_menu(self, links, position):
        """Right-click on a line on the physical view (the links it stands for)."""
        if self.network_map is None or self.worker is not None:
            return
        menu = QMenu(self)
        actions = {}
        stop = self.add_stop_highlight(menu)
        if stop is not None:
            actions[stop] = self.clear_vlan
        actions[menu.addAction("Show in Links")] = lambda: self.show_links_in_table(links)
        known = [link.key for link in links if link in self.network_map.links]
        if known:
            text = "What If It Fails?" if len(known) == 1 else f"What If All {len(known)} Links Fail?"
            actions[menu.addAction(text)] = lambda: self.show_overlay(overlays.IMPACT, known)
        menu.addSeparator()
        self.add_link_actions(menu, actions, links)
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def show_links_in_table(self, links):
        self.tabs.setCurrentWidget(self.links_table)
        self.links_table.clearSelection()
        wanted = {id(link) for link in links}
        rows = [row for row in range(self.links_table.rowCount())
                if id(self.links_table.item(row, 0).data_object.link) in wanted]
        if any(self.links_table.isRowHidden(row) for row in rows):
            self.table_filters[self.links_table].clear()
        mode = self.links_table.selectionMode()
        self.links_table.setSelectionMode(QAbstractItemView.MultiSelection)
        for row in rows:
            self.links_table.selectRow(row)
        self.links_table.setSelectionMode(mode)
        if rows:
            self.links_table.scrollToItem(self.links_table.item(rows[0], 0))

    def add_device(self, place=None, linked_to="", address="", name="", parent=None):
        """Add a device by hand (optionally linked to one on the map), and ask it over SNMP if it has an address.
        With no map open, it starts one. address, name: filled in (Add Device to Map, from another page). Returns
        the new device's key, or None."""
        if self.worker is not None:
            return None
        network_map = self.network_map or NetworkMap(started=datetime.datetime.now().isoformat(timespec="seconds"))
        dialog = DeviceDialog(network_map, linked_to=linked_to, parent=parent or self, address=address, name=name)
        if dialog.exec_() != QDialog.Accepted:
            return None
        device = put_device(network_map, *dialog.values())
        if self.network_map is None:
            self.show_map(network_map)
        self.map_changed(place={device.key: place} if place else None, select=device.key)
        message = f"Added {device.label}. It's kept when you map again."
        if device.mgmt_ip:
            message += " Checking whether it answers SNMP..."
            self.check_devices([device.key], announce=True)
        else:
            message += " Give it an IP address (Edit Device) to ping it while monitoring and check it over SNMP."
        set_hint(self.status_label, message, "success")
        return device.key

    # ----------------------------------------------------------------- Add Device to Map (from other pages)

    def map_choices(self):
        """The maps Add Device to Map offers: [(text, kind, value)], the one open here first."""
        if self.network_map is not None:
            choices = [(f"Open map: {self.map_name()}", OPEN_MAP, None)]
        else:
            choices = [("A new map (opened on the Network Map page)", OPEN_MAP, None)]
        open_file = Path(self.map_path).resolve() if self.map_path and self.tribe_map_id is None else None
        try:
            saved = store.recent()
        except OSError:
            saved = []
        choices += [(f"Saved map: {path.stem}", FILE_MAP, path) for path in saved if path.resolve() != open_file]
        maps = self.tribe.ensure() if self.tribe.available else None
        if maps is not None:
            choices += [(f"Tribe map: {item['name']}", TRIBE_MAP, item["id"]) for item in maps.maps()
                        if item["id"] != self.tribe_map_id]
        if self.network_map is not None:
            choices.append(("A new map (saved, not opened)", NEW_MAP, None))
        choices.append(("Another map file...", FILE_MAP, None))
        return choices

    def add_address(self, address, name="", parent=None):
        """Add Device to Map, from an address's right-click menu on any page: choose the map (the one open here, a
        saved one, a tribe map or a new one), then fill in the device as Add Device does. Returns the new device's
        key, or None."""
        parent = parent or self.window
        address = address.partition("%")[0]  # An IPv6 scope means nothing to the map
        dialog = MapChoiceDialog(address, self.map_choices(), parent)
        dialog.show_check.setChecked(self.show_added)
        if dialog.exec_() != QDialog.Accepted:
            return None
        kind, value = dialog.choice()
        self.show_added = show = dialog.show_check.isChecked()
        if kind == FILE_MAP and value is None:
            path, _ = QFileDialog.getOpenFileName(parent, "Add Device to Map", str(store.maps_dir()), MAP_FILTER)
            if not path:
                return None
            value = Path(path)
            if self.tribe_map_id is None and self.map_path and value.resolve() == Path(self.map_path).resolve():
                kind = OPEN_MAP
        if kind == OPEN_MAP:
            return self.add_to_open_map(address, name, show, parent)
        settings = seen = None
        try:
            if kind == FILE_MAP:
                network_map, title = store.load(value), value.stem
            elif kind == TRIBE_MAP:
                maps = self.tribe.ensure()
                info = maps.map_info(value) if maps is not None else None
                if info is None or info.get("deleted"):
                    raise ValueError("That map isn't shared with the tribe any more.")
                network_map, settings, seen = maps.snapshot(value)
                title = info.get("name", "the tribe map")
            else:
                network_map = NetworkMap(started=datetime.datetime.now().isoformat(timespec="seconds"))
                title = "a new map"
        except (OSError, ValueError) as error:
            QMessageBox.warning(parent, "Add Device to Map", f"Couldn't open the map:\n\n{error}")
            return None
        there = self.device_with_address(network_map, address)
        if there is not None:
            QMessageBox.information(parent, "Add Device to Map", f"{address} is already on {title}: it's "
                                    f"{there.label}.")
            if show:
                self.show_on_other_map(kind, value, there.key)
            return None
        dialog = DeviceDialog(network_map, parent=parent, address=address, name=name,
                              title=f"Add Device to {title}")
        if dialog.exec_() != QDialog.Accepted:
            return None
        device = put_device(network_map, *dialog.values())
        try:
            if kind == FILE_MAP:
                store.save(network_map, value)
            elif kind == TRIBE_MAP:
                self.tribe.save(value, network_map, settings, seen)
            else:
                value = store.save(network_map)
                title = value.stem
        except OSError as error:
            QMessageBox.warning(parent, "Add Device to Map", f"Couldn't save the map:\n\n{error}")
            return None
        if show:
            self.show_on_other_map(kind, value, device.key)
        else:
            self.window.show_status(f"Added {device.label} to {title}. Open that map to see it.", "success")
        return device.key

    def add_to_open_map(self, address, name, show, parent):
        """Add Device to Map, to the map open here (or a new one, with none open)."""
        if self.worker is not None:
            QMessageBox.information(parent, "Add Device to Map", "The map is being crawled. Add it once the crawl "
                                    "has finished, or choose another map.")
            return None
        there = self.device_with_address(self.network_map, address) if self.network_map is not None else None
        if there is not None:
            QMessageBox.information(parent, "Add Device to Map", f"{address} is already on {self.map_name()}: it's "
                                    f"{there.label}.")
            key = None
        else:
            key = self.add_device(address=address, name=name, parent=parent)
            if key is None:
                return None
            self.window.show_status(f"Added {self.network_map.devices[key].label} to {self.map_name()}.", "success")
        if show:
            self.window.navigator.setCurrentWidget(self)
            self.show_in(self.view, [key or there.key])
        return key

    def show_on_other_map(self, kind, value, key):
        """Open the map a device was just added to (or found on) here, with it selected."""
        self.window.navigator.setCurrentWidget(self)
        if self.worker is not None:
            set_hint(self.status_label, "The map can't be changed while the crawl runs: open it once it's finished.",
                     "info")
            return
        if kind == TRIBE_MAP:
            if not self.open_tribe_map(value):
                return
        else:
            self.open_path(Path(value))
        if self.network_map is None or key not in self.network_map.devices:
            return
        self.show_in(self.view, [key])
        device = self.network_map.devices[key]
        if device.manual and device.source == UNCHECKED and device.mgmt_ip:
            self.check_devices([key], announce=True)

    @staticmethod
    def device_with_address(network_map, address):
        address = address.partition("%")[0]
        return next((device for device in network_map.devices.values() if device.owns(address)), None)

    def edit_device(self, key):
        device = self.network_map.devices.get(key) if self.network_map else None
        if device is None or self.worker is not None:
            return
        dialog = DeviceDialog(self.network_map, device=device, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        edited, _ = dialog.values()
        self.network_map.devices[key] = edited
        self.map_changed(select=key)
        if not edited.manual and edited.corrected != device.corrected:
            set_hint(self.status_label, f"Corrected {edited.label}. It's kept when you map again; right-click it > "
                     "Forget Corrections to go back to what the crawl found.", "success")
        new_address = edited.source == UNCHECKED or (not edited.manual and edited.mgmt_ip != device.mgmt_ip)
        if edited.mgmt_ip and new_address:  # Ask it there
            set_hint(self.status_label, f"Checking whether {edited.label} answers SNMP at {edited.mgmt_ip}...", "info")
            self.check_devices([key], announce=True)

    def forget_corrections(self, key):
        device = self.network_map.devices.get(key) if self.network_map else None
        if device is None or not device.corrected or self.worker is not None:
            return
        device.forget_corrections()
        self.map_changed(select=key)
        set_hint(self.status_label, f"{device.label} is back to what the crawl found.", "info")

    def selected_table_devices(self):
        rows = {index.row() for index in self.devices_table.selectionModel().selectedRows()
                if not self.devices_table.isRowHidden(index.row())}
        return [self.devices_table.item(row, 0).data_object for row in sorted(rows)]

    def delete_devices(self, keys):
        """Take devices off the map. Ones the crawl found stay off it when mapping again (and aren't crawled
        through), until brought back from the background menu's Deleted Devices."""
        network_map = self.network_map
        keys = [key for key in keys if network_map is not None and key in network_map.devices]
        if not keys or self.worker is not None:
            return
        what = network_map.devices[keys[0]].label if len(keys) == 1 else f"these {len(keys)} devices"
        links = sum(1 for link in network_map.links if link.a in keys or link.b in keys)
        hosts = sum(1 for host in network_map.hosts if host.device in keys)
        text = f"Delete {what} from the map?"
        if links or hosts:
            parts = [count_text(count, noun) for count, noun in ((links, "link"), (hosts, "host")) if count]
            text += f"\n\n{' and '.join(parts).capitalize()} on {'it' if len(keys) == 1 else 'them'} go too."
        found = sum(1 for key in keys if not network_map.devices[key].manual)
        if found:
            which = ("it" if len(keys) == 1 else "them") if found == len(keys) else "the ones the crawl found"
            text += (f"\n\nMapping again leaves {which} off the map, and doesn't crawl through {which} to what's "
                     "beyond. To put them back, right-click the map's background > Deleted Devices.")
        if QMessageBox.question(self, "Delete Devices", text, QMessageBox.Yes | QMessageBox.No,
                                QMessageBox.No) != QMessageBox.Yes:
            return
        network_map.remove_devices(keys, remember=True)
        self.map_changed()
        set_hint(self.status_label, f"Deleted {count_text(len(keys), 'device')}.", "info")

    def show_deleted_devices(self):
        """The devices deleted from the map, to bring some back on the next crawl."""
        if self.network_map is None or not self.network_map.deleted or self.worker is not None:
            return
        dialog = DeletedDevicesDialog(self.network_map.deleted, self)
        if dialog.exec_() != QDialog.Accepted or not dialog.chosen():
            return
        keys = dialog.chosen()
        self.network_map.bring_back(keys)
        self.map_changed()
        set_hint(self.status_label, f"{count_text(len(keys), 'device').capitalize()} will be back on the map when "
                 "you map again (or Crawl from Here on a neighbor).", "success")

    def draw_link_from(self, key):
        self.tabs.setCurrentWidget(self.view)
        if self.view.start_drawing(key):
            set_hint(self.status_label, f"Click the device to link {self.network_map.devices[key].label} to. Esc, a "
                     "right-click or a click on the background stops.", "info")

    def add_link(self, a="", b=""):
        network_map = self.network_map
        if network_map is None or len(network_map.devices) < 2 or self.worker is not None:
            return
        dialog = LinkDialog(network_map, a, b, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        link = dialog.values()
        network_map.add_link(link)
        self.map_changed()
        set_hint(self.status_label, f"Linked {network_map.devices[link.a].label} and "
                 f"{network_map.devices[link.b].label}. It's drawn dotted, and kept when you map again until the "
                 "crawl finds a link between them.", "success")

    def edit_link(self, link):
        if self.network_map is None or link not in self.network_map.links or self.worker is not None:
            return
        dialog = LinkDialog(self.network_map, link=link, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            self.network_map.links[next(index for index, item in enumerate(self.network_map.links)
                                        if item is link)] = dialog.values()
            self.map_changed()

    def delete_links(self, links):
        if not links or self.network_map is None or self.worker is not None:
            return
        what = "this link" if len(links) == 1 else f"these {len(links)} links"
        if QMessageBox.question(self, "Delete Links", f"Delete {what} drawn by hand?",
                                QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return
        doomed = {id(link) for link in links}
        self.network_map.links = [link for link in self.network_map.links if id(link) not in doomed]
        self.map_changed()
        set_hint(self.status_label, f"Deleted {count_text(len(links), 'link')}.", "info")

    def check_devices(self, keys, announce=False):
        """Ask devices added by hand, in the background, whether they answer SNMP with the map's community
        strings (or only ping), and note it on them as a crawl would."""
        devices = self.network_map.devices if self.network_map else {}
        targets = [(key, devices[key].mgmt_ip) for key in keys
                   if key in devices and devices[key].mgmt_ip and key not in self.checking]
        if not targets:
            return
        self.checking.update(key for key, _ in targets)
        if announce:
            self.announce.update(key for key, _ in targets)
        thread = CheckThread(self.crawl_settings([address for _, address in targets]), targets, self.check_device,
                             self)
        thread.checked.connect(self.on_checked)
        thread.finished.connect(self.on_check_finished)
        self.check_threads.append(thread)
        thread.start()

    # Threads' signals go to methods, never lambdas: a lambda's signal still waiting to be delivered when the page
    # (and so its threads) is freed crashes Qt, where a method's is dropped

    def on_crawl_failed(self, message):
        set_hint(self.status_label, message, "error")

    def on_check_finished(self):
        thread = self.sender()
        if thread in self.check_threads:
            self.check_threads.remove(thread)
        for key, _ in thread.targets:  # Any that failed (or were stopped) without an answer
            self.checking.discard(key)
            self.announce.discard(key)

    def on_checked(self, key, address, check):
        self.checking.discard(key)
        if check.community:
            self.answered[address] = check.community
        announce = key in self.announce
        self.announce.discard(key)
        device = self.network_map.devices.get(key) if self.network_map else None
        if device is None or device.mgmt_ip != address:
            return  # Deleted, or given another address meanwhile
        why = f" ({'; '.join(check.reasons)})" if check.reasons else ""
        if not (device.manual or "mgmt_ip" in device.corrected):
            # Found by a crawl: one that answers now is read, as the crawl would have
            if check.source != SNMP:
                if announce:
                    set_hint(self.status_label, f"{device.label} still doesn't answer SNMP{why}.", "warning")
                return
            if self.worker is None:
                self.crawl_from(address)
                text = f"{device.label} answers SNMP now: reading it (Crawl from Here)."
            else:
                text = f"{device.label} answers SNMP now. Crawl from Here once the crawl going on has finished."
            if announce:
                set_hint(self.status_label, text, "success")
            return
        check.apply(device)
        if self.worker is None:
            self.map_changed()
        if announce:
            if check.source == SNMP:
                text, level = (f"{device.label} answers SNMP. Right-click it > Crawl from Here to read its neighbors "
                               "and hosts.", "success")
            elif check.source == NO_SNMP:
                text, level = f"{device.label}: {check.error}{why}", "warning"
            else:
                text, level = f"{device.label} doesn't answer SNMP or ping{why}.", "error"
            set_hint(self.status_label, text, level)

    # ----------------------------------------------------------------- Sites, buildings and rooms

    def add_group_menu(self, menu, actions, keys):
        """The Group submenu for the devices right-clicked: a new site, building or room, move to one, or out of
        one."""
        network_map = self.network_map
        what = "Device" if len(keys) == 1 else f"{len(keys)} Devices"
        submenu = menu.addMenu("Group")
        actions[submenu.addAction(f"New Site, Building or Room for the {what}...")] = lambda: self.new_group(keys)
        groups = sorted(network_map.groups, key=lambda group: network_map.group_label(group).lower())
        if groups:
            submenu.addSeparator()
            current = {network_map.group_of.get(key, "") for key in keys}
            for group in groups:
                action = submenu.addAction(f"Move to {network_map.group_label(group)}")
                action.setCheckable(True)
                action.setChecked(current == {group.key})
                actions[action] = lambda group=group: self.move_devices(keys, group.key)
        if any(key in network_map.group_of for key in keys):
            submenu.addSeparator()
            actions[submenu.addAction("Take Out of Its Group" if len(keys) == 1 else "Take Out of Their Groups")] = \
                lambda: self.move_devices(keys, "")

    def show_group_menu(self, key, position):
        network_map = self.network_map
        group = network_map.group(key) if network_map else None
        item = self.view.group_items.get(key)
        if group is None or item is None:
            return
        kind = GROUP_KINDS[group.kind]
        menu = QMenu(self)
        actions = {}
        stop = self.add_stop_highlight(menu)
        if stop is not None:
            actions[stop] = self.clear_vlan
        actions[menu.addAction("Expand" if group.collapsed else "Collapse")] = \
            lambda: self.view.set_collapsed(item, not group.collapsed)
        actions[menu.addAction("Select Its Devices")] = lambda: self.select_group_devices(key)
        if self.worker is None:
            members = network_map.members(key)
            style = self.selection_arrangement(self.view, members)[0]
            self.add_style_menu(menu, f"Arrange This {kind}", lambda style: self.arrange_group(key, style), style)
            self.add_spacing_menu(menu, f"Spacing of This {kind}", self.measured_spacing(self.view, members),
                                  lambda spacing: self.space_group(key, spacing))
            self.add_selection_actions(menu, self.view, self.view.selected_keys())  # With others selected
            menu.addSeparator()
            actions[menu.addAction("Rename...")] = lambda: self.rename_group(key)
            if group.kind in PARENT_KIND:
                outer = GROUP_KINDS[PARENT_KIND[group.kind]]
                choices = sorted((other for other in network_map.groups if other.kind == PARENT_KIND[group.kind]),
                                 key=lambda other: network_map.group_label(other).lower())
                move = menu.addMenu(f"Move to {outer}")
                for choice in choices:
                    action = move.addAction(network_map.group_label(choice))
                    action.setCheckable(True)
                    action.setChecked(group.parent == choice.key)
                    actions[action] = lambda choice=choice: self.move_subgroup(key, choice.key)
                if group.parent:
                    actions[move.addAction(f"Not in a {outer}")] = lambda: self.move_subgroup(key, "")
                move.setEnabled(bool(move.actions()))
            actions[menu.addAction(f"Ungroup {kind}")] = lambda: self.ungroup(key)
        chosen = menu.exec_(position)
        if chosen in actions:
            actions[chosen]()

    def new_group(self, keys):
        network_map = self.network_map
        current = {network_map.group_of.get(key, "") for key in keys}
        inside = current.pop() if len(current) == 1 else ""  # All in one group: most likely a group in it
        dialog = GroupDialog(network_map, count=len(keys), inside=inside, parent=self)
        if dialog.exec_() != QDialog.Accepted:
            return
        name, kind, inside = dialog.values()
        group = network_map.new_group(name, kind, inside)
        network_map.set_group(keys, group.key)
        self.groups_edited(f"Made {GROUP_KINDS[kind].lower()} {name} with {count_text(len(keys), 'device')}. Drag "
                           "devices into or out of its box; right-click its title to arrange, rename or collapse it.")

    def move_devices(self, keys, group_key):
        network_map = self.network_map
        for key in keys:
            if group_key:
                network_map.group_of[key] = group_key
            else:
                network_map.group_of.pop(key, None)
        network_map.prune_groups()
        what = network_map.devices[keys[0]].label if len(keys) == 1 else count_text(len(keys), "device")
        group = network_map.group(group_key)
        self.groups_edited(f"Moved {what} to {network_map.group_label(group)}." if group is not None
                           else f"Took {what} out of {'its group' if len(keys) == 1 else 'their groups'}.")

    def on_devices_dropped(self, changes):
        """Devices dragged into a group's box, or out of their group's."""
        if self.network_map is None or self.worker is not None:
            return
        targets = set(changes.values())
        if len(targets) == 1:
            self.move_devices(list(changes), targets.pop())
            return
        for key, group_key in changes.items():
            if group_key:
                self.network_map.group_of[key] = group_key
            else:
                self.network_map.group_of.pop(key, None)
        self.network_map.prune_groups()
        self.groups_edited(f"Moved {count_text(len(changes), 'device')} between groups.")

    def rename_group(self, key):
        group = self.network_map.group(key)
        dialog = GroupDialog(self.network_map, group=group, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            old, group.name = group.name, dialog.values()[0]
            self.groups_edited(f"Renamed {old} to {group.name}.")

    def move_subgroup(self, key, parent_key):
        """Move a building to another site or a room to another building ("" for none)."""
        group = self.network_map.group(key)
        group.parent = parent_key
        outer = self.network_map.group(parent_key)
        self.groups_edited(f"Moved {group.name} to {outer.name}." if outer else
                           f"{group.name} isn't in a {GROUP_KINDS[PARENT_KIND[group.kind]].lower()} now.")

    def ungroup(self, key):
        group = self.network_map.group(key)
        self.network_map.remove_group(key)
        where = f"its {GROUP_KINDS[PARENT_KIND[group.kind]].lower()}" if group.parent else "no group"
        self.groups_edited(f"Ungrouped {group.name}. Its devices stay where they are, in {where}.")

    def select_group_devices(self, key):
        item = self.view.group_items.get(key)
        if item is None:
            return
        if item.group.collapsed:
            self.view.set_collapsed(item, False)
        self.view.show_devices(self.network_map.members(key))

    def arrange_group(self, key, style=None):
        item = self.view.group_items.get(key)
        if item is None:
            return
        if item.group.collapsed:
            self.view.set_collapsed(item, False)
        self.arrange_selected(self.view, self.network_map.members(key), style=style)

    def space_group(self, key, spacing):
        """Space a group's devices out, keeping them as they're arranged."""
        item = self.view.group_items.get(key)
        if item is None:
            return
        if item.group.collapsed:
            self.view.set_collapsed(item, False)
        self.space_out(self.view, self.network_map.members(key), (), spacing)

    def groups_edited(self, message=None):
        """Redraw the groups after they changed, keeping the view where it was, and save."""
        network_map = self.network_map
        network_map.positions = self.view.positions()
        network_map.prune_groups()
        self.view.rebuild_groups()
        self.view.update_scene_rect()
        self.fill_tables()  # The Group column
        try:
            self.map_path = self.write_map(network_map, self.map_path)
        except OSError as error:
            QMessageBox.warning(self, "Save Network Map", f"Couldn't save the map:\n\n{error}")
        if message:
            set_hint(self.status_label, message, "success")
        self.record_layout()

    # ----------------------------------------------------------------- Undo and Redo

    def layout_state(self):
        """What Undo puts back: where everything is on both views, the sites, buildings and rooms (not whether
        they're collapsed), and which one each device is in."""
        network_map = self.network_map
        return {"positions": self.view.positions(), "l3_positions": self.l3_view.positions(),
                "groups": [(group.key, group.name, group.kind, group.parent) for group in network_map.groups],
                "group_of": dict(network_map.group_of)}

    def record_layout(self):
        """After the layout may have changed: keep the one before it for Undo."""
        if self.network_map is None or self.worker is not None:
            return  # While a crawl runs the views show the map so far, not the one open
        state = self.layout_state()
        if self.layout_now is not None and not self.restoring and state != self.layout_now:
            self.undo_stack = (self.undo_stack + [self.layout_now])[-UNDO_LIMIT:]
            self.redo_stack = []
        self.layout_now = state
        self.update_undo_buttons()

    def undo(self):
        self.step_layout(self.undo_stack, self.redo_stack, "Undid")

    def redo(self):
        self.step_layout(self.redo_stack, self.undo_stack, "Redid")

    def step_layout(self, source, target, verb):
        """Go back (or forward) to the layout on top of source, keeping the one now on target."""
        if not source or self.network_map is None or self.worker is not None:
            return
        target.append(self.layout_now)
        state = source.pop()
        network_map = self.network_map
        collapsed = {group.key for group in network_map.groups if group.collapsed}
        self.restoring = True
        try:
            network_map.groups = [Group(key, name, kind, parent, collapsed=key in collapsed)
                                  for key, name, kind, parent in state["groups"]]
            network_map.group_of = dict(state["group_of"])
            self.view.rebuild_groups()
            self.view.move_to(state["positions"])
            self.l3_view.move_to(state["l3_positions"])
            network_map.l3_positions = self.l3_view.positions()
            self.groups_edited(f"{verb} the last change to the layout.")
        finally:
            self.restoring = False
        self.layout_now = self.layout_state()
        self.update_undo_buttons()

    def update_undo_buttons(self):
        idle = self.network_map is not None and self.worker is None
        self.undo_button.setEnabled(idle and bool(self.undo_stack))
        self.redo_button.setEnabled(idle and bool(self.redo_stack))

    # ----------------------------------------------------------------- Monitoring

    def on_monitor_toggled(self, on):
        if on and self.network_map is None:
            self.monitor_check.setChecked(False)
            return
        if on:
            self.monitor.start(self.interval_combo.currentData())
        else:
            self.monitor.stop()
            self.counters.reset()
        self.remember_switches()
        self.show_statuses()
        if self.overlay_shown is not None and self.overlay_shown[0] == overlays.UTIL:
            self.apply_vlan_focus()

    def on_counters_updated(self):
        """A poll's counters are in: the Utilization overlay shows them."""
        if self.overlay_shown is not None and self.overlay_shown[0] == overlays.UTIL:
            self.apply_vlan_focus()

    def show_statuses(self):
        """After a poll: the dots on both maps, the Status column, the summary and the details showing."""
        for view in (self.view, self.l3_view):
            view.set_statuses(self.monitor.status)
        summary = self.monitor.summary()
        self.show_summary(self.monitor_label, summary)
        self.monitor_label.setStyleSheet(f"color: {COLORS['error' if ' down' in summary else 'success']};")
        if self.network_map is not None:
            column = export.DEVICE_COLUMNS.index("Status")
            for row in range(self.devices_table.rowCount()):
                item = self.devices_table.item(row, column)
                key = self.devices_table.item(row, 0).data_object
                if item is not None and item.text() != self.monitor.status_text(key):
                    item.setText(self.monitor.status_text(key))
            self.table_filters[self.devices_table].apply()  # A filter on Status follows the changes
            selected = self.current_view().scene().selectedItems()
            if len(selected) == 1 and getattr(selected[0], "device", None) is not None:
                self.show_details(("device", selected[0].key))

    def keep_history(self, entries):
        """Status changes go into the map's history, saved with it."""
        if self.network_map is None:
            return
        self.network_map.status_log = (self.network_map.status_log + entries)[-monitor.HISTORY_LIMIT:]
        self.save_timer.start()

    # ----------------------------------------------------------------- Comparing

    def fill_compare_menu(self):
        self.compare_menu.clear()
        current = Path(self.map_path).resolve() if self.map_path else None
        for path in store.recent(limit=store.RECENT_LIMIT + 1):
            if path.resolve() != current:
                self.compare_menu.addAction(f"With {path.stem}", lambda path=path: self.compare_with(path))
        self.compare_menu.addSeparator()
        self.compare_menu.addAction("With Another Map...", self.compare_with_file)

    def compare_with_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Compare with Map", str(store.maps_dir()), MAP_FILTER)
        if path:
            self.compare_with(Path(path))

    def compare_with(self, path):
        if self.network_map is None:
            return
        try:
            older = store.load(path)
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, "Compare Maps", f"Couldn't open {path.name}:\n\n{error}")
            return
        changes = diff.compare(older, self.network_map)
        if self.compare_dialog is not None:
            self.compare_dialog.close()
        self.compare_dialog = CompareDialog(changes, path.stem, self)
        self.compare_dialog.show_change.connect(self.show_change)
        self.compare_dialog.finished.connect(lambda _: self.view.set_highlights({}))
        colors = {}
        for change in changes:
            if change.what == diff.DEVICE and change.device:
                colors[change.device] = COLORS["success"] if change.change == diff.ADDED else COLORS["warning"]
        self.view.set_highlights(colors)
        self.tabs.setCurrentWidget(self.view)
        self.compare_dialog.show()
        set_hint(self.status_label, f"Compared with {path.stem}: {len(changes)} difference"
                 f"{'' if len(changes) == 1 else 's'}. New devices are ringed in green, changed ones in amber.",
                 "info")

    def show_change(self, change):
        self.tabs.setCurrentWidget(self.view)
        if change.mac:
            host = next((host for host in self.network_map.hosts if host.mac == change.mac), None)
            if host is not None:
                self.view.show_host(host)
                return
        if change.device:
            self.view.show_device(change.device)

    # ----------------------------------------------------------------- Watching for new devices

    def on_watch_toggled(self, on):
        if on and self.network_map is None:
            self.watch_check.setChecked(False)
            return
        if on:
            self.watcher.start()
        else:
            self.watcher.stop()
        self.remember_switches()
        self.update_watch_label()

    def update_watch_label(self):
        summary = self.watcher.summary()
        self.show_summary(self.watch_label, summary)
        new = self.network_map is not None and bool(self.network_map.news)
        self.watch_label.setStyleSheet(f"color: {COLORS['success' if new else 'muted']};")

    def watch_options(self):
        return watch.WatchOptions(communities=self.credentials(), overrides=[list(item) for item in self.overrides],
                                  scope=list(self.scope), version=self.version, timeout=self.timeout,
                                  max_hops=self.max_hops, max_devices=self.max_devices, workers=self.workers)

    def can_watch_now(self):
        """Whether watching may change the map now: not while the user's own crawl runs or something's dragged."""
        return self.worker is None and QApplication.mouseButtons() == Qt.NoButton

    def map_name(self):
        if self.tribe_map_id is not None and self.tribe.maps is not None:
            return (self.tribe.maps.map_info(self.tribe_map_id) or {}).get("name", "the tribe map")
        return Path(self.map_path).stem if self.map_path else "the map"

    def watch_applied(self, result):
        """Watching read some switches again and added what it found: redraw (keeping the view) and save."""
        if self.network_map is None:
            return
        place = {}
        for key in result.devices:  # Beside the switch it was seen on
            near = next((link.other(key) for link in self.network_map.links_of(key)
                         if link.other(key) in self.view.items_by_key), None)
            if near is not None:
                position = self.view.items_by_key[near].pos()
                place[key] = (position.x() + 40 * (1 + len(place)), position.y() + 140)
        self.map_changed(place=place)
        self.log_ipam_news(result)
        if result:
            self.window.show_status("Watch: " + "; ".join(result.lines[:3])
                                    + (f" (and {len(result.lines) - 3} more)" if len(result.lines) > 3 else ""))
            if result.devices or result.hosts:
                set_hint(self.status_label, "Watching found: " + "; ".join(result.lines[:5]) + ". They're tagged "
                         "NEW until marked as seen (right-click, or Mark All as Seen on the Watch tab).", "success")
        self.update_watch_label()

    def news_of_devices(self, keys):
        """News refs for these devices and the hosts on them."""
        if self.network_map is None:
            return []
        keys = set(keys)
        refs = [f"device:{key}" for key in keys if f"device:{key}" in self.network_map.news]
        refs += [f"host:{host.mac}" for host in self.network_map.hosts
                 if host.device in keys and f"host:{host.mac}" in self.network_map.news]
        return refs

    def mark_seen(self, refs):
        """Clear NEW tags (all of them when refs is None)."""
        if self.network_map is None or not self.network_map.news:
            return
        cleared = watch.acknowledge(self.network_map, refs)
        if not cleared:
            return
        self.view.set_news(self.network_map.news)
        self.fill_tables()
        try:
            self.map_path = self.write_map(self.network_map, self.map_path)
        except OSError as error:
            log.warning("Couldn't save the network map: %s", error)
        self.update_watch_label()
        self.watcher.update_summary()

    # ----------------------------------------------------------------- Tribe maps

    def write_map(self, network_map, path):
        """Save the map where it belongs: the tribe map open, the file it came from, or a new file. Returns the
        file's path (None for a tribe map)."""
        if self.tribe_map_id is not None and self.tribe.maps is not None:
            self.tribe.save(self.tribe_map_id, network_map, self.tribe_settings(), self.tribe_seen)
            self.update_tribe_label()
            return None
        return store.save(network_map, path) if path else store.save(network_map)

    def tribe_settings(self):
        """How the map is crawled, kept with a tribe map (community strings are kept apart, as secrets)."""
        return {"scope": list(self.scope), "max_hops": self.max_hops, "max_devices": self.max_devices,
                "version": self.version, "timeout": self.timeout, "collect_hosts": self.collect_hosts,
                "trace": self.trace, "workers": self.workers, "seeds": self.seeds_input.text()}

    def tribe_secrets(self):
        return credentials_to_json(self.communities, self.overrides, self.v3_users, self.v3_first)

    def apply_tribe_settings(self, settings, secrets):
        self.scope = list(settings.get("scope", self.scope))
        for name in ("max_hops", "max_devices", "version", "timeout", "collect_hosts", "trace", "workers"):
            if name in settings:
                setattr(self, name, type(getattr(self, name))(settings[name]))
        self.workers = max(1, min(MAX_WORKERS, self.workers))
        if settings.get("seeds"):
            self.seeds_input.setText(settings["seeds"])
        self.apply_tribe_secrets(secrets)

    def apply_tribe_secrets(self, secrets):
        """Use a tribe map's SNMP credentials (kept on the tribe server). Returns whether it has any (without,
        those already set here are used)."""
        if not (secrets.get("communities") or secrets.get("v3_users")):
            return False
        self.communities, self.overrides, self.v3_users, self.v3_first = credentials_from_json(secrets, [])
        return True

    def fill_tribe_menu(self):
        menu = self.tribe_menu
        menu.clear()
        maps = self.tribe.ensure()
        if maps is None:
            if is_tribe_server() and getattr(self.window, "admin", False) is not True:
                menu.addAction("This is the tribe server: restart NOMAD as administrator (File > Restart as "
                               "Administrator) to use its maps").setEnabled(False)
                menu.addSeparator()
            menu.addAction("Connect to the Tribe with a Key File...", self.join_tribe)
            return
        listed = maps.maps()
        if not listed:
            menu.addAction("No tribe maps yet" if maps.online else "No tribe maps here yet (the server hasn't "
                           "been reached)").setEnabled(False)
        for item in listed:
            action = menu.addAction(f"Open {item['name']}", lambda map_id=item["id"]: self.open_tribe_map(map_id))
            action.setCheckable(True)
            action.setChecked(item["id"] == self.tribe_map_id)
        menu.addSeparator()
        share = menu.addAction("Share This Map with the Tribe...", self.share_with_tribe)
        share.setEnabled(self.network_map is not None and self.tribe_map_id is None and self.worker is None)
        if self.tribe_map_id is not None:
            menu.addAction("Rename Tribe Map...", self.rename_tribe_map)
            menu.addAction("Keep a Copy on This Computer Only", self.leave_tribe_map)
            menu.addAction("Delete Tribe Map...", self.delete_tribe_map)
        menu.addSeparator()
        key = self.tribe_key()
        if key is not None and key.role == ADMIN:
            menu.addAction("This computer is the tribe server").setEnabled(False)
        else:
            menu.addAction("Connect to the Tribe with Another Key File...", self.join_tribe)

    def tribe_key(self):
        """The key for the tribe's server: its own admin key on the server (as administrator), or the saved one."""
        return current_key(getattr(self.window, "admin", False) is True)

    def join_tribe(self):
        """Save a tribe key file's key for this Windows account (the IP Addresses page uses it too)."""
        if not connect_to_tribe(self, self.window):  # Tells the pages, this one included
            return
        set_hint(self.status_label, "Connected to the tribe. The key is saved, encrypted for your Windows account, and the IP "
                 "Addresses page uses it too. Open the tribe's maps from Tribe (they arrive once the server has "
                 "been reached), or share this one. You can delete the key file now, or keep it somewhere safe: "
                 "anyone with it can change the tribe's maps and IPAM.", "success")

    def unsent_tribe_changes(self):
        return self.tribe.maps.pending_count() if self.tribe.maps is not None else 0

    def tribe_key_changed(self, forget=False):
        """The tribe key was saved, changed or forgotten (here or on the IP Addresses page)."""
        map_id = self.tribe_map_id
        if map_id is not None and self.network_map is not None:
            self.flush_save()
        self.tribe.reset(forget=forget)
        maps = self.tribe.ensure() if self.tribe_key() is not None else None
        if map_id is not None and (maps is None or maps.map_info(map_id) is None):
            self.leave_tribe_map("This computer no longer uses that tribe, so the tribe map that was open is kept as "
                                 "a file on this computer.")
        self.update_tribe_label()

    def flush_save(self):
        """Save a move waiting on the timer now (before the map open changes)."""
        if self.save_timer.isActive():
            self.save_timer.stop()
            self.save_positions()

    def open_tribe_map(self, map_id, quiet=False):
        """Open a tribe map. Returns whether it was."""
        maps = self.tribe.ensure()
        if maps is None or self.worker is not None:
            return False
        info = maps.map_info(map_id)
        if info is None or info.get("deleted"):
            if not quiet:
                QMessageBox.warning(self, "Open Tribe Map", "That map isn't shared with the tribe any more.")
            return False
        self.flush_save()
        network_map, settings, seen = maps.snapshot(map_id)
        secrets = maps.secrets(map_id)
        if not secrets:
            try:
                secrets = maps.fetch_secrets(map_id)
            except Exception as error:  # Offline: the communities already set here are used
                log.info("Couldn't fetch a tribe map's community strings: %s", error)
        self.apply_tribe_settings(settings, secrets)
        self.tribe_map_id, self.tribe_seen = map_id, seen
        self.show_map(network_map, None, fit=True)
        self.update_tribe_label()
        if not quiet:
            set_hint(self.status_label, f"Opened the tribe map {info['name']}. Changes made here reach everyone "
                     "with the tribe key (and are sent later if the server can't be reached now)." +
                     ("" if secrets.get("communities") or secrets.get("v3_users") else
                      " It has no shared SNMP credentials yet, so this computer's own are used: set them with SNMP "
                      "Credentials... to share them with everyone."), "info")
            if not network_map.ipam_network:
                QTimer.singleShot(0, self.ask_tribe_map_network)
        return True

    def ask_tribe_map_network(self):
        """A tribe map no one has said the IPAM network of: ask, once on this computer (everyone gets the answer)."""
        integration, maps = hub(self.window), self.tribe.maps
        if integration is None or maps is None or self.tribe_map_id is None or self.network_map is None or \
                self.network_map.ipam_network:
            return
        if maps.asked(self.tribe_map_id, "ipam_network"):
            return
        maps.note_asked(self.tribe_map_id, "ipam_network")
        log.info("Asking which IPAM network the tribe map %s is of", self.map_name())
        self.window.ipam_tab.open_store()
        if integration.networks():
            self.choose_ipam_network()

    def share_with_tribe(self):
        maps = self.tribe.ensure()
        if maps is None or self.network_map is None:
            return
        default = Path(self.map_path).stem if self.map_path else store.default_name(self.network_map)[:-len(
            store.EXTENSION)]
        name, ok = QInputDialog.getText(self, "Share with the Tribe", "Name for the map (everyone in the tribe will "
                                        "see it, and its community strings, by this name):", text=default)
        if not ok or not name.strip():
            return
        self.flush_save()
        self.network_map.positions = self.view.positions()
        self.network_map.l3_positions = self.l3_view.positions()
        try:
            map_id = maps.create(name, self.network_map, self.tribe_settings(), self.tribe_secrets())
        except IpamError as error:
            QMessageBox.warning(self, "Share with the Tribe", f"Couldn't share the map:\n\n{error}")
            return
        self.tribe_map_id, self.map_path = map_id, None
        self.tribe_seen = maps.items(map_id)
        self.watched_identity = (map_id, "None", self.network_map.started)  # Same map: watching carries on
        if self.watcher.running:
            self.watcher.map_changed()
        self.update_tribe_label()
        set_hint(self.status_label, f"Shared as the tribe map {name.strip()}. Everyone with the tribe key can open it "
                 "from Tribe, and changes anyone makes reach the others.", "success")

    def rename_tribe_map(self):
        info = self.tribe.maps.map_info(self.tribe_map_id) or {}
        name, ok = QInputDialog.getText(self, "Rename Tribe Map", "New name:", text=info.get("name", ""))
        if not ok or not name.strip():
            return
        try:
            self.tribe.maps.rename(self.tribe_map_id, name)
        except IpamError as error:
            QMessageBox.warning(self, "Rename Tribe Map", f"Couldn't rename it:\n\n{error}")
        self.update_tribe_label()

    def leave_tribe_map(self, message=None):
        """Carry on with the map as a file on this computer only."""
        self.flush_save()
        self.network_map.positions = self.view.positions()
        self.tribe_map_id, self.tribe_seen = None, None
        try:
            self.map_path = store.save(self.network_map)
        except OSError as error:
            QMessageBox.warning(self, "Tribe Map", f"Couldn't save the map:\n\n{error}")
        self.watched_identity = (None, str(self.map_path), self.network_map.started)
        if self.watcher.running:
            self.watcher.map_changed()
        self.update_tribe_label()
        set_hint(self.status_label, message or f"This map is now on this computer only, as "
                 f"{self.map_path.name if self.map_path else 'a file'}. The tribe map is unchanged.", "info")

    def delete_tribe_map(self):
        info = self.tribe.maps.map_info(self.tribe_map_id) or {}
        answer = QMessageBox.question(self, "Delete Tribe Map", f"Delete the tribe map {info.get('name', '')} for "
                                      "everyone? This computer keeps a copy as a file.")
        if answer != QMessageBox.Yes:
            return
        map_id = self.tribe_map_id
        try:
            self.tribe.maps.delete(map_id)
        except IpamError as error:
            QMessageBox.warning(self, "Delete Tribe Map", f"Couldn't delete it:\n\n{error}")
            return
        self.leave_tribe_map("Deleted the tribe map. This computer keeps a copy as a file.")

    def update_tribe_label(self):
        self.remember_open_map()  # Called whenever a tribe map is opened, shared or left
        text = self.tribe.status_text(self.tribe_map_id)
        self.tribe_label.setText(text)
        self.tribe_label.setVisible(bool(text))
        offline = bool(self.tribe.error) or (self.tribe.maps is not None and not self.tribe.maps.online)
        self.tribe_label.setStyleSheet(f"color: {COLORS['warning' if offline else 'muted']};")

    def on_tribe_synced(self, touched):
        self.update_tribe_label()
        map_id = self.tribe_map_id
        if map_id is None or map_id not in touched:
            return
        info = self.tribe.maps.map_info(map_id)
        if info is None or info.get("deleted"):
            self.leave_tribe_map("Someone deleted this tribe map. This computer keeps a copy as a file.")
            return
        changed = touched[map_id]
        if SECRETS in changed:
            self.tribe_secrets_changed()
        if changed - {SECRETS}:
            self.reload_from_tribe()

    def tribe_secrets_changed(self):
        """Someone changed the tribe map's SNMP credentials: use theirs from now on."""
        if not self.apply_tribe_secrets(self.tribe.maps.secrets(self.tribe_map_id)):
            return
        self.watcher.recheck_now()
        set_hint(self.status_label, "Someone in the tribe changed this map's SNMP credentials; they're used here "
                 "now.", "info")

    def reload_from_tribe(self):
        """Others changed the tribe map open: show their changes, keeping the view where it is."""
        if self.tribe_map_id is None or self.network_map is None:
            return
        if not self.can_watch_now():  # Mid-crawl or mid-drag: try again shortly
            QTimer.singleShot(2000, self.reload_from_tribe)
            return
        self.flush_save()
        newer, settings, self.tribe_seen = self.tribe.maps.snapshot(self.tribe_map_id)
        if shared.flatten(newer) == shared.flatten(self.network_map):
            return  # Only this computer's own changes coming back
        newer.status_log = self.network_map.status_log  # Monitoring history is this computer's own
        if self.history_map is self.network_map:
            self.history_map = newer
        self.watched_identity = (self.tribe_map_id, "None", newer.started)
        self.network_map = newer
        self.apply_tribe_settings(settings, {})
        self.redraw_keeping_view()
        self.update_watch_label()

    def redraw_keeping_view(self, show=None, select=None):
        """Draw the map open again, keeping the view where it was, what was selected and which hosts were open."""
        network_map = self.network_map
        expanded = {key for key, item in self.view.items_by_key.items() if item.expanded}
        selected = [select] if select else self.view.selected_keys()
        scroll = (self.view.horizontalScrollBar().value(), self.view.verticalScrollBar().value())
        self.show_map(network_map, self.map_path)
        for key in expanded | ({show.device} if show else set()):
            if key in self.view.items_by_key and self.view.items_by_key[key].host_count:
                self.view.items_by_key[key].set_expanded(True)
        self.view.update_scene_rect()
        self.view.horizontalScrollBar().setValue(scroll[0])
        self.view.verticalScrollBar().setValue(scroll[1])
        for key in selected:
            if key in self.view.items_by_key:
                self.view.items_by_key[key].setSelected(True)

    # ----------------------------------------------------------------- Files

    def open_map(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open Network Map", str(store.maps_dir()), MAP_FILTER)
        if path:
            self.open_path(Path(path))

    def open_path(self, path):
        try:
            network_map = store.load(path)
        except (OSError, ValueError) as error:
            QMessageBox.warning(self, "Open Network Map", f"Couldn't open {path.name}:\n\n{error}")
            return
        self.flush_save()
        self.tribe_map_id, self.tribe_seen = None, None
        self.update_tribe_label()
        self.show_map(network_map, path, fit=True)
        set_hint(self.status_label, f"Opened {path.name} (mapped {network_map.started.replace('T', ' ')}).", "info")

    def fill_recent_menu(self):
        self.recent_menu.clear()
        maps = store.recent()
        if not maps:
            self.recent_menu.addAction("No saved maps").setEnabled(False)
        for path in maps:
            self.recent_menu.addAction(path.stem, lambda path=path: self.open_path(path))

    def save_map_as(self):
        if self.network_map is None:
            return
        start = str(self.map_path or store.maps_dir() / store.default_name(self.network_map))
        path, _ = QFileDialog.getSaveFileName(self, "Save Network Map", start, MAP_FILTER)
        if not path:
            return
        self.network_map.positions = self.view.positions()
        try:
            saved = store.save(self.network_map, path)
        except OSError as error:
            QMessageBox.critical(self, "Save Network Map", f"Couldn't save the map:\n\n{error}")
            return
        if self.tribe_map_id is not None:  # A copy: the tribe's map stays open
            set_hint(self.status_label, f"Saved a copy as {saved.name}. The tribe map is still the one open.",
                     "success")
            return
        self.map_path = saved
        self.remember_open_map()
        set_hint(self.status_label, f"Saved {self.map_path.name}.", "success")

    def export_path(self, title, extension, file_filter):
        name = Path(self.map_path).stem if self.map_path else "Network map"
        path, _ = QFileDialog.getSaveFileName(self, title, str(Path.home() / f"{name}{extension}"), file_filter)
        return Path(path) if path else None

    def export_png(self):
        path = self.export_path("Export Picture", ".png", "PNG pictures (*.png)")
        if path and not self.current_view().render_image().save(str(path)):
            QMessageBox.critical(self, "Export Picture", f"Couldn't save {path}.")
        elif path:
            self.window.show_status(f"Saved the map as {path}.")

    def export_svg(self):
        path = self.export_path("Export Drawing", ".svg", "SVG drawings (*.svg)")
        if path:
            self.current_view().render_svg(path)
            self.window.show_status(f"Saved the map as {path}.")

    def export_drawio(self):
        path = self.export_path("Export for draw.io", ".drawio", "draw.io files (*.drawio)")
        if not path:
            return
        try:
            if self.current_view() is self.l3_view:
                text = export.drawio_graph([(key, node.label, node.device.kind if node.device else node.kind,
                                             node.kind in (l3.HOP, l3.STAR)) for key, node in self.l3_nodes.items()],
                                           l3.l3_graph(self.network_map)[1], self.l3_view.positions(), "Logical map")
            else:
                text = export.drawio(self.network_map, self.view.positions(), self.view.group_boxes())
            path.write_text(text, encoding="utf-8")
        except OSError as error:
            QMessageBox.critical(self, "Export for draw.io", f"Couldn't save the file:\n\n{error}")
            return
        self.window.show_status(f"Saved {path}. Open it in draw.io (or import it into Visio).")

    def export_csv(self, which):
        columns, rows = {"devices": (export.DEVICE_COLUMNS,
                                     lambda network_map: export.device_rows(network_map, self.monitor.status_text)),
                         "links": (export.LINK_COLUMNS, export.link_rows),
                         "hosts": (export.HOST_COLUMNS, export.host_rows)}[which]
        path = self.export_path(f"Export {which.title()}", f" {which}.csv", "CSV files (*.csv)")
        if not path:
            return
        try:
            export.write_csv(path, columns, rows(self.network_map))
        except OSError as error:
            QMessageBox.critical(self, "Export", f"Couldn't save the file:\n\n{error}")
            return
        self.window.show_status(f"Saved {path}.")

    def update_buttons(self):
        running = self.worker is not None
        has_map = self.network_map is not None
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        for widget in (self.save_button, self.export_button, self.compare_button, self.arrange_button,
                       self.ipam_network_button, self.ipam_record_button):
            widget.setEnabled(has_map and not running)  # Not while the map is being drawn from a crawl
        for widget in (self.open_button, self.recent_button):
            widget.setEnabled(not running)
        self.new_button.setEnabled(has_map and not running)
        for widget in (self.fit_button, self.hosts_check):
            widget.setEnabled(has_map or running)
        self.update_undo_buttons()
        self.monitor_check.setEnabled(has_map or self.monitor_check.isChecked())
        self.watch_check.setEnabled(has_map or self.watch_check.isChecked())
        here = self.tabs.currentWidget()
        self.find_input.setEnabled(has_map or running or here is self.crawl_progress.tab)
        self.update_crawl_row()


def put_device(network_map, device, link):
    """Put a device added by hand (and its link, if it's linked to one) on the map, in the same group as what it's
    linked to. Returns the device, with its new key."""
    device.key = network_map.new_device_key()
    network_map.devices[device.key] = device
    if link is not None:
        link.b = device.key
        network_map.add_link(link)
        if link.a in network_map.group_of:  # Most likely in the same room as what it's plugged into
            network_map.group_of[device.key] = network_map.group_of[link.a]
    return device


def fill_table(table, rows, ip_columns=(), keys=None):
    table.setSortingEnabled(False)
    table.setRowCount(len(rows))
    for row_number, row in enumerate(rows):
        for column, text in enumerate(row):
            sort_key = ip_sort_key(text) if column in ip_columns else None
            data = keys[row_number] if keys is not None and column == 0 else None
            table.setItem(row_number, column, SortableTableItem(text, sort_key, data))
    table.setSortingEnabled(True)


def device_html(network_map, key, state=None):
    """state: the device's monitor.DeviceStatus while it's monitored."""
    device = network_map.devices.get(key)
    if device is None:
        return ""
    escape = html.escape
    parts = [f"<h3>{escape(device.label)}</h3>",
             f"<p>{escape(KIND_NAMES.get(device.kind, device.kind))}"
             + (f" &middot; {escape(device.platform)}" if device.platform else "") + "</p><table>"]
    rows = [("Status", monitor_status_text(state)), ("Management IP", device.mgmt_ip),
            ("Group", network_map.device_group_label(key)), ("Found by", device.found_by),
            ("Hops from start", "" if device.manual else str(device.hops)),
            ("Addresses", ", ".join(device.addresses)), ("Problem", device.error), ("Note", device.note),
            ("Corrected", "; ".join(f"{CORRECTED_NAMES[attribute]} (the crawl found {shown_value(attribute, found)})"
                                    for attribute, (found, _) in device.corrected.items()))]
    for label, value in rows:
        if value:
            parts.append(f"<tr><td><b>{escape(label)}</b>&nbsp;</td><td>{escape(value)}</td></tr>")
    parts.append("</table>")
    links = network_map.links_of(key)
    if links:
        parts.append("<h4>Links</h4><table>")
        for link in sorted(links, key=lambda link: link.port_on(key)):
            other = network_map.devices[link.other(key)]
            port = vlan_port_text(vlan_info.port_info(device, link.port_on(key)))
            parts.append(f"<tr><td>{escape(link.port_on(key))}&nbsp;</td><td>&rarr; {escape(other.label)} "
                         f"{escape(link.port_on(other.key))}" + (f" &middot; {escape(port)}" if port else "")
                         + "</td></tr>")
        parts.append("</table>")
    parts.append(device_vlans_html(device))
    ports = network_map.hosts_by_port(key)
    if ports:
        count = sum(len(hosts) for hosts in ports.values())
        parts.append(f"<h4>Hosts ({count})</h4><table>")
        for port, hosts in ports.items():
            what = ", ".join(host.name or host.ip or host.mac for host in hosts) if len(hosts) <= 3 \
                else f"{len(hosts)} hosts"
            parts.append(f"<tr><td>{escape(port)}&nbsp;</td><td>{escape(what)}</td></tr>")
        parts.append("</table>")
    if device.interfaces_l3:
        parts.append("<h4>IP Interfaces</h4><table>")
        for address, prefix, port in device.interfaces_l3:
            parts.append(f"<tr><td>{escape(short_port(port))}&nbsp;</td><td>{escape(address)}/{prefix}</td></tr>")
        parts.append("</table>")
    routes = [route for route in device.routes if route[1]]  # Connected ones are the interfaces above
    if routes:
        parts.append(f"<h4>Routes ({len(routes)}{'+' if device.routes_truncated else ''})</h4><table>")
        for destination, next_hop, port, protocol in routes[:ROUTES_SHOWN]:
            parts.append(f"<tr><td>{escape(destination)}&nbsp;</td><td>via {escape(next_hop)} "
                         f"({escape(protocol)})</td></tr>")
        parts.append("</table>")
        if len(routes) > ROUTES_SHOWN:
            parts.append(f"<p>...and {len(routes) - ROUTES_SHOWN} more.</p>")
    if device.sys_descr:
        parts.append(f"<h4>Description</h4><p>{escape(device.sys_descr).replace(chr(10), '<br>')}</p>")
    if device.manual:
        parts.append("<p>Added by hand: right-click it to edit or delete it, or to draw a link from it. It's kept "
                     "when you map again, until the crawl finds it.</p>")
    return "".join(parts)


def vlan_port_text(info):
    """A port's VLANs in a few words: "trunk, native 1, VLANs 1-10,20" or "access VLAN 10, voice 20"."""
    if not info:
        return ""
    if info.get("mode") == vlan_info.TRUNK:
        allowed = info.get("allowed", "")
        return f"trunk, native {info.get('native', 1)}, " + (f"VLANs {allowed}" if allowed != "1-4094" else "all VLANs")
    text = f"access VLAN {info['vlan']}" if info.get("vlan") else ""
    if info.get("voice"):
        text += f"{', ' if text else ''}voice VLAN {info['voice']}"
    return text


def device_vlans_html(device):
    """A switch's VLANs, its VTP domain, and which ports are in which VLAN."""
    escape = html.escape
    names = vlan_info.vlan_names(device)
    if not names and not device.port_vlans:
        return ""
    vtp = f"VTP domain {device.vtp_domain}" if device.vtp_domain else ""
    if device.vtp_mode:
        vtp = f"{vtp} ({device.vtp_mode})" if vtp else f"VTP {device.vtp_mode}"
    parts = [f"<h4>VLANs ({len(names)})</h4>", f"<p>{escape(vtp)}</p>" if vtp else ""]
    if names:
        listed = [f"{vlan} {name}".strip() for vlan, name in sorted(names.items())]
        more = f" ...and {len(listed) - VLANS_LISTED} more" if len(listed) > VLANS_LISTED else ""
        parts.append(f"<p>{escape(', '.join(listed[:VLANS_LISTED]))}{more}</p>")
    trunks = [(port, info) for port, info in device.port_vlans.items() if info.get("mode") == vlan_info.TRUNK]
    if trunks:
        parts.append("<table>")
        for port, info in trunks:
            parts.append(f"<tr><td>{escape(port)}&nbsp;</td><td>{escape(vlan_port_text(info))}</td></tr>")
        parts.append("</table>")
    by_vlan = {}
    for port, info in device.port_vlans.items():
        if info.get("mode") != vlan_info.TRUNK and info.get("vlan"):
            by_vlan.setdefault(info["vlan"], []).append(port)
    if by_vlan:
        parts.append("<p><b>Access ports</b></p><table>")
        for vlan, ports in sorted(by_vlan.items()):
            listed = ", ".join(ports[:8]) + (f" and {len(ports) - 8} more" if len(ports) > 8 else "")
            parts.append(f"<tr><td>VLAN {vlan}&nbsp;</td><td>{escape(listed)}</td></tr>")
        parts.append("</table>")
    return "".join(parts)


def folded_text(folded):
    """For the status line after a crawl: devices added by hand that it has now found."""
    if not folded:
        return ""
    if len(folded) == 1:
        manual, found = folded[0]
        return f" {manual.label}, added by hand, was found by the crawl: it's {found.label} now."
    return f" {len(folded)} devices added by hand were found by the crawl and replaced by what it found."


class LinkRow(tuple):
    """A Links table row's data: its two devices' keys (what Show in looks for), and the Link itself."""

    def __new__(cls, link):
        row = super().__new__(cls, (link.a, link.b))
        row.link = link
        return row


def overlay_text(overlay):
    """What the bar over the map says of an overlay: its title, what it found, and its colors."""
    def escape(text):
        return html.escape(text, quote=False)
    title = escape(overlay.title)
    if overlay.tone:
        title = f"<span style='color:{COLORS[overlay.tone]}'>{title}</span>"
    parts = [f"<b>{title}</b>: " + escape(" · ".join(overlay.summary))]
    if overlay.legend:
        parts.append(" ".join(f"<span style='color:{COLORS.get(color, color)}'>&#9632;</span>&nbsp;{escape(text)}"
                              for color, text in overlay.legend))
    return " &nbsp;·&nbsp; ".join(parts)


def count_text(count, noun):
    return f"{count} {noun}{'' if count == 1 else 's'}"


def group_html(network_map, key, status_of=lambda key: None):
    """A site, building or room: what's in it, how many are down, and its links to the rest of the map."""
    group = network_map.group(key)
    if group is None:
        return ""
    escape = html.escape
    parent = network_map.group(group.parent)
    members = network_map.members(key)
    inside = set(members)
    down = [device for device in members if (status_of(device) or None) is not None
            and status_of(device).status == monitor.DOWN]
    parts = [f"<h3>{escape(group.name)}</h3>",
             f"<p>{GROUP_KINDS[group.kind]}" + (f" in {escape(network_map.group_label(parent))}" if parent else "")
             + f" &middot; {count_text(len(members), 'device')}"
             + (f" &middot; <span style='color:{COLORS['error']}'>{len(down)} down</span>" if down else "") + "</p>"]
    inner = network_map.subgroups(key)
    if inner:
        parts.append(f"<h4>{GROUP_KINDS[inner[0].kind]}s</h4><table>")
        for subgroup in sorted(inner, key=lambda subgroup: subgroup.name.lower()):
            parts.append(f"<tr><td>{escape(subgroup.name)}&nbsp;</td>"
                         f"<td>{count_text(len(network_map.members(subgroup.key)), 'device')}</td></tr>")
        parts.append("</table>")
    parts.append("<h4>Devices</h4><table>")
    for device in sorted((network_map.devices[device] for device in members), key=lambda device: device.label.lower()):
        path = [group.name for group in network_map.group_path(device.key)]
        where = escape(" / ".join(path[len(network_map.group_chain(group)):]))
        state = "<span style='color:%s'>down</span>" % COLORS["error"] if device.key in down else ""
        parts.append(f"<tr><td>{escape(device.label)}&nbsp;</td><td>{escape(KIND_NAMES.get(device.kind, ''))}"
                     f"&nbsp;</td><td>{where}&nbsp;</td><td>{state}</td></tr>")
    parts.append("</table>")
    leaving = [link for link in network_map.links if (link.a in inside) != (link.b in inside)]
    if leaving:
        parts.append(f"<h4>Links out ({len(leaving)})</h4><table>")
        for link in leaving[:GROUP_LINKS_SHOWN]:
            near, far = (link.a, link.b) if link.a in inside else (link.b, link.a)
            parts.append(f"<tr><td>{escape(network_map.devices[near].label)} {escape(link.port_on(near))}&nbsp;</td>"
                         f"<td>&rarr; {escape(network_map.devices[far].label)} {escape(link.port_on(far))}</td></tr>")
        parts.append("</table>")
        if len(leaving) > GROUP_LINKS_SHOWN:
            parts.append(f"<p>...and {len(leaving) - GROUP_LINKS_SHOWN} more.</p>")
    parts.append("<p>Double-click its title to collapse it into one box (or expand it). Drag the title to move "
                 "everything in it.</p>")
    return "".join(parts)


def monitor_status_text(state):
    if state is None:
        return ""
    if state.status == monitor.UNKNOWN:
        return "Being checked"
    since = datetime.datetime.fromtimestamp(state.since).strftime("%H:%M:%S")
    if state.status == monitor.DOWN:
        return f"Down for {monitor.duration_text(time.time() - state.since)} (since {since})"
    rtt = f", {'<1' if state.rtt < 1 else state.rtt} ms" if state.rtt is not None else ""
    return f"Up{rtt} (since {since})"


def subnet_html(network_map, subnet):
    escape = html.escape
    members, hosts = l3.subnet_details(network_map, subnet)
    parts = [f"<h3>{escape(subnet)}</h3><h4>Devices with an address in it</h4><table>"]
    for label, port, address in members:
        parts.append(f"<tr><td>{escape(label)}&nbsp;</td><td>{escape(port)} {escape(address)}</td></tr>")
    parts.append("</table>")
    routed = [(device.label, route) for device in network_map.devices.values() for route in device.routes
              if route[1] and route[0] == subnet]
    for label, (destination, next_hop, port, protocol) in routed[:ROUTES_SHOWN]:
        parts.append(f"<p>{escape(label)} routes it via {escape(next_hop)} ({escape(protocol)})</p>")
    if hosts:
        parts.append(f"<h4>Hosts on the map ({len(hosts)})</h4><table>")
        for host in hosts[:ROUTES_SHOWN]:
            device = network_map.devices.get(host.device)
            parts.append(f"<tr><td>{escape(host.ip)}&nbsp;</td><td>{escape(host.name or host.mac)} on "
                         f"{escape(device.label if device else host.device)} {escape(host.port)}</td></tr>")
        parts.append("</table>")
    return "".join(parts)


def node_html(network_map, node):
    """A hop traceroute found, an unanswered hop, or this computer: which traces went through it."""
    escape = html.escape
    parts = [f"<h3>{escape(node.label)}</h3>", f"<p>{escape(node.detail)}</p>" if node.detail else ""]
    through = [item for item in network_map.traces
               if node.key == l3.SELF or node.label in item.hops or node.key.startswith(f"star:{item.target}:")]
    if through:
        parts.append("<h4>Traceroutes</h4>")
        for item in through:
            path = " &rarr; ".join(escape(hop) or "*" for hop in item.hops)
            parts.append(f"<p><b>{escape(item.target)}</b> ({escape(item.reason)}"
                         f"{'' if item.reached else ', not reached'}): {path}</p>")
    return "".join(parts)


def port_html(network_map, key, port):
    escape = html.escape
    device = network_map.devices.get(key)
    hosts = network_map.hosts_by_port(key).get(port, [])
    vlans_text = vlan_port_text(vlan_info.port_info(device, port)) if device is not None else ""
    parts = [f"<h3>{escape(device.label if device else key)} {escape(port)}</h3>",
             f"<p>{escape(vlans_text[0].upper() + vlans_text[1:])}</p>" if vlans_text else "",
             f"<p>{len(hosts)} host{'' if len(hosts) == 1 else 's'}</p><table>"]
    for host in hosts:
        details = [host.ip, host.name, host.vendor or host.platform, f"VLAN {host.vlan}" if host.vlan else "",
                   "(added by hand)" if host.manual else "", host.note]
        parts.append(f"<tr><td>{escape(host.mac)}&nbsp;</td><td>"
                     f"{escape('  '.join(part for part in details if part))}</td></tr>")
    parts.append("</table>")
    return "".join(parts)
