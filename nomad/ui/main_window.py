"""Main window: adapter picker, sidebar of pages, menus, status bar, and shared services for the pages."""
import logging
import os
import time

from PyQt5.QtCore import QSettings, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import QAction, QActionGroup, QApplication, QComboBox, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox, \
    QProgressBar, QPushButton, QVBoxLayout, QWidget

from .. import __version__
from ..ipconfig import flush_dns
from ..profiles import ProfileStore
from ..snapshot import NetworkSnapshot, load_snapshot
from ..system import APP_FULL_NAME, APP_NAME, is_admin, relaunch_as_admin
from ..terminal.sessions import SessionFolderStore, SessionStore, TERMINAL_PROTOCOLS
from .adapter_tab import AdapterTab
from .capture_tab import CaptureTab
from .common import add_action, run_in_background
from .connections_tab import ConnectionsTab
from .dhcp_tab import DhcpTab
from .dialogs import AboutDialog, LogDialog
from .dns_servers_tab import DnsServersTab
from .iperf_tab import IperfTab
from .integration import Integration
from .inventory_tab import InventoryTab
from .ipam_tab import IpamTab
from .ip_menu import IpContextMenus
from .latency_tab import LatencyTab
from .lookup_tab import LookupTab
from .mtu_tab import MtuTab
from .navigation import Navigator
from .neighbors_tab import NeighborsTab
from .netmap_tab import NetworkMapTab
from .netreset_tab import NetworkResetTab
from .ping_tab import PingTab
from .placement_tab import PlacementTab
from .ports_tab import PortsTab
from .report_dialog import ReportDialog
from .routing_tab import RoutingTab
from .scp_tab import ScpTab
from .highlight_dialog import HighlightDialog
from .session_tabs import LAYOUTS
from .snmp_config_tab import SnmpConfigTab
from .snmp_tab import SnmpTab
from .subnet_tab import SubnetTab
from .sweep_tab import SweepTab
from .switch_tab import SwitchTab
from .mac_finder_tab import MacFinderTab
from .syslog_tab import SyslogTab
from .tftp_tab import TftpTab
from .theme import COLORS, DEFAULT_TEXT_SCALE, TEXT_SCALES, set_text_scale
from .traceroute_tab import TracerouteTab
from .terminal_tab import TerminalTab
from .rdp_tab import RdpTab
from .terminal_transfer import export_securecrt, export_terminal, import_terminal
from .vlan_tab import VlanTab
from .wake_tab import WakeTab
from .web_check_tab import WebCheckTab
from .workflow_shortcuts import install_workflow_shortcuts
from .shortcut_guide import ShortcutGuide

log = logging.getLogger(__name__)

# After a change, keep re-reading the network settings while an adapter waits for its DHCP lease
DHCP_SETTLE_SECONDS = 60
DHCP_RECHECK_MILLISECONDS = 3000

AUTO_REFRESH_AFTER_SECONDS = 3  # Refresh when switching to a tab if the data is older than this


class MainWindow(QMainWindow):
    snapshot_changed = pyqtSignal(object)  # NetworkSnapshot
    adapter_changed = pyqtSignal(object)  # Adapter or None

    def __init__(self, memory_log_handler):
        super().__init__()
        self.memory_log_handler = memory_log_handler
        self.admin = is_admin()
        self.settings = QSettings()
        self.profile_store = ProfileStore()
        self.snapshot = NetworkSnapshot()
        self.last_refresh = 0.0
        self.refreshing = False
        self.refresh_pending = False
        self.refresh_callbacks = []
        self.settle_until = 0.0  # Monotonic time until which to recheck adapters waiting for DHCP
        self.recheck_scheduled = False
        self.change_running = None  # Description of the change in progress
        self.busy_reasons = {}
        self.log_dialog = None
        self.text_scale = DEFAULT_TEXT_SCALE
        self.focus_mode = False  # Everything but the current page hidden (F11)

        self.setWindowTitle(f"{APP_NAME} {__version__} - {APP_FULL_NAME}" + (" (Administrator)" if self.admin else ""))
        self.resize(1180, 800)
        self.init_ui()
        self.ip_context_menus = IpContextMenus(self)
        self.init_menus()
        self.restore_settings()
        # Windows logging off or restarting (for updates, say) with NOMAD open: it may never get to close the window
        QApplication.instance().commitDataRequest.connect(lambda manager: self.save_settings())
        log.info("%s started (administrator: %s)", APP_NAME, self.admin)
        self.refresh()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        central = QWidget(self)
        layout = QVBoxLayout(central)
        self.central_layout = layout

        # Banner explaining read-only mode when not running as administrator
        self.admin_banner = QFrame(central)
        self.admin_banner.setStyleSheet(f"QFrame {{ background: {COLORS['warning_background']}; "
                                        f"border: 1px solid {COLORS['warning']}; }}"
                                        "QLabel { border: none; }")
        banner_layout = QHBoxLayout(self.admin_banner)
        banner_layout.setContentsMargins(8, 4, 8, 4)
        banner_label = QLabel("Running without administrator rights: you can view settings, ping, trace, sweep, "
                              "scan ports and look up names, but changing settings needs administrator rights.")
        banner_label.setWordWrap(True)
        banner_layout.addWidget(banner_label, 1)
        restart_button = QPushButton("Restart as Administrator")
        restart_button.clicked.connect(self.restart_as_admin)
        banner_layout.addWidget(restart_button)
        self.admin_banner.setVisible(not self.admin)
        layout.addWidget(self.admin_banner)

        # App-wide adapter picker used by the Interfaces, MTU, Ping, Sweep and other pages
        self.picker_bar = QWidget(central)
        picker_layout = QHBoxLayout(self.picker_bar)
        picker_layout.setContentsMargins(0, 0, 0, 0)
        picker_layout.addWidget(QLabel("Adapter:"))
        self.adapter_combo = QComboBox(central)
        self.adapter_combo.setMinimumWidth(420)
        self.adapter_combo.setToolTip("The network adapter the Interfaces, MTU, Ping, Sweep, DHCP Servers and "
                                      "other pages work with.")
        self.adapter_combo.currentIndexChanged.connect(self.on_adapter_selected)
        picker_layout.addWidget(self.adapter_combo, 1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setToolTip("Reload network settings (F5)")
        self.refresh_button.clicked.connect(lambda: self.refresh())
        picker_layout.addWidget(self.refresh_button)
        layout.addWidget(self.picker_bar)

        self.normal_margins = layout.getContentsMargins()
        self.navigator = Navigator(central)
        self.adapter_tab = AdapterTab(self)
        self.routing_tab = RoutingTab(self)
        self.neighbors_tab = NeighborsTab(self)
        self.connections_tab = ConnectionsTab(self)
        self.netreset_tab = NetworkResetTab(self)
        self.ping_tab = PingTab(self)
        self.latency_tab = LatencyTab(self)
        self.traceroute_tab = TracerouteTab(self)
        self.mtu_tab = MtuTab(self)
        self.ports_tab = PortsTab(self)
        self.iperf_tab = IperfTab(self)
        self.sweep_tab = SweepTab(self)
        self.netmap_tab = NetworkMapTab(self)
        self.switch_tab = SwitchTab(self)
        self.session_store = SessionStore()  # Shared by Terminal, SCP and RDP (and MAC Finder's SSH logins)
        self.mac_finder_tab = MacFinderTab(self)  # Searches the Network Map's crawls
        self.dhcp_tab = DhcpTab(self)
        self.snmp_tab = SnmpTab(self)
        self.lookup_tab = LookupTab(self)
        self.dns_servers_tab = DnsServersTab(self)
        self.web_check_tab = WebCheckTab(self)
        self.capture_tab = CaptureTab(self)
        self.syslog_tab = SyslogTab(self)
        self.tftp_tab = TftpTab(self)
        self.subnet_tab = SubnetTab(self)
        self.snmp_config_tab = SnmpConfigTab(self)
        self.inventory_tab = InventoryTab(self)  # The Network Map's devices and the saved sessions
        self.wake_tab = WakeTab(self)
        terminal_store = SessionFolderStore(self.session_store, TERMINAL_PROTOCOLS)
        self.terminal_tab = TerminalTab(self, terminal_store)
        self.scp_tab = ScpTab(self, terminal_store)
        self.rdp_tab = RdpTab(self, self.session_store)
        self.integration = Integration(self)  # The Manage pages and the map, as one
        self.ipam_tab = IpamTab(self)
        self.vlan_tab = VlanTab(self)  # Uses the IP Addresses page's databases and sync
        self.placement_tab = PlacementTab(self)  # Those and the Network Map's
        self.integration.connect_pages()
        sections = [
            ("This Computer", [(self.adapter_tab, "Interfaces"), (self.routing_tab, "Routing Table"),
                               (self.neighbors_tab, "ARP"), (self.connections_tab, "Connections"),
                               (self.netreset_tab, "Network Reset")]),
            ("Connect & Transfer", [(self.terminal_tab, "Terminal"), (self.scp_tab, "SCP"), (self.rdp_tab, "RDP"),
                                    (self.tftp_tab, "TFTP"), (self.wake_tab, "Wake-on-LAN")]),
            ("Discover", [(self.sweep_tab, "Sweep"), (self.switch_tab, "Switch Port"),
                          (self.mac_finder_tab, "MAC Finder"),
                          (self.dhcp_tab, "DHCP Servers"), (self.snmp_tab, "SNMP Walk")]),
            ("Diagnostics: Connectivity & Performance", [(self.ping_tab, "Ping"), (self.latency_tab, "Latency"),
                (self.traceroute_tab, "Traceroute"), (self.mtu_tab, "MTU"), (self.ports_tab, "Ports"),
                (self.iperf_tab, "iperf")]),
            ("Diagnostics: DNS & Web", [(self.lookup_tab, "DNS Lookup"), (self.dns_servers_tab, "DNS Servers"),
                                      (self.web_check_tab, "Web Check")]),
            ("Network Management", [(self.netmap_tab, "Network Map"), (self.ipam_tab, "IP Addresses"),
                (self.vlan_tab, "VLANs"), (self.placement_tab, "Subnet Placement"),
                (self.snmp_config_tab, "SNMP Config"), (self.inventory_tab, "Ansible Inventory")]),
            ("Capture & Logs", [(self.capture_tab, "Packet Capture"), (self.syslog_tab, "Syslog")]),
            ("Utilities", [(self.subnet_tab, "Subnet Calculator")]),
        ]
        self.all_tabs = []
        for section, pages in sections:
            self.navigator.add_section(section)
            for page, title in pages:
                self.navigator.add_page(page, title)
                self.all_tabs.append(page)
        self.navigator.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.navigator, 1)
        self.setCentralWidget(central)

        # Status bar: messages on the left, busy indicator and log button on the right
        self.busy_label = QLabel()
        self.busy_bar = QProgressBar()
        self.busy_bar.setRange(0, 0)  # Indeterminate
        self.busy_bar.setMaximumWidth(120)
        self.busy_bar.setMaximumHeight(14)
        log_button = QPushButton("View Log")
        log_button.setFlat(True)
        log_button.clicked.connect(self.show_log)
        self.statusBar().addPermanentWidget(self.busy_label)
        self.statusBar().addPermanentWidget(self.busy_bar)
        self.statusBar().addPermanentWidget(log_button)
        self.update_busy_indicator()

    def init_menus(self):
        file_menu = self.menuBar().addMenu("&File")
        file_menu.addAction("&Import Interface Profiles...", self.adapter_tab.import_profiles)
        file_menu.addAction("&Export Interface Profiles...", self.adapter_tab.export_profiles)
        file_menu.addSeparator()
        file_menu.addAction("Import Sessions from &PuTTY",
                            lambda: self.show_terminal(self.terminal_tab.manager.import_from_putty))
        file_menu.addAction("Import Sessions from &SecureCRT...",
                            lambda: self.show_terminal(self.terminal_tab.manager.import_from_securecrt))
        file_menu.addAction("Export SSH Sessions to SecureCRT...", lambda: export_securecrt(self))
        file_menu.addSeparator()
        file_menu.addAction("Export NOMAD Terminal Settings and Sessions...", lambda: export_terminal(self))
        file_menu.addAction("Import NOMAD Terminal Settings and Sessions...", lambda: import_terminal(self))
        file_menu.addSeparator()
        if not self.admin:
            file_menu.addAction("Restart as &Administrator", self.restart_as_admin)
        file_menu.addAction("E&xit", self.close)

        edit_menu = self.menuBar().addMenu("&Edit")
        edit_menu.addAction("New &Session...", lambda: self.show_terminal(
            lambda: self.terminal_tab.manager.new_session(self.terminal_tab.manager.selected_folder())))
        edit_menu.addAction("New &Folder...", lambda: self.show_terminal(
            lambda: self.terminal_tab.manager.new_folder(self.terminal_tab.manager.selected_folder())))
        edit_menu.addSeparator()
        edit_menu.addAction("Clear &Recent Connections", self.terminal_tab.manager.clear_recent)

        view_menu = self.menuBar().addMenu("&View")
        self.sidebar_action = QAction("Keep Tool &Drawer Open", self)
        self.sidebar_action.setCheckable(True)
        self.sidebar_action.setChecked(False)
        self.sidebar_action.setShortcut("Ctrl+B")
        self.sidebar_action.triggered.connect(self.navigator.set_sidebar_visible)
        self.navigator.sidebarToggled.connect(self.on_sidebar_toggled)
        view_menu.addAction(self.sidebar_action)
        self.addAction(self.sidebar_action)  # Ctrl+B works even while the menu is closed
        self.focus_action = QAction("&Focus Mode", self)
        self.focus_action.setCheckable(True)
        self.focus_action.setShortcut("F11")
        self.focus_action.setToolTip("Hide the sidebar, adapter bar and status bar so the page (such as a terminal "
                                     "session) gets the whole window")
        self.focus_action.triggered.connect(self.set_focus_mode)
        view_menu.addAction(self.focus_action)
        self.addAction(self.focus_action)
        # Also beside the Terminal page's tabs; here too so it can always be reached
        layout_menu = view_menu.addMenu("Terminal &Layout")
        layout_group = QActionGroup(self)
        for key, label, _, _ in LAYOUTS:
            action = layout_menu.addAction(label, lambda key=key: self.set_terminal_layout(key))
            action.setCheckable(True)
            action.setData(key)
            layout_group.addAction(action)
        layout_menu.aboutToShow.connect(lambda: [action.setChecked(action.data() == self.terminal_tab.tabs.layout_key)
                                                 for action in layout_group.actions()])
        self.buttons_action = add_action(view_menu, "Terminal Command &Buttons", self.toggle_command_buttons)
        self.buttons_action.setCheckable(True)
        self.highlight_action = add_action(
            view_menu, "&Highlight Terminal Keywords", lambda checked: self.terminal_tab.highlights.set_enabled(checked))
        self.highlight_action.setCheckable(True)
        view_menu.addAction("Terminal &Keyword Highlighting...",
                            lambda: HighlightDialog(self, self.terminal_tab.highlights).exec_())
        view_menu.aboutToShow.connect(self.update_terminal_actions)
        bar_menu = view_menu.addMenu("Network Map &Top Bar")
        bar_group = QActionGroup(self)
        for compact, label in ((True, "&Compact"), (False, "C&lassic")):
            action = bar_menu.addAction(label, lambda compact=compact: self.netmap_tab.set_compact_top(compact))
            action.setCheckable(True)
            action.setData(compact)
            bar_group.addAction(action)
        bar_menu.aboutToShow.connect(lambda: [action.setChecked(action.data() == self.netmap_tab.compact_top)
                                              for action in bar_group.actions()])
        view_menu.addSeparator()
        text_menu = view_menu.addMenu("&Text Size")
        self.text_scale_group = QActionGroup(self)
        for scale, label in TEXT_SCALES:
            action = text_menu.addAction(label, lambda scale=scale: self.set_text_scale(scale))
            action.setCheckable(True)
            action.setData(scale)
            self.text_scale_group.addAction(action)
        text_menu.addSeparator()
        for label, shortcuts, step in (("&Larger Text", ["Ctrl+=", "Ctrl++"], 1), ("&Smaller Text", ["Ctrl+-"], -1),
                                       ("&Default Size", ["Ctrl+0"], 0)):
            action = QAction(label, self)
            action.setShortcuts(shortcuts)
            action.triggered.connect(lambda _, step=step: self.step_text_scale(step))
            text_menu.addAction(action)
            self.addAction(action)  # Shortcuts work even while the menu is closed

        tools_menu = self.menuBar().addMenu("&Tools")
        report_action = QAction("Run &Diagnostics Report...", self)
        report_action.setShortcut("Ctrl+R")
        report_action.triggered.connect(self.show_report)
        tools_menu.addAction(report_action)
        tools_menu.addSeparator()
        refresh_action = QAction("&Refresh", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(lambda: self.refresh())
        tools_menu.addAction(refresh_action)
        find_action = QAction("&Find on This Page", self)
        find_action.setShortcut("Ctrl+F")
        find_action.setToolTip("Focus the current page's main input, search or filter")
        find_action.triggered.connect(self.focus_find)
        tools_menu.addAction(find_action)
        install_workflow_shortcuts(self)
        tools_menu.addSeparator()
        tools_menu.addAction("&Flush DNS Cache", self.flush_dns)
        tools_menu.addAction("Saved Password &Protection...", lambda: self.terminal_tab.manager.show_protection())
        tools_menu.addAction("Saved &Credentials...", lambda: self.terminal_tab.manager.show_credentials())
        tools_menu.addAction("&Tribe Management...", self.show_tribe_management)
        tools_menu.addAction("&Map Watcher Service...", self.show_map_watcher)
        tools_menu.addSeparator()
        tools_menu.addAction("Add &PuTTY to PATH", self.sweep_tab.add_putty_to_path)
        tools_menu.addAction("Default &Browser Settings...", self.open_default_apps)
        tools_menu.addSeparator()
        tools_menu.addAction("View &Log...", self.show_log)

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("&Keyboard Shortcuts", self.show_shortcuts)
        help_menu.addAction("&About", self.show_about)

    def show_terminal(self, then):
        """Switch to the Terminal page, then do something there (so what it adds is on screen)."""
        self.navigator.setCurrentWidget(self.terminal_tab)
        then()

    def show_snmp_config(self, destination="", credential=None, from_map=False):
        """The SNMP Config page, sending traps and syslog to destination, with credential or (from_map) the Network
        Map's credentials."""
        self.navigator.setCurrentWidget(self.snmp_config_tab)
        self.snmp_config_tab.prefill(destination, credential, from_map)

    # ----------------------------------------------------------------- Settings

    def restore_settings(self):
        geometry = self.settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        self.saved_adapter_name = self.settings.value("window/adapter", "", str)
        self.set_text_scale(self.settings.value("view/text_scale", DEFAULT_TEXT_SCALE, float))
        self.navigator.restore_settings(self.settings)
        self.navigator.setCurrentWidget(self.adapter_tab)  # Always start on Interfaces rather than the last tab used
        for tab in self.all_tabs:
            tab.restore_settings(self.settings)

    def save_settings(self):
        self.settings.setValue("window/geometry", self.saveGeometry())
        self.navigator.save_settings(self.settings)
        adapter = self.current_adapter()
        if adapter is not None:
            self.settings.setValue("window/adapter", adapter.name)
        for tab in self.all_tabs:
            tab.save_settings(self.settings)
        self.settings.sync()

    def closeEvent(self, event):
        if not self.terminal_tab.confirm_close() or not self.scp_tab.confirm_close():
            event.ignore()
            return
        self.save_settings()
        for tab in self.all_tabs:
            tab.shutdown()
        super().closeEvent(event)

    # ----------------------------------------------------------------- Text size

    def set_text_scale(self, scale):
        """Change the size of all text (saved for next time)."""
        scales = [choice for choice, _ in TEXT_SCALES]
        scale = min(scales, key=lambda choice: abs(choice - scale))  # Settings may hold an old or edited value
        self.text_scale = scale
        set_text_scale(QApplication.instance(), scale)
        for action in self.text_scale_group.actions():
            action.setChecked(action.data() == scale)
        self.settings.setValue("view/text_scale", scale)

    def step_text_scale(self, step):
        """Go one size larger (step 1) or smaller (-1), or back to the default (0)."""
        scales = [choice for choice, _ in TEXT_SCALES]
        if step == 0:
            self.set_text_scale(DEFAULT_TEXT_SCALE)
        else:
            index = scales.index(self.text_scale) + step
            self.set_text_scale(scales[max(0, min(len(scales) - 1, index))])

    def set_focus_mode(self, on):
        """Give the current page the whole window: no sidebar, adapter bar, banner, status bar or session list."""
        on = bool(on)
        self.focus_action.setChecked(on)
        for page in (self.terminal_tab, self.scp_tab):
            page.focus_button.setChecked(on)
        if on == self.focus_mode:
            return
        self.focus_mode = on
        self.navigator.set_navigation_hidden(on)
        self.picker_bar.setVisible(not on)
        self.admin_banner.setVisible(not on and not self.admin)
        self.statusBar().setVisible(not on)
        self.central_layout.setContentsMargins(*((0, 0, 0, 0) if on else self.normal_margins))
        for page in (self.terminal_tab, self.scp_tab):
            if on:
                page.set_manager_visible(False, remember=False)
            else:
                page.show_page(page.stack.currentIndex())
        if on:
            self.show_status("Focus mode: press F11 to bring everything back.", "info")

    def update_terminal_actions(self):
        tabs = self.terminal_tab.tabs
        self.buttons_action.setChecked(tabs.command_bar is not None and tabs.command_bar.isVisibleTo(tabs))
        self.highlight_action.setChecked(self.terminal_tab.highlights.enabled)

    def toggle_command_buttons(self, visible):
        self.terminal_tab.tabs.show_command_bar(visible)
        self.navigator.setCurrentWidget(self.terminal_tab)

    def set_terminal_layout(self, key):
        self.terminal_tab.tabs.set_layout(key)
        self.navigator.setCurrentWidget(self.terminal_tab)

    def on_sidebar_toggled(self, visible):
        self.sidebar_action.setChecked(visible)
        self.settings.setValue("view/sidebar", visible)

    # ----------------------------------------------------------------- Snapshot and adapter picker

    def refresh(self, then=None):
        """Reload the network snapshot in the background, then call then() (if given)."""
        if then is not None:
            self.refresh_callbacks.append(then)
        if self.refreshing:
            self.refresh_pending = True
            return
        self.refreshing = True
        self.set_busy("refresh", "Reading network settings")
        run_in_background(load_snapshot, self.on_snapshot_loaded, self.on_snapshot_failed)

    def on_snapshot_loaded(self, snapshot):
        self.refreshing = False
        self.clear_busy("refresh")
        if self.refresh_pending:  # Something changed while loading; load again before notifying
            self.refresh_pending = False
            self.refresh()
            return
        self.snapshot = snapshot
        self.last_refresh = time.monotonic()
        self.update_adapter_picker()
        self.snapshot_changed.emit(snapshot)
        self.run_refresh_callbacks()
        self.schedule_dhcp_recheck()

    def schedule_dhcp_recheck(self):
        """Windows gets a DHCP lease a few seconds after the change that asked for it, so look again shortly."""
        if self.recheck_scheduled or time.monotonic() > self.settle_until:
            return
        if any(adapter.awaiting_dhcp for adapter in self.snapshot.real_adapters()):
            self.recheck_scheduled = True
            QTimer.singleShot(DHCP_RECHECK_MILLISECONDS, self.dhcp_recheck)

    def dhcp_recheck(self):
        self.recheck_scheduled = False
        self.refresh()

    def on_snapshot_failed(self, error):
        self.refreshing = False
        self.clear_busy("refresh")
        self.refresh_pending = False
        self.show_status(f"Couldn't read network settings: {error}", "error")
        self.run_refresh_callbacks()

    def run_refresh_callbacks(self):
        callbacks, self.refresh_callbacks = self.refresh_callbacks, []
        for callback in callbacks:
            callback()

    def update_adapter_picker(self):
        combo = self.adapter_combo
        previous = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        for adapter in self.snapshot.real_adapters():
            combo.addItem(adapter.picker_label(), adapter.index)
            combo.setItemData(combo.count() - 1, adapter.description, Qt.ToolTipRole)
        index = combo.findData(previous) if previous is not None else -1
        if index < 0 and self.saved_adapter_name:
            saved = self.snapshot.adapter_by_name(self.saved_adapter_name)
            index = combo.findData(saved.index) if saved else -1
        combo.setCurrentIndex(max(index, 0) if combo.count() else -1)
        combo.blockSignals(False)
        if combo.currentData() != previous:
            self.adapter_changed.emit(self.current_adapter())

    def on_adapter_selected(self):
        adapter = self.current_adapter()
        if adapter is not None:
            self.saved_adapter_name = adapter.name
        self.adapter_changed.emit(adapter)

    def current_adapter(self):
        return self.snapshot.adapters.get(self.adapter_combo.currentData())

    def on_tab_changed(self, index):
        """Refresh data that may have changed outside the app when switching to a page that shows it."""
        widget = self.navigator.widget(index)
        if widget in (self.adapter_tab, self.routing_tab):
            if time.monotonic() - self.last_refresh > AUTO_REFRESH_AFTER_SECONDS:
                self.refresh()
        elif widget in (self.neighbors_tab, self.connections_tab, self.netreset_tab):
            widget.refresh_if_stale()
        self.connections_tab.update_timer()  # Auto refresh only while its page is showing

    # ----------------------------------------------------------------- Changes, admin and status

    def require_admin(self, action):
        """Return True if running as administrator; otherwise offer to restart elevated."""
        if self.admin:
            return True
        reply = QMessageBox.question(
            self, "Administrator Rights Needed",
            f"{action} needs administrator rights.\n\nRestart {APP_NAME} as administrator now? "
            "Your window layout and inputs will be kept.",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
        if reply == QMessageBox.Yes:
            self.restart_as_admin()
        return False

    def show_tribe_management(self):
        from .tribe_dialog import TribeDialog  # Loads pywin32 only when it's needed
        TribeDialog(self).exec_()

    def tribe_key_changed(self, origin=None):
        """A page saved or forgot the tribe key: the other pages that use the tribe start again with it."""
        if origin is not self.netmap_tab:
            self.netmap_tab.tribe_key_changed()
        if origin is not self.ipam_tab and self.ipam_tab.local_store is not None:  # Opened: else it's read later
            self.ipam_tab.connect_team()

    def confirm_leave_tribe(self, parent):
        """Ask, then stop using the tribe on this computer, showing the steps (Tools > Tribe Management is the one
        place to leave). Returns whether it left."""
        from .tribe_leave_dialog import disconnect_from_tribe
        return disconnect_from_tribe(parent, self)

    def show_map_watcher(self):
        from .watch_service_dialog import MapWatcherDialog  # Loads pywin32 only when it's needed
        MapWatcherDialog(self).exec_()

    def restart_as_admin(self):
        self.save_settings()
        if relaunch_as_admin():
            for tab in self.all_tabs:
                tab.shutdown()
            self.hide()
            QApplication.quit()
        else:
            self.show_status("Restarting as administrator was cancelled.", "warning")

    def run_change(self, description, function, on_success=None, on_error=None, needs_admin=True):
        """Run a system change in the background, then refresh the snapshot.

        on_success(result) runs after the refresh, so tabs see the new state. Errors go to
        on_error(exception) if given, otherwise to an error dialog. Returns False if not started.
        """
        if needs_admin and not self.require_admin(description):
            return False
        if self.change_running:
            QMessageBox.information(self, "Please Wait", f"Wait for \"{self.change_running}\" to finish first.")
            return False
        self.change_running = description
        self.set_busy("change", description)
        log.info("Starting: %s", description)

        def succeeded(result):
            self.change_running = None
            self.clear_busy("change")
            log.info("Finished: %s", description)
            self.settle_until = time.monotonic() + DHCP_SETTLE_SECONDS
            self.refresh(then=(lambda: on_success(result)) if on_success else None)

        def failed(error):
            self.change_running = None
            self.clear_busy("change")
            log.error("%s failed: %s", description, error)
            self.settle_until = time.monotonic() + DHCP_SETTLE_SECONDS
            self.refresh()
            if on_error:
                on_error(error)
            else:
                QMessageBox.critical(self, "Error", f"{description} failed:\n\n{error}")

        run_in_background(function, succeeded, failed)
        return True

    def set_busy(self, key, text):
        self.busy_reasons[key] = text
        self.update_busy_indicator()

    def clear_busy(self, key):
        self.busy_reasons.pop(key, None)
        self.update_busy_indicator()

    def update_busy_indicator(self):
        busy = bool(self.busy_reasons)
        self.busy_bar.setVisible(busy)
        self.busy_label.setText(" · ".join(self.busy_reasons.values()) + "..." if busy else "")
        self.refresh_button.setEnabled(not self.refreshing)

    def show_status(self, message, kind="success", timeout=10000):
        colors = {"success": COLORS["success"], "error": COLORS["error"], "warning": COLORS["warning"], "info": ""}
        self.statusBar().setStyleSheet(f"QStatusBar {{ color: {colors.get(kind, '')}; }}")
        self.statusBar().showMessage(message, timeout)
        log.info("Status: %s", message)

    # ----------------------------------------------------------------- Menu actions

    def flush_dns(self):
        self.run_change("Flushing the DNS cache", flush_dns,
                        on_success=lambda _: self.show_status("DNS cache flushed."))

    def show_report(self):
        adapter = self.current_adapter()
        if adapter is None:
            QMessageBox.information(self, "Diagnostics Report", "Choose an adapter to check first.")
            return
        ReportDialog(self, adapter).exec_()

    def wake_device(self, mac, name=""):
        """Open the Wake-on-LAN tab with a device filled in (from the Sweep and ARP tabs)."""
        self.navigator.setCurrentWidget(self.wake_tab)
        self.wake_tab.wake_device(mac, name)

    def focus_find(self):
        """Ctrl+F: the current page's search, filter or primary input."""
        page = self.navigator.currentWidget()
        if hasattr(page, "focus_find"):
            page.focus_find()
        else:
            self.show_status("This page has nothing to search.", "info", 3000)

    def show_log(self):
        if self.log_dialog is None or not self.log_dialog.isVisible():
            self.log_dialog = LogDialog(self, self.memory_log_handler)
        self.log_dialog.show()
        self.log_dialog.raise_()
        self.log_dialog.activateWindow()

    def open_default_apps(self):
        """Windows Settings page for choosing the browser that the Sweep tab's Open in Browser uses."""
        try:
            os.startfile("ms-settings:defaultapps")
        except OSError as error:
            QMessageBox.critical(self, "Default Apps", f"Couldn't open Windows Default Apps settings:\n\n{error}")

    def show_shortcuts(self, page_title=None):
        if getattr(self, "shortcut_guide", None) is None:
            self.shortcut_guide = ShortcutGuide(self)
        if not isinstance(page_title, str):
            page_title = self.navigator.title(self.navigator.currentWidget())
        self.shortcut_guide.show_for_page(page_title)

    def show_about(self):
        AboutDialog(self).exec_()
