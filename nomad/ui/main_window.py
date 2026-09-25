"""Main window: adapter picker, tabs, menus, status bar, and shared services for the tabs."""
import logging
import os
import time

from PyQt5.QtCore import QSettings, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import QAction, QActionGroup, QApplication, QComboBox, QFrame, QHBoxLayout, QLabel, QMainWindow, QMessageBox, \
    QProgressBar, QPushButton, QTabWidget, QVBoxLayout, QWidget

from .. import __version__
from ..ipconfig import flush_dns
from ..profiles import ProfileStore
from ..snapshot import NetworkSnapshot, load_snapshot
from ..system import APP_FULL_NAME, APP_NAME, is_admin, relaunch_as_admin
from .adapter_tab import AdapterTab
from .common import run_in_background
from .connections_tab import ConnectionsTab
from .dialogs import AboutDialog, LogDialog
from .iperf_tab import IperfTab
from .latency_tab import LatencyTab
from .lookup_tab import LookupTab
from .mtu_tab import MtuTab
from .neighbors_tab import NeighborsTab
from .ping_tab import PingTab
from .ports_tab import PortsTab
from .report_dialog import ReportDialog
from .routing_tab import RoutingTab
from .services_tab import ServicesTab
from .sweep_tab import SweepTab
from .switch_tab import SwitchTab
from .theme import COLORS, DEFAULT_TEXT_SCALE, TEXT_SCALES, set_text_scale
from .traceroute_tab import TracerouteTab
from .utilities_tab import UtilitiesTab

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

        self.setWindowTitle(f"{APP_NAME} {__version__} - {APP_FULL_NAME}" + (" (Administrator)" if self.admin else ""))
        self.resize(1100, 760)
        self.init_ui()
        self.init_menus()
        self.restore_settings()
        log.info("%s started (administrator: %s)", APP_NAME, self.admin)
        self.refresh()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        central = QWidget(self)
        layout = QVBoxLayout(central)

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

        # App-wide adapter picker used by the Interfaces, MTU, Ping and Sweep tabs
        picker_layout = QHBoxLayout()
        picker_layout.addWidget(QLabel("Adapter:"))
        self.adapter_combo = QComboBox(central)
        self.adapter_combo.setMinimumWidth(420)
        self.adapter_combo.setToolTip("The network adapter the Interfaces, MTU, Ping and Sweep tabs work with.")
        self.adapter_combo.currentIndexChanged.connect(self.on_adapter_selected)
        picker_layout.addWidget(self.adapter_combo, 1)
        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.setToolTip("Reload network settings (F5)")
        self.refresh_button.clicked.connect(lambda: self.refresh())
        picker_layout.addWidget(self.refresh_button)
        layout.addLayout(picker_layout)

        self.tabs = QTabWidget(central)
        self.adapter_tab = AdapterTab(self)
        self.routing_tab = RoutingTab(self)
        self.neighbors_tab = NeighborsTab(self)
        self.connections_tab = ConnectionsTab(self)
        self.mtu_tab = MtuTab(self)
        self.ping_tab = PingTab(self)
        self.latency_tab = LatencyTab(self)
        self.traceroute_tab = TracerouteTab(self)
        self.ports_tab = PortsTab(self)
        self.iperf_tab = IperfTab(self)
        self.lookup_tab = LookupTab(self)
        self.sweep_tab = SweepTab(self)
        self.switch_tab = SwitchTab(self)
        self.services_tab = ServicesTab(self)
        self.utilities_tab = UtilitiesTab(self)
        tabs = [(self.adapter_tab, "Interfaces"), (self.routing_tab, "Routing Table"), (self.neighbors_tab, "ARP"),
                (self.connections_tab, "Connections"), (self.switch_tab, "Switch Port"), (self.mtu_tab, "MTU"),
                (self.ping_tab, "Ping"), (self.latency_tab, "Latency"), (self.traceroute_tab, "Traceroute"),
                (self.ports_tab, "Ports"), (self.services_tab, "Services"), (self.iperf_tab, "iperf"),
                (self.lookup_tab, "DNS Lookup"), (self.sweep_tab, "Sweep"), (self.utilities_tab, "Utilities")]
        self.all_tabs = [tab for tab, _ in tabs]
        for tab, title in tabs:
            self.tabs.addTab(tab, title)
        self.tabs.currentChanged.connect(self.on_tab_changed)
        layout.addWidget(self.tabs, 1)
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
        file_menu.addAction("&Import Profiles...", self.adapter_tab.import_profiles)
        file_menu.addAction("&Export Profiles...", self.adapter_tab.export_profiles)
        file_menu.addSeparator()
        if not self.admin:
            file_menu.addAction("Restart as &Administrator", self.restart_as_admin)
        file_menu.addAction("E&xit", self.close)

        view_menu = self.menuBar().addMenu("&View")
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
        find_action = QAction("&Find Route", self)
        find_action.setShortcut("Ctrl+F")
        find_action.triggered.connect(self.focus_route_filter)
        tools_menu.addAction(find_action)
        tools_menu.addSeparator()
        tools_menu.addAction("&Flush DNS Cache", self.flush_dns)
        tools_menu.addSeparator()
        tools_menu.addAction("Add &PuTTY to PATH", self.sweep_tab.add_putty_to_path)
        tools_menu.addAction("Default &Browser Settings...", self.open_default_apps)
        tools_menu.addSeparator()
        tools_menu.addAction("View &Log...", self.show_log)

        help_menu = self.menuBar().addMenu("&Help")
        help_menu.addAction("&Keyboard Shortcuts", self.show_shortcuts)
        help_menu.addAction("&About", self.show_about)

    # ----------------------------------------------------------------- Settings

    def restore_settings(self):
        geometry = self.settings.value("window/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        self.saved_adapter_name = self.settings.value("window/adapter", "", str)
        self.set_text_scale(self.settings.value("view/text_scale", DEFAULT_TEXT_SCALE, float))
        self.tabs.setCurrentWidget(self.adapter_tab)  # Always start on Interfaces rather than the last tab used
        for tab in self.all_tabs:
            tab.restore_settings(self.settings)

    def save_settings(self):
        self.settings.setValue("window/geometry", self.saveGeometry())
        adapter = self.current_adapter()
        if adapter is not None:
            self.settings.setValue("window/adapter", adapter.name)
        for tab in self.all_tabs:
            tab.save_settings(self.settings)
        self.settings.sync()

    def closeEvent(self, event):
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
        """Refresh data that may have changed outside the app when switching to a tab that shows it."""
        widget = self.tabs.widget(index)
        if widget in (self.adapter_tab, self.routing_tab):
            if time.monotonic() - self.last_refresh > AUTO_REFRESH_AFTER_SECONDS:
                self.refresh()
        elif widget in (self.neighbors_tab, self.connections_tab):
            widget.refresh_if_stale()
        self.connections_tab.update_timer()  # Auto refresh only while its tab is showing

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
        """Open Wake-on-LAN on the Utilities tab with a device filled in (from the Sweep and ARP tabs)."""
        self.tabs.setCurrentWidget(self.utilities_tab)
        self.utilities_tab.wake_device(mac, name)

    def focus_route_filter(self):
        self.tabs.setCurrentWidget(self.routing_tab)
        self.routing_tab.focus_filter()

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

    def show_shortcuts(self):
        QMessageBox.information(self, "Keyboard Shortcuts",
                                "F5\tRefresh network settings\n"
                                "Ctrl+R\tRun a diagnostics report on the selected adapter\n"
                                "Ctrl+= / Ctrl+-\tLarger / smaller text (Ctrl+0 for the default size)\n"
                                "Ctrl+F\tFilter the routing table\n"
                                "Delete\tDelete the selected route (Routing Table tab)\n"
                                "Enter\tStart ping / traceroute / port scan / iperf / lookup / sweep from their "
                                "input fields")

    def show_about(self):
        AboutDialog(self).exec_()
