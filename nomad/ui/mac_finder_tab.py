"""MAC Finder page: which switch and port a MAC address (or part of one, an IP address or a name) is on.

Find searches the Network Map's last crawl (and the history of where MACs have been seen) at once, without touching
the network. Locate Now asks the map's switches over SNMP, with the map's credentials (macfind.Locator), and with
Also over SSH ticked, asks the ones that don't answer SNMP at their command line (macssh), following a MAC onto
switches beyond the map; with no map, from a switch named to start at. Every crawl of the map and every live lookup
is noted in the history (sightings.SightingLog).
"""
import csv
import datetime
import html
import ipaddress
import logging
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QApplication, QCheckBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, \
    QHBoxLayout, QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSplitter, \
    QTabWidget, QTextBrowser, QVBoxLayout, QWidget

from ..neighbors import arp_lookup
from ..netmap import macfind, macssh
from ..netmap.crawl import CrawlSettings
from ..netmap.macfind import FDB_KINDS, HISTORY, LIVE, MAC_FULL, MAC_PART, MAP, NAME, SOURCE_NAMES, Location
from ..netmap.model import NEIGHBOR, NETWORK_KINDS, SNMP, SWITCH, Device, NetworkMap, normalize_name
from ..netmap.sightings import SightingLog
from ..oui import format_mac, normalize_mac, vendor
from ..snmp import SnmpClient
from ..terminal.hostkeys import KnownHosts
from ..terminal.sessions import AUTH_PASSWORD, SSH, Session, same_host
from .common import SortableTableItem, StoppableThread, read_only_table, run_in_background, set_hint
from .credential_dialogs import CredentialPicker
from .host_menu import HostActions
from .prompts import SecretDialog
from .theme import COLORS, accent_button
from .vault_dialog import ensure_unlocked

log = logging.getLogger(__name__)

COLUMNS = ["Searched For", "MAC Address", "Vendor", "IP Address", "Name", "Switch", "Port", "VLAN", "Port Mode",
           "Seen", "From", "Note"]
(COL_QUERY, COL_MAC, COL_VENDOR, COL_IP, COL_NAME, COL_SWITCH, COL_PORT, COL_VLAN, COL_MODE, COL_SEEN, COL_SOURCE,
 COL_NOTE) = range(len(COLUMNS))
MAX_ROWS = 5000  # Shown at once (part of a MAC can match a great many)
MAX_LIST_TEXT = 200000  # Characters of the list kept in the settings
HISTORY_ROWS = 50  # Places shown in a MAC's history
DEVICE_COLUMNS = ["Switch", "Address", "SNMP", "SSH", "Logged In With", "Note"]
DEV_SWITCH, DEV_ADDRESS, DEV_SNMP, DEV_SSH, DEV_LOGIN, DEV_NOTE = range(len(DEVICE_COLUMNS))
ASK_LOGIN = "A user name and password asked for"
SSH_TIP = ("Ask switches that don't answer SNMP at their command line too (Cisco IOS, IOS XE and NX-OS show "
           "commands: nothing is changed), and when SNMP doesn't find a MAC, ask every switch again over SSH. A MAC "
           "is followed through CDP and LLDP onto switches the map doesn't have. Switches with a saved SSH session "
           "log in with it; the others with the login chosen here.")


@dataclass
class Entry:
    """A row of results: where something searched for is, or that it wasn't found (location None)."""
    index: int  # Which search
    query: macfind.Query
    location: Location = None
    problem: str = ""


def seen_text(when):
    try:
        return datetime.datetime.fromisoformat(when).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return when or ""


def history_location(sighting, query_text):
    """A history row as a Location (where it was last seen)."""
    return Location(query=query_text, mac=sighting.mac, ip=sighting.ip, name=sighting.name,
                    vendor=vendor(sighting.mac), switch=sighting.switch, switch_ip=sighting.switch_ip,
                    port=sighting.port, vlan=sighting.vlan, when=sighting.last_seen, source=HISTORY,
                    note="Not on the open map: where it was last seen.")


def map_locations(network_map):
    """Light Locations of every host on a map, for the history (no path or notes)."""
    when = network_map.finished or network_map.started
    devices = network_map.devices
    found = []
    for host in network_map.hosts:
        device = devices.get(host.device)
        if host.mac and device is not None:
            found.append(Location(query="", mac=host.mac, ip=host.ip, name=host.name, device=host.device,
                                  switch=device.label, switch_ip=device.mgmt_ip, port=host.port, vlan=host.vlan,
                                  when=when, source=MAP))
    return found


class RecordThread(StoppableThread):
    """Notes a map's hosts in the history, off the UI thread (a big map has thousands)."""

    def __init__(self, history, locations, name, parent=None):
        super().__init__(parent)
        self.history, self.locations, self.name = history, locations, name

    def run(self):
        try:
            self.history.record(self.locations, self.name)
        except (sqlite3.Error, OSError) as error:
            log.warning("Couldn't note the map's hosts in the MAC history: %s", error)


class LocateThread(StoppableThread):
    step = pyqtSignal(str)
    result = pyqtSignal(int, object, str)  # Query index, [Location], problem
    names_found = pyqtSignal(object)  # {ip: name} from reverse DNS
    device_report = pyqtSignal(object)  # macfind.DeviceReport: how asking a device went
    finished_locate = pyqtSignal(str, str)  # (message, kind)

    def __init__(self, network_map, settings, queries, hints, history, arp=None, client_factory=SnmpClient,
                 map_name="", parent=None, ssh_logins=None, vault=None, trust_new=False, start=None):
        super().__init__(parent)
        self.network_map, self.settings, self.queries, self.hints = network_map, settings, queries, hints
        self.history, self.arp, self.client_factory, self.map_name = history, arp, client_factory, map_name
        self.ssh_logins, self.vault, self.trust_new, self.start_key = ssh_logins, vault, trust_new, start
        self.shell_factory = macssh.SshShell  # Tests swap in fake switches

    def on_event(self, kind, *details):
        if kind == "step":
            log.debug("MAC Finder: %s", details[0])
            self.step.emit(details[0])
        elif kind == "result":
            self.result.emit(details[0], details[1], details[2])
        elif kind == "device":
            self.device_report.emit(details[0])

    def run(self):
        asker = None
        if self.ssh_logins is not None:
            asker = macssh.SshAsker(self.ssh_logins, self.vault, KnownHosts(), self.trust_new,
                                    lambda: self.stopping, self.shell_factory)
        locator = macfind.Locator(self.network_map, self.settings, client_factory=self.client_factory,
                                  should_stop=lambda: self.stopping, events=self.on_event, arp_lookup=self.arp,
                                  workers=self.settings.workers, ssh=asker, start=self.start_key)
        try:
            results = locator.run(self.queries, self.hints)
        except Exception as error:  # A bug shouldn't take the page down with it
            log.exception("MAC Finder: locating failed")
            self.finished_locate.emit(f"Locating failed: {error}", "error")
            return
        finally:
            if asker is not None:
                asker.close()
        found = [location for locations, _ in results.values() for location in locations]
        try:
            self.history.record(found)
        except (sqlite3.Error, OSError) as error:
            log.warning("Couldn't note the lookups in the MAC history: %s", error)
        if found and not self.stopping:
            nameless = [location.ip for location in found if location.ip and not location.name]
            if nameless:
                self.step.emit("Looking up names (reverse DNS)")
                names = macfind.reverse_names(nameless)
                if names:
                    self.names_found.emit(names)
        located = sum(1 for locations, _ in results.values() if locations)
        searched = len(self.queries)
        if self.stopping:
            message, kind = f"Stopped: {located} of {searched} found so far.", "warning"
        elif located == searched:
            message, kind = (f"Found {'it' if searched == 1 else f'all {searched}'} on the network now.",
                             "success")
        else:
            message = f"Found {located} of {searched} on the network now."
            kind = "warning" if located else "error"
        message += summary_text(list(locator.reports.values()), asker is not None)
        self.finished_locate.emit(message, kind)


def plural(count, word, many=None):
    return f"{count} {word if count == 1 else many or word + 's'}"


def summary_text(reports, ssh):
    """What asking the devices came to, for the end of the status line: how many were asked each way, and the ones
    that couldn't be (with why, for the first)."""
    failed = [report for report in reports if report.failed]
    if not ssh:
        if not failed:
            return ""
        labels = [report.name for report in failed]
        return (f" {plural(len(failed), 'device')} didn't answer SNMP: {', '.join(labels[:5])}"
                f"{'...' if len(labels) > 5 else ''}.")
    asked = [report for report in reports if report.asked]
    if not asked and not failed:
        return ""
    snmp = sum(1 for report in asked if report.snmp == macfind.ANSWERED)
    ssh_in = sum(1 for report in asked if report.ssh == macfind.LOGGED_IN)
    text = f" Asked {plural(len(asked), 'switch', 'switches')}: {snmp} over SNMP, {ssh_in} over SSH."
    refused = [report for report in reports if report.asked and report.ssh == macfind.LOGIN_FAILED]
    if refused:
        text += f" {plural(len(refused), 'SSH login')} failed ({refused[0].name}: " \
                f"{(refused[0].note or 'no reason given').rstrip('.')}). See Switches Asked."
    if failed:
        first = failed[0]
        reason = (first.note or "no answer").rstrip(".")
        text += (f" {plural(len(failed), 'switch', 'switches')} couldn't be asked ({first.name}: {reason}"
                 f"{'; and more' if len(failed) > 1 else ''}). See Switches Asked.")
    return text


class MacFinderTab(QWidget):
    def __init__(self, window, history=None):
        super().__init__(window)
        self.window = window
        self.history = history if history is not None else SightingLog()
        self.store = getattr(window, "session_store", None)  # Saved sessions and credentials, for SSH
        self.ssh_user = ""  # The user name last typed for "asked for"
        self.client_factory = SnmpClient  # Tests swap in a fake network
        self.shell_factory = None  # And fake switches' command lines (None: real SSH)
        self.worker = None
        self.recorder = None
        self.recorded = None  # What was last noted in the history from the map
        self.entries = []
        self.queries = []
        self.device_reports = {}  # Device key -> macfind.DeviceReport, from the last Locate Now
        self.last_logins = None  # The SSH logins of the last Locate Now, for Try SSH Login Again
        self.init_ui()
        page = self.map_page()
        if page is not None:
            page.map_shown.connect(self.on_map_shown)
        self.update_ssh()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Find the switch and port a device is plugged into. Enter its MAC address in any format "
                       "(aa:bb:cc:dd:ee:ff, aabb.ccdd.eeff, AA-BB-..., or no separators), part of one, an IP "
                       "address or a name. Find searches the Network Map's last crawl at once; Locate Now asks the "
                       "map's switches over SNMP (and over SSH, with Also over SSH ticked).")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        row = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("MAC address, part of one, IP address or name (several: separate "
                                             "with commas) (Ctrl+F)")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.returnPressed.connect(self.find)
        self.search_input.textChanged.connect(self.update_buttons)
        row.addWidget(self.search_input, 1)
        self.find_button = accent_button("Find")
        self.find_button.setToolTip("Search the Network Map's last crawl and the history (Enter). Doesn't touch "
                                    "the network.")
        self.find_button.clicked.connect(self.find)
        row.addWidget(self.find_button)
        self.locate_button = QPushButton("Locate Now")
        self.locate_button.setToolTip("Ask the map's switches over SNMP where it is now (Shift+Enter)")
        self.locate_button.clicked.connect(self.locate)
        row.addWidget(self.locate_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        row.addWidget(self.stop_button)
        self.list_button = QPushButton("List")
        self.list_button.setCheckable(True)
        self.list_button.setToolTip("Search for many at once: one MAC address, IP address or name per line, "
                                    "pasted or loaded from a file")
        self.list_button.toggled.connect(self.set_list_mode)
        row.addWidget(self.list_button)
        layout.addLayout(row)

        self.ssh_panel = QWidget()
        ssh_row = QHBoxLayout(self.ssh_panel)
        ssh_row.setContentsMargins(0, 0, 0, 0)
        self.ssh_check = QCheckBox("Also over SSH")
        self.ssh_check.setToolTip(SSH_TIP)
        self.ssh_check.toggled.connect(self.update_ssh)
        ssh_row.addWidget(self.ssh_check)
        self.login_label = QLabel("Log in with:")
        ssh_row.addWidget(self.login_label)
        if self.store is not None:
            default = self.store.credentials.default
            self.login_picker = CredentialPicker(self, self.store, SSH, default.id if default else "", ASK_LOGIN)
            self.login_picker.combo.setToolTip("For switches without a saved SSH session: a saved credential "
                                               "(Manage... to add one), or a user name and password asked for at "
                                               "Locate Now and kept only for that search.")
            ssh_row.addWidget(self.login_picker, 2)
        else:
            self.login_picker = None
        self.start_input = QLineEdit()
        self.start_input.setPlaceholderText("Start at switch (no map: required)")
        self.start_input.setToolTip("The switch to ask first when the map doesn't say where a MAC was: a core or "
                                    "distribution switch, by address or name. With no map open, the search starts "
                                    "here and follows the MAC from switch to switch.")
        self.start_input.textChanged.connect(self.update_buttons)
        self.start_input.textChanged.connect(self.update_map_label)
        ssh_row.addWidget(self.start_input, 1)
        self.trust_check = QCheckBox("Trust new SSH keys")
        self.trust_check.setChecked(True)
        self.trust_check.setToolTip("Log in to switches NOMAD hasn't connected to over SSH before, remembering their "
                                    "keys (as Trust and Connect does on the Terminal page). A switch whose key has "
                                    "changed is never logged into.")
        ssh_row.addWidget(self.trust_check)
        self.ssh_panel.setVisible(self.store is not None)
        layout.addWidget(self.ssh_panel)

        self.list_panel = QWidget()
        list_layout = QHBoxLayout(self.list_panel)
        list_layout.setContentsMargins(0, 0, 0, 0)
        self.list_input = QPlainTextEdit()
        self.list_input.setPlaceholderText("One per line: MAC addresses (any format), IP addresses or names. Rows "
                                           "pasted from a spreadsheet or CSV use their first MAC address.")
        self.list_input.setMaximumHeight(130)
        self.list_input.textChanged.connect(self.update_buttons)
        list_layout.addWidget(self.list_input, 1)
        list_buttons = QVBoxLayout()
        self.load_button = QPushButton("Load File...")
        self.load_button.setToolTip("Read the list from a text or CSV file")
        self.load_button.clicked.connect(self.load_list)
        list_buttons.addWidget(self.load_button)
        self.clear_list_button = QPushButton("Clear List")
        self.clear_list_button.clicked.connect(self.list_input.clear)
        list_buttons.addWidget(self.clear_list_button)
        list_buttons.addStretch()
        list_layout.addLayout(list_buttons)
        self.list_panel.setVisible(False)
        layout.addWidget(self.list_panel)

        self.map_label = QLabel()
        self.map_label.setWordWrap(True)
        layout.addWidget(self.map_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setMaximumHeight(12)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.splitter = QSplitter(Qt.Vertical)
        self.table = read_only_table(COLUMNS)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(COL_QUERY, Qt.AscendingOrder)  # In the order searched for
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_table_menu)
        self.table.itemSelectionChanged.connect(self.show_details)
        self.table.itemDoubleClicked.connect(self.on_double_click)
        self.splitter.addWidget(self.table)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.setPlaceholderText("Choose a result to see the way to it and where it's been.")
        self.devices_table = read_only_table(DEVICE_COLUMNS)
        self.devices_table.setSortingEnabled(True)
        self.devices_table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.devices_table.customContextMenuRequested.connect(self.show_devices_menu)
        self.devices_table.setToolTip("The switches Locate Now asked, and how: over SNMP, or logged into over SSH "
                                      "(and with what), or why one couldn't be asked. Right-click one to connect "
                                      "to it or try its SSH login again.")
        self.bottom_tabs = QTabWidget()
        self.bottom_tabs.addTab(self.details, "Details")
        self.bottom_tabs.addTab(self.devices_table, "Switches Asked")
        self.splitter.addWidget(self.bottom_tabs)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        layout.addWidget(self.splitter, 1)

        buttons = QHBoxLayout()
        self.copy_button = QPushButton("Copy Results")
        self.copy_button.clicked.connect(self.copy_results)
        buttons.addWidget(self.copy_button)
        self.export_button = QPushButton("Export CSV...")
        self.export_button.clicked.connect(self.export_csv)
        buttons.addWidget(self.export_button)
        buttons.addStretch()
        self.history_label = QLabel()
        buttons.addWidget(self.history_label)
        self.clear_history_button = QPushButton("Clear History...")
        self.clear_history_button.setToolTip("Forget where every MAC has been seen")
        self.clear_history_button.clicked.connect(self.clear_history)
        buttons.addWidget(self.clear_history_button)
        layout.addLayout(buttons)

    # ----------------------------------------------------------------- Tab interface

    def focus_find(self):
        target = self.list_input if self.list_button.isChecked() else self.search_input
        target.setFocus()
        if target is self.search_input:
            target.selectAll()

    def save_settings(self, settings):
        settings.setValue("macfinder/query", self.search_input.text())
        settings.setValue("macfinder/list_mode", self.list_button.isChecked())
        settings.setValue("macfinder/list", self.list_input.toPlainText()[:MAX_LIST_TEXT])
        settings.setValue("macfinder/splitter", self.splitter.saveState())
        settings.setValue("macfinder/ssh", self.ssh_check.isChecked())
        settings.setValue("macfinder/ssh_start", self.start_input.text())
        settings.setValue("macfinder/ssh_trust", self.trust_check.isChecked())
        settings.setValue("macfinder/ssh_user", self.ssh_user)
        if self.login_picker is not None:
            settings.setValue("macfinder/ssh_login", self.login_picker.credential_id())

    def restore_settings(self, settings):
        self.search_input.setText(settings.value("macfinder/query", "", str))
        self.list_input.setPlainText(settings.value("macfinder/list", "", str))
        self.list_button.setChecked(settings.value("macfinder/list_mode", False, bool))
        state = settings.value("macfinder/splitter")
        if state is not None:
            self.splitter.restoreState(state)
        self.ssh_check.setChecked(settings.value("macfinder/ssh", False, bool))
        self.start_input.setText(settings.value("macfinder/ssh_start", "", str))
        self.trust_check.setChecked(settings.value("macfinder/ssh_trust", True, bool))
        self.ssh_user = settings.value("macfinder/ssh_user", "", str)
        if self.login_picker is not None and settings.contains("macfinder/ssh_login"):
            self.login_picker.fill(settings.value("macfinder/ssh_login", "", str))
        self.update_ssh()

    def shutdown(self):
        for thread in (self.worker, self.recorder):
            if thread is not None:
                thread.stop()
                thread.wait(5000)

    def showEvent(self, event):
        super().showEvent(event)
        self.on_map_shown()
        self.update_history_label()

    # ----------------------------------------------------------------- The map

    def map_page(self):
        return getattr(self.window, "netmap_tab", None)

    def open_map(self):
        page = self.map_page()
        return getattr(page, "network_map", None) if page is not None else None

    def map_name(self):
        page = self.map_page()
        try:
            return page.map_name() if page is not None else ""
        except AttributeError:
            return ""

    def readable_switches(self, network_map):
        return [device for device in network_map.devices.values()
                if device.source == SNMP and device.mgmt_ip and device.kind in NETWORK_KINDS]

    def ssh_switches(self, network_map):
        """The map's switches (and routers) that didn't answer SNMP, which SSH can ask."""
        return [device for device in network_map.devices.values()
                if device.source != SNMP and device.mgmt_ip and device.kind in FDB_KINDS]

    def using_ssh(self):
        return self.store is not None and self.ssh_check.isChecked()

    def update_ssh(self, *_):
        on = self.using_ssh()
        for widget in (self.login_label, self.login_picker, self.start_input, self.trust_check):
            if widget is not None:
                widget.setEnabled(on)
        self.update_map_label()
        self.update_buttons()

    def update_map_label(self, *_):
        network_map = self.open_map()
        if network_map is None:
            if self.using_ssh():
                set_hint(self.map_label, "No map is open on the Network Map page: Find searches only the history "
                                         "of where MACs have been seen. Locate Now starts at the switch named in Start "
                                         "at switch and follows the MAC over SSH.", "warning")
            else:
                set_hint(self.map_label, "No map is open on the Network Map page: Find searches only the history of "
                                         "where MACs have been seen, and Locate Now needs a map (its switches and "
                                         "SNMP credentials), or Also over SSH and a switch to start at. Crawl or "
                                         "open one there first.", "warning")
            return
        when = seen_text(network_map.finished or network_map.started)
        switches = len(self.readable_switches(network_map))
        text = f"Map: {self.map_name() or 'the open map'}, crawled {when or 'at an unknown time'}: " \
               f"{len(network_map.hosts)} hosts on the ports of {switches} switches and routers read over SNMP"
        others = len(self.ssh_switches(network_map))
        if self.using_ssh() and others:
            text += f", and {others} more to ask over SSH"
        set_hint(self.map_label, text + ".", "info")

    def on_map_shown(self):
        """The Network Map page shows a map (or the same one again): note its hosts in the history once per crawl."""
        self.update_map_label()
        self.update_buttons()
        network_map = self.open_map()
        page = self.map_page()
        if network_map is None or not network_map.hosts or getattr(page, "worker", None) is not None:
            return
        identity = (self.map_name(), network_map.started, network_map.finished, len(network_map.hosts))
        if identity == self.recorded or self.recorder is not None:
            return
        self.recorded = identity
        self.recorder = RecordThread(self.history, map_locations(network_map), self.map_name(), self)
        self.recorder.finished.connect(self.on_recorded)
        self.recorder.start()

    def on_recorded(self):
        self.recorder.deleteLater()
        self.recorder = None
        self.update_history_label()

    def update_history_label(self):
        try:
            macs, _ = self.history.count()
        except (sqlite3.Error, OSError):
            macs = 0
        self.history_label.setText(f"History: {macs} MAC address{'' if macs == 1 else 'es'}" if macs else "")
        self.clear_history_button.setEnabled(bool(macs))

    # ----------------------------------------------------------------- What to search for

    def set_list_mode(self, on):
        self.list_panel.setVisible(on)
        self.search_input.setEnabled(not on)
        self.search_input.setPlaceholderText(
            "Searching the list below (turn off List to search for one)" if on else
            "MAC address, part of one, IP address or name (several: separate with commas) (Ctrl+F)")
        if on:
            self.list_input.setFocus()
        self.update_buttons()

    def read_queries(self):
        """(queries, problems) from the search box, or the list in List mode."""
        if self.list_button.isChecked():
            return macfind.parse_list(self.list_input.toPlainText())
        return macfind.parse_queries(self.search_input.text())

    def load_list(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load MAC Addresses", "",
                                              "Text and CSV files (*.txt *.csv *.tsv);;All files (*)")
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as error:
            QMessageBox.critical(self, "Load File", f"Couldn't read {path}:\n\n{error}")
            return
        self.list_input.setPlainText(text)
        queries, problems = macfind.parse_list(text)
        set_hint(self.status_label, f"Loaded {len(queries)} searches from {Path(path).name}" +
                 (f" ({len(problems)} lines skipped)." if problems else "."), "warning" if problems else "info")

    def show_problems(self, problems, searched):
        if not problems:
            return False
        text = problems[0] if len(problems) == 1 else f"{len(problems)} lines skipped: {problems[0]}"
        set_hint(self.status_label, text, "error" if not searched else "warning")
        return True

    # ----------------------------------------------------------------- Find: the map and the history

    def find(self):
        if self.worker is not None:
            return
        queries, problems = self.read_queries()
        if not queries:
            self.show_problems(problems or ["Enter a MAC address (or part of one), an IP address or a name."], 0)
            return
        network_map = self.open_map()
        snapshot = macfind.snapshot_map(network_map) if network_map is not None else None
        self.queries = queries
        self.entries = []
        on_map = in_history = 0
        for index, query in enumerate(queries):
            locations = macfind.search_map(snapshot, query) if snapshot is not None else []
            if locations:
                on_map += 1
            else:
                locations = self.history_locations(query)
                in_history += bool(locations)
            if locations:
                self.entries += [Entry(index, query, location) for location in locations]
            else:
                self.entries.append(Entry(index, query, problem=self.not_found_text(query, snapshot)))
        self.fill_table()
        searched = len(queries)
        parts = [f"{on_map} of {searched} on the map" if searched > 1 else
                 ("Found on the map" if on_map else "Not on the map")]
        if in_history:
            parts.append(f"{in_history} only in the history" if searched > 1 else "but in the history")
        text = ", ".join(parts) + "."
        if network_map is not None:
            text += f" As of the crawl on {seen_text(network_map.finished or network_map.started)}: Locate Now " \
                    "asks the switches where it is now."
        if not self.show_problems(problems, searched):
            set_hint(self.status_label, text, "success" if on_map == searched else "warning" if on_map or
                     in_history else "error")
        self.select_first()

    def history_locations(self, query):
        try:
            sightings = self.history.latest(query, limit=MAX_ROWS)
        except (sqlite3.Error, OSError) as error:
            log.warning("Couldn't read the MAC history: %s", error)
            return []
        return [history_location(sighting, query.text) for sighting in sightings]

    @staticmethod
    def not_found_text(query, network_map):
        where = "on the open map or in the history" if network_map is not None else "in the history (no map is open)"
        if query.kind == NAME:
            return f"No host named {query.text} {where}. Locate Now looks the name up in DNS and asks the switches."
        if query.kind == MAC_PART:
            return f"No MAC with {query.digits} in it {where}. Locate Now reads every switch's MAC table."
        return f"Not {where}. Locate Now asks the switches."

    # ----------------------------------------------------------------- Locate Now: the network

    def local_arp(self):
        """This computer's ARP, for addresses on its own subnets (Windows asks only those)."""
        snapshot = getattr(self.window, "snapshot", None)
        networks = []
        if snapshot is not None:
            networks = [interface.network for adapter in snapshot.real_adapters() for interface in adapter.ipv4
                        if interface.network.prefixlen < 32]

        def lookup(address):
            try:
                ip = ipaddress.ip_address(address)
            except ValueError:
                return None
            if ip.version == 4 and any(ip in network for network in networks):
                return arp_lookup(address)
            return None
        return lookup

    def locate(self):
        if self.worker is not None:
            return
        queries, problems = self.read_queries()
        if not queries:
            self.show_problems(problems or ["Enter a MAC address (or part of one), an IP address or a name."], 0)
            return
        network_map, page = self.open_map(), self.map_page()
        ssh = self.using_ssh()
        start_text = self.start_input.text().strip() if ssh else ""
        if network_map is None or page is None:
            if not start_text:
                set_hint(self.status_label, "Locate Now asks the switches of a network map: crawl or open one on the "
                                            "Network Map page first (or tick Also over SSH and name a switch to start "
                                            "at).", "error")
                return
            network_map = None
        elif not self.readable_switches(network_map) and not ssh:
            set_hint(self.status_label, "None of the map's devices answered SNMP, so there are no switches to ask. "
                                        "Check its SNMP credentials on the Network Map page and crawl again, or tick "
                                        "Also over SSH.", "error")
            return
        logins = self.ssh_logins() if ssh else None
        if ssh and logins is None:
            return
        snapshot = macfind.snapshot_map(network_map) if network_map is not None else NetworkMap()
        start = self.start_device(snapshot, start_text) if start_text else None
        settings = page.crawl_settings([]) if network_map is not None else CrawlSettings(seeds=[])
        hints = {index: macfind.search_map(snapshot, query) for index, query in enumerate(queries)}
        self.queries = queries
        self.entries = []
        for index, query in enumerate(queries):  # Where the map has each, until the network says
            if hints[index]:
                self.entries += [Entry(index, query, location) for location in hints[index]]
            else:
                self.entries.append(Entry(index, query, problem="Asking the switches..."))
        self.fill_table()
        self.worker = LocateThread(snapshot, settings, queries, hints, self.history, self.local_arp(),
                                   self.client_factory, self.map_name() if network_map is not None else "", self,
                                   ssh_logins=logins, vault=self.store.vault if ssh else None,
                                   trust_new=self.trust_check.isChecked(), start=start)
        if self.shell_factory is not None:
            self.worker.shell_factory = self.shell_factory
        self.last_logins = logins
        self.device_reports = {}
        self.fill_devices()
        self.worker.step.connect(self.on_step)
        self.worker.result.connect(self.on_result)
        self.worker.names_found.connect(self.on_names)
        self.worker.device_report.connect(self.on_device_report)
        self.worker.finished_locate.connect(self.on_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        busy = getattr(self.window, "set_busy", None)
        if busy is not None:
            busy("macfinder", "Locating MAC addresses")
        self.progress_bar.setVisible(True)
        count = len(queries)
        what = queries[0].text if count == 1 else f"{count} searches"
        set_hint(self.status_label, f"Asking the switches about {what}...", "info")
        if problems:
            self.show_problems(problems, count)
        self.update_buttons()

    def start_device(self, snapshot, text):
        """The key of the switch to start at: the map's device with that address or name, else one added for it."""
        name = normalize_name(text)
        key = next((key for key, device in snapshot.devices.items() if device.owns(text) or
                    same_host(device.mgmt_ip, text) or (name and normalize_name(device.name) == name)), None)
        if key is None:
            key = f"start:{text}"
            snapshot.devices[key] = Device(key, name="" if macfind.same_ip(text, text) else text, mgmt_ip=text,
                                           kind=SWITCH, source=NEIGHBOR)
        if snapshot.root not in snapshot.devices:
            snapshot.root = key  # Paths to what's found start there
        return key

    def ssh_logins(self):
        """How to log in to the switches for this search (macssh.SshLogins), asking what's needed now; None if
        cancelled."""
        store = self.store
        sessions = [store.credentials.apply(session.copy()) for session in store.sessions if session.protocol == SSH]
        credential = self.login_picker.credential() if self.login_picker is not None else None
        password = None
        if credential is None:
            asked = self.ask_login()
            if asked is None:
                return None
            username, password = asked
            fallback, label = Session("", username=username), f"user {username} (typed)"
        else:
            fallback = store.credentials.apply(Session("", credential_id=credential.id))
            label = f"credential {credential.name}"
            if credential.auth == AUTH_PASSWORD and not credential.saved_password:
                dialog = SecretDialog(self, "Password", f"Password for {credential.username} (the credential "
                                                       f"{credential.name}), used for this search only:", False)
                if dialog.exec_() != QDialog.Accepted:
                    return None
                password = dialog.field.text()
        secrets = any(item.saved_password or item.saved_passphrase for item in sessions + [fallback])
        if secrets and not ensure_unlocked(self, store, "MAC Finder logs in to switches with saved passwords."):
            return None
        return macssh.SshLogins(sessions, fallback, password, label)

    def ask_login(self):
        """(user name, password) to log in to switches with for one search, or None if cancelled."""
        dialog = QDialog(self)
        dialog.setWindowTitle("Log In to Switches")
        layout = QVBoxLayout(dialog)
        label = QLabel("For switches without a saved SSH session (kept only for this search):")
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        username = QLineEdit(self.ssh_user)
        password = QLineEdit()
        password.setEchoMode(QLineEdit.Password)
        form.addRow("User name:", username)
        form.addRow("Password:", password)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        (password if self.ssh_user else username).setFocus()
        if dialog.exec_() != QDialog.Accepted or not username.text().strip():
            return None
        self.ssh_user = username.text().strip()
        return self.ssh_user, password.text()

    def stop(self):
        if self.worker is not None:
            self.worker.stop()
            set_hint(self.status_label, "Stopping: finishing the requests on their way...", "warning")
            self.update_buttons()

    def on_step(self, text):
        set_hint(self.status_label, text, "info")

    def on_result(self, index, locations, problem):
        if not 0 <= index < len(self.queries):
            return
        query = self.queries[index]
        before = [entry for entry in self.entries if entry.index == index and entry.location is not None]
        rows = [Entry(index, query, location) for location in locations]
        if not rows:
            text = problem or "No switch has it in its MAC table now (a switch forgets a MAC after about 5 " \
                              "minutes without traffic from it)."
            last = before[0].location if before else None
            if last is not None:
                text += f" The map last had it on {last.switch} {last.port} ({seen_text(last.when)})."
            rows = [Entry(index, query, problem=text)]
        first = next((position for position, entry in enumerate(self.entries) if entry.index == index),
                     len(self.entries))
        self.entries = [entry for entry in self.entries if entry.index != index]
        self.entries[first:first] = rows
        self.fill_table()

    def on_device_report(self, report):
        self.device_reports[report.key] = report
        self.fill_devices()

    def fill_devices(self):
        """The Switches Asked tab: one row per device, failures first."""
        table = self.devices_table
        reports = sorted(self.device_reports.values(), key=lambda report: (not report.failed, report.name.lower()))
        table.setSortingEnabled(False)
        table.setRowCount(len(reports))
        good, bad = QColor(COLORS["success"]), QColor(COLORS["error"])
        for row, report in enumerate(reports):
            values = [report.name, report.address, report.snmp, report.ssh, report.login, report.note]
            for column, text in enumerate(values):
                item = SortableTableItem(text, None, report if column == 0 else None)
                if column == DEV_SNMP and text:
                    item.setForeground(good if text == macfind.ANSWERED else bad)
                elif column == DEV_SSH and text:
                    item.setForeground(good if text == macfind.LOGGED_IN else bad)
                elif column == DEV_NOTE and text:
                    item.setToolTip(text)
                table.setItem(row, column, item)
        table.setSortingEnabled(True)
        failed = sum(1 for report in reports if report.failed)
        title = "Switches Asked"
        if reports:
            title += f" ({len(reports)}" + (f", {failed} couldn't be" if failed else "") + ")"
        self.bottom_tabs.setTabText(1, title)

    def show_devices_menu(self, position):
        item = self.devices_table.itemAt(position)
        if item is None:
            return
        report = self.devices_table.item(item.row(), 0).data_object
        menu = QMenu(self)
        actions = {}
        if report.address:
            retry = menu.addAction("Try SSH Login Again")
            retry.setEnabled(self.worker is None and self.using_ssh())
            actions[retry] = lambda: self.try_login(report)
            connect = menu.addMenu(f"Switch: {report.name}")
            actions.update(HostActions(self.window, menu).add_to(connect, report.address, name=report.name,
                                                                 grouped=False))
        menu.addSeparator()
        actions[menu.addAction("Copy Row")] = lambda: QApplication.clipboard().setText("\t".join(
            [report.name, report.address, report.snmp, report.ssh, report.login, report.note]))
        chosen = menu.exec_(self.devices_table.viewport().mapToGlobal(position))
        menu.deleteLater()
        if chosen in actions:
            actions[chosen]()

    def try_login(self, report):
        """Log in to one switch over SSH again (after fixing its credential, say), and say how it went."""
        logins = self.ssh_logins()
        if logins is None:
            return
        set_hint(self.status_label, f"Logging in to {report.name} over SSH...", "info")
        trust, vault, factory = self.trust_check.isChecked(), self.store.vault, self.shell_factory or macssh.SshShell

        def attempt():
            asker = macssh.SshAsker(logins, vault, KnownHosts(), trust, shell_factory=factory)
            try:
                return asker.try_login(report.address, [report.name])
            finally:
                asker.close()

        run_in_background(attempt, lambda outcome: self.on_login_tried(report, outcome),
                          lambda error: self.on_login_tried(report, (False, "", str(error))))

    def on_login_tried(self, report, outcome):
        ok, login, problem = outcome
        report = macfind.DeviceReport(report.key, report.name, report.address, report.snmp,
                                      macfind.LOGGED_IN if ok else macfind.LOGIN_FAILED, login,
                                      "" if ok else problem)
        self.device_reports[report.key] = report
        self.fill_devices()
        if ok:
            set_hint(self.status_label, f"Logged in to {report.name} over SSH ({login}). Locate Now again to ask "
                                        "it.", "success")
        else:
            set_hint(self.status_label, f"{report.name}: couldn't log in over SSH: {problem}", "error")

    def on_names(self, names):
        for entry in self.entries:
            location = entry.location
            if location is not None and location.ip in names and not location.name:
                location.name = names[location.ip]
        self.fill_table()

    def on_finished(self, message, kind):
        set_hint(self.status_label, message, kind)
        log.info("MAC Finder: %s", message)

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        clear = getattr(self.window, "clear_busy", None)
        if clear is not None:
            clear("macfinder")
        self.progress_bar.setVisible(False)
        for entry in self.entries:
            if entry.location is None and entry.problem == "Asking the switches...":
                entry.problem = "Not asked (stopped)."
        self.fill_table()
        self.update_history_label()
        self.update_buttons()
        if not self.table.selectedItems():
            self.select_first()

    # ----------------------------------------------------------------- Results

    def row_values(self, entry):
        location, query = entry.location, entry.query
        if location is None:
            mac = query.mac or ""
            return [query.text, mac, vendor(mac) if mac else "", query.address, "", "", "", "", "", "", "",
                    entry.problem]
        return [location.query or query.text, location.mac, location.vendor, location.ip, location.name,
                location.switch, location.port, str(location.vlan or ""), location.mode, seen_text(location.when),
                SOURCE_NAMES.get(location.source, location.source), location.note]

    def fill_table(self):
        selected = self.selected_entry()
        table = self.table
        table.setSortingEnabled(False)
        shown = self.entries[:MAX_ROWS]
        table.setRowCount(len(shown))
        for row, entry in enumerate(shown):
            for column, text in enumerate(self.row_values(entry)):
                sort_key = None
                if column == COL_VLAN:
                    sort_key = int(text) if text else 0
                elif column == COL_IP and text:
                    try:
                        sort_key = (0, int(ipaddress.ip_address(text)))
                    except ValueError:
                        sort_key = (1, 0)
                elif column == COL_QUERY:
                    sort_key = (entry.index, text)
                item = SortableTableItem(text, sort_key, entry if column == 0 else None)
                if column == COL_NOTE and text:
                    item.setToolTip(text)
                if entry.location is None and column == COL_NOTE:
                    item.setForeground(QColor(COLORS["muted"]))
                table.setItem(row, column, item)
        table.setSortingEnabled(True)
        table.setColumnHidden(COL_QUERY, len(self.queries) <= 1)
        if len(self.entries) > MAX_ROWS:
            set_hint(self.status_label, f"Showing the first {MAX_ROWS} of {len(self.entries)} results: type more "
                                        "of the MAC address to narrow it down.", "warning")
        if selected is not None:
            for row in range(table.rowCount()):
                if table.item(row, 0).data_object is selected:
                    table.selectRow(row)
                    break
        self.update_buttons()

    def select_first(self):
        if self.table.rowCount():
            self.table.selectRow(0)
        else:
            self.details.clear()

    def selected_entry(self):
        rows = {index.row() for index in self.table.selectionModel().selectedRows()}
        if not rows:
            return None
        item = self.table.item(min(rows), 0)
        return item.data_object if item is not None else None

    def on_double_click(self, item):
        entry = self.table.item(item.row(), 0).data_object
        if entry is not None and entry.location is not None:
            self.show_on_map(entry.location)

    def show_details(self):
        entry = self.selected_entry()
        if entry is None:
            self.details.clear()
            return
        self.details.setHtml(self.details_html(entry))

    def details_html(self, entry):
        location, query = entry.location, entry.query
        escape = html.escape
        parts = []
        mac = location.mac if location is not None else query.mac
        if location is None:
            parts.append(f"<p><b>{escape(query.text)}</b>: {escape(entry.problem)}</p>")
        else:
            who = " &nbsp; ".join(escape(value) for value in (location.ip, location.name) if value)
            parts.append(f"<p><b>{escape(location.mac)}</b> &nbsp; {escape(location.vendor or 'Unknown vendor')}"
                         + (f" &nbsp; {who}" if who else "") + "</p>")
            if location.switch:
                port = f" port <b>{escape(location.port)}</b>" if location.port else ""
                described = f" ({escape(location.description)})" if location.description else ""
                vlan = f", VLAN {location.vlan}" if location.vlan else ""
                mode = f", {escape(location.mode)} port" if location.mode else ""
                address = f" ({escape(location.switch_ip)})" if location.switch_ip else ""
                parts.append(f"<p>On <b>{escape(location.switch)}</b>{address}{port}{described}{vlan}{mode}. "
                             f"{escape(SOURCE_NAMES.get(location.source, ''))}, "
                             f"{escape(seen_text(location.when))}.</p>")
            if location.note:
                parts.append(f"<p>{escape(location.note)}</p>")
            if len(location.path) > 1:
                steps = " &rarr; ".join(f"{escape(switch)} {escape(port)}".strip() for switch, port in location.path)
                parts.append(f"<p>The way there: {steps}</p>")
            if location.seen_on:
                seen = ", ".join(f"{escape(switch)} {escape(port)}" for switch, port in location.seen_on)
                parts.append(f"<p>Also in the MAC tables of: {seen} (uplinks it passes through).</p>")
        if normalize_mac(mac):
            parts.append(self.history_html(mac))
        return "".join(parts)

    def history_html(self, mac):
        escape = html.escape
        try:
            sightings = self.history.history(mac)
        except (sqlite3.Error, OSError) as error:
            return f"<p>Couldn't read the history: {escape(str(error))}</p>"
        if not sightings:
            return "<p><b>Where it's been:</b> nowhere noted yet (each crawl of the map and each Locate Now is " \
                   "noted).</p>"
        rows = []
        for sighting in sightings[:HISTORY_ROWS]:
            first, last = seen_text(sighting.first_seen), seen_text(sighting.last_seen)
            when = first if first == last else f"{first} to {last}"
            source = sighting.source.replace("map:", "Map:").replace("live", "Live")
            source = "Map" if source == "map" else source
            rows.append("<tr>" + "".join(f"<td>{escape(str(value))}&nbsp;&nbsp;</td>" for value in (
                when, sighting.switch, sighting.port, sighting.vlan or "", sighting.ip, source)) + "</tr>")
        more = f"<p>(and {len(sightings) - HISTORY_ROWS} earlier)</p>" if len(sightings) > HISTORY_ROWS else ""
        heading = "<tr>" + "".join(f"<th align='left'>{name}&nbsp;&nbsp;</th>" for name in (
            "When", "Switch", "Port", "VLAN", "IP Address", "Seen By")) + "</tr>"
        moves = len(sightings) - 1
        summary = f" ({moves} move{'s' if moves != 1 else ''})" if moves else ""
        return f"<p><b>Where it's been{summary}:</b></p><table>{heading}{''.join(rows)}</table>{more}"

    # ----------------------------------------------------------------- Actions

    def show_table_menu(self, position):
        item = self.table.itemAt(position)
        if item is None:
            return
        self.table.selectRow(item.row())
        entry = self.table.item(item.row(), 0).data_object
        location = entry.location
        mac = location.mac if location is not None else entry.query.mac
        menu = QMenu(self)
        actions = {}
        if normalize_mac(mac):
            locate = menu.addAction("Locate Now")
            locate.setEnabled(self.worker is None and self.locate_button.toolTip().startswith("Ask"))
            actions[locate] = lambda: self.locate_one(mac)
        if location is not None and location.switch:
            actions[menu.addAction("Show on Network Map")] = lambda: self.show_on_map(location)
        if location is not None and location.switch_ip:
            switch_menu = menu.addMenu(f"Switch: {location.switch}")
            actions.update(HostActions(self.window, menu).add_to(switch_menu, location.switch_ip,
                                                                 name=location.switch, grouped=False))
        menu.addSeparator()
        if normalize_mac(mac):
            actions[menu.addAction("Copy MAC Address")] = lambda: QApplication.clipboard().setText(mac)
        actions[menu.addAction("Copy Row")] = lambda: QApplication.clipboard().setText(
            "\t".join(self.row_values(entry)))
        if normalize_mac(mac):
            menu.addSeparator()
            actions[menu.addAction("Forget This MAC's History")] = lambda: self.forget_history(mac)
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        menu.deleteLater()
        if chosen in actions:
            actions[chosen]()

    def locate_one(self, mac):
        self.list_button.setChecked(False)
        self.search_input.setText(format_mac(mac))
        self.locate()

    def show_on_map(self, location):
        page, network_map = self.map_page(), self.open_map()
        if page is None or network_map is None or location.device not in network_map.devices:
            self.window.show_status(f"{location.switch} isn't on the open network map.", "info")
            return
        host = next((host for host in network_map.hosts if host.mac == location.mac and
                     host.device == location.device), None)
        self.window.navigator.setCurrentWidget(page)
        if host is not None:
            page.tabs.setCurrentWidget(page.view)
            if page.view.show_host(host):
                return
        page.show_device(location.device)

    def forget_history(self, mac):
        try:
            self.history.clear(mac)
        except (sqlite3.Error, OSError) as error:
            QMessageBox.critical(self, "MAC History", f"Couldn't change the history:\n\n{error}")
            return
        self.update_history_label()
        self.show_details()

    def clear_history(self):
        try:
            macs, _ = self.history.count()
        except (sqlite3.Error, OSError):
            macs = 0
        answer = QMessageBox.question(self, "Clear MAC History",
                                      f"Forget where all {macs} MAC addresses have been seen? The map's hosts are "
                                      "noted again the next time a map is crawled or opened.")
        if answer != QMessageBox.Yes:
            return
        try:
            self.history.clear()
        except (sqlite3.Error, OSError) as error:
            QMessageBox.critical(self, "MAC History", f"Couldn't clear the history:\n\n{error}")
            return
        self.recorded = None
        self.update_history_label()
        self.show_details()

    def visible_rows(self):
        return [[self.table.item(row, column).text() for column in range(len(COLUMNS))]
                for row in range(self.table.rowCount())]

    def copy_results(self):
        rows = self.visible_rows()
        lines = ["\t".join(COLUMNS)] + ["\t".join(row) for row in rows]
        QApplication.clipboard().setText("\n".join(lines) + "\n")
        self.window.show_status(f"Copied {len(rows)} results to the clipboard.", "info")

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export MAC Finder Results", "mac-finder-results.csv",
                                              "CSV files (*.csv);;All files (*)")
        if not path:
            return
        rows = self.visible_rows()
        try:
            with open(path, "w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(COLUMNS)
                writer.writerows(rows)
        except OSError as error:
            QMessageBox.critical(self, "Export Failed", f"Couldn't save {path}:\n\n{error}")
            return
        self.window.show_status(f"Exported {len(rows)} results to {path}.")

    def update_buttons(self, *_):
        running = self.worker is not None
        list_mode = self.list_button.isChecked()
        has_text = bool((self.list_input.toPlainText() if list_mode else self.search_input.text()).strip())
        network_map = self.open_map()
        ssh = self.using_ssh()
        can_locate = network_map is not None and bool(self.readable_switches(network_map) or (
            ssh and (self.ssh_switches(network_map) or self.start_input.text().strip())))
        can_locate = can_locate or (ssh and network_map is None and bool(self.start_input.text().strip()))
        self.find_button.setEnabled(not running and has_text)
        self.locate_button.setEnabled(not running and has_text and can_locate)
        how = "over SNMP and SSH" if ssh else "over SNMP"
        self.locate_button.setToolTip(
            f"Ask the switches {how} where it is now (Shift+Enter)" if can_locate else
            "Needs a network map with switches read over SNMP (crawl or open one on the Network Map page), or Also "
            "over SSH with a switch to start at")
        self.ssh_panel.setEnabled(not running)
        self.stop_button.setEnabled(running and not self.worker.stopping)
        self.list_button.setEnabled(not running)
        self.load_button.setEnabled(not running)
        has_rows = self.table.rowCount() > 0
        self.copy_button.setEnabled(has_rows)
        self.export_button.setEnabled(has_rows)
