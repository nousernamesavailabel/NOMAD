"""IPAM page: each network's subnets and addresses, what's used, reserved and free, with import from the tribe's
addressing spreadsheets.

Networks come from two places: this computer's own database (Local), and the tribe's, shared by the NOMAD IPAM server
(Tribe). A laptop connects to the server with the tribe key file; it keeps a copy of the tribe's data, synced at start,
every few minutes and on Sync Now, so it can look everything up offline, and sends its changes straight to the
server while it can reach it. On the server itself, NOMAD running as administrator manages the server's data
directly (Server admin): only there can spreadsheets be imported and tribe networks added or deleted.
"""
import csv
import ipaddress
import logging
import os
import threading
import time

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QObject, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QHBoxLayout, \
    QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QProgressBar, QPushButton, QSplitter, QStackedWidget, QTableView, \
    QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ..ipam.history import network_as_of
from ..ipam.client import OldServerError, ServerUnreachable, TeamKeyError, TeamStore, admin_key, \
    load_saved_key
from ..ipam.server import ConflictError, server_dir
from ..ipam.spreadsheet import SpreadsheetError, parse_page, read_pages
from ..ipam.store import ANYWHERE, DESCRIPTION, MAC, NAME, RESERVED, STATUSES, USED, VALUE, IpamError, IpamStore, \
    Subnet
from ..ipam.vlan_team import TeamVlanStore
from ..oui import normalize_mac
from ..sweep import SWEEP_PASSES
from ..system import log_dir
from .common import SortableTableItem, add_action, run_in_background, set_hint
from .integration import MAP_DEVICE, MAP_SUBNET, PLACEMENT, VLAN, hub, link
from .host_menu import HostActions
from .ipam_dialogs import AddressDialog, ImportDialog, NetworkDialog, SubnetDialog
from .ipam_tools import BulkAddressDialog, BulkSubnetDialog, CheckDataDialog, CompareDialog, FreeBlocksDialog, \
    apply_to_addresses, apply_to_subnets
from .theme import COLORS, accent_button
from .tribe_join_dialog import connect_to_tribe

log = logging.getLogger(__name__)

ADDRESS_COLUMNS = ["Address", "Status", "Last Seen", "Name", "MAC Address", "Description", "Last Changed",
                   "On Map"]
COL_SWEEP = 2
COL_MAP = 7  # Only shown while a map of the network is open (on screen only: exports don't use this table)
RESULT_COLUMNS = ["Network", "Subnet", "Subnet Name", "Address", "Status", "Name", "Details", "Description"]
SEARCH_MATCHES = [("Any field", ANYWHERE), ("Address or subnet", VALUE), ("Name", NAME),
                  ("Description", DESCRIPTION), ("MAC address", MAC)]  # Then each detail, such as Telephony Rng
SEARCH_KINDS = [("Everything", {}), ("Subnets", {"addresses": False}), ("Addresses", {"subnets": False}),
                ("Used addresses", {"subnets": False, "status": USED}),
                ("Reserved addresses", {"subnets": False, "status": RESERVED})]  # (label, IpamStore.search options)
LIST_EVERY_ADDRESS_UP_TO = 65536  # Larger subnets list only the addresses in use (a /16 is still listed in full)
UNSUBNETTED = "unsubnetted"
FREE = "Free"
LOCAL, TEAM = "local", "team"
SYNC_EVERY_MS = 5 * 60 * 1000  # A fallback: the watcher normally syncs the moment anything changes
WAIT_SECONDS = 25  # How long each wait at the server lasts before it's renewed
RETRY_SECONDS = 15  # After losing the server, how soon to try again
POLL_SECONDS = 30  # How often to check an older server (without instant sync) for changes
STATUS_REFRESH_MS = 30 * 1000
ADMIN_COPY_FILE = "ipam-server-admin.db"
OFFLINE_NOTE = "The IPAM server can't be reached. You can still assign, edit and free addresses: they're kept as " \
               "pending and sent when it's back. Subnets and networks can only be changed online."


class ServerWatcher(QObject):
    """Keeps a request waiting at the IPAM server on a background thread, so this laptop hears about every change
    the moment it's made (anyone's), and notices quickly when the server goes away or comes back."""
    changed = pyqtSignal(int)  # The server's new revision
    reachability = pyqtSignal(bool, str)  # (reachable, why not)
    rejected = pyqtSignal(str)  # The server refused the tribe key
    outdated = pyqtSignal()  # The server is an older NOMAD without instant sync: it's checked every 30 s instead

    def __init__(self, client, revision, sightings=None, parent=None):
        super().__init__(parent)
        self.client, self.revision, self.sightings = client, revision, sightings
        self.stopping = threading.Event()
        self.thread = threading.Thread(target=self.run, name="IPAM server watcher", daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.stopping.set()  # The thread ends when its current wait returns (it's a daemon, so it never delays exit)

    def run(self):
        polling = False
        confirmed = False  # Whether the server has answered since starting (or since it was last unreachable)
        while not self.stopping.is_set():
            try:
                if not confirmed:
                    # A quick check first, so being back online shows at once rather than after a whole wait
                    status = self.client.status()
                    revision, sightings = status["revision"], status.get("sightings")
                    confirmed = True
                elif polling:
                    self.stopping.wait(POLL_SECONDS)
                    status = self.client.status()
                    revision, sightings = status["revision"], status.get("sightings")
                else:
                    revision, sightings = self.client.wait(self.revision, WAIT_SECONDS, self.sightings)
            except OldServerError:
                polling = True
                self.outdated.emit()
                continue
            except TeamKeyError as error:
                if not self.stopping.is_set():
                    self.rejected.emit(str(error))
                self.stopping.wait(60)
                continue
            except ServerUnreachable as error:  # Only this means the server can't be reached
                confirmed = False
                self.emit_reachability(False, str(error))
                self.stopping.wait(RETRY_SECONDS)
                continue
            except IpamError as error:  # The server answered, but with a problem: it's still there
                log.info("IPAM server watcher: %s", error)
                self.stopping.wait(RETRY_SECONDS)
                continue
            self.emit_reachability(True, "")
            new_sightings = sightings is not None and self.sightings is not None and sightings > self.sightings
            if (revision > self.revision or new_sightings) and not self.stopping.is_set():
                self.revision = max(self.revision, revision)
                if sightings is not None and self.sightings is not None:
                    self.sightings = max(self.sightings, sightings)
                self.changed.emit(revision)

    def emit_reachability(self, reachable, reason):
        if not self.stopping.is_set():
            self.reachability.emit(reachable, reason)


def ago(seconds):
    """"just now", "4 min ago", "3 h ago", "2 days ago"."""
    if seconds < 60:
        return "just now"
    if seconds < 3600:
        return f"{int(seconds // 60)} min ago"
    if seconds < 172800:
        return f"{int(seconds // 3600)} h ago"
    return f"{int(seconds // 86400)} days ago"


def usable_count(network, loopbacks=False):
    """Addresses that can be handed out: all but the network and broadcast (first and last) addresses, or every one
    in a loopback subnet."""
    if not loopbacks and network.version == 4 and network.num_addresses > 2:
        return network.num_addresses - 2
    return network.num_addresses


class AddressModel(QAbstractTableModel):
    """The addresses of one subnet: every address (free ones too) or just the ones in use, without building a row
    object per address, so even a /16 lists instantly."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.network = None
        self.recorded = {}  # {address: Address}
        self.special = {}  # {address: "Network" / "Broadcast" / "Gateway"}
        self.nested = []  # [(Block, name)] subnets inside this one
        self.rows = None  # [address] when not listing every address
        self.first = 0
        self.pending = set()  # Addresses (as text) with a change waiting to be sent to the IPAM server
        self.sweep = None  # SweepResults for this network (what sweeps found, kept)
        self.places_from = None  # Integration.map_places: the open map's addresses, or None without a map
        self.places = {}  # {address: integration.MapPlace} of this subnet's addresses on the map

    def load(self, network, recorded, special, nested, every_address, pending=(), sweep=None, places=None):
        self.beginResetModel()
        self.network, self.recorded, self.special, self.nested = network, recorded, special, nested
        self.pending = set(pending)
        self.sweep = sweep
        self.places_from, self.places = places, self.places_here(places)
        self.first = int(network.network_address) if network is not None else 0
        if network is not None and every_address:
            self.rows = None
        else:
            # Free addresses where the sweep found something stay listed: they're what needs recording
            answered = {address for address in sweep.hosts if network is not None and address in network}                 if sweep is not None else set()
            self.rows = sorted(set(recorded) | set(special) | answered | set(self.places))  # And what the map has
        self.endResetModel()

    def places_here(self, places):
        """{address: MapPlace} of the map's addresses in this subnet (or, outside every subnet, those recorded)."""
        found = {}
        for ip, place in (places or {}).items():
            address = ipaddress.ip_address(ip)
            if (address in self.network) if self.network is not None else (address in self.recorded):
                found[address] = place
        return found

    def set_places(self, places):
        """The map changed: show where it has each address. False when that would change the rows listed (only
        the addresses in use are, and the map has others now): the caller loads the subnet again."""
        here = self.places_here(places)
        if self.rows is not None and not set(here) <= set(self.rows):
            return False
        self.places_from, self.places = places, here
        if self.rowCount():
            self.dataChanged.emit(self.index(0, COL_MAP), self.index(self.rowCount() - 1, COL_MAP))
        return True

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid() or (self.network is None and self.rows is None):
            return 0
        return len(self.rows) if self.rows is not None else self.network.num_addresses

    def columnCount(self, parent=QModelIndex()):
        return len(ADDRESS_COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return ADDRESS_COLUMNS[section]
        return None

    def address_at(self, row):
        if self.rows is not None:
            return self.rows[row]
        return ipaddress.ip_address(self.first + row) if self.network.version == 4 else \
            ipaddress.IPv6Address(self.first + row)

    def nested_name(self, address):
        for network, name in self.nested:
            if address in network:
                return network, name
        return None

    def status_text(self, address):
        record = self.recorded.get(address)
        special = self.special.get(address)
        if str(address) in self.pending:
            status = STATUSES.get(record.status, record.status) if record is not None else "Free"
            return f"{status} · pending"
        if record is not None:
            status = STATUSES.get(record.status, record.status)
            return f"{special} · {status}" if special else status
        if special:
            return special
        nested = self.nested_name(address)
        if nested:
            return f"In {nested[0]}"
        return FREE

    def sweep_result(self, address):
        """(what sweeps saw, color name, explanation) for the Last Seen column, or None."""
        if self.sweep is None:
            return None
        result = self.sweep.result(address)
        if result is None:
            return None
        record = self.recorded.get(address)
        who = self.sweep.seen_by.get(address)
        by = f" (swept by {who})" if who else ""
        if result[0] in ("answered", "seen"):
            _, rtt, mac, when = result
            speed = "no ping reply (ARP)" if rtt is None else "<1 ms" if rtt < 1 else f"{rtt} ms"
            text = f"Answered · {speed} · {when_text(when)}" if result[0] == "answered" else \
                f"Seen {when_text(when)} · {speed}"
            if record is None and address not in self.special:
                return text, "warning", f"A device answered {when_text(when)}{by}, but IPAM has no record of this " \
                                        "address."
            if record is not None and mac and record.mac and normalize_mac(mac) != normalize_mac(record.mac):
                return text, "error", f"Answered {when_text(when)} from {mac}{by}, but IPAM records {record.mac}."
            return text, "success", f"Answered {when_text(when)}{by}" + (f" from {mac}." if mac else ".")
        _, swept, last_seen = result
        if self.special.get(address) in ("Network", "Broadcast", "Subnet router anycast"):
            return None  # An address no device uses
        text = f"No answer · {when_text(swept)}"
        if last_seen:
            text += f" · last seen {when_text(last_seen)}"
        if record is not None and record.status != RESERVED:
            return text, "error", (f"Recorded as used but didn't answer the sweep {when_text(swept)}: it may be "
                                   "switched off, block ping and ARP, or be gone." +
                                   (f" It last answered {when_text(last_seen)}." if last_seen else
                                    " No sweep has ever heard from it."))
        return text, "muted", f"Nothing answered here in the sweep {when_text(swept)}."

    def map_result(self, address):
        """(where the open map has it, color name or "", explanation) for the On Map column, or None."""
        if self.places_from is None:
            return None
        place = self.places.get(address)
        record = self.recorded.get(address)
        if place is not None:
            text = place.text()
            if record is None and address not in self.special:
                return text, "warning", f"On the map ({text}), but IPAM has no record of this address: the map's "                                         "Record in IPAM... records it."
            return text, "", f"On the map: {text}. Right-click > Show on the Network Map goes to it."
        if record is None:
            return None
        return "Not on the map", "muted", "No device on the map has this address, and the switches haven't seen a "                                           "host with it (it may be off, or outside what was mapped)."

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        address = self.address_at(index.row())
        record = self.recorded.get(address)
        column = index.column()
        if column == COL_SWEEP and role in (Qt.DisplayRole, Qt.ForegroundRole, Qt.ToolTipRole):
            result = self.sweep_result(address)
            if result is None:
                return None
            text, color, explanation = result
            return {Qt.DisplayRole: text, Qt.ForegroundRole: QColor(COLORS[color]),
                    Qt.ToolTipRole: explanation}[role]
        if column == COL_MAP and role in (Qt.DisplayRole, Qt.ForegroundRole, Qt.ToolTipRole):
            result = self.map_result(address)
            if result is None:
                return None
            text, color, explanation = result
            return {Qt.DisplayRole: text, Qt.ForegroundRole: QColor(COLORS[color]) if color else None,
                    Qt.ToolTipRole: explanation}[role]
        if role == Qt.DisplayRole:
            if column == 0:
                return str(address)
            if column == 1:
                return self.status_text(address)
            if record is None:
                found = self.sweep.hosts.get(address) if self.sweep is not None else None
                if found is not None and column in (3, 4):  # What a sweep found, not yet in IPAM
                    return self.sweep.names.get(address, "") if column == 3 else found[1]
                if column == 3 and address not in self.special:
                    nested = self.nested_name(address)
                    return nested[1] if nested else ""
                return ""
            if column == 6:
                return f"{record.modified[:10]} {record.modified_by}" if record.modified else ""
            if column >= len(ADDRESS_COLUMNS) - 1:
                return ""
            return (record.name, record.mac, record.description)[column - 3]
        if role == Qt.ForegroundRole:
            if str(address) in self.pending and column == 1:
                return QColor(COLORS["link"])
            if record is None:
                return QColor(COLORS["muted"])
            if record.status == RESERVED and column == 1:
                return QColor(COLORS["warning"])
        if role == Qt.ToolTipRole and record is None and column in (3, 4) and self.sweep is not None and \
                address in self.sweep.hosts:
            return "Found by a sweep; not in IPAM yet (Record Answering Devices, or right-click, records it)."
        if role == Qt.FontRole and record is None and address in self.special:
            font = QFont()
            font.setItalic(True)
            return font
        if role == Qt.ToolTipRole and str(address) in self.pending:
            return "Changed while the IPAM server couldn't be reached: waiting to be sent to it."
        if role == Qt.UserRole:
            return address
        return None


class SweepResults:
    """What sweeps found in one IPAM network, as kept in the database (so it lasts, and is shared through the IPAM
    server): when each address last answered, and which ranges were swept in full, when. A sweep running now adds to
    it as hosts answer; an address it covers shows what this sweep found so far."""

    CURRENT_SECONDS = 24 * 3600  # A device seen outside a full sweep counts as there now for a day

    def __init__(self):
        self.hosts = {}  # {address: (response ms or None for ARP only, MAC, when seen)}
        self.names = {}  # {address: host name found (DNS or NetBIOS)}
        self.seen_by = {}  # {address: who swept}
        self.ranges = []  # [(Block, started, finished)] swept in full
        self.running = None  # (Block, started) while a sweep of it runs here
        self.message = None  # (Block, how the last sweep here ended)
        self.unsaved_hosts = {}  # {address: host dict} found by a sweep here, not yet saved to the database

    @classmethod
    def load(cls, store, network_id):
        results = cls()
        hosts, ranges = store.sightings(network_id)
        for address, row in hosts.items():
            results.hosts[address] = (row["rtt"], row["mac"], row["seen"])
            if row["name"]:
                results.names[address] = row["name"]
            results.seen_by[address] = row["seen_by"]
        results.ranges = [(block, started, finished) for block, started, finished, _ in ranges]
        return results

    def start(self, block):
        """A sweep of `block` begins here: its addresses show what this sweep finds, as it finds it."""
        self.running = (block, time.time())

    def finish(self, block):
        """The sweep started with start(block) tried every address: the ones that didn't answer count as silent.
        Returns the range, for saving."""
        started = self.running[1] if self.running else time.time()
        finished = time.time()
        self.ranges = [(old, begun, ended) for old, begun, ended in self.ranges if old != block] + \
            [(block, started, finished)]
        self.running = None
        return {"cidr": str(block), "started": started, "finished": finished}

    def stop(self):
        self.running = None

    def found(self, ip, rtt, mac):
        address = ipaddress.ip_address(ip)
        old = self.hosts.get(address)
        self.hosts[address] = (rtt, mac or (old[1] if old else ""), time.time())
        self._unsaved(address)

    def add_name(self, ip, name, mac=""):
        address = ipaddress.ip_address(ip)
        if name:
            self.names[address] = name
        if mac and address in self.hosts and not self.hosts[address][1]:
            rtt, _, when = self.hosts[address]
            self.hosts[address] = (rtt, mac, when)
        if address in self.unsaved_hosts:
            self._unsaved(address)

    def _unsaved(self, address):
        rtt, mac, when = self.hosts[address]
        self.unsaved_hosts[address] = {"ip": str(address), "seen": when, "rtt": rtt, "mac": mac,
                                       "name": self.names.get(address, "")}

    def add(self, ranges, hosts, complete, names=None):
        """A sweep elsewhere (the Sweep page) compared with this network. Returns (hosts, ranges) to save."""
        now = time.time()
        for ip, (rtt, mac) in hosts.items():
            address = ipaddress.ip_address(ip)
            self.hosts[address] = (rtt, mac, now)
            if names and names.get(ip):
                self.names[address] = names[ip]
        swept = []
        if complete:
            for block in ranges:
                self.ranges = [(old, begun, ended) for old, begun, ended in self.ranges if old != block] + \
                    [(block, now, now)]
                swept.append({"cidr": str(block), "started": now, "finished": now})
        saved = [{"ip": ip, "seen": now, "rtt": rtt, "mac": mac, "name": (names or {}).get(ip, "")}
                 for ip, (rtt, mac) in hosts.items()]
        return saved, swept

    def take_unsaved(self):
        hosts = list(self.unsaved_hosts.values())
        self.unsaved_hosts = {}
        return hosts

    def latest_sweep(self, address):
        """(started, finished) of the latest full sweep covering this address, or None."""
        covering = [(started, finished) for block, started, finished in self.ranges if address in block]
        return max(covering, key=lambda times: times[1]) if covering else None

    def swept_at(self, address):
        """When the latest full sweep covering this address finished, or None."""
        latest = self.latest_sweep(address)
        return latest[1] if latest else None

    def result(self, address):
        """What's known of an address: ("answered", rtt, mac, when) in the latest sweep (or the one running),
        ("seen", rtt, mac, when) answering outside a full sweep, ("silent", swept when, last seen or None), or
        None when nothing's known (or the sweep running hasn't reached it)."""
        host = self.hosts.get(address)
        if self.running is not None and address in self.running[0]:
            if host is not None and host[2] >= self.running[1]:
                return ("answered",) + host
            return None
        latest = self.latest_sweep(address)
        if latest is not None:
            if host is not None and host[2] >= latest[0]:
                return ("answered",) + host
            return "silent", latest[1], host[2] if host else None
        return ("seen",) + host if host is not None else None

    def current(self, address):
        """The host's (rtt, mac) if it answers now: in the latest sweep, or seen within the last day."""
        result = self.result(address)
        if result is None or result[0] == "silent":
            return None
        if result[0] == "seen" and time.time() - result[3] > self.CURRENT_SECONDS:
            return None
        return result[1], result[2]


def when_text(moment):
    """"today 14:05", "yesterday 09:30", "Sep 27 14:05", or "2025-09-27" for another year."""
    then = time.localtime(moment)
    now = time.localtime()
    if then.tm_year == now.tm_year and then.tm_yday == now.tm_yday:
        return time.strftime("today %H:%M", then)
    if then.tm_year == now.tm_year and then.tm_yday == now.tm_yday - 1:
        return time.strftime("yesterday %H:%M", then)
    if then.tm_year == now.tm_year:
        return time.strftime("%b %d %H:%M", then)
    return time.strftime("%Y-%m-%d", then)


class IpamTab(QWidget):
    # A sync with the tribe's server finished (the VLANs and Subnet Placement pages show what it brought)
    tribe_synced = pyqtSignal()
    tribe_sync_failed = pyqtSignal(str)  # Why (offline, or the key was refused): Connect to the Tribe shows it

    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.local_store = None
        self.team = None  # TeamStore, when connected to the IPAM server
        self.source = LOCAL  # Where the selected network comes from
        self.subnets = []
        self.network_id = None
        self.current = None  # The selected Subnet, UNSUBNETTED, or None
        self.map_stale = False  # The map changed while the page was hidden: the On Map column is shown again
        self.following = False  # Showing the network another page chose
        self.syncing = False
        self.sync_again = False  # A change arrived during a sync: sync once more when it ends
        self.watcher = None
        self.server_outdated = False  # The server lacks instant sync (an older NOMAD)
        self.sweeps = {}  # {"source:network id": SweepResults}: what sweeps found, loaded from the database
        self.as_of = None  # (moment in UTC, snapshot store) while viewing the network as it was
        self.sweep_worker = None
        self.sweeping = None  # (source, network id, Block) while a sweep runs
        self.sweep_refresh = QTimer(self)  # Show hosts as they're found, without redrawing for every one
        self.sweep_refresh.setSingleShot(True)
        self.sweep_refresh.timeout.connect(lambda: self.refresh_current() if self.local_store is not None else None)
        self.init_ui()
        self.sync_timer = QTimer(self)
        self.sync_timer.timeout.connect(self.sync_now)
        self.sync_timer.start(SYNC_EVERY_MS)
        self.status_timer = QTimer(self)
        self.status_timer.timeout.connect(self.show_team_status)
        self.status_timer.start(STATUS_REFRESH_MS)
        QTimer.singleShot(1500, self.open_store)  # Sync at start, even before the page is opened

    @property
    def store(self):
        """The store the selected network is in."""
        if self.as_of is not None:
            return self.as_of[1]  # The network as it was, read-only
        return self.live_store

    @property
    def live_store(self):
        """The selected network's store as it is now (even while viewing it as it was)."""
        return self.team if self.source == TEAM and self.team is not None else self.local_store

    def can_edit(self):
        """Whether the selected network's subnets and details can be changed now (tribe networks need the
        server for those)."""
        return self.as_of is None and (self.source == LOCAL or (self.team is not None and self.team.online))

    def can_edit_addresses(self):
        """Addresses can always be changed: offline, tribe changes wait as pending until the server is back."""
        return self.as_of is None and (self.source == LOCAL or self.team is not None)

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("Network:"))
        self.network_combo = QComboBox()
        self.network_combo.setMinimumWidth(220)
        self.network_combo.setToolTip("Each network is separate (such as an air-gapped network), so the same "
                                      "addresses can be used in more than one.")
        top.addWidget(self.network_combo)
        self.network_button = QPushButton("Network")
        network_menu = QMenu(self.network_button)
        network_menu.addAction("New Network...", self.new_network)
        self.edit_network_action = add_action(network_menu, "Edit Network...", self.edit_network)
        self.delete_network_action = add_action(network_menu, "Delete Network...", self.delete_network)
        network_menu.addSeparator()
        self.check_action = add_action(network_menu, "Check Data...", self.check_data)
        self.compare_action = add_action(network_menu, "Compare with Workbook...", self.compare_with_workbook)
        network_menu.addSeparator()
        self.export_action = add_action(network_menu, "Export to CSV...", self.export_csv)
        self.export_workbook_action = add_action(network_menu, "Export to Workbook...",
                                                 lambda: self.export_workbook(every=False))
        self.export_all_action = add_action(network_menu, "Export All Networks to Workbook...",
                                            lambda: self.export_workbook(every=True))
        network_menu.addSeparator()
        self.history_action = add_action(network_menu, "Network History...", self.show_network_history)
        self.as_of_action = add_action(network_menu, "View As Of...", self.view_as_of)
        self.network_button.setMenu(network_menu)
        top.addWidget(self.network_button)
        self.import_button = QPushButton("Import Spreadsheet...")
        self.import_button.setToolTip("Import networks from an addressing spreadsheet (.xlsx, or .csv for one page).")
        top.addWidget(self.import_button)
        self.team_button = QPushButton("Tribe")
        team_menu = QMenu(self.team_button)
        self.connect_action = add_action(team_menu, "Connect with Tribe Key File...", self.connect_with_key_file)
        self.sync_action = add_action(team_menu, "Sync Now", lambda: self.sync_now(announce=True))
        self.team_button.setMenu(team_menu)
        top.addWidget(self.team_button)
        self.server_label = QLabel()
        self.server_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        top.addWidget(self.server_label)
        self.refused_button = QPushButton()
        self.refused_button.setToolTip("Changes made offline that the IPAM server couldn't make, because someone "
                                       "else changed those addresses first.")
        self.refused_button.clicked.connect(self.review_refused)
        self.refused_button.setVisible(False)
        top.addWidget(self.refused_button)
        top.addStretch()
        layout.addLayout(top)
        # Search gets a row of its own, so the page still fits a small screen
        search_row = QHBoxLayout()
        search_row.addWidget(QLabel("Search:"))
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Find an address, name or subnet (Enter) (Ctrl+F)")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.setMinimumWidth(200)
        search_row.addWidget(self.search_input, 1)
        self.search_kind_combo = QComboBox()
        for label, options in SEARCH_KINDS:
            self.search_kind_combo.addItem(label, options)
        self.search_kind_combo.setToolTip("What to find")
        search_row.addWidget(self.search_kind_combo)
        search_row.addWidget(QLabel("in"))
        self.search_network_combo = QComboBox()
        self.search_network_combo.addItem("All networks", "")
        self.search_network_combo.setToolTip("Which network to search")
        # Long network names don't widen the page; the list itself shows them in full
        self.search_network_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.search_network_combo.setMinimumContentsLength(18)
        search_row.addWidget(self.search_network_combo)
        search_row.addWidget(QLabel("matching"))
        self.search_match_combo = QComboBox()
        for label, match in SEARCH_MATCHES:
            self.search_match_combo.addItem(label, match)
        self.search_match_combo.setToolTip("Where the text must be: anywhere, or in one field, such as a name or a "
                                           "detail like Telephony Rng")
        search_row.addWidget(self.search_match_combo)
        search_row.addStretch(1)
        layout.addLayout(search_row)
        self.team_label = QLabel()
        self.team_label.setWordWrap(True)
        layout.addWidget(self.team_label)
        self.as_of_bar = QWidget()
        as_of_layout = QHBoxLayout(self.as_of_bar)
        as_of_layout.setContentsMargins(8, 4, 8, 4)
        self.as_of_label = QLabel()
        self.as_of_label.setWordWrap(True)
        back_button = QPushButton("Back to Now")
        back_button.clicked.connect(self.back_to_now)
        as_of_layout.addWidget(self.as_of_label, 1)
        as_of_layout.addWidget(back_button)
        self.as_of_bar.setObjectName("asOfBar")  # So the frame goes round the bar, not each thing in it
        self.as_of_bar.setStyleSheet(f"#asOfBar {{ background: {COLORS['warning_background']}; border: 1px solid "
                                     f"{COLORS['warning']}; }}")
        self.as_of_bar.setVisible(False)
        layout.addWidget(self.as_of_bar)
        self.details_label = QLabel()
        self.details_label.setWordWrap(True)
        self.details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.details_label)

        splitter = QSplitter(Qt.Horizontal)
        self.splitter = splitter
        left = QWidget()
        self.subnet_panel = left
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.subnet_filter = QLineEdit()
        self.subnet_filter.setPlaceholderText("Filter subnets")
        self.subnet_filter.setClearButtonEnabled(True)
        left_layout.addWidget(self.subnet_filter)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Subnet", "Name", "Used"])
        self.tree.setRootIsDecorated(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)  # Ctrl/Shift-click to change several
        self.tree.header().setSectionResizeMode(QHeaderView.Interactive)
        left_layout.addWidget(self.tree, 1)
        subnet_buttons = QHBoxLayout()
        self.add_subnet_button = QPushButton("Add Subnet...")
        self.edit_subnet_button = QPushButton("Edit...")
        self.delete_subnet_button = QPushButton("Delete")
        self.move_subnet_button = QPushButton("Move...")
        self.move_subnet_button.setToolTip("Move the subnet, with its addresses, to another network (also on its "
                                           "right-click: Move to Another Network).")
        for button in (self.add_subnet_button, self.edit_subnet_button, self.delete_subnet_button,
                       self.move_subnet_button):
            subnet_buttons.addWidget(button)
        subnet_buttons.addStretch()
        left_layout.addLayout(subnet_buttons)
        splitter.addWidget(left)

        self.right_stack = QStackedWidget()
        addresses_page = QWidget()
        right_layout = QVBoxLayout(addresses_page)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.subnet_label = QLabel()
        self.subnet_label.setWordWrap(True)
        self.subnet_label.setTextFormat(Qt.RichText)
        # Its role, VLANs, placement and place on the map link to those pages
        self.subnet_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse)
        self.subnet_label.linkActivated.connect(self.open_link)
        self.subnet_line = ""  # The subnet's own details, before what the other pages know about it
        right_layout.addWidget(self.subnet_label)
        address_buttons = QHBoxLayout()
        self.next_free_button = accent_button("Use Next Free...")
        self.next_free_button.setProperty("normal_tip", "Record the lowest free address in this subnet (not the "
                                                        "network, broadcast or gateway address).")
        self.next_free_button.setToolTip(self.next_free_button.property("normal_tip"))
        self.sweep_button = QPushButton("Sweep Subnet")
        self.sweep_button.setToolTip("Ping every address in this subnet (with ARP on local subnets, and host names) "
                                     "and show what answers in the Last Sweep column. Uses the Sweep page's "
                                     "settings.")
        self.edit_address_button = QPushButton("Edit...")
        self.free_button = QPushButton("Mark Free")
        self.hide_free_check = QCheckBox("Hide free addresses")
        for widget in (self.next_free_button, self.edit_address_button, self.free_button, self.sweep_button):
            address_buttons.addWidget(widget)
        address_buttons.addStretch()
        address_buttons.addWidget(self.hide_free_check)
        right_layout.addLayout(address_buttons)
        sweep_row = QHBoxLayout()
        self.sweep_progress = QProgressBar()
        self.sweep_progress.setMaximumHeight(16)
        self.sweep_status = QLabel()
        self.record_found_button = QPushButton()
        self.record_found_button.setToolTip("Record every device the sweep found that IPAM doesn't have, as used, "
                                            "with its host name and MAC address.")
        self.update_macs_button = QPushButton()
        self.update_macs_button.setToolTip("Update the MAC address IPAM records wherever a different one answered.")
        sweep_row.addWidget(self.sweep_progress, 1)
        sweep_row.addWidget(self.sweep_status)
        sweep_row.addStretch()
        sweep_row.addWidget(self.record_found_button)
        sweep_row.addWidget(self.update_macs_button)
        self.sweep_row = QWidget()
        self.sweep_row.setLayout(sweep_row)
        sweep_row.setContentsMargins(0, 0, 0, 0)
        self.sweep_row.setVisible(False)
        right_layout.addWidget(self.sweep_row)
        self.model = AddressModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(self.table.fontMetrics().height() + 8)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        right_layout.addWidget(self.table, 1)
        self.right_stack.addWidget(addresses_page)

        results_page = QWidget()
        results_layout = QVBoxLayout(results_page)
        results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_label = QLabel()
        results_layout.addWidget(self.results_label)
        self.results_table = QTableWidget(0, len(RESULT_COLUMNS))
        self.results_table.setHorizontalHeaderLabels(RESULT_COLUMNS)
        self.results_table.verticalHeader().setVisible(False)
        self.results_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSortingEnabled(True)
        results_layout.addWidget(self.results_table, 1)
        results_layout.addWidget(QLabel("Double-click a result to go to it. Clear the search to go back."))
        self.right_stack.addWidget(results_page)
        splitter.addWidget(self.right_stack)
        # The subnets get just the width they need (see fit_subnet_panel); resizing the window grows the addresses
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setCollapsible(0, False)
        self.panel_fitted = False  # The subnet list is sized once, when the page first appears
        layout.addWidget(splitter, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        self.network_combo.currentIndexChanged.connect(self.on_network_chosen)
        self.import_button.clicked.connect(self.import_spreadsheet)
        self.search_input.returnPressed.connect(self.search)
        self.search_kind_combo.currentIndexChanged.connect(self.search_again)
        self.search_network_combo.currentIndexChanged.connect(self.search_again)
        self.search_match_combo.currentIndexChanged.connect(self.search_again)
        self.search_input.textChanged.connect(lambda text: None if text else self.right_stack.setCurrentIndex(0))
        self.subnet_filter.textChanged.connect(self.filter_tree)
        self.tree.currentItemChanged.connect(lambda *_: self.show_subnet())
        self.tree.itemDoubleClicked.connect(lambda *_: self.edit_subnet())
        self.tree.customContextMenuRequested.connect(self.subnet_menu)
        self.add_subnet_button.clicked.connect(lambda: self.add_subnet())
        self.edit_subnet_button.clicked.connect(self.edit_subnet)
        self.delete_subnet_button.clicked.connect(self.delete_subnet)
        self.move_subnet_button.clicked.connect(self.move_to_network)
        self.next_free_button.clicked.connect(self.use_next_free)
        self.sweep_button.clicked.connect(self.sweep_subnet)
        self.record_found_button.clicked.connect(self.record_found)
        self.update_macs_button.clicked.connect(self.update_macs)
        self.edit_address_button.clicked.connect(self.edit_address)
        self.free_button.clicked.connect(self.free_addresses)
        self.hide_free_check.toggled.connect(lambda: self.show_subnet())
        self.table.doubleClicked.connect(lambda _: self.edit_address())
        self.table.customContextMenuRequested.connect(self.address_menu)
        self.table.selectionModel().selectionChanged.connect(lambda *_: self.update_buttons())
        self.results_table.cellDoubleClicked.connect(self.go_to_result)

    # ----------------------------------------------------------------- Page interface

    def open_store(self):
        """Open the databases the first time they're needed, so starting NOMAD doesn't wait on them."""
        if self.local_store is None:
            try:
                self.local_store = IpamStore()
            except Exception as error:  # A damaged or locked database file
                log.exception("Couldn't open the IPAM database")
                set_hint(self.status_label, f"Couldn't open the IPAM database: {error}", "error")
                return False
            self.connect_team()
            self.fill_networks()
            integration = hub(self.window)
            if integration is not None:
                integration.stores_opened()  # A map opened before them shows its network now
        return True

    def fit_subnet_panel(self):
        """When the page first appears, make the subnet list just wide enough for its columns (and its buttons),
        leaving the rest of the width to the addresses. Never again after that: the divider stays where it is."""
        if self.panel_fitted:
            return
        tree = self.tree
        columns = sum(tree.columnWidth(column) for column in range(tree.columnCount()))
        needed = columns + 2 * tree.frameWidth() + tree.verticalScrollBar().sizeHint().width() + 4
        needed = max(needed, self.subnet_panel.minimumSizeHint().width())
        total = sum(self.splitter.sizes()) or self.splitter.width()
        if total <= needed:
            return  # Not laid out yet; tried again when the page is next shown
        self.splitter.setSizes([needed, total - needed])
        self.panel_fitted = True

    def showEvent(self, event):
        super().showEvent(event)
        self.open_store()
        if self.map_stale:  # The map (or the facts) changed while another page was shown
            self.map_stale = False
            self.on_facts_changed()
        QTimer.singleShot(0, self.fit_subnet_panel)  # Once the page has its real width

    def focus_find(self):
        """Ctrl+F on this page."""
        self.search_input.setFocus()
        self.search_input.selectAll()

    def save_settings(self, settings):
        if self.network_id:
            settings.setValue("ipam/network", f"{self.source}:{self.network_id}")
        settings.setValue("ipam/hide_free", self.hide_free_check.isChecked())

    def restore_settings(self, settings):
        self.saved_network_id = settings.value("ipam/network", "", str)
        self.hide_free_check.setChecked(settings.value("ipam/hide_free", False, bool))

    def shutdown(self):
        self.sync_timer.stop()
        if self.sweep_worker is not None:
            self.sweep_worker.stop()
            self.sweep_worker.wait(5000)
        self.stop_watching()
        for store in (self.local_store, self.team):
            if store is not None:
                store.close()
        self.local_store = self.team = None

    # ----------------------------------------------------------------- The tribe's server

    def connect_team(self):
        """Use the server's data: as its admin on the server itself (NOMAD running as administrator), or through
        the saved tribe key on a laptop."""
        self.stop_watching()
        if self.team is not None:
            self.team.close()
            self.team = None
        key, path = None, None
        if getattr(self.window, "admin", False):
            key = admin_key()
            path = log_dir() / ADMIN_COPY_FILE
        if key is None:
            key = load_saved_key()
            path = None
        if key is not None:
            try:
                self.team = TeamStore(key, path)
            except Exception as error:  # A damaged copy: say so rather than failing the page
                log.exception("Couldn't open the copy of the tribe's IPAM data")
                set_hint(self.status_label, f"Couldn't open the copy of the tribe's data: {error}", "error")
        self.show_team_status()
        self.sync_now()
        self.server_outdated = False
        if self.team is not None:
            self.watcher = ServerWatcher(self.team.client, self.team.revision, self.team.sighting_revision, self)
            self.watcher.changed.connect(self.on_server_changed)
            self.watcher.reachability.connect(self.on_reachability)
            self.watcher.outdated.connect(self.on_server_outdated)
            self.watcher.rejected.connect(self.on_key_rejected)
            self.watcher.start()

    def stop_watching(self):
        if self.watcher is not None:
            self.watcher.stop()
            self.watcher.changed.disconnect()
            self.watcher.reachability.disconnect()
            self.watcher.outdated.disconnect()
            self.watcher.rejected.disconnect()
            self.watcher = None

    def on_key_rejected(self, reason):
        if self.team is not None:
            self.team.online, self.team.last_error, self.team.key_rejected = False, reason, True
            self.show_team_status()
            self.update_permissions()

    def on_server_outdated(self):
        log.info("The IPAM server is an older version without instant sync; checking it every %d s", POLL_SECONDS)
        self.server_outdated = True
        self.show_team_status()

    def on_server_changed(self, _revision):
        """Someone changed the tribe's data: sync now (or right after the sync that's running)."""
        if self.syncing:
            self.sync_again = True
        else:
            self.sync_now()

    def on_reachability(self, reachable, reason):
        if self.team is None:
            return
        if reachable:
            if not self.team.online:
                self.sync_now()  # Back online: catch up (the sync marks it online)
            return
        if self.team.online or self.team.last_error != reason:
            self.team.online, self.team.last_error = False, reason
            self.show_team_status()
            self.update_permissions()

    def connect_with_key_file(self):
        if not self.open_store():
            return
        if not connect_to_tribe(self, self.window, "Connect to the Tribe's IPAM Server"):  # Tells the pages
            return
        set_hint(self.status_label, "Tribe key saved (encrypted for your Windows account). You can delete the key "
                                    "file now, or keep it somewhere safe: anyone with it can change the tribe's "
                                    "IPAM.", "success")

    def unsent_tribe_changes(self):
        """Changes made offline that haven't reached the server (waiting, or refused and not yet resolved),
        addresses' and VLANs'."""
        if self.team is None:
            return 0
        vlans = TeamVlanStore(self.team)
        return self.team.pending_count() + len(self.team.refused()) + vlans.pending_count() + len(vlans.refused())

    def forget_team_copy(self):
        """Empty and close the copy of the tribe's IPAM data (leaving the tribe)."""
        if self.team is not None:
            self.stop_watching()
            self.team.reset_copy()
            self.team.close()
            self.team = None

    def sync_now(self, announce=False):
        """Fetch the server's changes on a worker thread, then apply them here."""
        if self.team is None or self.syncing:
            return
        self.syncing = True
        team, client, revision, outgoing = self.team, self.team.client, self.team.revision, self.team.outgoing()
        history_revision, sighting_revision = self.team.history_revision, self.team.sighting_revision
        sightings_out = self.team.outgoing_sightings()
        vlans = TeamVlanStore(self.team)
        vlans_out = vlans.outgoing()
        if announce:
            set_hint(self.team_label, "Tribe: syncing...", "info")

        def fetch():
            sent = []
            try:
                sent = team.send_pending(outgoing) if outgoing else []  # Only talks to the server: thread-safe
                sent = (sent, vlans.send_pending(vlans_out) if vlans_out else [])  # And VLANs changed offline
                changes = client.fetch_all_changes(revision)
                try:
                    changes += (client.fetch_log(history_revision),)  # History, kept for offline use
                except OldServerError:
                    changes += (None,)  # An older server without history
                # Sweep results: this laptop's to the server, then everyone's back (None from an older server)
                changes += (team.send_sightings(sightings_out), client.fetch_sightings(sighting_revision))
                return sent, changes
            except IpamError as error:  # Offline or refused: expected, so not logged as a failure
                return sent, error

        run_in_background(fetch, lambda result: self.sync_done(result, announce, team),
                          lambda error: self.sync_failed(error, team))

    def sync_done(self, result, announce, team=None):
        self.syncing = False
        if self.team is None:
            return
        if self.replaced(team):
            QTimer.singleShot(0, self.sync_now)  # Fetched for another tribe since: sync the new one instead
            return
        if self.sync_again:
            self.sync_again = False
            QTimer.singleShot(0, self.sync_now)
        sent_results, result = result
        sent_results, vlan_results = sent_results if isinstance(sent_results, tuple) else (sent_results, [])
        if vlan_results:
            sent, refused = TeamVlanStore(self.team).apply_sent(vlan_results)
            log.info("Sent %d VLAN changes made offline to the IPAM server; %d refused", sent, refused)
        if sent_results:
            sent, refused = self.team.apply_sent(sent_results)
            log.info("Sent %d offline changes to the IPAM server; %d refused", sent, refused)
            if refused:
                set_hint(self.status_label, f"{refused} change{'s' if refused != 1 else ''} made offline couldn't "
                                            "be made: someone else changed those addresses first. Use Review "
                                            "Refused Changes to choose what to do.", "warning")
            elif sent:
                set_hint(self.status_label, f"Sent {sent} change{'s' if sent != 1 else ''} made offline to the IPAM "
                                            "server.", "success")
            self.refresh_everything()
        if isinstance(result, Exception):
            self.sync_failed(result)
            if announce:
                set_hint(self.status_label, f"Couldn't sync: {result}", "warning")
            return
        status, items, revision, history, sightings_sent, sightings = result
        self.team.apply_sync(items, revision, status)
        if history is not None:
            self.team.apply_log(*history)
        self.team.apply_sent_sightings(sightings_sent)
        if sightings is not None and (sightings[0]["hosts"] or sightings[0]["ranges"]):
            self.team.apply_sightings(*sightings)
            self.reload_sweep_results()
            if self.source == TEAM and not items:
                self.refresh_current()
        elif sightings is not None:
            self.team.apply_sightings(*sightings)
        self.update_buttons()  # Back online: tribe networks can be changed again
        if items:
            log.info("Synced %d changes from the IPAM server", len(items))
            self.refresh_everything()
        self.show_team_status()
        if announce:
            set_hint(self.status_label, f"Synced: {len(items)} change{'' if len(items) == 1 else 's'} from the "
                                        "server.", "success")
        self.tribe_synced.emit()

    def sync_failed(self, error, team=None):
        self.syncing = False
        if isinstance(error, tuple):  # (sent, error) from a sync that sent some changes first
            error = error[1]
        self.sync_again = False
        if self.team is None:
            return
        if self.replaced(team):
            QTimer.singleShot(0, self.sync_now)
            return
        self.team.online, self.team.last_error = False, str(error)
        self.team.key_rejected = isinstance(error, TeamKeyError)
        log.info("IPAM sync failed: %s", error)
        self.show_team_status()
        self.update_permissions()
        self.tribe_sync_failed.emit(str(error))

    def replaced(self, team):
        """Whether a sync started for `team` is for another tribe than the one used now (a different tribe key was
        connected while it ran): its results belong to neither. The same server's copy is the same file, so a sync
        from before connecting the same tribe again still counts."""
        return team is not None and team is not self.team and (team.key.server_id, team.key.role) !=             (self.team.key.server_id, self.team.key.role)

    def refresh_everything(self):
        """Show new data from a sync, keeping the selected network, subnet and address where they still exist."""
        if self.as_of is not None:
            return  # Viewing the past: the present can wait until Back to Now
        selected = self.selected_addresses()
        scroll = self.table.verticalScrollBar().value()
        self.fill_networks()
        self.table.verticalScrollBar().setValue(scroll)
        if len(selected) == 1:
            self.select_address(selected[0])

    def show_team_status(self):
        team = self.team
        self.connect_action.setEnabled(team is None or not team.admin)
        self.sync_action.setEnabled(team is not None)
        admin = team is not None and team.admin
        self.import_button.setText("Import to Tribe Server..." if admin else "Import Locally (Not Shared)...")
        if team is None:
            hint = ""
            if server_dir().exists():  # Its contents are hidden from NOMAD without administrator rights
                hint = " This computer is the IPAM server: restart NOMAD as administrator (File menu) to manage it."
            set_hint(self.team_label, "Tribe: not connected. To share networks with the tribe, use Tribe > Connect "
                                      "with Tribe Key File." + hint, "info")
            set_hint(self.server_label, "No IPAM server", "info")
            self.refused_button.setVisible(False)
            self.server_label.setToolTip("Not connected to the tribe's IPAM server.")
            return
        synced = f"synced {ago(time.time() - team.last_sync)}" if team.last_sync else "not synced yet"
        waiting = team.pending_count()
        if waiting:
            synced += f"; {waiting} change{'s' if waiting != 1 else ''} waiting to be sent"
        refused = len(team.refused())
        self.refused_button.setText(f"Review Refused Changes ({refused})")
        self.refused_button.setVisible(bool(refused))
        who = "Server admin: this is the server's IPAM; imports and new networks go to it" if admin else "Tribe"
        server = "This computer (IPAM server)" if admin else team.server_name
        if team.key_rejected:
            set_hint(self.team_label, f"{who}: {team.last_error}", "error")
            set_hint(self.server_label, f"● {server} · tribe key not accepted", "error")
        elif team.online and self.server_outdated:
            update = "use Tools > Tribe Management > Update Service here" if admin else "ask for it to be updated"
            set_hint(self.team_label, f"{who} · {synced}. The IPAM server is running an older version of NOMAD, so "
                                      f"changes arrive within {POLL_SECONDS} seconds instead of at once ({update}).",
                     "warning")
            set_hint(self.server_label, f"● {server} · connected (needs updating)", "warning")
        elif team.online:
            set_hint(self.team_label, f"{who} · {synced}; changes arrive as they're made", "success")
            set_hint(self.server_label, f"● {server} · connected", "success")
        elif team.last_error:
            set_hint(self.team_label, f"{who} · offline, {synced}. {OFFLINE_NOTE}", "warning")
            set_hint(self.server_label, f"● {server} · offline", "error")
        else:
            set_hint(self.team_label, f"{who} · connecting... ({synced})", "info")
            set_hint(self.server_label, f"● {server} · connecting...", "warning")
        details = [f"IPAM server: {team.server_name}, last reached at {team.server_address}",
                   f"Addresses tried: {', '.join(team.key.hosts)} (port {team.key.port})",
                   f"Last synced: {time.strftime('%Y-%m-%d %H:%M', time.localtime(team.last_sync))}"
                   if team.last_sync else "Not synced yet"]
        if team.last_error:
            details.append(f"Last problem: {team.last_error}")
        self.server_label.setToolTip("\n".join(details))

    # ----------------------------------------------------------------- For other pages (Sweep, ARP)

    def ipam_stores(self):
        """[(source, store)] with networks to compare against: the tribe's first, then this computer's."""
        if not self.open_store():
            return []
        return ([(TEAM, self.team)] if self.team is not None else []) + [(LOCAL, self.local_store)]

    def store_for(self, source):
        return self.team if source == TEAM else self.local_store

    def can_change_addresses(self, source):
        return source == LOCAL or self.team is not None

    def show_address(self, source, network_id, ip):
        """Go to an address on this page."""
        self.window.navigator.setCurrentWidget(self)
        self.subnet_filter.clear()
        self.search_input.clear()
        self.right_stack.setCurrentIndex(0)
        self.fill_networks(f"{source}:{network_id}")
        store = self.store_for(source)
        subnet = store.subnet_for(network_id, ip) if store is not None else None
        self.fill_tree(select=subnet if subnet is not None else UNSUBNETTED)
        self.select_address(ipaddress.ip_address(ip))

    def go_to_subnet(self, source, network_id, cidr):
        """Go to a subnet on this page (from the VLANs page)."""
        self.window.navigator.setCurrentWidget(self)
        self.subnet_filter.clear()
        self.search_input.clear()
        self.right_stack.setCurrentIndex(0)
        self.fill_networks(f"{source}:{network_id}")
        store = self.store_for(source)
        subnet = next((item for item in store.subnets(network_id) if item.cidr == cidr), None) if store else None
        if subnet is not None:
            self.fill_tree(select=subnet)

    def record_sweep(self, source, network_id, ranges, hosts, complete, names=None):
        """A sweep compared with this IPAM network finished: keep what it found (shared, for tribe networks), and
        show it in the Last Seen column."""
        if not self.open_store():
            return
        results = self.sweep_results(source, network_id)
        found, swept = results.add(ranges, hosts, complete, names)
        self.save_sightings(source, network_id, found, swept)
        if (source, network_id) == (self.source, self.network_id):
            self.refresh_current()

    # ----------------------------------------------------------------- What sweeps found (last seen)

    def sweep_results(self, source, network_id):
        """The network's SweepResults, loaded from its store the first time."""
        key = f"{source}:{network_id}"
        if key not in self.sweeps:
            store = self.store_for(source)
            self.sweeps[key] = SweepResults.load(store, network_id) if store is not None else SweepResults()
        return self.sweeps[key]

    def save_sightings(self, source, network_id, hosts, ranges):
        """Keep sweep results in the network's store; tribe ones go to the IPAM server with the next sync."""
        store = self.store_for(source)
        if store is None or not (hosts or ranges):
            return
        try:
            store.record_sightings(network_id, hosts, ranges)
        except IpamError as error:
            log.warning("Couldn't keep the sweep results: %s", error)
            return
        if source == TEAM:
            self.sync_now()

    def reload_sweep_results(self):
        """New sweep results arrived from the server: load them again (except where a sweep is running here)."""
        running = f"{self.sweeping[0]}:{self.sweeping[1]}" if self.sweeping else None
        self.sweeps = {key: results for key, results in self.sweeps.items() if key == running}

    def refresh_after_external_change(self):
        """Another page changed IPAM: show it here, and send tribe changes on."""
        if self.local_store is None:
            return
        self.refresh_everything()
        self.show_team_status()
        if self.team is not None:
            self.sync_now()

    # ----------------------------------------------------------------- History

    def show_history(self, kind, subject):
        from .ipam_history_dialog import HistoryDialog
        HistoryDialog(self, self.live_store, self.network_id, kind, subject, self.history_note()).exec_()

    def show_network_history(self):
        if self.network_id is not None:
            self.show_history("network", self.live_store.network(self.network_id))

    def history_note(self):
        """Why tribe history may be incomplete on this laptop, or ""."""
        if self.source == TEAM and self.team is not None and not self.team.history_revision:
            return ("The tribe's history arrives with the next sync from the IPAM server (the server needs NOMAD "
                    "1.5 or later).")
        return ""

    def view_as_of(self):
        from .ipam_history_dialog import AsOfDialog
        if self.network_id is None:
            return
        dialog = AsOfDialog(self, self.as_of[0] if self.as_of else None)
        if not dialog.exec_():
            return
        moment = dialog.moment_utc()
        snapshot = network_as_of(self.live_store, self.network_id, moment)
        if snapshot is None:
            QMessageBox.information(self, "View As Of", f"This network didn't exist yet at {dialog.moment_text()}.")
            return
        self.leave_as_of()
        self.as_of = (moment, snapshot)
        note = self.history_note()
        self.as_of_label.setText(f"<b>Showing {self.live_store.network(self.network_id).name} as it was at "
                                 f"{dialog.moment_text()}.</b> Read-only: nothing can be changed while viewing the "
                                 f"past." + (f" {note}" if note else ""))
        self.as_of_bar.setVisible(True)
        self.history_action.setEnabled(False)
        self.fill_tree()
        self.update_buttons()

    def leave_as_of(self):
        if self.as_of is not None:
            self.as_of[1].close()
            self.as_of = None
            self.as_of_bar.setVisible(False)
            self.history_action.setEnabled(True)

    def back_to_now(self):
        self.leave_as_of()
        self.fill_networks()

    def review_refused(self):
        from .ipam_dialogs import RefusedDialog
        if self.team is None:
            return
        RefusedDialog(self, self.team).exec_()
        self.refresh_everything()
        self.show_team_status()
        self.sync_now()

    def report(self, error, action="That change"):
        """Explain a change the server refused, and sync so the page shows the latest."""
        if isinstance(error, ServerUnreachable):
            self.team.online = False
            self.show_team_status()
            self.update_permissions()
        QMessageBox.warning(self, "Not Changed", f"{action} wasn't made. {error}")
        if isinstance(error, (ConflictError, TeamKeyError)):
            self.sync_now()

    def after_dialog(self):
        """A dialog may have hit a conflict or lost the server: bring the tribe's copy and status up to date."""
        if self.source == TEAM and self.team is not None:
            self.show_team_status()
            self.update_permissions()
            self.sync_now()

    # ----------------------------------------------------------------- Networks

    def fill_networks(self, select_id=None):
        """Every network: the tribe's first (marked Tribe), then this computer's (marked Local)."""
        if self.local_store is None:
            return
        select_id = select_id or (f"{self.source}:{self.network_id}" if self.network_id else "") or \
            getattr(self, "saved_network_id", "")
        self.network_combo.blockSignals(True)
        self.network_combo.clear()
        sources = [(TEAM, self.team), (LOCAL, self.local_store)] if self.team is not None else \
            [(LOCAL, self.local_store)]
        search_in = self.search_network_combo.currentData()
        self.search_network_combo.blockSignals(True)
        while self.search_network_combo.count() > 1:  # Keep All networks
            self.search_network_combo.removeItem(1)
        for source, store in sources:
            for network in store.networks():
                label = f"{network.name}   ({'Tribe' if source == TEAM else 'Local'})" if self.team else network.name
                self.network_combo.addItem(label, f"{source}:{network.id}")
                self.search_network_combo.addItem(label, f"{source}:{network.id}")
        index = self.network_combo.findData(select_id)
        self.network_combo.setCurrentIndex(index if index >= 0 else 0)
        self.network_combo.blockSignals(False)
        self.search_network_combo.setCurrentIndex(max(self.search_network_combo.findData(search_in), 0))
        self.search_network_combo.blockSignals(False)
        self.fill_search_matches([store for _, store in sources])

    def fill_search_matches(self, stores):
        """The fields search can be limited to: the fixed ones, then every detail recorded (such as Telephony Rng)."""
        details = sorted({name for store in stores for name in store.detail_names()}, key=str.casefold)
        chosen = self.search_match_combo.currentData()
        combo = self.search_match_combo
        combo.blockSignals(True)
        while combo.count() > len(SEARCH_MATCHES):
            combo.removeItem(len(SEARCH_MATCHES))
        if details:
            combo.insertSeparator(combo.count())
            for name in details:
                combo.addItem(name, name)
        combo.setCurrentIndex(max(combo.findData(chosen), 0))
        combo.blockSignals(False)
        self.on_network_chosen()

    def on_network_chosen(self):
        self.leave_as_of()
        data = self.network_combo.currentData()
        if data:
            self.source, self.network_id = data.split(":", 1)
        else:
            self.source, self.network_id = LOCAL, None
        has_network = self.network_id is not None
        for widget in (self.tree, self.subnet_filter):
            widget.setEnabled(has_network)
        for action in (self.export_action, self.export_workbook_action, self.export_all_action, self.check_action,
                       self.compare_action):
            action.setEnabled(has_network)
        if not has_network:
            self.details_label.setText("No networks yet. Import your addressing spreadsheet (Import Spreadsheet...), "
                                       "add one with Network > New Network, or connect to the tribe's IPAM server "
                                       "with Tribe > Connect with Tribe Key File.")
        self.fill_tree()
        integration = hub(self.window)
        if integration is not None and self.network_id is not None and not self.following:
            integration.choose_network(f"{self.source}:{self.network_id}", self)

    def update_permissions(self):
        """Enable what can be changed: tribe networks need the server, and only its admin adds or deletes them."""
        has_network = self.network_id is not None
        editable = has_network and self.can_edit()
        admin = self.team is not None and self.team.admin
        self.add_subnet_button.setEnabled(editable)
        self.edit_network_action.setEnabled(editable)
        self.delete_network_action.setEnabled(editable and (self.source == LOCAL or admin))
        self.import_button.setToolTip("Import networks from an addressing spreadsheet into the server's IPAM." if admin
                                      else "Import networks from an addressing spreadsheet (.xlsx, or .csv for one "
                                           "page) into this computer's IPAM (Local). The tribe's networks are "
                                           "imported on the server.")
        tip = "" if editable or not has_network else OFFLINE_NOTE
        for widget in (self.add_subnet_button, self.edit_subnet_button, self.delete_subnet_button,
                       self.move_subnet_button):
            widget.setToolTip(tip)

    def network(self):
        return self.store.network(self.network_id) if self.network_id else None

    def follow_network(self, key):
        """Another page (or the map) chose a network: show it here too."""
        integration = hub(self.window)
        if integration is not None and not integration.follows(self):
            return
        if self.local_store is None:
            self.saved_network_id = key  # Opened later: with it
            return
        if self.as_of is not None or key == f"{self.source}:{self.network_id}":
            return
        self.following = True  # Filling the list mustn't choose a network of its own for the others
        try:
            if self.network_combo.findData(key) < 0:
                self.fill_networks()  # Not listed yet (or new since)
            if self.network_combo.findData(key) >= 0:
                self.fill_networks(key)
        finally:
            self.following = False

    def on_facts_changed(self):
        """Something the subnet's role, VLANs or placement come from changed (or the map): say them again, and
        where the map has each address. Hidden, it's done when the page is next shown."""
        if self.current is None:
            return
        if not self.isVisible():
            self.map_stale = True
        else:
            places = self.map_places()
            if places is not self.model.places_from:
                if not self.model.set_places(places):
                    self.reload_addresses()
                self.table.setColumnHidden(COL_MAP, places is None)
            if isinstance(self.current, Subnet):
                self.show_subnet_line(self.current)

    def map_places(self):
        """The open map's addresses (Integration.map_places), when it's of the network shown, else None."""
        integration = hub(self.window)
        if integration is None or self.as_of is not None or not self.network_id:
            return None
        return integration.map_places(f"{self.source}:{self.network_id}")

    def reload_addresses(self):
        """Show the current subnet's addresses again, keeping the scroll position and the address selected."""
        scroll = self.table.verticalScrollBar().value()
        selected = self.selected_addresses()
        self.show_subnet()
        if len(selected) == 1:
            self.select_address(selected[0])
        self.table.verticalScrollBar().setValue(scroll)

    def show_subnet_line(self, subnet):
        parts = []
        integration = hub(self.window)
        if integration is not None and self.as_of is None and self.network_id:
            parts = integration.subnet_summary(f"{self.source}:{self.network_id}", subnet.cidr)
        self.subnet_label.setText("   ·   ".join([self.subnet_line] + parts))

    def open_link(self, url):
        integration = hub(self.window)
        if integration is not None:
            integration.open_link(url)

    def other_page_actions(self, menu, subnet=None, address=None):
        """Show the subnet's VLANs, its placement, or it (or the address) on the map: {action: link}."""
        integration = hub(self.window)
        if integration is None or self.as_of is not None or not self.network_id:
            return {}
        key, links = f"{self.source}:{self.network_id}", {}
        if subnet is not None:
            facts = integration.facts(key)
            row = facts.row(subnet.cidr) if facts is not None else None
            menu.addSeparator()
            for domain, vlan in (row.planned if row is not None else []):
                links[menu.addAction(f"Show VLAN {vlan.vlan} on the VLANs Page")] = link(
                    VLAN, src=self.source, domain=domain.id, vlan=vlan.vlan)
            links[menu.addAction("Show in Subnet Placement")] = link(
                PLACEMENT, src=self.source, net=self.network_id, cidr=subnet.cidr, vrf=row.vrf if row else "")
            if row is not None and row.found is not None:
                links[menu.addAction("Show on the Network Map")] = link(MAP_SUBNET, cidr=subnet.cidr)
        if address is not None:
            device = integration.map_device_for(key, address)
            if device is not None:
                links[menu.addAction("Show on the Network Map")] = link(MAP_DEVICE, key=device)
        return links

    def new_network(self):
        if not self.open_store():
            return
        admin = self.team is not None and self.team.admin
        target = self.team if admin else self.local_store
        dialog = NetworkDialog(self, target)
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.fill_networks(f"{TEAM if admin else LOCAL}:{dialog.result_item.id}")

    def edit_network(self):
        dialog = NetworkDialog(self, self.store, self.network())
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.fill_networks()

    def delete_network(self):
        network = self.network()
        count = len(self.store.addresses(network.id))
        where = " from the server, for the whole tribe" if self.source == TEAM else ""
        if QMessageBox.question(self, "Delete Network",
                                f"Delete {network.name}{where}, with its {len(self.subnets)} subnets and {count} "
                                "recorded addresses?") != QMessageBox.Yes:
            return
        try:
            self.store.delete_network(network.id)
        except IpamError as error:
            self.report(error, "Deleting the network")
            return
        self.network_id = None
        self.fill_networks()

    def show_network_details(self):
        network = self.network()
        if network is None:
            return
        parts = [network.description] if network.description else []
        parts += [f"{name}: {value}" for name, value in network.fields.items()]
        self.details_label.setText("   ·   ".join(parts))

    # ----------------------------------------------------------------- Subnet tree

    def fill_tree(self, select=None):
        """Subnets nested under the blocks that hold them, with how much of each is used."""
        previous = select if select is not None else self.current
        self.tree.clear()
        self.subnets = self.store.subnets(self.network_id) if self.network_id else []
        if self.network_id is None:
            self.show_subnet()
            return
        self.show_network_details()
        stack = []  # [(network, item)] of the blocks holding the current subnet
        select_item = None
        for subnet in self.subnets:
            network = subnet.network
            while stack and not (stack[-1][0].version == network.version and network.subnet_of(stack[-1][0])):
                stack.pop()
            used = self.store.count_addresses(self.network_id, network)
            item = QTreeWidgetItem([subnet.cidr, subnet.name,
                                    f"{used} / {usable_count(network, subnet.loopbacks):,}"])
            item.setData(0, Qt.UserRole, subnet)
            item.setToolTip(1, subnet.name)
            if subnet.loopbacks:
                item.setToolTip(0, "Loopbacks: every address is a /32 of its own")
            if stack:
                stack[-1][1].addChild(item)
            else:
                self.tree.addTopLevelItem(item)
            stack.append((network, item))
            if previous is not None and previous != UNSUBNETTED and getattr(previous, "id", None) == subnet.id:
                select_item = item
        outside = self.unsubnetted_addresses()
        if outside:
            item = QTreeWidgetItem(["(Not in any subnet)", "", str(len(outside))])
            item.setData(0, Qt.UserRole, UNSUBNETTED)
            item.setForeground(0, QColor(COLORS["warning"]))
            self.tree.addTopLevelItem(item)
            if previous == UNSUBNETTED:
                select_item = item
        self.tree.expandAll()
        for column in range(3):
            self.tree.resizeColumnToContents(column)
        self.tree.setColumnWidth(1, min(self.tree.columnWidth(1), 260))
        self.filter_tree()
        if select_item is None and self.tree.topLevelItemCount():
            select_item = self.tree.topLevelItem(0)
        self.tree.setCurrentItem(select_item)
        self.show_subnet()

    def unsubnetted_addresses(self):
        networks = [subnet.network for subnet in self.subnets]
        return [address for address in self.store.addresses(self.network_id)
                if not any(address.address.version == network.version and address.address in network
                           for network in networks)]

    def filter_tree(self):
        text = self.subnet_filter.text().strip().lower()

        def visit(item):
            children = [visit(item.child(index)) for index in range(item.childCount())]
            matches = not text or any(text in item.text(column).lower() for column in range(2)) or any(children)
            item.setHidden(not matches)
            return matches

        for index in range(self.tree.topLevelItemCount()):
            visit(self.tree.topLevelItem(index))

    def selected_subnet(self):
        item = self.tree.currentItem()
        value = item.data(0, Qt.UserRole) if item is not None else None
        return value if value != UNSUBNETTED else None

    def add_subnet(self, cidr=""):
        if not self.can_edit():
            return False
        dialog = SubnetDialog(self, self.store, self.network_id, cidr=cidr, extras=self.subnet_extras())
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.fill_tree(select=dialog.result_item)
            if dialog.extra_problem:
                set_hint(self.status_label, dialog.extra_problem, "warning")
        return bool(accepted)

    def subnet_extras(self):
        """(VLANs, placements) of the selected network's source, for a new subnet's role and VLAN; or None."""
        integration = hub(self.window)
        if integration is None or self.as_of is not None:
            return None
        _, vlans, placements, can_change = integration.stores(self.source)
        return (vlans, placements) if vlans is not None and can_change else None

    def tidy_after_delete(self, subnet, links, has_settings):
        """A subnet's gone: its VLAN links and its role and placement settings go too (they'd point at nothing)."""
        integration = hub(self.window)
        if integration is None:
            return ""
        from ..ipam.roles import AUTO
        _, vlans, placements, _ = integration.stores(self.source)
        try:
            for domain, vlan in links:
                current = vlans.vlan(domain.id, vlan.vlan)
                if current is not None and subnet.cidr in current.subnets:
                    vlans.set_vlan(domain.id, current.vlan, current.name, current.status,
                                   [cidr for cidr in current.subnets if cidr != subnet.cidr], current.description,
                                   current.fields)
            if has_settings:
                placements.set_role(self.network_id, subnet.cidr, AUTO)
                placements.set_placement(self.network_id, subnet.cidr)
        except IpamError as error:
            return f" Its VLAN links or settings weren't all removed: {error}"
        integration.invalidate()
        return ""

    def selected_subnets(self):
        """Every subnet selected in the list (Ctrl/Shift-click selects several)."""
        subnets = [item.data(0, Qt.UserRole) for item in self.tree.selectedItems()]
        return [subnet for subnet in subnets if subnet is not None and subnet != UNSUBNETTED]

    def edit_subnet(self):
        if len(self.selected_subnets()) > 1:
            self.edit_selected_subnets()
            return
        subnet = self.selected_subnet()
        if subnet is None or not self.can_edit():
            return
        dialog = SubnetDialog(self, self.store, self.network_id, self.store.subnet(subnet.id))
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.fill_tree(select=dialog.result_item)

    def delete_subnet(self):
        subnet = self.selected_subnet()
        if subnet is None:
            return
        count = self.store.count_addresses(self.network_id, subnet.network)
        try:
            from ..ipam.network_move import plan
            ties = plan(self.store, self.network_id, subnet.cidr, take_nested=False)
        except IpamError:
            ties = None
        if ties is not None and ties.problems:
            QMessageBox.warning(self, "Delete Subnet", f"{subnet.cidr} can't be deleted now. " + " ".join(ties.problems))
            return
        links = ties.links if ties is not None else []
        has_settings = ties is not None and bool(ties.roles or ties.placements)
        notes = []
        if links:
            notes.append("Its link to " + ", ".join(f"VLAN {vlan.vlan} ({domain.name})" for domain, vlan in links)
                         + " is removed too.")
        if has_settings:
            notes.append("Its role and placement settings are removed too.")
        box = QMessageBox(QMessageBox.Question, "Delete Subnet", f"Delete {subnet.cidr} ({subnet.name or 'no name'})?",
                          parent=self)
        if count or notes:
            box.setInformativeText(" ".join(([f"It has {count} recorded address{'' if count == 1 else 'es'}."]
                                             if count else []) + notes))
            with_addresses = box.addButton("Delete Subnet and Addresses", QMessageBox.DestructiveRole)
            box.addButton("Delete Just the Subnet", QMessageBox.AcceptRole)
        else:
            with_addresses = None
            box.addButton("Delete", QMessageBox.AcceptRole)
        box.addButton(QMessageBox.Cancel)
        box.exec_()
        if box.buttonRole(box.clickedButton()) == QMessageBox.RejectRole:
            return
        try:
            self.store.delete_subnet(subnet.id, with_addresses=box.clickedButton() is with_addresses)
        except IpamError as error:
            self.report(error, "Deleting the subnet")
            return
        problem = self.tidy_after_delete(subnet, links, has_settings) if links or has_settings else ""
        self.current = None
        self.fill_tree()
        if problem:
            set_hint(self.status_label, f"Deleted {subnet.cidr}.{problem}", "warning")

    def move_to_network(self):
        """Move the subnet chosen (with its addresses, and maybe the subnets inside it) to another network."""
        from .network_move_dialog import MoveToNetworkDialog
        subnet = self.selected_subnet()
        if subnet is None or not self.can_edit():
            return
        dialog = MoveToNetworkDialog(self, self, self.source, self.network_id, subnet)
        if not dialog.exec_():
            self.after_dialog()
            return
        source, _, network_id = dialog.moved_to.partition(":")
        integration = hub(self.window)
        if integration is not None:
            integration.invalidate()
        moved = len(dialog.done.subnets) if dialog.done is not None else 1
        self.go_to_subnet(source, network_id, subnet.cidr)  # Shown where it is now
        set_hint(self.status_label, f"Moved {subnet.cidr}" + (f" and the {moved - 1} subnets inside it" if moved > 2
                                                              else " and the subnet inside it" if moved == 2 else "")
                 + f" to {self.store.network(network_id).name}.", "success")

    def subnet_menu(self, position):
        if self.network_id is None:
            return
        menu = QMenu(self)
        subnet = self.selected_subnet()
        editable = self.can_edit()
        menu.addAction("Add Subnet...", self.add_subnet).setEnabled(editable)
        several = self.selected_subnets()
        if len(several) > 1:
            menu.addAction(f"Edit Selected Subnets ({len(several)})...", self.edit_selected_subnets).setEnabled(
                editable)
            menu.exec_(self.tree.viewport().mapToGlobal(position))
            return
        if subnet is not None:
            menu.addAction("Edit...", self.edit_subnet).setEnabled(editable)
            menu.addAction("Delete...", self.delete_subnet).setEnabled(editable)
            menu.addAction("Move to Another Network...", self.move_to_network).setEnabled(editable)
            menu.addSeparator()
            menu.addAction("Copy Subnet", lambda: QApplication.clipboard().setText(subnet.cidr))
            menu.addAction("Open in Subnet Calculator", lambda: self.open_calculator(subnet.cidr))
            menu.addAction("Sweep Subnet", self.sweep_subnet).setEnabled(subnet.network.version == 4)
            menu.addAction("Find Free Blocks...", self.find_free_blocks).setEnabled(self.as_of is None)
            menu.addAction("History...", lambda: self.show_history("subnet", subnet)).setEnabled(self.as_of is None)
        links = self.other_page_actions(menu, subnet=subnet) if subnet is not None else {}
        chosen = menu.exec_(self.tree.viewport().mapToGlobal(position))
        if chosen in links:
            self.open_link(links[chosen])

    # ----------------------------------------------------------------- Sweeping a subnet here

    def sweep_subnet(self):
        """Sweep the selected subnet on this page (or stop the sweep running), showing what answers as it goes."""
        from ..sweep import LARGE_SWEEP_HOSTS, local_networks, sweep_hosts
        from .sweep_tab import SweepThread
        if self.sweep_worker is not None:
            self.sweep_worker.stop()
            self.sweep_button.setEnabled(False)
            self.sweep_status.setText("Stopping...")
            return
        subnet = self.selected_subnet()
        if subnet is None:
            return
        try:
            network, hosts = sweep_hosts(subnet.cidr)
            if subnet.loopbacks:
                hosts = list(network)  # Each is a host route of its own, the first and last included
        except ValueError as error:
            set_hint(self.status_label, str(error), "error")
            return
        if len(hosts) > LARGE_SWEEP_HOSTS and QMessageBox.question(
                self, "Large Sweep", f"{network} has {len(hosts):,} addresses, which will take a while.\n\n"
                                     "Sweep it anyway?") != QMessageBox.Yes:
            return
        sweep_page = self.window.sweep_tab  # Same settings as the Sweep page
        snapshot = getattr(self.window, "snapshot", None)
        arp_networks = [local for local in local_networks(snapshot) if local.overlaps(network)] if snapshot else []
        block = subnet.network
        results = self.sweep_results(self.source, self.network_id)
        results.start(block)
        self.sweeping = (self.source, self.network_id, block)
        self.sweep_worker = SweepThread(hosts, sweep_page.workers_input.value(), sweep_page.timeout_input.value(),
                                        arp_networks, sweep_page.arp_check.isChecked(),
                                        sweep_page.names_check.isChecked(), self)
        self.sweep_worker.sweep_results, self.sweep_worker.sweep_block = results, block  # For its handlers
        self.sweep_worker.found.connect(self.on_sweep_found)
        self.sweep_worker.host_details.connect(self.on_sweep_name)
        self.sweep_worker.progress.connect(self.on_sweep_progress)
        self.sweep_worker.looking_up_names.connect(self.on_sweep_looking_up_names)
        self.sweep_worker.finished_sweep.connect(self.on_sweep_finished)
        self.sweep_worker.finished.connect(self.on_sweep_thread_done)
        self.sweep_progress.setRange(0, len(hosts) * SWEEP_PASSES)
        self.sweep_progress.setValue(0)
        self.sweep_progress.setVisible(True)
        self.sweep_row.setVisible(True)
        self.sweep_status.setText(f"Sweeping {network}...")
        if hasattr(self.window, "set_busy"):
            self.window.set_busy("ipam-sweep", f"Sweeping {network}")
        self.sweep_worker.start()
        log.info("Sweeping %s from the IP Addresses page", network)
        self.refresh_current()

    # Worker signals go to methods, never lambdas: a lambda's signal still waiting to be delivered when its sender is freed
    # crashes Qt, where a method's is dropped with the page

    def on_sweep_found(self, address, hit):
        self.sender().sweep_results.found(address, hit.rtt, hit.mac)
        self.sweep_refresh.start(300)

    def on_sweep_name(self, address, name, mac):
        self.sender().sweep_results.add_name(address, name, mac)
        self.sweep_refresh.start(300)

    def on_sweep_looking_up_names(self, remaining):
        self.sweep_status.setText(f"Looking up names for {remaining} hosts...")

    def on_sweep_progress(self, done, total, pass_number, remaining):
        self.sweep_progress.setValue(done)
        results = self.sweeps.get(f"{self.sweeping[0]}:{self.sweeping[1]}") if self.sweeping else None
        found = sum(1 for address in results.hosts if address in self.sweeping[2] and
                    (results.result(address) or ("",))[0] == "answered") if results is not None else 0
        what = f"{remaining:,} addresses" if pass_number == 1 else f"retrying {remaining:,}"
        self.sweep_status.setText(f"Pass {pass_number} of {SWEEP_PASSES}: {what} · {found} answered")

    def on_sweep_finished(self, message):
        results, block = self.sender().sweep_results, self.sender().sweep_block
        complete = self.sweep_worker is not None and not self.sweep_worker.stopping
        swept = [results.finish(block)] if complete else []
        if not complete:
            results.stop()
        results.message = (block, message if complete else f"{message} Addresses not reached yet aren't marked.")
        self.sweep_progress.setVisible(False)
        log.info("IP Addresses page: %s", message)
        if self.sweeping:
            self.save_sightings(self.sweeping[0], self.sweeping[1], results.take_unsaved(), swept)

    def on_sweep_thread_done(self):
        self.sweep_worker.deleteLater()
        self.sweep_worker = None
        if self.sweeping:  # Stopped before it finished: keep what it found anyway
            results = self.sweeps.get(f"{self.sweeping[0]}:{self.sweeping[1]}")
            if results is not None:
                results.stop()
                self.save_sightings(self.sweeping[0], self.sweeping[1], results.take_unsaved(), [])
        self.sweeping = None
        if hasattr(self.window, "clear_busy"):
            self.window.clear_busy("ipam-sweep")
        if self.local_store is not None:
            self.refresh_current()
        self.update_buttons()

    def sweep_findings(self):
        """(addresses answering now that aren't in IPAM, [(address, MAC)] answering with a different MAC) in the
        selected subnet, from the latest sweeps."""
        results = self.model.sweep
        subnet = self.selected_subnet()
        if results is None or subnet is None or self.as_of is not None:
            return [], []
        block = subnet.network
        missing, different = [], []
        for address in sorted(results.hosts):
            current = results.current(address)
            if current is None or address not in block or self.model.special.get(address) in ("Network", "Broadcast"):
                continue
            mac = current[1]
            record = self.model.recorded.get(address)
            if record is None:
                missing.append(address)
            elif mac and record.mac and normalize_mac(mac) != normalize_mac(record.mac):
                different.append((address, mac))
        return missing, different

    def show_sweep_actions(self):
        missing, different = self.sweep_findings()
        editable = self.can_edit_addresses()
        self.record_found_button.setText(f"Record Answering Devices ({len(missing)})...")
        self.record_found_button.setVisible(bool(missing))
        self.record_found_button.setEnabled(editable)
        self.update_macs_button.setText(f"Update MACs ({len(different)})...")
        self.update_macs_button.setVisible(bool(different))
        self.update_macs_button.setEnabled(editable)
        running = self.sweep_worker is not None
        self.sweep_progress.setVisible(running)
        subnet = self.selected_subnet()
        results = self.model.sweep
        if not running:  # How the last sweep of this subnet ended, if it was swept
            message = results.message if results is not None else None
            self.sweep_status.setText(message[1] if message and subnet is not None and
                                      subnet.network.subnet_of(message[0]) else "")
        self.sweep_row.setVisible(running or bool(missing or different) or bool(self.sweep_status.text()))

    def record_found(self):
        missing, _ = self.sweep_findings()
        if not missing:
            return
        results = self.model.sweep
        listing = "\n".join(f"{address}  {results.names.get(address, '')}  {results.hosts[address][1]}"
                            for address in missing[:15])
        more = f"\n... and {len(missing) - 15} more" if len(missing) > 15 else ""
        where = " (sent to the IPAM server now, or when it's back)" if self.source == TEAM else ""
        if QMessageBox.question(self, "Record Answering Devices",
                                f"Record these {len(missing)} devices as used{where}?\n\n{listing}{more}") != \
                QMessageBox.Yes:
            return
        recorded = 0
        try:
            with self.store.transaction():
                for address in missing:
                    self.store.set_address(self.network_id, str(address), USED, results.names.get(address, ""),
                                           results.hosts[address][1])
                    recorded += 1
        except IpamError as error:
            self.report(error, f"Recording all of them ({recorded} of {len(missing)} were recorded)")
        set_hint(self.status_label, f"Recorded {recorded} device{'' if recorded == 1 else 's'} found by the sweep.",
                 "success")
        self.after_dialog()
        self.refresh_current()

    def update_macs(self):
        _, different = self.sweep_findings()
        if not different:
            return
        listing = "\n".join(f"{address}  {self.model.recorded[address].mac} → {mac}" for address, mac in different)
        if QMessageBox.question(self, "Update MACs", f"Update these MAC addresses in IPAM?\n\n{listing}") != \
                QMessageBox.Yes:
            return
        try:
            for address, mac in different:
                self.update_mac_from_sweep(address, mac, refresh=False)
        except IpamError as error:
            self.report(error, "Updating the MAC addresses")
        self.after_dialog()
        self.refresh_current()

    def update_mac_from_sweep(self, address, mac, refresh=True):
        record = self.store.address(self.network_id, str(address))
        self.store.set_address(self.network_id, str(address), record.status, record.name, mac, record.description,
                               record.fields)
        if refresh:
            self.after_dialog()
            self.refresh_current(address)

    def record_from_sweep(self, address):
        results = self.model.sweep
        dialog = AddressDialog(self, self.store, self.network_id, str(address), None,
                               name=results.names.get(address, ""), mac=results.hosts[address][1])
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.refresh_current(address)

    def open_calculator(self, cidr):
        self.window.navigator.setCurrentWidget(self.window.subnet_tab)
        self.window.subnet_tab.calculate_subnet(cidr)

    # ----------------------------------------------------------------- Addresses

    def show_subnet(self):
        item = self.tree.currentItem()
        self.current = item.data(0, Qt.UserRole) if item is not None else None
        if self.current is None:
            self.model.load(None, {}, {}, [], False)
            self.subnet_label.setText("")
        elif self.current == UNSUBNETTED:
            recorded = {address.address: address for address in self.unsubnetted_addresses()}
            self.model.load(None, recorded, {}, [], False, places=self.map_places())
            self.subnet_label.setText("Recorded addresses outside every subnet in this network. Add a subnet for "
                                      "them, or mark them free.")
        else:
            subnet = self.current
            network = subnet.network
            recorded = {address.address: address for address in self.store.addresses(self.network_id, network)}
            nested = [(other.network, other.name) for other in self.subnets if other.id != subnet.id and
                      other.network.version == network.version and other.network.subnet_of(network)]
            every = not self.hide_free_check.isChecked() and network.num_addresses <= LIST_EVERY_ADDRESS_UP_TO
            now = self.as_of is None  # Pending changes and sweeps belong to the present, not a view of the past
            pending = self.team.pending_ips(self.network_id) if now and self.source == TEAM and self.team else ()
            sweep = self.sweep_results(self.source, self.network_id) if now else None
            self.model.load(network, recorded, subnet.special_addresses(), nested, every, pending, sweep,
                            self.map_places())
            parts = [f"<b>{subnet.cidr}</b>"]
            if subnet.name:
                parts.append(subnet.name)
            if subnet.gateway:
                parts.append(f"gateway {subnet.gateway}")
            if subnet.loopbacks:
                parts.append(f"loopbacks, each /{network.first.max_prefixlen}")
            else:
                parts.append(f"netmask {network.netmask}" if network.version == 4 else
                             f"{network.num_addresses:,} addresses")
            parts.append(f"{len(recorded)} of {usable_count(network, subnet.loopbacks):,} recorded")
            swept = sweep.swept_at(network.network_address) if sweep is not None else None
            if swept:
                answered = sum(1 for address in sweep.hosts if address in network and
                               (sweep.result(address) or ("",))[0] == "answered")
                silent = sum(1 for address, record in recorded.items() if record.status != RESERVED and
                             (sweep.result(address) or ("",))[0] == "silent")
                parts.append(f"swept {when_text(swept)}: {answered} answered, {silent} recorded but silent")
            parts += [f"{name}: {value}" for name, value in subnet.fields.items()]
            if subnet.description:
                parts.append(subnet.description)
            if network.num_addresses > LIST_EVERY_ADDRESS_UP_TO and not self.hide_free_check.isChecked():
                parts.append("<i>(too large to list every address, so only those recorded are shown)</i>")
            self.subnet_line = "   ·   ".join(parts)
            self.show_subnet_line(subnet)
        self.table.setColumnHidden(COL_MAP, self.model.places_from is None)
        self.map_stale = False
        self.table.resizeColumnToContents(0)
        metrics = self.table.fontMetrics()
        for column, sample in ((1, "Gateway · Reserved"), (COL_SWEEP, "No answer · yesterday 00:00 · last seen Sep 00"), (3, "M" * 16),
                               (4, "00-00-00-00-00-00")):
            self.table.setColumnWidth(column, metrics.horizontalAdvance(sample) + 24)
        self.update_buttons()

    def selected_addresses(self):
        return [self.model.address_at(index.row()) for index in self.table.selectionModel().selectedRows()]

    def update_buttons(self):
        editable = self.can_edit()
        has_subnet = self.selected_subnet() is not None
        self.edit_subnet_button.setEnabled(has_subnet and editable)
        self.delete_subnet_button.setEnabled(has_subnet and editable)
        self.move_subnet_button.setEnabled(has_subnet and editable and len(self.selected_subnets()) <= 1)
        subnet = self.selected_subnet()
        # Sweep is IPv4 only, and checks the present (not a view of the past); while one runs, the button stops it
        running = self.sweep_worker is not None
        self.sweep_button.setText("Stop Sweep" if running else "Sweep Subnet")
        self.sweep_button.setEnabled(running or (subnet is not None and subnet.network.version == 4 and
                                                 self.as_of is None))
        self.show_sweep_actions()
        addresses_editable = self.can_edit_addresses()
        self.next_free_button.setEnabled(has_subnet and addresses_editable)
        selected = self.selected_addresses()
        self.edit_address_button.setEnabled(bool(selected) and addresses_editable)
        self.edit_address_button.setText(f"Edit {len(selected)}..." if len(selected) > 1 else "Edit...")
        self.free_button.setEnabled(addresses_editable and any(address in self.model.recorded
                                                               for address in selected))
        self.update_permissions()

    def edit_address(self, address=None):
        if address is None:
            selected = self.selected_addresses()
            if len(selected) > 1:
                self.edit_selected_addresses()
                return
            if len(selected) != 1:
                return
            address = selected[0]
        note = ""
        special = self.model.special.get(address)
        if special and address not in self.model.recorded:
            note = f"This is the subnet's {special.lower()} address."
        if not self.can_edit_addresses():
            return
        record = self.store.address(self.network_id, address)
        dialog = AddressDialog(self, self.store, self.network_id, str(address), record, note)
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.refresh_current(address)

    def use_next_free(self):
        subnet = self.selected_subnet()
        if subnet is None:
            return
        address = self.store.next_free(subnet)
        if address is None:
            set_hint(self.status_label, f"{subnet.cidr} has no free addresses left.", "warning")
            return
        dialog = AddressDialog(self, self.store, self.network_id, str(address))
        accepted = dialog.exec_()
        self.after_dialog()
        if accepted:
            self.refresh_current(address)
            set_hint(self.status_label, f"Recorded {address} in {subnet.cidr}.", "success")

    def free_addresses(self):
        recorded = [address for address in self.selected_addresses() if address in self.model.recorded]
        if not recorded:
            return
        names = ", ".join(str(address) for address in recorded[:5]) + (" ..." if len(recorded) > 5 else "")
        if QMessageBox.question(self, "Mark Free", f"Mark {names} free, forgetting what's recorded?") != \
                QMessageBox.Yes:
            return
        try:
            with self.store.transaction():
                for address in recorded:
                    self.store.free_address(self.network_id, address)
        except IpamError as error:
            self.report(error, "Marking them free")
        self.refresh_current()

    def refresh_current(self, address=None):
        """Show changes to the current subnet's addresses, keeping the scroll position and selection."""
        scroll = self.table.verticalScrollBar().value()
        self.fill_tree()
        self.table.verticalScrollBar().setValue(scroll)
        if address is not None:
            self.select_address(address)

    def select_address(self, address):
        if self.model.rows is not None:
            row = self.model.rows.index(address) if address in self.model.rows else -1
        elif address.version == self.model.network.version:
            row = int(address) - self.model.first  # Every address is listed, so the row is its offset
        else:
            row = -1
        if 0 <= row < self.model.rowCount():
            self.table.selectRow(row)
            self.table.scrollTo(self.model.index(row, 0), QAbstractItemView.PositionAtCenter)

    def address_menu(self, position):
        index = self.table.indexAt(position)
        if not index.isValid():
            return
        if not self.table.selectionModel().isRowSelected(index.row(), index.parent()):
            self.table.selectRow(index.row())
        selected = self.selected_addresses()
        if not selected:
            return
        menu = QMenu(self)
        host_actions = {}
        host = str(selected[0])
        if len(selected) == 1:
            menu.addAction("Edit...", self.edit_address).setEnabled(self.can_edit_addresses())
        else:
            menu.addAction(f"Edit Selected ({len(selected)})...", self.edit_selected_addresses).setEnabled(
                self.can_edit_addresses())
        for status, label in STATUSES.items():
            menu.addAction(f"Mark {label}", lambda status=status: self.mark_addresses(status)).setEnabled(
                self.can_edit_addresses())
        if any(address in self.model.recorded for address in selected):
            menu.addAction("Mark Free", self.free_addresses).setEnabled(self.can_edit_addresses())
        found = self.model.sweep.hosts.get(selected[0]) if self.model.sweep is not None and len(selected) == 1 \
            else None
        if found is not None:
            record = self.model.recorded.get(selected[0])
            if record is None:
                menu.addAction("Record from Sweep...", lambda: self.record_from_sweep(selected[0])).setEnabled(
                    self.can_edit_addresses())
            elif found[1] and record.mac and normalize_mac(found[1]) != normalize_mac(record.mac):
                menu.addAction(f"Update MAC from Sweep ({found[1]})",
                               lambda: self.update_mac_from_sweep(selected[0], found[1])).setEnabled(
                    self.can_edit_addresses())
        menu.addAction("Copy", lambda: QApplication.clipboard().setText(
            "\n".join(self.model.data(self.model.index(index.row(), 0)) + "\t" +
                      self.model.data(self.model.index(index.row(), 3)) for index in
                      self.table.selectionModel().selectedRows())))
        if len(selected) == 1:
            menu.addSeparator()
            # Its saved sessions are found by the address or its recorded name; a new one is named after the address
            # and suggests the network and subnet as its folder
            record = self.model.recorded.get(selected[0])
            name = record.name.strip() if record is not None else ""
            host_actions = HostActions(self.window, self).add_to(
                menu, host, aliases=[name] if name else (), name=name, folder=self.session_folder(),
                leave_out=("Show in IPAM",))
            menu.addSeparator()
            menu.addAction("History...", lambda: self.show_history("address", host)).setEnabled(self.as_of is None)
        links = self.other_page_actions(menu, address=host) if len(selected) == 1 else {}
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in links:
            self.open_link(links[chosen])
        elif chosen in host_actions:
            host_actions[chosen]()

    def session_folder(self):
        """The folder to suggest for a new session to an address: the network and subnet, as Network/Subnet."""
        network, subnet = self.network(), self.selected_subnet()
        parts = [network.name if network is not None else "", subnet.name if subnet is not None else ""]
        return "/".join(part.strip().replace("/", "-") for part in parts if part and part.strip())

    def usable_selection(self):
        """The selected addresses a device can have (not a subnet's network or broadcast address)."""
        return [address for address in self.selected_addresses()
                if self.model.special.get(address) not in ("Network", "Broadcast", "Subnet router anycast")]

    def edit_selected_addresses(self):
        addresses = self.usable_selection()
        if not addresses or not self.can_edit_addresses():
            return
        dialog = BulkAddressDialog(self, len(addresses))
        if dialog.exec_() and dialog.values():
            self.change_addresses(addresses, dialog.values())

    def mark_addresses(self, status):
        addresses = self.usable_selection()
        if addresses and self.can_edit_addresses():
            self.change_addresses(addresses, {"status": status})

    def change_addresses(self, addresses, values):
        changed, failed = apply_to_addresses(self.store, self.network_id, addresses, values)
        if failed:
            self.report(IpamError(f"{len(failed)} of {len(addresses)} couldn't be changed: {failed[0][1]}"),
                        "Changing them all")
        else:
            set_hint(self.status_label, f"Changed {changed} address{'' if changed == 1 else 'es'}.", "success")
        self.after_dialog()
        self.refresh_current(addresses[0])

    def edit_selected_subnets(self):
        subnets = self.selected_subnets()
        if not subnets or not self.can_edit():
            return
        dialog = BulkSubnetDialog(self, len(subnets), self.store.detail_names())
        if not dialog.exec_() or not dialog.values():
            return
        changed, failed = apply_to_subnets(self.store, [self.store.subnet(subnet.id) for subnet in subnets],
                                           dialog.values())
        if failed:
            self.report(IpamError(f"{len(failed)} of {len(subnets)} couldn't be changed: {failed[0][1]}"),
                        "Changing them all")
        else:
            set_hint(self.status_label, f"Changed {changed} subnet{'' if changed == 1 else 's'}.", "success")
        self.after_dialog()
        self.fill_tree()

    def find_free_blocks(self):
        subnet = self.selected_subnet()
        if subnet is not None:
            FreeBlocksDialog(self, self.store, subnet, self.add_subnet).exec_()

    # ----------------------------------------------------------------- Checking and comparing

    def check_data(self):
        network = self.network()
        if network is None:
            return
        dialog = CheckDataDialog(self, self.store, network, self.go_to_finding)
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        dialog.show()  # Not modal: double-clicking a finding shows it here, with the list still open

    def go_to_finding(self, subnet, ip):
        self.subnet_filter.clear()
        self.search_input.clear()
        self.right_stack.setCurrentIndex(0)
        self.fill_tree(select=subnet if subnet is not None else UNSUBNETTED)
        if ip:
            self.select_address(ipaddress.ip_address(ip))

    def compare_with_workbook(self):
        network = self.network()
        if network is None:
            return
        if not self.can_edit():
            set_hint(self.status_label, OFFLINE_NOTE, "warning")
            return
        path, _ = QFileDialog.getOpenFileName(self, f"Compare {network.name} with a Workbook", "",
                                              "Spreadsheets (*.xlsx *.xlsm *.csv);;All files (*)")
        if not path:
            return
        set_hint(self.status_label, f"Reading {os.path.basename(path)}...", "info")

        def read():
            sheets = []
            for title, rows in read_pages(path):
                try:
                    sheets.append(parse_page(title, rows))
                except SpreadsheetError:
                    pass
            return sheets

        run_in_background(read, lambda sheets: self.review_comparison(path, network, sheets), self.import_failed)

    def review_comparison(self, path, network, sheets):
        from ..ipam.compare import compare_network
        set_hint(self.status_label, "", "info")
        if not sheets:
            set_hint(self.status_label, f"No addressing pages in {os.path.basename(path)}.", "error")
            return
        chooser = ImportDialog(self, self.live_store, os.path.basename(path), sheets, compare_with=network)
        if not chooser.exec_() or chooser.compare_plan is None:
            return
        page, plan = chooser.compare_plan
        changes = compare_network(self.live_store, network.id, plan)
        dialog = CompareDialog(self, self.live_store, network, page, changes)
        dialog.exec_()
        self.after_dialog()
        self.refresh_everything()
        if dialog.made:
            set_hint(self.status_label, f"Brought {dialog.made} change{'' if dialog.made == 1 else 's'} in from "
                                        f"{page}.", "success")

    def export_workbook(self, every):
        from ..ipam.workbook import export_workbook, outside_subnets
        network = self.network()
        if network is None:
            return
        store = self.store
        networks = store.networks() if every else [network]
        name = "IPAM" if every else network.name
        path, _ = QFileDialog.getSaveFileName(self, "Export to Workbook", f"{name}.xlsx", "Excel workbooks (*.xlsx)")
        if not path:
            return
        try:
            export_workbook(path, [(store, item) for item in networks])
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save {path}: {error.strerror or error}", "error")
            return
        left_out = sum(len(outside_subnets(store, item)) for item in networks)
        note = (f" {left_out} recorded address{'' if left_out == 1 else 'es'} outside every subnet had nowhere to "
                "go in the workbook layout (Check Data lists them)." if left_out else "")
        what = f"{len(networks)} networks" if every else network.name
        set_hint(self.status_label, f"Exported {what} to {path}.{note}", "warning" if left_out else "success")

    # ----------------------------------------------------------------- Finding

    def search(self):
        if not self.open_store():
            return
        text = self.search_input.text().strip()
        if not text:
            self.right_stack.setCurrentIndex(0)
            return
        options = dict(self.search_kind_combo.currentData(), match=self.search_match_combo.currentData())
        search_in = self.search_network_combo.currentData()
        where = "any network"
        if search_in:
            options["network_id"] = search_in.split(":", 1)[1]
            where = self.search_network_combo.currentText().strip()
        results = []
        for source, store in ((TEAM, self.team), (LOCAL, self.local_store)):
            if store is not None and (not search_in or search_in.startswith(f"{source}:")):
                results += [(source, network, subnet, address)
                            for network, subnet, address in store.search(text, **options)]
        self.results_table.setSortingEnabled(False)
        self.results_table.setRowCount(len(results))
        for row, (source, network, subnet, address) in enumerate(results):
            if self.team is not None:
                network = type(network)(**{**network.__dict__, "name": f"{network.name} "
                                                                        f"({'Tribe' if source == TEAM else 'Local'})"})
            status = STATUSES.get(address.status, "Free") if address is not None else ""
            values = [network.name, subnet.cidr if subnet else "", subnet.name if subnet else "",
                      address.ip if address else "", status, address.name if address else "",
                      ", ".join(f"{name}: {value}" for name, value in
                                (address.fields if address else subnet.fields if subnet else {}).items()),
                      (address.description if address else subnet.description if subnet else "")]
            for column, value in enumerate(values):
                sort_key = None
                if column == 3 and value:
                    sort_key = (address.address.version, int(address.address))
                elif column == 1 and value:
                    sort_key = (subnet.network.version, int(subnet.network.network_address))
                item = SortableTableItem(value, sort_key, (source, network, subnet, address))
                self.results_table.setItem(row, column, item)
        self.results_table.setSortingEnabled(True)
        self.results_table.resizeColumnsToContents()
        count = len(results)
        kind = self.search_kind_combo.currentText().lower()
        what = "" if kind == "everything" else f" ({kind})"
        shown = repr(text) if self.search_match_combo.currentData() == ANYWHERE else \
            f"{self.search_match_combo.currentText()} {text!r}"  # Telephony Rng '68890'
        self.results_label.setText(f"{count} result{'' if count == 1 else 's'} for {shown}{what} in {where}"
                                   if count else f"No {kind} match {shown} in {where}." if what else
                                   f"Nothing matches {shown} in {where}.")
        self.right_stack.setCurrentIndex(1)

    def search_again(self):
        """Changing what to find, or where, redoes a search already showing."""
        if self.search_input.text().strip() and self.right_stack.currentIndex() == 1:
            self.search()

    def go_to_result(self, row, _column):
        source, network, subnet, address = self.results_table.item(row, 0).data_object
        index = self.network_combo.findData(f"{source}:{network.id}")
        self.network_combo.setCurrentIndex(index)
        self.subnet_filter.clear()
        self.fill_tree(select=subnet if subnet is not None else UNSUBNETTED)
        self.search_input.clear()
        self.right_stack.setCurrentIndex(0)
        if address is not None:
            self.select_address(address.address)

    # ----------------------------------------------------------------- Import and export

    def import_spreadsheet(self):
        if not self.open_store():
            return
        path, _ = QFileDialog.getOpenFileName(self, "Import Addressing Spreadsheet", "",
                                              "Spreadsheets (*.xlsx *.xlsm *.csv);;All files (*)")
        if not path:
            return
        set_hint(self.status_label, f"Reading {os.path.basename(path)}...", "info")
        self.import_button.setEnabled(False)

        def read():
            sheets, skipped = [], []
            for title, rows in read_pages(path):
                try:
                    sheets.append(parse_page(title, rows))
                except SpreadsheetError as error:
                    log.info("Import: skipping page: %s", error)
                    skipped.append(title)
            return sheets, skipped

        run_in_background(read, lambda result: self.review_import(path, *result), self.import_failed)

    def import_failed(self, error):
        self.import_button.setEnabled(True)
        log.warning("Import failed: %s", error)
        set_hint(self.status_label, f"Couldn't import: {error}", "error")

    def review_import(self, path, sheets, skipped):
        self.import_button.setEnabled(True)
        if not sheets:
            message = (f"No addressing pages in {os.path.basename(path)}: no page has a header row with Subnet and "
                       f"Mask columns (pages: {', '.join(skipped)}).")
            log.warning("Import: %s", message)
            set_hint(self.status_label, message, "error")
            return
        set_hint(self.status_label, "", "info")
        admin = self.team is not None and self.team.admin
        target = self.team if admin else self.local_store
        dialog = ImportDialog(self, target, os.path.basename(path), sheets, skipped, to_server=admin,
                              team_connected=self.team is not None)
        if dialog.exec_() and dialog.imported:
            names = ", ".join(network.name for network in dialog.imported)
            self.network_id = None
            self.fill_networks(f"{TEAM if admin else LOCAL}:{dialog.imported[0].id}")
            if admin:
                set_hint(self.status_label, f"Imported {names} to the IPAM server: every connected laptop has them "
                                            "now.", "success")
            else:
                set_hint(self.status_label, f"Imported {names} to this computer only. They are NOT shared with the "
                                            "tribe (only the IPAM server can import tribe networks).", "warning")

    def export_csv(self):
        network = self.network()
        if network is None:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Network", f"{network.name}.csv", "CSV files (*.csv)")
        if not path:
            return
        from ..ipam.workbook import csv_rows
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as file:
                csv.writer(file).writerows(csv_rows(self.store, network.id, self.subnets))
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save {path}: {error.strerror or error}", "error")
            return
        set_hint(self.status_label, f"Exported {network.name} to {path}.", "success")
