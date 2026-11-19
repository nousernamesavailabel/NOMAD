"""The "Compare with IPAM" bar on the Sweep and ARP pages: which IPAM network the devices found belong to, what IPAM
says about each (for the page's IPAM column), and one-click recording of what's missing."""
import ipaddress
import logging

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton, \
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget

from ..ipam.reconcile import MAC_DIFFERS, NOT_RECORDED, PROXY_ARP, RECORDED, RESERVED_IN_USE, candidate_networks, \
    compare, proxy_arp, silent
from ..ipam.store import USED, IpamError
from .common import set_hint
from .ipam_dialogs import AddressDialog
from .theme import COLORS

log = logging.getLogger(__name__)

NO_COMPARISON = ""
STATE_COLORS = {RECORDED: "success", NOT_RECORDED: "warning", MAC_DIFFERS: "error", RESERVED_IN_USE: "warning",
                PROXY_ARP: "muted"}


def finding_color(finding):
    return QColor(COLORS[STATE_COLORS.get(finding.state, "text")]) if finding is not None else None


class IpamComparison(QWidget):
    """Compares a page's devices ({ip: (mac, name)}) with a chosen IPAM network. Emits `updated` after each
    comparison, so the page can refresh its IPAM column from `findings`."""
    updated = pyqtSignal()

    def __init__(self, window, allow_silent=True):
        super().__init__(window)
        self.window = window
        self.allow_silent = allow_silent
        self.found = {}  # {ip: (mac, name)}
        self.arp_only = set()  # The ips that answered ARP but not ping (a sweep's), to tell proxy ARP apart
        self.proxied = {}  # {ip: whose MAC answered for it, or ""}: only a router's proxy ARP answered there
        self.ranges = []  # Blocks swept in full, for addresses that didn't answer
        self.complete = False  # Whether every address in `ranges` was tried (a finished sweep)
        self.findings = {}  # {ip: Finding}
        self.quiet = []  # Recorded, but didn't answer
        self.chosen = None  # "source:network id" the user picked
        self.pending_compare = QTimer(self)
        self.pending_compare.setSingleShot(True)
        self.pending_compare.timeout.connect(self.compare_now)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(QLabel("Compare with IPAM:"))
        self.network_combo = QComboBox()
        self.network_combo.setMinimumWidth(240)
        self.network_combo.setToolTip("The IPAM network these devices are on (the same range can be in more than "
                                      "one separate network). Networks holding the most of these addresses come "
                                      "first.")
        layout.addWidget(self.network_combo)
        self.summary_label = QLabel()
        layout.addWidget(self.summary_label)
        layout.addStretch()
        self.record_button = QPushButton()
        self.record_button.setToolTip("Record every device IPAM doesn't have yet, as used, with its host name and "
                                      "MAC address.")
        self.silent_button = QPushButton()
        self.silent_button.setToolTip("Addresses IPAM records as used that didn't answer: they may be switched off, "
                                      "firewalled or gone.")
        layout.addWidget(self.record_button)
        layout.addWidget(self.silent_button)
        self.network_combo.activated.connect(self.on_network_picked)
        self.record_button.clicked.connect(self.record_missing)
        self.silent_button.clicked.connect(self.show_silent)
        self.show_summary()

    # ----------------------------------------------------------------- Feeding it

    @property
    def ipam(self):
        return self.window.ipam_tab

    def set_devices(self, found, ranges=(), complete=False, soon=True, arp_only=()):
        """The devices on the page (arp_only: those that answered ARP but not ping). Compares shortly after (so a
        running sweep isn't re-compared per host)."""
        self.found, self.ranges, self.complete = dict(found), list(ranges), complete
        self.arp_only = set(arp_only)
        if soon:
            self.pending_compare.start(400)
        else:
            self.compare_now()

    def selection(self):
        """(source, store, network id) to compare with, or None."""
        data = self.network_combo.currentData()
        if not data:
            return None
        source, network_id = data.split(":", 1)
        store = self.ipam.store_for(source)
        return (source, store, network_id) if store is not None else None

    def on_network_picked(self):
        self.chosen = self.network_combo.currentData()
        self.compare_now()

    def fill_networks(self):
        candidates = candidate_networks(self.ipam.ipam_stores(), list(self.found)) if self.found else []
        current = self.chosen  # Only what the user picked; otherwise the best match (first)
        if current and all(f"{source}:{network.id}" != current for source, network, _ in candidates):
            source, network_id = current.split(":", 1)
            store = self.ipam.store_for(source)
            try:
                if store is not None:
                    candidates.append((source, store.network(network_id), 0))
            except IpamError:  # Deleted since
                pass
        self.network_combo.blockSignals(True)
        self.network_combo.clear()
        tag = self.ipam.team is not None
        for source, network, held in candidates:
            label = f"{network.name}   ({'Tribe' if source == 'team' else 'Local'})" if tag else network.name
            self.network_combo.addItem(f"{label}   · {held} of these", f"{source}:{network.id}")
        self.network_combo.addItem("Don't compare", NO_COMPARISON)
        index = self.network_combo.findData(current) if current is not None else -1
        self.network_combo.setCurrentIndex(index if index >= 0 else 0)
        self.network_combo.blockSignals(False)

    def compare_now(self):
        self.pending_compare.stop()
        if getattr(self.window, "ipam_tab", None) is None:  # Still starting up
            return
        try:
            self.fill_networks()
            selection = self.selection()
            if selection is None:
                self.findings, self.quiet = {}, []
                self.proxied = proxy_arp(self.found, self.arp_only)  # What the sweep alone shows
            else:
                _, store, network_id = selection
                self.findings = compare(self.found, store, network_id, self.arp_only)
                self.proxied = proxy_arp(self.found, self.arp_only,
                                         {ip: finding.record for ip, finding in self.findings.items()})
                # A recorded address only proxy ARP answered for is as silent as one nothing answered for
                answered = [ip for ip in self.found if ip not in self.proxied]
                self.quiet = silent(store, network_id, answered, self.ranges) \
                    if self.allow_silent and self.complete else []
        except IpamError as error:
            log.warning("Comparing with IPAM failed: %s", error)
            self.findings, self.quiet = {}, []
            self.proxied = proxy_arp(self.found, self.arp_only)
        self.show_summary()
        self.updated.emit()

    def show_summary(self):
        counts = {state: 0 for state in STATE_COLORS}
        for finding in self.findings.values():
            counts[finding.state] += 1
        missing = counts[NOT_RECORDED]
        self.record_button.setText(f"Record Not in IPAM ({missing})...")
        self.record_button.setEnabled(bool(missing) and self.selection() is not None and self.can_change())
        self.silent_button.setText(f"Recorded but Silent ({len(self.quiet)})...")
        self.silent_button.setVisible(self.allow_silent)
        self.silent_button.setEnabled(bool(self.quiet))
        if not self.findings:
            text = ""
            if self.found and self.network_combo.count() <= 1:
                text = "None of these addresses are in an IPAM network."
            elif self.found and self.selection() is None:
                text = "Not compared with IPAM."
            set_hint(self.summary_label, text, "info")
            return
        parts = [f"{counts[RECORDED]} in IPAM"]
        if missing:
            parts.append(f"{missing} not in IPAM")
        if counts[MAC_DIFFERS]:
            parts.append(f"{counts[MAC_DIFFERS]} with a different MAC")
        if counts[RESERVED_IN_USE]:
            parts.append(f"{counts[RESERVED_IN_USE]} reserved but answering")
        if counts[PROXY_ARP]:
            parts.append(f"{counts[PROXY_ARP]} only proxy ARP (nothing there)")
        problems = missing or counts[MAC_DIFFERS] or counts[RESERVED_IN_USE]
        set_hint(self.summary_label, ", ".join(parts), "warning" if problems else "success")

    def can_change(self):
        selection = self.selection()
        return selection is not None and self.ipam.can_change_addresses(selection[0])

    # ----------------------------------------------------------------- Actions for the page's menus

    def menu_actions(self, ip, mac, name):
        """[(label, callable)] for a device's right-click menu."""
        selection = self.selection()
        if selection is None:
            return []
        source, _, network_id = selection
        finding = self.findings.get(ip)
        actions = []
        if finding is not None and finding.state == PROXY_ARP and finding.record is None:
            return []  # Nothing's there to record: a router answered for it
        if finding is None or finding.state == NOT_RECORDED:
            actions.append(("Record in IPAM...", lambda: self.record_one(ip, mac, name)))
        else:
            if finding.state == MAC_DIFFERS and mac:  # (A proxied one's MAC is the router's, so never offered)
                actions.append((f"Update MAC in IPAM to {mac}", lambda: self.update_mac(ip, mac)))
            actions.append(("Edit in IPAM...", lambda: self.record_one(ip, mac, name)))
            actions.append(("Show in IPAM", lambda: self.ipam.show_address(source, network_id, ip)))
        return actions if self.can_change() else [action for action in actions if action[0] == "Show in IPAM"]

    def record_one(self, ip, mac, name):
        source, store, network_id = self.selection()
        record = store.address(network_id, ip)
        dialog = AddressDialog(self, store, network_id, ip, record, name=name, mac=mac if not record else "")
        if dialog.exec_():
            self.after_change()

    def update_mac(self, ip, mac):
        _, store, network_id = self.selection()
        record = store.address(network_id, ip)
        try:
            store.set_address(network_id, ip, record.status, record.name, mac, record.description, record.fields)
        except IpamError as error:
            QMessageBox.warning(self, "Not Changed", f"The MAC address wasn't updated. {error}")
        self.after_change()

    def record_missing(self):
        source, store, network_id = self.selection()
        missing = [ip for ip, finding in self.findings.items() if finding.state == NOT_RECORDED]
        missing.sort(key=ipaddress.ip_address)
        network = store.network(network_id).name
        listing = "\n".join(f"{ip}  {self.found[ip][1] or ''}  {self.found[ip][0] or ''}" for ip in missing[:15])
        more = f"\n... and {len(missing) - 15} more" if len(missing) > 15 else ""
        where = " (sent to the IPAM server now, or when it's back)" if source == "team" else ""
        if QMessageBox.question(self, "Record in IPAM",
                                f"Record these {len(missing)} devices in {network} as used{where}?\n\n"
                                f"{listing}{more}") != QMessageBox.Yes:
            return
        recorded = 0
        try:
            with store.transaction():
                for ip in missing:
                    mac, name = self.found[ip]
                    store.set_address(network_id, ip, USED, name or "", mac or "")
                    recorded += 1
        except IpamError as error:
            QMessageBox.warning(self, "Not All Recorded", f"Recorded {recorded} of {len(missing)}. {error}")
        self.after_change()

    def show_silent(self):
        selection = self.selection()
        if selection is None:
            return
        SilentDialog(self, selection, self.quiet).exec_()
        self.after_change()

    def after_change(self):
        self.ipam.refresh_after_external_change()
        self.compare_now()


class SilentDialog(QDialog):
    """Addresses IPAM records as used that didn't answer the sweep."""

    def __init__(self, parent, selection, quiet):
        super().__init__(parent)
        self.source, self.store, self.network_id = selection
        self.quiet = quiet
        self.setWindowTitle("Recorded but Silent")
        self.resize(760, 460)
        layout = QVBoxLayout(self)
        note = QLabel("IPAM records these addresses as used, but nothing answered on them during the sweep. They "
                      "may be switched off, block ping and ARP, or be gone: check before marking any free.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.table = QTableWidget(len(quiet), 4)
        self.table.setHorizontalHeaderLabels(["Address", "Name", "MAC Address", "Last Changed"])
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        for row, record in enumerate(quiet):
            for column, value in enumerate((record.ip, record.name, record.mac,
                                            f"{record.modified[:10]} {record.modified_by}")):
                self.table.setItem(row, column, QTableWidgetItem(value))
        self.table.resizeColumnsToContents()
        layout.addWidget(self.table, 1)
        self.message_label = QLabel()
        layout.addWidget(self.message_label)
        buttons = QHBoxLayout()
        self.free_button = QPushButton("Mark Selected Free...")
        close_button = QPushButton("Close")
        buttons.addWidget(self.free_button)
        buttons.addStretch()
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        self.free_button.clicked.connect(self.mark_free)
        close_button.clicked.connect(self.accept)

    def mark_free(self):
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()}, reverse=True)
        if not rows:
            set_hint(self.message_label, "Select the addresses to mark free first.", "info")
            return
        if QMessageBox.question(self, "Mark Free", f"Mark {len(rows)} address{'es' if len(rows) != 1 else ''} free, "
                                                   "forgetting what IPAM records for them?") != QMessageBox.Yes:
            return
        try:
            for row in rows:
                self.store.free_address(self.network_id, self.quiet[row].ip)
                self.table.removeRow(row)
                del self.quiet[row]
        except IpamError as error:
            set_hint(self.message_label, f"Not all were marked free: {error}", "error")
            return
        set_hint(self.message_label, f"Marked {len(rows)} free.", "success")
