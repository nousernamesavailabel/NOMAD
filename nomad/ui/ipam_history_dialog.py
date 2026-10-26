"""IPAM history: the timeline of an address, a subnet or a whole network, and picking a moment to view a network
as it was."""
import datetime

from PyQt5.QtCore import QDateTime, Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QComboBox, QDateTimeEdit, QDialog, QDialogButtonBox, QFormLayout, \
    QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout

from ..ipam.assets import all_asset_history, asset_history, label as asset_label
from ..ipam.history import CREATED, DELETED, address_history, network_history, subnet_history
from ..ipam.vlans import domain_history, vlan_history
from .common import set_hint
from .theme import COLORS

PERIODS = [("Last 24 hours", 1), ("Last 7 days", 7), ("Last 30 days", 30), ("All time", None)]
ACTION_COLORS = {CREATED: "success", DELETED: "error"}


class HistoryDialog(QDialog):
    """kind: "address" (subject: the IP), "subnet" (a Subnet) or "network" (a Network); or for VLANs, "vlan"
    (subject: the VLAN number, network_id: its domain's id) or "vlan_domain" (a VlanDomain); or "asset" (an Asset), or
    "assets" (every asset's)."""

    def __init__(self, parent, store, network_id, kind, subject, note=""):
        super().__init__(parent)
        self.store, self.network_id, self.kind, self.subject = store, network_id, kind, subject
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint)
        self.resize(1000, 560)
        title = {"address": f"History of {subject}", "subnet": f"History of {getattr(subject, 'cidr', '')}",
                 "network": f"History of {getattr(subject, 'name', '')}", "vlan": f"History of VLAN {subject}",
                 "vlan_domain": f"History of {getattr(subject, 'name', '')}",
                 "asset": f"History of {asset_label(subject) if kind == 'asset' else ''}",
                 "assets": "Changes to the Assets"}[kind]
        listing = kind in ("network", "vlan_domain", "assets")  # Changes to several things: say which each was
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        heading = QLabel(f"<b>{title}</b>, newest first. Times are this computer's local time.")
        heading.setWordWrap(True)
        layout.addWidget(heading)
        if note:
            note_label = QLabel(note)
            note_label.setWordWrap(True)
            set_hint(note_label, note, "warning")
            layout.addWidget(note_label)
        top = QHBoxLayout()
        self.period_combo = QComboBox()
        for label, days in PERIODS:
            self.period_combo.addItem(label, days)
        self.period_combo.setCurrentIndex(1 if listing else len(PERIODS) - 1)
        top.addWidget(QLabel("Show:"))
        top.addWidget(self.period_combo)
        top.addStretch()
        layout.addLayout(top)
        columns = ["When", "Who", "What", "Change", "Details"] if listing else ["When", "Who", "Change", "Details"]
        self.table = QTableWidget(0, len(columns))
        self.table.setHorizontalHeaderLabels(columns)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setWordWrap(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        self.count_label = QLabel()
        layout.addWidget(self.count_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.period_combo.currentIndexChanged.connect(self.fill)
        self.fill()

    def events(self):
        days = self.period_combo.currentData()
        since = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)).isoformat(
            timespec="seconds") if days else None
        if self.kind == "address":
            events = address_history(self.store, self.network_id, self.subject)
        elif self.kind == "subnet":
            events = subnet_history(self.store, self.subject.id)
        elif self.kind == "vlan":
            events = vlan_history(self.store, self.network_id, self.subject)
        elif self.kind == "vlan_domain":
            events = domain_history(self.store, self.subject.id)
        elif self.kind == "asset":
            events = asset_history(self.store, self.subject.id)
        elif self.kind == "assets":
            return all_asset_history(self.store, since)
        else:
            return network_history(self.store, self.network_id, since)
        return [event for event in events if not since or event.when >= since]

    def fill(self):
        events = self.events()
        self.table.setRowCount(len(events))
        for row, event in enumerate(events):
            values = [event.local_time, event.who]
            if self.kind in ("network", "vlan_domain", "assets"):
                values.append(event.subject)
            values += [event.action, event.details]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                if column == len(values) - 2 and event.op in ACTION_COLORS:
                    item.setForeground(self.color(event.op))
                self.table.setItem(row, column, item)
        for column in range(self.table.columnCount() - 1):
            self.table.resizeColumnToContents(column)
        self.table.resizeRowsToContents()
        period = self.period_combo.currentText().lower()
        self.count_label.setText(f"{len(events)} change{'' if len(events) == 1 else 's'}" +
                                 ("" if period == "all time" else f" in the {period}") + "." if events else
                                 "No changes recorded" + ("" if period == "all time" else f" in the {period}") + ".")

    @staticmethod
    def color(op):
        return QColor(COLORS[ACTION_COLORS[op]])


class AsOfDialog(QDialog):
    """Pick a moment (this computer's local time) to view the network as it was."""

    def __init__(self, parent, current_utc=None):
        super().__init__(parent)
        self.setWindowTitle("View As Of")
        layout = QVBoxLayout(self)
        intro = QLabel("Show this network (its subnets and every address) as it was at a moment in the past. The "
                       "page is read-only until you choose Back to Now.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.moment_input = QDateTimeEdit()
        self.moment_input.setCalendarPopup(True)
        self.moment_input.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.moment_input.setMaximumDateTime(QDateTime.currentDateTime())
        start = QDateTime.currentDateTime().addDays(-1)
        if current_utc:
            start = QDateTime.fromString(current_utc[:19], "yyyy-MM-ddTHH:mm:ss")
            start.setTimeSpec(Qt.UTC)
            start = start.toLocalTime()
        self.moment_input.setDateTime(start)
        form.addRow("As of:", self.moment_input)
        layout.addLayout(form)
        shortcuts = QHBoxLayout()
        for label, days in (("1 day ago", 1), ("1 week ago", 7), ("30 days ago", 30)):
            button = QPushButton(label)
            button.clicked.connect(lambda _, days=days: self.moment_input.setDateTime(
                QDateTime.currentDateTime().addDays(-days)))
            shortcuts.addWidget(button)
        shortcuts.addStretch()
        layout.addLayout(shortcuts)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def moment_utc(self):
        """The chosen moment as UTC ISO 8601 (to the second, like the change log's times)."""
        moment = self.moment_input.dateTime().toUTC()
        return moment.toString("yyyy-MM-ddTHH:mm:59") + "+00:00"

    def moment_text(self):
        return self.moment_input.dateTime().toString("yyyy-MM-dd HH:mm")
