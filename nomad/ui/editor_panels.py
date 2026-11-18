"""The Editor page's side panels (Archive, Changes, Standards, Backups), its background threads, and its dialogs
(sending commands to a device, checking against a standard)."""
import datetime
import logging
import threading

from PyQt5.QtCore import QThread, Qt, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QAbstractItemView, QButtonGroup, QCheckBox, QComboBox, QDialog, QDialogButtonBox, \
    QFormLayout, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QPushButton, QRadioButton, QSpinBox, \
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ..configs import archive, pull, runner
from ..configs.text import FIXABLE, IOS, PLATFORM_NAMES
from ..ipam.client import OldServerError, ServerUnreachable, TeamKeyError
from .common import read_only_table, set_hint
from .theme import COLORS

log = logging.getLogger(__name__)

RETRY_SECONDS = 15
WAIT_SECONDS = 25
BACKUP_STEP_SECONDS = runner.STEP_SECONDS


def when_text(stamp):
    if not stamp:
        return ""
    moment = datetime.datetime.fromtimestamp(float(stamp))
    today = datetime.date.today()
    if moment.date() == today:
        return moment.strftime("Today %H:%M")
    return moment.strftime("%Y-%m-%d %H:%M")


def change_text(version):
    if version.get("first"):
        return "First copy"
    return f"+{version.get('added') or 0} −{version.get('removed') or 0}"


# ----------------------------------------------------------------- Threads

class ConfigSyncThread(QThread):
    """Keeps a laptop's copy of the tribe's archive in step: sync, then wait for the next change, until stopped."""
    synced = pyqtSignal(bool)  # Whether anything came
    failed = pyqtSignal(str, bool)  # Message, whether the server is too old for the archive

    def __init__(self, configs, parent=None):
        super().__init__(parent)
        self.configs = configs
        self.stop_event = threading.Event()
        self.wake = threading.Event()

    def stop(self):
        self.stop_event.set()
        self.wake.set()

    def run(self):
        while not self.stop_event.is_set():
            self.wake.clear()
            try:
                changed = self.configs.sync()
                self.synced.emit(changed)
                if self.stop_event.is_set() or self.wake.is_set():
                    continue
                with self.configs.lock:
                    revision = self.configs.store.revision()
                self.configs.client.wait_for_configs(revision, timeout=5 if self.configs.waiting() else WAIT_SECONDS)
            except OldServerError as error:
                self.failed.emit(str(error), True)
                return
            except (ServerUnreachable, TeamKeyError) as error:
                self.failed.emit(str(error), False)
                self.wake.wait(RETRY_SECONDS)
            except Exception as error:  # One sync going wrong shouldn't end syncing
                log.exception("Syncing the config archive failed")
                self.failed.emit(str(error), False)
                self.wake.wait(RETRY_SECONDS)


class BackupThread(QThread):
    """Scheduled backups on this computer: a runner step every half minute, until stopped."""
    stepped = pyqtSignal(object)  # [runner.Done]
    failed = pyqtSignal(str)

    def __init__(self, backup_runner, scope_source=None, parent=None):
        super().__init__(parent)
        self.runner = backup_runner
        self.scope_source = scope_source  # () -> scope rows (no tribe: the open map's), or None
        self.stop_event = threading.Event()
        self.wake = threading.Event()  # Set to step now (backups brought forward)

    def stop(self):
        self.stop_event.set()
        self.wake.set()

    def run(self):
        while not self.stop_event.is_set():
            try:
                done = self.runner.step()
                if done:
                    self.stepped.emit(done)
            except (ServerUnreachable, TeamKeyError) as error:
                self.failed.emit(f"The tribe server can't be reached: {error}")
            except Exception as error:
                log.exception("A scheduled backup step failed")
                self.failed.emit(str(error))
            self.wake.wait(BACKUP_STEP_SECONDS)
            self.wake.clear()


# ----------------------------------------------------------------- Panels

class ArchivePanel(QWidget):
    """The archived devices, each with its versions (filled in when opened)."""
    open_version = pyqtSignal(int)
    menu_requested = pyqtSignal(object)  # The position

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        row = QHBoxLayout()
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter devices")
        self.filter_input.setClearButtonEnabled(True)
        self.pull_button = QPushButton("Pull Config...")
        self.pull_button.setToolTip("Read a device's running-config over SSH into the archive")
        row.addWidget(self.filter_input, 1)
        row.addWidget(self.pull_button)
        layout.addLayout(row)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Device", "Last backup", "Next backup", "Status"])
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tree.setUniformRowHeights(True)
        layout.addWidget(self.tree, 1)
        self.filter_input.textChanged.connect(self.apply_filter)
        self.tree.itemDoubleClicked.connect(self.on_double_click)
        self.tree.itemExpanded.connect(self.on_expanded)
        self.tree.customContextMenuRequested.connect(self.on_menu)
        self.history_source = None  # device id -> [versions]

    def fill(self, devices, unreviewed, failing, now):
        open_ids = {self.tree.topLevelItem(index).data(0, Qt.UserRole)
                    for index in range(self.tree.topLevelItemCount()) if self.tree.topLevelItem(index).isExpanded()}
        selected = {item.data(0, Qt.UserRole) for item in self.tree.selectedItems()}
        self.tree.clear()
        for device in devices:
            item = QTreeWidgetItem([device["name"] or device["id"], when_text(device.get("last_ok")),
                                    next_text(device, now), device_status(device, unreviewed, failing, now)])
            item.setData(0, Qt.UserRole, device["id"])
            item.setData(0, Qt.UserRole + 1, "device")
            item.setToolTip(0, f"{device['id']}  ·  {PLATFORM_NAMES.get(device.get('platform') or '', 'Unknown')}")
            if unreviewed.get(device["id"]):
                font = item.font(0)
                font.setBold(True)
                item.setFont(0, font)
            if device.get("failures"):
                item.setToolTip(3, "\n".join(f"{failure['computer']}: {failure['reason']}"
                                             for failure in device["failures"]))
            if device.get("in_scope") and not device.get("excluded"):
                item.setToolTip(2, "When it's next due for a scheduled backup (right-click > Back Up Now to bring "
                                   "it forward)")
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            self.tree.addTopLevelItem(item)
            if device["id"] in open_ids:
                item.setExpanded(True)
            if device["id"] in selected:
                item.setSelected(True)
        self.tree.resizeColumnToContents(1)
        self.tree.resizeColumnToContents(2)
        self.apply_filter()

    def on_expanded(self, item):
        if item.data(0, Qt.UserRole + 1) != "device" or self.history_source is None:
            return
        item.takeChildren()
        for version in self.history_source(item.data(0, Qt.UserRole)):
            child = QTreeWidgetItem([f"{pull.WHICH_NAMES.get(version['which'], version['which'])}  ·  "
                                     f"{change_text(version)}", when_text(version["pulled_at"]), "",
                                     version_status(version)])
            child.setData(0, Qt.UserRole, version["id"])
            child.setData(0, Qt.UserRole + 1, "version")
            child.setToolTip(0, version_tip(version))
            if not version.get("reviewed_by"):
                font = child.font(0)
                font.setBold(True)
                child.setFont(0, font)
            item.addChild(child)
        if not item.childCount():
            item.setChildIndicatorPolicy(QTreeWidgetItem.DontShowIndicator)

    def on_double_click(self, item, column):
        if item.data(0, Qt.UserRole + 1) == "version":
            self.open_version.emit(int(item.data(0, Qt.UserRole)))
        elif item.childCount() == 0:
            item.setExpanded(True)

    def on_menu(self, position):
        self.menu_requested.emit(self.tree.viewport().mapToGlobal(position))

    def apply_filter(self, *_):
        words = self.filter_input.text().lower().split()
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            text = f"{item.text(0)} {item.toolTip(0)} {item.text(3)}".lower()
            item.setHidden(not all(word in text for word in words))

    def selected(self):
        """([device ids], [version ids]) selected."""
        devices, versions = [], []
        for item in self.tree.selectedItems():
            if item.data(0, Qt.UserRole + 1) == "device":
                devices.append(item.data(0, Qt.UserRole))
            else:
                versions.append(int(item.data(0, Qt.UserRole)))
        return devices, versions

    def device_of_version_item(self, version_id):
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            for child in range(item.childCount()):
                if item.child(child).data(0, Qt.UserRole) == version_id:
                    return item.data(0, Qt.UserRole)
        return None

    def show_device(self, device_id):
        for index in range(self.tree.topLevelItemCount()):
            item = self.tree.topLevelItem(index)
            if item.data(0, Qt.UserRole) == device_id:
                self.filter_input.clear()
                self.tree.clearSelection()
                item.setSelected(True)
                item.setExpanded(True)
                self.tree.scrollToItem(item)
                return True
        return False


def device_status(device, unreviewed, failing, now):
    parts = []
    if device.get("excluded"):
        parts.append("Excluded")
    elif device.get("in_scope") and device.get("next_due") and (device.get("last_ok") or device.get("created") or 0) \
            < now - 2 * 24 * 3600 and not device.get("last_ok"):
        parts.append("Not backed up yet")
    if unreviewed.get(device["id"]):
        count = unreviewed[device["id"]]
        parts.append(f"{count} change{'s' if count != 1 else ''} to review")
    if failing.get(device["id"]):
        parts.append(f"fails {failing[device['id']]} standard line{'s' if failing[device['id']] != 1 else ''}")
    if device.get("failures"):
        parts.append("couldn't back up")
    return ", ".join(parts) or ("Scheduled" if device.get("in_scope") else "")


def next_text(device, now):
    """When a device's next scheduled backup is: a time, Due now, Left out, or "" (not in the schedule)."""
    if device.get("excluded"):
        return "Left out"
    if not device.get("in_scope") or not device.get("next_due"):
        return ""
    if device["next_due"] <= now:
        return "Due now"
    return when_text(device["next_due"])


def who_text(by):
    """Who backed something up, short: "CORE-PC service" for the Map Watcher, "PC1 (alice)" for NOMAD."""
    name, _, computer = by.partition(" (")
    computer = computer.rstrip(")")
    if not computer:
        return by
    return f"{computer} service" if name == "Map Watcher service" else f"{computer} ({name})"


def version_status(version):
    if version.get("first"):
        return archive.SOURCE_NAMES.get(version.get("source"), "")
    if version.get("reviewed_by"):
        return "Reviewed"
    return "To review"


def version_tip(version):
    lines = [f"{pull.WHICH_NAMES.get(version['which'], version['which'])}, {when_text(version['pulled_at'])}",
             f"{archive.SOURCE_NAMES.get(version.get('source'), version.get('source') or '')} by "
             f"{version.get('pulled_by') or 'someone'}"]
    if version.get("changed_by"):
        lines.append(f"Changed on the device by {version['changed_by']}")
    if version.get("reviewed_by") and not version.get("first"):
        lines.append(f"Reviewed by {version['reviewed_by']} {when_text(version.get('reviewed_at'))}")
    return "\n".join(lines)


class ChangesPanel(QWidget):
    """Recent changes (newest first; bold ones nobody has reviewed), and the devices overdue for a backup."""
    open_change = pyqtSignal(int)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        row = QHBoxLayout()
        self.only_unreviewed = QCheckBox("Only changes to review")
        self.review_all_button = QPushButton("Mark All Reviewed")
        row.addWidget(self.only_unreviewed, 1)
        row.addWidget(self.review_all_button)
        layout.addLayout(row)
        self.table = read_only_table(["When", "Device", "Change", "Changed by", "Pulled by", "Reviewed"])
        self.table.setToolTip("Double-click a change to compare it with the copy before (and mark it reviewed)")
        layout.addWidget(self.table, 3)
        self.overdue_label = QLabel()
        layout.addWidget(self.overdue_label)
        self.overdue = read_only_table(["Device", "Last backup", "Why not"])
        layout.addWidget(self.overdue, 1)
        self.table.cellDoubleClicked.connect(self.on_double_click)
        self.only_unreviewed.toggled.connect(self.refill)
        self.recent, self.overdue_rows = [], []

    def fill(self, recent, overdue):
        self.recent, self.overdue_rows = recent, overdue
        self.refill()

    def refill(self, *_):
        rows = [item for item in self.recent if not (self.only_unreviewed.isChecked() and item.get("reviewed_by"))]
        self.table.setSortingEnabled(False)
        self.table.setRowCount(len(rows))
        bold = QFont(self.table.font())
        bold.setBold(True)
        for row, version in enumerate(rows):
            values = [when_text(version["pulled_at"]), version.get("device_name") or version["device_id"],
                      change_text(version), version.get("changed_by") or "", version.get("pulled_by") or "",
                      version.get("reviewed_by") or ""]
            for column, value in enumerate(values):
                item = self.table.item(row, column) or read_only_item()
                item.setText(value)
                item.setData(Qt.UserRole, version["id"])
                item.setFont(bold if not version.get("reviewed_by") else self.table.font())
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.overdue_label.setText(f"Overdue for a backup ({len(self.overdue_rows)}):" if self.overdue_rows else
                                   "No device is overdue for a backup.")
        self.overdue.setRowCount(len(self.overdue_rows))
        for row, device in enumerate(self.overdue_rows):
            reasons = "; ".join(f"{failure['computer']}: {failure['reason']}" for failure in device["failures"]) or \
                "No computer running backups has tried it"
            for column, value in enumerate([device["name"], when_text(device.get("last_ok")) or "Never", reasons]):
                item = read_only_item()
                item.setText(value)
                item.setToolTip(value)
                self.overdue.setItem(row, column, item)
        self.overdue.resizeColumnsToContents()

    def on_double_click(self, row, column):
        item = self.table.item(row, 0)
        if item is not None:
            self.open_change.emit(int(item.data(Qt.UserRole)))

    def unreviewed_ids(self):
        return [item["id"] for item in self.recent if not item.get("reviewed_by")]


def read_only_item():
    from PyQt5.QtWidgets import QTableWidgetItem
    item = QTableWidgetItem()
    item.setFlags(item.flags() & ~Qt.ItemIsEditable)
    return item


class StandardsPanel(QWidget):
    """The standards, and how each device stands against them (checked as each copy arrives)."""
    open_result = pyqtSignal(str, str)  # Device id, standard

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.list = QListWidget()
        self.list.setToolTip("Double-click to edit")
        layout.addWidget(self.list, 1)
        row = QHBoxLayout()
        self.new_button, self.edit_button = QPushButton("New"), QPushButton("Edit")
        self.delete_button, self.check_button = QPushButton("Delete"), QPushButton("Check...")
        self.check_button.setToolTip("Check archived configurations against a standard now (any devices you choose)")
        for button in (self.new_button, self.edit_button, self.delete_button, self.check_button):
            row.addWidget(button)
        layout.addLayout(row)
        self.summary = QLabel()
        layout.addWidget(self.summary)
        self.table = read_only_table(["Device", "Standard", "Failed", "Checked"])
        self.table.setToolTip("Double-click for what fails, and the commands that fix it")
        layout.addWidget(self.table, 2)
        self.table.cellDoubleClicked.connect(self.on_double_click)
        self.names = {}  # device id -> name

    def fill(self, standards_rows, compliance, names):
        current = self.list.currentItem().text() if self.list.currentItem() else ""
        self.list.clear()
        from ..configs import standards as standard_text
        for row in standards_rows:
            parsed = standard_text.parse(row["text"], row["name"])
            self.list.addItem(row["name"])
            item = self.list.item(self.list.count() - 1)
            item.setToolTip(f"For {parsed.applies_text}\nSaved by {row.get('updated_by') or 'someone'} "
                            f"{when_text(row.get('updated'))}")
            if row["name"] == current:
                self.list.setCurrentItem(item)
        rows = sorted(compliance, key=lambda item: (-(item["failed"] or 0), names.get(item["device_id"], "")))
        self.table.setRowCount(len(rows))
        failing = 0
        for row, result in enumerate(rows):
            failing += 1 if result["failed"] else 0
            values = [names.get(result["device_id"], result["device_id"]), result["standard"],
                      f"{result['failed']} of {result['total']}", when_text(result["checked"])]
            for column, value in enumerate(values):
                item = read_only_item()
                item.setText(value)
                item.setData(Qt.UserRole, (result["device_id"], result["standard"]))
                if result["failed"] and column == 2:
                    item.setForeground(Qt.red)
                self.table.setItem(row, column, item)
        self.table.resizeColumnsToContents()
        self.summary.setText(f"{failing} of {len(rows)} checks fail." if rows else
                             "No device has been checked yet: checks run as each copy arrives.")
        self.names = names

    def current_name(self):
        item = self.list.currentItem()
        return item.text() if item is not None else ""

    def on_double_click(self, row, column):
        item = self.table.item(row, 0)
        if item is not None:
            device_id, standard = item.data(Qt.UserRole)
            self.open_result.emit(device_id, standard)


class BackupsPanel(QWidget):
    """Scheduled backups on this computer, the tribe's interval, and how NOMAD logs in to devices."""
    run_toggled = pyqtSignal(bool)
    interval_applied = pyqtSignal(int)

    def __init__(self, parent, login_row):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        self.run_check = QCheckBox("Run scheduled config backups on this computer")
        self.run_check.setToolTip("While NOMAD is open, this computer backs up the devices due (a few at a time). "
                                  "With a tribe, every computer that has this on shares the work, device by device; "
                                  "a device one can't reach goes to another.")
        layout.addWidget(self.run_check)
        explain = QLabel("Backups log in with each device's saved SSH session, else the login below (it needs a saved "
                         "password: nobody's there to type one). The Map Watcher service can run them too "
                         "(Tools > Map Watcher Service).")
        explain.setWordWrap(True)
        explain.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(explain)
        layout.addWidget(login_row)
        form = QFormLayout()
        interval_row = QHBoxLayout()
        self.interval = QSpinBox()
        self.interval.setRange(1, 720)
        self.interval.setSuffix(" hours")
        self.interval_button = QPushButton("Apply")
        interval_row.addWidget(self.interval)
        interval_row.addWidget(self.interval_button)
        interval_row.addStretch(1)
        form.addRow("Back each device up every:", interval_row)
        layout.addLayout(form)
        self.scope_label = QLabel()
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)
        self.status = QLabel()
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        runners_row = QHBoxLayout()
        runners_row.addWidget(QLabel("Who's backing up:"), 1)
        self.refresh_button = QPushButton("Refresh")
        self.due_all_button = QPushButton("Back Up Everything Now")
        self.due_all_button.setToolTip("Bring every device's scheduled backup forward to now: the computers running "
                                       "backups take them a few at a time (then each keeps its usual interval)")
        runners_row.addWidget(self.refresh_button)
        runners_row.addWidget(self.due_all_button)
        layout.addLayout(runners_row)
        self.runners = read_only_table(["Computer", "Runs as", "Working on", "Last round", "Last asked"])
        self.runners.setToolTip("The computers (NOMAD windows and Map Watcher services) backing up devices now. "
                                "The service gets the devices due first.")
        layout.addWidget(self.runners, 1)
        self.runners_note = QLabel()
        self.runners_note.setWordWrap(True)
        layout.addWidget(self.runners_note)
        layout.addWidget(QLabel("Recent backups (every computer's):"))
        self.results = read_only_table(["When", "Device", "By", "Result"])
        self.results.setToolTip("The last 500 scheduled backups, from the Map Watcher service and every NOMAD "
                                "running them")
        layout.addWidget(self.results, 2)
        self.run_check.toggled.connect(self.run_toggled)
        self.interval_button.clicked.connect(self.apply_interval)

    def apply_interval(self):
        self.interval_applied.emit(self.interval.value())

    def fill_runners(self, runners, due_count):
        self.runners.setRowCount(len(runners))
        for row, runner in enumerate(runners):
            user = (runner.get("user") or "").split(" (")[0]  # "alice (LAPTOP7)": the computer has its own column
            kind = "Service" if runner.get("kind") == "service" else f"NOMAD: {user}" if user else "NOMAD"
            values = [runner.get("computer") or runner.get("holder"), kind,
                      ", ".join(runner.get("working_on") or []) or "Nothing now", runner.get("status") or "",
                      when_text(runner.get("last_seen"))]
            for column, value in enumerate(values):
                item = read_only_item()
                item.setText(value)
                item.setToolTip(value)
                self.runners.setItem(row, column, item)
        self.runners.resizeColumnsToContents()
        due = f"{due_count} device{'s' if due_count != 1 else ''} due now." if due_count else "Nothing is due now."
        if runners:
            set_hint(self.runners_note, due, "info")
        else:
            set_hint(self.runners_note, "No computer is backing up now: tick Run scheduled config backups above, or "
                                        "set the Map Watcher service up to. " + due, "warning")

    def fill_results(self, results):
        self.results.setRowCount(len(results))
        for row, result in enumerate(results):
            values = [when_text(result.get("at")), result.get("device_name") or result.get("device_id", ""),
                      who_text(result.get("by") or ""),
                      result.get("note") if result.get("ok") else f"Couldn't: {result.get('note')}"]
            for column, value in enumerate(values):
                item = read_only_item()
                item.setText(value)
                item.setToolTip(value)
                if column == 3 and not result.get("ok"):
                    item.setForeground(Qt.red)
                self.results.setItem(row, column, item)
        self.results.resizeColumnsToContents()


# ----------------------------------------------------------------- Dialogs

class SendDialog(QDialog):
    """Send configuration lines to a device over SSH (with the revert timer on IOS)."""

    def __init__(self, parent, address="", platform=IOS, line_count=0):
        super().__init__(parent)
        self.setWindowTitle("Send to Device")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.address = QLineEdit(address)
        self.address.setPlaceholderText("Address or name")
        form.addRow("Device:", self.address)
        self.platform = QComboBox()
        for value in sorted(FIXABLE):
            self.platform.addItem(PLATFORM_NAMES[value], value)
        self.platform.setCurrentIndex(max(self.platform.findData(platform), 0))
        form.addRow("Platform:", self.platform)
        revert_row = QHBoxLayout()
        self.revert = QCheckBox("Revert timer")
        self.revert.setToolTip("configure terminal revert timer: the device puts its old configuration back by itself "
                               "unless NOMAD can log in again afterwards and confirm (IOS / IOS XE)")
        self.minutes = QSpinBox()
        self.minutes.setRange(1, 120)
        self.minutes.setValue(5)
        self.minutes.setSuffix(" minutes")
        revert_row.addWidget(self.revert)
        revert_row.addWidget(self.minutes)
        revert_row.addStretch(1)
        form.addRow("", revert_row)
        self.save = QCheckBox("Save to the startup-config afterwards (write memory)")
        form.addRow("", self.save)
        self.pull_after = QCheckBox("Pull its running-config into the archive afterwards")
        self.pull_after.setChecked(True)
        form.addRow("", self.pull_after)
        layout.addLayout(form)
        note = QLabel(f"{line_count} line{'s' if line_count != 1 else ''} go in configuration mode, one at a time; "
                      f"NOMAD stops at the first one the device refuses.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.hint = QLabel()
        layout.addWidget(self.hint)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Send")
        buttons.accepted.connect(self.check_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.platform.currentIndexChanged.connect(self.platform_changed)
        self.platform_changed()

    def platform_changed(self, *_):
        ios = self.platform.currentData() == IOS
        self.revert.setEnabled(ios)
        self.minutes.setEnabled(ios)
        if not ios:
            self.revert.setChecked(False)
        else:
            self.revert.setChecked(True)

    def check_accept(self):
        if not self.address.text().strip():
            set_hint(self.hint, "Give the device's address.", "error")
            return
        self.accept()


class CheckDialog(QDialog):
    """Which standard, and which devices, to check now."""

    def __init__(self, parent, standard_names, current="", selected_count=0):
        super().__init__(parent)
        self.setWindowTitle("Check Against a Standard")
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.standard = QComboBox()
        self.standard.addItems(standard_names)
        if current in standard_names:
            self.standard.setCurrentText(current)
        form.addRow("Standard:", self.standard)
        layout.addLayout(form)
        self.group = QButtonGroup(self)
        self.applies = QRadioButton("The devices it applies to (its applies-to line)")
        self.every = QRadioButton("Every archived device")
        self.selected = QRadioButton(f"The devices selected in the Archive ({selected_count})")
        self.selected.setEnabled(bool(selected_count))
        for index, button in enumerate((self.applies, self.every, self.selected)):
            self.group.addButton(button, index)
            layout.addWidget(button)
        (self.selected if selected_count else self.applies).setChecked(True)
        note = QLabel("It checks the newest archived running-config of each (Pull Config first for one that's "
                      "changed since).")
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(note)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Check")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def scope(self):
        return ("applies", "every", "selected")[max(self.group.checkedId(), 0)]


class PullDialog(QDialog):
    """A device to pull a configuration from: picked from the list (the map's network devices, the archive's, saved
    SSH sessions), or an address or name typed."""

    def __init__(self, parent, choices=(), address=""):
        """choices: [target] ({"id", "name", "address", "names", "platform"}), shown as "name (address)"."""
        super().__init__(parent)
        self.setWindowTitle("Pull Config")
        self.setMinimumWidth(420)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.device = QComboBox()
        self.device.setEditable(True)
        self.device.setInsertPolicy(QComboBox.NoInsert)
        self.device.setMaxVisibleItems(20)
        for target in choices:
            label = target["name"] if target["name"] == target["address"] else \
                f"{target['name']} ({target['address']})"
            self.device.addItem(label, target)
        self.device.completer().setFilterMode(Qt.MatchContains)
        self.device.completer().setCaseSensitivity(Qt.CaseInsensitive)
        self.device.lineEdit().setPlaceholderText("Pick a device, or type its address or name")
        self.device.setCurrentIndex(-1)
        self.device.setEditText(address)
        form.addRow("Device:", self.device)
        self.platform = QComboBox()
        self.platform.addItem("Tell from its configuration", "")
        for value, name in PLATFORM_NAMES.items():
            if value != "other":
                self.platform.addItem(name, value)
        form.addRow("Platform:", self.platform)
        self.startup = QCheckBox("Its startup-config too (and compare them)")
        form.addRow("", self.startup)
        layout.addLayout(form)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("Pull")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def target(self, resolve):
        """The device chosen (a copy of its target), or resolve(text) for an address or name typed; None if empty."""
        text = self.device.currentText().strip()
        if not text:
            return None
        index = self.device.findText(text, Qt.MatchFixedString)
        if index >= 0 and self.device.itemData(index):
            target = dict(self.device.itemData(index))
        else:
            target = resolve(text)
        if self.platform.currentData():
            target["platform"] = self.platform.currentData()
        return target
