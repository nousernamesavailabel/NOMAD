"""Tools > Services & Firewall: every NOMAD service on this computer and every NOMAD rule in Windows Firewall, in
one place.

The services (services_catalog.py) can be installed, started, stopped and removed together, or one at a time; Set
Up opens a service's own dialog, as its Tools menu item does. Install or Update Ticked goes through them in the order
they're best installed: installing the Tribe Server, the Map Watcher or the NOMAD Dashboard opens its own dialog
(they need choices made), and the Syslog and Flow Collectors are installed with their usual settings, or the ones
they had before. The Version column says which NOMAD each running service runs (service_versions), and marks those
that want updating. Update (the selected one) and Install or Update Ticked update them with the settings they have,
with no window (service_updates.py).

The firewall list (firewall.py) shows each rule NOMAD makes, what uses it, the port it should allow and whether it
does, and opens, fixes or removes rules; the pages' Open Firewall Port buttons and the services make the same ones.
Reading needs no administrator rights; changing anything does.
"""
import logging
import os

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QGroupBox, QHBoxLayout, QLabel, \
    QMessageBox, QPushButton, QTableWidgetItem, QVBoxLayout

from .. import firewall, service_versions
from .. import services_catalog as catalog
from .common import HINT_COLORS, read_only_table, run_in_background, set_hint
from .service_updates import free_ports, services_changed
from .theme import accent_button

log = logging.getLogger(__name__)

STATUS_SECONDS = 5
NOT_INSTALLED, STOPPED, STARTING, RUNNING, STOPPING = "Not installed", "Stopped", "Starting", "Running", "Stopping"
INSTALLED = (STOPPED, STARTING, RUNNING, STOPPING)
SERVICE_COLUMNS = ["Service", "Status", "Version", "Ports", "What it does"]
RULE_COLUMNS = ["Rule", "Used by", "Allows", "State", "Details"]
STATUS_KINDS = {RUNNING: "success", STOPPED: "warning", STARTING: "info", STOPPING: "info", NOT_INSTALLED: "info"}
RULE_KINDS = {firewall.OPEN: "success", firewall.NOT_OPEN: "info", firewall.MISSING: "warning",
              firewall.NEEDS_FIXING: "warning", firewall.TURNED_OFF: "warning", firewall.LEFT_OVER: "warning",
              firewall.UNKNOWN: "info"}
FIXABLE = (firewall.MISSING, firewall.NEEDS_FIXING, firewall.TURNED_OFF)


def page_wants(window, rule):
    """(port, protocols) a page's rule should allow: the page's port setting now (its usual one if it has none)."""
    page = getattr(window, rule.page, None) if rule.page else None
    try:
        if rule.page == "syslog_tab":
            return page.port_input.value(), ("UDP", "TCP") if page.tcp_check.isChecked() else ("UDP",)
        if rule.page in ("flows_tab", "tftp_tab"):
            return page.port_input.value(), rule.protocols
        if rule.page == "iperf_tab":
            return page.server_port(), rule.protocols
    except AttributeError:  # Not made yet, or a stand-in in tests
        pass
    return rule.port, rule.protocols


class RuleRow:
    """One line of the firewall list: one of firewall.RULES, an older name of one, or a NOMAD rule NOMAD doesn't
    know (made by hand, or by a newer NOMAD)."""

    def __init__(self, name, used_by, rule=None, port=None, protocols=(), state="", details=""):
        self.name, self.used_by, self.rule = name, used_by, rule
        self.port, self.protocols, self.state, self.details = port, tuple(protocols), state, details
        self.shown_port = port

    def key(self):
        return self.name, self.used_by, self.port, self.protocols, self.state, self.details

    def openable(self):
        return self.rule is not None

    def removable(self):
        return self.state not in (firewall.NOT_OPEN, firewall.MISSING)

    def allows(self):
        if self.rule is None:
            return ""
        return firewall.describe(self.protocols, "?" if self.shown_port is None else self.shown_port)


class ServicesDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Services & Firewall")
        self.setMinimumWidth(900)
        self.setMinimumHeight(720)
        layout = QVBoxLayout(self)
        intro = QLabel("NOMAD's Windows services keep working when nobody has NOMAD open, and Windows Firewall has "
                       "to let devices reach them and some pages. Install the services this computer needs, and "
                       "check that the firewall rules are open. Each service and page also sets itself up on its "
                       "own.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.admin_row = QHBoxLayout()
        self.admin_label = QLabel()
        self.admin_label.setWordWrap(True)
        self.restart_button = QPushButton("Restart as Administrator")
        self.admin_row.addWidget(self.admin_label, 1)
        self.admin_row.addWidget(self.restart_button)
        layout.addLayout(self.admin_row)

        services_box = QGroupBox("Services on this computer")
        services_layout = QVBoxLayout(services_box)
        self.services_table = read_only_table(SERVICE_COLUMNS)
        self.services_table.setRowCount(len(catalog.SERVICES))
        for row, entry in enumerate(catalog.SERVICES):
            item = QTableWidgetItem(entry.title)
            item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            item.setCheckState(Qt.Unchecked)
            item.setToolTip("Tick it for Install or Update Ticked, or Uninstall Ticked")
            self.services_table.setItem(row, 0, item)
            for column in range(1, len(SERVICE_COLUMNS)):
                self.services_table.setItem(row, column, QTableWidgetItem())
            self.services_table.item(row, 4).setText(entry.purpose)
            self.services_table.item(row, 4).setToolTip(entry.purpose)
        self.services_table.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.services_table.setWordWrap(False)  # One line each (the whole of it in the tooltip), so it fits
        services_layout.addWidget(self.services_table)
        row_buttons = QHBoxLayout()
        self.set_up_button = QPushButton("Set Up...")
        self.set_up_button.setToolTip("Open this service's own window, to install it with your settings or change "
                                      "them")
        self.update_button = QPushButton("Update")
        self.update_button.setToolTip("Run this NOMAD in the service, with the settings it has")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.uninstall_button = QPushButton("Uninstall...")
        self.folder_button = QPushButton("Open Its Folder")
        for button in (self.set_up_button, self.update_button, self.start_button, self.stop_button,
                       self.uninstall_button, self.folder_button):
            row_buttons.addWidget(button)
        row_buttons.addStretch()
        services_layout.addLayout(row_buttons)
        bulk_buttons = QHBoxLayout()
        self.install_ticked_button = accent_button("Install or Update Ticked")
        self.install_ticked_button.setToolTip("Install the ticked services that aren't installed yet, and update "
                                              "those that need it (with the settings they have), in the order "
                                              "they're best installed")
        self.uninstall_ticked_button = QPushButton("Uninstall Ticked...")
        self.start_all_button = QPushButton("Start All")
        self.stop_all_button = QPushButton("Stop All")
        for button in (self.install_ticked_button, self.uninstall_ticked_button, self.start_all_button,
                       self.stop_all_button):
            bulk_buttons.addWidget(button)
        bulk_buttons.addStretch()
        services_layout.addLayout(bulk_buttons)
        layout.addWidget(services_box)

        firewall_box = QGroupBox("NOMAD's Windows Firewall rules")
        firewall_layout = QVBoxLayout(firewall_box)
        self.firewall_label = QLabel()
        self.firewall_label.setWordWrap(True)
        firewall_layout.addWidget(self.firewall_label)
        self.rules_table = read_only_table(RULE_COLUMNS)
        firewall_layout.addWidget(self.rules_table, 1)
        rule_buttons = QHBoxLayout()
        self.open_rule_button = QPushButton("Open Ticked")
        self.open_rule_button.setToolTip("Allow the ports the ticked rules' services or pages use now (replacing "
                                         "each rule if it's there)")
        self.remove_rule_button = QPushButton("Remove Ticked...")
        self.fix_button = accent_button("Fix All")
        self.fix_button.setToolTip("Open every rule that's missing, turned off or on the wrong port")
        self.remove_left_over_button = QPushButton("Remove Left Over")
        self.remove_left_over_button.setToolTip("Remove the rules of services that aren't installed, and rules "
                                                "under NOMAD's old name")
        self.reread_button = QPushButton("Check Again")
        for button in (self.open_rule_button, self.remove_rule_button, self.fix_button,
                       self.remove_left_over_button, self.reread_button):
            rule_buttons.addWidget(button)
        rule_buttons.addStretch()
        firewall_layout.addLayout(rule_buttons)
        layout.addWidget(firewall_box, 1)

        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.states = {}  # Service key: status
        self.firewall_state = None  # firewall.FirewallState once read
        self.firewall_problem = ""
        self.reading = False
        self.read_again = False
        self.rows = []  # RuleRow, as the firewall list shows them
        self.busy = ""  # What's being done, or ""
        self.done_text = ""
        self.touched = set()  # Keys of the services the running job changes
        self.released_watcher = None
        self.queue = []  # Install or Update Ticked: the services still to install or update
        self.behind = {}  # Key -> why a running service wants updating
        self.installing = None
        self.problems = []

        self.restart_button.clicked.connect(self.restart_as_admin)
        self.services_table.itemSelectionChanged.connect(self.update_buttons)
        self.services_table.itemChanged.connect(self.update_buttons)
        self.services_table.itemDoubleClicked.connect(self.set_up)
        self.set_up_button.clicked.connect(self.set_up)
        self.update_button.clicked.connect(self.update_service)
        self.start_button.clicked.connect(self.start_service)
        self.stop_button.clicked.connect(self.stop_service)
        self.uninstall_button.clicked.connect(self.uninstall_service)
        self.folder_button.clicked.connect(self.open_folder)
        self.install_ticked_button.clicked.connect(self.install_ticked)
        self.uninstall_ticked_button.clicked.connect(self.uninstall_ticked)
        self.start_all_button.clicked.connect(self.start_all)
        self.stop_all_button.clicked.connect(self.stop_all)
        self.rules_table.itemChanged.connect(self.update_buttons)
        self.open_rule_button.clicked.connect(self.open_rules)
        self.remove_rule_button.clicked.connect(self.remove_rules)
        self.fix_button.clicked.connect(self.fix_all)
        self.remove_left_over_button.clicked.connect(self.remove_left_over)
        self.reread_button.clicked.connect(self.read_firewall)
        self.timer = QTimer(self)
        self.timer.setInterval(STATUS_SECONDS * 1000)
        self.timer.timeout.connect(self.refresh_services)
        self.timer.start()
        self.services_table.selectRow(0)
        self.refresh_services()
        self.fit_services_table()
        self.read_firewall()

    # ----------------------------------------------------------------- State

    def showEvent(self, event):
        super().showEvent(event)
        self.fit_services_table()

    def fit_services_table(self):
        """Tall enough for every service, no taller."""
        table = self.services_table
        table.resizeRowsToContents()
        rows = sum(table.rowHeight(row) for row in range(table.rowCount()))
        table.setFixedHeight(table.horizontalHeader().sizeHint().height() + rows + 2 * table.frameWidth() + 2)

    def admin(self):
        return bool(getattr(self.window, "admin", False))

    def refresh_services(self):
        for row, entry in enumerate(catalog.SERVICES):
            state = catalog.status(entry)
            self.states[entry.key] = state
            status_item = self.services_table.item(row, 1)
            status_item.setText(state)
            status_item.setForeground(QColor(HINT_COLORS[STATUS_KINDS.get(state, "error")]))
            self.show_version(row, entry, state)
            try:
                ports = catalog.ports_text(entry, self.found_port)
            except Exception as error:  # Its module couldn't be read
                ports = f"? ({error})"
            self.services_table.item(row, 3).setText(ports)
        self.show_firewall()
        self.update_buttons()

    def show_version(self, row, entry, state):
        """The NOMAD a running service runs, marked when it wants updating."""
        self.behind.pop(entry.key, None)
        text, reason = "", ""
        try:
            if state == RUNNING:
                note = service_versions.read_note(entry.spec().argument)
                text = service_versions.version_text(entry, state, lambda _argument: note)
                reason = service_versions.why_behind(note)
        except Exception:  # Its module couldn't be read: nothing to say
            text, reason = "", ""
        item = self.services_table.item(row, 2)
        if reason:
            self.behind[entry.key] = reason
            text = f"{text}: update" if text else "Update"
        item.setText(text)
        item.setToolTip(f"It {reason}. Select it and click Update." if reason else
                        "The NOMAD it runs" if text else "")
        item.setForeground(QColor(HINT_COLORS["warning" if reason else "info"]))

    def found_port(self, name):
        """The port a rule in Windows Firewall has (for a service whose settings can't be read without
        administrator rights), or None."""
        found = self.firewall_state.named(name) if self.firewall_state is not None else []
        return found[0].ports if found else None

    def current(self):
        rows = self.services_table.selectionModel().selectedRows() if self.services_table.selectionModel() else []
        return catalog.SERVICES[rows[0].row()] if rows else None

    def ticked(self):
        return [entry for row, entry in enumerate(catalog.SERVICES)
                if self.services_table.item(row, 0).checkState() == Qt.Checked]

    def in_state(self, entries, states):
        return [entry for entry in entries if self.states.get(entry.key) in states]

    def ticked_rules(self):
        ticked = []
        for index, row in enumerate(self.rows):
            item = self.rules_table.item(index, 0)
            if item is not None and item.checkState() == Qt.Checked:
                ticked.append(row)
        return ticked

    def update_buttons(self):
        admin = self.admin()
        idle = admin and not self.busy
        entry = self.current()
        state = self.states.get(entry.key) if entry else None
        self.set_up_button.setEnabled(entry is not None and not self.busy)
        self.update_button.setEnabled(idle and entry is not None and entry.key in self.behind)
        self.start_button.setEnabled(idle and state == STOPPED)
        self.stop_button.setEnabled(idle and state == RUNNING)
        self.uninstall_button.setEnabled(idle and state in INSTALLED)
        self.folder_button.setEnabled(entry is not None and folder_exists(entry))
        ticked = self.ticked()
        self.install_ticked_button.setEnabled(idle and bool(self.to_install(ticked)))
        self.uninstall_ticked_button.setEnabled(idle and bool(self.in_state(ticked, INSTALLED)))
        self.start_all_button.setEnabled(idle and bool(self.in_state(catalog.SERVICES, (STOPPED,))))
        self.stop_all_button.setEnabled(idle and bool(self.in_state(catalog.SERVICES, (RUNNING,))))
        ticked_rules = self.ticked_rules()
        self.open_rule_button.setEnabled(idle and any(row.openable() for row in ticked_rules))
        self.remove_rule_button.setEnabled(idle and any(row.removable() for row in ticked_rules))
        self.fix_button.setEnabled(idle and any(row.state in FIXABLE for row in self.rows))
        self.remove_left_over_button.setEnabled(idle and any(row.state == firewall.LEFT_OVER for row in self.rows))
        self.reread_button.setEnabled(not self.reading)
        self.restart_button.setVisible(not admin)
        self.admin_label.setVisible(not admin)
        if not admin:
            set_hint(self.admin_label, "You can see everything here, but installing services and changing firewall "
                                       "rules needs administrator rights.", "warning")

    # ----------------------------------------------------------------- The firewall list

    def read_firewall(self):
        if self.reading:
            self.read_again = True  # What it's reading may be from before a change: read once more after
            return
        self.reading = True
        self.read_again = False
        self.reread_button.setEnabled(False)
        set_hint(self.firewall_label, "Reading Windows Firewall...", "info")
        run_in_background(firewall.read_state, self.firewall_read, self.firewall_failed)

    def firewall_read(self, state):
        self.reading = False
        self.firewall_state = state
        self.firewall_problem = ""
        self.refresh_services()  # Shows the firewall list too
        if self.read_again:
            self.read_firewall()

    def firewall_failed(self, error):
        self.reading = False
        log.warning("Couldn't read Windows Firewall: %s", error)
        self.firewall_problem = f"Couldn't read Windows Firewall: {error}"
        self.show_firewall()
        self.update_buttons()
        if self.read_again:
            self.read_firewall()

    def service_wants(self):
        """{rule name: ((port, protocols), installed: True/False/None if not known)} for the services' rules."""
        wants = {}
        for entry in catalog.SERVICES:
            state = self.states.get(entry.key)
            needed = True if state in INSTALLED else False if state == NOT_INSTALLED else None
            try:
                rules = entry.firewall()
            except Exception:
                rules = {}
            for name, want in rules.items():
                wants[name] = (want, needed)
        return wants

    def make_rows(self, state):
        rows = []
        wants = self.service_wants()
        for rule in firewall.RULES:
            if rule.service:
                (port, protocols), needed = wants.get(rule.name, ((rule.port, rule.protocols), None))
            else:
                (port, protocols), needed = page_wants(self.window, rule), None
            found = state.named(rule.name)
            verdict, details = firewall.assess(rule, found, port, protocols, needed)
            row = RuleRow(rule.name, rule.used_by, rule, port, protocols, verdict, details)
            if port is None and found:  # Its service's settings can't be read: show the port the rule has
                row.shown_port = found[0].ports
            rows.append(row)
        for rule, name in state.legacy_found():
            rows.append(RuleRow(name, rule.used_by, None, state=firewall.LEFT_OVER,
                                details="NOMAD's old name for it: Open on its row replaces it"))
        for name in state.unknown():
            rows.append(RuleRow(name, "", None, state=firewall.UNKNOWN,
                                details="Made by hand, or by another version of NOMAD"))
        return rows

    def show_firewall(self):
        if self.firewall_problem:
            set_hint(self.firewall_label, self.firewall_problem, "error")
        if self.firewall_state is None:
            return
        rows = self.make_rows(self.firewall_state)
        if not self.firewall_problem:
            warnings = self.firewall_state.warnings()
            set_hint(self.firewall_label, " ".join(warnings) if warnings else
                     "Tick rules to open or remove them. A page's rule follows the port set on that page now.",
                     "warning" if warnings else "info")
        if [row.key() for row in rows] == [row.key() for row in self.rows]:
            return  # Unchanged: keep the table as it is
        ticked = {row.name for row in self.ticked_rules()}
        current = self.rules_table.currentRow()
        current = self.rows[current].name if 0 <= current < len(self.rows) else None
        self.rows = rows
        self.rules_table.blockSignals(True)  # update_buttons once it's all there
        try:
            self.rules_table.setRowCount(len(rows))
            for index, row in enumerate(rows):
                for column, text in enumerate((row.name, row.used_by, row.allows(), row.state, row.details)):
                    item = QTableWidgetItem(text)
                    item.setToolTip(text)
                    self.rules_table.setItem(index, column, item)
                first = self.rules_table.item(index, 0)
                first.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
                first.setCheckState(Qt.Checked if row.name in ticked else Qt.Unchecked)
                self.rules_table.item(index, 3).setForeground(
                    QColor(HINT_COLORS[RULE_KINDS.get(row.state, "info")]))
                if row.name == current:
                    self.rules_table.selectRow(index)
        finally:
            self.rules_table.blockSignals(False)

    # ----------------------------------------------------------------- Running changes

    def run(self, message, job, done, touched=()):
        """Run job() on a worker thread. It returns a list of problems (or nothing): they're shown, else done."""
        self.busy = message
        self.done_text = done
        self.touched = set(touched)
        set_hint(self.message_label, message, "info")
        self.update_buttons()
        run_in_background(job, self.job_finished, self.job_failed)

    def job_finished(self, problems=None):
        self.busy = ""
        self.after_change()
        if problems:
            set_hint(self.message_label, " ".join(problems), "error")
        else:
            set_hint(self.message_label, self.done_text, "success")
        self.refresh_services()
        self.read_firewall()

    def job_failed(self, error):
        self.busy = ""
        log.warning("Services & Firewall: %s", error)
        self.after_change()
        set_hint(self.message_label, str(error), "error")
        self.refresh_services()
        self.read_firewall()

    def after_change(self):
        """Tell the pages about the services that changed (as each service's own dialog does)."""
        touched, self.touched = self.touched, set()
        released, self.released_watcher = self.released_watcher, None
        services_changed(self.window, touched, released)

    def free_port_for(self, entries):
        """A collector is about to start: this NOMAD stops listening on its port first (service_updates)."""
        self.released_watcher = free_ports(self.window, {entry.key for entry in entries}) or self.released_watcher

    # ----------------------------------------------------------------- One service

    def set_up(self, *_):
        entry = self.current()
        if entry is None or self.busy:
            return
        getattr(self.window, entry.dialog)()
        self.refresh_services()
        self.read_firewall()

    def update_service(self):
        entry = self.current()
        if entry is not None and entry.key in self.behind:
            self.free_port_for([entry])
            self.run(f"Updating the {entry.title} (this takes a few seconds)...", Job(update, [entry]),
                     f"The {entry.title} runs this NOMAD now.", [entry.key])

    def start_service(self):
        entry = self.current()
        if entry is not None:
            self.free_port_for([entry])
            self.run(f"Starting the {entry.title}...", Job(catalog.start, [entry]), f"The {entry.title} started.",
                     [entry.key])

    def stop_service(self):
        entry = self.current()
        if entry is not None:
            self.run(f"Stopping the {entry.title}...", Job(catalog.stop, [entry]), f"The {entry.title} stopped.",
                     [entry.key])

    def uninstall_service(self):
        entry = self.current()
        if entry is not None and self.confirm_uninstall([entry]):
            self.run(f"Removing the {entry.title}...", Job(uninstall, [entry]), f"Removed the {entry.title}.",
                     [entry.key])

    def open_folder(self):
        entry = self.current()
        if entry is None:
            return
        try:
            os.startfile(entry.folder())
        except OSError as error:
            set_hint(self.message_label, f"Couldn't open its folder: {error} (only administrators can open it).",
                     "error")

    # ----------------------------------------------------------------- Several services

    def confirm_uninstall(self, entries):
        lines = "\n".join(f"- {entry.title}" for entry in entries)
        kept = ("Their data stays in their folders, so installing again carries on where they left off."
                if len(entries) > 1 else "Its data stays in its folder, so installing again carries on where it "
                                         "left off.")
        tribe = ("\n\nWithout the Tribe Server, laptops can no longer sync or make changes."
                 if any(entry.key == "tribe" for entry in entries) else "")
        return QMessageBox.question(self, "Uninstall Services", f"Stop and remove these services and their firewall "
                                    f"rules?\n\n{lines}\n\n{kept}{tribe}") == QMessageBox.Yes

    def uninstall_ticked(self):
        entries = list(reversed(self.in_state(self.ticked(), INSTALLED)))  # The Map Watcher first
        if entries and self.confirm_uninstall(entries):
            self.run("Removing the ticked services...", Job(uninstall, entries),
                     f"Removed {names(entries)}.", [entry.key for entry in entries])

    def start_all(self):
        entries = self.in_state(catalog.SERVICES, (STOPPED,))
        if entries:
            self.free_port_for(entries)
            self.run("Starting the services...", Job(catalog.start, entries), f"Started {names(entries)}.",
                     [entry.key for entry in entries])

    def stop_all(self):
        entries = list(reversed(self.in_state(catalog.SERVICES, (RUNNING,))))
        if entries:
            self.run("Stopping the services...", Job(catalog.stop, entries), f"Stopped {names(entries)}.",
                     [entry.key for entry in entries])

    def to_install(self, entries):
        """Those of entries to install (not installed yet) or update (running an older NOMAD), in order."""
        return [entry for entry in entries
                if self.states.get(entry.key) == NOT_INSTALLED or entry.key in self.behind]

    def install_ticked(self):
        entries = self.to_install(self.ticked())
        if not entries:
            return
        lines = []
        for entry in entries:
            if entry.key in self.behind:
                how = "update, with the settings it has"
            else:
                how = "opens its own window to set it up" if entry.install_quietly is None else \
                    f"with its usual settings ({catalog.ports_text(entry)}); Set Up changes them after"
            lines.append(f"- {entry.title}: {how}")
        if QMessageBox.question(self, "Install Services", "Install or update these services, in this order?\n\n" +
                                "\n".join(lines)) != QMessageBox.Yes:
            return
        self.queue = list(entries)
        self.problems = []
        self.busy = "Installing or updating the ticked services..."
        self.update_buttons()
        self.next_install()

    def next_install(self):
        if not self.queue:
            self.installing = None
            self.busy = ""
            if self.problems:
                set_hint(self.message_label, " ".join(self.problems), "error")
            else:
                set_hint(self.message_label, "Done. Next: check the firewall rules below, and point the devices "
                                             "at this computer (SNMP Config and NetFlow Config pages).", "success")
            self.refresh_services()
            self.read_firewall()
            return
        entry = self.installing = self.queue.pop(0)
        updating = entry.key in self.behind
        if entry.install_quietly is None and not updating:
            set_hint(self.message_label, f"Setting up the {entry.title} in its own window...", "info")
            getattr(self.window, entry.dialog)()  # Modal: it's closed by the time this carries on
            self.refresh_services()
            if self.states.get(entry.key) == NOT_INSTALLED:
                self.problems.append(f"The {entry.title} wasn't installed (its window was closed first).")
            QTimer.singleShot(0, self.next_install)
            return
        set_hint(self.message_label, f"{'Updating' if updating else 'Installing'} the {entry.title} (this takes a "
                                     "few seconds)...", "info")
        self.touched = {entry.key}
        self.free_port_for([entry])
        run_in_background(entry.update if updating else entry.install_quietly, self.installed_one,
                          self.install_failed)

    def installed_one(self, _result=None):
        self.after_change()
        self.refresh_services()
        self.next_install()

    def install_failed(self, error):
        log.warning("Installing the %s: %s", self.installing.title if self.installing else "service", error)
        self.after_change()
        done = "updated" if self.installing.key in self.behind else "installed"
        self.problems.append(f"The {self.installing.title} wasn't {done}: {error}")
        self.refresh_services()
        self.next_install()

    # ----------------------------------------------------------------- Firewall rules

    def wanted(self, row):
        """(name, port, protocols, older names) to open a rule with: a page's port as set on it now."""
        rule = row.rule
        port, protocols = page_wants(self.window, rule) if rule.page else (row.port, row.protocols)
        return rule.name, rule.port if port is None else port, protocols or rule.protocols, rule.legacy

    def open_rules(self):
        rows = [row for row in self.ticked_rules() if row.openable()]
        if rows:
            self.run("Opening the rules in Windows Firewall...", OpenRules([self.wanted(row) for row in rows]),
                     f"Opened {names(rows)}.")

    def remove_rules(self):
        rows = [row for row in self.ticked_rules() if row.removable()]
        if not rows:
            return
        services = sorted({row.rule.service for row in rows if row.rule is not None and row.rule.service
                           and self.states.get(row.rule.service) in INSTALLED})
        warning = ("\n\nInstalled services use some of them: devices may no longer reach them." if services else "")
        if QMessageBox.question(self, "Remove Firewall Rules", "Remove these rules from Windows Firewall?\n\n" +
                                "\n".join(f"- {row.name}" for row in rows) + warning) != QMessageBox.Yes:
            return
        self.run("Removing the rules from Windows Firewall...", RemoveRules([row.name for row in rows]),
                 f"Removed {names(rows)}.")

    def fix_all(self):
        rows = [row for row in self.rows if row.state in FIXABLE and row.openable()]
        if rows:
            self.run("Fixing the rules in Windows Firewall...", OpenRules([self.wanted(row) for row in rows]),
                     f"Fixed {names(rows)}.")

    def remove_left_over(self):
        rows = [row for row in self.rows if row.state == firewall.LEFT_OVER]
        if rows:
            self.run("Removing the left-over rules...", RemoveRules([row.name for row in rows]),
                     f"Removed {names(rows)}.")

    # ----------------------------------------------------------------- Closing

    def restart_as_admin(self):
        self.timer.stop()
        self.accept()
        self.window.restart_as_admin()

    def reject(self):
        if self.busy:
            set_hint(self.message_label, f"Wait for this to finish first: {self.busy}", "warning")
            return
        self.timer.stop()
        super().reject()


# --------------------------------------------------------------------- Jobs (run on a worker thread)

class Job:
    """Do action(entry) for each service, carrying on past one that fails. Returns the problems."""

    def __init__(self, action, entries):
        self.action, self.entries = action, list(entries)

    def __call__(self):
        problems = []
        for entry in self.entries:
            try:
                self.action(entry)
            except Exception as error:
                log.warning("%s: %s", entry.title, error)
                problems.append(f"{entry.title}: {error}")
        return problems


class OpenRules:
    def __init__(self, rules):
        self.rules = rules  # (name, port, protocols, legacy names)

    def __call__(self):
        problems = []
        for name, port, protocols, legacy in self.rules:
            try:
                firewall.open_rule(name, port, protocols, legacy)
            except Exception as error:
                problems.append(f"{name}: {error}")
        return problems


class RemoveRules:
    def __init__(self, names):
        self.names = names

    def __call__(self):
        for name in self.names:
            firewall.close_rule(name)
        state = firewall.read_state()
        left = [name for name in self.names if state.named(name)]
        return [f"Couldn't remove {', '.join(left)}."] if left else []


def uninstall(entry):
    entry.uninstall()


def update(entry):
    entry.update()


def names(items):
    titles = [getattr(item, "title", None) or getattr(item, "name") for item in items]
    return titles[0] if len(titles) == 1 else ", ".join(titles[:-1]) + " and " + titles[-1]


def folder_exists(entry):
    try:
        return entry.folder().exists()
    except Exception:  # Can't be told: only administrators may look in it, or its module couldn't be read
        return False
