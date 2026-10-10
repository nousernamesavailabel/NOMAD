"""IPAM dialogs: editing networks, subnets and addresses, and reviewing a spreadsheet before importing it."""
import logging

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, \
    QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QSplitter, QTableWidget, QTableWidgetItem, \
    QShortcut, QTabWidget, QVBoxLayout, QWidget

from ..ipam.spreadsheet import DETAIL, SKIP, SUMMARY, SpreadsheetError, import_plan
from ..ipam.store import STATUSES, IpamError
from .common import set_hint
from .theme import COLORS

log = logging.getLogger(__name__)


class FieldsEditor(QTableWidget):
    """Extra details as name/value pairs (such as ASN or Telephony Rng from an imported spreadsheet)."""

    def __init__(self, fields):
        super().__init__(0, 2)
        self.setHorizontalHeaderLabels(["Detail", "Value"])
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setStretchLastSection(True)
        self.setMinimumHeight(120)
        for name, value in fields.items():
            self.add_row(name, value)
        self.add_row()

    def add_row(self, name="", value=""):
        row = self.rowCount()
        self.insertRow(row)
        self.setItem(row, 0, QTableWidgetItem(name))
        self.setItem(row, 1, QTableWidgetItem(value))

    def fields(self):
        """{name: value}; blank rows are dropped, so clearing a name removes that detail."""
        result = {}
        for row in range(self.rowCount()):
            name = (self.item(row, 0).text() if self.item(row, 0) else "").strip()
            value = (self.item(row, 1).text() if self.item(row, 1) else "").strip()
            if name:
                result[name] = value
        return result

    def keyPressEvent(self, event):
        super().keyPressEvent(event)
        last = self.rowCount() - 1
        if last < 0 or (self.item(last, 0) and self.item(last, 0).text()):
            self.add_row()  # Always leave an empty row to type a new detail into


class _EditDialog(QDialog):
    """A form with OK/Cancel and a line for errors; subclasses save in apply(), raising IpamError to stay open."""

    def __init__(self, parent, title):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(480)
        self.layout = QVBoxLayout(self)
        self.form = QFormLayout()
        self.layout.addLayout(self.form)
        self.result_item = None

    def finish_layout(self):
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.error_label)
        self.layout.addWidget(buttons)

    def save(self):
        try:
            self.result_item = self.apply()
        except IpamError as error:
            set_hint(self.error_label, str(error), "error")
            return
        self.accept()

    def apply(self):
        raise NotImplementedError


class NetworkDialog(_EditDialog):
    def __init__(self, parent, store, network=None):
        super().__init__(parent, "Edit Network" if network else "New Network")
        self.store, self.network = store, network
        self.name_input = QLineEdit(network.name if network else "")
        self.name_input.setPlaceholderText("Such as the unit, like 11AB")
        self.description_input = QLineEdit(network.description if network else "")
        self.fields_editor = FieldsEditor(network.fields if network else {})
        self.form.addRow("Name:", self.name_input)
        self.form.addRow("Description:", self.description_input)
        self.form.addRow("Details:", self.fields_editor)
        self.finish_layout()

    def apply(self):
        values = dict(name=self.name_input.text(), description=self.description_input.text().strip(),
                      fields=self.fields_editor.fields())
        if self.network is None:
            return self.store.add_network(**values)
        return self.store.update_network(self.network.id, **values)


class SubnetDialog(_EditDialog):
    """extras (a new subnet only): ((VlanStore-like, PlacementStore-like)) to set its role and link it to a VLAN of the
    network's domains as it's added; kept beside IPAM, so its export is the same."""

    def __init__(self, parent, store, network_id, subnet=None, cidr="", extras=None):
        super().__init__(parent, "Edit Subnet" if subnet else "New Subnet")
        self.store, self.network_id, self.subnet = store, network_id, subnet
        self.extras = extras if subnet is None else None
        self.extra_problem = ""
        self.cidr_input = QLineEdit(subnet.cidr if subnet else cidr)
        self.cidr_input.setPlaceholderText("10.1.2.0/24 or 10.1.2.0 255.255.255.0")
        if subnet:
            self.cidr_input.setReadOnly(True)
            self.cidr_input.setToolTip("To change the range, add a new subnet and delete this one.")
        self.name_input = QLineEdit(subnet.name if subnet else "")
        self.gateway_input = QLineEdit(subnet.gateway if subnet else "")
        self.loopbacks_check = QCheckBox("Loopbacks: every address is a /32 of its own (no network, broadcast or "
                                         "gateway)")
        self.loopbacks_check.setChecked(bool(subnet and subnet.loopbacks))
        self.loopbacks_check.toggled.connect(self.on_loopbacks_toggled)
        self.on_loopbacks_toggled(self.loopbacks_check.isChecked())
        self.description_input = QLineEdit(subnet.description if subnet else "")
        self.fields_editor = FieldsEditor(subnet.fields if subnet else {})
        self.form.addRow("Subnet:", self.cidr_input)
        self.form.addRow("Name:", self.name_input)
        self.form.addRow("", self.loopbacks_check)
        self.form.addRow("Gateway:", self.gateway_input)
        self.form.addRow("Description:", self.description_input)
        self.form.addRow("Details:", self.fields_editor)
        if self.extras is not None:
            self.add_extra_rows()
        self.finish_layout()

    def add_extra_rows(self):
        """What it's for, and the VLAN carrying it (next free, or one there is), when the network has VLAN domains."""
        from ..ipam.roles import AUTO, ROLE_NAMES
        vlans, _ = self.extras
        self.role_combo = QComboBox()
        self.role_combo.addItem("Automatic (from the map and IPAM)", AUTO)
        for key, label in ROLE_NAMES.items():
            self.role_combo.addItem(label, key)
        self.role_combo.setToolTip("What the subnet is for (Subnet Placement's Role and Scope). Kept beside IPAM.")
        self.form.addRow("It's for:", self.role_combo)
        self.vlan_combo = QComboBox()
        self.vlan_combo.addItem("(not in a VLAN, or link it later)", None)
        for domain in vlans.domains():
            if domain.network_id != self.network_id:
                continue
            number = vlans.next_free(domain.id)
            if number:
                self.vlan_combo.addItem(f"New VLAN {number} in {domain.name} (the next free)", ("new", domain.id))
            for vlan in vlans.vlans(domain.id):
                self.vlan_combo.addItem(f"VLAN {vlan.vlan} {vlan.name} ({domain.name})".replace("  ", " "),
                                        (domain.id, vlan.vlan))
        self.vlan_combo.setToolTip("Link it to a VLAN of the network's domains (VLANs page). IPAM isn't changed.")
        if self.vlan_combo.count() > 1:
            self.form.addRow("VLAN:", self.vlan_combo)

    def apply_extras(self, subnet):
        """Its role and VLAN, once it's added. A failure here doesn't undo the subnet: it's said instead."""
        from ..ipam.roles import AUTO
        from ..ipam.vlans import ACTIVE
        vlans, placements = self.extras
        role = self.role_combo.currentData()
        choice = self.vlan_combo.currentData() if self.vlan_combo.count() > 1 else None
        try:
            if role != AUTO:
                placements.set_role(self.network_id, subnet.cidr, role)
            if choice is not None and choice[0] == "new":
                number = vlans.next_free(choice[1])
                vlans.set_vlan(choice[1], number, "", ACTIVE, [subnet.cidr])
            elif choice is not None:
                vlan = vlans.vlan(*choice)
                vlans.set_vlan(choice[0], vlan.vlan, vlan.name, vlan.status, vlan.subnets + [subnet.cidr],
                               vlan.description, vlan.fields)
        except IpamError as error:
            self.extra_problem = f"{subnet.cidr} was added, but its role or VLAN wasn't set: {error}"

    def on_loopbacks_toggled(self, loopbacks):
        self.gateway_input.setEnabled(not loopbacks)
        self.gateway_input.setPlaceholderText("None: loopbacks have no gateway" if loopbacks else "")

    def apply(self):
        loopbacks = self.loopbacks_check.isChecked()
        values = dict(name=self.name_input.text(), gateway="" if loopbacks else self.gateway_input.text(),
                      description=self.description_input.text().strip(), fields=self.fields_editor.fields(),
                      loopbacks=loopbacks)
        if self.subnet is None:
            subnet = self.store.add_subnet(self.network_id, self.cidr_input.text(), **values)
            if self.extras is not None:
                self.apply_extras(subnet)
            return subnet
        return self.store.update_subnet(self.subnet.id, **values)


class AddressDialog(_EditDialog):
    def __init__(self, parent, store, network_id, ip, address=None, note="", name="", mac=""):
        super().__init__(parent, f"Address {ip}")
        self.store, self.network_id, self.ip = store, network_id, ip
        self.status_combo = QComboBox()
        for status, label in STATUSES.items():
            self.status_combo.addItem(label, status)
        self.status_combo.setToolTip("Used: a device has it. Reserved: held for something (the Reserved column "
                                     "of the spreadsheet).")
        if address is not None:
            self.status_combo.setCurrentIndex(self.status_combo.findData(address.status))
        self.name_input = QLineEdit(address.name if address else name)
        self.name_input.setPlaceholderText("Host name or what it's for")
        self.mac_input = QLineEdit(mac or (address.mac if address else ""))
        self.description_input = QLineEdit(address.description if address else "")
        address_label = QLabel(ip)
        address_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.form.addRow("Address:", address_label)
        if note:
            note_label = QLabel(note)
            note_label.setWordWrap(True)
            set_hint(note_label, note, "warning")
            self.form.addRow("", note_label)
        self.form.addRow("Status:", self.status_combo)
        self.form.addRow("Name:", self.name_input)
        self.form.addRow("MAC address:", self.mac_input)
        self.form.addRow("Description:", self.description_input)
        if address is not None and address.modified_by:
            self.form.addRow("Last changed:", QLabel(f"{address.modified[:16].replace('T', ' ')} UTC by "
                                                     f"{address.modified_by}"))
        self.finish_layout()

    def apply(self):
        return self.store.set_address(self.network_id, self.ip, self.status_combo.currentData(),
                                      self.name_input.text(), self.mac_input.text(),
                                      self.description_input.text().strip())


# --------------------------------------------------------------------- Import

PAGE_COLUMNS = ["Page", "Import as network", "Subnets", "Addresses", "To decide", "Gateways to check", "Problems",
                "Result"]
UNDECIDED_COLUMN, GATEWAYS_COLUMN, PROBLEMS_COLUMN, RESULT_COLUMN = 4, 5, 6, 7
GATEWAY_COLUMNS = ["Where", "Subnet", "Name", "Sheet's gateway", "What's wrong", "Use gateway", "Why this one"]
GATEWAY_EDIT_COLUMN, GATEWAY_WHY_COLUMN = 5, 6
DIFFERENCE_COLUMNS = ["Subnet", "Choice", "Summary says", "Detailed info says", "What differs"]
CHOICE_COLUMN = 1


def _subnet_text(subnet):
    if subnet is None:
        return "(not listed)"
    parts = [subnet.name or "(no name)"]
    if subnet.loopbacks:
        parts.append("loopbacks")
    if subnet.gateway:
        parts.append(f"gateway {subnet.gateway}")
    parts.extend(f"{name} {value}" for name, value in subnet.fields.items())
    return ", ".join(parts)


class ImportDialog(QDialog):
    """Review each page of a spreadsheet: the network to import it as, a choice for every place the summary and
    the detailed info disagree, the gateway to use where the sheet's isn't in its subnet, and the rows that can't
    be used. It can be maximized or shown full screen (F11) for room.

    With compare_with (a network), it picks the one page to compare that network with instead of importing, and
    leaves the page's plan in compare_plan as (page title, plan)."""

    def __init__(self, parent, store, file_name, sheets, skipped=(), to_server=False, team_connected=False,
                 compare_with=None):
        super().__init__(parent)
        self.store, self.sheets, self.compare_with = store, sheets, compare_with
        for sheet in sheets:
            for difference in sheet.differences:
                if difference.choice is None and (difference.summary is None or difference.detail is None):
                    difference.choice = SUMMARY if difference.summary is not None else DETAIL
        self.imported = []
        self.compare_plan = None
        self.gateway_errors = {}  # {id(GatewayFix): message} for gateways typed in that aren't usable
        self.setWindowTitle(f"Compare {compare_with.name} with {file_name}" if compare_with else
                            f"Import {file_name}")
        self.setWindowFlags(self.windowFlags() | Qt.WindowMaximizeButtonHint | Qt.WindowMinimizeButtonHint)
        self.resize(1280, 760)
        layout = QVBoxLayout(self)
        intro = QLabel("Tick the pages to import. Where Summary and Detailed Info disagree, choose which to keep "
                       "for each subnet or use the buttons to choose for the whole page. Subnets listed in only "
                       "one section are imported from that section even if you prefer the other source. "
                       "Choose Skip this subnet to exclude one. SNMP strings are never imported.")
        intro.setWordWrap(True)
        # Where the networks go, impossible to miss: only the IPAM server itself imports tribe networks
        destination = QLabel()
        destination.setWordWrap(True)
        if compare_with is not None:
            destination.setText(f"<b>Comparing {compare_with.name} with a page of this workbook.</b> Tick the page "
                                "to compare it with, and settle its differences as you would to import it. Nothing "
                                "changes until you choose what to bring in, next.")
            colors = (COLORS["success_background"], COLORS["link"])
            intro.setText("Tick one page. Where Summary and Detailed Info disagree, choose which to compare with. "
                          "Subnets listed in only one section are included from that section even if you prefer "
                          "the other source. Choose Skip this subnet to exclude one.")
        elif to_server:
            destination.setText("<b>Importing to the tribe's IPAM server.</b> Every connected laptop gets these "
                                "networks as soon as the import finishes.")
            colors = (COLORS["success_background"], COLORS["success"])
        else:
            team = ("You're connected to the tribe, but this import is NOT sent to the IPAM server and the tribe won't "
                    "see it." if team_connected else "It isn't shared with anyone.")
            destination.setText(f"<b>Importing to this computer only (Local networks).</b> {team} Tribe networks can "
                                "only be imported on the IPAM server itself (NOMAD running as administrator there).")
            colors = (COLORS["warning_background"], COLORS["warning"])
        destination.setStyleSheet(f"background: {colors[0]}; border: 1px solid {colors[1]}; color: {COLORS['text']}; "
                                  "padding: 8px;")
        layout.addWidget(destination)
        layout.addWidget(intro)
        if skipped:
            skipped_label = QLabel(f"Skipped {len(skipped)} page{'' if len(skipped) == 1 else 's'} without a Subnet "
                                   "and Mask header (not addressing pages): " + ", ".join(skipped))
            skipped_label.setWordWrap(True)
            set_hint(skipped_label, skipped_label.text(), "info")
            layout.addWidget(skipped_label)

        splitter = QSplitter(Qt.Vertical)
        self.page_table = QTableWidget(len(sheets), len(PAGE_COLUMNS))
        self.page_table.setHorizontalHeaderLabels(PAGE_COLUMNS)
        self.page_table.verticalHeader().setVisible(False)
        self.page_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.page_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.page_table.horizontalHeader().setStretchLastSection(True)
        matching = compare_with.fields.get("Imported from", "") if compare_with is not None else ""
        if compare_with is not None and not any(sheet.title == matching for sheet in sheets):
            matching = sheets[0].title if len(sheets) == 1 else ""
        for row, sheet in enumerate(sheets):
            check = QTableWidgetItem(sheet.title)
            check.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            check.setCheckState(Qt.Checked if compare_with is None or sheet.title == matching else Qt.Unchecked)
            self.page_table.setItem(row, 0, check)
            self.page_table.setItem(row, 1, QTableWidgetItem(compare_with.name if compare_with is not None
                                                             else sheet.suggested_name))
            for column, value in ((2, len(sheet.matched) + len(sheet.differences)), (3, len(sheet.addresses)),
                                  (PROBLEMS_COLUMN, len(sheet.problems))):
                item = QTableWidgetItem(str(value))
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.page_table.setItem(row, column, item)
            for column in (UNDECIDED_COLUMN, GATEWAYS_COLUMN, RESULT_COLUMN):
                item = QTableWidgetItem()
                item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                self.page_table.setItem(row, column, item)
        self.page_table.resizeColumnsToContents()
        splitter.addWidget(self.page_table)

        self.detail_tabs = QTabWidget()
        differences_page = QWidget()
        differences_layout = QVBoxLayout(differences_page)
        differences_layout.setContentsMargins(0, 4, 0, 0)
        bulk_row = QHBoxLayout()
        bulk_row.addWidget(QLabel("For every difference on this page:"))
        # In the same order as the Summary says and Detailed info says columns below
        for label, preference in (("Use the Summary", SUMMARY), ("Use the Detailed Info", DETAIL),
                                  ("Clear choices", None)):
            button = QPushButton(label)
            button.clicked.connect(lambda _, preference=preference: self.choose_all(preference))
            bulk_row.addWidget(button)
        bulk_row.addStretch()
        differences_layout.addLayout(bulk_row)
        self.difference_table = QTableWidget(0, len(DIFFERENCE_COLUMNS))
        self.difference_table.setHorizontalHeaderLabels(DIFFERENCE_COLUMNS)
        self.difference_table.verticalHeader().setVisible(False)
        self.difference_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.difference_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        differences_layout.addWidget(self.difference_table)
        gateways_page = QWidget()
        gateways_layout = QVBoxLayout(gateways_page)
        gateways_layout.setContentsMargins(0, 4, 0, 0)
        gateways_note = QLabel("The sheet gives these subnets a gateway that can't be right (outside the subnet, or "
                               "not an address). NOMAD suggests one under Use gateway and says why. Double-click it "
                               "to type another, or clear it to import the subnet without a gateway.")
        gateways_note.setWordWrap(True)
        gateways_layout.addWidget(gateways_note)
        self.gateway_table = QTableWidget(0, len(GATEWAY_COLUMNS))
        self.gateway_table.setHorizontalHeaderLabels(GATEWAY_COLUMNS)
        self.gateway_table.verticalHeader().setVisible(False)
        self.gateway_table.horizontalHeader().setStretchLastSection(True)
        self.gateway_table.setWordWrap(True)  # The explanations wrap rather than being cut off
        gateways_layout.addWidget(self.gateway_table)
        self.problem_table = self._read_only_table(["Row", "Problem"])
        self.details_table = self._read_only_table(["Detail", "Value"])
        self.detail_tabs.addTab(differences_page, "Differences")
        self.detail_tabs.addTab(gateways_page, "Gateways")
        self.detail_tabs.addTab(self.problem_table, "Problems")
        self.detail_tabs.addTab(self.details_table, "Network details")
        splitter.addWidget(self.detail_tabs)
        splitter.setSizes([180, 520])
        layout.addWidget(splitter, 1)

        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.full_screen_button = buttons.addButton("Full Screen (F11)", QDialogButtonBox.ActionRole)
        self.full_screen_button.clicked.connect(self.toggle_full_screen)
        QShortcut(QKeySequence("F11"), self, self.toggle_full_screen)
        self.import_button = buttons.addButton("Compare..." if compare_with is not None else
                                               "Import to the Tribe Server" if to_server else
                                               "Import to This Computer Only", QDialogButtonBox.AcceptRole)
        self.import_button.setProperty("accent", True)
        buttons.accepted.connect(self.run_import)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.page_table.itemSelectionChanged.connect(self.show_page)
        self.page_table.itemChanged.connect(self.on_page_ticked)
        self.gateway_table.itemChanged.connect(self.on_gateway_edited)
        self.page_table.selectRow(0)
        self.update_state()

    def on_page_ticked(self, item):
        if self.compare_with is not None and item.column() == 0 and item.checkState() == Qt.Checked:
            self.page_table.blockSignals(True)  # One page to compare with
            for row in range(self.page_table.rowCount()):
                if row != item.row():
                    self.page_table.item(row, 0).setCheckState(Qt.Unchecked)
            self.page_table.blockSignals(False)
        self.update_state()

    def toggle_full_screen(self):
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()
        self.full_screen_button.setText("Exit Full Screen (F11)" if self.isFullScreen() else "Full Screen (F11)")

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape and self.isFullScreen():
            self.toggle_full_screen()  # Escape leaves full screen before it cancels
            return
        super().keyPressEvent(event)

    @staticmethod
    def _read_only_table(headers):
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.horizontalHeader().setStretchLastSection(True)
        table.setWordWrap(True)
        return table

    def current_sheet(self):
        row = self.page_table.currentRow()
        return self.sheets[row] if 0 <= row < len(self.sheets) else None

    def show_page(self):
        sheet = self.current_sheet()
        if sheet is None:
            return
        table = self.difference_table
        # Remove the previous page's choice boxes now: Qt only deletes replaced cell widgets later, and until then
        # they can show over the new rows
        for row in range(table.rowCount()):
            widget = table.cellWidget(row, CHOICE_COLUMN)
            if widget is not None:
                widget.hide()
                widget.deleteLater()
        table.setRowCount(0)
        table.setRowCount(len(sheet.differences))
        for row, difference in enumerate(sheet.differences):
            for column, text in zip((0, 2, 3, 4), (difference.cidr, _subnet_text(difference.summary),
                                                   _subnet_text(difference.detail), difference.describe())):
                item = QTableWidgetItem(text)
                item.setToolTip(text)
                table.setItem(row, column, item)
            combo = QComboBox()
            if difference.summary is not None and difference.detail is not None:
                combo.addItem("Choose...", None)
            for choice, label in difference.options():
                combo.addItem(label, choice)
            combo.setCurrentIndex(max(0, combo.findData(difference.choice)))
            combo.currentIndexChanged.connect(
                lambda _, difference=difference, combo=combo: self.set_choice(difference, combo.currentData()))
            table.setCellWidget(row, CHOICE_COLUMN, combo)
        table.resizeColumnsToContents()
        table.setColumnWidth(CHOICE_COLUMN,
                             table.fontMetrics().horizontalAdvance("Import subnet from Detailed Info") + 48)
        for column in (2, 3, 4):
            table.setColumnWidth(column, min(table.columnWidth(column), 320))

        self.fill_gateways(sheet)
        self.problem_table.setRowCount(len(sheet.problems))
        for row, (number, message) in enumerate(sheet.problems):
            self.problem_table.setItem(row, 0, QTableWidgetItem(str(number)))
            self.problem_table.setItem(row, 1, QTableWidgetItem(message))
        self.problem_table.resizeColumnToContents(0)
        self.problem_table.resizeRowsToContents()
        self.details_table.setRowCount(len(sheet.fields))
        for row, (name, value) in enumerate(sheet.fields.items()):
            self.details_table.setItem(row, 0, QTableWidgetItem(name))
            self.details_table.setItem(row, 1, QTableWidgetItem(value))
        self.detail_tabs.setTabText(0, f"Differences ({len(sheet.differences)})")
        self.detail_tabs.setTabText(1, f"Gateways ({len(sheet.gateway_fixes)})")
        self.detail_tabs.setTabText(2, f"Problems ({len(sheet.problems)})")

    def fill_gateways(self, sheet):
        table = self.gateway_table
        table.blockSignals(True)
        table.setRowCount(len(sheet.gateway_fixes))
        for row, fix in enumerate(sheet.gateway_fixes):
            values = [f"{fix.section} row {fix.subnet.row}", fix.subnet.cidr, fix.subnet.name, fix.given,
                      fix.problem, fix.gateway, fix.reason]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column != GATEWAY_EDIT_COLUMN:
                    item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
                item.setData(Qt.UserRole, row)
                item.setToolTip(value)
                table.setItem(row, column, item)
            self.mark_gateway(row, fix)
        table.blockSignals(False)
        table.resizeColumnsToContents()
        text_width = table.fontMetrics().averageCharWidth()
        table.setColumnWidth(2, min(table.columnWidth(2), 20 * text_width))  # Name
        table.setColumnWidth(4, 28 * text_width)  # What's wrong; Why this one takes the rest of the width
        table.resizeRowsToContents()

    def mark_gateway(self, row, fix):
        """Color the chosen gateway, and show why it was chosen, or what's wrong with what was typed."""
        item = self.gateway_table.item(row, GATEWAY_EDIT_COLUMN)
        why = self.gateway_table.item(row, GATEWAY_WHY_COLUMN)
        error = self.gateway_errors.get(id(fix))
        if error:
            item.setForeground(QColor(COLORS["error"]))
            why.setText(error)
            why.setForeground(QColor(COLORS["error"]))
        elif not fix.gateway:
            item.setForeground(QColor(COLORS["muted"]))
            why.setText("Left out: the subnet is imported without a gateway.")
            why.setForeground(QColor(COLORS["muted"]))
        else:
            item.setForeground(QColor(COLORS["success"]))
            why.setText(fix.reason if fix.gateway == fix.suggested else "Typed in.")
            why.setForeground(QColor(COLORS["text"]))
        item.setToolTip("Double-click to type another gateway; clear it to leave the gateway out.")
        why.setToolTip(why.text())

    def on_gateway_edited(self, item):
        if item.column() != GATEWAY_EDIT_COLUMN:
            return
        sheet = self.current_sheet()
        fix = sheet.gateway_fixes[item.row()]
        error = fix.set_gateway(item.text())
        if error:
            self.gateway_errors[id(fix)] = error
        else:
            self.gateway_errors.pop(id(fix), None)
        self.gateway_table.blockSignals(True)
        self.mark_gateway(item.row(), fix)
        self.gateway_table.blockSignals(False)
        self.gateway_table.resizeRowToContents(item.row())
        self.update_state()

    def set_choice(self, difference, choice):
        difference.choice = choice
        self.update_state()

    def choose_all(self, preference):
        sheet = self.current_sheet()
        if sheet is None:
            return
        for difference in sheet.differences:
            if preference == SKIP:
                difference.choice = SKIP
            elif difference.summary is not None and difference.detail is not None:
                difference.choice = preference
            else:  # Import from the available source even when the other source is preferred.
                difference.choice = SUMMARY if difference.summary is not None else DETAIL
        self.show_page()
        self.update_state()

    def chosen_pages(self):
        """[(sheet, network name)] for the ticked pages."""
        return [(sheet, self.page_table.item(row, 1).text().strip()) for row, sheet in enumerate(self.sheets)
                if self.page_table.item(row, 0).checkState() == Qt.Checked]

    def update_state(self):
        self.page_table.blockSignals(True)
        chosen = self.chosen_pages()
        names = [name.casefold() for _, name in chosen]
        blockers = []
        for row, sheet in enumerate(self.sheets):
            ticked = self.page_table.item(row, 0).checkState() == Qt.Checked
            name = self.page_table.item(row, 1).text().strip()
            undecided = len(sheet.undecided())
            bad_gateways = sum(id(fix) in self.gateway_errors for fix in sheet.gateway_fixes)
            gateways_item = self.page_table.item(row, GATEWAYS_COLUMN)
            if bad_gateways:
                gateways_item.setText(f"{bad_gateways} not usable")
                gateways_item.setForeground(QColor(COLORS["error"]))
            elif sheet.gateway_fixes:
                gateways_item.setText(f"{len(sheet.gateway_fixes)} fixed")
                gateways_item.setForeground(QColor(COLORS["warning"]))
            else:
                gateways_item.setText("None")
                gateways_item.setForeground(QColor(COLORS["muted"]))
            gateways_item.setToolTip("Gateways the sheet gives that can't be right; see the Gateways tab for the "
                                     "one NOMAD will use instead." if sheet.gateway_fixes else "")
            self.page_table.item(row, UNDECIDED_COLUMN).setText(
                f"{undecided} of {len(sheet.differences)}" if undecided else "Done")
            self.page_table.item(row, UNDECIDED_COLUMN).setForeground(
                QColor(COLORS["warning" if undecided else "muted"]))
            result, kind = "", "muted"
            if self.compare_with is not None:
                result = "Compare" if ticked else ""
            elif not ticked:
                result = "Not imported"
            elif not name:
                result, kind = "Needs a network name", "error"
            elif names.count(name.casefold()) > 1:
                result, kind = "Two pages have this name", "error"
            elif self.store.network_named(name) is not None:
                result, kind = "Replaces the existing network", "warning"
            else:
                result = "New network"
            self.page_table.item(row, RESULT_COLUMN).setText(result)
            self.page_table.item(row, RESULT_COLUMN).setForeground(QColor(COLORS[kind]))
            if ticked and (kind == "error" or undecided or bad_gateways):
                blockers.append(sheet.title)
        self.page_table.blockSignals(False)
        self.import_button.setEnabled(bool(chosen) and not blockers)
        if self.compare_with is not None:
            if not chosen:
                set_hint(self.status_label, "Tick the page to compare with.", "info")
            elif blockers:
                set_hint(self.status_label, "Still to sort out before comparing: choices under Differences, or "
                                            "gateways under Gateways.", "warning")
            else:
                set_hint(self.status_label, f"Ready to compare with {chosen[0][0].title}.", "success")
        elif not chosen:
            set_hint(self.status_label, "Tick at least one page to import.", "info")
        elif blockers:
            set_hint(self.status_label, "Still to sort out before importing: " + ", ".join(blockers) +
                     " (choices under Differences, gateways under Gateways, or the network name).", "warning")
        else:
            set_hint(self.status_label, f"Ready to import {len(chosen)} page{'' if len(chosen) == 1 else 's'}.",
                     "success")

    def run_import(self):
        chosen = self.chosen_pages()
        if self.compare_with is not None:
            sheet = chosen[0][0]
            self.compare_plan = (sheet.title, import_plan(sheet, self.compare_with.name))
            self.accept()
            return
        replacing = [name for _, name in chosen if self.store.network_named(name) is not None]
        if replacing and QMessageBox.question(
                self, "Replace Networks",
                "These networks already exist, and importing replaces everything recorded in them:\n\n" +
                "\n".join(replacing) + "\n\nReplace them?") != QMessageBox.Yes:
            return
        try:
            # All pages at once (in one request, when importing to the server), so it's all or nothing
            self.imported = self.store.import_networks([import_plan(sheet, name, replace=name in replacing)
                                                        for sheet, name in chosen])
            for sheet, name in chosen:
                log.info("Imported page %r as network %r: %d subnets, %d addresses, %d problems", sheet.title,
                         name, len(sheet.subnets_to_import()), len(sheet.addresses), len(sheet.problems))
        except (IpamError, SpreadsheetError) as error:
            log.warning("Import failed (nothing imported): %s", error)
            self.imported = []
            set_hint(self.status_label, f"Nothing was imported: {error}", "error")
            return
        self.accept()


REFUSED_COLUMNS = ["Network", "Address", "Your change", "Made (UTC)", "Why it wasn't made"]


class RefusedDialog(QDialog):
    """Changes made offline that the IPAM server refused (someone else changed the address first): record the
    same thing at the next free address instead, or discard it."""

    def __init__(self, parent, team):
        super().__init__(parent)
        self.team = team
        self.setWindowTitle("Refused Changes")
        self.resize(1000, 420)
        layout = QVBoxLayout(self)
        intro = QLabel("These changes were made while the IPAM server couldn't be reached. When they were sent, "
                       "someone else had already changed those addresses, so the server kept theirs. For each, "
                       "record the same thing at the next free address in its subnet, or discard it.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.table = QTableWidget(0, len(REFUSED_COLUMNS))
        self.table.setHorizontalHeaderLabels(REFUSED_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setWordWrap(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.table, 1)
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QHBoxLayout()
        self.next_free_button = QPushButton("Use Next Free Address...")
        self.next_free_button.setProperty("accent", True)
        self.discard_button = QPushButton("Discard")
        close_button = QPushButton("Close")
        for button in (self.next_free_button, self.discard_button):
            buttons.addWidget(button)
        buttons.addStretch()
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        self.next_free_button.clicked.connect(self.use_next_free)
        self.discard_button.clicked.connect(self.discard)
        close_button.clicked.connect(self.accept)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.fill()

    def fill(self):
        self.entries = self.team.refused()
        networks = {network.id: network.name for network in self.team.networks()}
        self.table.setRowCount(len(self.entries))
        for row, entry in enumerate(self.entries):
            if entry["action"] == "set_address":
                data = entry["data"]
                change = f"{STATUSES.get(data.get('status'), 'Used')}: {data.get('name') or '(no name)'}"
            else:
                change = "Mark free"
            values = [networks.get(entry["network_id"], "(deleted network)"), entry["ip"], change,
                      entry["made"][:16].replace("T", " "), entry["error"]]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
        for column in range(4):  # The reason takes the rest of the width, wrapping onto more lines
            self.table.resizeColumnToContents(column)
        self.table.resizeRowsToContents()
        if self.entries:
            self.table.selectRow(0)
        self.update_buttons()

    def showEvent(self, event):
        super().showEvent(event)
        self.table.resizeRowsToContents()  # Now the reason column has its final width

    def selected(self):
        rows = self.table.selectionModel().selectedRows()
        return self.entries[rows[0].row()] if rows else None

    def update_buttons(self):
        entry = self.selected()
        self.discard_button.setEnabled(entry is not None)
        self.next_free_button.setEnabled(entry is not None and entry["action"] == "set_address")

    def use_next_free(self):
        entry = self.selected()
        subnet = self.team.subnet_for(entry["network_id"], entry["ip"])
        if subnet is None:
            set_hint(self.message_label, f"{entry['ip']} isn't in any subnet now, so there's no subnet to take "
                                         "another address from.", "error")
            return
        address = self.team.next_free(subnet)
        if address is None:
            set_hint(self.message_label, f"{subnet.cidr} has no free addresses left.", "error")
            return
        name = entry["data"].get("name") or "(no name)"
        if QMessageBox.question(self, "Use Next Free Address",
                                f"Record {name} at {address} in {subnet.cidr} instead of {entry['ip']}?") != \
                QMessageBox.Yes:
            return
        try:
            self.team.set_address(entry["network_id"], str(address), **entry["data"])
        except IpamError as error:
            set_hint(self.message_label, f"Couldn't record it: {error}", "error")
            return
        self.team.discard(entry["seq"])
        set_hint(self.message_label, f"Recorded {name} at {address}.", "success")
        self.fill()

    def discard(self):
        entry = self.selected()
        self.team.discard(entry["seq"])
        set_hint(self.message_label, f"Discarded the change to {entry['ip']}.", "info")
        self.fill()
