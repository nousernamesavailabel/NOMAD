"""The ACLs page's editors for prefix lists and route maps: their entries in a table (numbers typed in, dragged into
place), checks, where they're applied, and a route tester. They edit the page's working copy of the device; the
page shows the changes and sends them."""
import logging
import re

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QDialog, QGridLayout, QGroupBox, QHBoxLayout, QHeaderView, \
    QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPushButton, QSplitter, \
    QTableWidget, QTableWidgetItem, QToolButton, QVBoxLayout, QWidget

from ..netmap import routepolicy
from ..netmap.acl import PERMIT, V6
from ..netmap.routepolicy import OTHER, PREFIX_LIST, ROUTE_MAP
from .acl_dialogs import TextDialog, severity_color
from .common import set_hint
from .policy_dialogs import MapEntryDialog, PolicyApplyDialog, PrefixEntryDialog
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

PREFIX_COLUMNS = ["Seq", "Action", "Prefix", "ge", "le", "Matches", "Hits"]
MAP_COLUMNS = ["Seq", "Action", "Match", "Set", "Continue", "Description", "Hits"]


class SeqTable(QTableWidget):
    """Numbered entries, which can be dragged to a new place; only the number column can be typed in."""
    rows_moved = pyqtSignal(list, int)  # Rows, the row they go before

    def __init__(self, columns):
        super().__init__(0, len(columns))
        self.setHorizontalHeaderLabels(columns)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)  # Seq cells only
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.InternalMove)
        self.setDropIndicatorShown(True)
        self.verticalHeader().setVisible(False)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.horizontalHeader().setStretchLastSection(True)

    def dropEvent(self, event):
        if event.source() is not self:
            event.ignore()
            return
        rows = sorted({index.row() for index in self.selectedIndexes()})
        target = self.indexAt(event.pos()).row()
        if target < 0:
            target = self.rowCount()
        elif self.dropIndicatorPosition() == QAbstractItemView.BelowItem:
            target += 1
        event.setDropAction(Qt.IgnoreAction)
        event.accept()
        if rows:
            self.rows_moved.emit(rows, target)


class SeqEditor(QWidget):
    """What the prefix list and route map editors share: the head, where it's applied, the entries, the checks."""
    columns = []
    kind = ""
    noun = "entry"

    def __init__(self, tab):
        super().__init__()
        self.tab = tab
        self.filling = False
        self.pending_number = None  # (row, text) typed into a Seq cell, taken once the editor has closed
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        self.title = QLabel()
        font = self.title.font()
        font.setBold(True)
        self.title.setFont(font)
        head.addWidget(self.title, 1)
        library = QPushButton("Save to Library...")
        library.clicked.connect(self.save_to_library)
        head.addWidget(library)
        compare = QPushButton("Compare...")
        compare.setToolTip("Compare with the same one on the other devices read")
        compare.clicked.connect(self.compare)
        head.addWidget(compare)
        self.delete_button = QPushButton("Delete")
        self.delete_button.clicked.connect(self.delete_item)
        head.addWidget(self.delete_button)
        layout.addLayout(head)
        applied = QHBoxLayout()
        self.applied_label = QLabel()
        self.applied_label.setWordWrap(True)
        applied.addWidget(self.applied_label, 1)
        self.apply_button = accent_button("Apply To...")
        self.apply_button.clicked.connect(self.apply_to)
        applied.addWidget(self.apply_button)
        self.take_off_button = QToolButton()
        self.take_off_button.setText("Take Off")
        self.take_off_button.setPopupMode(QToolButton.InstantPopup)
        self.take_off_menu = QMenu(self.take_off_button)
        self.take_off_menu.aboutToShow.connect(self.fill_take_off_menu)
        self.take_off_button.setMenu(self.take_off_menu)
        applied.addWidget(self.take_off_button)
        layout.addLayout(applied)
        self.make_extra(layout)
        split = QSplitter(Qt.Vertical)
        upper = QWidget()
        upper_layout = QVBoxLayout(upper)
        upper_layout.setContentsMargins(0, 0, 0, 0)
        self.table = SeqTable(self.columns)
        self.table.rows_moved.connect(self.move_rows)
        self.table.itemDoubleClicked.connect(self.edit_entry)
        self.table.itemChanged.connect(self.on_cell_changed)
        self.table.itemSelectionChanged.connect(self.update_buttons)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self.show_menu)
        upper_layout.addWidget(self.table, 1)
        row = QHBoxLayout()
        self.add_button = accent_button("Add Entry...")
        self.add_button.clicked.connect(self.add_entry)
        row.addWidget(self.add_button)
        self.edit_button = QPushButton("Edit...")
        self.edit_button.clicked.connect(self.edit_entry)
        row.addWidget(self.edit_button)
        self.duplicate_button = QPushButton("Duplicate")
        self.duplicate_button.clicked.connect(self.duplicate_entries)
        row.addWidget(self.duplicate_button)
        self.remove_button = QPushButton("Delete")
        self.remove_button.clicked.connect(self.delete_entries)
        row.addWidget(self.remove_button)
        self.up_button = QPushButton("Move Up")
        self.up_button.clicked.connect(self.move_up)
        row.addWidget(self.up_button)
        self.down_button = QPushButton("Move Down")
        self.down_button.clicked.connect(self.move_down)
        row.addWidget(self.down_button)
        row.addStretch(1)
        upper_layout.addLayout(row)
        split.addWidget(upper)
        lower = QWidget()
        lower_layout = QHBoxLayout(lower)
        lower_layout.setContentsMargins(0, 0, 0, 0)
        checks = QGroupBox("Checks")
        checks_layout = QVBoxLayout(checks)
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        self.findings_list.itemClicked.connect(self.on_finding_clicked)
        checks_layout.addWidget(self.findings_list)
        lower_layout.addWidget(checks, 3)
        lower_layout.addWidget(self.make_tester(), 2)
        split.addWidget(lower)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        layout.addWidget(split, 1)

    # ----------------------------------------------------------------- For the editors to fill in

    def make_extra(self, layout):
        pass

    def make_tester(self):
        return QWidget()

    def current(self):
        return None

    def items(self, device):
        """The device's dict of these (prefix_lists or route_maps)."""
        return {}

    def plan(self, before, item):
        return None

    def cells(self, entry, number):
        return []

    def entry_dialog(self, entry=None, number=""):
        return None, None

    def findings(self, item, device):
        return []

    def max_seq(self):
        return routepolicy.MAX_MAP_SEQ

    def uses(self, item, device):
        return []

    def library_item(self, item):
        return ""

    def fill_test(self, entry):
        pass

    # ----------------------------------------------------------------- Shared

    def device(self):
        return self.tab.device()

    def before_item(self, item):
        """The same one as read from the device (None: new, or the Scratch Pad)."""
        if self.tab.current_key == self.tab.scratch_key:
            return None
        before = self.tab.read.get(self.tab.current_key)
        return self.items(before).get(item.key) if before is not None else None

    def planned(self, item=None):
        item = item or self.current()
        if item is None:
            return None
        try:
            return self.plan(self.before_item(item), item)
        except Exception:  # A plan that fails shouldn't stop the table showing
            log.exception("Planning %s failed", item.name)
            return None

    def planned_numbers(self, item=None):
        change = self.planned(item)
        return change.numbers if change is not None else {}

    def tested_item(self, item):
        """The item as it will be (numbered as planned), its entries tagged with their rows."""
        change = self.planned(item)
        if change is not None and change.after is not None:
            return change.after
        return item.copy(entries=[entry.copy(origin=row) for row, entry in enumerate(item.entries)])

    def entry_state(self, before, entry):
        if self.tab.current_key == self.tab.scratch_key:
            return ""
        if before is None or not entry.seq:
            return "new"
        old = next((item for item in before.entries if item.seq == entry.seq), None)
        if old is None:
            return "new"
        return "" if old.key() == entry.key() else "changed"

    def fill(self):
        item, device = self.current(), self.device()
        if item is None or device is None:
            return
        before = self.before_item(item)
        new = before is None and self.tab.current_key != self.tab.scratch_key
        self.title.setText(item.title[:1].upper() + item.title[1:] + ("  - new, not on the device yet" if new
                                                                      else ""))
        uses = self.uses(item, device)
        if uses:
            set_hint(self.applied_label, "Used by: " + "; ".join(uses), "info")
        else:
            set_hint(self.applied_label, "Not used anywhere: it does nothing until it's applied (Apply To...) or "
                                         "named by something.", "warning")
        checks = self.findings(item, device)
        flagged = {}
        for finding in checks:
            if finding.index >= 0 and finding.index not in flagged:
                flagged[finding.index] = finding
        selected = self.selected_rows()
        numbers = self.planned_numbers(item)
        table = self.table
        self.filling = True
        table.setRowCount(len(item.entries))
        for row, entry in enumerate(item.entries):
            state = self.entry_state(before, entry)
            planned = numbers.get(row)
            if planned is None:
                number = str(entry.seq) if entry.seq else ("new" if state == "new" else "")
            elif entry.seq and planned != entry.seq and self.tab.current_key != self.tab.scratch_key:
                number = f"{planned} (was {entry.seq})"
            else:
                number = str(planned)
            for column, text in enumerate(self.cells(entry, number)):
                cell = QTableWidgetItem(text)
                if column == 0:
                    cell.setFlags(cell.flags() | Qt.ItemIsEditable)
                    cell.setToolTip(self.number_tip(entry, planned, state))
                else:
                    cell.setFlags(cell.flags() & ~Qt.ItemIsEditable)
                    cell.setToolTip(text)
                if state:
                    cell.setForeground(QColor(COLORS["accent"]))
                    font = cell.font()
                    font.setBold(True)
                    cell.setFont(font)
                if column == 1:
                    cell.setForeground(QColor(COLORS["success"] if entry.action == PERMIT else COLORS["error"]))
                table.setItem(row, column, cell)
            finding = flagged.get(row)
            if finding is not None:
                table.item(row, 0).setToolTip(finding.text + "\n" + table.item(row, 0).toolTip())
                table.item(row, 0).setBackground(severity_color(finding.severity).darker(250))
        self.filling = False
        table.resizeColumnsToContents()
        self.select_rows(selected)
        self.findings_list.clear()
        for finding in checks:
            entry = QListWidgetItem(finding.text)
            entry.setForeground(severity_color(finding.severity))
            entry.setData(Qt.UserRole, finding.index)
            self.findings_list.addItem(entry)
        if not checks:
            entry = QListWidgetItem("Nothing found.")
            entry.setForeground(QColor(COLORS["muted"]))
            self.findings_list.addItem(entry)
        self.update_buttons()

    def number_tip(self, entry, planned, state):
        if entry.want_seq and planned is not None and planned != entry.want_seq:
            tip = f"Number {entry.want_seq} was typed in, but it can't have it: it gets {planned}."
        elif entry.want_seq:
            tip = "A number typed in."
        elif state == "new":
            tip = "New: the number it gets when sent."
        elif entry.seq and planned is not None and planned != entry.seq:
            tip = f"Renumbered when sent (it's {entry.seq} on the device now)."
        else:
            tip = "Its number on the device." if entry.seq else ""
        return (tip + "\n" if tip else "") + f"Double-click (or F2) to type a number: the {self.noun} goes to its " \
                                             "place by it. Nothing typed: an automatic one."

    def selected_rows(self):
        return sorted({index.row() for index in self.table.selectedIndexes()})

    def select_rows(self, rows):
        table = self.table
        table.clearSelection()
        mode = table.selectionMode()
        table.setSelectionMode(QAbstractItemView.MultiSelection)
        for row in rows:
            if 0 <= row < table.rowCount():
                table.selectRow(row)
        table.setSelectionMode(mode)
        if rows and 0 <= rows[0] < table.rowCount():
            table.scrollToItem(table.item(rows[0], 0))

    def edited(self, focus=None):
        self.tab.edited()
        if focus is not None:
            self.select_rows(focus)

    def on_finding_clicked(self, item):
        index = item.data(Qt.UserRole)
        if index is not None and index >= 0:
            self.select_rows([index])

    def update_buttons(self):
        item = self.current()
        rows = self.selected_rows() if item is not None else []
        real = self.tab.current_key not in ("", self.tab.scratch_key)
        self.add_button.setEnabled(item is not None)
        for button in (self.edit_button, self.duplicate_button, self.remove_button):
            button.setEnabled(bool(rows))
        self.up_button.setEnabled(bool(rows) and rows[0] > 0)
        self.down_button.setEnabled(bool(rows) and item is not None and rows[-1] < len(item.entries) - 1)
        self.apply_button.setEnabled(item is not None and real)
        self.take_off_button.setEnabled(item is not None and real)

    # ----------------------------------------------------------------- Numbers typed in

    def on_cell_changed(self, cell):
        if self.filling or cell.column() != 0:
            return
        self.pending_number = (cell.row(), cell.text())
        QTimer.singleShot(0, self.take_pending_number)  # Not while the table's editor is still closing

    def take_pending_number(self):
        if self.pending_number is None:
            return
        (row, text), self.pending_number = self.pending_number, None
        text = text.strip()
        found = re.match(r"(\d+)", text)
        if text and not found:
            set_hint(self.tab.status_label, "Type a sequence number (or nothing, for an automatic one).", "error")
            self.fill()
            return
        self.set_number(row, int(found.group(1)) if found else None)

    def set_number(self, row, number):
        """Give the entry on row number (None: an automatic one), moving it to its place by that number."""
        item = self.current()
        if item is None or not 0 <= row < len(item.entries):
            return
        entry = item.entries[row]
        if number is None:
            if entry.want_seq:
                entry.want_seq = 0
                self.edited([row])
            else:
                self.fill()
            return
        if not 1 <= number <= self.max_seq():
            set_hint(self.tab.status_label, f"A sequence number is 1 to {self.max_seq()}.", "error")
            self.fill()
            return
        numbers = self.planned_numbers(item)
        for other_row, other in enumerate(item.entries):
            staying = other.want_seq or (other.seq if numbers.get(other_row) == other.seq else 0)
            if other_row != row and staying == number:
                set_hint(self.tab.status_label, f"Line {other_row + 1} has number {number} already: give that one "
                                                "another first.", "error")
                self.fill()
                return
        others = [(other_row, other) for other_row, other in enumerate(item.entries) if other_row != row]
        at = next((place for place, (other_row, other) in enumerate(others)
                   if (other.want_seq or numbers.get(other_row) or other.seq) > number), len(others))
        item.entries.insert(at, item.entries.pop(row))
        entry.want_seq = number
        self.edited([at])
        got = self.planned_numbers(item).get(at)
        if got is not None and got != number:
            set_hint(self.tab.status_label, f"It can't have {number} (see Changes): it gets {got}.", "warning")
        elif at != row:
            set_hint(self.tab.status_label, f"Moved to line {at + 1}: an {self.noun}'s number is its place.",
                     "info")

    # ----------------------------------------------------------------- Entries

    def add_entry(self):
        item = self.current()
        if item is None:
            return
        entry, number = self.entry_dialog()
        if entry is None:
            return
        entry.seq, entry.hits, entry.want_seq = 0, None, 0
        rows = self.selected_rows()
        at = rows[-1] + 1 if rows else len(item.entries)
        item.entries.insert(at, entry)
        self.edited([at])
        if number:
            self.set_number(at, int(number))

    def edit_entry(self, *args):
        if args and isinstance(args[0], QTableWidgetItem) and args[0].column() == 0:
            return  # A double-click on the number types a number in
        item = self.current()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        row = rows[0]
        old = item.entries[row]
        shown = self.planned_numbers(item).get(row) or old.want_seq or old.seq or ""
        entry, number = self.entry_dialog(old, shown)
        if entry is None:
            return
        if entry.key() != old.key():
            entry.hits = None
            item.entries[row] = entry
            self.edited([row])
        if number is not None:
            self.set_number(row, int(number) if number else None)

    def duplicate_entries(self):
        item = self.current()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        copies = [item.entries[row].copy(seq=0, hits=None, want_seq=0) for row in rows]
        at = rows[-1] + 1
        item.entries[at:at] = copies
        self.edited(list(range(at, at + len(copies))))

    def delete_entries(self):
        item = self.current()
        rows = self.selected_rows()
        if item is None or not rows:
            return
        for row in reversed(rows):
            del item.entries[row]
        self.edited([min(rows[0], len(item.entries) - 1)] if item.entries else [])

    def move_rows(self, rows, target):
        item = self.current()
        if item is None or not rows:
            return
        moving = [item.entries[row] for row in rows]
        for entry in moving:  # Put where they're dropped: numbers typed in before would pull them back
            entry.want_seq = 0
        before = sum(1 for row in rows if row < target)
        rest = [entry for row, entry in enumerate(item.entries) if row not in rows]
        at = max(0, min(len(rest), target - before))
        item.entries = rest[:at] + moving + rest[at:]
        self.edited(list(range(at, at + len(moving))))

    def move_up(self):
        rows = self.selected_rows()
        if rows and rows[0] > 0:
            self.move_rows(rows, rows[0] - 1)

    def move_down(self):
        rows = self.selected_rows()
        item = self.current()
        if item is not None and rows and rows[-1] < len(item.entries) - 1:
            self.move_rows(rows, rows[-1] + 2)

    def show_menu(self, position):
        if self.current() is None:
            return
        menu = QMenu(self)
        actions = {menu.addAction("Add Entry..."): self.add_entry}
        if self.selected_rows():
            actions[menu.addAction("Edit...")] = self.edit_entry
            actions[menu.addAction("Duplicate")] = self.duplicate_entries
            actions[menu.addAction("Delete")] = self.delete_entries
            menu.addSeparator()
            actions[menu.addAction("Move Up")] = self.move_up
            actions[menu.addAction("Move Down")] = self.move_down
            menu.addSeparator()
            actions[menu.addAction("Test a Route Like This")] = self.test_like_entry
        chosen = menu.exec_(self.table.viewport().mapToGlobal(position))
        if chosen in actions:
            actions[chosen]()

    def test_like_entry(self):
        item, rows = self.current(), self.selected_rows()
        if item is not None and rows:
            self.fill_test(item.entries[rows[0]])

    # ----------------------------------------------------------------- Where it's used

    def apply_to(self):
        item, device = self.current(), self.device()
        if item is None:
            return
        if self.tab.current_key == self.tab.scratch_key:
            set_hint(self.tab.status_label, "The Scratch Pad has nothing to apply it to: save it to the Library and "
                                            "use it on a device.", "warning")
            return
        dialog = PolicyApplyDialog(self, device, self.kind, item)
        if dialog.exec_() != QDialog.Accepted:
            return
        routepolicy.set_use(device, dialog.chosen)
        self.tab.edited()

    def fill_take_off_menu(self):
        menu = self.take_off_menu
        menu.clear()
        item, device = self.current(), self.device()
        uses = [use for use in routepolicy.uses_of(device, self.kind, item.name, getattr(item, "family", None) or
                                                   "ipv4") if use.where != OTHER] if item is not None else []
        for use in uses:
            menu.addAction(use.label(), lambda use=use: self.take_off(use))
        if not uses:
            menu.addAction("It isn't applied anywhere NOMAD can take it off").setEnabled(False)

    def take_off(self, use):
        routepolicy.take_use_off(self.device(), use)
        self.tab.edited()

    def delete_item(self):
        item, device = self.current(), self.device()
        if item is None:
            return
        family = getattr(item, "family", "ipv4")
        uses = routepolicy.uses_of(device, self.kind, item.name, family)
        placed = [use for use in uses if use.where != OTHER]
        others = [use for use in uses if use.where == OTHER]
        text = f"Delete {item.title}?"
        if placed:
            text += "\n\nIt's taken off " + ", ".join(use.label() for use in placed) + " first."
        named = []
        if self.kind == PREFIX_LIST:
            named = [f"route map {rmap.name} entry {entry.seq}" for rmap, entry in
                     routepolicy.maps_naming(device, PREFIX_LIST, item.name, family)]
        if others or named:
            text += ("\n\nThese still name it: " + "; ".join([use.line for use in others] + named) +
                     ". What IOS does with a missing one depends on the feature.")
        if QMessageBox.question(self, "Delete", text) != QMessageBox.Yes:
            return
        for use in placed:
            routepolicy.take_use_off(device, use)
        del self.items(device)[item.key]
        self.tab.current_item = None
        self.tab.edited()

    # ----------------------------------------------------------------- Library and comparing

    def save_to_library(self):
        item, device = self.current(), self.device()
        if item is None:
            return
        name, ok = QInputDialog.getText(self, "Save to Library", "Name in the library:", text=item.name)
        name = name.strip()
        if not ok or not name:
            return
        if any(entry.name == name for entry in self.tab.store.library) and QMessageBox.question(
                self, "Save to Library", f"The library has {name} already. Replace it?") != QMessageBox.Yes:
            return
        self.tab.store.add_to_library(name, routepolicy.library_config(item, device), item=self.library_item(item))
        self.tab.fill_library()
        set_hint(self.tab.status_label, f"Saved {item.title} to the library as {name}.", "success")

    def compare(self):
        item = self.current()
        if item is None:
            return
        here = self.tab.targets[self.tab.current_key].label
        others = [(key, device) for key, device in self.tab.read.items()
                  if key not in (self.tab.current_key, self.tab.scratch_key) and device.read and
                  item.key in self.items(device)]
        if not others:
            set_hint(self.tab.status_label, f"No other device read has {item.name}: read more devices first.", "info")
            return
        mine = [self.entry_text(entry) for entry in item.entries]
        lines = [f"{item.title} on {here} (as edited here) against the others read:", ""]
        for key, device in others:
            theirs = [self.entry_text(entry) for entry in self.items(device)[item.key].entries]
            label = self.tab.targets[key].label if key in self.tab.targets else key
            only_here = [text for text in mine if text not in theirs]
            only_there = [text for text in theirs if text not in mine]
            if not only_here and not only_there:
                lines.append(f"{label}: the same" + (" in the same order." if mine == theirs else
                                                     ", in another order."))
            else:
                lines.append(f"{label}:")
                lines += [f"  only on {here}:   {text}" for text in only_here]
                lines += [f"  only on {label}:  {text}" for text in only_there]
            lines.append("")
        TextDialog(self, f"Compare {item.name}", "\n".join(lines)).exec_()

    def entry_text(self, entry):
        return ""


class PrefixListEditor(SeqEditor):
    columns = PREFIX_COLUMNS
    kind = PREFIX_LIST

    def make_extra(self, layout):
        row = QHBoxLayout()
        row.addWidget(QLabel("Description:"))
        self.description_input = QLineEdit()
        self.description_input.editingFinished.connect(self.set_description)
        row.addWidget(self.description_input, 1)
        layout.addLayout(row)

    def make_tester(self):
        box = QGroupBox("Route Tester")
        grid = QGridLayout(box)
        self.test_prefix = QLineEdit()
        self.test_prefix.setPlaceholderText("10.1.2.0/24")
        self.test_prefix.returnPressed.connect(self.run_test)
        test = QPushButton("Test")
        test.clicked.connect(self.run_test)
        self.test_result = QLabel()
        self.test_result.setWordWrap(True)
        grid.addWidget(QLabel("Prefix:"), 0, 0)
        grid.addWidget(self.test_prefix, 0, 1)
        grid.addWidget(test, 0, 2)
        grid.addWidget(self.test_result, 1, 0, 1, 3)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(2, 1)
        return box

    def current(self):
        return self.tab.current_plist()

    def items(self, device):
        return device.prefix_lists

    def plan(self, before, item):
        return routepolicy.prefix_change(before, item)

    def max_seq(self):
        return routepolicy.MAX_PREFIX_SEQ

    def cells(self, entry, number):
        return [number, entry.action, entry.prefix, f"/{entry.ge}" if entry.ge else "",
                f"/{entry.le}" if entry.le else "", entry.explain(), "" if entry.hits is None else str(entry.hits)]

    def entry_dialog(self, entry=None, number=""):
        dialog = PrefixEntryDialog(self, self.current(), entry, self.tab.address_choices(), number)
        if dialog.exec_() != QDialog.Accepted:
            return None, None
        typed = dialog.number_input.text().strip()
        return dialog.entry, (None if typed == str(number) else typed)

    def findings(self, item, device):
        return routepolicy.prefix_findings(item)

    def uses(self, item, device):
        found = [use.label() for use in routepolicy.uses_of(device, PREFIX_LIST, item.name, item.family)]
        found += [f"route map {rmap.name} entry {entry.seq or 'new'}" for rmap, entry in
                  routepolicy.maps_naming(device, PREFIX_LIST, item.name, item.family)]
        return found

    def library_item(self, item):
        return f"prefix-list {item.family} {item.name}"

    def entry_text(self, entry):
        return entry.body()

    def fill(self):
        item = self.current()
        if item is not None and not self.description_input.hasFocus():
            self.description_input.setText(item.description)
        super().fill()

    def set_description(self):
        item = self.current()
        text = self.description_input.text().strip()
        if item is not None and item.description != text:
            item.description = text
            self.tab.edited()

    def fill_test(self, entry):
        self.test_prefix.setText(entry.prefix)
        self.run_test()

    def run_test(self):
        item = self.current()
        if item is None:
            return
        try:
            network = routepolicy.route_from_text(self.test_prefix.text()).network
        except ValueError as error:
            set_hint(self.test_result, str(error), "error")
            return
        if (network.version == 6) != (item.family == V6):
            set_hint(self.test_result, f"{item.name} is an {'IPv6' if item.family == V6 else 'IPv4'} prefix list.",
                     "error")
            return
        planned = self.tested_item(item)
        permitted, entry, text = routepolicy.evaluate_prefix_list(planned, network)
        before = self.before_item(item)
        if before is not None:
            was = routepolicy.evaluate_prefix_list(before, network)[0]
            if was != permitted:
                text += f"  (On the device now: {'permitted' if was else 'denied'}.)"
        set_hint(self.test_result, text, "success" if permitted else "error")
        if entry is not None and entry.origin >= 0:
            self.select_rows([entry.origin])


class RouteMapEditor(SeqEditor):
    columns = MAP_COLUMNS
    kind = ROUTE_MAP

    def make_tester(self):
        box = QGroupBox("Route Tester")
        grid = QGridLayout(box)
        self.test_prefix = QLineEdit()
        self.test_prefix.setPlaceholderText("10.1.2.0/24")
        self.test_hop = QLineEdit()
        self.test_hop.setPlaceholderText("next hop (optional)")
        self.test_path = QLineEdit()
        self.test_path.setPlaceholderText("65001 65002")
        self.test_communities = QLineEdit()
        self.test_communities.setPlaceholderText("65000:100 no-export")
        self.test_tag = QLineEdit()
        self.test_tag.setPlaceholderText("tag")
        self.test_metric = QLineEdit()
        self.test_metric.setPlaceholderText("metric")
        self.test_pref = QLineEdit()
        self.test_pref.setPlaceholderText("local-pref")
        for edit in (self.test_prefix, self.test_hop, self.test_path, self.test_communities):
            edit.returnPressed.connect(self.run_test)
        test = QPushButton("Test")
        test.clicked.connect(self.run_test)
        self.test_result = QLabel()
        self.test_result.setWordWrap(True)
        grid.addWidget(QLabel("Prefix:"), 0, 0)
        grid.addWidget(self.test_prefix, 0, 1)
        grid.addWidget(self.test_hop, 0, 2)
        grid.addWidget(QLabel("AS path:"), 1, 0)
        grid.addWidget(self.test_path, 1, 1, 1, 2)
        grid.addWidget(QLabel("Communities:"), 2, 0)
        grid.addWidget(self.test_communities, 2, 1, 1, 2)
        numbers = QHBoxLayout()
        for edit in (self.test_tag, self.test_metric, self.test_pref):
            numbers.addWidget(edit)
        grid.addWidget(QLabel("Tag, metric:"), 3, 0)
        grid.addLayout(numbers, 3, 1, 1, 2)
        grid.addWidget(test, 4, 2)
        grid.addWidget(self.test_result, 5, 0, 1, 3)
        grid.setColumnStretch(1, 1)
        grid.setRowStretch(6, 1)
        return box

    def current(self):
        return self.tab.current_rmap()

    def items(self, device):
        return device.route_maps

    def plan(self, before, item):
        return routepolicy.map_change(before, item)

    def cells(self, entry, number):
        cont = "" if not entry.cont else ("next" if entry.cont == "next" else entry.cont)
        return [number, entry.action, "; ".join(entry.matches) or "(everything)", "; ".join(entry.sets), cont,
                entry.description.replace("\n", " | "), "" if entry.hits is None else str(entry.hits)]

    def entry_dialog(self, entry=None, number=""):
        item = self.current()
        numbers = self.planned_numbers(item)
        row = item.entries.index(entry) if entry is not None and entry in item.entries else len(item.entries)
        later = [numbers.get(other) or item.entries[other].seq for other in range(row + 1, len(item.entries))]
        dialog = MapEntryDialog(self, item, entry, self.device(), number, [seq for seq in later if seq])
        if dialog.exec_() != QDialog.Accepted:
            return None, None
        typed = dialog.number_input.text().strip()
        return dialog.entry, (None if typed == str(number) else typed)

    def findings(self, item, device):
        return routepolicy.map_findings(self.tested_item(item), device)

    def uses(self, item, device):
        return [use.label() for use in routepolicy.uses_of(device, ROUTE_MAP, item.name)]

    def library_item(self, item):
        return f"route-map {item.name}"

    def entry_text(self, entry):
        return " / ".join([entry.action] + entry.clauses())

    def fill_test(self, entry):
        for text in entry.matches:
            head, values = routepolicy.split_clause(text)
            device = self.device()
            if head.endswith("prefix-list") and values:
                family = V6 if head.startswith("ipv6") else "ipv4"
                plist = device.prefix_lists.get((family, values[0]))
                if plist is not None and plist.entries:
                    self.test_prefix.setText(plist.entries[0].prefix)
            elif head == "tag" and values:
                self.test_tag.setText(values[0])

    def run_test(self):
        item, device = self.current(), self.device()
        if item is None:
            return
        try:
            route = routepolicy.route_from_text(self.test_prefix.text(), self.test_hop.text(), self.test_path.text(),
                                                self.test_communities.text(), self.test_tag.text(),
                                                self.test_metric.text(), self.test_pref.text())
        except ValueError as error:
            set_hint(self.test_result, str(error), "error")
            return
        verdict = routepolicy.evaluate_map(self.tested_item(item), route, device)
        text = verdict.text
        before = self.before_item(item)
        if before is not None:
            was = routepolicy.evaluate_map(before, route, self.tab.read.get(self.tab.current_key))
            if was.permitted != verdict.permitted or was.sets != verdict.sets:
                text += f"  (On the device now: {lower_first(was.text)})"
        if verdict.notes:
            text += "  " + " ".join(dict.fromkeys(verdict.notes))
        set_hint(self.test_result, text, "success" if verdict.permitted else "error")
        rows = [entry.origin for entry in verdict.entries if entry.origin >= 0]
        if rows:
            self.select_rows(rows)


def lower_first(text):
    return text[:1].lower() + text[1:]
