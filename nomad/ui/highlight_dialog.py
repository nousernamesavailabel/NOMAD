"""Editing the terminal's keyword highlighting: the words (or patterns) and their colors."""
import dataclasses
import re

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QLabel, \
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout

from ..terminal.highlight import COLORS, DEFAULT_RULES, HighlightRule
from .common import ColumnFitter, set_hint
from .theme import COLORS as THEME

COLUMNS = ["Word or Pattern", "Color", "Pattern (regex)", "Match Case", "Whole Word"]


class HighlightDialog(QDialog):
    def __init__(self, parent, store):
        super().__init__(parent)
        self.store = store
        self.setWindowTitle("Keyword Highlighting")
        self.resize(720, 560)
        layout = QVBoxLayout(self)
        self.enabled_check = QCheckBox("Highlight keywords in terminal sessions")
        self.enabled_check.setChecked(store.enabled)
        layout.addWidget(self.enabled_check)
        intro = QLabel("Words are colored where the device shows them in the plain color (colors the device uses "
                       "itself are left alone). Where two rules match the same text, the one higher in the list wins, "
                       "so put \"administratively down\" above \"down\".")
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {THEME['muted']};")
        layout.addWidget(intro)
        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        ColumnFitter(self.table, stretch=0)
        layout.addWidget(self.table, 1)
        buttons_row = QHBoxLayout()
        add_button, remove_button = QPushButton("Add"), QPushButton("Remove")
        up_button, down_button = QPushButton("Move Up"), QPushButton("Move Down")
        defaults_button = QPushButton("Restore Defaults")
        for button in (add_button, remove_button, up_button, down_button):
            buttons_row.addWidget(button)
        buttons_row.addStretch()
        buttons_row.addWidget(defaults_button)
        layout.addLayout(buttons_row)
        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        box = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        layout.addWidget(box)

        add_button.clicked.connect(self.add_row)
        remove_button.clicked.connect(self.remove_row)
        up_button.clicked.connect(lambda: self.move_row(-1))
        down_button.clicked.connect(lambda: self.move_row(1))
        defaults_button.clicked.connect(lambda: self.fill([dataclasses.replace(rule) for rule in DEFAULT_RULES]))
        box.accepted.connect(self.save)
        box.rejected.connect(self.reject)
        self.fill(store.rules)

    def fill(self, rules):
        self.table.setRowCount(0)
        for rule in rules:
            self.append(rule)

    def append(self, rule, row=None):
        row = self.table.rowCount() if row is None else row
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(rule.pattern))
        color_combo = QComboBox()
        for name, value in COLORS.items():
            color_combo.addItem(name)
            color_combo.setItemData(color_combo.count() - 1, QColor(value), Qt.ForegroundRole)
        color_combo.setCurrentText(rule.color if rule.color in COLORS else "Red")
        self.table.setCellWidget(row, 1, color_combo)
        for column, value in ((2, rule.regex), (3, rule.match_case), (4, rule.whole_word)):
            item = QTableWidgetItem()
            item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled | Qt.ItemIsSelectable)
            item.setCheckState(Qt.Checked if value else Qt.Unchecked)
            self.table.setItem(row, column, item)

    def rule_at(self, row):
        checked = [self.table.item(row, column).checkState() == Qt.Checked for column in (2, 3, 4)]
        return HighlightRule((self.table.item(row, 0).text() if self.table.item(row, 0) else "").strip(),
                             self.table.cellWidget(row, 1).currentText(), *checked)

    def rules(self):
        return [self.rule_at(row) for row in range(self.table.rowCount())]

    def add_row(self):
        row = max(0, self.table.currentRow())
        self.append(HighlightRule("", "Red"), row)
        self.table.setCurrentCell(row, 0)
        self.table.editItem(self.table.item(row, 0))

    def remove_row(self):
        if self.table.currentRow() >= 0:
            self.table.removeRow(self.table.currentRow())

    def move_row(self, step):
        row = self.table.currentRow()
        target = row + step
        if row < 0 or not 0 <= target < self.table.rowCount():
            return
        rule = self.rule_at(row)
        self.table.removeRow(row)
        self.append(rule, target)
        self.table.setCurrentCell(target, 0)

    def save(self):
        rules = [rule for rule in self.rules() if rule.pattern]
        for rule in rules:
            try:
                rule.compile()
            except re.error as error:
                set_hint(self.error_label, f"\"{rule.pattern}\" isn't a valid pattern: {error}", "error")
                return
        self.store.enabled = self.enabled_check.isChecked()
        self.store.set_rules(rules)
        self.accept()
