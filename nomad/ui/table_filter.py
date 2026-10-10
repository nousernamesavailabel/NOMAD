"""Excel-style filters for a table's columns: a filter button in each column header (or right-clicking the header)
opens a list of the column's values to tick, with a search box and sorting. Filters on several columns combine."""
import re

from PyQt5.QtCore import QEvent, QPoint, QRect, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, \
    QPushButton, QToolTip, QVBoxLayout, QWidget, QWidgetAction

from .common import ColumnFitter
from .theme import COLORS

BUTTON_WIDTH = 22  # The filter button at the left of each column header (the style puts the sort arrow right)
BUTTON_MARGIN = 4
BLANK = "(Blanks)"
SELECT_ALL = "(Select All)"


def natural_key(text):
    """Gi1/0/2 before Gi1/0/10, VLAN 9 before VLAN 10, 10.0.0.9 before 10.0.0.10."""
    return [(0, int(part), "") if part.isdigit() else (1, 0, part.lower()) for part in re.split(r"(\d+)", text)]


def funnel(rect):
    """A filter (funnel) shape filling rect."""
    left, top, width, height = rect.left(), rect.top(), rect.width(), rect.height()
    middle = left + width / 2
    path = QPainterPath()
    path.moveTo(left, top)
    path.lineTo(left + width, top)
    path.lineTo(middle + width * 0.14, top + height * 0.5)
    path.lineTo(middle + width * 0.14, top + height)
    path.lineTo(middle - width * 0.14, top + height * 0.82)
    path.lineTo(middle - width * 0.14, top + height * 0.5)
    path.closeSubpath()
    return path


class FilterHeader(QHeaderView):
    """A horizontal header with a filter button at the left of each column. Clicking the button (or right-clicking
    anywhere on the header) opens the column's filter; clicking the rest of the header sorts, as usual."""
    filter_requested = pyqtSignal(int, QPoint)  # Column, where to open the list

    def __init__(self, parent=None):
        super().__init__(Qt.Horizontal, parent)
        self.active = set()  # Filtered columns, whose buttons are drawn filled in the accent color
        self.hovered = -1  # Column whose button the mouse is over
        self.setSectionsClickable(True)
        self.setHighlightSections(False)
        self.setMouseTracking(True)
        self.setStyleSheet(f"QHeaderView::section {{ padding-left: {BUTTON_WIDTH + BUTTON_MARGIN * 2}px; }}")

    def section_rect(self, index):
        return QRect(self.sectionViewportPosition(index), 0, self.sectionSize(index), self.height())

    def button_rect(self, section_rect):
        return QRect(section_rect.left() + BUTTON_MARGIN, section_rect.top() + BUTTON_MARGIN,
                     BUTTON_WIDTH, section_rect.height() - BUTTON_MARGIN * 2)

    def button_at(self, position):
        """The column whose filter button is at position, or -1."""
        index = self.logicalIndexAt(position)
        if index >= 0 and self.button_rect(self.section_rect(index)).adjusted(-3, -BUTTON_MARGIN, 3,
                                                                              BUTTON_MARGIN).contains(position):
            return index
        return -1

    def paintSection(self, painter, rect, index):
        painter.save()
        super().paintSection(painter, rect, index)
        painter.restore()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        button = QRectF(self.button_rect(rect))
        active, hovered = index in self.active, index == self.hovered
        if active or hovered:
            painter.setPen(QPen(QColor(COLORS["accent"] if active else COLORS["border"]), 1))
            painter.setBrush(QColor(COLORS["accent_dim"] if active else COLORS["hover"]))
            painter.drawRoundedRect(button.adjusted(0.5, 0.5, -0.5, -0.5), 3, 3)
        icon = funnel(button.adjusted(5, max(4, (button.height() - 11) / 2), -5, -max(4, (button.height() - 11) / 2)))
        color = QColor(COLORS["accent_hover"] if active else COLORS["text"] if hovered else COLORS["muted"])
        painter.setPen(QPen(color, 1.2))
        painter.setBrush(color if active else Qt.NoBrush)
        painter.drawPath(icon)
        painter.restore()

    def mouseMoveEvent(self, event):
        hovered = self.button_at(event.pos())
        if hovered != self.hovered:
            self.hovered = hovered
            self.viewport().update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event):
        self.hovered = -1
        self.viewport().update()
        super().leaveEvent(event)

    def event(self, event):
        if event.type() == QEvent.ToolTip:
            index = self.button_at(event.pos())
            if index >= 0:
                name = self.model().headerData(index, Qt.Horizontal) if self.model() else ""
                QToolTip.showText(event.globalPos(), f"Filter {name}" + (" (filtered)" if index in self.active
                                                                         else ""), self)
                return True
        return super().event(event)

    def open_filter(self, index):
        rect = self.section_rect(index)
        self.filter_requested.emit(index, self.mapToGlobal(QPoint(rect.left(), self.height())))

    def mousePressEvent(self, event):
        index = self.button_at(event.pos())
        if index >= 0 and event.button() == Qt.LeftButton:
            self.open_filter(index)
            event.accept()
            return  # A filter, not a sort
        super().mousePressEvent(event)

    def contextMenuEvent(self, event):
        index = self.logicalIndexAt(event.pos())
        if index >= 0:
            self.open_filter(index)
            event.accept()


class TableFilter:
    """Adds filters to a QTableWidget. Call apply() after refilling the table; filters are kept by the values
    ticked, so they carry over to new contents."""

    def __init__(self, table, changed=lambda shown, total: None):
        self.table, self.changed = table, changed
        self.filters = {}  # Column -> set of allowed cell texts
        self.words = []  # From a quick filter box: rows must contain each of them, in any column
        stretch_last = table.horizontalHeader().stretchLastSection()
        self.header = FilterHeader(table)
        table.setHorizontalHeader(self.header)  # Deletes the old header
        self.header.setStretchLastSection(stretch_last)
        self.columns = ColumnFitter(table)  # Its widest: set by the page, for columns that could be very wide
        self.header.setSortIndicatorShown(True)
        self.header.setSortIndicator(0, Qt.AscendingOrder)  # Qt's default is Z to A
        self.header.filter_requested.connect(self.open)
        # Sorting moves cells between rows but not the rows' hidden flags, so filter again after a sort
        self.header.sortIndicatorChanged.connect(lambda *_: QTimer.singleShot(0, self.apply))

    def text(self, row, column):
        item = self.table.item(row, column)
        return item.text() if item is not None else ""

    def passes(self, row, skip=None):
        if not all(self.text(row, column) in allowed for column, allowed in self.filters.items() if column != skip):
            return False
        if self.words:
            line = " ".join(self.text(row, column) for column in range(self.table.columnCount())).lower()
            return all(word in line for word in self.words)
        return True

    def apply(self):
        total = self.table.rowCount()
        shown = 0
        for row in range(total):
            visible = self.passes(row)
            self.table.setRowHidden(row, not visible)
            shown += visible
        self.header.active = set(self.filters)
        self.header.viewport().update()
        self.changed(shown, total)

    def set_filter(self, column, allowed):
        """Show only rows whose cell in column is one of allowed (None to stop filtering the column)."""
        if allowed is None:
            self.filters.pop(column, None)
        else:
            self.filters[column] = set(allowed)
        self.apply()

    def set_text(self, text):
        """Show only rows containing every word of text, in any column (on top of the column filters)."""
        self.words = text.lower().split()
        self.apply()

    def clear(self):
        """Clear the column filters (the quick filter's text belongs to its box, so it stays)."""
        self.filters = {}
        self.apply()

    @property
    def active(self):
        return bool(self.filters or self.words)

    def values(self, column):
        """{text: count} for the column, over the rows the other columns' filters let through (as Excel does)."""
        counts = {}
        for row in range(self.table.rowCount()):
            if self.passes(row, skip=column):
                text = self.text(row, column)
                counts[text] = counts.get(text, 0) + 1
        return counts

    def sort(self, column, order):
        self.table.sortItems(column, order)
        self.header.setSortIndicator(column, order)
        self.apply()

    # ----------------------------------------------------------------- The drop-down list

    def open(self, column, position):
        popup = FilterPopup(self, column, self.table)
        popup.exec_(position)


class FilterPopup(QMenu):
    def __init__(self, table_filter, column, parent=None):
        super().__init__(parent)
        self.table_filter, self.column = table_filter, column
        name = table_filter.table.horizontalHeaderItem(column).text()
        box = QWidget()
        layout = QVBoxLayout(box)
        layout.setContentsMargins(8, 8, 8, 8)
        title = QLabel(f"Show rows where {name} is:")
        bold = QFont(title.font())
        bold.setBold(True)
        title.setFont(bold)
        layout.addWidget(title)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search")
        self.search.setClearButtonEnabled(True)
        self.list = QListWidget()
        self.list.setMinimumWidth(240)
        self.list.setMinimumHeight(220)
        allowed = table_filter.filters.get(column)
        counts = table_filter.values(column)
        self.all_item = QListWidgetItem(SELECT_ALL)
        self.all_item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
        self.list.addItem(self.all_item)
        for text in sorted(counts, key=lambda value: (value == "", natural_key(value))):
            item = QListWidgetItem(f"{text or BLANK}  ({counts[text]})")
            item.setData(Qt.UserRole, text)
            item.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)
            item.setCheckState(Qt.Checked if allowed is None or text in allowed else Qt.Unchecked)
            self.list.addItem(item)
        self.update_all()
        buttons = QHBoxLayout()
        buttons.addStretch()
        ok, cancel = QPushButton("OK"), QPushButton("Cancel")
        ok.setDefault(True)
        buttons.addWidget(ok)
        buttons.addWidget(cancel)
        layout.addWidget(self.search)
        layout.addWidget(self.list)
        layout.addLayout(buttons)
        action = QWidgetAction(self)
        action.setDefaultWidget(box)
        self.addAction(action)
        self.addSeparator()
        if column in table_filter.filters:
            self.addAction(f'Clear Filter from "{name}"', lambda: table_filter.set_filter(column, None))
        if len(table_filter.filters) > 1 or (table_filter.filters and column not in table_filter.filters):
            self.addAction("Clear All Filters", table_filter.clear)
        self.addAction("Sort A to Z", lambda: table_filter.sort(column, Qt.AscendingOrder))
        self.addAction("Sort Z to A", lambda: table_filter.sort(column, Qt.DescendingOrder))

        self.search.textChanged.connect(self.on_search)
        self.list.itemChanged.connect(self.on_item_changed)
        ok.clicked.connect(self.accept)
        cancel.clicked.connect(self.close)
        self.search.returnPressed.connect(self.accept)
        QTimer.singleShot(0, self.search.setFocus)

    def value_items(self):
        return [self.list.item(row) for row in range(1, self.list.count())]

    def on_search(self, text):
        text = text.strip().lower()
        for item in self.value_items():
            item.setHidden(bool(text) and text not in (item.data(Qt.UserRole) or BLANK).lower())
        if text:  # As in Excel: searching ticks what matches
            self.list.blockSignals(True)
            for item in self.value_items():
                item.setCheckState(Qt.Unchecked if item.isHidden() else Qt.Checked)
            self.list.blockSignals(False)
        self.update_all()

    def on_item_changed(self, item):
        self.list.blockSignals(True)
        if item is self.all_item:
            state = Qt.Checked if item.checkState() != Qt.Unchecked else Qt.Unchecked
            for value in self.value_items():
                if not value.isHidden():
                    value.setCheckState(state)
        self.list.blockSignals(False)
        self.update_all()

    def update_all(self):
        shown = [item for item in self.value_items() if not item.isHidden()]
        ticked = sum(item.checkState() == Qt.Checked for item in shown)
        self.list.blockSignals(True)
        self.all_item.setCheckState(Qt.Checked if shown and ticked == len(shown) else
                                    Qt.Unchecked if not ticked else Qt.PartiallyChecked)
        self.list.blockSignals(False)

    def accept(self):
        values = self.value_items()
        allowed = {item.data(Qt.UserRole) for item in values
                   if item.checkState() == Qt.Checked and not item.isHidden()}
        everything = {item.data(Qt.UserRole) for item in values}
        self.table_filter.set_filter(self.column, None if allowed == everything else allowed)
        self.close()
