"""Packet Capture's viewer: the packets of a capture (just taken, or any pcap/pcapng file) with Wireshark-style
filters, each packet decoded with its bytes, summaries (conversations, top talkers, protocols, traffic over time,
devices heard), the problems found, and following a TCP or UDP conversation."""
import logging
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass

from PyQt5.QtCore import QAbstractTableModel, QModelIndex, QStringListModel, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QBrush, QColor, QPainter, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QCompleter, QDialog, \
    QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, \
    QPushButton, QSplitter, QTableView, QTabWidget, QTextEdit, QToolTip, QTreeWidget, QTreeWidgetItem, \
    QVBoxLayout, QWidget

from ..capture import find_wireshark
from ..packets import capfile, dfilter, expert, stats, streams
from ..packets.live import LiveCapture
from ..packets.reader import CaptureError
from .common import ColumnFitter, OneLineLabel, SortableTableItem, StoppableThread, add_action, add_submenu, \
    read_only_table, release_thread, set_hint
from .theme import COLORS, monospace_font

log = logging.getLogger(__name__)

COLUMNS = ["No.", "Time", "Source", "Src Port", "Destination", "Dst Port", "Protocol", "Length", "Info"]
NUMBER_COLUMNS = (0, 1, 3, 5, 7)  # Right-aligned
ROW_COLORS = {  # Packet list row colors (background, text), as Wireshark's coloring rules but for a dark theme
    "bad": ("#4a1f24", "#ffc2c2"), "reset": ("#3f1a1a", "#ff9e9e"), "syn": ("#262d35", "#c9d1d9"),
    "error": ("#3d3115", "#ffd98a"), "icmp": ("#33213b", "#e9c6ff"), "arp": ("#2a2547", "#d6ccff"),
    "layer2": ("#1f3141", "#b9dcff"), "names": ("#173238", "#a9eef5"), "routing": ("#2b3520", "#d3eeb0"),
}
SEVERITY_COLORS = {expert.ERROR: COLORS["error"], expert.WARNING: COLORS["warning"], expert.NOTE: COLORS["muted"]}
CLIENT_COLOR, SERVER_COLOR = "#ff9e9e", "#8ecbff"
FILTER_OK, FILTER_BAD = "#17372a", "#4a1f24"
MAX_TABLE_ROWS = 5000  # Summary tables list the biggest this many
MAX_FOLLOW_BYTES = 2_000_000  # Of a followed stream shown at once
PROGRESS_STEPS = 200
CAPTURE_FILES = "Captures (*.pcapng *.pcap *.cap *.pcapng.gz);;All files (*)"
WORD_AT_END = re.compile(r"[A-Za-z_][\w.\-]*$")
LIVE_BATCH = 2000  # Packets decoded before the list is given them
LIVE_TICK_SECONDS = 0.25  # How often a live capture looks for new packets when it's caught up
LIVE_COUNT_SECONDS = 1.0
LIVE_SUM_MILLISECONDS = 3000  # How often a live capture's summaries and problems are worked out again
NOT_ASKED = object()
COLUMN_FILTERS = {2: "source", 3: "source port", 4: "destination", 5: "destination port", 6: "protocol",
                  8: "destination port"}  # Offered first (in bold)
FILTER_WAYS = [("Add to Filter", "and"), ("Add to Filter with Or", "or"), ("Exclude from Filter", "not")]


class LoadThread(StoppableThread):
    """Reads a capture file (or switches an open one to another view) and decodes it."""
    progressed = pyqtSignal(str, float)  # What it's doing, how far (-1: can't tell)
    loaded = pyqtSignal(object, object)  # CaptureFile, View
    failed = pyqtSignal(str)

    def __init__(self, path, capture=None, unwrapped=None, keep_duplicates=False, parent=None):
        super().__init__(parent)
        self.path, self.capture, self.unwrapped, self.keep_duplicates = path, capture, unwrapped, keep_duplicates
        self.last = (None, -1)

    def run(self):
        try:
            capture = self.capture or capfile.load(self.path, self.keep_duplicates, self.report, self.should_stop)
            unwrapped = capture.default_unwrapped() if self.unwrapped is None else self.unwrapped
            view = capture.view(unwrapped, self.report, self.should_stop)
        except capfile.Cancelled:
            return
        except (CaptureError, OSError, MemoryError) as error:
            self.failed.emit(str(error) or type(error).__name__)
            return
        except Exception as error:  # A capture NOMAD trips over shouldn't take the app down
            log.exception("Opening the capture %s failed", self.path)
            self.failed.emit(f"NOMAD couldn't decode it ({error}).")
            return
        if not self.stopping:
            self.loaded.emit(capture, view)

    def should_stop(self):
        return self.stopping

    def report(self, stage, fraction):
        step = -1 if fraction is None else int(fraction * PROGRESS_STEPS)
        if (stage, step) != self.last:
            self.last = (stage, step)
            self.progressed.emit(stage, -1.0 if fraction is None else fraction)


class FilterThread(StoppableThread):
    """Works out which packets a display filter shows."""
    progressed = pyqtSignal(float)
    filtered = pyqtSignal(object, object)  # The Filter (None: all), [packet indexes]

    def __init__(self, filter_, packets, parent=None):
        super().__init__(parent)
        self.filter, self.packets = filter_, packets
        self.last = -1

    def run(self):
        try:
            shown = dfilter.apply(self.filter, self.packets, self.should_stop, self.report)
        except Exception:  # A filter that trips over a packet shouldn't take the app down
            log.exception("Filtering with %s failed", self.filter.text if self.filter else "")
            shown = []
        if shown is not None and not self.stopping:
            self.filtered.emit(self.filter, shown)

    def should_stop(self):
        return self.stopping

    def report(self, fraction):
        step = int(fraction * PROGRESS_STEPS)
        if step != self.last:
            self.last = step
            self.progressed.emit(fraction)


@dataclass
class LiveCounts:
    """How a live capture is going, for the status line."""
    captured: int = 0
    mirrored: int = 0
    duplicates: int = 0
    waiting: int = 0  # Come but not yet in the list
    missed: int = 0  # Packets the live view missed (the saved file has them)
    missed_more: bool = False  # Windows dropped whole batches of them as well: more were missed than counted
    full: bool = False


class LiveThread(StoppableThread):
    """Takes pktmon's packets as it captures them (a pktmon_live.LiveFeed) and decodes them (a LiveCapture), for the
    live view. The viewer changes the filter or the view through set_filter() and show_unwrapped(), and asks for the
    summaries and problems with sum_up()."""
    arrived = pyqtSignal(int, object)  # Generation, [indexes of the view's packets to add to the list]
    restarted = pyqtSignal(int, object, object, object)  # Generation, View, [indexes shown], Filter: list anew
    summed = pyqtSignal(int, object)  # Generation, View (its summaries and problems worked out again)
    counted = pyqtSignal(object)  # LiveCounts
    failed = pyqtSignal(str)

    def __init__(self, feed, live, parent=None):
        super().__init__(parent)
        self.feed, self.live = feed, live
        self.lock = threading.Lock()
        self.wanted_filter = NOT_ASKED
        self.wanted_unwrapped = None
        self.want_sums = threading.Event()
        self.generation = 0

    def set_filter(self, filter_):
        with self.lock:
            self.wanted_filter = filter_

    def show_unwrapped(self, unwrapped):
        with self.lock:
            self.wanted_unwrapped = unwrapped

    def sum_up(self):
        self.want_sums.set()

    def run(self):
        try:
            self.restart(self.live.set_filter(self.live.filter))
            next_count = 0.0
            while not self.stopping:
                self.handle_requests()
                if self.live.add(self.feed.take()):  # Switched to the mirrored frames
                    self.restart([])
                shown = self.live.decode(LIVE_BATCH)
                if shown:
                    self.arrived.emit(self.generation, shown)
                now = time.monotonic()
                if now >= next_count:
                    next_count = now + LIVE_COUNT_SECONDS
                    self.counted.emit(self.counts())
                if self.want_sums.is_set():
                    self.want_sums.clear()
                    self.summed.emit(self.generation, self.live.finish())
                if not self.live.waiting:
                    self.stop_event.wait(LIVE_TICK_SECONDS)
        except Exception as error:  # The live view failing mustn't take the app (or the capture) down
            log.exception("The live view failed")
            self.failed.emit(str(error) or type(error).__name__)

    def handle_requests(self):
        with self.lock:
            filter_, self.wanted_filter = self.wanted_filter, NOT_ASKED
            unwrapped, self.wanted_unwrapped = self.wanted_unwrapped, None
        if unwrapped is None and filter_ is NOT_ASKED:
            return
        if unwrapped is not None:
            self.live.show(unwrapped)
        rows = self.live.set_filter(self.live.filter if filter_ is NOT_ASKED else filter_, self.should_stop)
        if rows is not None:
            self.restart(rows)

    def restart(self, rows):
        self.generation += 1
        self.restarted.emit(self.generation, self.live.view, rows, self.live.filter)
        self.want_sums.set()

    def counts(self):
        capture = self.live.capture
        missed, more = self.feed.missed()
        return LiveCounts(len(capture.captured), len(capture.mirrored), capture.duplicates,
                          self.feed.waiting + self.live.waiting, missed, more, self.live.full)

    def should_stop(self):
        return self.stopping


class PacketModel(QAbstractTableModel):
    """The packet list: the packets a filter shows (rows: indexes into the view's packets)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.packets, self.rows = [], []
        self.brushes = {name: (QBrush(QColor(background)), QBrush(QColor(text)))
                        for name, (background, text) in ROW_COLORS.items()}

    def show(self, packets, rows):
        self.beginResetModel()
        self.packets, self.rows = packets, rows
        self.endResetModel()

    def add_rows(self, rows):
        """Add packets (indexes) to the end of the list: a live capture's newest."""
        if not rows:
            return
        first = len(self.rows)
        self.beginInsertRows(QModelIndex(), first, first + len(rows) - 1)
        self.rows.extend(rows)
        self.endInsertRows()

    def packet(self, row):
        return self.packets[self.rows[row]] if 0 <= row < len(self.rows) else None

    def row_of(self, number):
        """The row showing packet number (1-based), or -1."""
        index = number - 1
        try:
            return self.rows.index(index)
        except ValueError:
            return -1

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        packet = self.packets[self.rows[index.row()]]
        column = index.column()
        if role == Qt.DisplayRole:
            if column == 0:
                return str(packet.number)
            if column == 1:
                return f"{packet.time:.6f}"
            if column == 2:
                return packet.src
            if column == 3:
                return "" if packet.sport is None else str(packet.sport)
            if column == 4:
                return packet.dst
            if column == 5:
                return "" if packet.dport is None else str(packet.dport)
            if column == 6:
                return packet.protocol
            if column == 7:
                return str(packet.wire_length)
            return packet.info
        if role == Qt.BackgroundRole or role == Qt.ForegroundRole:
            brushes = self.brushes.get(packet.color)
            return None if brushes is None else brushes[0 if role == Qt.BackgroundRole else 1]
        if role == Qt.TextAlignmentRole and column in NUMBER_COLUMNS:
            return int(Qt.AlignRight | Qt.AlignVCenter)
        if role == Qt.ToolTipRole:
            if column == 1:
                return packet.clock()
            if column == 8:
                return packet.info
        return None

    def sort(self, column, order=Qt.AscendingOrder):
        keys = [lambda packet: packet.number, lambda packet: packet.time, lambda packet: sort_address(packet.src),
                lambda packet: sort_port(packet.sport), lambda packet: sort_address(packet.dst),
                lambda packet: sort_port(packet.dport), lambda packet: packet.protocol.lower(),
                lambda packet: packet.wire_length, lambda packet: packet.info.lower()]
        key = keys[column]
        packets = self.packets
        self.layoutAboutToBeChanged.emit()
        self.rows.sort(key=lambda index: key(packets[index]), reverse=order == Qt.DescendingOrder)
        self.layoutChanged.emit()


def detail_filter(item):
    """The filter for a details line: its own, else the nearest line above it that has one (its protocol's)."""
    while item is not None:
        text = item.data(0, Qt.UserRole + 1)
        if text and makes_sense(text):
            return text
        item = item.parent()
    return ""


def makes_sense(text):
    try:
        return dfilter.compile_filter(text) is not None
    except dfilter.FilterError:
        return False


def sort_port(port):
    return -1 if port is None else port


def sort_address(text):
    parts = text.split(".")
    if len(parts) == 4 and all(part.isdigit() for part in parts):
        return (0, tuple(int(part) for part in parts))
    return (1, text)


class HexView(QPlainTextEdit):
    """The selected packet's bytes, with the part the selected detail is about highlighted."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setFont(monospace_font())
        self.size = 0

    def show_bytes(self, data):
        self.size = len(data)
        self.setPlainText(streams.hex_dump(data))
        self.setExtraSelections([])

    def highlight(self, start, end):
        if start < 0 or end <= start:
            self.setExtraSelections([])
            return
        end = min(end, self.size)
        selections = []
        style = QTextCharFormat()
        style.setBackground(QColor(COLORS["accent_dim"]))
        style.setForeground(QColor(COLORS["text"]))
        document = self.document()
        for line in range(start // 16, (end - 1) // 16 + 1):
            first, last = max(start, line * 16) - line * 16, min(end, line * 16 + 16) - line * 16 - 1
            block = document.findBlockByNumber(line)
            if not block.isValid():
                break
            for low, high in ((hex_column(first), hex_column(last) + 2), (60 + first, 60 + last + 1)):
                selection = QTextEdit.ExtraSelection()
                cursor = QTextCursor(block)
                cursor.setPosition(block.position() + low)
                cursor.setPosition(block.position() + high, QTextCursor.KeepAnchor)
                selection.cursor, selection.format = cursor, style
                selections.append(selection)
        self.setExtraSelections(selections)
        cursor = QTextCursor(document.findBlockByNumber(start // 16))
        self.setTextCursor(cursor)
        self.ensureCursorVisible()


def hex_column(byte):
    """Where byte (0-15) of a hex_dump line starts."""
    return 10 + byte * 3 + (1 if byte >= 8 else 0)


class TimelineChart(QWidget):
    """Traffic over time as bars; clicking a bar shows its packets."""
    clicked = pyqtSignal(float, float)  # Start, end (seconds since the first packet)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.width_seconds, self.rows = 1.0, []
        self.bits = False
        self.setMouseTracking(True)
        self.setMinimumHeight(160)

    def show_rows(self, width_seconds, rows, bits):
        self.width_seconds, self.rows, self.bits = width_seconds, rows, bits
        self.update()

    def values(self):
        if self.bits:
            return [size * 8 / self.width_seconds for _, size in self.rows]
        return [count / self.width_seconds for count, _ in self.rows]

    def bar_at(self, x):
        if not self.rows:
            return -1
        left, width = 60, max(1, self.width() - 70)
        index = int((x - left) * len(self.rows) / width)
        return index if 0 <= index < len(self.rows) else -1

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(COLORS["input"]))
        values = self.values()
        if not values:
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(self.rect(), Qt.AlignCenter, "No packets")
            return
        top, bottom, left = 10, self.height() - 22, 60
        width = max(1, self.width() - 70)
        peak = max(values) or 1
        painter.setPen(QColor(COLORS["muted"]))
        painter.drawText(4, top + 10, rate_label(peak, self.bits))
        painter.drawText(4, bottom, "0")
        painter.drawText(left, self.height() - 6, "0 s")
        end_text = f"{len(values) * self.width_seconds:g} s"
        painter.drawText(left + width - painter.fontMetrics().horizontalAdvance(end_text), self.height() - 6, end_text)
        painter.setPen(QColor(COLORS["border"]))
        painter.drawLine(left, bottom, left + width, bottom)
        bar = width / len(values)
        color = QColor(COLORS["accent"])
        for index, value in enumerate(values):
            height = int((bottom - top) * value / peak)
            if height:
                painter.fillRect(int(left + index * bar), bottom - height, max(1, int(bar) - (1 if bar > 3 else 0)),
                                 height, color)

    def mouseMoveEvent(self, event):
        index = self.bar_at(event.x())
        if index >= 0:
            count, size = self.rows[index]
            start = index * self.width_seconds
            rate = rate_label(size * 8 / self.width_seconds, True)
            QToolTip.showText(event.globalPos(), f"{start:g}–{start + self.width_seconds:g} s: {count:,} packets, "
                                                 f"{stats.size_text(size)} ({rate})", self)

    def mousePressEvent(self, event):
        index = self.bar_at(event.x())
        if index >= 0 and event.button() == Qt.LeftButton:
            start = index * self.width_seconds
            self.clicked.emit(start, start + self.width_seconds)


def rate_label(value, bits):
    return stats.rate_text(value) if bits else f"{value:,.0f} packets/s"


class FollowDialog(QDialog):
    """A TCP or UDP conversation's data, both sides in their own color."""

    def __init__(self, followed, viewer, parent=None):
        super().__init__(parent)
        self.followed, self.viewer = followed, viewer
        self.setWindowTitle(f"Follow {followed.kind.upper()} Stream {followed.index}: {followed.client} ↔ "
                            f"{followed.server}")
        self.resize(900, 640)
        layout = QVBoxLayout(self)
        summary = QLabel(followed.describe())
        summary.setWordWrap(True)
        layout.addWidget(summary)
        notes = []
        if followed.truncated:
            notes.append("Only the start of some packets was captured, so parts of the data are missing: capture "
                         "whole packets to follow streams.")
        if any(chunk.missing for chunk in followed.chunks):
            notes.append("Some data was never captured (gaps are marked).")
        if followed.chunks and followed.chunks[0].data[:1] == b"\x16":
            notes.append("This is encrypted (TLS): only the handshake can be read.")
        if notes:
            note = QLabel(" ".join(notes))
            note.setWordWrap(True)
            set_hint(note, note.text(), "warning")
            layout.addWidget(note)
        options = QHBoxLayout()
        self.direction_combo = QComboBox()
        self.direction_combo.addItem("Both directions", None)
        self.direction_combo.addItem(f"{followed.client} → {followed.server} ({stats.size_text(followed.sent(0))})", 0)
        self.direction_combo.addItem(f"{followed.server} → {followed.client} ({stats.size_text(followed.sent(1))})", 1)
        self.format_combo = QComboBox()
        self.format_combo.addItems(["Text", "Hex dump"])
        options.addWidget(QLabel("Show:"))
        options.addWidget(self.direction_combo)
        options.addSpacing(12)
        options.addWidget(QLabel("As:"))
        options.addWidget(self.format_combo)
        options.addStretch()
        layout.addLayout(options)
        self.text = QTextEdit()
        self.text.setReadOnly(True)
        self.text.setFont(monospace_font())
        self.text.setLineWrapMode(QTextEdit.WidgetWidth)
        layout.addWidget(self.text, 1)
        buttons = QHBoxLayout()
        self.filter_button = QPushButton("Show These Packets")
        self.save_button = QPushButton("Save As...")
        close_button = QPushButton("Close")
        buttons.addWidget(self.filter_button)
        buttons.addWidget(self.save_button)
        buttons.addStretch()
        buttons.addWidget(close_button)
        layout.addLayout(buttons)
        self.direction_combo.currentIndexChanged.connect(self.fill)
        self.format_combo.currentIndexChanged.connect(self.fill)
        self.filter_button.clicked.connect(self.filter_packets)
        self.save_button.clicked.connect(self.save)
        close_button.clicked.connect(self.close)
        self.fill()

    def fill(self, *_):
        direction = self.direction_combo.currentData()
        hex_view = self.format_combo.currentIndex() == 1
        self.text.clear()
        cursor = self.text.textCursor()
        styles = {}
        for side, color in ((0, CLIENT_COLOR), (1, SERVER_COLOR)):
            style = QTextCharFormat()
            style.setForeground(QColor(color))
            styles[side] = style
        gap_style = QTextCharFormat()
        gap_style.setForeground(QColor(COLORS["warning"]))
        shown = 0
        offsets = [0, 0]
        for chunk in self.followed.chunks:
            if direction is not None and chunk.direction != direction:
                continue
            if chunk.missing:
                cursor.insertText(f"\n[{chunk.missing:,} bytes not captured]\n", gap_style)
            data = chunk.data[:max(0, MAX_FOLLOW_BYTES - shown)]
            if hex_view:
                text = streams.hex_dump(data, offsets[chunk.direction]) + "\n"
                offsets[chunk.direction] += len(chunk.data)
            else:
                text = streams.as_text(data)
            cursor.insertText(text, styles[chunk.direction])
            shown += len(data)
            if shown >= MAX_FOLLOW_BYTES:
                cursor.insertText(f"\n[The rest isn't shown: over {stats.size_text(MAX_FOLLOW_BYTES)}. Save As "
                                  "saves all of it.]", gap_style)
                break
        self.text.moveCursor(QTextCursor.Start)

    def filter_packets(self):
        self.viewer.apply_filter_text(f"{self.followed.kind}.stream == {self.followed.index}")

    def save(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Stream As", f"stream {self.followed.index}.bin",
                                              "All files (*)")
        if not path:
            return
        direction = self.direction_combo.currentData()
        try:
            with open(path, "wb") as output:
                output.write(self.followed.data(direction))
        except OSError as error:
            QMessageBox.critical(self, "Save Stream", f"Couldn't save {path}:\n\n{error}")


class FilterEdit(QLineEdit):
    """The display filter box: completes field and protocol names as they're typed."""

    def __init__(self, parent=None):
        super().__init__(parent)
        names = sorted(set(dfilter.FIELDS) | {name for name in dfilter.PROTOCOLS if not name.startswith("_")})
        self.completer_model = QStringListModel(names, self)
        self.completer = QCompleter(self.completer_model, self)
        self.completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.completer.setCompletionMode(QCompleter.PopupCompletion)
        self.completer.setWidget(self)
        self.completer.activated[str].connect(self.complete_word)
        self.textEdited.connect(self.suggest)

    def suggest(self, text):
        before = text[:self.cursorPosition()]
        match = WORD_AT_END.search(before)
        if not match or len(match.group()) < 2:
            self.completer.popup().hide()
            return
        self.completer.setCompletionPrefix(match.group())
        if self.completer.completionCount() == 1 and self.completer.currentCompletion() == match.group():
            self.completer.popup().hide()
            return
        self.completer.complete()

    def complete_word(self, word):
        position = self.cursorPosition()
        before, after = self.text()[:position], self.text()[position:]
        match = WORD_AT_END.search(before)
        start = match.start() if match else position
        self.setText(before[:start] + word + after)
        self.setCursorPosition(start + len(word))

    def keyPressEvent(self, event):
        if self.completer.popup().isVisible() and event.key() in (Qt.Key_Enter, Qt.Key_Return, Qt.Key_Tab):
            event.ignore()
            return
        super().keyPressEvent(event)


class TabCorner(QWidget):
    """What sits beside a tab widget's tabs: as wide as the room the tabs leave (a tab widget gives its corner
    widget the width it asks for)."""

    def sizeHint(self):
        hint = super().sizeHint()
        tabs = self.parentWidget()
        if isinstance(tabs, QTabWidget):
            room = tabs.width() - tabs.tabBar().sizeHint().width() - 8
            hint.setWidth(max(room, self.minimumSizeHint().width()))
        return hint


class CaptureViewer(QWidget):
    """The viewer: open a capture with open(path)."""
    filter_applied = pyqtSignal(str)

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.capture = None
        self.view = None
        self.path = ""
        self.filter = None
        self.loader = None
        self.filterer = None
        self.followers = []  # Open Follow Stream dialogs
        self.menu_packet = None
        self.menu_row = None
        self.live = None  # LiveThread while a capture's packets show as they come
        self.live_generation = 0
        self.live_counts = None
        self.auto_scrolling = False
        self.stale = set()  # Tabs (Summaries, Problems) to fill again when they're next looked at
        self.sum_timer = QTimer(self)
        self.sum_timer.timeout.connect(self.ask_for_sums)
        self.init_ui()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        top = QHBoxLayout()
        self.open_button = QPushButton("Open Capture...")
        self.open_button.setToolTip("Open a pcapng or pcap file (from pktmon, Wireshark or tcpdump).")
        self.filter_input = FilterEdit()
        self.filter_input.setPlaceholderText("Display filter, as in Wireshark: ip.addr == 10.0.0.5 && tcp.port == "
                                             "443, dns, !arp, 10.0.0.0/24 (Enter to apply)")
        self.filter_input.setToolTip(
            "Fields as Wireshark names them (ip.addr, ip.src, eth.addr, tcp.port, udp.port, vlan.id, tcp.stream, "
            "dns.qry.name, tcp.flags.syn, tcp.analysis.retransmission...) or a protocol (dns, dhcp, arp, stp, cdp)."
            "\nCompare with == != > < >= <=, contains, matches (a regular expression) or in {80 443}; combine with "
            "&& (and), || (or), ! (not) and parentheses.\nJust an address, subnet, MAC address or port number "
            "shows that one's packets.")
        self.filter_help = self.filter_input.toolTip()
        self.apply_button = QPushButton("Apply")
        self.clear_button = QPushButton("Clear")
        self.unwrap_button = QPushButton("Show Mirrored Frames")
        self.unwrap_button.setToolTip("Switch between the frames a switch mirrored to this PC over ERSPAN (unwrapped) "
                                      "and the packets as captured.")
        self.wireshark_button = QPushButton("Open in Wireshark")
        top.addWidget(self.open_button)
        top.addWidget(self.filter_input, 1)
        top.addWidget(self.apply_button)
        top.addWidget(self.clear_button)
        top.addWidget(self.unwrap_button)
        top.addWidget(self.wireshark_button)
        layout.addLayout(top)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.corner = TabCorner()  # Beside the tabs, not a row of its own, so the packet list gets the room
        status = QHBoxLayout(self.corner)
        status.setContentsMargins(12, 0, 4, 0)
        self.status_label = OneLineLabel("Packets show here as they're captured, and the whole capture opens here "
                                         "after Stop and Save. Or open a capture file.")
        self.status_label.set_one_line(True)
        self.progress = QProgressBar()
        self.progress.setMaximumWidth(160)
        self.progress.setTextVisible(False)
        self.progress.hide()
        self.duplicates_check = QCheckBox("Hide duplicates")
        self.duplicates_check.setChecked(True)
        self.duplicates_check.setToolTip("Hide a packet captured twice (pktmon can see one at more than one point; a "
                                         "mirror of two ports copies a frame passing between them twice).")
        self.follow_check = QCheckBox("Follow newest")
        self.follow_check.setToolTip("Keep the newest packets in sight while capturing. Scrolling up stops it; "
                                     "scrolling to the bottom starts it again.")
        self.follow_check.hide()
        status.addWidget(self.status_label, 1)
        status.addWidget(self.progress)
        status.addWidget(self.follow_check)
        status.addWidget(self.duplicates_check)
        self.tabs.setCornerWidget(self.corner, Qt.TopRightCorner)

        # Packets
        self.model = PacketModel(self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.AscendingOrder)
        self.table.verticalHeader().setVisible(False)
        self.table.setWordWrap(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.Interactive)
        header.setStretchLastSection(True)
        for column, width in enumerate((70, 100, 145, 85, 145, 85, 90, 75)):
            self.table.setColumnWidth(column, width)
        self.details = QTreeWidget()
        self.details.setHeaderHidden(True)
        self.details.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hex = HexView()
        lower = QSplitter(Qt.Horizontal)
        lower.addWidget(self.details)
        lower.addWidget(self.hex)
        lower.setSizes([480, 640])
        lower.setStretchFactor(0, 1)
        self.packet_splitter = QSplitter(Qt.Vertical)
        self.packet_splitter.addWidget(self.table)
        self.packet_splitter.addWidget(lower)
        self.packet_splitter.setSizes([540, 220])
        self.tabs.addTab(self.packet_splitter, "Packets")

        # Summaries
        summaries = QWidget()
        summaries_layout = QVBoxLayout(summaries)
        self.headline = QLabel()
        self.headline.setWordWrap(True)
        summaries_layout.addWidget(self.headline)
        self.summary_tabs = QTabWidget()
        summaries_layout.addWidget(self.summary_tabs, 1)

        conversations = QWidget()
        conversations_layout = QVBoxLayout(conversations)
        row = QHBoxLayout()
        self.conversation_combo = QComboBox()
        for kind, title in (("ip", "IP"), ("tcp", "TCP"), ("udp", "UDP"), ("eth", "Ethernet")):
            self.conversation_combo.addItem(title, kind)
        row.addWidget(QLabel("Between:"))
        row.addWidget(self.conversation_combo)
        row.addWidget(QLabel("Double-click one to see its packets; right-click to follow a TCP or UDP one."))
        row.addStretch()
        conversations_layout.addLayout(row)
        self.conversation_table = read_only_table(["A", "B", "Packets", "Bytes", "A → B", "B → A", "Start",
                                                   "Duration", "Notes"])
        self.conversation_table.setSortingEnabled(True)
        self.conversation_table.setContextMenuPolicy(Qt.CustomContextMenu)
        conversations_layout.addWidget(self.conversation_table, 1)
        self.summary_tabs.addTab(conversations, "Conversations")

        talkers = QWidget()
        talkers_layout = QVBoxLayout(talkers)
        row = QHBoxLayout()
        self.talker_combo = QComboBox()
        self.talker_combo.addItem("IP addresses", "ip")
        self.talker_combo.addItem("MAC addresses", "eth")
        row.addWidget(QLabel("By:"))
        row.addWidget(self.talker_combo)
        row.addStretch()
        talkers_layout.addLayout(row)
        self.talker_table = read_only_table(["Address", "Name", "Packets", "Bytes", "Sent", "Received"])
        self.talker_table.setSortingEnabled(True)
        talkers_layout.addWidget(self.talker_table, 1)
        self.summary_tabs.addTab(talkers, "Top Talkers")

        self.protocol_tree = QTreeWidget()
        self.protocol_tree.setHeaderLabels(["Protocol", "Packets", "% Packets", "Bytes", "% Bytes"])
        ColumnFitter(self.protocol_tree)
        self.summary_tabs.addTab(self.protocol_tree, "Protocols")

        timeline = QWidget()
        timeline_layout = QVBoxLayout(timeline)
        row = QHBoxLayout()
        self.rate_combo = QComboBox()
        self.rate_combo.addItems(["Packets per second", "Bits per second"])
        row.addWidget(QLabel("Show:"))
        row.addWidget(self.rate_combo)
        row.addWidget(QLabel("Click a bar to see its packets."))
        row.addStretch()
        timeline_layout.addLayout(row)
        self.chart = TimelineChart()
        timeline_layout.addWidget(self.chart, 1)
        self.summary_tabs.addTab(timeline, "Over Time")

        self.neighbor_table = read_only_table(["Heard", "Device", "Port", "Platform", "Native VLAN", "Address", "MAC",
                                               "Packets"])
        neighbors = QWidget()
        neighbors_layout = QVBoxLayout(neighbors)
        self.neighbor_note = QLabel()
        self.neighbor_note.setWordWrap(True)
        neighbors_layout.addWidget(self.neighbor_note)
        neighbors_layout.addWidget(self.neighbor_table, 1)
        self.summary_tabs.addTab(neighbors, "Devices Heard")
        self.tabs.addTab(summaries, "Summaries")

        # Problems
        problems = QWidget()
        problems_layout = QVBoxLayout(problems)
        self.problem_tree = QTreeWidget()
        self.problem_tree.setHeaderLabels(["Severity", "Area", "Problem", "Packets"])
        self.problem_tree.setRootIsDecorated(True)
        ColumnFitter(self.problem_tree, stretch=2)
        problems_layout.addWidget(self.problem_tree, 1)
        self.problem_detail = QLabel()
        self.problem_detail.setWordWrap(True)
        self.problem_detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        problems_layout.addWidget(self.problem_detail)
        row = QHBoxLayout()
        self.problem_button = QPushButton("Show These Packets")
        row.addWidget(self.problem_button)
        row.addStretch()
        problems_layout.addLayout(row)
        self.tabs.addTab(problems, "Problems")

        self.open_button.clicked.connect(self.browse)
        self.filter_input.returnPressed.connect(self.apply_filter)
        self.filter_input.textChanged.connect(self.check_filter)
        self.apply_button.clicked.connect(self.apply_filter)
        self.clear_button.clicked.connect(self.clear_filter)
        self.unwrap_button.clicked.connect(self.toggle_unwrapped)
        self.wireshark_button.clicked.connect(self.open_in_wireshark)
        self.duplicates_check.toggled.connect(self.reload)
        self.table.selectionModel().currentRowChanged.connect(self.show_packet)
        self.table.customContextMenuRequested.connect(self.packet_menu)
        self.table.doubleClicked.connect(self.follow_selected)
        self.details.currentItemChanged.connect(self.show_bytes_of)
        self.details.customContextMenuRequested.connect(self.details_menu)
        self.details.itemExpanded.connect(self.remember_expanded)
        self.details.itemCollapsed.connect(self.remember_collapsed)
        self.conversation_combo.currentIndexChanged.connect(self.fill_conversations)
        self.conversation_table.itemDoubleClicked.connect(self.filter_from_table)
        self.conversation_table.customContextMenuRequested.connect(self.conversation_menu)
        self.talker_combo.currentIndexChanged.connect(self.fill_talkers)
        self.talker_table.itemDoubleClicked.connect(self.filter_from_table)
        self.neighbor_table.itemDoubleClicked.connect(self.filter_from_table)
        self.protocol_tree.itemDoubleClicked.connect(self.filter_from_tree)
        self.rate_combo.currentIndexChanged.connect(self.fill_timeline)
        self.chart.clicked.connect(self.filter_time)
        self.problem_tree.currentItemChanged.connect(self.show_problem)
        self.problem_tree.itemDoubleClicked.connect(self.filter_from_tree)
        self.problem_button.clicked.connect(self.filter_problem)
        self.tabs.currentChanged.connect(self.tab_changed)
        self.follow_check.toggled.connect(self.follow_toggled)
        self.table.verticalScrollBar().valueChanged.connect(self.scrolled)
        self.expanded = set()

    # ----------------------------------------------------------------- Opening

    def browse(self):
        folder = os.path.dirname(self.path) if self.path else os.path.join(os.path.expanduser("~"), "Documents")
        path, _ = QFileDialog.getOpenFileName(self, "Open Capture", folder, CAPTURE_FILES)
        if path:
            self.open(path)

    def open(self, path, unwrapped=None):
        """Open a capture file (in the background). unwrapped: show the mirrored frames (None: when most of it is
        ERSPAN)."""
        self.stop_live()
        self.stop_threads()
        self.path = path
        self.capture = self.view = None
        self.model.show([], [])
        self.clear_details()
        self.start_loader(LoadThread(path, None, unwrapped, not self.duplicates_check.isChecked(), self))
        set_hint(self.status_label, f"Opening {os.path.basename(path)}...", "info")

    def reload(self, *_):
        if self.path and (self.capture is not None or self.loader is not None):
            self.open(self.path, self.view.unwrapped if self.view is not None else None)

    def toggle_unwrapped(self):
        if self.live is not None:
            if self.capture is not None and (self.capture.mirrored or self.view.unwrapped):
                self.live.show_unwrapped(not self.view.unwrapped)
            return
        if self.capture is None or not self.capture.mirrored or self.loader is not None:
            return
        self.stop_threads()
        self.start_loader(LoadThread(self.path, self.capture, not self.view.unwrapped, False, self))
        set_hint(self.status_label, "Decoding...", "info")

    def start_loader(self, loader):
        self.loader = loader
        loader.progressed.connect(self.load_progress)
        loader.loaded.connect(self.loaded)
        loader.failed.connect(self.load_failed)
        loader.finished.connect(self.loader_finished)
        self.progress.setRange(0, 0)
        self.progress.show()
        self.update_buttons()
        loader.start()

    def load_progress(self, stage, fraction):
        if self.sender() is not self.loader:
            return
        if fraction < 0:
            self.progress.setRange(0, 0)
        else:
            self.progress.setRange(0, PROGRESS_STEPS)
            self.progress.setValue(int(fraction * PROGRESS_STEPS))
        set_hint(self.status_label, f"{stage} {os.path.basename(self.path)}...", "info")

    def loaded(self, capture, view):
        if self.sender() is not self.loader:
            return
        try:
            self.capture, self.view = capture, view
            self.progress.hide()
            self.fill_summaries()
            self.fill_problems()
            filter_text = self.filter_input.text().strip()
            self.filter = None
            if filter_text:
                self.apply_filter()
            else:
                self.show_rows(None, list(range(len(view.packets))))
        except Exception:  # A slot that raises would take the app down
            log.exception("Showing the capture failed")
            set_hint(self.status_label, "Couldn't show the capture: see the log.", "error")

    def load_failed(self, message):
        if self.sender() is not self.loader:
            return
        self.progress.hide()
        set_hint(self.status_label, f"Couldn't open {os.path.basename(self.path)}: {message}", "error")

    def loader_finished(self):
        if self.sender() is self.loader:
            self.loader = None
            self.update_buttons()

    def stop_threads(self):
        for thread in (self.loader, self.filterer):
            if thread is not None:
                thread.stop()
                for signal in (getattr(thread, "loaded", None), getattr(thread, "filtered", None)):
                    if signal is not None:
                        try:
                            signal.disconnect()
                        except TypeError:
                            pass
                release_thread(thread, 100)
        self.loader = self.filterer = None

    def shutdown(self):
        self.stop_live()
        self.stop_threads()
        for dialog in self.followers:
            dialog.close()

    # ----------------------------------------------------------------- Live

    def start_live(self, feed, name, unwrapped=None):
        """Show a capture's packets as they come (feed: a pktmon_live.LiveFeed), until stop_live(). unwrapped: show
        the frames mirrored over ERSPAN (None: when most of it is ERSPAN)."""
        self.stop_live()
        self.stop_threads()
        live = LiveCapture(name, not self.duplicates_check.isChecked(), unwrapped)
        try:
            live.filter = dfilter.compile_filter(self.filter_input.text().strip())
        except dfilter.FilterError:
            live.filter = None
        self.path = ""
        self.capture, self.view, self.filter = live.capture, live.view, live.filter
        self.live_counts = LiveCounts()
        self.live_generation = 0
        self.model.show(live.view.packets, [])
        self.clear_details()
        self.progress.hide()
        thread = LiveThread(feed, live, self)
        thread.restarted.connect(self.live_restarted)
        thread.arrived.connect(self.live_arrived)
        thread.summed.connect(self.live_summed)
        thread.counted.connect(self.live_counted)
        thread.failed.connect(self.live_failed)
        self.live = thread
        self.follow_check.setChecked(True)
        self.follow_check.show()
        self.sum_timer.start(LIVE_SUM_MILLISECONDS)
        self.update_buttons()
        set_hint(self.status_label, f"{name}: waiting for packets...", "info")
        thread.start()

    def stop_live(self):
        """Stop showing new packets (the capture stopped): what came stays, with its summaries and problems."""
        thread, self.live = self.live, None
        self.sum_timer.stop()
        self.follow_check.hide()
        if thread is None:
            return
        thread.stop()
        release_thread(thread, 2000)
        if thread.isFinished() and self.view is not None:
            try:
                thread.live.finish()
                self.stale = set()
                self.fill_summaries()
                self.fill_problems(keep_selection=True)
            except Exception:
                log.exception("Summing up the live capture failed")
        self.update_status()
        self.update_buttons()

    def live_restarted(self, generation, view, rows, filter_):
        if self.sender() is not self.live:
            return
        self.live_generation = generation
        self.view = view
        try:
            self.show_rows(filter_, rows)
        except Exception:
            log.exception("Showing the live capture failed")

    def live_arrived(self, generation, rows):
        if self.sender() is not self.live or generation != self.live_generation:
            return
        self.model.add_rows(rows)
        header = self.table.horizontalHeader()
        if header.sortIndicatorSection() != 0 or header.sortIndicatorOrder() != Qt.AscendingOrder:
            self.model.sort(header.sortIndicatorSection(), header.sortIndicatorOrder())
        elif self.follow_check.isChecked():
            self.scroll_to_newest()

    def live_counted(self, counts):
        if self.sender() is not self.live:
            return
        self.live_counts = counts
        self.live_status()
        self.update_buttons()

    def live_summed(self, generation, view):
        if self.sender() is not self.live or generation != self.live_generation or view.summary is None:
            return
        try:
            self.refresh_sums()
        except Exception:
            log.exception("Showing the live capture's summaries failed")

    def live_failed(self, message):
        if self.sender() is not self.live:
            return
        self.stop_live()
        set_hint(self.status_label, f"The live view stopped ({message}). The capture carries on: all of it opens "
                                    "here after Stop and Save.", "error")

    def ask_for_sums(self):
        if self.live is not None:
            self.live.sum_up()

    def refresh_sums(self):
        """Fill the summaries or problems again if they're being looked at, else when they next are."""
        current = self.tabs.currentIndex()
        if current == 1:
            self.fill_summaries()
        elif current == 2:
            self.fill_problems(keep_selection=True)
        self.stale = {1, 2} - {current}
        problems = [problem for problem in self.view.problems if problem.severity != expert.NOTE]
        self.tabs.setTabText(2, f"Problems ({len(problems)})" if problems else "Problems")

    def tab_changed(self, index):
        if index not in self.stale or self.view is None or self.view.summary is None:
            return
        self.stale.discard(index)
        try:
            if index == 1:
                self.fill_summaries()
            else:
                self.fill_problems(keep_selection=True)
        except Exception:
            log.exception("Filling the %s tab failed", self.tabs.tabText(index))

    def live_status(self):
        counts, view = self.live_counts, self.view
        if counts is None or view is None:
            return
        name = self.capture.name
        if not counts.captured:
            set_hint(self.status_label, f"{name}: waiting for packets...", "info")
            return
        if view.unwrapped:
            text = f"{name}: {counts.mirrored:,} mirrored frames"
            extras = [f"{counts.captured - counts.mirrored:,} other packets not shown"]
        else:
            text = f"{name}: {counts.captured:,} packets"
            extras = [f"{counts.mirrored:,} ERSPAN frames inside"] if counts.mirrored else []
        if counts.duplicates:
            extras.append(f"{counts.duplicates:,} duplicates hidden")
        if extras:
            text += f" ({', '.join(extras)})"
        if self.filter is not None:
            text += f". Showing {len(self.model.rows):,} that match the filter"
        text += "."
        kind = "info"
        if counts.waiting > LIVE_BATCH:
            text += f" Catching up: {counts.waiting:,} still to show."
        if counts.missed or counts.missed_more:
            text += (f" The live view missed {counts.missed:,}{' or more' if counts.missed_more else ''} packets "
                     "(more than it could keep up with); the saved file will have them all.")
            kind = "warning"
        if counts.full:
            text += f" The live view stopped adding packets at {capfile.MAX_PACKETS:,}; the saved file has the rest."
            kind = "warning"
        set_hint(self.status_label, text, kind)

    def scroll_to_newest(self):
        self.auto_scrolling = True
        try:
            self.table.scrollToBottom()
        finally:
            self.auto_scrolling = False

    def scrolled(self, value):
        """Scrolling up while live stops following the newest packets; scrolling to the bottom starts it again."""
        if self.live is None or self.auto_scrolling:
            return
        at_bottom = value >= self.table.verticalScrollBar().maximum() - 1
        if at_bottom != self.follow_check.isChecked():
            self.follow_check.setChecked(at_bottom)

    def follow_toggled(self, checked):
        if checked and self.live is not None:
            self.scroll_to_newest()

    # ----------------------------------------------------------------- Filtering

    def check_filter(self, text):
        """Green while the filter makes sense, red (saying why) while it doesn't."""
        if not text.strip():
            self.filter_input.setStyleSheet("")
            self.filter_input.setToolTip(self.filter_help)
            return
        try:
            dfilter.compile_filter(text)
        except dfilter.FilterError as error:
            self.filter_input.setStyleSheet(f"background: {FILTER_BAD};")
            self.filter_input.setToolTip(str(error))
            return
        self.filter_input.setStyleSheet(f"background: {FILTER_OK};")
        self.filter_input.setToolTip(self.filter_help)

    def apply_filter_text(self, text):
        self.filter_input.setText(text)
        self.apply_filter()
        self.tabs.setCurrentIndex(0)

    def apply_filter(self):
        text = self.filter_input.text().strip()
        try:
            filter_ = dfilter.compile_filter(text)
        except dfilter.FilterError as error:
            set_hint(self.status_label, f"Filter: {error}", "error")
            return
        if self.live is not None:
            self.live.set_filter(filter_)
            self.filter_applied.emit(filter_.text if filter_ else "")
            return
        if self.view is None:
            return
        if self.filterer is not None:
            self.filterer.stop()
            try:
                self.filterer.filtered.disconnect()
            except TypeError:
                pass
            release_thread(self.filterer, 100)
            self.filterer = None
        if filter_ is None:
            self.show_rows(None, list(range(len(self.view.packets))))
            return
        self.filterer = FilterThread(filter_, self.view.packets, self)
        self.filterer.progressed.connect(self.filter_progress)
        self.filterer.filtered.connect(self.filtered)
        self.filterer.finished.connect(self.filterer_finished)
        self.progress.setRange(0, PROGRESS_STEPS)
        self.progress.setValue(0)
        self.progress.show()
        set_hint(self.status_label, "Filtering...", "info")
        self.filterer.start()

    def filter_progress(self, fraction):
        if self.sender() is self.filterer:
            self.progress.setValue(int(fraction * PROGRESS_STEPS))

    def filtered(self, filter_, shown):
        if self.sender() is not self.filterer:
            return
        try:
            self.progress.hide()
            self.show_rows(filter_, shown)
            self.filter_applied.emit(filter_.text if filter_ else "")
        except Exception:
            log.exception("Showing the filtered packets failed")

    def filterer_finished(self):
        if self.sender() is self.filterer:
            self.filterer = None

    def clear_filter(self):
        self.filter_input.clear()
        self.apply_filter()

    def show_rows(self, filter_, rows):
        current = self.selected_packet()
        self.filter = filter_
        self.model.show(self.view.packets, rows)
        header = self.table.horizontalHeader()
        if header.sortIndicatorSection() != 0 or header.sortIndicatorOrder() != Qt.AscendingOrder:
            self.model.sort(header.sortIndicatorSection(), header.sortIndicatorOrder())
        self.update_status()
        if current is not None:
            row = self.model.row_of(current.number)
            if row >= 0:
                self.table.selectRow(row)
                self.table.scrollTo(self.model.index(row, 0), QAbstractItemView.PositionAtCenter)
                return
        self.clear_details()
        if rows:
            self.table.selectRow(0)
        self.update_buttons()

    def update_status(self):
        capture, view = self.capture, self.view
        if capture is None or view is None:
            return
        if self.live is not None:
            self.live_status()
            return
        total, shown = len(view.packets), len(self.model.rows)
        text = f"{capture.name}: {total:,} {'mirrored frames' if view.unwrapped else 'packets'}"
        extras = []
        if capture.duplicates:
            extras.append(f"{capture.duplicates:,} duplicates hidden")
        if view.unwrapped:
            extras.append(f"{len(capture.captured) - len(view.packets):,} other packets not shown")
        elif capture.mirrored:
            extras.append(f"{len(capture.mirrored):,} ERSPAN frames inside")
        if extras:
            text += f" ({', '.join(extras)})"
        if self.filter is not None:
            text += f". Showing {shown:,} that match the filter."
        set_hint(self.status_label, text, "info")
        problems = [problem for problem in view.problems if problem.severity != expert.NOTE]
        self.tabs.setTabText(2, f"Problems ({len(problems)})" if problems else "Problems")
        self.update_buttons()

    # ----------------------------------------------------------------- The selected packet

    def selected_packet(self):
        index = self.table.currentIndex()
        return self.model.packet(index.row()) if index.isValid() else None

    def clear_details(self):
        self.details.clear()
        self.hex.show_bytes(b"")

    def show_packet(self, current, previous=None):
        packet = self.model.packet(current.row()) if current.isValid() else None
        if packet is None:
            self.clear_details()
            return
        try:
            d = packet.dissect(tree=True)
        except Exception:  # Shouldn't happen (dissect catches its own), but a slot mustn't raise
            log.exception("Decoding packet %s failed", packet.number)
            self.clear_details()
            return
        self.details.clear()
        for node in d.nodes:
            self.details.addTopLevelItem(self.tree_item(node))
        for index in range(self.details.topLevelItemCount()):
            item = self.details.topLevelItem(index)
            if expanded_key(item.text(0)) in self.expanded:
                item.setExpanded(True)
        self.hex.show_bytes(d.data)

    def tree_item(self, node):
        item = QTreeWidgetItem([node.text])
        item.setData(0, Qt.UserRole, (node.start, node.end))
        item.setData(0, Qt.UserRole + 1, node.field)
        item.setToolTip(0, node.text)
        for child in node.children:
            item.addChild(self.tree_item(child))
        return item

    def show_bytes_of(self, current, previous=None):
        if current is None:
            self.hex.highlight(-1, -1)
            return
        start, end = current.data(0, Qt.UserRole) or (-1, -1)
        self.hex.highlight(start, end)

    def remember_expanded(self, item):
        if item.parent() is None:
            self.expanded.add(expanded_key(item.text(0)))

    def remember_collapsed(self, item):
        if item.parent() is None:
            self.expanded.discard(expanded_key(item.text(0)))

    def packet_menu(self, position):
        index = self.table.indexAt(position)
        packet = self.model.packet(index.row()) if index.isValid() else None
        if packet is None:
            return
        self.table.selectRow(index.row())
        self.menu_packet = packet
        menu = QMenu(self)
        if packet.kind:
            add_action(menu, f"Follow {packet.kind.upper()} Stream", self.follow_selected)
            add_action(menu, "Show Only This Conversation", self.filter_conversation)
        if packet.src:
            add_action(menu, f"Show Only {packet.src}", self.filter_source)
        if packet.dst and packet.dst != packet.src:
            add_action(menu, f"Show Only {packet.dst}", self.filter_destination)
        if packet.protocol:
            add_action(menu, f"Hide {packet.protocol}", self.filter_out_protocol)
        filters, clicked = self.row_filters(packet, index.column())
        self.add_filter_menus(menu, filters, clicked)
        menu.addSeparator()
        add_action(menu, "Copy Summary", self.copy_summary)
        add_action(menu, "Copy Details", self.copy_details)
        menu.exec_(self.table.viewport().mapToGlobal(position))

    def details_menu(self, position):
        if self.details.topLevelItemCount() == 0:
            return
        menu = QMenu(self)
        item = self.details.itemAt(position)
        text = detail_filter(item)
        if text:
            self.details.setCurrentItem(item)
            add_action(menu, "Show Only This", self.filter_from_menu).setData(("only", text))
            for title, how in FILTER_WAYS:
                add_action(menu, title, self.filter_from_menu).setData((how, text))
            add_action(menu, text.replace("&", "&&")).setEnabled(False)  # Says what they'd add
            menu.addSeparator()
        add_action(menu, "Expand All", self.details.expandAll)
        add_action(menu, "Collapse All", self.details.collapseAll)
        add_action(menu, "Copy Details", self.copy_details)
        menu.exec_(self.details.viewport().mapToGlobal(position))

    def follow_selected(self, *_):
        packet = self.selected_packet()
        if packet is not None and packet.kind and packet.stream >= 0:
            self.follow(packet.kind, packet.stream)

    def follow(self, kind, index):
        if self.view is None:
            return
        try:
            followed = streams.follow(self.view, kind, index)
        except Exception:
            log.exception("Following %s stream %s failed", kind, index)
            followed = None
        if followed is None:
            set_hint(self.status_label, f"Couldn't follow {kind.upper()} stream {index}.", "error")
            return
        self.followers = [dialog for dialog in self.followers if dialog.isVisible()]
        dialog = FollowDialog(followed, self, self)
        dialog.setAttribute(Qt.WA_DeleteOnClose)
        self.followers.append(dialog)
        dialog.finished.connect(self.forget_follower)
        dialog.show()

    def forget_follower(self, *_):
        dialog = self.sender()
        self.followers = [item for item in self.followers if item is not dialog]

    def filter_conversation(self):
        packet = self.menu_packet
        if packet is not None and packet.kind:
            self.apply_filter_text(f"{packet.kind}.stream == {packet.stream}")

    def filter_source(self):
        if self.menu_packet is not None:
            source = self.menu_packet.src
            self.apply_filter_text(dfilter.shortcut_for(source) or f'frame contains "{source}"')

    def filter_destination(self):
        packet = self.menu_packet
        if packet is not None:
            text = "eth.dst == ff:ff:ff:ff:ff:ff" if packet.dst == "Broadcast" else dfilter.shortcut_for(packet.dst)
            self.apply_filter_text(text or f'frame contains "{packet.dst}"')

    def filter_out_protocol(self):
        packet = self.menu_packet
        if packet is None or not packet.chain:
            return
        name = packet.chain[-1] if packet.chain[-1] != "data" or len(packet.chain) < 2 else packet.chain[-2]
        self.apply_filter_text(dfilter.combine(self.filter_input.text(), name, "not"))

    def row_filters(self, packet, column):
        """Filters for what a packet list row shows, the one for the column right-clicked first, and whether there
        was one for it."""
        try:
            found = dfilter.packet_filters(packet.dissect(), packet)
        except Exception:  # A menu mustn't fail over a packet that won't decode
            log.exception("Working out filters for packet %s failed", packet.number)
            return [], False
        wanted = COLUMN_FILTERS.get(column)
        found = [pair for pair in found if makes_sense(pair[1])]
        found.sort(key=lambda pair: pair[0] != wanted)
        return [text for _, text in found], bool(found) and found[0][0] == wanted

    def add_filter_menus(self, menu, filters, clicked=False):
        """Add to Filter, ...with Or and Exclude from Filter submenus, each offering these filters (clicked: the
        first is for the column right-clicked, shown in bold)."""
        if not filters:
            return
        menu.addSeparator()
        for title, how in FILTER_WAYS:
            submenu = add_submenu(menu, title)
            for text in filters:
                action = add_action(submenu, text.replace("&", "&&"), self.filter_from_menu)
                action.setData((how, text))
                if clicked and text is filters[0]:
                    submenu.setDefaultAction(action)

    def filter_from_menu(self):
        """An Add to Filter (or Show Only This) entry: its data is (how, filter)."""
        action = self.sender()
        how, text = (action.data() if action is not None else None) or (None, "")
        if text:
            self.apply_filter_text(text if how == "only" else dfilter.combine(self.filter_input.text(), text, how))

    def copy_summary(self):
        packet = self.menu_packet or self.selected_packet()
        if packet is not None:
            ports = ["" if port is None else str(port) for port in (packet.sport, packet.dport)]
            QApplication.clipboard().setText("\t".join([str(packet.number), f"{packet.time:.6f}", packet.src, ports[0],
                                                        packet.dst, ports[1], packet.protocol,
                                                        str(packet.wire_length), packet.info]))

    def copy_details(self):
        lines = []

        def walk(item, depth):
            lines.append("    " * depth + item.text(0))
            for index in range(item.childCount()):
                walk(item.child(index), depth + 1)
        for index in range(self.details.topLevelItemCount()):
            walk(self.details.topLevelItem(index), 0)
        if lines:
            QApplication.clipboard().setText("\n".join(lines))

    # ----------------------------------------------------------------- Summaries

    def fill_summaries(self):
        summary = self.view.summary
        self.headline.setText(summary.headline())
        self.fill_conversations()
        self.fill_talkers()
        self.fill_protocols()
        self.fill_timeline()
        self.fill_neighbors()

    def named(self, address):
        name = self.view.summary.names.get(address.split(":")[0] if address.count(":") == 1 else address)
        return f"{address} ({name})" if name else address

    def fill_conversations(self, *_):
        table = self.conversation_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if self.view is None:
            return
        kind = self.conversation_combo.currentData()
        conversations = self.view.summary.conversations.get(kind, [])[:MAX_TABLE_ROWS]
        table.setRowCount(len(conversations))
        for row, conversation in enumerate(conversations):
            items = [SortableTableItem(self.named(conversation.a), sort_address(conversation.a), conversation),
                     SortableTableItem(self.named(conversation.b), sort_address(conversation.b)),
                     SortableTableItem(f"{conversation.packets:,}", conversation.packets),
                     SortableTableItem(stats.size_text(conversation.bytes), conversation.bytes),
                     SortableTableItem(f"{conversation.packets_ab:,} / {stats.size_text(conversation.bytes_ab)}",
                                       conversation.bytes_ab),
                     SortableTableItem(f"{conversation.packets_ba:,} / {stats.size_text(conversation.bytes_ba)}",
                                       conversation.bytes_ba),
                     SortableTableItem(f"{conversation.first:.3f}", conversation.first),
                     SortableTableItem(stats.duration_text(conversation.duration), conversation.duration),
                     SortableTableItem(conversation.note)]
            for column, item in enumerate(items):
                item.setData(Qt.UserRole, conversation.filter)
                table.setItem(row, column, item)
        table.setSortingEnabled(True)
        table.sortItems(3, Qt.DescendingOrder)  # The biggest first

    def fill_talkers(self, *_):
        table = self.talker_table
        table.setSortingEnabled(False)
        table.setRowCount(0)
        if self.view is None:
            return
        endpoints = self.view.summary.endpoints.get(self.talker_combo.currentData(), [])[:MAX_TABLE_ROWS]
        table.setRowCount(len(endpoints))
        for row, endpoint in enumerate(endpoints):
            items = [SortableTableItem(endpoint.address, sort_address(endpoint.address)),
                     SortableTableItem(endpoint.name),
                     SortableTableItem(f"{endpoint.packets:,}", endpoint.packets),
                     SortableTableItem(stats.size_text(endpoint.bytes), endpoint.bytes),
                     SortableTableItem(f"{endpoint.packets_sent:,} / {stats.size_text(endpoint.bytes_sent)}",
                                       endpoint.bytes_sent),
                     SortableTableItem(f"{endpoint.packets_received:,} / {stats.size_text(endpoint.bytes_received)}",
                                       endpoint.bytes_received)]
            for column, item in enumerate(items):
                item.setData(Qt.UserRole, endpoint.filter)
                table.setItem(row, column, item)
        table.setSortingEnabled(True)
        table.sortItems(3, Qt.DescendingOrder)

    def fill_protocols(self):
        tree = self.protocol_tree
        tree.clear()
        summary = self.view.summary
        total_packets, total_bytes = summary.packets or 1, summary.bytes or 1

        def add(row, parent):
            item = QTreeWidgetItem([row.name, f"{row.packets:,}", f"{row.packets * 100 / total_packets:.1f}%",
                                    stats.size_text(row.bytes), f"{row.bytes * 100 / total_bytes:.1f}%"])
            item.setData(0, Qt.UserRole, row.filter)
            for column in range(1, 5):
                item.setTextAlignment(column, Qt.AlignRight | Qt.AlignVCenter)
            if parent is None:
                tree.addTopLevelItem(item)
            else:
                parent.addChild(item)
            for child in row.children:
                add(child, item)
        for row in summary.protocols:
            add(row, None)
        tree.expandAll()

    def fill_timeline(self, *_):
        if self.view is None:
            self.chart.show_rows(1.0, [], False)
            return
        width, rows = stats.timeline(self.view.packets)
        self.chart.show_rows(width, rows, self.rate_combo.currentIndex() == 1)

    def fill_neighbors(self):
        table = self.neighbor_table
        neighbors = self.view.summary.neighbors
        if neighbors:
            self.neighbor_note.setText("Devices announcing themselves over CDP or LLDP: the switch and port this is "
                                       "plugged into. Double-click one to see its packets.")
        else:
            start = ("No device has announced itself over CDP or LLDP yet" if self.live is not None
                     else "No device announced itself over CDP or LLDP in this capture")
            self.neighbor_note.setText(
                f"{start}. Switches send them out of each port about every 60 seconds (CDP) or 30 seconds (LLDP), so a "
                "capture needs a minute or so, on a wired port: an access point doesn't pass them on to Wi-Fi. A SPAN "
                "destination port doesn't send the switch's own, and copies the mirrored ports' only on switches "
                "set to (encapsulation replicate).")
        table.setRowCount(len(neighbors))
        for row, neighbor in enumerate(neighbors):
            for column, text in enumerate([neighbor.protocol, neighbor.device, neighbor.port, neighbor.platform,
                                           neighbor.native_vlan, neighbor.address, neighbor.mac,
                                           f"{neighbor.packets:,}"]):
                item = SortableTableItem(text)
                item.setData(Qt.UserRole, neighbor.filter)
                table.setItem(row, column, item)

    def filter_from_table(self, item):
        text = item.data(Qt.UserRole)
        if text:
            self.apply_filter_text(text)

    def filter_from_tree(self, item, column=0):
        text = item.data(0, Qt.UserRole)
        if isinstance(text, expert.Problem):
            text = text.filter
        if text:
            self.apply_filter_text(text)

    def filter_time(self, start, end):
        self.apply_filter_text(f"frame.time_relative >= {start:g} && frame.time_relative < {end:g}")

    def conversation_menu(self, position):
        item = self.conversation_table.itemAt(position)
        if item is None:
            return
        self.menu_row = item.data(Qt.UserRole)
        menu = QMenu(self)
        add_action(menu, "Show These Packets", self.filter_menu_row)
        if self.menu_row and re.fullmatch(r"(tcp|udp)\.stream == \d+", self.menu_row):
            add_action(menu, "Follow Stream", self.follow_menu_row)
        menu.exec_(self.conversation_table.viewport().mapToGlobal(position))

    def filter_menu_row(self):
        if self.menu_row:
            self.apply_filter_text(self.menu_row)

    def follow_menu_row(self):
        match = re.fullmatch(r"(tcp|udp)\.stream == (\d+)", self.menu_row or "")
        if match:
            self.follow(match.group(1), int(match.group(2)))

    # ----------------------------------------------------------------- Problems

    def fill_problems(self, keep_selection=False):
        tree = self.problem_tree
        current = tree.currentItem()
        kept = current.data(0, Qt.UserRole) if keep_selection and current is not None else None
        kept = problem_key(kept) if isinstance(kept, expert.Problem) else None
        tree.clear()
        self.problem_detail.clear()
        for problem in self.view.problems:
            item = self.problem_item(problem)
            tree.addTopLevelItem(item)
            for child in problem.children:
                item.addChild(self.problem_item(child))
        if not self.view.problems:
            item = QTreeWidgetItem(["", "", "Nothing found", ""])
            tree.addTopLevelItem(item)
        if kept is not None:
            for index in range(tree.topLevelItemCount()):
                problem = tree.topLevelItem(index).data(0, Qt.UserRole)
                if isinstance(problem, expert.Problem) and problem_key(problem) == kept:
                    tree.setCurrentItem(tree.topLevelItem(index))
                    break

    def problem_item(self, problem):
        item = QTreeWidgetItem([problem.severity, problem.group, problem.summary,
                                f"{problem.count:,}" if problem.count else ""])
        item.setForeground(0, QBrush(QColor(SEVERITY_COLORS[problem.severity])))
        item.setData(0, Qt.UserRole, problem)
        item.setToolTip(2, problem.detail or problem.summary)
        item.setTextAlignment(3, Qt.AlignRight | Qt.AlignVCenter)
        return item

    def show_problem(self, current, previous=None):
        problem = current.data(0, Qt.UserRole) if current is not None else None
        if not isinstance(problem, expert.Problem):
            self.problem_detail.clear()
            self.problem_button.setEnabled(False)
            return
        text = problem.detail
        if problem.filter:
            text += f"{chr(10) if text else ''}Filter: {problem.filter}"
        self.problem_detail.setText(text)
        self.problem_button.setEnabled(bool(problem.filter))

    def filter_problem(self):
        item = self.problem_tree.currentItem()
        if item is not None:
            self.filter_from_tree(item)

    # ----------------------------------------------------------------- Wireshark

    def open_in_wireshark(self):
        wireshark = find_wireshark()
        if not wireshark or not self.path:
            return
        arguments = [wireshark, self.path]
        if self.filter is not None and not (self.view is not None and self.view.unwrapped):
            arguments += ["-Y", self.filter.text]
        try:
            subprocess.Popen(arguments)
        except OSError as error:
            QMessageBox.critical(self, "Wireshark", f"Couldn't start Wireshark:\n\n{error}")

    def update_buttons(self):
        loaded = self.view is not None
        self.unwrap_button.setVisible(bool(self.capture is not None and (self.capture.mirrored or (
            self.view is not None and self.view.unwrapped))))
        if self.view is not None:
            self.unwrap_button.setText("Show as Captured" if self.view.unwrapped else "Show Mirrored Frames")
        self.unwrap_button.setEnabled(loaded and self.loader is None)
        wireshark = find_wireshark()
        self.wireshark_button.setVisible(wireshark is not None)
        self.wireshark_button.setEnabled(bool(self.path) and os.path.isfile(self.path) and self.live is None)
        self.open_button.setEnabled(self.live is None)
        self.duplicates_check.setEnabled(self.live is None)
        self.apply_button.setEnabled(loaded)
        self.problem_button.setEnabled(self.problem_button.isEnabled() and loaded)


def problem_key(problem):
    """What a problem is, apart from how many times it happened (which a live capture's next look changes)."""
    return problem.severity, problem.group, problem.filter, " ".join(word for word in problem.summary.split()
                                                                     if not word.replace(",", "").isdigit())


def expanded_key(text):
    return text.split(",")[0].split(" (")[0][:40]
