"""Compare, as in Notepad++'s Compare: two files side by side (or one pane showing both), scrolled together and lined
up by blank space (annotations, so neither file changes), with the changes colored. Both sides can be edited; the
arrows in the margin copy a change from one side to the other, and the comparison follows every edit."""
from PyQt5.Qsci import QsciScintilla, QsciStyle
from PyQt5.QtCore import QPoint, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QPainter, QPen, QPixmap, QPolygonF
from PyQt5.QtWidgets import QComboBox, QHBoxLayout, QLabel, QMenu, QPushButton, QSplitter, QStackedWidget, QStyle, \
    QStyleOptionSlider, QToolButton, QVBoxLayout, QWidget

from ..configs import diff, text as config_text
from .code_editor import MARK_ADDED, MARK_CHANGED, MARK_COLORS, MARK_COPY, MARK_HIDDEN, MARK_MOVED, MARK_REMOVED, \
    SYMBOL_MARGIN, CodeEditor, language_for
from .common import add_action
from .theme import COLORS, monospace_font

MARK_COPY_BACK = 7
MARK_HERE, MARK_HERE_BAR = 8, 9  # Reviewing: an arrow at the block being reviewed, and a bar beside the rest of it
KIND_MARKS = {diff.ADDED: MARK_ADDED, diff.REMOVED: MARK_REMOVED, diff.CHANGED: MARK_CHANGED, diff.MOVED: MARK_MOVED}
KIND_COLORS = {diff.ADDED: "#35c27a", diff.REMOVED: "#e05d5d", diff.CHANGED: "#d9a53a", diff.MOVED: "#5b8fd6"}
QUICK_LINES = 20000  # Past this many lines, the comparison waits longer after typing before it runs again
SHOW_AT = 3  # Prev/Next put a change this far down the screen (a third), so the lines before it show too


def gap_style(editor):
    """The style of the blank space that lines the sides up (one per editor, made the first time)."""
    style = getattr(editor, "gap_style", None)
    if style is None:
        style = QsciStyle(-1, "Gap", QColor(COLORS["border"]), QColor(COLORS["panel"]), monospace_font(), True)
        editor.gap_style = style
    return style


def arrow_pixmap(rightward):
    """A copy arrow for the margin: pointing at the other side."""
    pixmap = QPixmap(14, 14)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(COLORS["accent"]))
    points = [QPointF(3, 2), QPointF(12, 7), QPointF(3, 12)] if rightward else         [QPointF(11, 2), QPointF(2, 7), QPointF(11, 12)]
    painter.drawPolygon(QPolygonF(points))
    painter.end()
    return pixmap


def groove_of(bar):
    """The vertical scroll bar's track (between its arrows), in its own coordinates."""
    option = QStyleOptionSlider()
    option.initFrom(bar)
    option.orientation = Qt.Vertical
    option.minimum, option.maximum = bar.minimum(), bar.maximum()
    option.sliderPosition = option.sliderValue = bar.value()
    option.singleStep, option.pageStep = bar.singleStep(), bar.pageStep()
    option.upsideDown = False
    option.subControls = QStyle.SC_All
    return bar.style().subControlRect(QStyle.CC_ScrollBar, option, QStyle.SC_ScrollBarGroove, bar)


class OverviewStrip(QWidget):
    """Where the changes are in the whole comparison, lined up with the right side's scroll bar track (so a mark is
    beside the thumb when its change is on the screen), and a box for what's on the screen; a click goes there."""
    picked = pyqtSignal(float)  # How far down (0 to 1)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedWidth(12)
        self.marks = []  # (from, to, color): fractions of the whole comparison
        self.bar = None  # The scroll bar whose track the marks line up with
        self.setToolTip("Where the changes are: click to go there")

    def set_marks(self, marks):
        self.marks = marks
        self.update()

    def follow(self, bar):
        self.bar = bar
        bar.valueChanged.connect(self.update)
        bar.rangeChanged.connect(self.update)

    def track(self):
        """(top, height) of the strip that stands for the whole comparison: the scroll bar's track, when there is
        one to line up with."""
        bar = self.bar
        if bar is not None and bar.isVisible() and bar.maximum() > bar.minimum():
            groove = groove_of(bar)
            top = self.mapFromGlobal(bar.mapToGlobal(QPoint(0, groove.top()))).y()
            if groove.height() > 10 and 0 <= top < self.height():
                return float(top), float(min(groove.height(), self.height() - top))
        return 0.0, float(max(self.height(), 1))

    def on_screen(self):
        """(from, to) fractions of the comparison on the screen, or None (it all fits)."""
        bar = self.bar
        if bar is None or bar.maximum() <= bar.minimum():
            return None
        total = bar.maximum() - bar.minimum() + bar.pageStep()
        return (bar.value() - bar.minimum()) / total, (bar.value() - bar.minimum() + bar.pageStep()) / total

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor(COLORS["panel"]))
        top, height = self.track()
        for start, end, color in self.marks:
            painter.fillRect(QRectF(1, top + start * height, self.width() - 2, max((end - start) * height, 2)),
                             QColor(color))
        shown = self.on_screen()
        if shown is not None:
            pen = QPen(QColor(COLORS["text"]))
            pen.setWidth(1)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawRect(QRectF(0.5, top + shown[0] * height, self.width() - 1.5,
                                    max((shown[1] - shown[0]) * height, 3) - 1))

    def mousePressEvent(self, event):
        top, height = self.track()
        self.picked.emit(min(max((event.pos().y() - top) / max(height, 1), 0.0), 1.0))


class ComparePane(QWidget):
    """One side: its title over its editor."""

    def __init__(self, parent, title, text, path="", read_only=False):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        self.title_label = QLabel()
        self.title_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold; padding: 2px 4px;")
        self.title_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.title_label)
        self.editor = CodeEditor(self, read_only)
        self.editor.set_language(language_for(path, text))
        self.editor.setText(text)
        self.editor.setModified(False)
        self.editor.setMarginWidth(SYMBOL_MARGIN, 16)
        self.editor.setMarginSensitivity(SYMBOL_MARGIN, True)
        self.editor.markerDefine(arrow_pixmap(True), MARK_COPY)
        self.editor.markerDefine(arrow_pixmap(False), MARK_COPY_BACK)
        here = QColor(COLORS["accent"])
        self.editor.markerDefine(QsciScintilla.RightArrow, MARK_HERE)
        self.editor.setMarkerForegroundColor(here, MARK_HERE)
        self.editor.setMarkerBackgroundColor(here, MARK_HERE)
        self.bar_height = 0  # The line height MARK_HERE_BAR's picture was drawn for (set when first used)
        layout.addWidget(self.editor, 1)
        self.title, self.path = title, path
        self.context = {}  # Where it came from: {"device_id", "address", "names", "platform", "version_id"}
        self.show_title()
        self.editor.modificationChanged.connect(self.show_title)

    def define_bar(self):
        """MARK_HERE_BAR: a bar down the middle of the margin, as tall as a line so the lines' bars join up (drawn
        again when the font size or zoom changes the line height)."""
        height = max(int(self.editor.SendScintilla(QsciScintilla.SCI_TEXTHEIGHT, 0)), 1)
        if height == self.bar_height:
            return
        self.bar_height = height
        pixmap = QPixmap(14, height)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        painter.fillRect(5, 0, 4, height, QColor(COLORS["accent"]))
        painter.end()
        self.editor.markerDefine(pixmap, MARK_HERE_BAR)

    def show_title(self, *_):
        self.title_label.setText(self.title + ("  •" if self.editor.isModified() else ""))
        self.title_label.setToolTip(self.path or self.title)


class CompareView(QWidget):
    """Two texts compared. fix_requested(current, wanted, title, context): the commands that take one side to the
    other were asked for (context: the side being changed's)."""
    fix_requested = pyqtSignal(str, str, str, object)
    modified_changed = pyqtSignal()
    compared = pyqtSignal()
    position_changed = pyqtSignal(int)  # The change Prev/Next went to

    def __init__(self, parent, left, right, left_title, right_title, mode=diff.SECTION, left_path="", right_path="",
                 read_only=(False, False)):
        super().__init__(parent)
        self.result = None
        self.current = -1  # Which change Prev/Next is at
        self.arrows = ({}, {})  # {line: hunk} on each side
        self.syncing = False
        self.review = None  # A config_review.ReviewController while a change is reviewed here
        self.here = None  # (a_start, a_end, b_start, b_end) of the block being reviewed, marked in the margins
        self.locked = False  # Reviewing: read-only, so no copy arrows
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        bar = QHBoxLayout()
        bar.setContentsMargins(4, 2, 4, 0)
        self.mode_combo = QComboBox()
        for value, name in diff.MODES:
            self.mode_combo.addItem(name, value)
        self.mode_combo.setCurrentIndex(max(self.mode_combo.findData(mode), 0))
        self.mode_combo.setToolTip("Plain text: line by line. Hide noise: without timestamps, byte counts, "
                                   "checksums and certificate data. Section-aware: by mode, so a block that only "
                                   "moved isn't a change, and each change says where it is.")
        previous_button, next_button = QPushButton("◀ Prev"), QPushButton("Next ▶")
        previous_button.setToolTip("The change before (Shift+F7)")
        next_button.setToolTip("The next change (F7)")
        previous_button.setShortcut("Shift+F7")
        next_button.setShortcut("F7")
        self.position_label = QLabel()
        self.inline_button = QToolButton()
        self.inline_button.setText("Inline")
        self.inline_button.setCheckable(True)
        self.inline_button.setToolTip("Show both sides in one pane, - and + lines, like git diff")
        swap_button = self.swap_button = QPushButton("Swap Sides")
        self.fix_button = QPushButton("Fix Commands")
        self.fix_button.setToolTip("The Cisco commands that make one side's configuration like the other's")
        fix_menu = QMenu(self.fix_button)
        self.fix_left_action = add_action(fix_menu, "Make the Left Side Like the Right", self.fix_left)
        self.fix_right_action = add_action(fix_menu, "Make the Right Side Like the Left", self.fix_right)
        self.fix_button.setMenu(fix_menu)
        bar.addWidget(QLabel("Compare:"))
        bar.addWidget(self.mode_combo)
        bar.addWidget(previous_button)
        bar.addWidget(next_button)
        bar.addWidget(self.position_label, 1)
        bar.addWidget(self.inline_button)
        bar.addWidget(swap_button)
        bar.addWidget(self.fix_button)
        layout.addLayout(bar)
        self.review_slot = QVBoxLayout()  # Where a review's bar goes
        self.review_slot.setContentsMargins(0, 0, 0, 0)
        layout.addLayout(self.review_slot)

        self.stack = QStackedWidget()
        side_by_side = QWidget()
        sides = QHBoxLayout(side_by_side)
        sides.setContentsMargins(0, 0, 0, 0)
        sides.setSpacing(0)
        self.splitter = QSplitter(Qt.Horizontal)
        self.left = ComparePane(self, left_title, left, left_path, read_only[0])
        self.right = ComparePane(self, right_title, right, right_path, read_only[1])
        self.splitter.addWidget(self.left)
        self.splitter.addWidget(self.right)
        self.strip = OverviewStrip()
        sides.addWidget(self.splitter, 1)
        sides.addWidget(self.strip)
        self.strip.follow(self.right.editor.verticalScrollBar())
        self.stack.addWidget(side_by_side)
        self.inline = CodeEditor(self, read_only=True)
        self.inline.setMarginWidth(0, 0)
        self.stack.addWidget(self.inline)
        layout.addWidget(self.stack, 1)

        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.timeout.connect(self.run_compare)
        self.mode_combo.currentIndexChanged.connect(self.run_compare)
        previous_button.clicked.connect(self.previous_change)
        next_button.clicked.connect(self.next_change)
        self.inline_button.toggled.connect(self.show_inline)
        swap_button.clicked.connect(self.swap)
        self.strip.picked.connect(self.go_to_fraction)
        for pane in (self.left, self.right):
            pane.editor.textChanged.connect(self.text_changed)
            pane.editor.modificationChanged.connect(self.on_modified)
            pane.editor.marginClicked.connect(self.margin_clicked)
            pane.editor.verticalScrollBar().valueChanged.connect(self.scrolled)
            pane.editor.horizontalScrollBar().valueChanged.connect(self.scrolled_across)
        self.run_compare()

    # ----------------------------------------------------------------- Comparing

    @property
    def mode(self):
        return self.mode_combo.currentData()

    def set_mode(self, mode):
        index = self.mode_combo.findData(mode)
        if index >= 0:
            self.mode_combo.setCurrentIndex(index)

    def text_changed(self):
        lines = max(self.left.editor.lines(), self.right.editor.lines())
        self.timer.start(1000 if lines > QUICK_LINES else 300)

    def on_modified(self, *_):
        self.modified_changed.emit()

    def run_compare(self, *_):
        self.timer.stop()
        self.result = diff.compare(self.left.editor.text(), self.right.editor.text(), self.mode)
        self.paint()
        platforms = {config_text.platform_of(self.left.editor.text()), config_text.platform_of(self.right.editor.text())}
        self.fix_button.setEnabled(bool(platforms & config_text.FIXABLE) and not self.result.same)
        if self.current >= len(self.result.changes):
            self.current = len(self.result.changes) - 1
        self.show_position()
        if self.inline_button.isChecked():
            self.fill_inline()
        self.compared.emit()

    def paint(self):
        result = self.result
        top = self.left.editor.verticalScrollBar().value()
        for pane in (self.left, self.right):
            pane.editor.markerDeleteAll()
            pane.editor.clearAnnotations()
        for line, kind in result.a_kinds.items():
            self.left.editor.markerAdd(line, KIND_MARKS[kind])
        for line, kind in result.b_kinds.items():
            self.right.editor.markerAdd(line, KIND_MARKS[kind])
        for line in result.a_hidden:
            self.left.editor.markerAdd(line, MARK_HIDDEN)
        for line in result.b_hidden:
            self.right.editor.markerAdd(line, MARK_HIDDEN)
        left_arrows, right_arrows = {}, {}
        last_left, last_right = len(result.a_lines) - 1, len(result.b_lines) - 1
        for hunk in result.changes if not self.locked else []:
            left_line, right_line = min(hunk.a_start, last_left), min(hunk.b_start, last_right)
            if left_line not in left_arrows:
                left_arrows[left_line] = hunk
                self.left.editor.markerAdd(left_line, MARK_COPY)
            if right_line not in right_arrows:
                right_arrows[right_line] = hunk
                self.right.editor.markerAdd(right_line, MARK_COPY_BACK)
        self.arrows = (left_arrows, right_arrows)
        self.pad(self.left.editor, [row.a for row in result.rows])
        self.pad(self.right.editor, [row.b for row in result.rows])
        self.strip.set_marks(self.strip_marks())
        self.paint_here()
        self.syncing = True
        self.left.editor.verticalScrollBar().setValue(top)
        self.right.editor.verticalScrollBar().setValue(top)
        self.syncing = False

    def pad(self, editor, numbers):
        """Blank space where the other side has lines this one doesn't, so the sides line up."""
        gap = 0
        pending = {}  # Line the gap goes under -> its height
        last = None
        for number in numbers:
            if number is None:
                gap += 1
                continue
            if gap:
                pending[max(number - 1, 0)] = pending.get(max(number - 1, 0), 0) + gap
                gap = 0
            last = number
        if gap and last is not None:
            pending[last] = pending.get(last, 0) + gap
        elif gap:
            pending[0] = gap
        for line, height in pending.items():
            editor.annotate(line, "\n".join([" "] * height), gap_style(editor))

    def strip_marks(self):
        """(from, to, color) of each run of changed rows: fractions of the rows (each a line on the screen, since
        the gaps line the sides up)."""
        rows = self.result.rows
        total = max(len(rows), 1)
        marks = []
        for index, row in enumerate(rows):
            kind = self.result.a_kinds.get(row.a) if row.a is not None else None
            kind = kind or (self.result.b_kinds.get(row.b) if row.b is not None else None)
            if kind is None:
                continue
            color = KIND_COLORS[kind]
            if marks and marks[-1][2] == color and abs(marks[-1][1] - index / total) < 1e-9:
                marks[-1] = (marks[-1][0], (index + 1) / total, color)
            else:
                marks.append((index / total, (index + 1) / total, color))
        return marks

    # ----------------------------------------------------------------- Moving about

    def scrolled(self, value):
        if self.syncing:
            return
        self.syncing = True
        source = self.sender()
        for pane in (self.left, self.right):
            bar = pane.editor.verticalScrollBar()
            if bar is not source:
                bar.setValue(value)
        self.syncing = False

    def scrolled_across(self, value):
        if self.syncing:
            return
        self.syncing = True
        source = self.sender()
        for pane in (self.left, self.right):
            bar = pane.editor.horizontalScrollBar()
            if bar is not source:
                bar.setValue(value)
        self.syncing = False

    def show_position(self):
        changes = self.result.changes
        if not changes:
            self.position_label.setText(self.result.summary())
            return
        summary = self.result.summary()
        if 0 <= self.current < len(changes):
            hunk = changes[self.current]
            where = f"  ·  {hunk.path}" if hunk.path else ""
            self.position_label.setText(f"{summary}  ·  at {self.current + 1} of {len(changes)}{where}")
        else:
            self.position_label.setText(summary)

    def go_to_change(self, index):
        changes = self.result.changes if self.result else []
        if not changes:
            return
        self.current = index % len(changes)
        hunk = changes[self.current]
        if self.inline_button.isChecked():
            for number, (_, a, b, _) in enumerate(self.result.inline()):
                if a == hunk.a_start or b == hunk.b_start:
                    self.inline.go_to(number)
                    break
        else:
            self.show_lines(hunk.a_start, hunk.b_start, SHOW_AT)
        self.show_position()
        self.position_changed.emit(self.current)

    def show_lines(self, left_line, right_line, at=0):
        """Put the cursor on left_line on the left and right_line on the right, then scroll both sides to the same
        place, so they stay lined up: whichever comes first a few rows down the screen, or (at) 1/at of the way down
        (Prev/Next: a third, so what comes before it shows too). Scrolling from code doesn't pass through the scroll
        bars' sync, so both sides are set here."""
        rows = []
        for pane, line in ((self.left, left_line), (self.right, right_line)):
            editor = pane.editor
            line = max(0, min(line, editor.lines() - 1))
            editor.setCursorPosition(line, 0)
            rows.append(editor.SendScintilla(QsciScintilla.SCI_VISIBLEFROMDOCLINE, line))
        screen = max(self.right.editor.SendScintilla(QsciScintilla.SCI_LINESONSCREEN), 1)
        above = max(screen // at, 3) if at else 3
        top = max(min(rows) - above, 0)
        self.syncing = True
        for pane in (self.left, self.right):
            pane.editor.setFirstVisibleLine(top)
        self.syncing = False

    def next_change(self):
        self.go_to_change(self.current + 1)

    def previous_change(self):
        self.go_to_change(self.current - 1 if self.current >= 0 else -1)

    def go_to_fraction(self, fraction):
        rows = self.result.rows if self.result else []
        if not rows:
            return
        index = min(int(fraction * len(rows)), len(rows) - 1)
        left_line = next((row.a for row in rows[index:] if row.a is not None), len(self.result.a_lines))
        right_line = next((row.b for row in rows[index:] if row.b is not None), len(self.result.b_lines))
        self.show_lines(left_line, right_line, 2)  # The place clicked in the middle of the screen

    # ----------------------------------------------------------------- Copying across

    def margin_clicked(self, margin, line, modifiers):
        if margin != SYMBOL_MARGIN:
            return
        from_left = self.sender() is self.left.editor
        hunk = self.arrows[0 if from_left else 1].get(line)
        if hunk is not None:
            self.take(hunk, to_right=from_left)

    def take(self, hunk, to_right=True):
        """Copy one change across (left's version to the right, or the other way)."""
        result = self.result
        if to_right:
            if self.right.editor.isReadOnly():
                return
            self.right.editor.replace_lines(hunk.b_start, hunk.b_end, result.a_lines[hunk.a_start:hunk.a_end])
        else:
            if self.left.editor.isReadOnly():
                return
            self.left.editor.replace_lines(hunk.a_start, hunk.a_end, result.b_lines[hunk.b_start:hunk.b_end])
        self.run_compare()

    def swap(self):
        """Left and right change places (their texts, titles and files)."""
        left_state = (self.left.editor.text(), self.left.title, self.left.path, self.left.context,
                      self.left.editor.isModified(), self.left.editor.isReadOnly())
        right_state = (self.right.editor.text(), self.right.title, self.right.path, self.right.context,
                       self.right.editor.isModified(), self.right.editor.isReadOnly())
        for pane, (text, title, path, context, modified, read_only) in ((self.left, right_state),
                                                                         (self.right, left_state)):
            pane.editor.blockSignals(True)
            pane.editor.setReadOnly(False)
            pane.editor.setText(text)
            pane.editor.setReadOnly(read_only)
            pane.editor.setModified(modified)
            pane.editor.blockSignals(False)
            pane.title, pane.path, pane.context = title, path, context
            pane.show_title()
        self.run_compare()
        self.modified_changed.emit()

    # ----------------------------------------------------------------- Inline

    def show_inline(self, inline):
        if inline:
            self.fill_inline()
        self.stack.setCurrentIndex(1 if inline else 0)

    def fill_inline(self):
        lines = self.result.inline()
        prefixes = {diff.EQUAL: "  ", diff.DELETE: "- ", diff.INSERT: "+ ", diff.HIDDEN: "  "}
        self.inline.setReadOnly(False)
        self.inline.setText("\n".join(prefixes[tag] + line for tag, _, _, line in lines))
        self.inline.setReadOnly(True)
        self.inline.markerDeleteAll()
        marks = {diff.DELETE: MARK_REMOVED, diff.INSERT: MARK_ADDED, diff.HIDDEN: MARK_HIDDEN}
        for number, (tag, _, _, _) in enumerate(lines):
            if tag in marks:
                self.inline.markerAdd(number, marks[tag])

    # ----------------------------------------------------------------- Fix commands

    def fix_left(self):
        context = dict(self.left.context)
        self.fix_requested.emit(self.left.editor.text(), self.right.editor.text(),
                                f"{self.left.title} → like {self.right.title}", context)

    def fix_right(self):
        context = dict(self.right.context)
        self.fix_requested.emit(self.right.editor.text(), self.left.editor.text(),
                                f"{self.right.title} → like {self.left.title}", context)

    # ----------------------------------------------------------------- Reviewing

    def add_review_bar(self, bar):
        self.review_slot.addWidget(bar)

    def mark_here(self, a_start, a_end, b_start, b_end):
        """Point at the lines being reviewed on both sides: an arrow on the block's first line and a bar beside the
        rest. A side without lines in the block (a block only added, or only removed) gets the arrow where they'd
        be."""
        self.here = (a_start, a_end, b_start, b_end)
        self.paint_here()

    def paint_here(self):
        for pane in self.panes():
            pane.editor.markerDeleteAll(MARK_HERE)
            pane.editor.markerDeleteAll(MARK_HERE_BAR)
        if self.here is None:
            return
        a_start, a_end, b_start, b_end = self.here
        for pane, start, end in ((self.left, a_start, a_end), (self.right, b_start, b_end)):
            editor = pane.editor
            pane.define_bar()
            last = editor.lines() - 1
            first = max(0, min(start, last))
            editor.markerAdd(first, MARK_HERE)
            for line in range(first + 1, min(end, last + 1)):
                editor.markerAdd(line, MARK_HERE_BAR)

    def here_lines(self, pane):
        """The lines of a side marked as being reviewed (for tests and the bar): [(line, marker)]."""
        found = []
        for line in range(pane.editor.lines()):
            mask = pane.editor.markersAtLine(line)
            for marker in (MARK_HERE, MARK_HERE_BAR):
                if mask & (1 << marker):
                    found.append((line, marker))
        return found

    def lock_for_review(self):
        """Section-aware with noise left out, read-only, side by side: the comparison a review is checked against."""
        self.set_mode(diff.SECTION)
        if self.mode != diff.SECTION:
            self.run_compare()
        self.inline_button.setChecked(False)
        for widget in (self.mode_combo, self.inline_button, self.swap_button):
            widget.setEnabled(False)
        self.mode_combo.setToolTip("Locked while reviewing: section-aware, with noise left out")
        for pane in self.panes():
            pane.editor.setReadOnly(True)
        self.locked = True
        self.paint()

    # ----------------------------------------------------------------- For the page

    def panes(self):
        return [self.left, self.right]

    def is_modified(self):
        return any(pane.editor.isModified() and not pane.editor.isReadOnly() for pane in self.panes())

    def focused_pane(self):
        for pane in self.panes():
            if pane.editor.hasFocus():
                return pane
        return None


__all__ = ["CompareView", "MARK_COLORS"]
