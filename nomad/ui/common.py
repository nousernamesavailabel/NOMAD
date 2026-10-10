"""Widgets and helpers shared by the tabs."""
import logging
import threading

from PyQt5 import sip
from PyQt5.QtCore import QEvent, QObject, QRunnable, Qt, QThread, QThreadPool, QTimer, pyqtSignal
from PyQt5.QtGui import QPainter
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QHeaderView, QLabel, QMenu, QSizePolicy, \
    QTableView, QTableWidget, QTableWidgetItem

from .theme import COLORS

log = logging.getLogger(__name__)

INVALID_INPUT_STYLE = f"border: 1px solid {COLORS['error']};"
HINT_COLORS = {kind: COLORS[name] for kind, name in
               {"error": "error", "warning": "warning", "info": "muted", "success": "success"}.items()}


def set_invalid(line_edit, invalid):
    """Outline a field in red while it holds an invalid value."""
    line_edit.setStyleSheet(INVALID_INPUT_STYLE if invalid else "")


def set_hint(label, text, kind="info"):
    label.setStyleSheet(f"color: {HINT_COLORS[kind]};")
    label.setText(text)


def add_submenu(menu, title):
    """A submenu at the end of menu, for grouping like items so a right-click menu stays short. Made in Python, not
    with menu.addMenu(title), so its wrapper can't outlive it."""
    submenu = QMenu(title, menu)
    menu.addMenu(submenu)
    return submenu


def drop_empty_submenus(menu, *submenus):
    """Take submenus nothing was put in back out of menu."""
    for submenu in submenus:
        if submenu is not None and not submenu.actions():
            menu.removeAction(submenu.menuAction())


def menu_labels(menu):
    """The text of every entry of menu, its submenus' included."""
    labels = set()
    for action in menu.actions():
        labels.add(action.text())
        if action.menu() is not None:
            labels |= menu_labels(action.menu())
    return labels


def format_size(size):
    """Bytes for display, such as "12.3 MB"."""
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.0f} {unit}" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024


def format_ms(value):
    """Milliseconds for display: "" when missing, "<1 ms" when under a millisecond."""
    return "" if value is None else "<1 ms" if value < 1 else f"{value:.0f} ms"


class SortableTableItem(QTableWidgetItem):
    """Table item that sorts by its sort_key, so IP addresses and numbers sort numerically."""

    def __init__(self, text, sort_key=None, data=None):
        super().__init__(text)
        self.sort_key = sort_key
        self.data_object = data

    def __lt__(self, other):
        other_key = getattr(other, "sort_key", None)
        if self.sort_key is not None and other_key is not None:
            return self.sort_key < other_key
        return super().__lt__(other)


def read_only_table(columns):
    """A table of results: rows are selected whole, one at a time, and can't be edited."""
    table = QTableWidget(0, len(columns))
    table.setHorizontalHeaderLabels(columns)
    table.setEditTriggers(QAbstractItemView.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectRows)
    table.setSelectionMode(QAbstractItemView.SingleSelection)
    table.verticalHeader().setVisible(False)
    table.horizontalHeader().setStretchLastSection(True)
    ColumnFitter(table)
    return table


class ColumnFitter(QObject):
    """Columns the user can drag wider or narrower that otherwise fit their contents, as ResizeToContents does (up
    to widest, {column: pixels}): a column keeps the width the user dragged it to, until its edge is double-clicked.
    stretch: a column that also takes up the room the others leave (as Stretch does, but draggable); or the header's
    last section, if it stretches. only: the columns to fit (the others keep the widths they're given). Works for a
    table or a tree; parented to its header, so it goes when that does."""

    def __init__(self, view, widest=None, stretch=None, only=None):
        header = view.horizontalHeader() if isinstance(view, QTableView) else view.header()
        super().__init__(header)
        # Kept by the view: Qt owning it doesn't keep its Python side (and slots) alive. It reaches the view and
        # header through its parent, not attributes, so the two don't hold each other
        view.column_fitter = self
        self.widest = dict(widest or {})
        self.stretch, self.only = stretch, only
        self.dragged = set()  # Columns the user sized: left as they are
        self.fitted = {}  # Column -> the width fitting its contents, which the stretch column doesn't go under
        self.fitting = False
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(0)
        self.timer.timeout.connect(self.fit)
        header.setSectionResizeMode(QHeaderView.Interactive)
        if stretch is not None:
            header.setStretchLastSection(False)
            view.viewport().installEventFilter(self)  # Its resizes: the stretch column fills the room again
        header.sectionResized.connect(self.on_resized)
        header.sectionHandleDoubleClicked.connect(self.on_double_clicked)
        model = view.model()
        for signal in (model.rowsInserted, model.rowsRemoved, model.dataChanged, model.modelReset,
                       model.layoutChanged, model.columnsInserted, model.headerDataChanged):
            signal.connect(self.schedule)
        self.schedule()

    @property
    def header(self):
        # Looked up as a QHeaderView: parent() looks it up as a QObject, which can find a wrapper Python still holds
        # of an object Qt made and deleted at the same address (a menu, say), not the header there now
        return sip.wrapinstance(sip.unwrapinstance(self.parent()), QHeaderView)

    @property
    def view(self):
        return self.header.parentWidget()

    def schedule(self, *_):
        """Fit once the current changes are made (many rows added at once fit once)."""
        self.timer.start()

    def header_stretches(self, column):
        """Whether the header sizes the column itself: its last section, which it stretches."""
        return self.stretch is None and self.header.stretchLastSection() and column == self.header.count() - 1

    def replaced(self):
        """Whether the view has another header now (and this one is going, with this)."""
        view = self.view
        if view is None:
            return True
        return (view.horizontalHeader() if isinstance(view, QTableView) else view.header()) is not self.header

    def fit(self):
        if self.replaced():
            return
        header, view = self.header, self.view
        self.fitting = True
        try:
            for column in range(header.count()):
                if column in self.dragged or header.isSectionHidden(column) or self.header_stretches(column) \
                        or (self.only is not None and column not in self.only):
                    continue
                view.resizeColumnToContents(column)
                width = min(header.sectionSize(column), self.widest.get(column, 1 << 20))
                self.fitted[column] = width
                header.resizeSection(column, width)
        finally:
            self.fitting = False
        self.fill()

    def fill(self):
        """Widen the stretch column into the room the others leave (back to its fitted width when there's none)."""
        column = self.stretch
        if column is None or column in self.dragged or self.replaced():
            return
        header = self.header
        if column >= header.count():
            return
        others = sum(header.sectionSize(other) for other in range(header.count())
                     if other != column and not header.isSectionHidden(other))
        width = max(self.fitted.get(column, 0), self.view.viewport().width() - others)
        if width != header.sectionSize(column):
            self.fitting = True
            try:
                header.resizeSection(column, width)
            finally:
                self.fitting = False

    def on_resized(self, column, old, new):
        if self.fitting or not QApplication.mouseButtons() & Qt.LeftButton or self.header_stretches(column):
            return
        self.dragged.add(column)  # Being dragged by the user
        self.fill()

    def on_double_clicked(self, column):
        """Double-clicking a column's edge: it fits its contents again (and keeps fitting them)."""
        self.dragged.discard(column)
        self.schedule()

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Resize:
            self.fill()
        return False


class _TaskSignals(QObject):
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(object)


class _Task(QRunnable):
    def __init__(self, function, signals):
        super().__init__()
        self.function = function
        self.signals = signals

    def run(self):
        try:
            result = self.function()
        except Exception as error:  # Reported to the caller's error handler
            log.exception("Background task failed")
            self.signals.failed.emit(error)
        else:
            self.signals.succeeded.emit(result)


_running_signals = set()  # Keeps signal objects alive until their task finishes and Qt frees them


def forget_deleted(objects):
    """Drop from a set the Qt objects Qt has freed."""
    for item in [item for item in objects if sip.isdeleted(item)]:
        objects.discard(item)


def run_in_background(function, on_success=None, on_error=None):
    """Run function() on a worker thread and call on_success(result) / on_error(exception) on the UI thread."""
    forget_deleted(_running_signals)
    signals = _TaskSignals()
    _running_signals.add(signals)
    if on_success:
        signals.succeeded.connect(on_success)
    if on_error:
        signals.failed.connect(on_error)
    # Freed by Qt once it has said how it went (its own slot, after on_success or on_error): freeing it from a lambda
    # (dropping the last reference to it) while its signal is being delivered isn't safe
    signals.succeeded.connect(signals.deleteLater)
    signals.failed.connect(signals.deleteLater)
    QThreadPool.globalInstance().start(_Task(function, signals))


class StoppableThread(QThread):
    """Base for long-running workers (ping, traceroute, MTU test) that report progress through signals."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.stop_event = threading.Event()

    def stop(self):
        self.stop_event.set()

    @property
    def stopping(self):
        return self.stop_event.is_set()


_orphaned_threads = set()  # Threads let go of while still running, kept alive until they finish


def release_thread(thread, wait_ms=3000):
    """Wait for a stopped thread to finish; if it's still stuck (connecting, say), let it finish on its own. Its
    signals are cut and it no longer belongs to its widget, so closing the widget can't destroy a running thread
    (which takes the whole program down)."""
    if thread.wait(wait_ms):
        return
    try:
        thread.disconnect()  # Every signal: nothing it says now should reach the widget
    except TypeError:
        pass
    thread.setParent(None)
    forget_deleted(_orphaned_threads)
    _orphaned_threads.add(thread)
    thread.finished.connect(thread.deleteLater)  # Freed by Qt once it has finished (its own slot, not a lambda)
    if thread.isFinished():  # Finished just now, before that was connected
        thread.deleteLater()


def hotkey_hint(text, parent):
    """A small badge naming a key, shown over a button while Ctrl is held (command buttons' numbers, a terminal
    session's S and Shift+S). Hidden to start with; clicks go through it."""
    hint = QLabel(text, parent)
    hint.setAlignment(Qt.AlignCenter)
    hint.setAttribute(Qt.WA_TransparentForMouseEvents)
    set_hint_enabled(hint, True)
    hint.hide()
    return hint


def set_hint_enabled(hint, enabled):
    """A hotkey badge in the accent color, or muted while its button can't be pressed."""
    hint.setStyleSheet(f"color: {COLORS['accent' if enabled else 'muted']}; background: {COLORS['background']}; "
                       f"border: 1px solid {COLORS['border']}; border-radius: 3px; padding: 1px 4px; "
                       "font-weight: bold;")


class OneLineLabel(QLabel):
    """A label that can be kept to one line (set_one_line): what doesn't fit is cut short with "...", the whole of
    it in the tooltip. text() is always the whole text. wraps: whether it wraps when it isn't kept to one line."""

    def __init__(self, text="", parent=None, wraps=False):
        super().__init__(text, parent)
        self.wraps, self.one_line = wraps, False
        self.setWordWrap(wraps)

    def set_one_line(self, on, width=None):
        """width: keep to that many pixels, taking the same room whatever it says (rather than whatever's left)."""
        self.one_line = on
        self.setWordWrap(self.wraps and not on)
        if on and width:
            self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Preferred)
            self.setFixedWidth(width)
        else:
            self.setSizePolicy(QSizePolicy.Ignored if on else QSizePolicy.Preferred, QSizePolicy.Preferred)
            self.setMinimumWidth(0)
            self.setMaximumWidth(16777215)
        self.setToolTip(self.text() if on else "")
        self.updateGeometry()
        self.update()

    def setText(self, text):
        super().setText(text)
        if self.one_line:
            self.setToolTip(text)

    def paintEvent(self, event):
        if not self.one_line:
            super().paintEvent(event)
            return
        painter = QPainter(self)
        rect = self.contentsRect()
        text = self.fontMetrics().elidedText(self.text(), Qt.ElideRight, rect.width())
        self.style().drawItemText(painter, rect, int(self.alignment()), self.palette(), self.isEnabled(), text,
                                  self.foregroundRole())
