"""The terminal widget (drawing, keyboard, mouse) and a session view that connects it to a live connection."""
import logging
import os
import time

from PyQt5.QtCore import QEvent, QPoint, QPointF, QRectF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QFontMetricsF, QKeySequence, QPainter, QPen
from PyQt5.QtWidgets import QApplication, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QScrollBar, \
    QShortcut, QSizePolicy, QVBoxLayout, QWidget

from ..terminal.model import LogCleaner, Position, TerminalModel, encode_key, encode_paste
from ..terminal.config_capture import CONFIG_PROFILES, ConfigCapture, write_config
from ..terminal.highlight import COLORS as KEYWORD_COLORS
from ..terminal.sessions import SERIAL, decode_escapes
from ..terminal.transports import ConnectionFailed, make_transport
from .common import StoppableThread, hotkey_hint, release_thread, set_hint_enabled
from .prompts import PromptAnswers, UiPrompter
from .theme import COLORS

log = logging.getLogger(__name__)

BACKGROUND = QColor("#0b0f14")
FOREGROUND = QColor(COLORS["text"])
CURSOR = QColor(COLORS["accent"])
SELECTION = QColor(COLORS["accent_dim"])
FIND_HIGHLIGHT = QColor(COLORS["warning"])
ANSI = {"black": "#1e2227", "red": "#e06c75", "green": "#98c379", "brown": "#e5c07b", "yellow": "#e5c07b",
        "blue": "#61afef", "magenta": "#c678dd", "cyan": "#56b6c2", "white": "#dcdfe4",
        "brightblack": "#5c6370", "brightred": "#ff7a85", "brightgreen": "#b5e890", "brightbrown": "#ffd68a",
        "brightyellow": "#ffd68a", "brightblue": "#7cc4ff", "brightmagenta": "#de9df0", "brightcyan": "#6fd3df",
        "brightwhite": "#ffffff"}
BASE_COLORS = {"black", "red", "green", "brown", "yellow", "blue", "magenta", "cyan", "white"}
QT_KEYS = {
    Qt.Key_Up: "Up", Qt.Key_Down: "Down", Qt.Key_Left: "Left", Qt.Key_Right: "Right", Qt.Key_Home: "Home",
    Qt.Key_End: "End", Qt.Key_PageUp: "PageUp", Qt.Key_PageDown: "PageDown", Qt.Key_Insert: "Insert",
    Qt.Key_Delete: "Delete", Qt.Key_Return: "Enter", Qt.Key_Enter: "Enter", Qt.Key_Tab: "Tab",
    Qt.Key_Backtab: "Backtab", Qt.Key_Escape: "Escape", Qt.Key_Backspace: "Backspace",
    **{getattr(Qt, f"Key_F{number}"): f"F{number}" for number in range(1, 13)},
}
CTRL_CHARACTERS = {Qt.Key_Space: " ", Qt.Key_At: "@", Qt.Key_2: "2", Qt.Key_BracketLeft: "[", Qt.Key_Backslash: "\\",
                   Qt.Key_BracketRight: "]", Qt.Key_AsciiCircum: "^", Qt.Key_6: "6", Qt.Key_Underscore: "_",
                   Qt.Key_Minus: "-", Qt.Key_Slash: "/", Qt.Key_Question: "?"}
APP_SHORTCUTS = {(Qt.Key_Tab, Qt.ControlModifier), (Qt.Key_Backtab, Qt.ControlModifier | Qt.ShiftModifier),
                 (Qt.Key_Tab, Qt.ControlModifier | Qt.ShiftModifier),
                 (Qt.Key_F, Qt.ControlModifier),
                 (Qt.Key_N, Qt.ControlModifier),
                 (Qt.Key_N, Qt.ControlModifier | Qt.ShiftModifier),
                 (Qt.Key_W, Qt.ControlModifier),
                 (Qt.Key_Left, Qt.AltModifier), (Qt.Key_Right, Qt.AltModifier),
                 (Qt.Key_Return, Qt.ControlModifier | Qt.ShiftModifier),
                 (Qt.Key_Enter, Qt.ControlModifier | Qt.ShiftModifier),
                 (Qt.Key_A, Qt.AltModifier), (Qt.Key_F1, Qt.NoModifier),
                 (Qt.Key_F11, Qt.NoModifier),
                 (Qt.Key_S, Qt.ControlModifier), (Qt.Key_S, Qt.ControlModifier | Qt.ShiftModifier)}
# Left to the window: switching tabs/pages, session filter, focus mode, and the session's Log Session and Save Config
# (so Ctrl+S never sends the device an XOFF, which would freeze its output)
LOG_KEYS, CONFIG_KEYS = "Ctrl+S", "Ctrl+Shift+S"
LOG_TIP = f"Choose a file on this workstation and start logging this session ({LOG_KEYS})"
CONFIG_TIP = f"Save the full running configuration to a file on this workstation ({CONFIG_KEYS})"
REPAINT_MILLISECONDS = 15
RECONNECT_SECONDS = 10
RECONNECT_LIMIT = 180  # Tries (half an hour) before giving up: long enough for a big chassis to reload
EXIT_COMMANDS = {"exit", "logout", "quit", "logoff", "bye"}  # Closing with one isn't a drop to reconnect
WHEEL_LINES = 3


def is_simple(text):
    """Characters that can be drawn together in one run without drifting off the grid."""
    return len(text) == 1 and ord(text) < 0x2500


class TerminalView(QWidget):
    """Draws a TerminalModel and turns keys and mouse actions into input. Knows nothing about connections."""
    key_input = pyqtSignal(str)  # Text to send
    paste_requested = pyqtSignal()
    grid_changed = pyqtSignal(int, int)  # Columns, rows
    scrolled = pyqtSignal()
    find_requested = pyqtSignal()

    def __init__(self, model, parent=None):
        super().__init__(parent)
        self.model = model
        self.offset = 0  # Lines scrolled back from the bottom
        self.zoom = 0  # Points added to the text size (Ctrl+wheel)
        self.selection = None  # (anchor, end) Positions
        self.selecting = False
        self.double_click = None  # (time, QPoint) of the last double-click, so a click straight after it takes the line
        self.highlight = None  # (Position, length) of a find match
        self.highlighter = None  # Keyword highlighting (terminal.highlight.Highlighter), or None when it's off
        self.hotkey = None  # Called with 0-8 for Ctrl+1 to Ctrl+9 (command buttons); True if it used the key
        self.application_keys = False
        self.backspace_delete = True
        self.enter = "\r"
        self.colors = {}
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAttribute(Qt.WA_OpaquePaintEvent)
        self.setAttribute(Qt.WA_InputMethodEnabled)
        self.setCursor(Qt.IBeamCursor)
        self.repaint_timer = QTimer(self)
        self.repaint_timer.setSingleShot(True)
        self.repaint_timer.timeout.connect(self.update)
        self.update_font()

    # ----------------------------------------------------------------- Fonts and the grid

    def update_font(self):
        size = QApplication.font().pointSizeF() * 1.05 + self.zoom
        self.fonts = {}
        for bold in (False, True):
            for italic in (False, True):
                font = QFont("Consolas")
                font.setStyleHint(QFont.Monospace)
                font.setPointSizeF(max(5.0, size))
                font.setBold(bold)
                font.setItalic(italic)
                self.fonts[(bold, italic)] = font
        metrics = QFontMetricsF(self.fonts[(False, False)])
        self.cell_width = max(1.0, metrics.horizontalAdvance("M"))
        self.cell_height = max(1.0, float(metrics.height()))
        self.ascent = metrics.ascent()
        self.update_grid()
        self.update()

    def update_grid(self):
        # Before the widget is shown it has no real size yet; sizing the terminal to that would wrap everything
        if not self.isVisible() or self.width() < self.cell_width * 10 or self.height() < self.cell_height * 2:
            return
        columns = int(self.width() // self.cell_width)
        rows = int(self.height() // self.cell_height)
        if (columns, rows) != (self.model.columns, self.model.rows):
            self.grid_changed.emit(columns, rows)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.update_grid()

    def showEvent(self, event):
        super().showEvent(event)
        self.update_grid()

    def changeEvent(self, event):
        if event.type() in (QEvent.FontChange, QEvent.ApplicationFontChange):
            self.update_font()
        super().changeEvent(event)

    def set_zoom(self, zoom):
        self.zoom = max(-6, min(24, zoom))
        self.update_font()

    def schedule_repaint(self):
        if not self.repaint_timer.isActive():
            self.repaint_timer.start(REPAINT_MILLISECONDS)

    # ----------------------------------------------------------------- Scrolling

    def top_line(self):
        return max(0, self.model.line_count - self.model.rows - self.offset)

    def set_offset(self, offset):
        offset = max(0, min(self.model.history_length, offset))
        if offset != self.offset:
            self.offset = offset
            self.update()
            self.scrolled.emit()

    def scroll_to_line(self, index):
        """Scroll so a line (from Position.line) is in view."""
        top = self.top_line()
        if top <= index < top + self.model.rows:
            return
        self.set_offset(self.model.line_count - self.model.rows - max(0, index - self.model.rows // 2))

    # ----------------------------------------------------------------- Drawing

    def color(self, name, default):
        if name == "default":
            return default
        color = self.colors.get(name)
        if color is None:
            value = ANSI.get(name)
            if value is None and len(name) == 6:
                try:
                    int(name, 16)
                    value = "#" + name
                except ValueError:
                    value = None
            color = QColor(value) if value else default
            self.colors[name] = color
        return color

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.fillRect(self.rect(), BACKGROUND)
        model = self.model
        rows, columns = model.rows, model.columns
        top = self.top_line()
        selection = self.normalized_selection()
        cursor = model.cursor_position()
        show_cursor = self.offset == 0 or top <= cursor.line < top + rows
        show_cursor = show_cursor and model.cursor_visible
        cursor_column = min(cursor.column, columns - 1)
        width, height = self.cell_width, self.cell_height

        for row in range(rows):
            index = top + row
            if index >= model.line_count:
                break
            line = model.line(index)
            keywords = self.keyword_colors(line, columns)
            y = row * height
            column = 0
            while column < columns:
                char = line[column]
                selected = selection is not None and selection[0] <= Position(index, column) <= selection[1]
                keyword = keywords[column] if keywords else None
                key = (char.fg, char.bg, char.bold, char.italics, char.underscore, char.strikethrough, char.reverse,
                       selected, keyword)
                texts = [char.data or " "]
                start = column
                column += 1
                if is_simple(texts[0]):
                    while column < columns:
                        following = line[column]
                        data = following.data or " "
                        following_selected = selection is not None and \
                            selection[0] <= Position(index, column) <= selection[1]
                        following_keyword = keywords[column] if keywords else None
                        if not is_simple(data) or (following.fg, following.bg, following.bold, following.italics,
                                                   following.underscore, following.strikethrough, following.reverse,
                                                   following_selected, following_keyword) != key:
                            break
                        texts.append(data)
                        column += 1
                self.draw_run(painter, "".join(texts), start, y, char, selected, keyword)

            if self.highlight is not None and self.highlight[0].line == index:
                position, length = self.highlight
                painter.setPen(QPen(FIND_HIGHLIGHT, 1.5))
                painter.setBrush(Qt.NoBrush)
                painter.drawRect(QRectF(position.column * width, y, length * width, height).adjusted(0.5, 0.5, -1, -1))

        if show_cursor and top <= cursor.line < top + rows:
            rect = QRectF(cursor_column * width, (cursor.line - top) * height, width, height)
            if self.hasFocus():
                painter.fillRect(rect, CURSOR)
                char = model.line(cursor.line)[cursor_column]
                painter.setPen(BACKGROUND)
                painter.setFont(self.fonts[(char.bold, char.italics)])
                painter.drawText(QPointF(rect.x(), rect.y() + self.ascent), char.data or " ")
            else:
                painter.setPen(QPen(CURSOR, 1))
                painter.setBrush(Qt.NoBrush)
                painter.drawRect(rect.adjusted(0.5, 0.5, -1, -1))

    def keyword_colors(self, line, columns):
        """The keyword color of each column of a line (None for most), or None if nothing matches. Only text
        in the default color is colored: the device's own colors are left alone."""
        if self.highlighter is None:
            return None
        text = "".join(line[column].data or " " for column in range(columns))  # One character per column
        spans = self.highlighter.spans(text.rstrip())
        if not spans:
            return None
        colors = [None] * columns
        for start, end, color in spans:
            for column in range(start, min(end, columns)):
                char = line[column]
                if char.fg == "default" and not char.reverse:
                    colors[column] = color
        return colors if any(colors) else None

    def draw_run(self, painter, text, column, y, char, selected, keyword=None):
        foreground_name = char.fg
        if char.bold and foreground_name in BASE_COLORS:
            foreground_name = "bright" + foreground_name  # Bold shows as the bright color, as most terminals do
        foreground = self.color(foreground_name, FOREGROUND)
        if keyword is not None:
            foreground = self.color(KEYWORD_COLORS[keyword][1:], foreground)
        background = self.color(char.bg, BACKGROUND)
        if char.reverse:
            foreground, background = background, foreground
        if selected:
            background = SELECTION
        rect = QRectF(column * self.cell_width, y, len(text) * self.cell_width, self.cell_height)
        if background is not BACKGROUND:
            painter.fillRect(rect, background)
        if not text.strip():
            return
        font = self.fonts[(char.bold, char.italics)]
        if char.underscore or char.strikethrough:
            font = QFont(font)
            font.setUnderline(char.underscore)
            font.setStrikeOut(char.strikethrough)
        painter.setFont(font)
        painter.setPen(foreground)
        painter.drawText(QPointF(rect.x(), y + self.ascent), text)

    # ----------------------------------------------------------------- Selection and clipboard

    def normalized_selection(self):
        if self.selection is None:
            return None
        start, end = self.selection
        return (start, end) if start <= end else (end, start)

    def selected_text(self):
        selection = self.normalized_selection()
        return self.model.text_between(*selection) if selection else ""

    def position_at(self, point):
        column = max(0, min(self.model.columns - 1, int(point.x() // self.cell_width)))
        row = max(0, min(self.model.rows - 1, int(point.y() // self.cell_height)))
        return Position(min(self.top_line() + row, self.model.line_count - 1), column)

    def copy_selection(self):
        text = self.selected_text()
        if text:
            QApplication.clipboard().setText(text)
        return bool(text)

    def clear_selection(self):
        if self.selection is not None:
            self.selection = None
            self.update()

    def shift_selection(self, lines):
        """Move the selection by some lines (the text under it moved), or drop it if its text has gone."""
        anchor, end = self.selection
        anchor, end = Position(anchor.line + lines, anchor.column), Position(end.line + lines, end.column)
        if min(anchor.line, end.line) < 0:
            self.selection = None
            self.selecting = False
        else:
            self.selection = (anchor, end)

    def mousePressEvent(self, event):
        self.setFocus()
        if event.button() == Qt.LeftButton:
            if self.is_triple_click(event.pos()):
                self.select_at(self.model.line_at, event.pos())  # As in PuTTY: double-click a word, triple-click a line
                return
            position = self.position_at(event.pos())
            self.selection = (position, position)
            self.selecting = True
            self.update()
        elif event.button() in (Qt.RightButton, Qt.MiddleButton):
            self.paste_requested.emit()  # Right-click pastes, as in MobaXterm and PuTTY

    def mouseMoveEvent(self, event):
        if self.selecting and self.selection is not None:
            self.selection = (self.selection[0], self.position_at(event.pos()))
            if event.pos().y() < 0:
                self.set_offset(self.offset + 1)
            elif event.pos().y() > self.height():
                self.set_offset(self.offset - 1)
            self.update()

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.LeftButton and self.selecting:
            self.selecting = False
            if self.selection is None:  # Its text scrolled out of the scrollback while selecting
                self.update()
                return
            start, end = self.selection
            if start == end:
                self.selection = None
            else:
                self.copy_selection()  # Selecting copies, as in MobaXterm and PuTTY
            self.update()

    def mouseDoubleClickEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.select_at(self.model.word_at, event.pos())
            self.double_click = (time.monotonic(), event.pos())

    def is_triple_click(self, point):
        """Whether a press is the third click: straight after a double-click, in the same place."""
        if self.double_click is None:
            return False
        clicked, where = self.double_click
        self.double_click = None
        return time.monotonic() - clicked <= QApplication.doubleClickInterval() / 1000 and \
            (point - where).manhattanLength() <= QApplication.startDragDistance()

    def select_at(self, span, point):
        """Select and copy the span (a word or line) under a point."""
        self.selection = span(self.position_at(point))
        self.selecting = False
        self.copy_selection()
        self.update()

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        if event.modifiers() & Qt.ControlModifier:
            self.set_zoom(self.zoom + (1 if steps > 0 else -1))
        else:
            self.set_offset(self.offset + int(round(steps * WHEEL_LINES)))

    # ----------------------------------------------------------------- Keyboard

    def event(self, event):
        if event.type() == QEvent.ShortcutOverride:
            # Keys belong to the remote side (Ctrl+B for tmux, Ctrl+R for shell history, F5...), not NOMAD's
            # shortcuts, except the few that switch tabs and pages
            if (event.key(), int(event.modifiers()) & ~int(Qt.KeypadModifier)) not in \
                    {(key, int(modifiers)) for key, modifiers in APP_SHORTCUTS}:
                event.accept()
                return True
        if event.type() == QEvent.KeyPress and event.key() in (Qt.Key_Tab, Qt.Key_Backtab) and \
                not event.modifiers() & Qt.ControlModifier:
            self.keyPressEvent(event)  # Tab goes to the terminal, not to the next widget
            return True
        return super().event(event)

    def keyPressEvent(self, event):
        key, modifiers = event.key(), event.modifiers()
        ctrl, alt, shift = bool(modifiers & Qt.ControlModifier), bool(modifiers & Qt.AltModifier), \
            bool(modifiers & Qt.ShiftModifier)

        # Terminal commands
        if ctrl and shift and key == Qt.Key_C or ctrl and not shift and key == Qt.Key_Insert:
            self.copy_selection()
            return
        if ctrl and shift and key == Qt.Key_V or shift and not ctrl and key == Qt.Key_Insert:
            self.paste_requested.emit()
            return
        if ctrl and shift and key == Qt.Key_F:
            self.find_requested.emit()
            return
        if ctrl and not shift and not alt and Qt.Key_1 <= key <= Qt.Key_9 and self.hotkey is not None and \
                self.hotkey(key - Qt.Key_1):
            return  # A command button's hotkey; otherwise Ctrl+digit goes to the device as usual
        if shift and not ctrl and key in (Qt.Key_PageUp, Qt.Key_PageDown):
            self.set_offset(self.offset + (1 if key == Qt.Key_PageUp else -1) * max(1, self.model.rows - 1))
            return
        if shift and ctrl and key in (Qt.Key_Home, Qt.Key_End):
            self.set_offset(self.model.history_length if key == Qt.Key_Home else 0)
            return

        name = QT_KEYS.get(key, "")
        text = ""
        if not name:
            if ctrl and not alt and Qt.Key_A <= key <= Qt.Key_Z:
                text = chr(key).lower()
            elif ctrl and not alt and key in CTRL_CHARACTERS:
                text = CTRL_CHARACTERS[key]
            else:
                text = event.text()
                if text and not text.isprintable():
                    text = ""
        if ctrl and alt and text and text.isprintable():
            ctrl = alt = False  # AltGr (Ctrl+Alt on Windows) typing characters like @ or \ on many keyboards
        data = encode_key(name, text, ctrl=ctrl, alt=alt, shift=shift,
                          application_cursor=self.model.application_cursor, backspace_delete=self.backspace_delete,
                          enter=self.enter)
        if data:
            self.clear_selection()
            self.set_offset(0)
            self.key_input.emit(data)

    def inputMethodEvent(self, event):
        text = event.commitString()
        if text:
            self.set_offset(0)
            self.key_input.emit(text)
        event.accept()

    def focusInEvent(self, event):
        super().focusInEvent(event)
        self.update()

    def focusOutEvent(self, event):
        super().focusOutEvent(event)
        self.update()


# ----------------------------------------------------------------- A connected session

class ConnectionThread(StoppableThread):
    connected = pyqtSignal(str, str)  # (description, notice)
    data = pyqtSignal(bytes)
    closed = pyqtSignal(str)  # Reason
    failed = pyqtSignal(str)  # Couldn't connect

    def __init__(self, transport, parent=None):
        super().__init__(parent)
        self.transport = transport

    def run(self):
        try:
            self.transport.connect()
        except ConnectionFailed as error:
            self.failed.emit(str(error))
            return
        except Exception as error:  # Anything unexpected still has to end the "Connecting..." state
            log.exception("Unexpected error connecting")
            self.failed.emit(f"Couldn't connect: {error}")
            return
        if self.stopping:  # Closed while connecting: don't keep a connection nobody is looking at
            self.transport.close()
            return
        self.connected.emit(self.transport.description, self.transport.notice)
        while True:
            chunk = self.transport.read()
            if not chunk:
                break
            self.data.emit(chunk)
        if not self.stopping:
            self.closed.emit(self.transport.close_reason or "Disconnected.")


CONNECTING, CONNECTED, DISCONNECTED = "connecting", "connected", "disconnected"
NOTE_COLOR = "\x1b[38;2;139;152;165m"  # Muted, for NOMAD's own messages in the terminal
ERROR_COLOR = "\x1b[38;2;255;107;107m"
WARNING_COLOR = "\x1b[38;2;240;180;41m"
RESET = "\x1b[0m"


class SessionView(PromptAnswers, QWidget):
    """One open session: the terminal, its scrollbar, a status line and a find bar, plus the live connection."""
    state_changed = pyqtSignal(object)  # This view
    question = pyqtSignal(object)  # A _Request from the connection thread

    def __init__(self, session, store=None, parent=None):
        super().__init__(parent)
        self.session = session
        self.store = store  # For saving passwords the user asks to keep, if the session is saved
        self.state = DISCONNECTED
        self.transport = None
        self.thread = None
        self.prompter = UiPrompter(self)
        self.log_file = None
        self.log_cleaner = LogCleaner()
        self.config_capture = None
        self.config_commands = []
        self.config_profile = next(iter(CONFIG_PROFILES))
        self.config_timer = QTimer(self)
        self.config_timer.setSingleShot(True)
        self.config_timer.timeout.connect(self.advance_config_capture)
        self.config_timeout = QTimer(self)
        self.config_timeout.setSingleShot(True)
        self.config_timeout.timeout.connect(lambda: self.stop_config_capture(
            "Timed out waiting for the device prompt. No configuration file was saved."))
        self.last_history = 0
        self.last_scrolled_out = 0
        self.model = TerminalModel(80, 24, session.scrollback, session.encoding, respond=self.respond)
        self.mirror = None  # Called with (this view, text, block) after typing: Send to All's Type in All
        self.left_out = False  # Left out of Send to All
        self.status_text = ""
        self.outbox = []  # Lines still to send, line_delay apart (a paste or a command button)
        self.outbox_total = 0
        self.outbox_delay = 0  # At least this many ms between lines (a block that asked for it), besides line_delay
        self.outbox_timer = QTimer(self)
        self.outbox_timer.setSingleShot(True)
        self.outbox_timer.timeout.connect(self.send_next_line)
        self.auto_reconnect = session.auto_reconnect
        self.reconnect_attempts = 0  # While reconnecting after a drop
        self.reconnect_timer = QTimer(self)
        self.reconnect_timer.setSingleShot(True)
        self.reconnect_timer.timeout.connect(self.connect_session)
        self.typed_line = ""
        self.last_command = ("", 0.0)  # The last line sent, and when: an "exit" means the drop was wanted
        self.idle_timer = QTimer(self)
        self.idle_timer.setSingleShot(True)
        self.idle_timer.timeout.connect(self.send_anti_idle)
        self.question.connect(self.answer, Qt.QueuedConnection)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        body = QHBoxLayout()
        body.setSpacing(0)
        self.view = TerminalView(self.model, self)
        self.view.backspace_delete = session.backspace_sends_delete
        self.scrollbar = QScrollBar(Qt.Vertical, self)
        body.addWidget(self.view, 1)
        body.addWidget(self.scrollbar)
        layout.addLayout(body, 1)

        self.find_bar = QWidget(self)
        find_layout = QHBoxLayout(self.find_bar)
        find_layout.setContentsMargins(6, 3, 6, 3)
        find_layout.addWidget(QLabel("Find:"))
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Text to find in the scrollback (Enter finds the one before)")
        find_layout.addWidget(self.find_input, 1)
        find_previous = QPushButton("Previous")
        close_find = QPushButton("Close")
        find_layout.addWidget(find_previous)
        find_layout.addWidget(close_find)
        self.find_bar.setVisible(False)
        layout.addWidget(self.find_bar)
        self.find_from = None

        status = QHBoxLayout()
        status.setContentsMargins(6, 2, 6, 2)
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"color: {COLORS['muted']};")
        # A long message is cut off (it's in the tooltip) rather than widening the session, which in a tiled
        # layout could push the window wider than the screen
        self.status_label.setSizePolicy(QSizePolicy.Ignored, QSizePolicy.Preferred)
        self.log_label = QLabel()
        self.log_label.setStyleSheet(f"color: {COLORS['accent']};")
        status.addWidget(self.status_label, 1)
        status.addWidget(self.log_label)
        self.config_button = QPushButton("Save Config…")
        self.config_button.setToolTip(CONFIG_TIP)
        self.config_button.setEnabled(False)
        self.config_button.clicked.connect(self.save_running_config)
        status.addWidget(self.config_button)
        self.logging_button = QPushButton("Log Session…")
        self.logging_button.setToolTip(LOG_TIP)
        self.logging_button.clicked.connect(self.toggle_logging)
        status.addWidget(self.logging_button)
        layout.addLayout(status)
        # The buttons' keys, wherever the focus is in this session (the terminal leaves them to these)
        for keys, slot in ((LOG_KEYS, self.toggle_logging), (CONFIG_KEYS, self.config_shortcut)):
            QShortcut(QKeySequence(keys), self, context=Qt.WidgetWithChildrenShortcut).activated.connect(slot)
        # Over the buttons while Ctrl is held, as the command buttons' numbers are (the command bar says when)
        self.key_hints = [(self.logging_button, hotkey_hint("S", self)),
                          (self.config_button, hotkey_hint("Shift+S", self))]
        self.key_hints_shown = False
        for button, _ in self.key_hints:
            button.installEventFilter(self)  # Its text changes its width (Stop Logging, Cancel Save)

        self.view.key_input.connect(self.type_text)
        self.view.paste_requested.connect(self.paste)
        self.view.grid_changed.connect(self.resize_grid)
        self.view.scrolled.connect(self.sync_scrollbar)
        self.view.find_requested.connect(self.show_find)
        self.scrollbar.valueChanged.connect(lambda value: self.view.set_offset(self.model.history_length - value))
        self.find_input.returnPressed.connect(self.find_previous)
        self.find_input.textChanged.connect(self.restart_find)
        find_previous.clicked.connect(self.find_previous)
        close_find.clicked.connect(self.hide_find)
        self.sync_scrollbar()

    # ----------------------------------------------------------------- Ctrl's hotkey hints

    def show_key_hints(self, shown):
        """Show (or hide) S over Log Session and Shift+S over Save Config, while Ctrl is held."""
        self.key_hints_shown = shown
        self.position_key_hints()

    def position_key_hints(self):
        shown = self.key_hints_shown and self.isVisible()
        for button, hint in self.key_hints:
            if shown and button.isVisible():
                set_hint_enabled(hint, button.isEnabled())
                hint.adjustSize()
                center = button.mapTo(self, button.rect().center()).x()
                top = button.mapTo(self, QPoint(0, 0)).y()
                hint.move(min(max(0, center - hint.width() // 2), self.width() - hint.width()),
                          max(0, top - hint.height() - 2))
                hint.raise_()
                hint.show()
            else:
                hint.hide()

    def eventFilter(self, watched, event):
        if self.key_hints_shown and event.type() in (QEvent.Resize, QEvent.Move, QEvent.EnabledChange):
            self.position_key_hints()
        return super().eventFilter(watched, event)

    def showEvent(self, event):
        super().showEvent(event)
        # Shown while Ctrl is held (Alt+Right to another session, say): as the others are
        self.key_hints_shown = bool(QApplication.keyboardModifiers() & Qt.ControlModifier) and self.key_hints_shown
        self.position_key_hints()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.key_hints_shown:
            self.position_key_hints()

    # ----------------------------------------------------------------- Connecting

    @property
    def title(self):
        return self.session.name

    def connect_session(self):
        if self.state != DISCONNECTED:
            return
        self.reconnect_timer.stop()
        self.set_state(CONNECTING)
        self.prompter = UiPrompter(self)  # A fresh one: the last connection's was cancelled when it closed
        target = self.session.target()
        self.note(f"Connecting to {target} ({self.session.protocol})...", NOTE_COLOR)
        self.transport = make_transport(self.session, self.prompter, (self.model.columns, self.model.rows),
                                        self.store.vault if self.store is not None else None)
        self.view.enter = self.transport.enter
        self.thread = ConnectionThread(self.transport, self)
        self.thread.connected.connect(self.on_connected)
        self.thread.data.connect(self.on_data)
        self.thread.closed.connect(self.on_closed)
        self.thread.failed.connect(self.on_failed)
        self.thread.start()

    def on_connected(self, description, notice):
        self.reconnect_attempts = 0
        self.set_state(CONNECTED, description)
        if notice:
            self.note(notice, WARNING_COLOR)
        if self.session.log_to_file and self.log_file is None:
            self.start_logging()
        log.info("Connected: %s", description)
        self.view.setFocus()

    def on_failed(self, message):
        self.note(message, ERROR_COLOR)
        self.transport = None
        self.set_state(DISCONNECTED, message)
        if self.reconnect_attempts and self.auto_reconnect:  # Still coming back up: keep trying
            self.schedule_reconnect()
        else:
            self.reconnect_attempts = 0
            self.note("Press Enter to try again.", NOTE_COLOR)

    def on_closed(self, reason):
        self.note(reason, NOTE_COLOR)
        self.close_transport()
        self.set_state(DISCONNECTED, reason)
        if self.should_reconnect():
            self.schedule_reconnect()
        else:
            self.note("Press Enter to reconnect.", NOTE_COLOR)

    def should_reconnect(self):
        """After a drop, with Reconnect Automatically on, unless it closed because "exit" was just typed."""
        command, when = self.last_command
        words = command.split()
        exited = bool(words) and words[0].lower() in EXIT_COMMANDS and time.time() - when < 10
        return self.auto_reconnect and not exited

    def schedule_reconnect(self):
        if self.reconnect_attempts >= RECONNECT_LIMIT:
            self.note(f"Gave up reconnecting after {RECONNECT_LIMIT} tries. Press Enter to try again.", NOTE_COLOR)
            self.reconnect_attempts = 0
            return
        self.reconnect_attempts += 1
        self.note(f"Reconnecting in {RECONNECT_SECONDS} s (try {self.reconnect_attempts}). Press Enter to try now, "
                  "or right-click the tab > Stop Reconnecting.", NOTE_COLOR)
        self.set_state(DISCONNECTED, f"Reconnecting in {RECONNECT_SECONDS} s (try {self.reconnect_attempts})...")
        self.reconnect_timer.start(RECONNECT_SECONDS * 1000)

    def stop_reconnecting(self):
        if self.reconnect_timer.isActive():
            self.reconnect_timer.stop()
            self.note("Stopped reconnecting. Press Enter to connect.", NOTE_COLOR)
            self.set_state(DISCONNECTED, "Not connected.")
        self.reconnect_attempts = 0

    def toggle_auto_reconnect(self):
        self.auto_reconnect = not self.auto_reconnect
        if not self.auto_reconnect:
            self.stop_reconnecting()

    def reconnect(self):
        self.disconnect_session()
        self.connect_session()

    def disconnect_session(self):
        self.stop_reconnecting()  # Disconnecting on purpose: don't come back
        if self.state == DISCONNECTED:
            return
        self.close_transport()
        self.note("Disconnected.", NOTE_COLOR)
        self.set_state(DISCONNECTED, "Disconnected.")

    def close_transport(self):
        self.stop_config_capture("Connection closed. No configuration file was saved.")
        self.prompter.cancel_all()
        if self.thread is not None:
            self.thread.stop()
        if self.transport is not None:
            self.transport.close()
        if self.thread is not None:
            # Still connecting can mean stuck for a while (no answer, or a password prompt): don't keep the UI waiting
            release_thread(self.thread, 3000 if self.state == CONNECTED else 200)
            self.thread = None
        self.transport = None

    def shutdown(self):
        """Close the connection and the log (the view is going away)."""
        for timer in (self.reconnect_timer, self.outbox_timer, self.idle_timer):
            timer.stop()
        self.close_transport()
        self.stop_logging()
        self.state = DISCONNECTED

    # ----------------------------------------------------------------- In a tab (see session_tabs)

    def focus_target(self):
        return self.view

    def confirm_close(self):
        return True

    def add_tab_actions(self, menu, actions):
        config_action = menu.addAction(("Cancel Config Save" if self.config_capture else "Save Running Config…")
                                       + f"\t{CONFIG_KEYS}")
        config_action.setEnabled(self.state == CONNECTED)
        actions[config_action] = self.cancel_config_capture if self.config_capture else self.save_running_config
        if self.session.protocol == SERIAL:
            break_action = menu.addAction("Send Break")
            break_action.setToolTip("What Cisco devices watch for at boot to enter ROMMON (password recovery).")
            break_action.setEnabled(self.state == CONNECTED)
            actions[break_action] = self.send_break
        actions[menu.addAction(("Stop Logging" if self.log_file is not None else "Log to File")
                               + f"\t{LOG_KEYS}")] = self.toggle_logging
        actions[menu.addAction("Find...")] = self.show_find
        actions[menu.addAction("Clear Scrollback")] = self.clear_scrollback
        if self.outbox:
            actions[menu.addAction(f"Stop Sending ({len(self.outbox)} lines left)")] = self.stop_sending
        if self.reconnect_timer.isActive():
            actions[menu.addAction("Stop Reconnecting")] = self.stop_reconnecting
        auto = menu.addAction("Reconnect Automatically")
        auto.setCheckable(True)
        auto.setChecked(self.auto_reconnect)
        auto.setToolTip("When the connection drops (such as a device reloading), keep trying until it's back")
        actions[auto] = self.toggle_auto_reconnect
        if self.mirror is not None:
            leave_out = menu.addAction("Leave Out of Send to All")
            leave_out.setCheckable(True)
            leave_out.setChecked(self.left_out)
            actions[leave_out] = self.toggle_left_out

    def toggle_left_out(self):
        self.left_out = not self.left_out
        self.state_changed.emit(self)  # Updates the tab

    def set_state(self, state, detail=""):
        self.state = state
        self.config_button.setEnabled(state == CONNECTED)
        self.status_text = {CONNECTING: "Connecting...", CONNECTED: detail,
                            DISCONNECTED: detail or "Not connected."}[state]
        if state != CONNECTED:
            self.stop_sending()
        self.restart_idle_timer()
        self.update_status()
        self.state_changed.emit(self)

    def update_status(self):
        parts = [self.status_text, f"{self.model.columns}×{self.model.rows}"]
        if self.outbox:
            parts.append(f"Sending line {self.outbox_total - len(self.outbox) + 1} of {self.outbox_total}")
        self.status_label.setText("   ·   ".join(parts))
        self.status_label.setToolTip(self.status_text)

    # ----------------------------------------------------------------- Data

    def respond(self, text):
        """Answers the terminal gives to the device's questions (cursor position and the like)."""
        if self.transport is not None and self.state == CONNECTED:
            self.transport.send(text.encode(self.session.encoding, "replace"))

    def on_data(self, data):
        text = self.model.feed(data)
        if self.config_capture is not None:
            self.config_capture.feed(text)
            self.config_timer.stop()
            if self.config_capture.complete:
                self.config_timer.start(500)
        self.after_output(text)

    def after_output(self, text=""):
        if self.log_file is not None and text:
            try:
                self.log_file.write(self.log_cleaner.clean(text))
            except OSError:
                self.stop_logging()
        history, scrolled_out = self.model.history_length, self.model.scrolled_out
        scrolled = scrolled_out - self.last_scrolled_out  # Lines that moved up into the scrollback
        # Lines gone from the top: dropped from a full scrollback, or cleared (Clear Scrollback, a reset)
        dropped = scrolled - (history - self.last_history)
        self.last_history, self.last_scrolled_out = history, scrolled_out
        if self.view.offset and scrolled > 0:
            self.view.offset = min(self.view.offset + scrolled, history)  # Keep showing the same text when scrolled back
        if dropped > 0 and self.view.selection is not None:
            self.view.shift_selection(-dropped)  # Stays on its text (even mid-drag), unless that text has gone
        self.view.schedule_repaint()
        self.sync_scrollbar()

    def note(self, message, color):
        """Write one of NOMAD's own messages into the terminal, then the line it interrupted (the device's prompt and
        anything typed after it) again, so the cursor is back where the device has it: what's typed next, or Save
        Config looking for the prompt, carries on from there."""
        column = self.model.screen.cursor.x
        line = self.model.line(self.model.cursor_position().line)
        interrupted = "".join(line[index].data for index in range(column))  # Spaces kept: "$ " stays "$ "
        prefix = "\r\n" if column else ""
        self.model.feed_text(f"{prefix}{color}[{message}]{RESET}\r\n{interrupted}")
        self.after_output()

    def type_text(self, text):
        if self.state == DISCONNECTED:
            if text in ("\r", "\r\n", "\n", self.view.enter):
                self.connect_session()
            return
        if self.send_text(text) and self.mirror is not None:
            self.mirror(self, text, False)

    def send_text(self, text):
        """Send text as if typed here (without mirroring it). Returns whether it was sent."""
        if self.state != CONNECTED or self.transport is None or self.config_capture is not None:
            return False
        data = text.encode(self.session.encoding, "replace")
        self.transport.send(data)
        if self.transport.local_echo:
            self.model.feed(data.replace(b"\r", b"\r\n") if data.endswith(b"\r") else data)
            self.after_output()
        self.track_command(text)
        self.restart_idle_timer()
        return True

    def track_command(self, text):
        """Keep the line being typed, so a drop right after "exit" isn't taken for one to reconnect after."""
        for char in text:
            if char in "\r\n":
                if self.typed_line.strip():
                    self.last_command = (self.typed_line.strip(), time.time())
                self.typed_line = ""
            elif char in "\x7f\b":
                self.typed_line = self.typed_line[:-1]
            elif char.isprintable():
                self.typed_line = (self.typed_line + char)[-200:]

    def send_line(self, command):
        """Send a command and this session's Enter (Send to All)."""
        return self.send_block(command)

    def send_block(self, text, final_enter=True, min_delay=0):
        """Send lines of text (a paste, a command button, Send to All), each with this session's Enter; the
        last one too if final_enter (or the text ends with a line break). With a line delay set (the session's, or
        min_delay ms for a block that needs one, such as switch configuration), one line at a time, so slow
        consoles don't drop characters. Returns whether it's being sent."""
        if self.state != CONNECTED or self.transport is None or self.config_capture is not None:
            return False
        normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = normalized.split("\n")
        if normalized.endswith("\n"):
            lines.pop()
            final_enter = True
        chunks = [line + self.view.enter for line in lines[:-1]]
        if lines:
            chunks.append(lines[-1] + (self.view.enter if final_enter else ""))
        chunks = [chunk for chunk in chunks if chunk]
        if max(self.session.line_delay, min_delay) <= 0 or len(chunks) + len(self.outbox) <= 1:
            return self.send_text("".join(chunks)) or not chunks
        self.outbox += chunks
        self.outbox_total += len(chunks)
        self.outbox_delay = max(self.outbox_delay, min_delay)
        if not self.outbox_timer.isActive():
            self.send_next_line()
        return True

    def send_next_line(self):
        if not self.outbox or self.state != CONNECTED:
            self.stop_sending()
            return
        self.send_text(self.outbox.pop(0))
        if self.outbox:
            self.outbox_timer.start(max(self.session.line_delay, self.outbox_delay))
            self.update_status()
        else:
            self.stop_sending()

    def stop_sending(self):
        """Drop the lines not sent yet."""
        self.outbox_timer.stop()
        self.outbox = []
        self.outbox_total = 0
        self.outbox_delay = 0
        self.update_status()

    def restart_idle_timer(self):
        """Anti-idle: after this long without sending anything, send the anti-idle text."""
        if (self.config_capture is None and self.session.anti_idle > 0 and self.state == CONNECTED
                and decode_escapes(self.session.anti_idle_text)):
            self.idle_timer.start(self.session.anti_idle * 1000)
        else:
            self.idle_timer.stop()

    def send_anti_idle(self):
        if self.state == CONNECTED:
            self.send_text(decode_escapes(self.session.anti_idle_text))  # Which starts the timer again

    def paste(self):
        text = QApplication.clipboard().text()
        if not text:
            return
        if text.count("\n") >= 5 and self.state == CONNECTED:
            reply = QMessageBox.question(self, "Paste", f"Paste {text.count(chr(10)) + 1} lines into "
                                         f"{self.session.name}?", QMessageBox.Yes | QMessageBox.No,
                                         QMessageBox.Yes)
            if reply != QMessageBox.Yes:
                return
        self.view.set_offset(0)
        if self.session.line_delay > 0 and self.state == CONNECTED and "\n" in text.strip("\r\n"):
            self.send_block(text, final_enter=False)
            if self.mirror is not None:
                self.mirror(self, text, True)
            return
        self.type_text(encode_paste(text, self.model.bracketed_paste))

    def resize_grid(self, columns, rows):
        self.model.resize(columns, rows)
        if self.transport is not None:
            self.transport.resize(columns, rows)
        self.update_status()
        self.after_output()

    def sync_scrollbar(self):
        history = self.model.history_length
        self.scrollbar.blockSignals(True)
        self.scrollbar.setRange(0, history)
        self.scrollbar.setPageStep(self.model.rows)
        self.scrollbar.setValue(history - self.view.offset)
        self.scrollbar.blockSignals(False)

    def send_break(self):
        if self.session.protocol == SERIAL and self.transport is not None and self.state == CONNECTED:
            self.transport.send_break()
            self.note("Sent a serial break.", NOTE_COLOR)

    def clear_scrollback(self):
        self.model.clear_scrollback()
        self.view.set_offset(0)
        self.after_output()  # Counts the cleared lines as gone, which drops a selection on them

    # ----------------------------------------------------------------- Running configuration

    def save_running_config(self):
        if self.config_capture is not None:
            self.cancel_config_capture()
            return
        if self.state != CONNECTED or self.transport is None:
            return
        if self.outbox or self.typed_line:
            QMessageBox.information(self, "Save Running Config", "Finish the current command before saving a config.")
            return
        cursor = self.model.cursor_position()
        prompt = "".join(self.model.line(cursor.line)[column].data or " "
                         for column in range(self.model.columns)).strip()
        if not prompt or prompt[-1] not in "#>$%" or "(config" in prompt.lower():
            QMessageBox.information(self, "Save Running Config",
                                    "Return to the device's operational / exec prompt first. "
                                    "For Cisco devices, use a privileged (#) prompt.")
            return
        profiles = list(CONFIG_PROFILES)
        profile, accepted = QInputDialog.getItem(
            self, "Save Running Config", "Device type (use a prompt with permission to view the full config):",
            profiles, profiles.index(self.config_profile), False)
        if not accepted:
            return
        commands = list(CONFIG_PROFILES[profile])
        if not commands:
            command, accepted = QInputDialog.getText(
                self, "Config Command", "Command to display the entire config (disable paging first):",
                text="show running-config")
            if not accepted or not command.strip():
                return
            if any(char in command for char in "\r\n\x00"):
                return
            commands = [command.strip()]
        safe_name = "".join(char if char.isalnum() or char in " -_.@" else "_" for char in self.session.name)
        suggested = os.path.join(self.default_log_folder(),
                                 f"{safe_name} running-config {time.strftime('%Y-%m-%d %H%M%S')}.cfg")
        path, _ = QFileDialog.getSaveFileName(self, "Save Running Config", suggested,
                                            "Configuration (*.cfg);;Text files (*.txt);;All files (*)")
        if not path or self.state != CONNECTED:
            return
        self.config_profile = profile
        self.config_path = path
        self.config_prompt = prompt
        self.config_commands = commands
        self.config_button.setText("Cancel Save")
        self.config_timeout.start(300000)
        self.start_config_command()

    def config_shortcut(self):
        """Ctrl+Shift+S: what the Save Config button (Cancel Save, while saving) does, if it can be pressed."""
        if self.config_button.isEnabled():
            self.save_running_config()
        else:
            self.note("Save Config needs a connected session.", ERROR_COLOR)

    def start_config_command(self):
        command = self.config_commands.pop(0)
        self.config_capture = ConfigCapture(self.config_prompt, command)
        self.idle_timer.stop()
        # Send only to this device; never mirror a capture into other sessions.
        try:
            self.transport.send((command + self.view.enter).encode(self.session.encoding, "replace"))
        except Exception as error:
            self.stop_config_capture(f"Couldn't request the configuration: {error}. No file was saved.")

    def advance_config_capture(self):
        capture = self.config_capture
        if capture is None or not capture.complete:
            return
        try:
            text = capture.output()
            if self.config_commands:
                self.start_config_command()
                return
            if not text.strip():
                raise ValueError("The device returned no configuration.")
            write_config(self.config_path, text)
        except (ValueError, OSError) as error:
            self.stop_config_capture(f"Config save failed: {error}. No configuration file was saved.")
            return
        path = self.config_path
        self.stop_config_capture()
        self.note(f"Saved running configuration to {path}", NOTE_COLOR)
        self.config_button.setToolTip(f"Last saved configuration: {path} ({CONFIG_KEYS} saves it again)")

    def stop_config_capture(self, message=""):
        if self.config_capture is None:
            return
        self.config_timer.stop()
        self.config_timeout.stop()
        self.config_capture = None
        self.config_commands = []
        self.config_button.setText("Save Config…")
        self.restart_idle_timer()
        if message:
            self.note(message, ERROR_COLOR)

    def cancel_config_capture(self):
        if self.config_capture is None:
            return
        try:
            if self.transport is not None:
                self.transport.send(b"\x03")
        except Exception as error:
            log.warning("Couldn't interrupt config capture: %s", error)
        finally:
            self.stop_config_capture("Config save cancelled. No configuration file was saved.")

    # ----------------------------------------------------------------- Logging

    def default_log_folder(self):
        return self.session.log_folder or os.path.join(os.path.expanduser("~"), "Documents", "NOMAD Logs")

    def suggested_log_path(self):
        folder = self.default_log_folder()
        safe_name = "".join(character if character.isalnum() or character in " -_.@" else "_"
                            for character in self.session.name)
        return os.path.join(folder, f"{safe_name} {time.strftime('%Y-%m-%d %H%M%S')}.log")

    def start_logging(self, path=None):
        if self.log_file is not None:
            return
        automatic = path is None
        path = self.suggested_log_path() if automatic else path
        file = None
        try:
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
            file = open(path, "a" if automatic else "w", encoding="utf-8", buffering=1)
            file.write(f"--- {self.session.name} ({self.session.target()}), {time.strftime('%c')} ---\n")
        except OSError as error:
            if file is not None:
                file.close()
            self.note(f"Couldn't start logging to {path}: {error}", ERROR_COLOR)
            return
        self.log_file = file
        self.log_cleaner = LogCleaner()
        self.log_path = path
        self.log_label.setText("● Logging")
        self.log_label.setToolTip(path)
        self.logging_button.setText("Stop Logging")
        self.logging_button.setToolTip(f"Stop logging to {path} ({LOG_KEYS})")
        self.note(f"Logging to {path}", NOTE_COLOR)

    def stop_logging(self):
        if self.log_file is not None:
            try:
                self.log_file.close()
            except OSError:
                pass
            self.log_file = None
            self.log_label.clear()
            self.log_label.setToolTip("")
            self.logging_button.setText("Log Session…")
            self.logging_button.setToolTip(LOG_TIP)

    def toggle_logging(self):
        if self.log_file is None:
            path, _ = QFileDialog.getSaveFileName(self, "Log Session", self.suggested_log_path(),
                                                "Log files (*.log);;Text files (*.txt);;All files (*)")
            if path:
                self.start_logging(path)
        else:
            self.stop_logging()
            self.note("Stopped logging.", NOTE_COLOR)

    # ----------------------------------------------------------------- Find

    def show_find(self):
        self.find_bar.setVisible(True)
        self.find_input.setFocus()
        self.find_input.selectAll()

    def hide_find(self):
        self.find_bar.setVisible(False)
        self.view.highlight = None
        self.view.update()
        self.view.setFocus()

    def restart_find(self):
        self.find_from = None
        self.find_input.setStyleSheet("")

    def find_previous(self):
        query = self.find_input.text()
        found = self.model.find(query, self.find_from)
        if found is None and self.find_from is not None:
            found = self.model.find(query)  # Wrap around to the bottom
        if found is None:
            self.find_input.setStyleSheet(f"border: 1px solid {COLORS['error']};")
            self.view.highlight = None
            self.view.update()
            return
        self.find_input.setStyleSheet("")
        self.find_from = found
        self.view.highlight = (found, len(query))
        self.view.scroll_to_line(found.line)
        self.view.update()

    # ----------------------------------------------------------------- Questions from the connection thread
    def report(self, message, warning):
        """A note from saving a password (PromptAnswers)."""
        self.note(message, WARNING_COLOR if warning else NOTE_COLOR)
