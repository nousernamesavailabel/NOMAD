"""Command buttons under the terminal sessions: saved commands (or blocks of configuration) sent with one click."""
from PyQt5.QtCore import QEvent, QMimeData, QPoint, Qt, QTimer
from PyQt5.QtGui import QDrag
from PyQt5.QtWidgets import QApplication, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QFrame, QHBoxLayout, \
    QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QScrollArea, QToolButton, QVBoxLayout, QWidget

from ..terminal.commands import CommandButton
from .common import hotkey_hint, set_hint
from .terminal_view import SessionView
from .theme import COLORS, monospace_font

BUTTON_MIME = "application/x-nomad-command-button"


class DraggableButton(QToolButton):
    """A command button that can be dragged along the bar to change the order (and so its Ctrl+number)."""

    def __init__(self, button_id, number=None, hint_parent=None):
        super().__init__()
        self.button_id = button_id
        self.press_position = None
        # A sibling overlay in the terminal area, outside the button and the bar's layout.
        self.shortcut_hint = hotkey_hint(str(number) if number is not None else "", hint_parent or self)
        self.destroyed.connect(self.shortcut_hint.deleteLater)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.press_position = event.pos()
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.press_position is None or not event.buttons() & Qt.LeftButton or \
                (event.pos() - self.press_position).manhattanLength() < QApplication.startDragDistance():
            super().mouseMoveEvent(event)
            return
        self.press_position = None
        self.setDown(False)  # A drag, not a click: nothing is sent
        mime = QMimeData()
        mime.setData(BUTTON_MIME, self.button_id.encode())
        drag = QDrag(self)
        drag.setMimeData(mime)
        drag.setPixmap(self.grab())
        drag.setHotSpot(event.pos())
        drag.exec_(Qt.MoveAction)


class ButtonRow(QWidget):
    """The row the buttons sit in: a button dropped on it goes where it's dropped."""

    def __init__(self, store):
        super().__init__()
        self.store = store
        self.setAcceptDrops(True)
        self.marker = QFrame(self)  # Where a dragged button will land
        self.marker.setStyleSheet(f"background: {COLORS['accent']};")
        self.marker.setFixedWidth(2)
        self.marker.hide()

    def buttons(self, leaving_out=None):
        """The buttons in the row, in order (not old ones still waiting to be deleted)."""
        items = (self.layout().itemAt(index) for index in range(self.layout().count()))
        return [item.widget() for item in items if isinstance(item.widget(), DraggableButton) and
                item.widget().button_id != leaving_out]

    def drop_position(self, x, button_id):
        """Where a button dropped at x goes, counting the others (0 first)."""
        others = sorted(self.buttons(button_id), key=lambda widget: widget.x())
        return sum(1 for widget in others if widget.geometry().center().x() < x), others

    def dragEnterEvent(self, event):
        if event.mimeData().hasFormat(BUTTON_MIME):
            event.acceptProposedAction()

    def dragMoveEvent(self, event):
        if not event.mimeData().hasFormat(BUTTON_MIME):
            return
        event.acceptProposedAction()
        button_id = bytes(event.mimeData().data(BUTTON_MIME)).decode()
        position, others = self.drop_position(event.pos().x(), button_id)
        if others:
            x = others[position].x() - 3 if position < len(others) else others[-1].geometry().right() + 2
        else:
            x = 0
        self.marker.setGeometry(max(0, x), 2, 2, max(4, self.height() - 4))
        self.marker.show()
        self.marker.raise_()

    def dragLeaveEvent(self, event):
        self.marker.hide()

    def dropEvent(self, event):
        self.marker.hide()
        if not event.mimeData().hasFormat(BUTTON_MIME):
            return
        button_id = bytes(event.mimeData().data(BUTTON_MIME)).decode()
        position, _ = self.drop_position(event.pos().x(), button_id)
        event.acceptProposedAction()
        QTimer.singleShot(0, lambda: self.store.move_to(button_id, position))  # After the drag has finished


class CommandDialog(QDialog):
    """Add or edit a command button."""

    def __init__(self, parent, button, title="Command Button"):
        super().__init__(parent)
        self.button = button
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_input = QLineEdit(button.name)
        self.name_input.setPlaceholderText("The button's label, such as Interfaces")
        self.text_input = QPlainTextEdit(button.text)
        self.text_input.setFont(monospace_font())
        self.text_input.setPlaceholderText("show ip interface brief\n\nOr a block of configuration, one command per "
                                           "line:\nconfigure terminal\ninterface Gi1/0/5\n description Printer\nend")
        self.enter_check = QCheckBox("Press Enter after the last line")
        self.enter_check.setChecked(button.press_enter)
        self.enter_check.setToolTip("Untick for a command you finish typing yourself, such as \"ping \"")
        form.addRow("Name:", self.name_input)
        form.addRow("Commands:", self.text_input)
        form.addRow("", self.enter_check)
        layout.addLayout(form)
        hint = QLabel("Each line is sent with the session's Enter. Sessions with a line delay (in their settings) send "
                      "the lines one at a time. Click the button to send to the session you're in, or right-click it "
                      "> Send to All.")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(hint)
        self.error_label = QLabel()
        layout.addWidget(self.error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def save(self):
        name = self.name_input.text().strip()
        text = self.text_input.toPlainText().rstrip("\r\n")
        if not name:
            set_hint(self.error_label, "Give the button a name.", "error")
            return
        if not text.strip():
            set_hint(self.error_label, "Enter the command (or commands) to send.", "error")
            return
        self.button = CommandButton(name, text, self.enter_check.isChecked(), self.button.id)
        self.accept()


class CommandBar(QFrame):
    """A row of command buttons. Clicking sends to the session you're in, or to every session Send to All reaches
    while Type in All is on (so a click goes where your typing goes)."""

    def __init__(self, page, tabs):
        super().__init__()
        self.page = page
        self.tabs = tabs
        self.store = page.commands
        self.hints_shown = False
        self.ctrl_held = False  # The sessions' own hints (Log Session, Save Config) show while it is, bar or no bar
        self.setObjectName("commandBar")
        self.setStyleSheet(f"#commandBar {{ border-top: 1px solid {COLORS['border']}; }}")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 2, 4, 2)
        layout.setSpacing(4)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.row = ButtonRow(self.store)
        self.row_layout = QHBoxLayout(self.row)
        self.row_layout.setContentsMargins(0, 0, 0, 0)
        self.row_layout.setSpacing(4)
        self.scroll.setWidget(self.row)
        self.scroll.horizontalScrollBar().valueChanged.connect(self.position_hints)
        layout.addWidget(self.scroll, 1)
        self.status_label = QLabel()
        self.status_label.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(self.status_label)
        add_button = QToolButton()
        add_button.setText("+ Add")
        add_button.setAutoRaise(True)
        add_button.setToolTip("Add a command button")
        add_button.clicked.connect(self.add)
        layout.addWidget(add_button)
        self.store.listeners.append(self.fill)
        self.destroyed.connect(lambda: self.store.listeners.remove(self.fill) if self.fill in self.store.listeners
                               else None)
        self.fill()
        self.setVisible(False)
        QApplication.instance().installEventFilter(self)

    def fit_height(self):
        """Just one row of buttons tall (a scroll area's own size is far taller), with room for the scrollbar only
        when the buttons don't fit across."""
        row_height = max(self.row.sizeHint().height(), QToolButton().sizeHint().height())
        crowded = self.row.sizeHint().width() > self.scroll.viewport().width()
        bar = self.scroll.horizontalScrollBar().sizeHint().height() if crowded else 0
        self.scroll.setFixedHeight(row_height + bar)
        margins = self.layout().contentsMargins()
        self.setFixedHeight(row_height + bar + margins.top() + margins.bottom() + 1)  # 1: the border on top
        self.position_hints()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.fit_height()

    def show_hints(self, visible):
        if visible != self.ctrl_held:
            self.ctrl_held = visible
            for view in self.tabs.findChildren(SessionView):
                view.show_key_hints(visible)
        shown = visible and self.isVisible()
        if shown == self.hints_shown:
            return
        self.hints_shown = shown
        self.position_hints()

    def position_hints(self):
        if not self.hints_shown:
            for button in self.row.buttons():
                button.shortcut_hint.hide()
            return
        viewport = self.scroll.viewport()
        left = viewport.mapTo(self.tabs, QPoint(0, 0)).x()
        right = left + viewport.width()
        top = self.mapTo(self.tabs, QPoint(0, 0)).y()
        for button in self.row.buttons():
            hint = button.shortcut_hint
            center = button.mapTo(self.tabs, button.rect().center()).x()
            shown = self.hints_shown and bool(hint.text()) and left <= center < right
            if shown:
                hint.adjustSize()
                hint.move(center - hint.width() // 2, max(0, top - hint.height() - 2))
                hint.raise_()
            hint.setVisible(shown)

    def eventFilter(self, watched, event):
        if event.type() == QEvent.ApplicationDeactivate or \
                event.type() == QEvent.WindowDeactivate and watched is self.window():
            self.show_hints(False)
        elif event.type() == QEvent.KeyRelease and event.key() == Qt.Key_Control and not event.isAutoRepeat():
            self.show_hints(False)
        elif event.type() == QEvent.KeyPress and isinstance(watched, QWidget) and \
                QWidget.window(watched) is self.window() and \
                (event.key() == Qt.Key_Control or event.modifiers() & Qt.ControlModifier):
            self.show_hints(True)
        elif self.hints_shown and event.type() in (QEvent.Move, QEvent.Resize, QEvent.LayoutRequest) and \
                (watched in (self.tabs, self.row, self.scroll.viewport()) or
                 isinstance(watched, DraggableButton) and watched.parentWidget() is self.row):
            self.position_hints()
        return super().eventFilter(watched, event)

    def showEvent(self, event):
        super().showEvent(event)
        self.show_hints(bool(QApplication.keyboardModifiers() & Qt.ControlModifier))

    def hideEvent(self, event):
        self.hints_shown = False  # Its buttons' hints go; the sessions' stay while Ctrl is held
        self.position_hints()
        super().hideEvent(event)

    def fill(self):
        while self.row_layout.count():
            item = self.row_layout.takeAt(0)
            if item.widget() is not None:
                if isinstance(item.widget(), DraggableButton):
                    item.widget().shortcut_hint.hide()
                item.widget().deleteLater()
        if not self.store.buttons:
            hint = QLabel("No command buttons yet: + Add makes one (a command, or a block of configuration).")
            hint.setStyleSheet(f"color: {COLORS['muted']};")
            self.row_layout.addWidget(hint)
        for number, button in enumerate(self.store.buttons, 1):
            widget = DraggableButton(button.id, number if number <= 9 else None, self.tabs)
            widget.setText(button.name)
            hotkey = f"Ctrl+{number} in a session. Drag to change the order.\n\n" if number <= 9 else \
                "Drag to change the order.\n\n"
            widget.setToolTip(hotkey + button.text + ("" if button.press_enter else "\n(without pressing Enter)"))
            widget.setContextMenuPolicy(Qt.CustomContextMenu)
            widget.clicked.connect(lambda _, button_id=button.id: self.send(button_id))
            widget.customContextMenuRequested.connect(
                lambda position, widget=widget, button_id=button.id: self.show_menu(button_id,
                                                                                    widget.mapToGlobal(position)))
            self.row_layout.addWidget(widget)
        self.row_layout.addStretch()
        self.fit_height()
        QTimer.singleShot(0, self.fit_height)  # Again once the new buttons are showing (Qt shows them just after)

    # ----------------------------------------------------------------- Sending

    def send(self, button_id, to_all=None, target=None):
        """Send a button's commands: to the session you're in (or `target`), or to all (to_all None: all while
        Type in All)."""
        button = self.store.get(button_id)
        if button is None:
            return
        if to_all is None:
            to_all = self.page.mirror_typing
        if to_all:
            targets = self.page.broadcast_targets(self.page.broadcast_scope, self.tabs)
        else:
            current = target or self.tabs.currentWidget()
            targets = [current] if current is not None and hasattr(current, "send_block") else []
        count = sum(bool(view.send_block(button.text, button.press_enter)) for view in targets)
        if not count:
            set_hint(self.status_label, "Not connected." if not to_all else "No connected sessions to send to.",
                     "warning")
        elif to_all:
            set_hint(self.status_label, f"Sent {button.name} to {count} session{'' if count == 1 else 's'}.", "info")
        else:
            self.status_label.clear()
        if not to_all and targets:
            targets[0].focus_target().setFocus()  # Carry on typing in the session

    # ----------------------------------------------------------------- Editing

    def show_menu(self, button_id, global_position):
        button = self.store.get(button_id)
        if button is None:
            return
        menu = QMenu(self)
        menu.addAction("Send to This Session", lambda: self.send(button_id, to_all=False))
        menu.addAction("Send to All", lambda: self.send(button_id, to_all=True))
        menu.addSeparator()
        menu.addAction("Edit...", lambda: self.edit(button))
        menu.addAction("Duplicate", lambda: self.store.put(CommandButton(f"{button.name} (copy)", button.text,
                                                                         button.press_enter)))
        index, count = self.store.index_of(button_id), len(self.store.buttons)
        menu.addAction("Move Left", lambda: self.store.move(button_id, -1)).setEnabled(index > 0)
        menu.addAction("Move Right", lambda: self.store.move(button_id, 1)).setEnabled(index < count - 1)
        positions = menu.addMenu("Move to Position")
        positions.setEnabled(count > 1)
        for position in range(count):
            label = f"{position + 1}" + (f"  (Ctrl+{position + 1})" if position < 9 else "")
            action = positions.addAction(label, lambda position=position: self.store.move_to(button_id, position))
            action.setCheckable(True)
            action.setChecked(position == index)
        menu.addSeparator()
        menu.addAction("Delete", lambda: self.delete(button))
        menu.exec_(global_position)

    def add(self):
        dialog = CommandDialog(self, CommandButton(""), "Add Command Button")
        if dialog.exec_():
            self.store.put(dialog.button)

    def edit(self, button):
        dialog = CommandDialog(self, button, "Edit Command Button")
        if dialog.exec_():
            self.store.put(dialog.button)

    def delete(self, button):
        reply = QMessageBox.question(self, "Delete Button", f"Delete the {button.name} button?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.store.delete(button.id)
