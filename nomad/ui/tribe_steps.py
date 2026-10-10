"""StepsDialog: a window listing the steps of something that takes a while (connecting to the tribe, disconnecting
from it), each marked as it happens so it's plain that something is going on: waiting, under way (a spinner, and the
seconds once it's slow), done, a warning, failed or skipped, with a note under it. A bar moves while a step is under
way."""
import time

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QDialog, QGridLayout, QHBoxLayout, QLabel, QProgressBar, QPushButton, QVBoxLayout

from .common import set_hint
from .theme import COLORS

WAITING, WORKING, DONE, WARNING, FAILED, SKIPPED = "waiting", "working", "done", "warning", "failed", "skipped"
MARKS = {WAITING: ("○", "muted"), DONE: ("✓", "success"), WARNING: ("!", "warning"), FAILED: ("✗", "error"),
         SKIPPED: ("–", "muted")}
NOTE_COLORS = {WARNING: "warning", FAILED: "error"}
SPINNER = "◐◓◑◒"
TICK_MS = 150
SECONDS_SHOWN_AFTER = 2  # A step that takes longer shows how long it's been going


class StepsDialog(QDialog):
    def __init__(self, parent, title, steps, headline):
        """steps: {step: what it does}, in order."""
        super().__init__(parent)
        self.steps = steps
        self.states, self.started = {}, {}
        self.followed = []  # (signal, slot): another object's signals, disconnected on closing
        self.frame = 0
        self.setWindowTitle(title)
        self.setMinimumWidth(540)
        layout = QVBoxLayout(self)
        self.headline = QLabel(headline)
        font = self.headline.font()
        font.setBold(True)
        font.setPointSizeF(font.pointSizeF() * 1.15)
        self.headline.setFont(font)
        layout.addWidget(self.headline)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        layout.addWidget(self.bar)

        grid = QGridLayout()
        grid.setColumnStretch(1, 1)
        grid.setHorizontalSpacing(8)
        grid.setVerticalSpacing(2)
        self.marks, self.titles, self.notes, self.clocks = {}, {}, {}, {}
        for row, (step, text) in enumerate(steps.items()):
            mark = QLabel()
            mark.setFixedWidth(20)
            mark.setAlignment(Qt.AlignCenter)
            name = QLabel(text)
            clock = QLabel()
            clock.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
            note = QLabel()
            note.setWordWrap(True)
            note.setTextInteractionFlags(Qt.TextSelectableByMouse)  # Errors can be copied
            note.hide()
            grid.addWidget(mark, row * 2, 0)
            grid.addWidget(name, row * 2, 1)
            grid.addWidget(clock, row * 2, 2)
            grid.addWidget(note, row * 2 + 1, 1, 1, 2)
            self.marks[step], self.titles[step], self.notes[step], self.clocks[step] = mark, name, note, clock
        layout.addSpacing(6)
        layout.addLayout(grid)
        layout.addSpacing(6)

        self.message = QLabel()
        self.message.setWordWrap(True)
        self.message.hide()
        layout.addWidget(self.message)
        self.buttons = QHBoxLayout()
        self.buttons.addStretch()
        self.close_button = QPushButton("Cancel")
        self.buttons.addWidget(self.close_button)
        layout.addLayout(self.buttons)
        self.close_button.clicked.connect(self.reject)

        self.timer = QTimer(self)
        self.timer.setInterval(TICK_MS)
        self.timer.timeout.connect(self.tick)
        for step in steps:
            self.set_state(step, WAITING)

    def add_button(self, button):
        """A button beside Cancel/Close (hidden until it's wanted)."""
        button.hide()
        self.buttons.insertWidget(self.buttons.count() - 1, button)
        return button

    def set_state(self, step, state, note=None):
        if state == WORKING and self.states.get(step) != WORKING:
            self.started[step] = time.monotonic()
            self.timer.start()
        elif state != WORKING and self.states.get(step) == WORKING:
            took = time.monotonic() - self.started[step]
            self.clocks[step].setText(f"{took:.0f} s" if took >= SECONDS_SHOWN_AFTER else "")
        self.states[step] = state
        if state == WORKING:
            self.show_mark(step, SPINNER[self.frame % len(SPINNER)], "accent")
        else:
            self.show_mark(step, *MARKS[state])
        self.titles[step].setStyleSheet(f"color: {COLORS['muted']};" if state in (WAITING, SKIPPED) else
                                        "font-weight: bold;" if state == WORKING else "")
        if note is not None:
            self.notes[step].setText(note)
            self.notes[step].setStyleSheet(f"color: {COLORS[NOTE_COLORS.get(state, 'muted')]};")
            self.notes[step].setVisible(bool(note))
        if not self.working():
            self.timer.stop()
        self.update_bar()

    def show_mark(self, step, text, color):
        self.marks[step].setText(text)
        self.marks[step].setStyleSheet(f"color: {COLORS[color]}; font-family: 'Segoe UI Symbol'; font-weight: bold;")

    def working(self):
        return [step for step in self.steps if self.states.get(step) == WORKING]

    def update_bar(self):
        """Moving while a step is under way; otherwise how far it got."""
        if self.working():
            self.bar.setRange(0, 0)
        else:
            self.bar.setRange(0, len(self.steps))
            self.bar.setValue(sum(state in (DONE, WARNING, SKIPPED) for state in self.states.values()))

    def tick(self):
        """Turn the spinners, and count the seconds of a step that takes a while."""
        self.frame += 1
        now = time.monotonic()
        for step in self.working():
            self.show_mark(step, SPINNER[self.frame % len(SPINNER)], "accent")
            elapsed = now - self.started[step]
            self.clocks[step].setText(f"{elapsed:.0f} s" if elapsed >= SECONDS_SHOWN_AFTER else "")

    def say(self, text, kind):
        set_hint(self.message, text, kind)
        self.message.show()

    def skip_the_rest(self):
        for step in self.steps:
            if self.states[step] in (WAITING, WORKING):
                self.set_state(step, SKIPPED)

    def finished_with(self, close_text="Close"):
        """Nothing more to do: the one button left closes it."""
        self.close_button.setText(close_text)
        self.close_button.setToolTip("")
        self.close_button.setDefault(True)

    def follow(self, signal, slot):
        """Connect another object's signal (a page's), until this is closed."""
        signal.connect(slot)
        self.followed.append((signal, slot))

    def done(self, result):
        """Closed: stop following the pages (what they're doing carries on)."""
        self.timer.stop()
        for signal, slot in self.followed:
            try:
                signal.disconnect(slot)
            except TypeError:  # Already disconnected
                pass
        self.followed = []
        super().done(result)
