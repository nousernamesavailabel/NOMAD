"""Reviewing a config change in Compare: a bar under Compare's own, with every block of the change to give a verdict
(Expected or Unexpected) while it's on the screen, a note on each sensitive block, then Finish Review (Approve or
Raise, with a reason). A change already dealt with shows its record instead: each block's verdict and note as Prev and
Next step through them, and, for a raised change, Close as Explained or Reverted.

The comparison is locked while reviewing (section-aware, noise left out, both sides read-only), so the blocks are the
ones the archive checks the review against (configs/review.py)."""
import datetime
import time

from PyQt5.QtCore import QEvent, QObject, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, \
    QPlainTextEdit, QPushButton, QVBoxLayout, QWidget
from PyQt5.Qsci import QsciScintilla

from ..configs import diff, review
from .common import set_hint
from .theme import COLORS

TICK_MS = 250
VERDICT_TEXT = {review.EXPECTED: "Expected", review.UNEXPECTED: "Unexpected", None: "Not checked yet"}


def when_text(stamp):
    if not stamp:
        return ""
    return datetime.datetime.fromtimestamp(float(stamp)).strftime("%Y-%m-%d %H:%M")


def visible_lines(editor):
    """(first, last) document lines on the editor's screen (annotations and folds counted)."""
    top = editor.SendScintilla(QsciScintilla.SCI_GETFIRSTVISIBLELINE)
    rows = max(editor.SendScintilla(QsciScintilla.SCI_LINESONSCREEN), 1)
    first = editor.SendScintilla(QsciScintilla.SCI_DOCLINEFROMVISIBLE, top)
    last = editor.SendScintilla(QsciScintilla.SCI_DOCLINEFROMVISIBLE, top + rows - 1)
    return first, last


def own_login_names(session_store):
    """The device user names this computer logs in with (saved sessions and credentials), lowercased."""
    names = set()
    if session_store is None:
        return names
    for session in getattr(session_store, "sessions", []) or []:
        if getattr(session, "username", ""):
            names.add(session.username.strip().lower())
    book = getattr(session_store, "credentials", None)
    for credential in (book.sorted() if book is not None and hasattr(book, "sorted") else []):
        if getattr(credential, "username", ""):
            names.add(credential.username.strip().lower())
    return names


class ReviewState:
    """What's been done in one review: each block's verdict, note, push and time on screen (no Qt)."""

    def __init__(self, blocks, pushes=(), now=None):
        self.blocks = list(blocks)
        self.pushes = list(pushes)
        self.verdicts = {}  # index -> verdict
        self.notes = {}  # index -> note
        self.seconds = {block.index: 0.0 for block in self.blocks}
        self.seen = set()
        self.total_seconds = 0.0
        self.started = time.time() if now is None else now
        self.suggested = {}  # index -> push that typed its lines
        for block in self.blocks:
            push = review.explained_by(block, self.pushes)
            if push is not None:
                self.suggested[block.index] = push

    def mark(self, index, verdict, note=None):
        self.verdicts[index] = verdict
        if note is not None:
            self.notes[index] = note.strip()

    def needs_note(self, index):
        block = self.blocks[index]
        return block.sensitive and len(self.notes.get(index, "").strip()) < review.MIN_REASON

    def done(self):
        return len(self.verdicts) == len(self.blocks)

    def checked(self):
        return len(self.verdicts)

    def next_unchecked(self, after):
        count = len(self.blocks)
        for step in range(1, count + 1):
            index = (after + step) % count
            if index not in self.verdicts:
                return index
        return None

    def unexpected(self):
        return sum(1 for verdict in self.verdicts.values() if verdict == review.UNEXPECTED)

    def outcome(self):
        return review.RAISED if self.unexpected() else review.APPROVED

    def tick(self, on_screen, seconds):
        self.total_seconds += seconds
        for index in on_screen:
            self.seen.add(index)
            self.seconds[index] = self.seconds.get(index, 0.0) + seconds

    def verdict_rows(self):
        """The verdicts as the archive takes them."""
        return [{"index": block.index, "fingerprint": block.fingerprint, "verdict": self.verdicts.get(block.index),
                 "note": self.notes.get(block.index, ""), "seconds": round(self.seconds.get(block.index, 0.0), 1),
                 "seen": block.index in self.seen,
                 "push": review.push_label(self.suggested.get(block.index))} for block in self.blocks]


class ReviewBar(QWidget):
    """The bar a review (or a review's record) shows under Compare's own."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 2)
        layout.setSpacing(2)
        self.title = QLabel()
        self.title.setWordWrap(True)
        self.title.setTextFormat(Qt.RichText)
        layout.addWidget(self.title)
        self.block_label = QLabel()
        self.block_label.setWordWrap(True)
        self.block_label.setTextFormat(Qt.RichText)
        layout.addWidget(self.block_label)
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        self.expected_button = QPushButton("Expected (Space)")
        self.expected_button.setToolTip("This block was meant to happen: mark it and go to the next (Space)")
        self.unexpected_button = QPushButton("Unexpected (U)")
        self.unexpected_button.setToolTip("This block shouldn't be there: mark it and go to the next (U)")
        self.note_button = QPushButton("Note... (N)")
        self.note_button.setToolTip("A note on this block (a sensitive block needs one)")
        self.progress = QLabel()
        self.finish_button = QPushButton("Finish Review...")
        self.finish_button.setToolTip("Once every block has a verdict: Approve the change, or Raise it")
        self.explained_button = QPushButton("Close as Explained...")
        self.explained_button.setToolTip("The raised change is all right after all: say why")
        self.reverted_button = QPushButton("Close as Reverted...")
        self.reverted_button.setToolTip("The raised change has been put back on the device (a later backup closes it "
                                        "by itself when it shows the unexpected lines gone)")
        self.undo_button = QPushButton("Commands to Undo It...")
        self.undo_button.setToolTip("The commands that take the device back to the copy before this change")
        for widget in (self.expected_button, self.unexpected_button, self.note_button):
            row.addWidget(widget)
        row.addWidget(self.progress, 1)
        for widget in (self.undo_button, self.explained_button, self.reverted_button, self.finish_button):
            row.addWidget(widget)
        layout.addLayout(row)
        self.hint = QLabel()
        self.hint.setWordWrap(True)
        layout.addWidget(self.hint)
        self.setStyleSheet(f"ReviewBar {{ border-top: 1px solid {COLORS['border']}; }}")

    def set_reviewing(self, reviewing, raised=False):
        for widget in (self.expected_button, self.unexpected_button, self.note_button, self.finish_button):
            widget.setVisible(reviewing)
        for widget in (self.explained_button, self.reverted_button, self.undo_button):
            widget.setVisible(raised and not reviewing)


class ReviewController(QObject):
    """Ties a CompareView to a review of one change (or its record). The page gives it the change's version row,
    its blocks, NOMAD's pushes before it, the review log's rows for it, and who's reviewing.

    finish_requested(payload): {"verdicts", "reason", "seconds", "started", "self_review"}, for the page to send.
    close_requested(outcome, note), undo_requested(): a raised change closed, or its undo commands asked for."""
    finish_requested = pyqtSignal(object)
    close_requested = pyqtSignal(str, str)
    undo_requested = pyqtSignal()

    def __init__(self, view, version, blocks, pushes, records, user, own_names=(), device_name=""):
        super().__init__(view)
        self.view, self.version, self.user = view, dict(version), user
        self.device_name = device_name or version.get("device_id") or "the device"
        self.state = ReviewState(blocks, pushes)
        self.records = list(records)
        self.record = next((row for row in reversed(self.records) if row.get("kind") == review.KIND_REVIEW), None)
        self.record_blocks = {block.get("fingerprint"): block for block in (self.record or {}).get("blocks") or []}
        self.own_names = {name.lower() for name in own_names}
        self.current = 0
        self.reviewing = review.state_of(self.version) in (None, review.SEEN)
        self.bar = ReviewBar(view)
        view.add_review_bar(self.bar)
        view.lock_for_review()
        self.bar.set_reviewing(self.reviewing, self.version.get("review_state") == review.RAISED)
        self.bar.expected_button.clicked.connect(self.mark_expected)
        self.bar.unexpected_button.clicked.connect(self.mark_unexpected)
        self.bar.note_button.clicked.connect(self.edit_note)
        self.bar.finish_button.clicked.connect(self.finish)
        self.bar.explained_button.clicked.connect(self.close_explained)
        self.bar.reverted_button.clicked.connect(self.close_reverted)
        self.bar.undo_button.clicked.connect(self.undo_requested)
        view.position_changed.connect(self.on_position)
        for pane in view.panes():
            pane.editor.installEventFilter(self)
        self.timer = QTimer(self)
        self.timer.setInterval(TICK_MS)
        self.timer.timeout.connect(self.tick)
        if self.reviewing and self.state.blocks:
            self.timer.start()
        self.show_title()
        if self.state.blocks:
            QTimer.singleShot(0, self.go_first)
        else:
            self.bar.block_label.setText("The two copies differ only in noise: there's nothing to review.")

    # ----------------------------------------------------------------- Moving about

    def go_first(self):
        self.go_to(0)

    def go_to(self, index):
        if not self.state.blocks:
            return
        self.current = index % len(self.state.blocks)
        block = self.state.blocks[self.current]
        self.view.current = self.current
        self.view.show_lines(block.a_start, block.b_start)
        self.view.show_position()
        self.show_block()

    def on_position(self, index):
        if 0 <= index < len(self.state.blocks):
            self.current = index
            self.show_block()

    def on_screen(self, block):
        if block.b_end > block.b_start:
            first, last = visible_lines(self.view.right.editor)
            return block.b_start <= last and block.b_end - 1 >= first
        first, last = visible_lines(self.view.left.editor)
        start, end = block.a_start, max(block.a_end - 1, block.a_start)
        return start <= last and end >= first

    def tick(self):
        if not self.view.isVisible() or not self.view.window().isActiveWindow() or self.view.stack.currentIndex():
            return
        shown = [block.index for block in self.state.blocks if self.on_screen(block)]
        self.state.tick(shown, TICK_MS / 1000)
        self.show_progress()

    # ----------------------------------------------------------------- Marking

    def eventFilter(self, watched, event):
        if self.reviewing and event.type() == QEvent.KeyPress and not event.modifiers() & (
                Qt.ControlModifier | Qt.AltModifier | Qt.ShiftModifier):
            if event.key() == Qt.Key_Space:
                self.mark_expected()
                return True
            if event.key() == Qt.Key_U:
                self.mark_unexpected()
                return True
            if event.key() == Qt.Key_N:
                self.edit_note()
                return True
        return False

    def mark_expected(self):
        self.mark(review.EXPECTED)

    def mark_unexpected(self):
        self.mark(review.UNEXPECTED)

    def mark(self, verdict):
        """Give the block Prev/Next is at a verdict, if it's on the screen (else go to it first), then go on to
        the next one without a verdict."""
        if not self.reviewing or not self.state.blocks:
            return
        block = self.state.blocks[self.current]
        if not self.on_screen(block):
            self.go_to(self.current)
            self.hint("That block wasn't on the screen: here it is. Mark it once you've read it.", "warning")
            return
        note = None
        if self.state.needs_note(block.index):
            note = self.ask_note(block, required=True)
            if note is None:
                return
        elif verdict == review.UNEXPECTED and not self.state.notes.get(block.index):
            note = self.ask_note(block, required=False, prompt="What's wrong with it? (optional, but it helps whoever "
                                                               "closes it)")
            if note is None:
                return
        self.state.mark(block.index, verdict, note)
        self.state.seen.add(block.index)
        self.show_progress()
        following = self.state.next_unchecked(self.current)
        if following is None:
            self.show_block()
            self.show_progress()
            self.hint("Every block has a verdict: Finish Review.", "success")
            self.bar.finish_button.setFocus()
            return
        self.hint("", "info")
        self.go_to(following)

    def edit_note(self):
        if not self.reviewing or not self.state.blocks:
            return
        block = self.state.blocks[self.current]
        note = self.ask_note(block, required=block.sensitive)
        if note is not None:
            self.state.notes[block.index] = note.strip()
            self.show_block()

    def ask_note(self, block, required, prompt=""):
        dialog = NoteDialog(self.view, block, self.state.notes.get(block.index, ""), required, prompt)
        if dialog.exec_() != QDialog.Accepted:
            return None
        return dialog.text()

    # ----------------------------------------------------------------- Finishing and closing

    def self_review(self):
        """Whether the reviewer looks like the one who made the change: their device login changed it, or NOMAD's
        push by them typed it."""
        changed_by = (self.version.get("changed_by") or "").strip().lower()
        if changed_by and changed_by in self.own_names:
            return True
        return any(push.get("user") == self.user for push in self.state.pushes)

    def finish(self):
        if not self.state.done():
            missing = self.state.next_unchecked(self.current - 1 if self.current else len(self.state.blocks) - 1)
            if missing is not None:
                self.go_to(missing)
            self.hint(f"{len(self.state.blocks) - self.state.checked()} block(s) still need a verdict.", "warning")
            return
        missing_note = next((block for block in self.state.blocks if self.state.needs_note(block.index)), None)
        if missing_note is not None:
            self.go_to(missing_note.index)
            self.hint("This block touches a sensitive line: it needs a note (N).", "warning")
            return
        dialog = FinishDialog(self.view, self.state, self.self_review(), self.device_name)
        if dialog.exec_() != QDialog.Accepted:
            return
        self.finish_requested.emit({"verdicts": self.state.verdict_rows(), "reason": dialog.reason(),
                                    "seconds": round(self.state.total_seconds, 1), "started": self.state.started,
                                    "self_review": self.self_review()})

    def finished(self, version, records):
        """The archive took the review: show its record."""
        self.version, self.records = dict(version), list(records)
        self.record = next((row for row in reversed(self.records) if row.get("kind") == review.KIND_REVIEW), None)
        self.record_blocks = {block.get("fingerprint"): block for block in (self.record or {}).get("blocks") or []}
        self.reviewing = False
        self.timer.stop()
        self.bar.set_reviewing(False, self.version.get("review_state") == review.RAISED)
        self.show_title()
        self.show_block()
        self.hint("", "info")

    def close_explained(self):
        self.ask_close(review.EXPLAINED)

    def close_reverted(self):
        self.ask_close(review.REVERTED)

    def ask_close(self, outcome):
        dialog = CloseDialog(self.view, outcome, self.record)
        if dialog.exec_() == QDialog.Accepted:
            self.close_requested.emit(outcome, dialog.note())

    def hint(self, text, kind="info"):
        set_hint(self.bar.hint, text, kind)

    # ----------------------------------------------------------------- What the bar says

    def show_title(self):
        state = review.state_of(self.version)
        if self.reviewing:
            text = (f"<b>Reviewing</b> the change to {escape(self.device_name)}: give every block a verdict while "
                    f"it's on the screen. <b>Space</b> Expected, <b>U</b> Unexpected, <b>N</b> a note, "
                    f"<b>F7</b> / <b>Shift+F7</b> to move.")
            if state == review.SEEN:
                text += f" (Opened by {escape(self.version.get('reviewed_by') or 'someone')} before reviews were kept.)"
        else:
            text = record_text(self.version, self.records)
        self.bar.title.setText(text)
        self.show_progress()

    def show_progress(self):
        if not self.reviewing:
            self.bar.progress.setText("")
            return
        total = len(self.state.blocks)
        self.bar.progress.setText(f"{self.state.checked()} of {total} checked · {self.state.unexpected()} unexpected · "
                                  f"{review.time_text(self.state.total_seconds)}")
        self.bar.finish_button.setEnabled(bool(total))

    def show_block(self):
        if not self.state.blocks:
            return
        block = self.state.blocks[self.current]
        parts = [f"<b>Block {block.index + 1} of {len(self.state.blocks)}</b> · {escape(block.where)} · "
                 f"{block_size(block)}"]
        if block.sensitive:
            parts.append(f"<span style='color:{COLORS.get('error', '#e05d5d')}'><b>Sensitive</b>: needs a note</span>")
        push = self.state.suggested.get(block.index)
        if push is not None:
            parts.append(f"Sent by {escape(review.push_label(push))} at {when_text(push.get('at'))}: looks expected")
        if self.reviewing:
            verdict = self.state.verdicts.get(block.index)
            parts.append(f"Your verdict: <b>{VERDICT_TEXT[verdict]}</b>")
            note = self.state.notes.get(block.index)
        else:
            kept = self.record_blocks.get(block.fingerprint)
            if kept:
                parts.append(f"Verdict: <b>{VERDICT_TEXT.get(kept.get('verdict'), 'none')}</b>")
                if kept.get("push"):
                    parts.append(f"(sent by {escape(kept['push'])})")
            elif self.record:
                parts.append("Not in the review (the copies were compared differently)")
            note = (kept or {}).get("note")
        if note:
            parts.append(f"Note: <i>{escape(note)}</i>")
        self.bar.block_label.setText(" · ".join(parts))

    def stop(self):
        self.timer.stop()


def block_size(block):
    pieces = []
    if block.removed:
        pieces.append(f"−{len(block.removed)}")
    if block.added:
        pieces.append(f"+{len(block.added)}")
    return {diff.ADDED: "added", diff.REMOVED: "removed", diff.CHANGED: "changed"}.get(block.kind, block.kind) + \
        (f" ({' '.join(pieces)})" if pieces else "")


def escape(text):
    return str(text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def record_text(version, records):
    """What happened to a change, for the bar: its state, who, when, why, and the flags."""
    state = review.state_of(version)
    if state is None:
        return "<b>To review</b>: nobody has reviewed this change yet."
    lines = []
    for row in records:
        if row.get("kind") == review.KIND_SEEN:
            continue
        flags = []
        if row.get("self_review"):
            flags.append("self-reviewed" if row.get("kind") == review.KIND_REVIEW else "closed by who raised it")
        if row.get("quick"):
            flags.append(f"quick: {review.time_text(row.get('seconds'))} for {row.get('total')} blocks")
        text = (f"<b>{review.STATE_NAMES.get(row.get('outcome'), row.get('outcome'))}</b> by "
                f"{escape(row.get('user'))} {when_text(row.get('at'))}")
        if row.get("kind") == review.KIND_REVIEW:
            text += f" ({row.get('total')} blocks, {row.get('unexpected') or 0} unexpected, " \
                    f"{review.time_text(row.get('seconds'))})"
        if row.get("reason"):
            text += f": <i>{escape(row['reason'])}</i>"
        if flags:
            text += f" <span style='color:{COLORS.get('warning', '#d9a53a')}'>[{', '.join(flags)}]</span>"
        lines.append(text)
    if not lines:
        if state == review.SEEN:
            return (f"<b>Seen</b> by {escape(version.get('reviewed_by'))} {when_text(version.get('reviewed_at'))}, "
                    f"before reviews were kept.")
        return f"<b>{review.STATE_NAMES.get(state, state)}</b> by {escape(version.get('reviewed_by'))}"
    return "<br>".join(lines)


# ----------------------------------------------------------------- Dialogs

class NoteDialog(QDialog):
    def __init__(self, parent, block, note, required, prompt=""):
        super().__init__(parent)
        self.setWindowTitle(f"Note on Block {block.index + 1}")
        self.required = required
        layout = QVBoxLayout(self)
        label = QLabel(prompt or ("This block touches a sensitive line: say what it is and why it's all right."
                                  if required else "A note on this block:"))
        label.setWordWrap(True)
        layout.addWidget(label)
        where = QLabel(f"{block.where} · {block_size(block)}")
        where.setStyleSheet(f"color: {COLORS['muted']};" if "muted" in COLORS else "")
        layout.addWidget(where)
        self.edit = QPlainTextEdit(note)
        self.edit.setTabChangesFocus(True)
        self.edit.setMinimumSize(420, 90)
        layout.addWidget(self.edit)
        self.message = QLabel()
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def text(self):
        return " ".join(self.edit.toPlainText().split())

    def check(self):
        if self.required and len(self.text()) < review.MIN_REASON:
            set_hint(self.message, "This block needs a note.", "warning")
            return
        self.accept()


class FinishDialog(QDialog):
    """Approve (every block expected) or Raise (one wasn't), with the reason."""

    def __init__(self, parent, state, self_review, device_name):
        super().__init__(parent)
        raised = state.outcome() == review.RAISED
        self.setWindowTitle("Raise the Change" if raised else "Approve the Change")
        layout = QVBoxLayout(self)
        total = len(state.blocks)
        summary = QLabel(f"{device_name}: {total} block{'s' if total != 1 else ''}, "
                         f"{total - state.unexpected()} expected, {state.unexpected()} unexpected, "
                         f"{review.time_text(state.total_seconds)} on the review.")
        summary.setWordWrap(True)
        layout.addWidget(summary)
        if raised:
            what = QLabel("This change will be <b>Raised</b>: it stays flagged (on the map too) until someone closes "
                          "it as Explained or Reverted.")
        else:
            what = QLabel("This change will be <b>Approved</b>.")
        what.setWordWrap(True)
        layout.addWidget(what)
        if self_review:
            note = QLabel("It will be labeled <b>self-reviewed</b>: your login or one of your pushes made it.")
            note.setWordWrap(True)
            layout.addWidget(note)
        form = QFormLayout()
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("What's wrong with it" if raised else "A ticket number, or why it was made")
        form.addRow("What's wrong:" if raised else "Why it was made:", self.reason_input)
        layout.addLayout(form)
        self.message = QLabel()
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.ok_button = buttons.addButton("Raise" if raised else "Approve", QDialogButtonBox.AcceptRole)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setMinimumWidth(480)

    def reason(self):
        return self.reason_input.text().strip()

    def check(self):
        if len(self.reason()) < review.MIN_REASON:
            set_hint(self.message, "Give a reason.", "warning")
            return
        self.accept()


class CloseDialog(QDialog):
    def __init__(self, parent, outcome, record=None):
        super().__init__(parent)
        explained = outcome == review.EXPLAINED
        self.setWindowTitle("Close as Explained" if explained else "Close as Reverted")
        layout = QVBoxLayout(self)
        if record:
            raised = QLabel(f"Raised by {escape(record.get('user'))} {when_text(record.get('at'))}: "
                            f"<i>{escape(record.get('reason'))}</i>")
            raised.setWordWrap(True)
            layout.addWidget(raised)
        label = QLabel("Why the change is all right after all:" if explained else
                       "How it was put back (a later backup closes it by itself once it shows the unexpected lines "
                       "gone):")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.note_input = QLineEdit()
        layout.addWidget(self.note_input)
        self.message = QLabel()
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setMinimumWidth(460)

    def note(self):
        return self.note_input.text().strip()

    def check(self):
        if len(self.note()) < review.MIN_REASON:
            set_hint(self.message, "Say why.", "warning")
            return
        self.accept()


class AcknowledgeDialog(QDialog):
    """Acknowledge changes without a review (only when the archive's settings allow it)."""

    def __init__(self, parent, count):
        super().__init__(parent)
        self.setWindowTitle("Acknowledge Without Review")
        layout = QVBoxLayout(self)
        label = QLabel(f"Clear {count} change{'s' if count != 1 else ''} without reviewing "
                       f"{'them' if count != 1 else 'it'}? They're kept as <b>Acknowledged</b>, never as reviewed, "
                       f"with your name and reason in the review log.")
        label.setWordWrap(True)
        layout.addWidget(label)
        form = QFormLayout()
        self.reason_input = QLineEdit()
        self.reason_input.setPlaceholderText("A maintenance window or ticket, say")
        form.addRow("Why:", self.reason_input)
        layout.addLayout(form)
        self.message = QLabel()
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        buttons.addButton("Acknowledge", QDialogButtonBox.AcceptRole)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setMinimumWidth(460)

    def reason(self):
        return self.reason_input.text().strip()

    def check(self):
        if len(self.reason()) < review.MIN_REASON:
            set_hint(self.message, "Give a reason.", "warning")
            return
        self.accept()


class ReviewSettingsDialog(QDialog):
    """The archive's review settings (the tribe's, on a tribe): Acknowledge Without Review allowed, and the
    sensitive lines."""

    def __init__(self, parent, settings, is_tribe=False):
        super().__init__(parent)
        self.setWindowTitle("Review Settings")
        layout = QVBoxLayout(self)
        whose = QLabel("These settings are the tribe's: they apply on every computer." if is_tribe else
                       "These settings are for the archive on this computer.")
        whose.setWordWrap(True)
        layout.addWidget(whose)
        self.allow_check = QCheckBox("Allow Acknowledge Without Review")
        self.allow_check.setToolTip("Lets anyone clear changes without reviewing them (with a reason). They're kept as "
                                    "Acknowledged, never as reviewed.")
        self.allow_check.setChecked(bool(settings.get("allow_acknowledge")))
        layout.addWidget(self.allow_check)
        label = QLabel("Sensitive lines: a block with a line (or in a mode) matching one of these regular expressions "
                       "needs a note when it's reviewed. One per line, case doesn't matter.")
        label.setWordWrap(True)
        layout.addWidget(label)
        self.patterns = QPlainTextEdit("\n".join(settings.get("sensitive_patterns") or review.SENSITIVE_PATTERNS))
        self.patterns.setMinimumSize(480, 220)
        layout.addWidget(self.patterns)
        row = QHBoxLayout()
        defaults = QPushButton("Defaults")
        defaults.setToolTip("Put back NOMAD's own list")
        defaults.clicked.connect(self.use_defaults)
        row.addWidget(defaults)
        row.addStretch(1)
        layout.addLayout(row)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def use_defaults(self):
        self.patterns.setPlainText("\n".join(review.SENSITIVE_PATTERNS))

    def values(self):
        patterns = [line.strip() for line in self.patterns.toPlainText().splitlines() if line.strip()]
        return {"allow_acknowledge": self.allow_check.isChecked(), "sensitive_patterns": patterns}

    def check(self):
        bad = review.bad_patterns(self.values()["sensitive_patterns"])
        if bad:
            set_hint(self.message, f"{bad[0][0]} isn't a regular expression: {bad[0][1]}", "error")
            return
        self.accept()


# ----------------------------------------------------------------- The review log, exported

LOG_COLUMNS = ["When", "Device", "Configuration", "Change pulled", "Change", "Changed by", "What", "Outcome", "Who",
               "Reason", "Blocks", "Unexpected", "Blocks seen", "Time (s)", "Self-reviewed", "Quick", "Block notes"]


def log_rows(rows):
    result = []
    for row in rows:
        notes = "; ".join(f"{block.get('index', 0) + 1} {block.get('path') or '(top level)'}: "
                          f"{VERDICT_TEXT.get(block.get('verdict'), '')}" + (f" ({block['note']})" if block.get("note")
                                                                             else "")
                          for block in row.get("blocks") or [] if block.get("note") or block.get("verdict") ==
                          review.UNEXPECTED)
        result.append([when_text(row.get("at")), row.get("device_name") or row.get("device_id") or "",
                       row.get("which") or "", when_text(row.get("pulled_at")),
                       f"+{row.get('added') or 0} -{row.get('removed') or 0}", row.get("changed_by") or "",
                       {review.KIND_REVIEW: "Review", review.KIND_CLOSE: "Closed", review.KIND_ACKNOWLEDGE:
                        "Acknowledged", review.KIND_SEEN: "Opened (older NOMAD)"}.get(row.get("kind"), row.get("kind")),
                       review.STATE_NAMES.get(row.get("outcome"), row.get("outcome") or ""), row.get("user") or "",
                       row.get("reason") or "", row.get("total") if row.get("total") is not None else "",
                       row.get("unexpected") if row.get("unexpected") is not None else "",
                       row.get("seen") if row.get("seen") is not None else "",
                       row.get("seconds") if row.get("seconds") is not None else "",
                       "yes" if row.get("self_review") else "", "yes" if row.get("quick") else "", notes])
    return result


def write_log(path, rows, progress=None):
    """The review log as a workbook (or CSV, for a .csv path)."""
    from ..exporting import NO_PROGRESS, saving, write_csv
    progress = progress or NO_PROGRESS
    table = log_rows(rows)
    if str(path).lower().endswith(".csv"):
        write_csv(path, table, LOG_COLUMNS, progress)
        return
    from openpyxl import Workbook
    from openpyxl.styles import Font
    book = Workbook()
    sheet = book.active
    sheet.title = "Review log"
    sheet.append(LOG_COLUMNS)
    for cell in sheet[1]:
        cell.font = Font(bold=True)
    progress.stage("Writing the review log", len(table))
    for row in table:
        sheet.append(row)
        progress.step()
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for column in sheet.columns:
        width = max(len(str(cell.value or "")) for cell in column)
        sheet.column_dimensions[column[0].column_letter].width = min(max(10, width + 2), 60)
    progress.stage("Saving the workbook...")
    with saving(path) as temporary:
        book.save(temporary)
