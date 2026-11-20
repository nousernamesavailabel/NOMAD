"""A progress bar for exports: run_export() writes a file on a worker thread while a progress dialog (with Cancel)
shows how far it has got. The dialog appears only if the export takes more than a moment.

The work function gets a nomad.exporting.Progress and runs on the worker thread: it must not touch widgets or the
stores (read what it needs first, on the UI thread, and hand it over). Write with exporting.saving() or
exporting.write_csv() so a cancelled or failed export leaves no half-written file.
"""
import logging

from PyQt5 import sip
from PyQt5.QtCore import QObject, Qt, pyqtSignal
from PyQt5.QtWidgets import QProgressDialog

from ..exporting import ExportCancelled, Progress
from .common import StoppableThread, forget_deleted

log = logging.getLogger(__name__)

SHOW_AFTER_MS = 300  # Quicker exports than this never show the dialog
DIALOG_WIDTH = 440

_running = set()  # Exports under way, kept alive until their thread has finished
_ended_threads = set()  # Finished workers, kept until Qt frees them (deleteLater, never Python's collector)


class ExportWorker(StoppableThread):
    progressed = pyqtSignal(int, int, str)
    succeeded = pyqtSignal(object)
    failed = pyqtSignal(object)

    def __init__(self, work):
        super().__init__()
        self.work = work

    def run(self):
        progress = Progress(self.progressed.emit, self.stop_event)
        try:
            result = self.work(progress)
        except ExportCancelled as error:
            self.failed.emit(error)
        except Exception as error:  # Reported to the export's error handler
            log.exception("Export failed")
            self.failed.emit(error)
        else:
            self.succeeded.emit(result)


class ExportRun(QObject):
    """One export: its worker thread and its progress dialog."""

    def __init__(self, parent, title, work, on_done, on_error, on_cancelled):
        super().__init__()
        self.parent_widget = parent
        self.on_done, self.on_error, self.on_cancelled = on_done, on_error, on_cancelled
        self.ended = False
        self.dialog = QProgressDialog(f"{title}...", "Cancel", 0, 0, parent)
        self.dialog.setWindowTitle(title)
        self.dialog.setWindowModality(Qt.WindowModal)
        self.dialog.setAutoReset(False)  # Each stage fills the bar; the dialog stays until the export ends
        self.dialog.setMinimumWidth(DIALOG_WIDTH)
        self.dialog.setMinimumDuration(SHOW_AFTER_MS)
        self.dialog.canceled.connect(self.cancel)
        self.worker = ExportWorker(work)
        self.worker.progressed.connect(self.show_progress)
        self.worker.succeeded.connect(self.succeeded)
        self.worker.failed.connect(self.failed)
        self.worker.finished.connect(self.thread_finished)

    def start(self):
        _running.add(self)
        self.worker.start()

    def cancel(self):
        if not self.ended:
            self.worker.stop()

    def dialog_alive(self):
        return self.dialog is not None and not sip.isdeleted(self.dialog)

    def show_progress(self, done, total, text):
        if self.ended or not self.dialog_alive() or self.worker.stopping:
            return
        if text != self.dialog.labelText():
            self.dialog.setLabelText(text)
        if total:
            if self.dialog.maximum() != total:
                self.dialog.setRange(0, total)
            self.dialog.setValue(min(done, total))  # Last: a modal dialog's setValue handles pending events
        elif self.dialog.maximum() != 0:
            self.dialog.setRange(0, 0)  # Busy: this part can't say how far it has got

    def end(self):
        self.ended = True
        if self.dialog_alive():
            self.dialog.canceled.disconnect(self.cancel)
            self.dialog.reset()  # Hides it, and stops it showing later if it hadn't yet
            self.dialog.deleteLater()
        self.dialog = None

    def parent_alive(self):
        return self.parent_widget is not None and not sip.isdeleted(self.parent_widget)

    def succeeded(self, result):
        self.end()
        if self.on_done is not None and self.parent_alive():
            self.on_done(result)

    def failed(self, error):
        self.end()
        if not self.parent_alive():
            return
        if isinstance(error, ExportCancelled):
            if self.on_cancelled is not None:
                self.on_cancelled()
        elif self.on_error is not None:
            self.on_error(error)

    def thread_finished(self):
        # Freed by Qt's deleteLater, the safe way for a thread that has just said it finished: dropping the last
        # Python reference instead could free it while it's still winding down
        forget_deleted(_ended_threads)
        _ended_threads.add(self.worker)
        self.worker.deleteLater()
        self.parent_widget = None
        _running.discard(self)


def run_export(parent, title, work, on_done=None, on_error=None, on_cancelled=None):
    """Run work(progress) on a worker thread behind a progress dialog titled title; then on_done(result),
    on_error(exception) or, when Cancel was pressed, on_cancelled(). All three are called on the UI thread."""
    run = ExportRun(parent, title, work, on_done, on_error, on_cancelled)
    run.start()
    return run


def exports_running():
    return bool(_running)


def wait_for_exports(seconds=20):
    """Handle events until every export has ended (for tests: an export finishes after run_export returns)."""
    from PyQt5.QtCore import QCoreApplication, QDeadlineTimer, QThread
    deadline = QDeadlineTimer(int(seconds * 1000))
    while _running and not deadline.hasExpired():
        QCoreApplication.processEvents()
        QThread.msleep(5)
    QCoreApplication.processEvents()
    return not _running


def error_text(error):
    """An export error for a message: an OSError's reason without its number and path."""
    if isinstance(error, OSError) and error.strerror:
        return error.strerror
    return str(error) or type(error).__name__
