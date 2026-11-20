"""Writing exports with a progress bar: what the writing side needs, without Qt (ui/export_progress.py shows it).

An export reads what it needs on the UI thread (the stores' SQLite connections and the tables belong to it), then
writes the file on a worker thread, telling a Progress how far it has got. Cancel stops it at the next step, and a
cancelled or failed export leaves no half-written file: the file is written beside the target and put in place only
once it's complete.
"""
import contextlib
import csv
import os
import threading
import time

from .system import replace_file

REPORT_EVERY = 0.05  # Seconds between progress reports (one per row would swamp the UI thread)


class ExportCancelled(Exception):
    """The export was cancelled: whatever it was writing has been removed."""


class Progress:
    """How far an export has got, told to report(done, total, text); total 0 means "can't tell" (a busy bar)."""

    def __init__(self, report=None, stop_event=None):
        self.report = report
        self.stop_event = stop_event or threading.Event()
        self.text, self.total, self.done = "", 0, 0
        self.last_report = 0.0

    def stage(self, text, total=0):
        """A new part of the export: text says what, total how many steps it has (0: unmeasured)."""
        self.check()
        self.text, self.total, self.done = text, max(0, int(total)), 0
        self._send()

    def step(self, count=1):
        self.done = min(self.done + count, self.total) if self.total else self.done + count
        if self.stop_event.is_set():
            raise ExportCancelled()
        now = time.monotonic()
        if now - self.last_report >= REPORT_EVERY or (self.total and self.done >= self.total):
            self._send(now)

    def check(self):
        if self.stop_event.is_set():
            raise ExportCancelled()

    def _send(self, now=None):
        self.last_report = now if now is not None else time.monotonic()
        if self.report is not None:
            self.report(self.done, self.total, self.text)


NO_PROGRESS = Progress()  # For exports made without a progress bar (tests, scripts)


@contextlib.contextmanager
def saving(path):
    """Yields a temporary path beside path to write to; put in place when the block finishes, removed if it fails
    or is cancelled (so a stopped export never leaves half a file, nor spoils one that was already there)."""
    path = os.fspath(path)
    temporary = f"{path}.part"
    try:
        yield temporary
        replace_file(temporary, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.remove(temporary)
        raise


def write_csv(path, rows, header=None, progress=NO_PROGRESS, encoding="utf-8-sig", text="Writing rows"):
    """Write rows (a list) to a CSV file, header first; returns how many rows were written (not counting it)."""
    progress.stage(text, len(rows))
    with saving(path) as temporary, open(temporary, "w", newline="", encoding=encoding) as file:
        writer = csv.writer(file)
        if header is not None:
            writer.writerow(header)
        for row in rows:
            writer.writerow(row)
            progress.step()
    return len(rows)
