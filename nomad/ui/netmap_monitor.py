"""Monitoring the Network Map's devices: ping them every so often on a background thread, and log when one goes down
or comes back. Runs while NOMAD is open, whichever page is showing."""
import datetime
import time

from PyQt5.QtCore import QObject, QThread, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, \
    QPushButton, QVBoxLayout, QWidget

from ..netmap import monitor
from ..netmap.monitor import DOWN, UNKNOWN, UP
from .theme import monospace_font

LOG_LINES = 20000


class PollThread(QThread):
    finished_poll = pyqtSignal(object)  # {key: rtt or None}

    def __init__(self, targets, pinger, parent=None):
        super().__init__(parent)
        self.targets, self.pinger = targets, pinger

    def run(self):
        self.finished_poll.emit(monitor.poll(self.targets, self.pinger))


class NetworkMonitor(QObject):
    """Owns the polling timer, each device's status and the Monitor tab."""
    statuses_changed = pyqtSignal()  # After every poll, to redraw the dots and response times
    polled = pyqtSignal()  # After each poll's results are in (the map then reads its links' counters)
    history_added = pyqtSignal(list)  # [history entries] for the map to keep

    def __init__(self, parent=None, pinger=monitor.ping):
        super().__init__(parent)
        self.pinger = pinger
        self.tracker = monitor.StatusTracker()
        self.targets, self.labels = {}, {}  # key -> address, key -> label
        self.interval = monitor.DEFAULT_INTERVAL
        self.thread = None
        self.last_poll = None
        self.lines = []
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_now)

        self.tab = QWidget()
        layout = QVBoxLayout(self.tab)
        top = QHBoxLayout()
        self.summary_label = QLabel()
        top.addWidget(self.summary_label, 1)
        self.copy_button = QPushButton("Copy Log")
        self.save_button = QPushButton("Save Log...")
        top.addWidget(self.copy_button)
        top.addWidget(self.save_button)
        layout.addLayout(top)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumBlockCount(LOG_LINES)
        self.log_view.setFont(monospace_font())
        self.log_view.setLineWrapMode(QPlainTextEdit.NoWrap)
        layout.addWidget(self.log_view, 1)
        self.copy_button.clicked.connect(lambda: QApplication.clipboard().setText("\n".join(self.lines)))
        self.save_button.clicked.connect(self.save_log)
        self.update_summary()

    # ----------------------------------------------------------------- What to watch

    @property
    def running(self):
        return self.timer.isActive()

    def set_map(self, network_map):
        """Watch the devices on this map (those with an address to ping), and show its history in the log."""
        self.targets = {key: device.mgmt_ip for key, device in network_map.devices.items() if device.mgmt_ip}
        self.labels = {key: device.label for key, device in network_map.devices.items()}
        self.tracker.forget_others(set(self.targets))
        self.update_summary()

    def load_history(self, entries):
        """Show a map's saved status changes in the log (from when it was last watched)."""
        self.lines = []
        self.log_view.clear()
        for when, _key, _label, _status, text in entries[-LOG_LINES:]:
            try:
                stamp = datetime.datetime.fromisoformat(when).strftime("%Y-%m-%d %H:%M:%S")
            except ValueError:
                stamp = when
            self.add_line(f"{stamp}  {text}")

    def status(self, key):
        """The DeviceStatus of a watched device, or None if it isn't being watched."""
        if key not in self.targets or not (self.running or key in self.tracker.devices):
            return None
        return self.tracker.get(key)

    def status_text(self, key):
        """For the Devices table's Status column (plain, so it filters well)."""
        state = self.status(key)
        return monitor.STATUS_NAMES[state.status] if state is not None else ""

    # ----------------------------------------------------------------- Running

    def start(self, interval=None):
        self.interval = interval or self.interval
        self.timer.start(self.interval * 1000)
        self.log(f"Monitoring {len(self.targets)} device{'' if len(self.targets) == 1 else 's'} every "
                 f"{monitor.duration_text(self.interval)}")
        self.poll_now()
        self.update_summary()

    def stop(self):
        if self.running:
            self.timer.stop()
            self.log("Stopped monitoring")
        self.tracker.devices = {}  # Stale once nobody's checking
        self.update_summary()
        self.statuses_changed.emit()

    def set_interval(self, seconds):
        self.interval = seconds
        if self.running:
            self.timer.start(seconds * 1000)
            self.log(f"Now checking every {monitor.duration_text(seconds)}")
            self.update_summary()

    def poll_now(self):
        if self.thread is not None or not self.targets:
            return  # The last poll is still going (a big map with many devices down), or nothing to watch
        self.thread = PollThread(dict(self.targets), self.pinger, self)
        self.thread.finished_poll.connect(self.on_results)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()

    def on_thread_finished(self):
        self.thread = None

    def on_results(self, results):
        if not self.running:
            return  # Stopped while it was polling
        results = {key: rtt for key, rtt in results.items() if key in self.targets}
        changes = self.tracker.update(results)
        self.last_poll = time.time()
        history = []
        for change in changes:
            if change.status == UP and change.lasted is None:
                continue  # Answered the first poll: nothing's happened to it
            label = self.labels.get(change.key, change.key)
            text = monitor.change_text(change, label, self.targets.get(change.key, ""))
            self.log(text, change.when)
            history.append(monitor.history_entry(change, label, text))
        if history:
            self.history_added.emit(history)
        self.update_summary()
        self.statuses_changed.emit()
        self.polled.emit()

    def shutdown(self):
        self.timer.stop()
        if self.thread is not None:
            self.thread.wait(monitor.PING_TIMEOUT_MS * monitor.PING_TRIES * 4)

    # ----------------------------------------------------------------- Showing it

    def counts(self):
        counts = {UP: 0, DOWN: 0, UNKNOWN: 0}
        for key in self.targets:
            counts[self.tracker.get(key).status] += 1
        return counts

    def summary(self):
        """"12 up · 2 down" for beside the Monitor switch, or "" when not monitoring."""
        if not self.running:
            return ""
        counts = self.counts()
        parts = [f"{counts[UP]} up"]
        if counts[DOWN]:
            parts.append(f"{counts[DOWN]} down")
        if counts[UNKNOWN]:
            parts.append(f"{counts[UNKNOWN]} checking")
        return " · ".join(parts)

    def update_summary(self):
        if not self.running:
            text = ("Not monitoring. Tick Monitor to ping the devices on the map every so often and log when one "
                    "goes down or comes back.")
        else:
            checked = (f", last checked {datetime.datetime.fromtimestamp(self.last_poll):%H:%M:%S}"
                       if self.last_poll else "")
            text = (f"Monitoring {len(self.targets)} devices every {monitor.duration_text(self.interval)}: "
                    f"{self.summary()}{checked}. A device is down after missing {monitor.FAILS_FOR_DOWN} checks "
                    "in a row.")
        self.summary_label.setText(text)

    def log(self, text, when=None):
        stamp = datetime.datetime.fromtimestamp(when or time.time()).strftime("%Y-%m-%d %H:%M:%S")
        self.add_line(f"{stamp}  {text}")

    def add_line(self, line):
        self.lines.append(line)
        self.lines = self.lines[-LOG_LINES:]
        self.log_view.appendPlainText(line)

    def save_log(self):
        path, _ = QFileDialog.getSaveFileName(self.tab, "Save Monitor Log", "Network monitor.txt",
                                              "Text files (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write("\n".join(self.lines) + "\n")
        except OSError as error:
            QMessageBox.critical(self.tab, "Save Monitor Log", f"Couldn't save the log:\n\n{error}")
