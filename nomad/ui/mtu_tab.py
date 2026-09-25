"""MTU tab: find the largest MTU that reaches a host without fragmenting, and apply it."""
import logging

from PyQt5.QtCore import pyqtSignal
from PyQt5.QtGui import QFont, QIntValidator
from PyQt5.QtWidgets import QFormLayout, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QProgressBar, \
    QPushButton, QVBoxLayout, QWidget

from ..icmp import IcmpClient, find_path_mtu, make_mtu_probe, path_mtu_steps, resolve_host
from ..ipconfig import MAX_MTU, MIN_MTU
from .common import StoppableThread, set_hint
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"host": "8.8.8.8", "minimum": "1200", "maximum": "1500", "timeout": "2000", "retries": "2"}


class MtuTestThread(StoppableThread):
    line = pyqtSignal(str)
    progress = pyqtSignal(int)
    finished_test = pyqtSignal(object, str)  # (mtu or None, message)

    def __init__(self, host, minimum, maximum, timeout, retries, source, parent=None):
        super().__init__(parent)
        self.host, self.minimum, self.maximum = host, minimum, maximum
        self.timeout, self.retries, self.source = timeout, retries, source

    def run(self):
        try:
            address, _ = resolve_host(self.host, family=4)  # DF-based testing only works over IPv4
            source = f" from {self.source}" if self.source else ""
            self.line.emit(f"Testing path MTU to {self.host} [{address}]{source}, between {self.minimum} and "
                           f"{self.maximum}...")
            with IcmpClient(4) as client:
                mtu, message = find_path_mtu(
                    make_mtu_probe(client, address, self.timeout, self.source), self.minimum, self.maximum,
                    retries=self.retries, should_stop=lambda: self.stopping, log=self.line.emit,
                    progress=self.progress.emit)
        except (OSError, ValueError) as error:
            mtu, message = None, str(error)
        self.line.emit(message)
        self.finished_test.emit(mtu, message)


class MtuTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.worker = None
        self.result_mtu = None
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.update_adapter_info())
        window.adapter_changed.connect(lambda _: self.update_adapter_info())
        self.update_adapter_info()
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.adapter_label = QLabel()
        self.adapter_label.setWordWrap(True)
        layout.addWidget(self.adapter_label)

        self.host_input = QLineEdit(DEFAULTS["host"])
        self.host_input.setToolTip("An IPv4 host that answers ping. Pick one past the link you want to test.")
        self.minimum_input = QLineEdit(DEFAULTS["minimum"])
        self.maximum_input = QLineEdit(DEFAULTS["maximum"])
        self.timeout_input = QLineEdit(DEFAULTS["timeout"])
        self.retries_input = QLineEdit(DEFAULTS["retries"])
        self.retries_input.setToolTip("How many times to retry a size that times out before treating it as too "
                                      "big. Retries stop a single lost packet from skewing the result.")
        for line_edit, validator in ((self.minimum_input, QIntValidator(MIN_MTU, MAX_MTU)),
                                     (self.maximum_input, QIntValidator(MIN_MTU, MAX_MTU)),
                                     (self.timeout_input, QIntValidator(100, 60000)),
                                     (self.retries_input, QIntValidator(0, 10))):
            line_edit.setValidator(validator)
        form = QFormLayout()
        form.addRow("Remote host:", self.host_input)
        form.addRow("Minimum MTU:", self.minimum_input)
        form.addRow("Maximum MTU:", self.maximum_input)
        form.addRow("Timeout (ms):", self.timeout_input)
        form.addRow("Retries on timeout:", self.retries_input)
        layout.addLayout(form)
        self.form_hint = QLabel()
        layout.addWidget(self.form_hint)

        buttons = QHBoxLayout()
        self.run_button = accent_button("Run MTU Test")
        self.stop_button = QPushButton("Stop")
        buttons.addWidget(self.run_button)
        buttons.addWidget(self.stop_button)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)

        result_layout = QHBoxLayout()
        self.result_label = QLabel()
        font = QFont(self.result_label.font())
        font.setBold(True)
        self.result_label.setFont(font)
        self.result_label.setWordWrap(True)
        result_layout.addWidget(self.result_label, 1)
        self.apply_button = QPushButton("Apply MTU")
        self.apply_button.setVisible(False)
        result_layout.addWidget(self.apply_button)
        layout.addLayout(result_layout)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9))
        layout.addWidget(self.output, 1)

        self.run_button.clicked.connect(self.start_test)
        self.stop_button.clicked.connect(self.stop_test)
        self.apply_button.clicked.connect(self.apply_result)
        self.host_input.returnPressed.connect(self.start_test)

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        for key, line_edit in self.inputs().items():
            settings.setValue(f"mtu/{key}", line_edit.text())

    def restore_settings(self, settings):
        for key, line_edit in self.inputs().items():
            line_edit.setText(settings.value(f"mtu/{key}", DEFAULTS[key], str))

    def shutdown(self):
        if self.worker is not None:
            self.worker.stop()
            self.worker.wait(3000)

    def inputs(self):
        return {"host": self.host_input, "minimum": self.minimum_input, "maximum": self.maximum_input,
                "timeout": self.timeout_input, "retries": self.retries_input}

    # ----------------------------------------------------------------- Test

    def source_address(self):
        """Send probes from the selected adapter so the result applies to it."""
        adapter = self.window.current_adapter()
        if adapter is not None and adapter.ipv4 and adapter.status == "Up":
            return str(adapter.ipv4[0].ip)
        return None

    def update_adapter_info(self):
        adapter = self.window.current_adapter()
        if adapter is None:
            self.adapter_label.setText("No adapter selected; probes use whichever adapter Windows picks.")
        elif self.source_address():
            self.adapter_label.setText(f"Testing from <b>{adapter.name}</b> ({self.source_address()}), current MTU "
                                       f"<b>{adapter.mtu4 or 'unknown'}</b>. Choose a different adapter at the top.")
        else:
            self.adapter_label.setText(f"{adapter.name} has no IPv4 address or isn't connected; probes use "
                                       "whichever adapter Windows picks.")
        self.update_apply_button()

    def start_test(self):
        if self.worker is not None:
            return
        try:
            minimum, maximum = int(self.minimum_input.text()), int(self.maximum_input.text())
            timeout = int(self.timeout_input.text())
            retries = int(self.retries_input.text() or 0)
        except ValueError:
            set_hint(self.form_hint, "Fill in the MTU range and timeout.", "error")
            return
        if not MIN_MTU <= minimum < maximum <= MAX_MTU:
            set_hint(self.form_hint, f"The range must satisfy {MIN_MTU} â‰¤ minimum < maximum â‰¤ {MAX_MTU}.", "error")
            return
        self.form_hint.clear()
        self.output.clear()
        self.result_label.clear()
        self.result_mtu = None
        self.progress_bar.setRange(0, path_mtu_steps(minimum, maximum))
        self.progress_bar.setValue(0)

        self.worker = MtuTestThread(self.host_input.text().strip(), minimum, maximum, timeout, retries,
                                    self.source_address(), self)
        self.worker.line.connect(self.output.appendPlainText)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished_test.connect(self.on_test_finished)
        self.worker.finished.connect(self.on_thread_finished)
        self.worker.start()
        self.update_buttons()

    def stop_test(self):
        if self.worker is not None:
            self.worker.stop()  # The thread notices between probes; no need to block the UI waiting for it
            self.stop_button.setEnabled(False)
            self.output.appendPlainText("Stopping...")

    def on_test_finished(self, mtu, message):
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.result_mtu = mtu
        if mtu is None:
            self.result_label.setStyleSheet(f"color: {COLORS['error']};")
            self.result_label.setText(message)
        else:
            self.result_label.setStyleSheet("")
            self.result_label.setText(f"Path MTU to {self.host_input.text().strip()}: {mtu} bytes "
                                      f"(largest ping payload {mtu - 28} bytes)")
        self.update_apply_button()

    def on_thread_finished(self):
        self.worker.deleteLater()
        self.worker = None
        self.update_buttons()

    def update_buttons(self):
        running = self.worker is not None
        self.run_button.setEnabled(not running)
        self.stop_button.setEnabled(running)

    def update_apply_button(self):
        adapter = self.window.current_adapter()
        show = self.result_mtu is not None and adapter is not None and adapter.is_adapter
        self.apply_button.setVisible(show)
        if show:
            matches = adapter.mtu4 == self.result_mtu
            self.apply_button.setText(f"Apply MTU {self.result_mtu} to {adapter.name}")
            self.apply_button.setEnabled(not matches)
            self.apply_button.setToolTip("The adapter already uses this MTU." if matches else "")

    def apply_result(self):
        if self.result_mtu is not None:
            self.window.adapter_tab.set_mtu_from_test(self.result_mtu)
