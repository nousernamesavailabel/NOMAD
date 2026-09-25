"""iperf tab: measure bandwidth against an iperf3 server, or act as one for other machines."""
import logging

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QDoubleValidator, QFont, QIntValidator
from PyQt5.QtWidgets import QButtonGroup, QComboBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit, \
    QPlainTextEdit, QProgressBar, QPushButton, QRadioButton, QVBoxLayout, QWidget

from ..iperf import DEFAULT_PORT, IperfClient, IperfError, IperfParams, IperfServer, open_firewall_port
from .common import StoppableThread, set_hint
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

DEFAULTS = {"host": "", "port": str(DEFAULT_PORT), "duration": "10", "parallel": "1", "bitrate": "10",
            "server_port": str(DEFAULT_PORT)}


class IperfClientThread(StoppableThread):
    line = pyqtSignal(str)
    interval = pyqtSignal(object)
    result = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, host, port, params, parent=None):
        super().__init__(parent)
        self.host, self.port, self.params = host, port, params

    def run(self):
        try:
            result = IperfClient(self.host, self.port, self.params, on_interval=self.interval.emit,
                                 on_log=self.line.emit, should_stop=lambda: self.stopping).run()
        except IperfError as error:
            self.failed.emit(str(error))
        else:
            self.result.emit(result)


class IperfServerThread(StoppableThread):
    line = pyqtSignal(str)
    interval = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, port, parent=None):
        super().__init__(parent)
        self.port = port

    def run(self):
        try:
            IperfServer(self.port, on_log=self.line.emit, on_interval=self.interval.emit,
                        should_stop=lambda: self.stopping).serve()
        except IperfError as error:
            self.failed.emit(str(error))


class IperfTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.client_worker = None
        self.server_worker = None
        self.interval_header_shown = False
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.update_server_info())
        self.on_mode_changed()
        self.update_buttons()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        layout = QVBoxLayout(self)

        mode_row = QHBoxLayout()
        self.client_radio = QRadioButton("Client: test against an iperf3 server")
        self.server_radio = QRadioButton("Server: let other computers test against this one")
        self.client_radio.setChecked(True)
        mode_group = QButtonGroup(self)
        mode_group.addButton(self.client_radio)
        mode_group.addButton(self.server_radio)
        mode_row.addWidget(self.client_radio)
        mode_row.addWidget(self.server_radio)
        mode_row.addStretch()
        layout.addLayout(mode_row)

        # Client settings
        self.client_group = QGroupBox("Client")
        client_form = QFormLayout(self.client_group)
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("iperf3 server name or address (another PC running iperf3 -s or "
                                           "NOMAD in server mode)")
        self.port_input = QLineEdit(DEFAULTS["port"])
        self.port_input.setValidator(QIntValidator(1, 65535))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("TCP", "tcp")
        self.protocol_combo.addItem("UDP", "udp")
        self.direction_combo = QComboBox()
        self.direction_combo.addItem("Upload (this computer → server)", False)
        self.direction_combo.addItem("Download (server → this computer)", True)
        self.duration_input = QLineEdit(DEFAULTS["duration"])
        self.duration_input.setValidator(QIntValidator(1, 3600))
        self.parallel_input = QLineEdit(DEFAULTS["parallel"])
        self.parallel_input.setValidator(QIntValidator(1, 128))
        self.parallel_input.setToolTip("Parallel streams (-P). Several streams help fill fast or long-distance "
                                       "links.")
        self.bitrate_input = QLineEdit(DEFAULTS["bitrate"])
        self.bitrate_input.setValidator(QDoubleValidator(0.001, 100000, 3))
        self.bitrate_input.setToolTip("Target UDP rate per stream (-b). UDP sends at this rate whether or not "
                                      "the network keeps up; loss shows how much got through.")
        client_form.addRow("Server:", self.host_input)
        client_form.addRow("Port:", self.port_input)
        client_form.addRow("Protocol:", self.protocol_combo)
        client_form.addRow("Direction:", self.direction_combo)
        client_form.addRow("Duration (s):", self.duration_input)
        client_form.addRow("Parallel streams:", self.parallel_input)
        client_form.addRow("UDP bitrate (Mbit/s):", self.bitrate_input)
        client_buttons = QHBoxLayout()
        self.start_button = accent_button("Start Test")
        self.stop_button = QPushButton("Stop")
        client_buttons.addWidget(self.start_button)
        client_buttons.addWidget(self.stop_button)
        client_buttons.addStretch()
        client_form.addRow(client_buttons)
        self.progress_bar = QProgressBar()
        client_form.addRow(self.progress_bar)
        layout.addWidget(self.client_group)

        # Server settings
        self.server_group = QGroupBox("Server")
        server_layout = QVBoxLayout(self.server_group)
        server_form = QFormLayout()
        self.server_port_input = QLineEdit(DEFAULTS["server_port"])
        self.server_port_input.setValidator(QIntValidator(1, 65535))
        server_form.addRow("Listen on port:", self.server_port_input)
        server_layout.addLayout(server_form)
        server_buttons = QHBoxLayout()
        self.start_server_button = accent_button("Start Server")
        self.stop_server_button = QPushButton("Stop Server")
        self.firewall_button = QPushButton("Open Firewall Port")
        self.firewall_button.setToolTip("Add a Windows Firewall rule allowing inbound iperf tests on this port "
                                        "(TCP and UDP). Needs administrator rights.")
        server_buttons.addWidget(self.start_server_button)
        server_buttons.addWidget(self.stop_server_button)
        server_buttons.addWidget(self.firewall_button)
        server_buttons.addStretch()
        server_layout.addLayout(server_buttons)
        self.server_info = QLabel()
        self.server_info.setWordWrap(True)
        self.server_info.setTextInteractionFlags(Qt.TextSelectableByMouse)
        server_layout.addWidget(self.server_info)
        layout.addWidget(self.server_group)

        self.hint_label = QLabel()
        self.hint_label.setWordWrap(True)
        layout.addWidget(self.hint_label)

        self.result_label = QLabel()
        self.result_label.setFont(QFont("Consolas", 10, QFont.Bold))
        self.result_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.result_label)

        output_buttons = QHBoxLayout()
        output_buttons.addStretch()
        clear_button = QPushButton("Clear")
        output_buttons.addWidget(clear_button)
        layout.addLayout(output_buttons)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 9))
        self.output.setMaximumBlockCount(20000)
        layout.addWidget(self.output, 1)

        self.client_radio.toggled.connect(self.on_mode_changed)
        self.protocol_combo.currentIndexChanged.connect(self.on_protocol_changed)
        self.start_button.clicked.connect(self.start_test)
        self.stop_button.clicked.connect(self.stop_test)
        self.host_input.returnPressed.connect(self.start_test)
        self.start_server_button.clicked.connect(self.start_server)
        self.stop_server_button.clicked.connect(self.stop_server)
        self.firewall_button.clicked.connect(self.open_firewall)
        self.server_port_input.textChanged.connect(self.update_server_info)
        clear_button.clicked.connect(self.clear_output)
        self.on_protocol_changed()

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("iperf/mode", "server" if self.server_radio.isChecked() else "client")
        settings.setValue("iperf/host", self.host_input.text())
        settings.setValue("iperf/port", self.port_input.text())
        settings.setValue("iperf/protocol", self.protocol_combo.currentData())
        settings.setValue("iperf/reverse", self.direction_combo.currentData())
        settings.setValue("iperf/duration", self.duration_input.text())
        settings.setValue("iperf/parallel", self.parallel_input.text())
        settings.setValue("iperf/bitrate", self.bitrate_input.text())
        settings.setValue("iperf/server_port", self.server_port_input.text())

    def restore_settings(self, settings):
        (self.server_radio if settings.value("iperf/mode", "client", str) == "server"
         else self.client_radio).setChecked(True)
        for key, line_edit in (("host", self.host_input), ("port", self.port_input),
                               ("duration", self.duration_input), ("parallel", self.parallel_input),
                               ("bitrate", self.bitrate_input), ("server_port", self.server_port_input)):
            line_edit.setText(settings.value(f"iperf/{key}", DEFAULTS[key], str))
        self.protocol_combo.setCurrentIndex(max(0, self.protocol_combo.findData(
            settings.value("iperf/protocol", "tcp", str))))
        self.direction_combo.setCurrentIndex(1 if settings.value("iperf/reverse", False, bool) else 0)

    def shutdown(self):
        for worker in (self.client_worker, self.server_worker):
            if worker is not None:
                worker.stop()
                worker.wait(5000)

    # ----------------------------------------------------------------- Mode and output

    def on_mode_changed(self):
        client = self.client_radio.isChecked()
        self.client_group.setVisible(client)
        self.server_group.setVisible(not client)
        self.hint_label.clear()
        self.update_server_info()

    def on_protocol_changed(self):
        self.bitrate_input.setEnabled(self.protocol_combo.currentData() == "udp")

    def clear_output(self):
        self.output.clear()
        self.result_label.clear()

    def show_interval(self, interval):
        if not self.interval_header_shown:
            header = "Interval           Transfer         Bitrate"
            if interval.jitter_ms is not None:
                header += "          Jitter    Lost/Total"
            self.output.appendPlainText(header)
            self.interval_header_shown = True
        self.output.appendPlainText(interval.format())

    def update_buttons(self):
        client_running = self.client_worker is not None
        server_running = self.server_worker is not None
        self.start_button.setEnabled(not client_running and not server_running)
        self.stop_button.setEnabled(client_running)
        self.start_server_button.setEnabled(not server_running and not client_running)
        self.stop_server_button.setEnabled(server_running)
        self.server_port_input.setEnabled(not server_running)
        self.client_radio.setEnabled(not server_running and not client_running)
        self.server_radio.setEnabled(not server_running and not client_running)

    # ----------------------------------------------------------------- Client

    def read_params(self):
        try:
            duration = int(self.duration_input.text())
            parallel = int(self.parallel_input.text())
            port = int(self.port_input.text())
            bitrate = float(self.bitrate_input.text() or 0)
        except ValueError:
            return None, None, "Fill in the port, duration and number of streams."
        if not self.host_input.text().strip():
            return None, None, "Enter the iperf3 server to test against."
        udp = self.protocol_combo.currentData() == "udp"
        if udp and bitrate <= 0:
            return None, None, "Enter a UDP bitrate above 0."
        params = IperfParams(protocol=self.protocol_combo.currentData(), duration=duration, parallel=parallel,
                             reverse=self.direction_combo.currentData(),
                             bitrate=int(bitrate * 1_000_000) if udp else 0)
        return params, port, None

    def start_test(self):
        if self.client_worker is not None or self.server_worker is not None:
            return
        params, port, error = self.read_params()
        if error:
            set_hint(self.hint_label, error, "error")
            return
        self.hint_label.clear()
        self.result_label.clear()
        if self.output.toPlainText():
            self.output.appendPlainText("")
        self.interval_header_shown = False
        self.progress_bar.setRange(0, params.duration)
        self.progress_bar.setValue(0)
        host = self.host_input.text().strip()
        self.output.appendPlainText(f"Testing {params.protocol.upper()} "
                                    f"{'download from' if params.reverse else 'upload to'} {host}:{port} for "
                                    f"{params.duration} s with {params.parallel} stream(s)...")

        self.client_worker = IperfClientThread(host, port, params, self)
        self.client_worker.line.connect(self.output.appendPlainText)
        self.client_worker.interval.connect(self.show_interval)
        self.client_worker.interval.connect(lambda interval: self.progress_bar.setValue(int(interval.end)))
        self.client_worker.result.connect(self.show_result)
        self.client_worker.failed.connect(self.show_failure)
        self.client_worker.finished.connect(self.on_client_finished)
        self.client_worker.start()
        self.update_buttons()

    def stop_test(self):
        if self.client_worker is not None:
            self.client_worker.stop()  # The test ends early but still collects results
            self.stop_button.setEnabled(False)

    def show_result(self, result):
        self.progress_bar.setValue(self.progress_bar.maximum())
        lines = result.summary_lines()
        self.output.appendPlainText("")
        self.output.appendPlainText("\n".join(lines))
        self.result_label.setStyleSheet("")
        self.result_label.setText("\n".join(lines[1:]))

    def show_failure(self, message):
        self.output.appendPlainText(message)
        self.result_label.setStyleSheet(f"color: {COLORS['error']};")
        self.result_label.setText(message)

    def on_client_finished(self):
        self.client_worker.deleteLater()
        self.client_worker = None
        self.update_buttons()

    # ----------------------------------------------------------------- Server

    def server_port(self):
        try:
            return int(self.server_port_input.text())
        except ValueError:
            return DEFAULT_PORT

    def update_server_info(self):
        port = self.server_port()
        addresses = [str(address.ip) for adapter in self.window.snapshot.real_adapters()
                     if adapter.status == "Up" for address in adapter.ipv4]
        port_flag = "" if port == DEFAULT_PORT else f" -p {port}"
        target = addresses[0] if addresses else "<this computer's address>"
        running = self.server_worker is not None
        text = ("<b>Server running.</b> " if running else "") + \
            f"This computer's addresses: {', '.join(addresses) or 'none found'}.<br>" \
            f"On the other computer run <code>iperf3 -c {target}{port_flag}</code> " \
            f"(add <code>-R</code> to test the other direction, <code>-u -b 100M</code> for UDP), " \
            f"or use NOMAD's client mode.<br>" \
            "If the other computer can't connect, click Open Firewall Port (or allow NOMAD when Windows " \
            "asks)."
        self.server_info.setText(text)

    def start_server(self):
        if self.server_worker is not None or self.client_worker is not None:
            return
        self.hint_label.clear()
        if self.output.toPlainText():
            self.output.appendPlainText("")
        self.interval_header_shown = False
        self.server_worker = IperfServerThread(self.server_port(), self)
        self.server_worker.line.connect(self.on_server_line)
        self.server_worker.interval.connect(self.show_interval)
        self.server_worker.failed.connect(self.show_failure)
        self.server_worker.finished.connect(self.on_server_finished)
        self.server_worker.start()
        self.update_buttons()
        self.update_server_info()

    def on_server_line(self, line):
        if line.startswith("Test from"):
            if self.output.toPlainText():
                self.output.appendPlainText("")
            self.interval_header_shown = False  # New test: show the column header again
        self.output.appendPlainText(line)

    def stop_server(self):
        if self.server_worker is not None:
            self.server_worker.stop()
            self.stop_server_button.setEnabled(False)

    def on_server_finished(self):
        self.server_worker.deleteLater()
        self.server_worker = None
        self.update_buttons()
        self.update_server_info()

    def open_firewall(self):
        port = self.server_port()
        self.window.run_change(
            f"Opening port {port} in Windows Firewall", lambda: open_firewall_port(port),
            on_success=lambda _: self.window.show_status(f"Windows Firewall now allows iperf tests on port {port}."))
