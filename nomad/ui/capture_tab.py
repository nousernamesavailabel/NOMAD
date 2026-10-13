"""Packet Capture page: capture traffic with Windows' pktmon, save it as pcapng, and look through it in the viewer
(or Wireshark)."""
import logging
import os
import subprocess

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import QCheckBox, QComboBox, QFileDialog, QFormLayout, QHBoxLayout, QLabel, QLineEdit, \
    QMessageBox, QPushButton, QSpinBox, QToolButton, QVBoxLayout, QWidget

from .. import erspan
from ..capture import DEFAULT_FILE_SIZE_MB, PROTOCOLS, Capture, default_output_path, validate_filter
from ..pktmon import PktmonBusy, find_pktmon
from ..system import CommandError
from .capture_viewer import CaptureViewer
from .common import format_size, run_in_background, set_hint, set_invalid
from .theme import accent_button

log = logging.getLogger(__name__)

UPDATE_MILLISECONDS = 500


def format_duration(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}:{minutes:02d}:{seconds:02d}"


class CaptureTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.capture = None
        self.busy = False  # Starting, or stopping and saving
        self.saved_path = None
        self.capture_note = ""  # Said while capturing (promiscuous mode refused)
        self.span_adapter_name = ""  # Chosen before the adapters were read
        self.init_ui()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_progress)
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        self.settings_panel = QWidget()  # Folds away (the Settings button) to give the packets the room
        panel = QVBoxLayout(self.settings_panel)
        panel.setContentsMargins(0, 0, 0, 0)
        intro = QLabel("Capture network traffic on every adapter with Windows' built-in packet monitor (pktmon), "
                       "watch it below as it comes, save it as a pcapng file, and look through it: filters, "
                       "conversations, problems found, streams. Needs administrator rights. A filter keeps the "
                       "capture small; leave the fields blank to capture everything. Starting a capture clears any "
                       "packet filters you've set in pktmon yourself.")
        intro.setWordWrap(True)
        panel.addWidget(intro)

        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText("Optional: an IP address or subnet, such as 10.0.0.5 or 10.0.0.0/24")
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("Optional, such as 443")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(PROTOCOLS)
        filter_row = QHBoxLayout()
        filter_row.addWidget(self.address_input, 3)
        filter_row.addWidget(QLabel("Port:"))
        filter_row.addWidget(self.port_input, 1)
        filter_row.addWidget(QLabel("Protocol:"))
        filter_row.addWidget(self.protocol_combo)

        self.whole_check = QCheckBox("Capture whole packets")
        self.whole_check.setChecked(True)
        self.whole_check.setToolTip("Untick to keep only the first 128 bytes of each packet (the headers), which "
                                    "keeps long captures small.")
        self.size_input = QSpinBox()
        self.size_input.setRange(10, 100000)
        self.size_input.setValue(DEFAULT_FILE_SIZE_MB)
        self.size_input.setSuffix(" MB")
        self.size_input.setToolTip("Once the capture reaches this size, the oldest packets are dropped to make room.")
        self.minutes_input = QSpinBox()
        self.minutes_input.setRange(0, 24 * 60)
        self.minutes_input.setSpecialValueText("Until stopped")
        self.minutes_input.setSuffix(" min")
        self.minutes_input.setToolTip("Stop and save automatically after this long.")
        for spin_box in (self.size_input, self.minutes_input):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        self.live_check = QCheckBox("Show packets live")
        self.live_check.setChecked(True)
        self.live_check.setToolTip("Show the packets below as they're captured. On a very busy link the live view "
                                   "can miss some (it says so); the saved file always has them all.")
        options_row = QHBoxLayout()
        options_row.addWidget(self.whole_check)
        options_row.addSpacing(12)
        options_row.addWidget(self.live_check)
        options_row.addSpacing(12)
        options_row.addWidget(QLabel("Keep up to:"))
        options_row.addWidget(self.size_input)
        options_row.addSpacing(12)
        options_row.addWidget(QLabel("Stop after:"))
        options_row.addWidget(self.minutes_input)
        options_row.addStretch()

        self.unwrap_check = QCheckBox("Unwrap ERSPAN")
        self.unwrap_check.setToolTip("For a switch mirroring to this PC over ERSPAN (Port Mirroring): also save the "
                                     "frames it mirrored, unwrapped from their GRE packets, as their own capture "
                                     "(\"... (unwrapped).pcapng\"), which Open in Wireshark opens. Put the switch's "
                                     "origin address in Only traffic to or from.")
        self.erspan_id_input = QSpinBox()
        self.erspan_id_input.setRange(0, 1023)
        self.erspan_id_input.setSpecialValueText("Any")
        self.erspan_id_input.setButtonSymbols(QSpinBox.NoButtons)
        self.erspan_id_input.setToolTip("Only this ERSPAN session's frames (its ERSPAN ID). Any keeps every session's.")
        self.unwrap_check.toggled.connect(self.erspan_id_input.setEnabled)
        self.erspan_id_input.setEnabled(False)
        self.span_check = QCheckBox("SPAN copies on:")
        self.span_check.setToolTip("For a switch mirroring (SPAN or RSPAN) to this PC's port: hold that adapter in "
                                   "promiscuous mode while capturing, so the copies (addressed to other machines) "
                                   "aren't thrown away. Built into Windows, no driver needed. The adapter needs an "
                                   "IPv4 address (on a SPAN port it usually gets a 169.254 one).")
        self.span_adapter_combo = QComboBox()
        self.span_adapter_combo.setMinimumContentsLength(24)
        self.span_adapter_combo.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.span_check.toggled.connect(self.span_adapter_combo.setEnabled)
        self.span_adapter_combo.setEnabled(False)
        erspan_row = QHBoxLayout()
        erspan_row.addWidget(self.unwrap_check)
        erspan_row.addSpacing(12)
        erspan_row.addWidget(QLabel("ERSPAN ID:"))
        erspan_row.addWidget(self.erspan_id_input)
        erspan_row.addSpacing(24)
        erspan_row.addWidget(self.span_check)
        erspan_row.addWidget(self.span_adapter_combo)
        erspan_row.addStretch()

        self.output_input = QLineEdit()
        self.browse_button = QPushButton("Browse...")
        output_row = QHBoxLayout()
        output_row.addWidget(self.output_input, 1)
        output_row.addWidget(self.browse_button)

        form = QFormLayout()
        form.addRow("Only traffic to or from:", filter_row)
        form.addRow("Options:", options_row)
        form.addRow("Mirrored to this PC:", erspan_row)
        form.addRow("Save to:", output_row)
        panel.addLayout(form)
        layout.addWidget(self.settings_panel)

        buttons = QHBoxLayout()
        self.start_button = accent_button("Start Capture")
        self.stop_button = QPushButton("Stop and Save")
        self.discard_button = QPushButton("Discard")
        self.discard_button.setToolTip("Stop without saving.")
        self.settings_button = QToolButton()
        self.settings_button.setCheckable(True)
        self.settings_button.setChecked(True)
        self.settings_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.settings_button.setToolTip("Show or hide what to capture and where to save it. They fold away by "
                                        "themselves while capturing.")
        self.folder_button = QPushButton("Open Folder")
        self.status_label = QLabel()  # Beside the buttons, not a row of its own
        self.status_label.setWordWrap(True)
        for button in (self.start_button, self.stop_button, self.discard_button):
            buttons.addWidget(button)
        buttons.addSpacing(8)
        buttons.addWidget(self.status_label, 1)
        buttons.addWidget(self.settings_button)
        buttons.addWidget(self.folder_button)
        layout.addLayout(buttons)

        self.viewer = CaptureViewer(self.window, self)
        layout.addWidget(self.viewer, 1)

        self.browse_button.clicked.connect(self.browse)
        self.start_button.clicked.connect(self.start)
        self.stop_button.clicked.connect(lambda: self.stop(save=True))
        self.discard_button.clicked.connect(lambda: self.stop(save=False))
        self.folder_button.clicked.connect(self.open_folder)
        for line_edit in (self.address_input, self.port_input, self.output_input):
            line_edit.textChanged.connect(lambda _, line_edit=line_edit: set_invalid(line_edit, False))
        self.settings_button.toggled.connect(self.show_settings)
        for line_edit in (self.address_input, self.port_input):
            line_edit.textChanged.connect(self.describe_settings)
        self.protocol_combo.currentTextChanged.connect(self.describe_settings)
        for check in (self.unwrap_check, self.span_check):
            check.toggled.connect(self.describe_settings)
        self.show_settings(True)

    def show_settings(self, shown):
        self.settings_panel.setVisible(shown)
        self.settings_button.blockSignals(True)
        self.settings_button.setChecked(shown)
        self.settings_button.blockSignals(False)
        self.settings_button.setArrowType(Qt.DownArrow if shown else Qt.RightArrow)
        self.describe_settings()

    def describe_settings(self, *_):
        """The Settings button says what a capture would take, so it can be seen with the settings folded away."""
        try:
            what = validate_filter(self.address_input.text(), self.port_input.text(),
                                   self.protocol_combo.currentText()).describe()
        except ValueError:
            what = "check the filter"
        if self.span_check.isChecked():
            what += ", SPAN copies"
        if self.unwrap_check.isChecked():
            what += ", ERSPAN"
        self.settings_button.setText(f"Settings: {what}")

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.show_settings(True)
        self.address_input.setFocus()
        self.address_input.selectAll()

    def save_settings(self, settings):
        settings.setValue("capture/address", self.address_input.text())
        settings.setValue("capture/port", self.port_input.text())
        settings.setValue("capture/protocol", self.protocol_combo.currentText())
        settings.setValue("capture/whole", self.whole_check.isChecked())
        settings.setValue("capture/live", self.live_check.isChecked())
        settings.setValue("capture/size", self.size_input.value())
        settings.setValue("capture/minutes", self.minutes_input.value())
        settings.setValue("capture/unwrap", self.unwrap_check.isChecked())
        settings.setValue("capture/erspan_id", self.erspan_id_input.value())
        settings.setValue("capture/span", self.span_check.isChecked())
        settings.setValue("capture/span_adapter", self.span_adapter_combo.currentData() or self.span_adapter_name)
        settings.setValue("capture/folder", os.path.dirname(self.output_input.text()))
        settings.setValue("capture/viewer_splitter", self.viewer.packet_splitter.saveState())
        settings.setValue("capture/settings_shown", self.settings_button.isChecked())

    def restore_settings(self, settings):
        self.address_input.setText(settings.value("capture/address", "", str))
        self.port_input.setText(settings.value("capture/port", "", str))
        self.protocol_combo.setCurrentText(settings.value("capture/protocol", "Any", str))
        self.whole_check.setChecked(settings.value("capture/whole", True, bool))
        self.live_check.setChecked(settings.value("capture/live", True, bool))
        self.size_input.setValue(settings.value("capture/size", DEFAULT_FILE_SIZE_MB, int))
        self.minutes_input.setValue(settings.value("capture/minutes", 0, int))
        self.unwrap_check.setChecked(settings.value("capture/unwrap", False, bool))
        self.erspan_id_input.setValue(settings.value("capture/erspan_id", 0, int))
        self.span_adapter_name = settings.value("capture/span_adapter", "", str)
        self.span_check.setChecked(settings.value("capture/span", False, bool))
        self.fill_span_adapters()
        self.output_input.setText(default_output_path(settings.value("capture/folder", "", str) or None))
        state = settings.value("capture/viewer_splitter")
        if state is not None:
            self.viewer.packet_splitter.restoreState(state)
        self.show_settings(settings.value("capture/settings_shown", True, bool))

    def showEvent(self, event):
        super().showEvent(event)
        self.fill_span_adapters()

    def fill_span_adapters(self):
        """The adapters a SPAN copy could come in on: those with an IPv4 address (wired ones first)."""
        from .mirror_tab import is_wireless
        current = self.span_adapter_combo.currentData() or self.span_adapter_name
        snapshot = getattr(self.window, "snapshot", None)
        try:
            adapters = [adapter for adapter in (snapshot.real_adapters() if snapshot is not None else [])
                        if adapter.ipv4]
        except Exception:  # The adapters not read yet
            adapters = []
        adapters.sort(key=is_wireless)
        self.span_adapter_combo.blockSignals(True)
        self.span_adapter_combo.clear()
        for adapter in adapters:
            self.span_adapter_combo.addItem(f"{adapter.name} ({adapter.ipv4[0].ip})", adapter.name)
        if not adapters:
            self.span_adapter_combo.addItem("No adapter with an IPv4 address", "")
        index = self.span_adapter_combo.findData(current)
        self.span_adapter_combo.setCurrentIndex(max(0, index))
        self.span_adapter_combo.blockSignals(False)

    def span_address(self):
        """The IPv4 address of the adapter chosen for SPAN copies, or ""."""
        name = self.span_adapter_combo.currentData()
        snapshot = getattr(self.window, "snapshot", None)
        if not name or snapshot is None:
            return ""
        adapter = next((adapter for adapter in snapshot.real_adapters() if adapter.name == name), None)
        return str(adapter.ipv4[0].ip) if adapter is not None and adapter.ipv4 else ""

    def shutdown(self):
        """Closing the app mid-capture saves what was captured rather than losing it."""
        self.viewer.shutdown()
        capture = self.capture
        if capture is None or self.busy:  # Already being saved or discarded in the background
            return
        try:
            if capture.running:
                capture.stop()
                capture.save(self.output_input.text())
                log.info("Saved the capture to %s while closing", self.output_input.text())
        except (CommandError, OSError) as error:
            log.error("Couldn't save the capture while closing: %s", error)
        finally:
            capture.cleanup()
            self.capture = None

    def capture_host(self, address):
        """Fill in a host to capture (from other pages)."""
        self.show_settings(True)
        self.address_input.setText(address)
        self.port_input.clear()
        self.protocol_combo.setCurrentText("Any")

    def capture_span(self, adapter_name):
        """Fill in a capture of what a switch mirrors (SPAN or RSPAN) to this PC's adapter (from Port Mirroring)."""
        self.show_settings(True)
        self.address_input.clear()
        self.port_input.clear()
        self.protocol_combo.setCurrentText("Any")
        self.unwrap_check.setChecked(False)
        self.span_adapter_name = adapter_name
        self.fill_span_adapters()
        index = self.span_adapter_combo.findData(adapter_name)
        if index >= 0:
            self.span_adapter_combo.setCurrentIndex(index)
        self.span_check.setChecked(True)
        if self.capture is None and not self.busy:
            set_hint(self.status_label, f"Ready to capture the copies the switch sends {adapter_name}: Start "
                                        "Capture, then Stop and Save to look through them below.", "info")

    def capture_erspan(self, origin_ip, erspan_id=0):
        """Fill in a capture of what a switch mirrors to this PC over ERSPAN (from Port Mirroring)."""
        self.capture_host(origin_ip)
        self.unwrap_check.setChecked(True)
        self.span_check.setChecked(False)
        self.erspan_id_input.setValue(erspan_id)
        if self.capture is None and not self.busy:
            set_hint(self.status_label, f"Ready to capture the copies {origin_ip} sends this PC (ERSPAN"
                                        f"{f' ID {erspan_id}' if erspan_id else ''}): Start Capture, then Stop and "
                                        "Save to get them unwrapped.", "info")

    # ----------------------------------------------------------------- Capture

    def browse(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Capture As", self.output_input.text(),
                                              "Wireshark captures (*.pcapng);;All files (*)")
        if path:
            self.output_input.setText(path if path.lower().endswith(".pcapng") else path + ".pcapng")

    def start(self):
        if self.capture is not None or self.busy:
            return
        try:
            capture_filter = validate_filter(self.address_input.text(), self.port_input.text(),
                                             self.protocol_combo.currentText())
        except ValueError as error:
            target = self.port_input if "port" in str(error).lower() else self.address_input
            set_invalid(target, True)
            set_hint(self.status_label, str(error), "error")
            return
        output = self.output_input.text().strip()
        if not output:
            self.output_input.setText(default_output_path())
            output = self.output_input.text()
        if os.path.exists(output):
            self.output_input.setText(default_output_path(os.path.dirname(output)))
        if not find_pktmon():
            set_hint(self.status_label, "This version of Windows doesn't have pktmon (it arrived in Windows 10 "
                                        "version 1809), so packet capture isn't available.", "error")
            return
        promiscuous = ""
        if self.span_check.isChecked():
            promiscuous = self.span_address()
            if not promiscuous:
                set_hint(self.status_label, "Choose the adapter the SPAN copies come in on (it needs an IPv4 "
                                            "address), or untick SPAN copies.", "error")
                return
        if not self.window.require_admin("Capturing packets"):
            return
        capture = Capture(capture_filter, self.whole_check.isChecked(), self.size_input.value(), promiscuous,
                          self.live_check.isChecked())
        unwrapped = True if self.unwrap_check.isChecked() else None
        self.busy = True
        self.saved_path = None
        self.capture_note = ""
        set_hint(self.status_label, "Starting the capture...", "info")
        self.update_buttons()

        def started(_):
            self.busy = False
            self.capture = capture
            self.show_settings(False)  # They can't be changed while capturing: the room goes to the packets
            self.timer.start(UPDATE_MILLISECONDS)
            self.window.set_busy("capture", "Capturing packets")
            log.info("Capturing %s", capture_filter.describe())
            if capture.promiscuous_problem:
                self.capture_note = (f" {capture.promiscuous_problem}. Only this PC's own traffic will be "
                                     "captured.")
            elif capture.promiscuous is not None:
                self.capture_note = f" Promiscuous mode on for {self.span_adapter_combo.currentText()}."
            if capture.live:
                self.viewer.start_live(capture.feed, os.path.basename(output), unwrapped)
            elif capture.live_problem:
                self.capture_note += (f" No live view: {capture.live_problem} The packets open below after Stop "
                                      "and Save.")
            self.update_progress()
            self.update_buttons()

        def failed(error):
            self.busy = False
            message = str(error) if isinstance(error, PktmonBusy) else f"Couldn't start the capture: {error}"
            set_hint(self.status_label, message, "error")
            self.update_buttons()

        run_in_background(capture.start, started, failed)

    def update_progress(self):
        capture = self.capture
        if capture is None or not capture.running:
            return
        elapsed = capture.elapsed()
        limit = self.minutes_input.value() * 60
        what = capture.filter.describe()
        remaining = f"  ·  stops in {format_duration(limit - elapsed)}" if limit else ""
        set_hint(self.status_label, f"Capturing {what}: {format_duration(elapsed)}, {format_size(capture.size())}"
                                    f"{remaining}.{self.capture_note}",
                 "warning" if capture.promiscuous_problem else "info")
        if limit and elapsed >= limit:
            self.stop(save=True)

    def stop(self, save=True):
        capture = self.capture
        if capture is None or self.busy:
            return
        self.busy = True
        self.timer.stop()
        self.viewer.stop_live()
        output = self.output_input.text().strip()
        unwrap = save and self.unwrap_check.isChecked()
        erspan_id = self.erspan_id_input.value()
        sender = capture.filter.address if erspan.valid_sender(capture.filter.address) else ""
        set_hint(self.status_label, "Stopping and converting to pcapng (large captures take a moment)..." if save
                 else "Stopping...", "info")
        self.window.set_busy("capture", "Saving the capture" if save else "Stopping the capture")
        self.update_buttons()

        def finish():
            try:
                capture.stop()
                if not save:
                    return None
                size = capture.save(output)
            finally:
                capture.cleanup()
            if not unwrap:
                return size, None, ""
            path = erspan.unwrapped_path(output)
            try:
                return size, erspan.unwrap(output, path, erspan_id, sender), path
            except (erspan.CaptureError, OSError) as error:
                return size, str(error), path

        def saved(outcome):
            self.finish_capture()
            if save:
                size, unwrapped, path = outcome
                self.saved_path = output
                text, kind = f"Saved {format_size(size)} to {output}.", "success"
                if isinstance(unwrapped, erspan.Result):
                    text += f" Unwrapped ERSPAN: {unwrapped.summary()}"
                    if unwrapped.frames:
                        self.saved_path = path
                        text += f" Saved to {path}."
                    else:
                        kind = "warning"
                elif unwrapped:
                    text += f" Couldn't unwrap ERSPAN: {unwrapped}"
                    kind = "warning"
                set_hint(self.status_label, text, kind)
                log.info("Saved a capture to %s", output)
                self.output_input.setText(default_output_path(os.path.dirname(output)))
                self.viewer.open(self.saved_path)
            else:
                set_hint(self.status_label, "Capture discarded.", "info")
            self.update_buttons()

        def failed(error):
            self.finish_capture()
            set_hint(self.status_label, f"Couldn't save the capture: {error}", "error")
            self.update_buttons()

        run_in_background(finish, saved, failed)

    def finish_capture(self):
        self.busy = False
        self.capture = None
        self.window.clear_busy("capture")

    def open_folder(self):
        path = self.saved_path or self.output_input.text()
        folder = os.path.dirname(path)
        try:
            if self.saved_path and os.path.isfile(self.saved_path):
                subprocess.Popen(["explorer", "/select,", os.path.normpath(self.saved_path)])
            else:
                os.startfile(folder)
        except OSError as error:
            QMessageBox.critical(self, "Open Folder", f"Couldn't open {folder}:\n\n{error}")

    def update_buttons(self):
        capturing = self.capture is not None
        self.start_button.setEnabled(not capturing and not self.busy)
        self.stop_button.setEnabled(capturing and not self.busy)
        self.discard_button.setEnabled(capturing and not self.busy)
        for widget in (self.address_input, self.port_input, self.protocol_combo, self.whole_check, self.size_input,
                       self.output_input, self.browse_button, self.unwrap_check, self.span_check, self.live_check):
            widget.setEnabled(not capturing and not self.busy)
        self.span_adapter_combo.setEnabled(not capturing and not self.busy and self.span_check.isChecked())
        self.folder_button.setEnabled(bool(self.output_input.text()))
