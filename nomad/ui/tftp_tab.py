"""TFTP page: serve a folder to switches, phones and access points (firmware, configs), and fetch or send files."""
import logging
import os
import time

from PyQt5.QtCore import QObject, Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, \
    QLabel, QLineEdit, QMessageBox, QProgressBar, QPushButton, QSpinBox, QSplitter, QTableWidget, QVBoxLayout, QWidget

from ..system import allow_inbound_port
from ..tftp import CLIENT_BLOCK_SIZE, MAX_BLOCK_SIZE, MIN_BLOCK_SIZE, TFTP_PORT, TftpError, TftpServer, download, \
    upload
from .common import ColumnFitter, SortableTableItem, StoppableThread, format_size, set_hint, set_invalid
from .theme import COLORS, accent_button

log = logging.getLogger(__name__)

TRANSFER_COLUMNS = ["Time", "Client", "File", "Direction", "Size", "Progress", "Speed", "Status"]
COL_PROGRESS, COL_SPEED, COL_STATUS = 5, 6, 7
FIREWALL_RULE = "NOMAD TFTP server"
MAX_TRANSFER_ROWS = 500


def default_folder():
    return os.path.join(os.path.expanduser("~"), "Documents", "NOMAD TFTP")


class _ServerEvents(QObject):
    """Carries transfer updates from the server's threads to the UI thread."""
    transfer = pyqtSignal(object, float, bool)  # (Transfer, rate, finished) snapshot values


class ClientThread(StoppableThread):
    progress = pyqtSignal(int, object)  # (bytes, total or None)
    finished_transfer = pyqtSignal(str, str)  # (message, kind)

    def __init__(self, direction, host, port, remote, local, block_size, parent=None):
        super().__init__(parent)
        self.direction, self.host, self.port = direction, host, port
        self.remote, self.local, self.block_size = remote, local, block_size

    def run(self):
        started = time.monotonic()
        try:
            if self.direction == "download":
                size = download(self.host, self.remote, self.local, self.port, self.block_size,
                                progress=self.progress.emit, should_stop=lambda: self.stopping)
                what = f"Downloaded {self.remote} ({format_size(size)}) to {self.local}"
            else:
                size = upload(self.host, self.local, self.remote, self.port, self.block_size,
                              progress=self.progress.emit, should_stop=lambda: self.stopping)
                what = f"Uploaded {os.path.basename(self.local)} ({format_size(size)}) as {self.remote}"
        except TftpError as error:
            self.finished_transfer.emit(str(error), "error")
            return
        except OSError as error:
            self.finished_transfer.emit(f"Couldn't reach {self.host}: {error.strerror or error}", "error")
            return
        elapsed = max(time.monotonic() - started, 0.001)
        self.finished_transfer.emit(f"{what} in {elapsed:.1f} s ({format_size(size / elapsed)}/s).", "success")


class TftpTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.server = None
        self.client_worker = None
        self.rows = {}  # Transfer id -> row
        self.events = _ServerEvents()
        self.events.transfer.connect(self.show_transfer)
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.fill_addresses())
        self.update_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        splitter = QSplitter(Qt.Vertical)
        self.server_group = self.build_server_group()
        splitter.addWidget(self.server_group)
        splitter.addWidget(self.build_client_group())
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter)

    # ----------------------------------------------------------------- Server

    def build_server_group(self):
        group = QGroupBox("TFTP Server")
        layout = QVBoxLayout(group)
        folder_row = QHBoxLayout()
        self.folder_input = QLineEdit(default_folder())
        self.folder_browse = QPushButton("Browse...")
        self.folder_open = QPushButton("Open Folder")
        folder_row.addWidget(self.folder_input, 1)
        folder_row.addWidget(self.folder_browse)
        folder_row.addWidget(self.folder_open)

        listen_row = QHBoxLayout()
        self.address_combo = QComboBox()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(TFTP_PORT)
        self.port_input.setButtonSymbols(QSpinBox.NoButtons)
        listen_row.addWidget(self.address_combo, 1)
        listen_row.addWidget(QLabel("Port:"))
        listen_row.addWidget(self.port_input)

        options_row = QHBoxLayout()
        self.upload_check = QCheckBox("Allow uploads")
        self.upload_check.setChecked(True)
        self.upload_check.setToolTip("Let devices send files here, such as config backups.")
        self.overwrite_check = QCheckBox("Allow replacing files")
        self.overwrite_check.setToolTip("Let an upload replace a file that's already in the folder.")
        options_row.addWidget(self.upload_check)
        options_row.addWidget(self.overwrite_check)
        options_row.addStretch()

        form = QFormLayout()
        form.addRow("Folder:", folder_row)
        form.addRow("Listen on:", listen_row)
        form.addRow("Options:", options_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.server_start = accent_button("Start Server")
        self.server_stop = QPushButton("Stop Server")
        self.firewall_button = QPushButton("Open Firewall Port")
        self.firewall_button.setToolTip("Allow TFTP requests (UDP port 69) in through Windows Firewall.")
        self.clear_button = QPushButton("Clear List")
        buttons.addWidget(self.server_start)
        buttons.addWidget(self.server_stop)
        buttons.addStretch()
        buttons.addWidget(self.clear_button)
        buttons.addWidget(self.firewall_button)
        layout.addLayout(buttons)
        self.server_status = QLabel()
        self.server_status.setWordWrap(True)
        layout.addWidget(self.server_status)

        self.transfers = QTableWidget(0, len(TRANSFER_COLUMNS))
        self.transfers.setHorizontalHeaderLabels(TRANSFER_COLUMNS)
        self.transfers.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.transfers.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.transfers.verticalHeader().setVisible(False)
        self.transfers.horizontalHeader().setStretchLastSection(True)
        ColumnFitter(self.transfers)
        layout.addWidget(self.transfers, 1)

        self.folder_browse.clicked.connect(self.browse_folder)
        self.folder_open.clicked.connect(self.open_folder)
        self.server_start.clicked.connect(self.start_server)
        self.server_stop.clicked.connect(self.stop_server)
        self.firewall_button.clicked.connect(self.open_firewall)
        self.clear_button.clicked.connect(self.clear_transfers)
        self.upload_check.toggled.connect(self.update_server_options)
        self.overwrite_check.toggled.connect(self.update_server_options)
        self.fill_addresses()
        return group

    def fill_addresses(self):
        current = self.address_combo.currentData() or getattr(self, "saved_address", "0.0.0.0")
        self.address_combo.blockSignals(True)
        self.address_combo.clear()
        self.address_combo.addItem("All addresses (0.0.0.0)", "0.0.0.0")
        for adapter in self.window.snapshot.real_adapters():
            for address in adapter.ipv4:
                self.address_combo.addItem(f"{address.ip}  ({adapter.name})", str(address.ip))
        self.address_combo.setCurrentIndex(max(self.address_combo.findData(current), 0))
        self.address_combo.blockSignals(False)

    def browse_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Folder to Serve", self.folder_input.text())
        if folder:
            self.folder_input.setText(os.path.normpath(folder))

    def open_folder(self):
        folder = self.folder_input.text().strip()
        try:
            os.makedirs(folder, exist_ok=True)
            os.startfile(folder)
        except OSError as error:
            QMessageBox.critical(self, "Open Folder", f"Couldn't open {folder}:\n\n{error}")

    def start_server(self):
        if self.server is not None:
            return
        folder = self.folder_input.text().strip()
        try:
            os.makedirs(folder, exist_ok=True)
        except OSError as error:
            set_invalid(self.folder_input, True)
            set_hint(self.server_status, f"Couldn't use the folder {folder}: {error}", "error")
            return
        set_invalid(self.folder_input, False)
        server = TftpServer(folder, self.address_combo.currentData(), self.port_input.value(),
                            self.upload_check.isChecked(), self.overwrite_check.isChecked(), self.on_server_event)
        try:
            server.start()
        except OSError as error:
            reason = "another program (probably another TFTP server) is using it" \
                if getattr(error, "winerror", None) == 10048 else (error.strerror or str(error))
            set_hint(self.server_status, f"Couldn't start on port {self.port_input.value()}: {reason}.", "error")
            return
        self.server = server
        address = self.address_combo.currentData()
        files = sum(1 for _ in os.scandir(folder) if _.is_file())
        set_hint(self.server_status, f"Serving {folder} ({files} file{'' if files == 1 else 's'}) on {address} port "
                                     f"{self.port_input.value()}. Devices can now fetch files"
                                     f"{' and send files' if self.upload_check.isChecked() else ''}.", "success")
        log.info("TFTP server serving %s on %s:%s", folder, address, self.port_input.value())
        self.window.set_busy("tftp", "TFTP server running")
        self.update_buttons()

    def stop_server(self):
        if self.server is None:
            return
        self.server.stop()
        self.server = None
        self.window.clear_busy("tftp")
        set_hint(self.server_status, "Server stopped.", "info")
        self.update_buttons()

    def update_server_options(self):
        if self.server is not None:
            self.server.allow_upload = self.upload_check.isChecked()
            self.server.allow_overwrite = self.overwrite_check.isChecked()

    def on_server_event(self, transfer):
        """Called from the server's threads."""
        self.events.transfer.emit(transfer, transfer.rate, transfer.finished)

    def show_transfer(self, transfer, rate, finished):
        row = self.rows.get(transfer.id)
        if row is None:
            if self.transfers.rowCount() >= MAX_TRANSFER_ROWS:
                self.clear_transfers()
            row = self.transfers.rowCount()
            self.transfers.insertRow(row)
            self.rows[transfer.id] = row
            for column, text in enumerate([time.strftime("%H:%M:%S"), transfer.peer, transfer.filename,
                                           "Sent" if transfer.direction == "Sent" else "Received"]):
                self.transfers.setItem(row, column, SortableTableItem(text))
            self.transfers.scrollToBottom()
        size = transfer.size
        self.transfers.setItem(row, 4, SortableTableItem(format_size(size) if size is not None else ""))
        progress = f"{transfer.done * 100 // size}%" if size else format_size(transfer.done)
        self.transfers.setItem(row, COL_PROGRESS, SortableTableItem(
            progress if not (finished and transfer.ok) else format_size(transfer.done)))
        self.transfers.setItem(row, COL_SPEED, SortableTableItem(f"{format_size(rate)}/s" if transfer.done else ""))
        status = SortableTableItem(transfer.status)
        if finished:
            status.setForeground(QColor(COLORS["success"] if transfer.ok else COLORS["error"]))
        self.transfers.setItem(row, COL_STATUS, status)

    def clear_transfers(self):
        self.transfers.setRowCount(0)
        self.rows = {}

    def open_firewall(self):
        port = self.port_input.value()
        self.window.run_change(f"Opening UDP port {port} in Windows Firewall",
                               lambda: allow_inbound_port(FIREWALL_RULE, port),
                               on_success=lambda _: self.window.show_status(
                                   f"Windows Firewall now lets TFTP requests in on UDP port {port}."))

    # ----------------------------------------------------------------- Client

    def build_client_group(self):
        group = QGroupBox("TFTP Client")
        layout = QVBoxLayout(group)
        server_row = QHBoxLayout()
        self.client_host = QLineEdit()
        self.client_host.setPlaceholderText("TFTP server's address")
        self.client_port = QSpinBox()
        self.client_port.setRange(1, 65535)
        self.client_port.setValue(TFTP_PORT)
        self.block_size = QSpinBox()
        self.block_size.setRange(MIN_BLOCK_SIZE, MAX_BLOCK_SIZE)
        self.block_size.setValue(CLIENT_BLOCK_SIZE)
        self.block_size.setToolTip("Bigger blocks are faster. Servers that don't support larger blocks fall back to "
                                   "512 bytes automatically.")
        for spin_box in (self.client_port, self.block_size):
            spin_box.setButtonSymbols(QSpinBox.NoButtons)
        server_row.addWidget(self.client_host, 1)
        server_row.addWidget(QLabel("Port:"))
        server_row.addWidget(self.client_port)
        server_row.addWidget(QLabel("Block size:"))
        server_row.addWidget(self.block_size)
        self.remote_input = QLineEdit()
        self.remote_input.setPlaceholderText("File name on the server, such as firmware.bin or configs/switch1.cfg")
        local_row = QHBoxLayout()
        self.local_input = QLineEdit()
        self.local_input.setPlaceholderText("File on this computer")
        self.local_browse = QPushButton("Browse...")
        local_row.addWidget(self.local_input, 1)
        local_row.addWidget(self.local_browse)
        form = QFormLayout()
        form.addRow("Server:", server_row)
        form.addRow("Remote file:", self.remote_input)
        form.addRow("Local file:", local_row)
        layout.addLayout(form)

        buttons = QHBoxLayout()
        self.download_button = accent_button("Download")
        self.download_button.setToolTip("Get the remote file from the server and save it as the local file.")
        self.upload_button = QPushButton("Upload")
        self.upload_button.setToolTip("Send the local file to the server as the remote file name.")
        self.client_stop = QPushButton("Stop")
        for button in (self.download_button, self.upload_button, self.client_stop):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.client_progress = QProgressBar()
        layout.addWidget(self.client_progress)
        self.client_status = QLabel()
        self.client_status.setWordWrap(True)
        layout.addWidget(self.client_status)

        self.local_browse.clicked.connect(self.browse_local)
        self.download_button.clicked.connect(lambda: self.start_client("download"))
        self.upload_button.clicked.connect(lambda: self.start_client("upload"))
        self.client_stop.clicked.connect(self.stop_client)
        self.remote_input.textEdited.connect(self.suggest_local_name)
        return group

    def browse_local(self):
        current = self.local_input.text() or os.path.join(os.path.expanduser("~"), "Documents")
        path, _ = QFileDialog.getSaveFileName(self, "Local File", current, "All files (*)",
                                              options=QFileDialog.DontConfirmOverwrite)
        if path:
            self.local_input.setText(os.path.normpath(path))

    def suggest_local_name(self, remote):
        """Keep the local file's folder but follow the remote file's name, until the user edits the local file."""
        local = self.local_input.text()
        if remote and (not local or os.path.basename(local) == getattr(self, "suggested_name", None)):
            folder = os.path.dirname(local) if local else os.path.join(os.path.expanduser("~"), "Documents")
            self.suggested_name = os.path.basename(remote.replace("\\", "/"))
            self.local_input.setText(os.path.join(folder, self.suggested_name))

    def start_client(self, direction):
        if self.client_worker is not None:
            return
        host, remote, local = self.client_host.text().strip(), self.remote_input.text().strip(), \
            self.local_input.text().strip()
        missing = [(widget, text) for widget, value, text in (
            (self.client_host, host, "Enter the TFTP server's address."),
            (self.remote_input, remote, "Enter the file's name on the server."),
            (self.local_input, local, "Choose the file on this computer.")) if not value]
        if missing:
            set_invalid(missing[0][0], True)
            set_hint(self.client_status, missing[0][1], "error")
            return
        for widget in (self.client_host, self.remote_input, self.local_input):
            set_invalid(widget, False)
        if direction == "upload" and not os.path.isfile(local):
            set_invalid(self.local_input, True)
            set_hint(self.client_status, f"{local} doesn't exist.", "error")
            return
        if direction == "download" and os.path.exists(local):
            reply = QMessageBox.question(self, "Replace File", f"{local} already exists. Replace it?",
                                         QMessageBox.Yes | QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        self.client_progress.setRange(0, 0)
        verb = "Downloading" if direction == "download" else "Uploading"
        set_hint(self.client_status, f"{verb} {remote} {'from' if direction == 'download' else 'to'} {host}...",
                 "info")
        self.client_worker = ClientThread(direction, host, self.client_port.value(), remote, local,
                                          self.block_size.value(), self)
        self.client_worker.progress.connect(self.on_client_progress)
        self.client_worker.finished_transfer.connect(self.on_client_finished)
        self.client_worker.finished.connect(self.on_client_thread_finished)
        self.client_worker.start()
        self.update_buttons()

    def on_client_progress(self, done, total):
        if total:
            self.client_progress.setRange(0, 1000)
            self.client_progress.setValue(int(done * 1000 / total))
            self.client_progress.setFormat(f"{format_size(done)} of {format_size(total)}")
        else:
            self.client_progress.setRange(0, 0)
            self.client_progress.setFormat(format_size(done))

    def on_client_finished(self, message, kind):
        self.client_progress.setRange(0, 1)
        self.client_progress.setValue(1 if kind == "success" else 0)
        self.client_progress.setFormat("")
        set_hint(self.client_status, message, kind)
        log.info(message)

    def on_client_thread_finished(self):
        self.client_worker.deleteLater()
        self.client_worker = None
        self.update_buttons()

    def stop_client(self):
        if self.client_worker is not None:
            self.client_worker.stop()
            self.client_stop.setEnabled(False)

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        # Both sections are visible: keep the shortcut in the section the user is working in.
        focus = QApplication.focusWidget()
        target = self.folder_input if focus is not None and self.server_group.isAncestorOf(focus) else self.client_host
        target.setFocus()
        target.selectAll()

    def save_settings(self, settings):
        settings.setValue("tftp/folder", self.folder_input.text())
        settings.setValue("tftp/address", self.address_combo.currentData())
        settings.setValue("tftp/port", self.port_input.value())
        settings.setValue("tftp/uploads", self.upload_check.isChecked())
        settings.setValue("tftp/overwrite", self.overwrite_check.isChecked())
        settings.setValue("tftp/client_host", self.client_host.text())
        settings.setValue("tftp/client_port", self.client_port.value())
        settings.setValue("tftp/block_size", self.block_size.value())
        settings.setValue("tftp/remote", self.remote_input.text())
        settings.setValue("tftp/local", self.local_input.text())

    def restore_settings(self, settings):
        self.folder_input.setText(settings.value("tftp/folder", default_folder(), str))
        self.saved_address = settings.value("tftp/address", "0.0.0.0", str)
        self.fill_addresses()
        self.port_input.setValue(settings.value("tftp/port", TFTP_PORT, int))
        self.upload_check.setChecked(settings.value("tftp/uploads", True, bool))
        self.overwrite_check.setChecked(settings.value("tftp/overwrite", False, bool))
        self.client_host.setText(settings.value("tftp/client_host", "", str))
        self.client_port.setValue(settings.value("tftp/client_port", TFTP_PORT, int))
        self.block_size.setValue(settings.value("tftp/block_size", CLIENT_BLOCK_SIZE, int))
        self.remote_input.setText(settings.value("tftp/remote", "", str))
        self.local_input.setText(settings.value("tftp/local", "", str))

    def shutdown(self):
        self.stop_server()
        if self.client_worker is not None:
            self.client_worker.stop()
            self.client_worker.wait(5000)

    def update_buttons(self):
        serving = self.server is not None
        self.server_start.setEnabled(not serving)
        self.server_stop.setEnabled(serving)
        for widget in (self.folder_input, self.folder_browse, self.address_combo, self.port_input):
            widget.setEnabled(not serving)
        transferring = self.client_worker is not None
        self.download_button.setEnabled(not transferring)
        self.upload_button.setEnabled(not transferring)
        self.client_stop.setEnabled(transferring and not self.client_worker.stopping)
