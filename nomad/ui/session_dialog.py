"""Session editor: everything about how to connect to a device, for any of the protocols."""
from PyQt5.QtWidgets import QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, \
    QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QStackedWidget, QVBoxLayout, QWidget

from ..terminal.credentials import CredentialError
from ..terminal.sessions import AUTH_KEY, AUTH_PASSWORD, BAUD_RATES, DEFAULT_PORTS, ENCODINGS, FLOW_CONTROLS, \
    LINE_ENDINGS, PARITIES, TERMINAL_PROTOCOLS, RAW, SERIAL, SSH, TELNET, validate_session
from ..terminal.transports import serial_ports
from .common import set_hint
from .credential_dialogs import AUTH_CHOICES, SAVED_PLACEHOLDER, CredentialPicker, default_credential_id, \
    secret_to_store

TERMINAL_TYPES = ["xterm-256color", "xterm", "vt100", "vt220", "linux"]


class SerialPortCombo(QComboBox):
    """The COM ports on this computer, with their descriptions ("COM3  (USB Serial Port)"). Editable, so a port that
    isn't plugged in yet can still be typed, and it looks again each time it's opened (after plugging in a cable)."""

    def __init__(self, current="", parent=None):
        super().__init__(parent)
        self.setEditable(True)
        self.setInsertPolicy(QComboBox.NoInsert)
        self.fill(current)

    def fill(self, current=None):
        current = self.port() if current is None else current
        self.clear()
        try:
            ports = serial_ports()
        except Exception:  # Listing ports is a convenience; the name can still be typed
            ports = []
        for device, description in ports:
            self.addItem(f"{device}  ({description})" if description and description != device else device, device)
        self.lineEdit().setPlaceholderText("COM port" if ports else "No COM ports found; type one")
        index = self.findData(current) if current else (0 if ports else -1)
        if index >= 0:
            self.setCurrentIndex(index)
        else:
            self.setEditText(current or "")

    def showPopup(self):
        self.fill()
        self.view().setMinimumWidth(self.view().sizeHintForColumn(0) + 24)  # Whole descriptions, even when narrow
        super().showPopup()

    def port(self):
        """The chosen port's name (COM3), or what was typed."""
        text = self.currentText().strip()
        index = self.findText(text)
        if index >= 0 and self.itemData(index):
            return self.itemData(index)
        return text.split()[0] if text else ""


class SessionDialog(QDialog):
    def __init__(self, parent, session, folders, title="Session", store=None):
        super().__init__(parent)
        self.session = session
        self.store = store  # For the master password, if one is set
        self.setWindowTitle(title)
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)

        general = QFormLayout()
        self.name_input = QLineEdit(session.name)
        self.folder_combo = QComboBox()
        self.folder_combo.setEditable(True)
        self.folder_combo.addItem("")
        self.folder_combo.addItems(sorted(folders, key=str.lower))
        self.folder_combo.setCurrentText(session.folder)
        self.folder_combo.lineEdit().setPlaceholderText("Top level, or a folder such as Site A/Core")
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(TERMINAL_PROTOCOLS)
        self.protocol_combo.setCurrentText(session.protocol)
        general.addRow("Name:", self.name_input)
        general.addRow("Folder:", self.folder_combo)
        general.addRow("Protocol:", self.protocol_combo)
        layout.addLayout(general)

        # Where to connect: a host and port, or a serial port
        self.pages = QStackedWidget()
        self.pages.addWidget(self.build_network_page())
        self.pages.addWidget(self.build_serial_page())
        layout.addWidget(self.pages)

        terminal = QGroupBox("Terminal")
        terminal_form = QFormLayout(terminal)
        self.terminal_combo = QComboBox()
        self.terminal_combo.setEditable(True)
        self.terminal_combo.addItems(TERMINAL_TYPES)
        self.terminal_combo.setCurrentText(session.terminal_type)
        self.encoding_combo = QComboBox()
        self.encoding_combo.setEditable(True)
        self.encoding_combo.addItems(ENCODINGS)
        self.encoding_combo.setCurrentText(session.encoding)
        self.backspace_combo = QComboBox()
        self.backspace_combo.addItems(["Delete (^?)", "Control-H (^H)"])
        self.backspace_combo.setCurrentIndex(0 if session.backspace_sends_delete else 1)
        self.backspace_combo.setToolTip("If Backspace prints ^H or ^? instead of deleting, try the other one.")
        self.scrollback_input = QSpinBox()
        self.scrollback_input.setRange(100, 1000000)
        self.scrollback_input.setSingleStep(1000)
        self.scrollback_input.setValue(session.scrollback)
        self.log_check = QCheckBox("Log everything to a file")
        self.log_check.setChecked(session.log_to_file)
        self.log_folder_input = QLineEdit(session.log_folder)
        self.log_folder_input.setPlaceholderText("Documents\\NOMAD Logs")
        log_browse = QPushButton("Browse...")
        log_row = QHBoxLayout()
        log_row.addWidget(self.log_check)
        log_row.addWidget(self.log_folder_input, 1)
        log_row.addWidget(log_browse)
        terminal_form.addRow("Terminal type:", self.terminal_combo)
        terminal_form.addRow("Character set:", self.encoding_combo)
        terminal_form.addRow("Backspace sends:", self.backspace_combo)
        terminal_form.addRow("Scrollback lines:", self.scrollback_input)
        terminal_form.addRow("Logging:", log_row)
        layout.addWidget(terminal)

        sending = QGroupBox("Sending and Staying Connected")
        sending_form = QFormLayout(sending)
        self.line_delay_input = QSpinBox()
        self.line_delay_input.setRange(0, 5000)
        self.line_delay_input.setSingleStep(50)
        self.line_delay_input.setSuffix(" ms")
        self.line_delay_input.setSpecialValueText("Off")
        self.line_delay_input.setValue(int(session.line_delay))
        self.line_delay_input.setToolTip("When pasting several lines (or sending a command button), send them "
                                         "one at a time this far apart. Consoles and older switches drop "
                                         "characters from a fast paste; 100-300 ms usually fixes it.")
        self.anti_idle_input = QSpinBox()
        self.anti_idle_input.setRange(0, 86400)
        self.anti_idle_input.setSingleStep(30)
        self.anti_idle_input.setSuffix(" s")
        self.anti_idle_input.setSpecialValueText("Off")
        self.anti_idle_input.setValue(int(session.anti_idle))
        self.anti_idle_input.setToolTip("After this long without typing, send the text beside it, so the device "
                                        "doesn't log you out (Cisco exec-timeout, shell TMOUT).")
        self.anti_idle_text_input = QLineEdit(session.anti_idle_text)
        self.anti_idle_text_input.setToolTip("What to send: \\b is Backspace, \\r Enter, \\t Tab, \\e Esc, "
                                             "\\xNN any character. A space then Backspace (\" \\b\") "
                                             "leaves nothing to see at a prompt.")
        anti_idle_row = QHBoxLayout()
        anti_idle_row.addWidget(self.anti_idle_input)
        anti_idle_row.addWidget(QLabel("then send:"))
        anti_idle_row.addWidget(self.anti_idle_text_input, 1)
        self.reconnect_check = QCheckBox("Reconnect automatically when the connection drops")
        self.reconnect_check.setChecked(bool(session.auto_reconnect))
        self.reconnect_check.setToolTip("Such as a device reloading: NOMAD keeps trying every 10 seconds until "
                                        "it's back (for up to half an hour). Not after you type exit or "
                                        "logout, or disconnect it yourself.")
        sending_form.addRow("Line delay:", self.line_delay_input)
        sending_form.addRow("Anti-idle:", anti_idle_row)
        sending_form.addRow("", self.reconnect_check)
        layout.addWidget(sending)

        self.notes_input = QLineEdit(session.notes)
        self.notes_input.setPlaceholderText("Optional notes, such as the device's location")
        notes = QFormLayout()
        notes.addRow("Notes:", self.notes_input)
        layout.addLayout(notes)

        self.error_label = QLabel()
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.save)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.protocol_combo.currentTextChanged.connect(self.on_protocol_changed)
        log_browse.clicked.connect(self.browse_log_folder)
        self.previous_protocol = session.protocol
        self.on_protocol_changed(session.protocol)

    def build_network_page(self):
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        self.host_input = QLineEdit(self.session.host)
        self.host_input.setPlaceholderText("Host name or IP address")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(int(self.session.port))
        host_row = QHBoxLayout()
        host_row.addWidget(self.host_input, 1)
        host_row.addWidget(QLabel("Port:"))
        host_row.addWidget(self.port_input)
        form.addRow("Host:", host_row)

        self.ssh_group = QGroupBox("SSH")
        ssh_form = QFormLayout(self.ssh_group)
        self.credential_picker = None
        self.own_login = None  # What was typed for this session, kept while a saved credential is chosen
        if self.store is not None:
            self.credential_picker = CredentialPicker(self, self.store, SSH,
                                                      default_credential_id(self.store, self.session))
            ssh_form.addRow("Credential:", self.credential_picker)
        self.username_input = QLineEdit(self.session.username)
        self.username_input.setPlaceholderText("Asked when connecting if left blank")
        self.auth_combo = QComboBox()
        for value, label in AUTH_CHOICES:
            self.auth_combo.addItem(label, value)
        self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(self.session.auth)))
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.save_password_check = QCheckBox("Save (encrypted)")
        self.save_password_check.setChecked(bool(self.session.saved_password))
        if self.session.saved_password:
            self.password_input.setPlaceholderText(SAVED_PLACEHOLDER)
        password_row = QHBoxLayout()
        password_row.addWidget(self.password_input, 1)
        password_row.addWidget(self.save_password_check)
        self.key_input = QLineEdit(self.session.key_file)
        self.key_input.setPlaceholderText("OpenSSH private key, such as C:\\Users\\you\\.ssh\\id_ed25519")
        key_browse = QPushButton("Browse...")
        key_row = QHBoxLayout()
        key_row.addWidget(self.key_input, 1)
        key_row.addWidget(key_browse)
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.Password)
        self.save_passphrase_check = QCheckBox("Save (encrypted)")
        self.save_passphrase_check.setChecked(bool(self.session.saved_passphrase))
        if self.session.saved_passphrase:
            self.passphrase_input.setPlaceholderText(SAVED_PLACEHOLDER)
        else:
            self.passphrase_input.setPlaceholderText("Only if the key is protected; asked when needed")
        passphrase_row = QHBoxLayout()
        passphrase_row.addWidget(self.passphrase_input, 1)
        passphrase_row.addWidget(self.save_passphrase_check)
        self.keepalive_input = QSpinBox()
        self.keepalive_input.setRange(0, 3600)
        self.keepalive_input.setSuffix(" s")
        self.keepalive_input.setSpecialValueText("Off")
        self.keepalive_input.setValue(int(self.session.keepalive))
        self.keepalive_input.setToolTip("Send a keepalive this often, so firewalls don't drop an idle session.")
        self.file_protocol_combo = QComboBox()
        for value, label in (("Auto", "Auto (SFTP if the server has it, otherwise SCP)"), ("SFTP", "SFTP only"),
                             ("SCP", "SCP (browse with ls)")):
            self.file_protocol_combo.addItem(label, value)
        self.file_protocol_combo.setCurrentIndex(max(0, self.file_protocol_combo.findData(
            self.session.file_protocol)))
        self.file_protocol_combo.setToolTip("How the SCP page moves files. Choose SCP for servers whose SFTP is "
                                            "broken rather than missing (SCP transfers can't resume).")
        self.scp_sudo_check = QCheckBox("Work as root (sudo) on the SCP page")
        self.scp_sudo_check.setChecked(bool(self.session.scp_sudo))
        self.scp_sudo_check.setToolTip("Browse, copy and edit as root, by running SFTP through sudo. NOMAD tries "
                                       "your login password for sudo and asks if that doesn't work.")
        ssh_form.addRow("User name:", self.username_input)
        ssh_form.addRow("Log in with:", self.auth_combo)
        self.password_label = QLabel("Password:")
        ssh_form.addRow(self.password_label, password_row)
        self.key_label = QLabel("Key file:")
        ssh_form.addRow(self.key_label, key_row)
        self.passphrase_label = QLabel("Passphrase:")
        ssh_form.addRow(self.passphrase_label, passphrase_row)
        ssh_form.addRow("Keepalive:", self.keepalive_input)
        ssh_form.addRow("File transfer:", self.file_protocol_combo)
        ssh_form.addRow("", self.scp_sudo_check)
        self.password_widgets = [self.password_label, self.password_input, self.save_password_check]
        self.key_widgets = [self.key_label, self.key_input, key_browse, self.passphrase_label, self.passphrase_input,
                            self.save_passphrase_check]
        form.addRow(self.ssh_group)

        self.raw_group = QGroupBox("Options")
        raw_form = QFormLayout(self.raw_group)
        self.raw_enter_combo = QComboBox()
        self.raw_enter_combo.addItems(list(LINE_ENDINGS))
        self.raw_enter_combo.setCurrentText(self.session.line_ending if self.session.protocol == RAW else "CR+LF")
        self.raw_echo_check = QCheckBox("Show what I type (for devices that don't echo)")
        self.raw_echo_check.setChecked(self.session.local_echo)
        raw_form.addRow("Enter sends:", self.raw_enter_combo)
        raw_form.addRow("Local echo:", self.raw_echo_check)
        form.addRow(self.raw_group)

        self.login_widgets = [self.username_input, self.auth_combo, self.password_input, self.save_password_check,
                              self.key_input, key_browse, self.passphrase_input, self.save_passphrase_check]
        self.auth_combo.currentIndexChanged.connect(self.update_auth_fields)
        key_browse.clicked.connect(self.browse_key)
        if self.credential_picker is not None:
            self.credential_picker.combo.currentIndexChanged.connect(self.update_credential_fields)
        self.update_credential_fields()
        return page

    def build_serial_page(self):
        page = QWidget()
        form = QFormLayout(page)
        form.setContentsMargins(0, 0, 0, 0)
        session = self.session
        self.serial_combo = SerialPortCombo(session.serial_port)
        refresh = QPushButton("Refresh")
        refresh.setToolTip("Look for COM ports again (after plugging in a USB console cable).")
        serial_row = QHBoxLayout()
        serial_row.addWidget(self.serial_combo, 1)
        serial_row.addWidget(refresh)
        self.baud_combo = QComboBox()
        self.baud_combo.setEditable(True)
        self.baud_combo.addItems([str(rate) for rate in BAUD_RATES])
        self.baud_combo.setCurrentText(str(session.baud_rate))
        self.data_bits_combo = QComboBox()
        self.data_bits_combo.addItems(["5", "6", "7", "8"])
        self.data_bits_combo.setCurrentText(str(session.data_bits))
        self.parity_combo = QComboBox()
        self.parity_combo.addItems(PARITIES)
        self.parity_combo.setCurrentText(session.parity)
        self.stop_bits_combo = QComboBox()
        self.stop_bits_combo.addItems(["1", "1.5", "2"])
        stop = float(session.stop_bits)
        self.stop_bits_combo.setCurrentText(str(int(stop)) if stop.is_integer() else str(stop))
        self.flow_combo = QComboBox()
        self.flow_combo.addItems(FLOW_CONTROLS)
        self.flow_combo.setCurrentText(session.flow_control)
        self.serial_enter_combo = QComboBox()
        self.serial_enter_combo.addItems(list(LINE_ENDINGS))
        self.serial_enter_combo.setCurrentText(session.line_ending if session.protocol == SERIAL else "CR")
        self.serial_echo_check = QCheckBox("Show what I type (for devices that don't echo)")
        self.serial_echo_check.setChecked(session.local_echo)
        form.addRow("Serial port:", serial_row)
        form.addRow("Speed (baud):", self.baud_combo)
        form.addRow("Data bits:", self.data_bits_combo)
        form.addRow("Parity:", self.parity_combo)
        form.addRow("Stop bits:", self.stop_bits_combo)
        form.addRow("Flow control:", self.flow_combo)
        form.addRow("Enter sends:", self.serial_enter_combo)
        form.addRow("Local echo:", self.serial_echo_check)
        hint = QLabel("Most switch and router consoles use 9600 baud, 8 data bits, no parity, 1 stop bit and no "
                      "flow control (9600 8N1).")
        hint.setWordWrap(True)
        form.addRow(hint)
        refresh.clicked.connect(self.fill_serial_ports)
        return page

    def fill_serial_ports(self):
        self.serial_combo.fill()

    def serial_port(self):
        return self.serial_combo.port()

    def on_protocol_changed(self, protocol):
        self.pages.setCurrentIndex(1 if protocol == SERIAL else 0)
        self.ssh_group.setVisible(protocol == SSH)
        self.raw_group.setVisible(protocol == RAW)
        old_default = DEFAULT_PORTS.get(self.previous_protocol)
        if protocol in DEFAULT_PORTS and (self.port_input.value() == old_default or old_default is None):
            self.port_input.setValue(DEFAULT_PORTS[protocol])
        self.previous_protocol = protocol
        self.adjustSize()

    def update_credential_fields(self, *_):
        """A saved credential shows its user name and how it logs in, which can't be changed here."""
        credential = self.credential_picker.credential() if self.credential_picker is not None else None
        if credential is not None:
            if self.own_login is None:
                self.own_login = (self.username_input.text(), self.auth_combo.currentIndex(), self.key_input.text(),
                                  self.save_password_check.isChecked(), self.save_passphrase_check.isChecked())
            self.username_input.setText(credential.username)
            self.auth_combo.setCurrentIndex(max(0, self.auth_combo.findData(credential.auth)))
            self.key_input.setText(credential.key_file)
            self.save_password_check.setChecked(bool(credential.saved_password))
            self.save_passphrase_check.setChecked(bool(credential.saved_passphrase))
            self.password_input.clear()
            self.passphrase_input.clear()
            self.password_input.setPlaceholderText(f"Saved in {credential.name}" if credential.saved_password else
                                                   f"Asked when connecting ({credential.name} has none saved)")
            self.passphrase_input.setPlaceholderText(f"Saved in {credential.name}" if credential.saved_passphrase else
                                                     "Asked when needed")
        else:
            if self.own_login is not None:
                username, auth_index, key_file, save_password, save_passphrase = self.own_login
                self.own_login = None
                self.username_input.setText(username)
                self.auth_combo.setCurrentIndex(auth_index)
                self.key_input.setText(key_file)
                self.save_password_check.setChecked(save_password)
                self.save_passphrase_check.setChecked(save_passphrase)
            self.password_input.setPlaceholderText(SAVED_PLACEHOLDER if self.session.saved_password else "")
            self.passphrase_input.setPlaceholderText(
                SAVED_PLACEHOLDER if self.session.saved_passphrase else
                "Only if the key is protected; asked when needed")
        for widget in self.login_widgets:
            widget.setEnabled(credential is None)
        self.update_auth_fields()

    def update_auth_fields(self):
        auth = self.auth_combo.currentData()
        for widget in self.password_widgets:
            widget.setVisible(auth == AUTH_PASSWORD)
        for widget in self.key_widgets:
            widget.setVisible(auth == AUTH_KEY)

    def browse_key(self):
        path, _ = QFileDialog.getOpenFileName(self, "Private Key", self.key_input.text() or "", "All files (*)")
        if path:
            self.key_input.setText(path.replace("/", "\\"))

    def browse_log_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Log Folder", self.log_folder_input.text())
        if folder:
            self.log_folder_input.setText(folder.replace("/", "\\"))

    def save(self):
        session = self.session.copy(id=self.session.id)
        session.name = self.name_input.text().strip()
        session.folder = self.folder_combo.currentText().strip()
        session.protocol = self.protocol_combo.currentText()
        session.terminal_type = self.terminal_combo.currentText().strip() or "xterm-256color"
        session.encoding = self.encoding_combo.currentText().strip() or "utf-8"
        session.backspace_sends_delete = self.backspace_combo.currentIndex() == 0
        session.scrollback = self.scrollback_input.value()
        session.log_to_file = self.log_check.isChecked()
        session.log_folder = self.log_folder_input.text().strip()
        session.line_delay = self.line_delay_input.value()
        session.anti_idle = self.anti_idle_input.value()
        session.anti_idle_text = self.anti_idle_text_input.text()
        session.auto_reconnect = self.reconnect_check.isChecked()
        session.notes = self.notes_input.text().strip()
        if session.protocol == SERIAL:
            session.serial_port = self.serial_port()
            try:
                session.baud_rate = int(self.baud_combo.currentText())
            except ValueError:
                set_hint(self.error_label, "The speed must be a number, such as 9600.", "error")
                return
            session.data_bits = int(self.data_bits_combo.currentText())
            session.parity = self.parity_combo.currentText()
            session.stop_bits = float(self.stop_bits_combo.currentText())
            session.flow_control = self.flow_combo.currentText()
            session.line_ending = self.serial_enter_combo.currentText()
            session.local_echo = self.serial_echo_check.isChecked()
        else:
            session.host = self.host_input.text().strip()
            session.port = self.port_input.value()
            if session.protocol == RAW:
                session.line_ending = self.raw_enter_combo.currentText()
                session.local_echo = self.raw_echo_check.isChecked()
            elif session.protocol == TELNET:
                session.local_echo = False
        session.credential_id = ""
        if session.protocol == SSH and self.credential_picker is not None and self.credential_picker.credential():
            session.credential_id = self.credential_picker.credential_id()
            session.keepalive = self.keepalive_input.value()
            session.file_protocol = self.file_protocol_combo.currentData()
            session.scp_sudo = self.scp_sudo_check.isChecked()
            self.store.credentials.apply(session)
        elif session.protocol == SSH:
            session.username = self.username_input.text().strip()
            session.auth = self.auth_combo.currentData()
            session.key_file = self.key_input.text().strip()
            session.keepalive = self.keepalive_input.value()
            session.file_protocol = self.file_protocol_combo.currentData()
            session.scp_sudo = self.scp_sudo_check.isChecked()
            try:
                session.saved_password = secret_to_store(self, self.store, self.password_input,
                                                         self.save_password_check, self.session.saved_password)
                session.saved_passphrase = secret_to_store(self, self.store, self.passphrase_input,
                                                           self.save_passphrase_check, self.session.saved_passphrase)
            except CredentialError as error:
                QMessageBox.critical(self, "Save Password", str(error))
                return
        error = validate_session(session)
        if error:
            set_hint(self.error_label, error, "error")
            return
        self.session = session
        self.accept()

