"""Tools > Tribe Management > Move to Another Computer: what the move file needs (where the new server will be, and a
password for the file). The export itself and setting the new computer up are run by TribeDialog; see
nomad/ipam/migrate.py."""
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QLabel, QLineEdit, QSpinBox, \
    QVBoxLayout

from ..ipam.migrate import MIN_PASSWORD, MOVE_FILE_SUFFIX, parse_hosts
from .common import set_hint


class MoveOutDialog(QDialog):
    def __init__(self, parent, port):
        super().__init__(parent)
        self.setWindowTitle("Move the Tribe Server to Another Computer")
        self.setMinimumWidth(560)
        layout = QVBoxLayout(self)
        intro = QLabel("This saves everything the tribe server keeps (networks and history, tribe maps and their SNMP "
                       "credentials, its certificate and the tribe key) in a move file protected by a password. On "
                       "the new computer, run NOMAD as administrator and use Tribe Management > Set Up from Move "
                       "File.\n\nThe service here is stopped while the file is made, and afterwards only points "
                       "laptops to the new server's address, so no change is left behind. Laptops switch over by "
                       "themselves (keeping their copies and pending changes) when they next reach this server: "
                       "leave it running until they all have, then uninstall it.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.hosts_input = QLineEdit()
        self.hosts_input.setPlaceholderText("Name and/or IP address, e.g. ipam2.example.mil, 10.1.2.3")
        self.hosts_input.setToolTip("Where laptops will find the new server (several separated by commas; they "
                                    "try each). Leave it empty if it isn't known yet: laptops then need the new "
                                    "tribe key file from the new server.")
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(port)
        self.port_input.setToolTip("The port the new server will listen on (the move file sets it up with this).")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        form.addRow("New server's address:", self.hosts_input)
        form.addRow("Port:", self.port_input)
        form.addRow("Password for the file:", self.password_input)
        form.addRow("Password again:", self.confirm_input)
        layout.addLayout(form)
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Cancel)
        self.save_button = buttons.addButton("Save Move File...", QDialogButtonBox.AcceptRole)
        buttons.accepted.connect(self.choose_file)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.path = ""

    @property
    def hosts(self):
        return parse_hosts(self.hosts_input.text())

    @property
    def port(self):
        return self.port_input.value()

    @property
    def password(self):
        return self.password_input.text()

    def choose_file(self):
        if len(self.password) < MIN_PASSWORD:
            set_hint(self.message_label, f"Use a password of at least {MIN_PASSWORD} characters: the file holds the "
                                         "tribe key and the maps' SNMP credentials.", "error")
            return
        if self.password != self.confirm_input.text():
            set_hint(self.message_label, "The two passwords are different.", "error")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Move File", f"NOMAD tribe server{MOVE_FILE_SUFFIX}",
                                              f"NOMAD tribe server move file (*{MOVE_FILE_SUFFIX})")
        if path:
            self.path = path
            self.accept()
