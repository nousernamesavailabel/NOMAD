"""Tools > NOMAD Dashboard Service: set up the read-only NOMAD Dashboard web site on this computer (the NOMAD Dashboard
Windows service), its logins, its certificate and the tribe viewer key it reads the tribe with."""
import logging
import os
import webbrowser

from PyQt5 import sip
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QDoubleSpinBox, QFileDialog, QFormLayout, \
    QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QTableWidget, \
    QTableWidgetItem, QVBoxLayout, QAbstractItemView, QHeaderView

from ..dashboard import service as dashboard_service, tls
from ..dashboard.accounts import AccountError, UserFile
from .common import run_in_background, set_hint
from .theme import accent_button

log = logging.getLogger(__name__)


class LoginDialog(QDialog):
    """A new dashboard login, or a new password for one."""

    def __init__(self, parent, name="", kiosk=False, new=True):
        super().__init__(parent)
        self.setWindowTitle("New Dashboard Login" if new else f"New Password for {name}")
        layout = QFormLayout(self)
        self.name_input = QLineEdit(name)
        self.name_input.setMaxLength(64)
        self.name_input.setEnabled(new)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.again_input = QLineEdit()
        self.again_input.setEchoMode(QLineEdit.Password)
        self.kiosk_check = QCheckBox("Kiosk (a wall screen: stays signed in for a year)")
        self.kiosk_check.setChecked(kiosk)
        self.kiosk_check.setVisible(new)
        layout.addRow("Login name:", self.name_input)
        layout.addRow("Password:", self.password_input)
        layout.addRow("Again:", self.again_input)
        layout.addRow("", self.kiosk_check)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addRow(self.message)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.check)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def check(self):
        if self.password_input.text() != self.again_input.text():
            set_hint(self.message, "The passwords aren't the same.", "error")
            return
        self.accept()


class DashboardDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("NOMAD Dashboard Service")
        self.setMinimumWidth(680)
        self.directory = dashboard_service.dashboard_dir()
        self.users = UserFile(self.directory)
        layout = QVBoxLayout(self)
        intro = QLabel("A read-only web site showing the network's state to people without NOMAD: devices up and "
                       "down, events, traffic, VPNs, IPAM and hosts per subnet, the tribe maps, and trends. It reads "
                       "what the Map Watcher, the Syslog Collector and the Flow Collector on this computer collect, "
                       "and the tribe with a viewer key (which can only read). It never asks the network anything "
                       "itself. Each person signs in with a login made here.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        config = dashboard_service.load_config() if self.readable() else dashboard_service.default_config()
        self.tribe = config.get("tribe")
        self.new_key = None  # A viewer key chosen here (a TeamKey), until installed

        form = QFormLayout()
        self.status_label = QLabel()
        form.addRow("Service:", self.status_label)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(int(config.get("port", dashboard_service.DEFAULT_PORT)))
        self.port_input.setToolTip("The HTTPS port people's browsers connect to (opened in Windows Firewall)")
        form.addRow("HTTPS port:", self.port_input)
        key_row = QHBoxLayout()
        self.key_label = QLabel()
        self.key_label.setWordWrap(True)
        self.key_button = QPushButton("Choose Viewer Key File...")
        self.key_button.setToolTip("A viewer key file, saved on the tribe server (Tools > Tribe Management > Save "
                                   "Viewer Key File)")
        self.make_key_button = QPushButton("Make One Here")
        self.make_key_button.setToolTip("This computer is the tribe server: make the viewer key here")
        key_row.addWidget(self.key_label, 1)
        key_row.addWidget(self.key_button)
        key_row.addWidget(self.make_key_button)
        form.addRow("Tribe:", key_row)
        cert_row = QHBoxLayout()
        self.cert_label = QLabel()
        self.cert_label.setWordWrap(True)
        self.cert_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.import_button = QPushButton("Import Certificate...")
        self.import_button.setToolTip("A certificate from your company's certificate authority (PFX/P12, or PEM with "
                                      "its key), so browsers trust the dashboard without a warning")
        self.self_signed_button = QPushButton("Use Self-Signed")
        cert_row.addWidget(self.cert_label, 1)
        cert_row.addWidget(self.import_button)
        cert_row.addWidget(self.self_signed_button)
        form.addRow("Certificate:", cert_row)
        keep_row = QHBoxLayout()
        self.raw_input = spin(1, 3650, int(config.get("raw_days", 30)), " days")
        self.raw_input.setToolTip("Every sample (each traffic read, each host count) is kept this long")
        self.hourly_input = spin(1, 3650, int(config.get("hourly_days", 365)), " days")
        self.hourly_input.setToolTip("Hourly averages and peaks, and devices' up and down history, are kept this long")
        self.size_input = QDoubleSpinBox()
        self.size_input.setRange(0.1, 500)
        self.size_input.setDecimals(1)
        self.size_input.setSuffix(" GB")
        self.size_input.setValue(float(config.get("max_gb", 2)))
        self.size_input.setToolTip("Past this, the oldest samples go first")
        for label, widget in (("Samples", self.raw_input), ("hourly", self.hourly_input), ("at most", self.size_input)):
            keep_row.addWidget(QLabel(label))
            keep_row.addWidget(widget)
        keep_row.addStretch()
        form.addRow("Keep history:", keep_row)
        layout.addLayout(form)

        logins = QGroupBox("Logins")
        logins_layout = QVBoxLayout(logins)
        self.logins_table = QTableWidget(0, 2)
        self.logins_table.setHorizontalHeaderLabels(["Login name", "Kiosk"])
        self.logins_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.logins_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.logins_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.logins_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.logins_table.verticalHeader().hide()
        self.logins_table.setMaximumHeight(150)
        logins_layout.addWidget(self.logins_table)
        login_row = QHBoxLayout()
        self.add_button = QPushButton("Add...")
        self.password_button = QPushButton("New Password...")
        self.kiosk_button = QPushButton("Kiosk On/Off")
        self.remove_button = QPushButton("Remove...")
        for button in (self.add_button, self.password_button, self.kiosk_button, self.remove_button):
            login_row.addWidget(button)
        login_row.addStretch()
        logins_layout.addLayout(login_row)
        layout.addWidget(logins)

        row = QHBoxLayout()
        self.install_button = accent_button("Install Service")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.uninstall_button = QPushButton("Uninstall...")
        self.folder_button = QPushButton("Open Its Folder")
        self.browse_button = QPushButton("Open in Browser")
        for button in (self.install_button, self.start_button, self.stop_button, self.uninstall_button,
                       self.folder_button, self.browse_button):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.sources_label = QLabel()
        self.sources_label.setWordWrap(True)
        layout.addWidget(self.sources_label)
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.key_button.clicked.connect(self.choose_key)
        self.make_key_button.clicked.connect(self.make_key)
        self.import_button.clicked.connect(self.import_certificate)
        self.self_signed_button.clicked.connect(self.use_self_signed)
        self.add_button.clicked.connect(self.add_login)
        self.password_button.clicked.connect(self.new_password)
        self.kiosk_button.clicked.connect(self.toggle_kiosk)
        self.remove_button.clicked.connect(self.remove_login)
        self.install_button.clicked.connect(self.install)
        self.start_button.clicked.connect(lambda: self.run("Starting the service...", lambda: service().start(
            dashboard_service.spec()), "Started."))
        self.stop_button.clicked.connect(lambda: self.run("Stopping the service...", lambda: service().stop(
            dashboard_service.spec()), "Stopped."))
        self.uninstall_button.clicked.connect(self.uninstall)
        self.folder_button.clicked.connect(self.open_folder)
        self.browse_button.clicked.connect(self.open_browser)
        self.logins_table.itemSelectionChanged.connect(self.refresh)
        self.busy = False
        self.fill_logins()
        self.show_key()
        self.show_certificate()
        self.show_sources()
        self.refresh()

    # ----------------------------------------------------------------- State

    def readable(self):
        try:
            (self.directory / "config.json").stat()
            return True
        except OSError:
            return False

    @property
    def admin(self):
        return bool(getattr(self.window, "admin", False))

    def refresh(self):
        try:
            state = dashboard_service.status()
        except Exception as error:  # pywin32 missing (running from an unusual setup)
            state = f"Unknown ({error})"
        module = service()
        self.status_label.setText(state)
        installed = state != module.NOT_INSTALLED
        idle = self.admin and not self.busy
        has_key = bool(self.tribe or self.new_key)
        self.install_button.setText("Update Service" if installed else "Install Service")
        self.install_button.setEnabled(idle and has_key)
        self.start_button.setEnabled(idle and state == module.STOPPED)
        self.stop_button.setEnabled(idle and state == module.RUNNING)
        self.uninstall_button.setEnabled(idle and installed)
        self.folder_button.setEnabled(self.directory.exists())
        self.browse_button.setEnabled(state == module.RUNNING)
        selected = self.selected_login() is not None
        for button in (self.key_button, self.make_key_button, self.import_button, self.self_signed_button,
                       self.add_button):
            button.setEnabled(idle)
        self.make_key_button.setVisible(self.tribe_server_here())
        for button in (self.password_button, self.kiosk_button, self.remove_button):
            button.setEnabled(idle and selected)
        if not self.admin and not self.busy:
            set_hint(self.message_label, "Setting up the NOMAD Dashboard needs administrator rights: use File > "
                                         "Restart as Administrator, then open this again.", "warning")
        elif not has_key and not self.busy:
            set_hint(self.message_label, "Choose the tribe's viewer key file first: on the tribe server, Tools > "
                                         "Tribe Management > Save Viewer Key File.", "info")

    @staticmethod
    def tribe_server_here():
        from ..ipam.client import admin_key
        return admin_key() is not None

    def show_key(self):
        key = self.new_key
        if key is not None:
            self.key_label.setText(f"Viewer key for {', '.join(key.hosts[:3])} (installed with the service)")
        elif self.tribe:
            role = "viewer key" if self.tribe.get("role") == "viewer" else "tribe key"
            self.key_label.setText(f"{role.capitalize()} for {', '.join(self.tribe.get('hosts', [])[:3])}")
        else:
            self.key_label.setText("No viewer key yet")

    def show_certificate(self):
        about = tls.describe(self.directory) if self.readable() else {}
        if not about:
            self.cert_label.setText("Self-signed, made when it's installed")
            return
        kind = "Self-signed" if about["self_signed"] else f"From {about['issuer']}"
        self.cert_label.setText(f"{kind}, expires {about['expires']}\nSHA-256 {about['fingerprint']}")

    def show_sources(self):
        """Say which of what it reads isn't on this computer."""
        missing = []
        for name, module_name in (("Map Watcher", "netmap.watch_service"), ("Syslog Collector", "syslogs.service"),
                                  ("Flow Collector", "flows.service")):
            try:
                import importlib
                state = importlib.import_module(f"nomad.{module_name}").status()
            except Exception:
                continue
            if state == service().NOT_INSTALLED:
                missing.append(name)
        if missing:
            set_hint(self.sources_label, f"Not installed on this computer: {', '.join(missing)}. The dashboard shows "
                                         "only what's here (the Map Watcher, with Monitor ticked, gives it devices' "
                                         "status and traffic).", "warning")
        else:
            self.sources_label.setText("")

    # ----------------------------------------------------------------- The tribe

    def choose_key(self):
        from ..ipam.client import TeamKeyError, read_key_file
        from ..ipam.server import KEY_FILE_SUFFIX
        path, _ = QFileDialog.getOpenFileName(self, "Choose the Tribe's Viewer Key File", "",
                                              f"Tribe key files (*{KEY_FILE_SUFFIX});;All files (*)")
        if not path:
            return
        try:
            key = read_key_file(path, viewer=True)
        except TeamKeyError as error:
            set_hint(self.message_label, str(error), "error")
            return
        if key.role != "viewer":
            if QMessageBox.question(self, "Not a Viewer Key",
                                    "That's the tribe key, which can change the tribe's maps and IP addresses. A "
                                    "viewer key can only read: save one on the tribe server (Tools > Tribe "
                                    "Management > Save Viewer Key File).\n\nUse this tribe key anyway?",
                                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
                return
        self.new_key = key
        self.show_key()
        set_hint(self.message_label, "Click Install Service (or Update Service) to use it.", "info")
        self.refresh()

    def make_key(self):
        from ..ipam.client import TeamKey
        from ..ipam.server import ensure_viewer_secret, viewer_key
        try:
            config = ensure_viewer_secret()
            data = viewer_key(config)
        except Exception as error:
            set_hint(self.message_label, f"Couldn't make the viewer key: {error}", "error")
            return
        data["hosts"] = ["127.0.0.1"] + [host for host in data["hosts"] if host != "127.0.0.1"]
        self.new_key = TeamKey.from_dict(data)
        self.show_key()
        set_hint(self.message_label, "Click Install Service (or Update Service) to use it.", "info")
        self.refresh()

    # ----------------------------------------------------------------- The certificate

    def secure_folder(self):
        service().secure_service_folder(self.directory)

    def import_certificate(self):
        path, _ = QFileDialog.getOpenFileName(self, "Import a Certificate", "",
                                              "Certificates (*.pfx *.p12 *.pem *.crt *.cer);;All files (*)")
        if not path:
            return
        key_path = None
        if not path.lower().endswith((".pfx", ".p12")):
            with open(path, "rb") as file:
                has_key = b"PRIVATE KEY" in file.read()
            if not has_key:
                key_path, _ = QFileDialog.getOpenFileName(self, "The Certificate's Private Key", "",
                                                          "Keys (*.key *.pem);;All files (*)")
                if not key_path:
                    return
        password, ok = QInputDialog.getText(self, "Import a Certificate", "Its password (leave empty if it has "
                                                                          "none):", QLineEdit.Password)
        if not ok:
            return
        try:
            chain, key = tls.load_import(path, password, key_path)
            tls.check_pair(chain, key)
            self.secure_folder()
            tls.write_pair(self.directory, chain, key)
        except Exception as error:
            set_hint(self.message_label, str(error), "error")
            return
        self.show_certificate()
        self.restart_if_running("The certificate is in use.")

    def use_self_signed(self):
        if QMessageBox.question(self, "Use a Self-Signed Certificate",
                                "Make a new self-signed certificate for this computer? Browsers warn about it until "
                                "they're told to trust it.") != QMessageBox.Yes:
            return
        try:
            self.secure_folder()
            tls.make_self_signed(self.directory)
        except Exception as error:
            set_hint(self.message_label, f"Couldn't make the certificate: {error}", "error")
            return
        self.show_certificate()
        self.restart_if_running("The new certificate is in use.")

    def restart_if_running(self, done):
        if dashboard_service.running():
            self.run("Restarting the service...", dashboard_service.restart, done)
        else:
            set_hint(self.message_label, done.replace("is in use", "will be used when it starts"), "success")

    # ----------------------------------------------------------------- Logins

    def fill_logins(self):
        users = self.users.load() if self.readable() or self.users.path.exists() else {}
        self.logins_table.setRowCount(0)
        for name in sorted(users, key=str.lower):
            row = self.logins_table.rowCount()
            self.logins_table.insertRow(row)
            self.logins_table.setItem(row, 0, QTableWidgetItem(name))
            self.logins_table.setItem(row, 1, QTableWidgetItem("Yes" if users[name].get("kiosk") else ""))

    def selected_login(self):
        rows = self.logins_table.selectionModel().selectedRows() if self.logins_table.selectionModel() else []
        return self.logins_table.item(rows[0].row(), 0).text() if rows else None

    def change_logins(self, action, done):
        try:
            self.secure_folder()
            action()
        except AccountError as error:
            set_hint(self.message_label, str(error), "error")
            return False
        except Exception as error:
            set_hint(self.message_label, f"Couldn't change the logins: {error}", "error")
            return False
        self.fill_logins()
        set_hint(self.message_label, done, "success")
        self.refresh()
        return True

    def add_login(self):
        dialog = LoginDialog(self)
        while dialog.exec_() == QDialog.Accepted:
            name = dialog.name_input.text().strip()
            if self.change_logins(lambda: self.users.add(name, dialog.password_input.text(),
                                                         dialog.kiosk_check.isChecked()),
                                  f"{name} can sign in now (no restart needed)."):
                return

    def new_password(self):
        name = self.selected_login()
        if name is None:
            return
        dialog = LoginDialog(self, name, new=False)
        if dialog.exec_() == QDialog.Accepted:
            self.change_logins(lambda: self.users.set_password(name, dialog.password_input.text()),
                               f"{name}'s password is changed; it's signed out everywhere.")

    def toggle_kiosk(self):
        name = self.selected_login()
        if name is None:
            return
        kiosk = not self.users.load().get(name, {}).get("kiosk")
        self.change_logins(lambda: self.users.set_kiosk(name, kiosk),
                           f"{name} is {'now' if kiosk else 'no longer'} a kiosk login (signed out everywhere).")

    def remove_login(self):
        name = self.selected_login()
        if name is None or QMessageBox.question(self, "Remove a Login", f"Remove {name}? It's signed out "
                                                                        "everywhere.") != QMessageBox.Yes:
            return
        self.change_logins(lambda: self.users.remove(name), f"{name} is removed.")

    # ----------------------------------------------------------------- The service

    def run(self, message, action, done, on_done=None):
        self.busy = True
        set_hint(self.message_label, message, "info")
        self.refresh()

        def succeeded(_):
            if sip.isdeleted(self.message_label):  # The window was closed while it worked: it's done all the same
                log.info("NOMAD Dashboard: %s", done)
                return
            self.busy = False
            if on_done is not None:
                on_done()
            set_hint(self.message_label, done, "success")
            self.show_certificate()
            self.refresh()

        def failed(error):
            log.warning("NOMAD Dashboard: %s failed: %s", message, error)
            if sip.isdeleted(self.message_label):
                return
            self.busy = False
            set_hint(self.message_label, str(error), "error")
            self.refresh()

        run_in_background(action, succeeded, failed)

    def install(self):
        config = dashboard_service.make_config(self.port_input.value(), self.raw_input.value(),
                                               self.hourly_input.value(), self.size_input.value(),
                                               key=self.new_key, tribe=None if self.new_key else self.tribe)
        if not config.get("tribe"):
            set_hint(self.message_label, "Choose the tribe's viewer key file first.", "warning")
            return
        no_logins = not self.users.names()
        port = config["port"]
        log.info("Installing the NOMAD Dashboard on port %s", port)

        def installed():
            self.tribe, self.new_key = config.get("tribe"), None
            self.show_key()

        self.run("Installing the service (this takes a few seconds)...", lambda: dashboard_service.install(config),
                 f"The NOMAD Dashboard is running on https://{host_name()}:{port}/."
                 + (" Add a login for each person who'll use it." if no_logins else ""), installed)

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the NOMAD Dashboard",
                                "Stop and remove the NOMAD Dashboard service and its firewall rule? Its logins and "
                                "history stay in its folder.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", dashboard_service.uninstall, "Removed.")

    def open_folder(self):
        try:
            os.startfile(self.directory)
        except OSError as error:
            set_hint(self.message_label, f"Couldn't open its folder: {error} (it's readable by administrators "
                                         "only).", "error")

    def open_browser(self):
        webbrowser.open(f"https://localhost:{self.port_input.value()}/")


def spin(low, high, value, suffix):
    box = QSpinBox()
    box.setRange(low, high)
    box.setValue(value)
    box.setSuffix(suffix)
    return box


def host_name():
    import socket
    return socket.getfqdn() or socket.gethostname()


def service():
    from ..ipam import service as module  # pywin32 is loaded only when it's needed
    return module
