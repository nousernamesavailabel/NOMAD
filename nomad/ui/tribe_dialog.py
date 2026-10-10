"""Tools > Tribe Management: connect to the tribe with a tribe key file or disconnect this computer from it (the only
place to leave the tribe), and turn this computer into the tribe server (the NOMAD IPAM Server Windows service),
handing out the tribe key file others connect with, or move the tribe server to another computer (see
nomad/ipam/migrate.py). The tribe shares both IPAM networks and network maps."""
import logging
import os

from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, \
    QInputDialog, QLabel, QLineEdit, QMessageBox, QPushButton, QSpinBox, QVBoxLayout

from ..ipam import service
from ..ipam.client import admin_key, load_saved_key
from ..ipam.migrate import MOVE_FILE_SUFFIX, MoveFile, existing_server, export_server, import_server, moved, \
    undo_move
from ..ipam.server import DEFAULT_PORT, KEY_FILE_SUFFIX, change_team_secret, fingerprint_of_file, load_config, \
    server_dir, write_team_key
from ..ipam.store import IpamError
from .common import run_in_background, set_hint
from .theme import accent_button
from .tribe_join_dialog import connect_to_tribe
from .tribe_move_dialog import MoveOutDialog

log = logging.getLogger(__name__)


class TribeDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Tribe Management")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        intro = QLabel("The tribe is the people sharing IPAM networks and network maps through one tribe server. "
                       "Connect to it with the tribe key file, or make this computer the tribe server.")
        intro.setWordWrap(True)
        layout.addWidget(intro)

        member_box = QGroupBox("This computer")
        member_layout = QVBoxLayout(member_box)
        self.member_label = QLabel()
        self.member_label.setWordWrap(True)
        member_layout.addWidget(self.member_label)
        member_row = QHBoxLayout()
        self.join_button = QPushButton("Connect with Key File...")
        self.join_button.setToolTip("Save a tribe key file's key for your Windows account (encrypted). The IP "
                                    "Addresses and Network Map pages both use it.")
        self.disconnect_button = QPushButton("Disconnect from the Tribe...")
        self.disconnect_button.setToolTip("Forget the saved tribe key and the copies of the tribe's networks and "
                                          "maps on this computer. Your own networks and maps are kept.")
        member_row.addWidget(self.join_button)
        member_row.addWidget(self.disconnect_button)
        member_row.addStretch()
        member_layout.addLayout(member_row)
        layout.addWidget(member_box)

        server_box = QGroupBox("Tribe server")
        server_layout = QVBoxLayout(server_box)
        server_intro = QLabel("Make this computer the tribe server: it keeps the shared copy of the tribe's networks "
                              "and maps and sends changes to NOMAD on every laptop. It runs as the NOMAD IPAM Server "
                              "Windows service, so it keeps working when nobody is signed in.")
        server_intro.setWordWrap(True)
        server_layout.addWidget(server_intro)
        form = QFormLayout()
        self.status_label = QLabel()
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(service.configured_port() or DEFAULT_PORT)
        self.port_input.setToolTip("The TCP port laptops connect to. Installing opens it in Windows Firewall.")
        self.folder_label = QLabel(str(server_dir()))
        self.fingerprint_label = QLabel()
        self.fingerprint_label.setWordWrap(True)
        form.addRow("Service:", self.status_label)
        form.addRow("Port:", self.port_input)
        form.addRow("Data folder:", self.folder_label)
        form.addRow("Certificate:", self.fingerprint_label)
        server_layout.addLayout(form)

        service_row = QHBoxLayout()
        self.install_button = accent_button("Install Service")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.uninstall_button = QPushButton("Uninstall...")
        for button in (self.install_button, self.start_button, self.stop_button, self.uninstall_button):
            service_row.addWidget(button)
        service_row.addStretch()
        server_layout.addLayout(service_row)
        key_row = QHBoxLayout()
        self.save_key_button = QPushButton("Save Tribe Key File...")
        self.save_key_button.setToolTip("The file others join the tribe with (here, or from Tribe on the IP Addresses "
                                        "or Network Map page). Anyone with it can change the tribe's IPAM and maps.")
        self.change_key_button = QPushButton("Change Tribe Key...")
        self.change_key_button.setToolTip("Lock out every copy of the current tribe key file, for example after a "
                                          "laptop is lost. Laptops then need the new file.")
        self.open_folder_button = QPushButton("Open Data Folder")
        for button in (self.save_key_button, self.change_key_button, self.open_folder_button):
            key_row.addWidget(button)
        key_row.addStretch()
        server_layout.addLayout(key_row)
        move_row = QHBoxLayout()
        self.move_out_button = QPushButton("Move to Another Computer...")
        self.move_out_button.setToolTip("Save everything the tribe server keeps in a move file for the new computer, "
                                        "and point laptops there. They keep their copies and pending changes.")
        self.move_in_button = QPushButton("Set Up from Move File...")
        self.move_in_button.setToolTip("Make this computer the tribe server, carrying on from the move file saved "
                                       "on the old one (same data, certificate and tribe key).")
        self.undo_move_button = QPushButton("Undo Move...")
        self.undo_move_button.setToolTip("Put this server back in service, if the move is called off.")
        for button in (self.move_out_button, self.move_in_button, self.undo_move_button):
            move_row.addWidget(button)
        move_row.addStretch()
        server_layout.addLayout(move_row)
        self.admin_label = QLabel()
        self.admin_label.setWordWrap(True)
        server_layout.addWidget(self.admin_label)
        layout.addWidget(server_box)

        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.join_button.clicked.connect(self.join)
        self.disconnect_button.clicked.connect(self.leave_tribe)
        self.install_button.clicked.connect(self.install)
        self.start_button.clicked.connect(lambda: self.run("Starting the service...", service.start, "Started."))
        self.stop_button.clicked.connect(lambda: self.run("Stopping the service...", service.stop, "Stopped."))
        self.uninstall_button.clicked.connect(self.uninstall)
        self.save_key_button.clicked.connect(self.save_key)
        self.change_key_button.clicked.connect(self.change_key)
        self.open_folder_button.clicked.connect(lambda: os.startfile(server_dir()))
        self.move_out_button.clicked.connect(self.move_out)
        self.move_in_button.clicked.connect(self.move_in)
        self.undo_move_button.clicked.connect(self.undo_move)
        self.busy = False
        self.refresh()

    def refresh(self):
        admin = getattr(self.window, "admin", False)
        state = service.status()
        self.refresh_membership(admin, state)
        configured = (server_dir() / "config.json").exists()
        moved_to = moved() if configured and admin else None
        if moved_to:
            where = ", ".join(moved_to.get("hosts") or []) or "an address not given (laptops need the new key file)"
            self.status_label.setText(f"{state}; moved to {where}. It only points laptops there now.")
        else:
            self.status_label.setText(state)
        try:
            self.fingerprint_label.setText(f"Self-signed; fingerprint {fingerprint_of_file(server_dir() / 'cert.pem')}"
                                           if configured and admin else "Created when the service is installed")
        except OSError:
            self.fingerprint_label.setText("Created when the service is installed")
        idle = admin and not self.busy
        self.install_button.setText("Update Service" if state != service.NOT_INSTALLED else "Install Service")
        self.install_button.setToolTip("Install it again from this copy of NOMAD (after updating NOMAD, or to change "
                                       "the port). The data and tribe key are kept." if state != service.NOT_INSTALLED
                                       else "Set up the server's data folder, certificate and tribe key, install the "
                                            "service, open the port in Windows Firewall and start it.")
        self.install_button.setEnabled(idle)
        self.port_input.setEnabled(idle)
        self.start_button.setEnabled(idle and state == service.STOPPED)
        self.stop_button.setEnabled(idle and state == service.RUNNING)
        self.uninstall_button.setEnabled(idle and state != service.NOT_INSTALLED)
        for button in (self.save_key_button, self.change_key_button, self.open_folder_button, self.move_out_button):
            button.setEnabled(idle and configured)
        self.move_in_button.setEnabled(idle)
        self.undo_move_button.setVisible(bool(moved_to))
        self.undo_move_button.setEnabled(idle)
        self.admin_label.setVisible(not admin)
        if not admin:
            set_hint(self.admin_label, "Managing the tribe server needs administrator rights: use File > Restart as "
                                       "Administrator, then open this again.", "warning")

    def refresh_membership(self, admin, state):
        saved = load_saved_key()
        if admin and admin_key() is not None:
            set_hint(self.member_label, "This computer is the tribe server, and uses the server's own key.", "success")
        elif saved is not None:
            set_hint(self.member_label, f"In the tribe: server at {', '.join(saved.hosts)} (port {saved.port}). The "
                                        "IP Addresses and Network Map pages share the tribe's networks and maps.",
                     "success")
        elif state != service.NOT_INSTALLED:
            set_hint(self.member_label, "This computer is the tribe server: restart NOMAD as administrator (File > "
                                        "Restart as Administrator) to use its networks and maps.", "info")
        else:
            set_hint(self.member_label, "Not in a tribe. Connect with the tribe key file to share networks and maps.",
                     "info")
        self.join_button.setText("Connect with Another Key File..." if saved is not None else "Connect with Key File...")
        self.disconnect_button.setEnabled(saved is not None and not self.busy)

    def join(self):
        if connect_to_tribe(self, self.window):
            set_hint(self.message_label, "Connected to the tribe. The key is saved, encrypted for your Windows "
                                         "account.", "success")
        self.refresh()

    def leave_tribe(self):
        if self.window.confirm_leave_tribe(self):
            set_hint(self.message_label, "Disconnected from the tribe. Your own networks and maps are kept.",
                     "success")
        self.refresh()

    def run(self, message, action, done, on_done=None):
        """Run a service action on a worker thread (they can take several seconds)."""
        self.busy = True
        set_hint(self.message_label, message, "info")
        self.refresh()

        def succeeded(result):
            self.busy = False
            set_hint(self.message_label, done, "success")
            self.refresh()
            if on_done:
                on_done(result)

        def failed(error):
            self.busy = False
            log.warning("Tribe server: %s failed: %s", message, error)
            set_hint(self.message_label, str(error), "error")
            self.refresh()

        run_in_background(action, succeeded, failed)

    def install(self):
        port = self.port_input.value()
        self.run("Installing the service (this takes a few seconds)...", lambda: service.install(port),
                 f"The tribe server is running on port {port}. Next: Save Tribe Key File and give it to the tribe; "
                 "then import your spreadsheet on the IP Addresses page (it goes to the server).",
                 lambda _: self.window.tribe_key_changed())

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the Tribe Server",
                                "Stop and remove the service and its firewall rule? Laptops can no longer sync or "
                                f"make changes. The data stays in {server_dir()}, so installing again carries on "
                                "where it left off.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", service.uninstall, "Removed. The data is kept.",
                 lambda _: self.window.tribe_key_changed())

    def save_key(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Tribe Key File", f"NOMAD tribe{KEY_FILE_SUFFIX}",
                                              f"NOMAD tribe key (*{KEY_FILE_SUFFIX})")
        if not path:
            return
        try:
            config = load_config()
        except OSError as error:
            log.warning("Couldn't read the tribe server's settings: %s", error)
            set_hint(self.message_label, f"Couldn't read the server's settings in {server_dir()} "
                                         f"({error.strerror or error}). Update Service repairs the folder's "
                                         "permissions.", "error")
            return
        try:
            write_team_key(path, config)
        except OSError as error:
            log.warning("Couldn't save the tribe key file: %s", error)
            set_hint(self.message_label, f"Couldn't save {path}: {error.strerror or error}", "error")
            return
        set_hint(self.message_label, f"Saved {path}. Give it to the tribe (a USB stick or a file share only the "
                                     "tribe can read): anyone with it can change the tribe's IPAM and maps.",
                 "success")

    def move_out(self):
        dialog = MoveOutDialog(self, service.configured_port() or self.port_input.value())
        if dialog.exec_() != QDialog.Accepted:
            return
        path, password, hosts, port = dialog.path, dialog.password, dialog.hosts, dialog.port

        def export():
            running = service.status() == service.RUNNING
            if running:
                service.stop()  # So nothing changes after the export
            try:
                return export_server(path, password, hosts, port)
            finally:
                if running:
                    service.start()  # Moved now: it only points laptops to the new server

        where = (f"Laptops that reach this server now switch to {', '.join(hosts)} by themselves. Leave it running "
                 "until they all have (those away during the move too), then uninstall it." if hosts else
                 "No new address was given, so laptops need the new tribe key file (Save Tribe Key File on the new "
                 "server); they keep their copies and pending changes.")
        self.run("Saving the move file...", export,
                 f"Saved {path}. Take it to the new computer (and give the password separately), run NOMAD as "
                 f"administrator there, and use Tribe Management > Set Up from Move File. {where}",
                 self.report_lost_secrets)

    def report_lost_secrets(self, summary):
        if summary.lost_secrets:
            QMessageBox.warning(self, "Tribe Maps' SNMP Credentials",
                                f"The SNMP credentials of {summary.lost_secrets} tribe map(s) couldn't be read, so "
                                "they aren't in the move file. Set them again with SNMP Credentials... on the map "
                                "page once the new server is running.")

    def move_in(self):
        path, _ = QFileDialog.getOpenFileName(self, "Set Up from Move File", "",
                                              f"NOMAD tribe server move file (*{MOVE_FILE_SUFFIX});;All files (*)")
        if not path:
            return
        password, ok = QInputDialog.getText(self, "Move File Password", "The move file's password:",
                                            QLineEdit.Password)
        if not ok:
            return
        try:
            move_file = MoveFile(path, password)
        except IpamError as error:
            set_hint(self.message_label, str(error), "error")
            return
        summary = move_file.summary
        here = existing_server()
        replaces = ""
        if here:
            replaces = ("\n\nThis computer already has " + ("this tribe server's data" if here == summary.server_id
                                                            else "a different tribe server") +
                        ", which this replaces. Its folder is kept beside the new one, renamed "
                        "server-before-move-<date>.")
        if QMessageBox.question(self, "Set Up the Tribe Server Here",
                                f"{summary.describe()}\n\nMake this computer the tribe server with it? NOMAD installs "
                                f"the service on port {summary.port} and opens the port in Windows Firewall."
                                f"{replaces}") != QMessageBox.Yes:
            return

        def set_up_here():
            if service.status() != service.NOT_INSTALLED:
                service.stop()
            import_server(move_file)
            return service.install(summary.port)

        self.port_input.setValue(summary.port)
        self.run("Setting the tribe server up from the move file...", set_up_here,
                 f"This computer is the tribe server now, on port {summary.port}. Laptops told this address switch "
                 "over by themselves; give the others a new tribe key file (Save Tribe Key File): they keep their "
                 "copies and pending changes. Delete the move file once you're done: it holds the tribe key.",
                 lambda _: self.window.tribe_key_changed())

    def undo_move(self):
        if QMessageBox.question(self, "Undo the Move",
                                "Put this server back in service? Only do this if nobody has used the new server: "
                                "changes made there stay there, and laptops that switched to it need this server's "
                                "tribe key file again.") != QMessageBox.Yes:
            return
        try:
            undo_move()
        except OSError as error:
            set_hint(self.message_label, f"Couldn't change it: {error.strerror or error}", "error")
            return
        if service.status() == service.RUNNING:
            self.run("Restarting the service...", lambda: (service.stop(), service.start()),
                     "This server is back in service.", lambda _: self.window.tribe_key_changed())
        else:
            set_hint(self.message_label, "This server is back in service once the service is started.", "success")
            self.refresh()

    def change_key(self):
        if QMessageBox.question(self, "Change the Tribe Key",
                                "Make a new tribe key? Every laptop stops syncing until it's given the new tribe key "
                                "file.") != QMessageBox.Yes:
            return
        try:
            change_team_secret()
        except OSError as error:
            set_hint(self.message_label, f"Couldn't change it: {error.strerror or error}", "error")
            return
        if service.status() == service.RUNNING:
            self.run("Restarting the service with the new key...", lambda: (service.stop(), service.start()),
                     "Tribe key changed. Save the new tribe key file and give it to the tribe.")
        else:
            set_hint(self.message_label, "Tribe key changed. Save the new tribe key file and give it to the tribe.",
                     "success")
