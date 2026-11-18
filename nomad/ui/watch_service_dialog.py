"""Tools > Map Watcher Service: watch tribe maps for new devices from this computer even when NOMAD isn't open (the
NOMAD Map Watcher Windows service)."""
import json
import logging
import os

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, QLineEdit, \
    QListWidget, QListWidgetItem, QMessageBox, QPushButton, QVBoxLayout

from ..ipam.client import current_key
from ..netmap import watch_service
from ..terminal.sessions import AUTH_PASSWORD, SSH
from .common import run_in_background, set_hint
from .credential_dialogs import CredentialPicker
from .netmap_watch import WatchTimers
from .theme import accent_button

log = logging.getLogger(__name__)


class MapWatcherDialog(QDialog):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.setWindowTitle("Map Watcher Service")
        self.setMinimumWidth(620)
        layout = QVBoxLayout(self)
        intro = QLabel("Watch tribe maps for new switches, access points and hosts from this computer, even when "
                       "nobody has NOMAD open. Use a computer that's usually on and can reach the switches over SNMP "
                       "(the tribe server may not). It takes over watching from NOMAD left open elsewhere, and adds "
                       "what it finds to the tribe maps, tagged NEW. Switches can send it syslog (UDP 514) and SNMP "
                       "traps (UDP 162) so it reads a switch the moment something's plugged in.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.status_label = QLabel()
        form.addRow("Service:", self.status_label)
        self.maps_list = QListWidget()
        self.maps_list.setMaximumHeight(140)
        form.addRow("Maps to watch:", self.maps_list)
        self.timers = WatchTimers()
        self.listen_check = QCheckBox("Listen for syslog and SNMP traps (opens UDP 514 and 162 in Windows Firewall)")
        form.addRow(self.timers)
        form.addRow("", self.listen_check)
        self.backups_check = QCheckBox("Run the tribe's scheduled config backups (it gets the devices due first)")
        self.backups_check.setToolTip("The Editor page's config archive: each router, switch, firewall and WLC on the "
                                      "tribe maps is backed up once an interval. The service logs in with the login "
                                      "below (its password is copied into the service's settings, encrypted for this "
                                      "computer).")
        form.addRow("", self.backups_check)
        backup_row = QHBoxLayout()
        self.backup_login = CredentialPicker(self, getattr(window, "session_store", None), SSH, "",
                                             "Choose a saved credential")
        self.backup_enable = QLineEdit()
        self.backup_enable.setEchoMode(QLineEdit.Password)
        self.backup_enable.setPlaceholderText("Enable password (if they log in at >)")
        backup_row.addWidget(self.backup_login, 2)
        backup_row.addWidget(self.backup_enable, 1)
        form.addRow("Backups log in with:", backup_row)
        layout.addLayout(form)
        row = QHBoxLayout()
        self.install_button = accent_button("Install Service")
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.uninstall_button = QPushButton("Uninstall...")
        self.folder_button = QPushButton("Open Its Folder")
        for button in (self.install_button, self.start_button, self.stop_button, self.uninstall_button,
                       self.folder_button):
            row.addWidget(button)
        row.addStretch()
        layout.addLayout(row)
        self.message_label = QLabel()
        self.message_label.setWordWrap(True)
        layout.addWidget(self.message_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.install_button.clicked.connect(self.install)
        self.start_button.clicked.connect(lambda: self.run("Starting the service...", lambda: service().start(
            watch_service.spec()), "Started."))
        self.stop_button.clicked.connect(lambda: self.run("Stopping the service...", lambda: service().stop(
            watch_service.spec()), "Stopped."))
        self.uninstall_button.clicked.connect(self.uninstall)
        self.folder_button.clicked.connect(lambda: os.startfile(watch_service.watcher_dir()))
        self.busy = False
        self.fill()
        self.refresh()

    def configured(self):
        try:
            return watch_service.load_config()
        except (OSError, ValueError):
            return {}

    def fill(self):
        config = self.configured()
        chosen = set(config.get("maps", []))
        page = self.window.netmap_tab
        maps = page.tribe.ensure()
        self.maps_list.clear()
        for item in (maps.maps() if maps is not None else []):
            entry = QListWidgetItem(item["name"])
            entry.setData(Qt.UserRole, item["id"])
            entry.setFlags(entry.flags() | Qt.ItemIsUserCheckable)
            entry.setCheckState(Qt.Checked if item["id"] in chosen or (not chosen and item["id"] == page.tribe_map_id)
                                else Qt.Unchecked)
            self.maps_list.addItem(entry)
        self.timers.set_values(watch_service.config_timers(config))
        self.listen_check.setChecked(config.get("listen", True))
        self.backups_check.setChecked(bool(config.get("backups")))
        if maps is None:
            set_hint(self.message_label, "This computer has no tribe key: connect to the tribe first (Tribe > Connect "
                                         "to the Tribe with a Key File on the Network Map page), then share a map "
                                         "with it.",
                     "warning")
        elif not maps.maps():
            set_hint(self.message_label, "There are no tribe maps yet: share one from the Network Map page "
                                         "(Tribe > Share This Map with the Tribe).", "warning")

    def chosen_maps(self):
        return [self.maps_list.item(row).data(Qt.UserRole) for row in range(self.maps_list.count())
                if self.maps_list.item(row).checkState() == Qt.Checked]

    def refresh(self):
        admin = getattr(self.window, "admin", False)
        try:
            state = watch_service.status()
        except Exception as error:  # pywin32 missing (running from an unusual setup)
            state = f"Unknown ({error})"
        self.state = state
        self.status_label.setText(state)
        installed = state != service().NOT_INSTALLED
        idle = admin and not self.busy
        self.install_button.setText("Update Service" if installed else "Install Service")
        self.install_button.setEnabled(idle and self.maps_list.count() > 0)
        self.start_button.setEnabled(idle and state == service().STOPPED)
        self.stop_button.setEnabled(idle and state == service().RUNNING)
        self.uninstall_button.setEnabled(idle and installed)
        self.folder_button.setEnabled(watch_service.watcher_dir().exists())
        if not admin:
            set_hint(self.message_label, "Installing the Map Watcher needs administrator rights: use File > Restart "
                                         "as Administrator, then open this again.", "warning")

    def run(self, message, action, done):
        self.busy = True
        set_hint(self.message_label, message, "info")
        self.refresh()

        def succeeded(_):
            self.busy = False
            set_hint(self.message_label, done, "success")
            self.refresh()

        def failed(error):
            self.busy = False
            log.warning("Map Watcher: %s failed: %s", message, error)
            set_hint(self.message_label, str(error), "error")
            self.refresh()

        run_in_background(action, succeeded, failed)

    def install(self):
        chosen = self.chosen_maps()
        if not chosen:
            set_hint(self.message_label, "Tick the maps for it to watch.", "warning")
            return
        key = current_key(admin=True)  # On the tribe server itself, its own key (this needs administrator anyway)
        if key is None:
            set_hint(self.message_label, "This computer has no tribe key: connect to the tribe first (Tribe > Connect "
                                         "to the Tribe with a Key File on the Network Map page).", "error")
            return
        backups = None
        if self.backups_check.isChecked():
            backups = self.backup_login_settings()
            if backups is None:
                return
        try:
            config = watch_service.make_config(key, chosen, self.listen_check.isChecked(), self.timers.values(),
                                               backups=backups)
        except Exception as error:
            set_hint(self.message_label, f"Couldn't prepare the service's settings: {error}", "error")
            return
        log.info("Installing the Map Watcher for maps %s", json.dumps(chosen))
        self.run("Installing the service (this takes a few seconds)...", lambda: watch_service.install(config),
                 "The Map Watcher is running. NOMAD open on other computers stands by while it watches; what it "
                 "finds appears on the tribe maps tagged NEW.")

    def backup_login_settings(self):
        """The backup login for the service's config ({"username", "password", ...} as typed), or None (and why,
        said)."""
        store = getattr(self.window, "session_store", None)
        credential = self.backup_login.credential() if store is not None else None
        if credential is None or credential.auth != AUTH_PASSWORD or not credential.saved_password:
            set_hint(self.message_label, "Choose a saved credential with a saved password for the backups: the "
                                         "service has nobody to ask.", "warning")
            return None
        from .vault_dialog import ensure_unlocked
        if not ensure_unlocked(self, store, "The Map Watcher's backups need the credential's password."):
            return None
        try:
            password = store.vault.reveal(credential.saved_password)
        except Exception as error:
            set_hint(self.message_label, f"Couldn't read the credential's password: {error}", "error")
            return None
        return {"username": credential.username, "password": password, "enable": self.backup_enable.text(),
                "label": f"credential {credential.name}", "trust_new": True}

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the Map Watcher",
                                "Stop and remove the Map Watcher service and its firewall rules? NOMAD left open "
                                "with Watch ticked takes over watching.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", watch_service.uninstall, "Removed.")


def service():
    from ..ipam import service as module  # pywin32 is loaded only when it's needed
    return module
