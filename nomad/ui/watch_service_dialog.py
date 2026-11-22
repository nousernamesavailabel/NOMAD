"""Tools > Map Watcher Service: watch tribe maps for new devices from this computer even when NOMAD isn't open (the
NOMAD Map Watcher Windows service), and monitor them and maps on this computer that aren't shared with the tribe."""
import json
import logging
import os
from pathlib import Path

from PyQt5 import sip
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFormLayout, QGroupBox, \
    QHBoxLayout, QInputDialog, QLabel, QListWidget, QListWidgetItem, QMessageBox, QPushButton, QVBoxLayout

from ..ipam.client import current_key
from ..netmap import monitor, store, watch_local, watch_monitor, watch_service
from .common import run_in_background, set_hint
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
                       "traps (UDP 162) so it reads a switch the moment something's plugged in. When the Syslog "
                       "Collector service runs on this computer, it reads syslog from that instead.")
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
                                      "tribe maps is backed up once an interval. The service logs in the way the "
                                      "Editor's Backups tab says (the passwords are copied into the service's "
                                      "settings, encrypted for this computer).")
        form.addRow("", self.backups_check)
        self.backup_logins_label = QLabel()
        self.backup_logins_label.setWordWrap(True)
        self.backup_logins_label.setTextInteractionFlags(Qt.LinksAccessibleByMouse)
        self.backup_logins_label.linkActivated.connect(self.show_editor_logins)
        form.addRow("Backups log in:", self.backup_logins_label)
        layout.addLayout(form)
        layout.addWidget(self.make_monitoring_box())
        layout.addWidget(self.make_local_box())
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

    def make_monitoring_box(self):
        """Monitoring for the NOMAD Dashboard: pings, link counters and IPAM sweeps of the watched maps."""
        box = QGroupBox("Monitoring for the Dashboard")
        form = QFormLayout(box)
        self.monitor_check = QCheckBox("Monitor the watched maps (ping, IP SLA probes, link traffic and tunnels)")
        self.monitor_check.setToolTip("What the NOMAD Dashboard shows as up or down, and its traffic graphs, comes "
                                      "from here. NOMAD's own Monitor tick box on the Network Map still pings from "
                                      "the computer it's open on.")
        form.addRow(self.monitor_check)
        self.ping_combo = interval_combo(watch_monitor.INTERVALS)
        self.counter_combo = interval_combo(watch_monitor.COUNTER_INTERVALS)
        row = QHBoxLayout()
        row.addWidget(QLabel("Ping every"))
        row.addWidget(self.ping_combo)
        row.addSpacing(12)
        row.addWidget(QLabel("Read link traffic every"))
        row.addWidget(self.counter_combo)
        row.addStretch()
        form.addRow(row)
        self.sweep_combo = QComboBox()
        for hours in watch_monitor.SWEEP_HOURS:
            self.sweep_combo.addItem("Never" if not hours else f"every {hours} h", hours)
        self.sweep_combo.setToolTip("Ping every address in the IPAM subnets of the watched maps' tribe networks, and "
                                    "record what answers (Last Seen on the IP Addresses page, and hosts per subnet on "
                                    "the dashboard)")
        self.prefix_combo = QComboBox()
        for prefix in watch_monitor.SWEEP_PREFIXES:
            self.prefix_combo.addItem(f"/{prefix} ({2 ** (32 - prefix) - 2:,} addresses)", prefix)
        self.prefix_combo.setToolTip("Larger subnets are left out (a /16 has 65,534 addresses to ping)")
        row = QHBoxLayout()
        row.addWidget(QLabel("Sweep IPAM subnets"))
        row.addWidget(self.sweep_combo)
        row.addSpacing(12)
        row.addWidget(QLabel("up to"))
        row.addWidget(self.prefix_combo)
        row.addStretch()
        form.addRow(row)
        self.monitor_check.toggled.connect(self.monitoring_toggled)
        return box

    def make_local_box(self):
        """Maps on this computer, not shared with the tribe, for it to monitor (watch_local)."""
        box = QGroupBox("Maps on This Computer (Not Shared with the Tribe)")
        column = QVBoxLayout(box)
        note = QLabel("It monitors these too, without the tribe: their devices' status and uptime show on NOMAD's "
                      "map on this computer and on the NOMAD Dashboard. It doesn't watch them for new devices. It "
                      "keeps a copy of each, with the SNMP credentials set on the Network Map page: click Copy Again "
                      "after the map changes.")
        note.setWordWrap(True)
        column.addWidget(note)
        self.local_list = QListWidget()
        self.local_list.setMaximumHeight(90)
        column.addWidget(self.local_list)
        row = QHBoxLayout()
        self.add_open_button = QPushButton("Add the Map Open")
        self.add_file_button = QPushButton("Add a Map File...")
        self.copy_again_button = QPushButton("Copy Again")
        self.remove_local_button = QPushButton("Remove")
        for button in (self.add_open_button, self.add_file_button, self.copy_again_button, self.remove_local_button):
            row.addWidget(button)
        row.addStretch()
        column.addLayout(row)
        self.add_open_button.clicked.connect(self.add_open_map)
        self.add_file_button.clicked.connect(self.add_map_file)
        self.copy_again_button.clicked.connect(self.copy_again)
        self.remove_local_button.clicked.connect(self.remove_local)
        self.local_entries = []  # {"record_id", "name", "path", "map": NetworkMap to copy in (None: as it is)}
        return box

    def fill_local(self, config):
        self.local_entries = [{"record_id": entry["record_id"], "name": entry.get("name") or "Map",
                               "path": entry.get("path", ""), "map": None} for entry in watch_local.entries(config)]
        self.show_local()

    def show_local(self):
        self.local_list.clear()
        for entry in self.local_entries:
            note = " (copied in when you click Update Service)" if entry["map"] is not None else ""
            item = QListWidgetItem(entry["name"] + note)
            item.setToolTip(entry["path"])
            self.local_list.addItem(item)
        self.refresh_buttons()

    def add_local(self, network_map, path):
        """Add a map (or take a newer copy of one already here)."""
        record_id, made = watch_local.ensure_record_id(network_map)
        if made:  # Its record ID goes with the map, so NOMAD finds the Watcher's monitoring of it
            try:
                store.save(network_map, path)
            except OSError as error:
                set_hint(self.message_label, f"Couldn't save the map: {error}", "error")
                return
        existing = next((entry for entry in self.local_entries if entry["record_id"] == record_id), None)
        if existing is None:
            name, ok = QInputDialog.getText(self, "Map Watcher", "Name it (as NOMAD and the dashboard show it):",
                                            text=Path(path).stem)
            if not ok:
                return
            existing = {"record_id": record_id, "name": name.strip() or Path(path).stem, "path": str(path)}
            self.local_entries.append(existing)
        existing.update(map=network_map, path=str(path))
        self.show_local()
        set_hint(self.message_label, "Click Update Service (or Install Service) to give the Map Watcher the map.",
                 "info")

    def add_open_map(self):
        page = self.window.netmap_tab
        if page.network_map is None or page.tribe_map_id is not None or page.map_path is None:
            set_hint(self.message_label, "Open a map saved on this computer on the Network Map page first (a tribe "
                                         "map goes in the list above).", "warning")
            return
        page.flush_save()
        self.add_local(page.network_map, page.map_path)

    def add_map_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Give the Map Watcher a Map", str(store.maps_dir()),
                                              f"Network maps (*{store.EXTENSION})")
        if not path:
            return
        try:
            network_map = store.load(path)
        except (OSError, ValueError) as error:
            set_hint(self.message_label, f"Couldn't open the map: {error}", "error")
            return
        self.add_local(network_map, Path(path))

    def copy_again(self):
        """Take the maps again from where they were added from (they've changed since)."""
        missing = []
        for entry in self.local_entries:
            try:
                entry["map"] = store.load(entry["path"])
            except (OSError, ValueError):
                missing.append(entry["name"])
        self.show_local()
        if missing:
            set_hint(self.message_label, "Couldn't find " + ", ".join(missing) + " where it was added from: add it "
                     "again with Add a Map File.", "warning")
        else:
            set_hint(self.message_label, "Click Update Service to give the Map Watcher the new copies.", "info")

    def remove_local(self):
        row = self.local_list.currentRow()
        if 0 <= row < len(self.local_entries):
            del self.local_entries[row]
            self.show_local()
            set_hint(self.message_label, "Click Update Service for the Map Watcher to stop monitoring it.", "info")

    def local_maps(self):
        """(entries kept in the config as they are, [(NetworkMap, name, path, credentials JSON)] to copy in)."""
        old = {entry["record_id"]: entry for entry in watch_local.entries(self.configured())}
        kept, copies = [], []
        secrets = self.window.netmap_tab.tribe_secrets()
        for entry in self.local_entries:
            if entry["map"] is not None:
                copies.append((entry["map"], entry["name"], entry["path"], secrets))
            elif entry["record_id"] in old:
                kept.append(dict(old[entry["record_id"]], name=entry["name"]))
        return kept, copies

    def monitoring_toggled(self, on):
        for widget in (self.ping_combo, self.counter_combo, self.sweep_combo, self.prefix_combo):
            widget.setEnabled(on)

    def monitoring(self):
        return {"enabled": self.monitor_check.isChecked(), "interval": self.ping_combo.currentData(),
                "counter_interval": self.counter_combo.currentData(), "sweep_hours": self.sweep_combo.currentData(),
                "sweep_max_prefix": self.prefix_combo.currentData()}

    def set_monitoring(self, config):
        settings = watch_monitor.monitor_settings(config)
        self.monitor_check.setChecked(settings["enabled"])
        for combo, value in ((self.ping_combo, settings["interval"]),
                             (self.counter_combo, settings["counter_interval"]),
                             (self.sweep_combo, settings["sweep_hours"]),
                             (self.prefix_combo, settings["sweep_max_prefix"])):
            index = combo.findData(value)
            if index < 0:
                combo.addItem(str(value), value)
                index = combo.count() - 1
            combo.setCurrentIndex(index)
        self.monitoring_toggled(settings["enabled"])

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
        self.show_backup_logins()
        self.set_monitoring(config)
        self.fill_local(config)
        if maps is None:
            set_hint(self.message_label, "This computer has no tribe key, so the Map Watcher can only monitor maps on "
                                         "this computer (below). To watch tribe maps, connect to the tribe first "
                                         "(Tribe > Connect to the Tribe with a Key File on the Network Map page).",
                     "warning")
        elif not maps.maps():
            set_hint(self.message_label, "There are no tribe maps yet: share one from the Network Map page "
                                         "(Tribe > Share This Map with the Tribe), or give it maps on this computer "
                                         "(below).", "warning")

    def backup_sync(self):
        editor = getattr(self.window, "editor_tab", None)
        return getattr(editor, "backup_sync", None)

    def show_backup_logins(self):
        """What the service's backups log in with: as the Editor's Backups tab says (set there only)."""
        sync = self.backup_sync()
        if sync is None:
            self.backup_logins_label.setText("As the Editor's Backups tab says.")
            return
        text, _ = sync.summary()
        self.backup_logins_label.setText(
            f"The same way as NOMAD's own backups: {text}. <a href=\"editor\">Change them in the Editor's Backups "
            "tab</a> (the service is given the change at once).")

    def show_editor_logins(self, _link):
        """Close this window and show the Editor's Backups tab, the one place backups' logins are set."""
        self.reject()
        editor = getattr(self.window, "editor_tab", None)
        navigator = getattr(self.window, "navigator", None)
        if editor is None:
            return
        if navigator is not None:
            navigator.setCurrentWidget(editor)
        editor.show_backup_logins()

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
        self.refresh_buttons()
        self.start_button.setEnabled(idle and state == service().STOPPED)
        self.stop_button.setEnabled(idle and state == service().RUNNING)
        self.uninstall_button.setEnabled(idle and installed)
        self.folder_button.setEnabled(watch_service.watcher_dir().exists())
        if not admin:
            set_hint(self.message_label, "Installing the Map Watcher needs administrator rights: use File > Restart "
                                         "as Administrator, then open this again.", "warning")

    def refresh_buttons(self):
        idle = getattr(self.window, "admin", False) and not self.busy
        self.install_button.setEnabled(idle and (self.maps_list.count() > 0 or bool(self.local_entries)))
        for button in (self.add_open_button, self.add_file_button, self.copy_again_button):
            button.setEnabled(not self.busy)
        self.copy_again_button.setEnabled(not self.busy and bool(self.local_entries))
        self.remove_local_button.setEnabled(not self.busy and bool(self.local_entries))

    def run(self, message, action, done, after=None):
        self.busy = True
        set_hint(self.message_label, message, "info")
        self.refresh()

        def succeeded(_):
            if sip.isdeleted(self.message_label):  # The window was closed while it worked: it's done all the same
                log.info("Map Watcher: %s", done)
                return
            self.busy = False
            set_hint(self.message_label, done, "success")
            self.refresh()
            if after is not None:
                after()

        def failed(error):
            log.warning("Map Watcher: %s failed: %s", message, error)
            if sip.isdeleted(self.message_label):
                return
            self.busy = False
            set_hint(self.message_label, str(error), "error")
            self.refresh()

        run_in_background(action, succeeded, failed)

    def install(self):
        chosen = self.chosen_maps()
        kept, copies = self.local_maps()
        if not chosen and not kept and not copies:
            set_hint(self.message_label, "Tick the maps for it to watch, or give it maps on this computer.", "warning")
            return
        key = current_key(admin=True)  # On the tribe server itself, its own key (this needs administrator anyway)
        if key is None and chosen:
            set_hint(self.message_label, "This computer has no tribe key: connect to the tribe first (Tribe > Connect "
                                         "to the Tribe with a Key File on the Network Map page).", "error")
            return
        if not chosen:
            key = None  # Only maps on this computer: it runs without the tribe
        backups = None
        if self.backups_check.isChecked() and key is not None:
            backups = self.backup_login_settings()
            if backups is None:
                return
        try:
            config = watch_service.make_config(key, chosen, self.listen_check.isChecked(), self.timers.values(),
                                               backups=backups, monitoring=self.monitoring(), local_maps=kept)
        except Exception as error:
            set_hint(self.message_label, f"Couldn't prepare the service's settings: {error}", "error")
            return
        log.info("Installing the Map Watcher for maps %s and %d on this computer", json.dumps(chosen),
                 len(kept) + len(copies))
        done = ("The Map Watcher is running. NOMAD open on other computers stands by while it watches; what it finds "
                "appears on the tribe maps tagged NEW." if chosen else
                "The Map Watcher is running. It monitors the maps on this computer it was given.")
        self.run("Installing the service (this takes a few seconds)...",
                 lambda: watch_service.install(config, copies), done, self.copied)

    def copied(self):
        for entry in self.local_entries:
            entry["map"] = None
        self.show_local()

    def backup_login_settings(self):
        """The backup logins for the service's config, from the Editor's Backups tab (make_config's backups), or None
        (and why, said). When they haven't changed since the service was given them, they're kept as they are
        (nothing asked)."""
        sync = self.backup_sync()
        if sync is None or sync.store is None:
            set_hint(self.message_label, "The Editor isn't available, so the backups have no logins.", "error")
            return None
        _, usable = sync.summary()
        if not usable:
            set_hint(self.message_label, "Backups have no login to use: in the Editor's Backups tab, choose a saved "
                                         "credential with a saved password in Log in with (the service has nobody "
                                         "to ask).", "warning")
            return None
        backups = sync.backups_for_service(self, self.configured().get("backups"), ask=True)
        if backups is None:
            locked = sync.problem == "locked"
            set_hint(self.message_label, "The backup logins need the master password." if locked else sync.problem,
                     "warning" if locked else "error")
        return backups

    def uninstall(self):
        if QMessageBox.question(self, "Uninstall the Map Watcher",
                                "Stop and remove the Map Watcher service and its firewall rules? NOMAD left open "
                                "with Watch ticked takes over watching.") != QMessageBox.Yes:
            return
        self.run("Removing the service...", watch_service.uninstall, "Removed.")


def interval_combo(seconds):
    combo = QComboBox()
    for value in seconds:
        combo.addItem(monitor.duration_text(value), value)
    return combo


def service():
    from ..ipam import service as module  # pywin32 is loaded only when it's needed
    return module
