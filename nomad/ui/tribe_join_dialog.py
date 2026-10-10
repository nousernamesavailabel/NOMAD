"""Connect to the Tribe: joining with a tribe key file, each step shown as it happens so it's plain that something is
going on. The key file is read; the tribe server is reached (each address in the key file tried in turn, its
certificate checked against the key file's) and the key checked with it, on a worker thread; then the key is saved
and the pages' first download of the tribe's IPAM networks and maps is followed until they arrive. Closing the window
then leaves the download running. A server that can't be reached right now needn't stop it (NOMAD works offline):
the key can be saved anyway, and NOMAD connects when the server can be reached."""
import logging

from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QFileDialog

from ..ipam.client import ServerMoved, ServerUnreachable, TeamClient, TeamKeyError, read_key_file, save_key
from ..ipam.server import KEY_FILE_SUFFIX
from ..ipam.store import IpamError
from .common import release_thread
from .theme import accent_button
from .tribe_steps import DONE, FAILED, SKIPPED, WAITING, WARNING, WORKING, StepsDialog

log = logging.getLogger(__name__)

KEY, REACH, CHECK, SAVE, NETWORKS, MAPS = range(6)
STEPS = {KEY: "Read the tribe key file", REACH: "Reach the tribe server", CHECK: "Check the tribe key",
         SAVE: "Save the key on this computer", NETWORKS: "Download the tribe's IPAM networks",
         MAPS: "Download the tribe's network maps"}
DOWNLOADS = (NETWORKS, MAPS)
KEEP_IT_SAFE = ("You can delete the key file now, or keep it somewhere safe: anyone with it can change the tribe's "
                "IPAM and maps.")


def connect_to_tribe(parent, window, title="Connect to the Tribe"):
    """Ask for a tribe key file and connect with it, showing the steps. Returns whether the key was saved (the pages
    have been told: window.tribe_key_changed())."""
    path, _ = QFileDialog.getOpenFileName(parent, title, "", f"NOMAD tribe key (*{KEY_FILE_SUFFIX});;All files (*)")
    if not path:
        return False
    dialog = JoinTribeDialog(parent, window, path)
    dialog.exec_()
    return dialog.saved


def plural(count, word):
    return f"{count} {word}{'' if count == 1 else 's'}"


class CheckThread(QThread):
    """Reach the tribe server with the key and ask for its status: the certificate is checked on connecting, and the
    key by the reply."""
    attempt = pyqtSignal(str, str)  # "trying" or "reached", the address
    succeeded = pyqtSignal(object)  # The server's status
    failed = pyqtSignal(object)  # The exception

    def __init__(self, key, parent=None):
        super().__init__(parent)
        self.key = key

    def run(self):
        try:
            status = TeamClient(self.key, on_attempt=self.attempt.emit).status()  # A moved server: key points on
            if status.get("server_id") != self.key.server_id:
                raise TeamKeyError("The server has changed (it was set up again). Ask for the new tribe key file.")
        except Exception as error:
            if not isinstance(error, IpamError):
                log.exception("Checking the tribe key failed")
            self.failed.emit(error)
            return
        self.succeeded.emit(status)


class JoinTribeDialog(StepsDialog):
    def __init__(self, parent, window, path):
        super().__init__(parent, "Connect to the Tribe", STEPS, "Connecting to the tribe...")
        self.window, self.path = window, path
        self.key = None
        self.saved = False
        self.offline = False
        self.thread = None
        self.ipam = self.tribe = None  # What's followed once the key is saved
        self.anyway_button = self.add_button(accent_button("Save Key Anyway"))
        self.anyway_button.setToolTip("Save the key now; NOMAD connects as soon as the tribe server can be reached.")
        self.anyway_button.clicked.connect(self.save_anyway)
        self.start()

    # ----------------------------------------------------------------- Reading the key file and checking it

    def start(self):
        self.set_state(KEY, WORKING)
        try:
            self.key = read_key_file(self.path)
        except IpamError as error:
            self.fail(KEY, str(error))
            return
        key = self.key
        self.set_state(KEY, DONE, f"Tribe server at {', '.join(key.hosts)}, port {key.port}")
        self.set_state(REACH, WORKING, f"Trying {key.hosts[0]}...")
        self.thread = CheckThread(key, self)
        self.thread.attempt.connect(self.on_attempt)
        self.thread.succeeded.connect(self.on_checked)
        self.thread.failed.connect(self.on_check_failed)
        self.thread.start()

    def on_attempt(self, event, host):
        if event == "trying":
            self.set_state(REACH, WORKING, f"Trying {host} (port {self.key.port})...")
        else:
            self.set_state(REACH, DONE, f"Reached {host}; its certificate matches the tribe key file's")
            self.set_state(CHECK, WORKING, "Asking the tribe server whether it accepts the key...")

    def thread_finished(self):
        if self.thread is not None:
            self.thread.wait(2000)  # It has just said how it went
            self.thread = None

    def on_checked(self, status):
        self.thread_finished()
        name = status.get("name") or ", ".join(self.key.hosts)
        self.set_state(CHECK, DONE, f"Accepted by {name}")
        self.save()

    def on_check_failed(self, error):
        self.thread_finished()
        if isinstance(error, ServerUnreachable) and not isinstance(error, ServerMoved):
            self.set_state(REACH, FAILED, str(error))
            self.set_state(CHECK, SKIPPED, "Checked when the tribe server can be reached")
            self.offer_saving_anyway()
            return
        # Refused, or not the server in the key file, or moved without saying where: the key file needs replacing
        self.fail(CHECK if self.states[REACH] == DONE else REACH, str(error))

    def fail(self, step, message):
        self.set_state(step, FAILED, message)
        self.skip_the_rest()
        self.headline.setText("Couldn't connect to the tribe")
        self.say("The key wasn't saved, so nothing on this computer has changed.", "error")
        self.finished_with()

    def offer_saving_anyway(self):
        self.headline.setText("The tribe server can't be reached right now")
        self.say("Save the key anyway, and NOMAD connects as soon as the server can be reached (from the office "
                 "network or over VPN, say); the tribe's networks and maps arrive then. Or cancel and try again "
                 "later.", "warning")
        self.anyway_button.show()
        self.anyway_button.setDefault(True)
        self.anyway_button.setFocus()

    def save_anyway(self):
        self.anyway_button.hide()
        self.message.hide()
        self.offline = True
        self.headline.setText("Connecting to the tribe...")
        self.save()

    # ----------------------------------------------------------------- Saving it, and the first download

    def save(self):
        self.set_state(SAVE, WORKING)
        try:
            save_key(self.key)
        except Exception as error:  # A file that can't be written, or Windows couldn't encrypt it
            log.warning("Couldn't save the tribe key: %s", error)
            self.fail(SAVE, f"Couldn't save it: {getattr(error, 'strerror', None) or error}")
            return
        self.saved = True
        self.set_state(SAVE, DONE, "Encrypted for your Windows account")
        self.follow_downloads()

    def follow_downloads(self):
        """Tell the pages about the new key (they start syncing with it) and follow the first sync of each."""
        window = self.window
        self.ipam = getattr(window, "ipam_tab", None)
        self.tribe = getattr(getattr(window, "netmap_tab", None), "tribe", None)
        if self.ipam is not None:  # Connected before the pages start, so a quick answer isn't missed
            self.follow(self.ipam.tribe_synced, self.on_networks_synced)
            self.follow(self.ipam.tribe_sync_failed, self.on_networks_failed)
        if self.tribe is not None:
            self.follow(self.tribe.synced, self.on_maps_synced)
            self.follow(self.tribe.status_changed, self.on_maps_status)
        window.tribe_key_changed()
        if self.ipam is not None:
            self.ipam.open_store()  # Its tribe copy is opened (and synced) with it: the page may not have been shown
        for step, there in ((NETWORKS, self.ipam is not None and self.ipam.team is not None),
                            (MAPS, self.tribe is not None and self.tribe.maps is not None)):
            if self.states[step] != WAITING:
                continue  # Already arrived
            if not there:
                self.set_state(step, WARNING, "Not started: see the " + ("IP Addresses" if step == NETWORKS else
                                                                          "Network Map") + " page")
            elif self.offline:
                self.set_state(step, SKIPPED, "Downloaded when the tribe server can be reached")
            else:
                self.set_state(step, WORKING, "Downloading from the tribe server...")
        self.check_finished()

    def on_networks_synced(self):
        team = self.ipam.team if self.ipam is not None else None
        count = len(team.networks()) if team is not None else 0
        self.set_state(NETWORKS, DONE, plural(count, "network") + (" from the tribe" if count else
                                                                   " yet: the tribe hasn't shared any"))
        self.check_finished()

    def on_networks_failed(self, message):
        if self.states[NETWORKS] in (WORKING, WARNING):
            self.set_state(NETWORKS, WARNING, f"Not yet: {message} NOMAD keeps trying.")
            self.check_finished()

    def on_maps_synced(self, _touched):
        maps = self.tribe.maps if self.tribe is not None else None
        count = len(maps.maps()) if maps is not None else 0
        self.set_state(MAPS, DONE, plural(count, "map") + (" from the tribe" if count else
                                                           " yet: the tribe hasn't shared any"))
        self.check_finished()

    def on_maps_status(self):
        tribe = self.tribe
        if tribe is None or self.states[MAPS] not in (WORKING, WARNING) or not tribe.error:
            return
        if tribe.too_old:
            self.set_state(MAPS, WARNING, "The tribe server is running an older version of NOMAD that can't share "
                                          "maps: it needs updating.")
        else:
            self.set_state(MAPS, WARNING, f"Not yet: {tribe.error} NOMAD keeps trying.")
        self.check_finished()

    def check_finished(self):
        """Once nothing is under way any more, say how it went (again if a download arrives after a problem)."""
        if self.working():
            self.close_button.setText("Continue in Background")
            self.close_button.setToolTip("Close this; the download carries on.")
            return
        self.finished_with()
        if any(self.states[step] == SKIPPED for step in DOWNLOADS):  # Saved anyway, and still not reached
            self.headline.setText("Tribe key saved")
            self.say("NOMAD connects to the tribe server as soon as it can be reached. " + KEEP_IT_SAFE, "info")
        elif any(self.states[step] == WARNING for step in DOWNLOADS):
            self.headline.setText("Connected to the tribe, but not everything has arrived yet")
            self.say("The key is saved; see above for what's missing. " + KEEP_IT_SAFE, "warning")
        else:
            self.headline.setText("Connected to the tribe")
            self.say("The IP Addresses and Network Map pages share the tribe's networks and maps now. " +
                     KEEP_IT_SAFE, "success")

    # ----------------------------------------------------------------- Closing

    def done(self, result):
        """Closed: the pages' syncs carry on, and a check still waiting on the server ends on its own."""
        if self.thread is not None:
            release_thread(self.thread, 0)
            self.thread = None
        super().done(result)
