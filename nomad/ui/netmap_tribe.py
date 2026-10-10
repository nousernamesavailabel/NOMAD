"""Tribe maps on the Network Map page: the copy of the tribe's maps, kept in step with the server on a background
thread (sending this computer's changes, and waiting for everyone else's)."""
import datetime
import logging
import threading
import time

from PyQt5.QtCore import QObject, QThread, pyqtSignal

from ..ipam.client import OldServerError, ServerUnreachable, TeamClient, TeamKeyError, load_saved_key
from ..netmap.tribe import TribeMaps
from .common import release_thread

log = logging.getLogger(__name__)

RETRY_SECONDS = 15  # After the server couldn't be reached
WAIT_SECONDS = 25  # How long each wait for others' changes lasts on the server


class SyncThread(QThread):
    """Sync, then wait for the next change on the server, until stopped."""
    synced = pyqtSignal(object)  # {map id: items changed}
    failed = pyqtSignal(str, bool)  # Message, whether the server is too old for tribe maps

    def __init__(self, maps, parent=None):
        super().__init__(parent)
        self.maps = maps
        self.stop_event = threading.Event()
        self.wake = threading.Event()  # Set when there's something to send

    def stop(self):
        self.stop_event.set()
        self.wake.set()

    def run(self):
        while not self.stop_event.is_set():
            self.wake.clear()
            try:
                touched = self.maps.sync()
                self.synced.emit(touched)
                if self.stop_event.is_set() or self.wake.is_set():
                    continue
                self.maps.client.wait_for_maps(self.maps.revision, timeout=5 if self.maps.pending_count() else
                                               WAIT_SECONDS)
            except OldServerError as error:
                self.failed.emit(str(error), True)
                self.wake.wait(600)
            except (ServerUnreachable, TeamKeyError) as error:
                self.failed.emit(str(error), False)
                self.wake.wait(RETRY_SECONDS)
            except Exception as error:  # A problem with one sync shouldn't end syncing
                log.exception("Syncing tribe maps failed")
                self.failed.emit(str(error), False)
                self.wake.wait(RETRY_SECONDS)


class TribeSync(QObject):
    """The tribe's maps for the map page, once a tribe key has been set up (on the IP Addresses page)."""
    synced = pyqtSignal(object)  # {map id: items changed}
    status_changed = pyqtSignal()

    def __init__(self, parent=None, key_loader=load_saved_key, maps_factory=None):
        super().__init__(parent)
        self.key_loader = key_loader
        self.maps_factory = maps_factory or self._make_maps
        self.maps = None
        self.thread = None
        self.pusher = None
        self.error, self.too_old = "", False
        self.last_sync = 0.0

    @staticmethod
    def _make_maps(key):
        from ..terminal.credentials import protect, unprotect
        return TribeMaps(key.server_id, TeamClient(key), protect=protect, unprotect=unprotect)

    def ensure(self):
        """The copy of the tribe's maps (started syncing), or None when there's no tribe key on this computer."""
        if self.maps is None:
            key = self.key_loader()
            if key is None:
                return None
            self.maps = self.maps_factory(key)
            self.start()
        return self.maps

    @property
    def available(self):
        return self.maps is not None or self.key_loader() is not None

    def start(self):
        if self.maps is None or self.thread is not None:
            return
        self.thread = SyncThread(self.maps, self)
        self.thread.synced.connect(self.on_synced)
        self.thread.failed.connect(self.on_failed)
        self.thread.start()

    def on_synced(self, touched):
        self.error, self.too_old, self.last_sync = "", False, time.time()
        self.synced.emit(touched)
        self.status_changed.emit()

    def on_failed(self, message, too_old):
        self.error, self.too_old = message, too_old
        self.status_changed.emit()

    def request_sync(self):
        """Send changes now (after a save), on a thread of their own: the sync thread may be waiting on the server
        for others' changes. The server then tells everyone waiting, this computer's sync thread included."""
        if self.maps is None or (self.pusher is not None and self.pusher.is_alive()):
            if self.thread is not None:
                self.thread.wake.set()
            return
        maps = self.maps

        def push():
            try:
                maps.send_pending()
            except Exception as error:  # Offline: the sync thread sends them when the server's back
                log.info("Couldn't send tribe map changes yet: %s", error)
            if maps.pending_count() and self.thread is not None:
                self.thread.wake.set()
        self.pusher = threading.Thread(target=push, name="Tribe map changes", daemon=True)
        self.pusher.start()

    def save(self, map_id, network_map, settings, seen=None):
        changed = self.maps.save(map_id, network_map, settings, seen)
        if changed:
            self.request_sync()
        return changed

    @property
    def online(self):
        return self.maps is not None and self.maps.online and not self.error

    def status_text(self, map_id):
        """For beside the map: whether it's in step with the server."""
        if self.maps is None or map_id is None:
            return ""
        info = self.maps.map_info(map_id) or {}
        waiting = self.maps.pending_count(map_id)
        name = info.get("name", "Tribe map")
        if self.too_old:
            return f"Tribe map {name}: the tribe server needs updating to share maps"
        if self.error or not self.maps.online:
            text = f"Tribe map {name}: offline"
            return text + (f", {waiting} change{'' if waiting == 1 else 's'} waiting to send" if waiting else "")
        if waiting:
            return f"Tribe map {name}: sending {waiting} change{'' if waiting == 1 else 's'}"
        when = datetime.datetime.fromtimestamp(self.last_sync).strftime("%H:%M") if self.last_sync else ""
        return f"Tribe map {name}: up to date" + (f" ({when})" if when else "")

    def reset(self, forget=False):
        """The tribe key changed (joined, left, or another one): start again with it on the next ensure(). forget:
        also empty the copy of the maps (leaving the tribe)."""
        self.shutdown()
        if self.maps is not None:
            if forget:
                self.maps.clear()
            self.maps.close()
            self.maps = None
        self.error, self.too_old, self.last_sync = "", False, 0.0
        self.status_changed.emit()

    def shutdown(self, wait_ms=3000):
        if self.thread is not None:
            self.thread.stop()
            release_thread(self.thread, wait_ms)  # A wait on the server may still be open: let it end on its own
            self.thread = None
