"""The tribe's config archive, from a laptop: a copy of the server's (devices, versions without their texts, standards,
results) kept in step by sync(), with texts fetched as they're opened. Changes go to the server; a configuration
pulled while the server can't be reached waits in the copy's outbox and goes on the next sync, so none is lost."""
from ..ipam.client import IpamError, OldServerError, ServerUnreachable
from ..system import log_dir
from . import archive

COPY_FILE = "tribe-configs.db"
COPY_FORMAT = "2"  # 2: drops the devices the server notes as gone (merged or forgotten). A copy from before read past
# those notes, so it reads everything once more (absorb's whole), which drops the ones it kept


def copy_path():
    return log_dir() / COPY_FILE


class TribeConfigs:
    is_tribe = True

    def __init__(self, server_id, client, path=None):
        self.server_id, self.client = server_id, client
        self.store = archive.ConfigStore(path or copy_path())
        self.online = False
        with self.lock:
            if self.store.meta("server_id") not in (None, server_id):  # Another tribe's copy: start again
                with self.store.db:
                    for table in ("devices", "versions", "claims", "failures", "standards", "compliance", "settings",
                                  "outbox", "meta", "reviews"):
                        self.store.db.execute(f"DELETE FROM {table}")
            with self.store.db:
                self.store.set_meta("server_id", server_id)
                if self.store.meta("copy_format") != COPY_FORMAT:
                    self.store.set_meta("revision", 0)
                    self.store.set_meta("copy_format", COPY_FORMAT)

    @property
    def lock(self):
        return self.store.lock

    def close(self):
        self.store.close()

    # ----------------------------------------------------------------- Keeping in step

    def sync(self):
        """Send uploads waiting, then take the server's changes. Returns whether anything came. Raises when the
        server can't be reached (or is too old: OldServerError)."""
        try:
            self.send_waiting()
            with self.lock:
                since = self.store.revision()
            changes, revision = self.client.config_changes(since)
        except IpamError:
            self.online = False
            raise
        with self.lock:
            self.store.absorb(changes, revision, whole=not since)
        self.online = True
        return any(changes.get(name) for name in ("devices", "versions", "standards", "compliance", "settings",
                                                  "gone", "reviews"))

    def send_waiting(self):
        with self.lock:
            waiting = self.store.waiting_uploads()
        for outbox_id, upload in waiting:
            self.client.config_request("upload", **upload)
            with self.lock:
                self.store.sent_upload(outbox_id)

    def waiting(self):
        with self.lock:
            return len(self.store.waiting_uploads())

    def text(self, version_id):
        """A version's text (fetched from the server the first time)."""
        with self.lock:
            if self.store.has_text(version_id):
                return self.store.version(version_id)["text"]
        version = self.client.config_version(version_id)
        with self.lock:
            self.store.store_text(version_id, version["text"])
        return version["text"]

    def set_scope(self, rows, now=None):
        return set()  # The server takes it from the tribe maps

    # ----------------------------------------------------------------- Backups

    def claim(self, holder, computer, kind=archive.GUI, limit=3, now=None, status="", user=""):
        return self.client.config_request("claim", holder=holder, kind=kind, limit=limit, status=status)["devices"]

    def runners(self):
        return self.client.config_runners()

    def results(self, limit=200):
        return self.client.config_results(limit)

    def make_due(self, device_ids=None):
        body = {"all": True} if device_ids is None else {"device_ids": list(device_ids)}
        return self.client.config_request("due", **body)["count"]

    def report_failure(self, device_id, computer, reason, now=None, by=""):
        return self.client.config_request("report", device_id=device_id, reason=reason)

    def upload(self, device_id, which, config, user, source=archive.MANUAL, changed_by="", name="", address="",
               platform="", now=None):
        """Send a configuration (who sent it is the login's). Kept to send later when the server can't be
        reached: {"queued": True}."""
        body = {"device_id": device_id, "which": which, "text": config, "source": source, "changed_by": changed_by,
                "name": name, "address": address, "platform": platform}
        try:
            return self.client.config_request("upload", **body)
        except (ServerUnreachable, OSError):
            with self.lock:
                self.store.queue_upload(body)
            return {"stored": None, "queued": True, "first": False}

    # ----------------------------------------------------------------- Changes (need the server)

    # ----------------------------------------------------------------- Reviews (need a server at API 21)

    def finish_review(self, version_id, user, verdicts, reason, seconds=0.0, started=None, self_review=False):
        return self._needs_reviews("review_finish", version_id=int(version_id), verdicts=list(verdicts),
                                   reason=reason, seconds=seconds, started=started, self_review=bool(self_review))

    def close_raised(self, version_id, user, outcome, note):
        return self._needs_reviews("review_close", version_id=int(version_id), outcome=outcome, note=note)

    def acknowledge(self, version_ids, user, reason):
        return self._needs_reviews("acknowledge", version_ids=[int(item) for item in version_ids],
                                   reason=reason)["count"]

    def pushes_for_version(self, version_id):
        try:
            return self.client.config_pushes(int(version_id))
        except OldServerError:
            return []

    def record_push(self, user, source, target, names, lines):
        try:
            return self.client.config_request("push", source=source, target=target, names=list(names or []),
                                              lines=list(lines))
        except OldServerError:
            return None

    def review_log(self, limit=5000):
        with self.lock:
            return self.store.review_log(limit)

    def mark_seen(self, version_id):
        """An older tribe server, which can't keep reviews: the change marked reviewed its old way."""
        return self.client.config_request("review", version_id=int(version_id))

    def _needs_reviews(self, action, **body):
        try:
            return self.client.config_request(action, **body)
        except OldServerError:
            raise OldServerError("The tribe server is running an older NOMAD that can't keep reviews: update it "
                                 "first.") from None

    def set_excluded(self, device_id, excluded):
        return self.client.config_request("exclude", device_id=device_id, excluded=bool(excluded))

    def merge_devices(self, sources, target):
        return self._needs_merge("merge", sources=list(sources), target=target)

    def forget_devices(self, device_ids):
        return self._needs_merge("forget", device_ids=list(device_ids))

    def _needs_merge(self, action, **body):
        try:
            return self.client.config_request(action, **body)
        except OldServerError:
            raise OldServerError("The tribe server is running an older NOMAD that can't merge or forget devices in "
                                 "the config archive: update it first.") from None

    def save_standard(self, name, source, user):
        return self.client.config_request("standard", name=name, text=source)

    def delete_standard(self, name):
        return self.client.config_request("standard", name=name, delete=True)

    def set_settings(self, values):
        return self.client.config_request("settings", values=values)


__all__ = ["TribeConfigs", "OldServerError", "ServerUnreachable", "copy_path"]
