"""The config archive kept on this computer (no tribe): the same calls as the tribe's (tribe.TribeConfigs), straight
to a ConfigStore."""
import time

from . import archive, checks


class LocalConfigs:
    is_tribe = False
    online = True

    def __init__(self, path):
        self.store = archive.ConfigStore(path)

    @property
    def lock(self):
        return self.store.lock

    def close(self):
        self.store.close()

    def sync(self):
        return False

    def text(self, version_id):
        with self.lock:
            version = self.store.version(version_id)
        return version["text"] if version else None

    def set_scope(self, rows, now=None):
        """The devices backups cover: the open map's routers, switches, firewalls and WLCs."""
        with self.lock:
            changed = self.store.sync_devices(rows, now)
            if self.store.standards():
                for device_id in changed:
                    checks.recheck(self.store, device_id, now=now)
            return changed

    def claim(self, holder, computer, kind=archive.GUI, limit=3, now=None, status="", user=""):
        with self.lock:
            return self.store.claim(holder, computer, kind, limit, now, status, user)

    def runners(self):
        with self.lock:
            return self.store.runners()

    def make_due(self, device_ids=None):
        with self.lock:
            return self.store.make_due(device_ids)

    def results(self, limit=200):
        with self.lock:
            return self.store.results(limit)

    def report_failure(self, device_id, computer, reason, now=None, by=""):
        with self.lock:
            return self.store.report_failure(device_id, computer, reason, now, by)

    def upload(self, device_id, which, config, user, source=archive.MANUAL, changed_by="", name="", address="",
               platform="", now=None):
        with self.lock:
            outcome = self.store.upload(device_id, which, config, user, source, changed_by, name, address, platform,
                                        now)
            if outcome["stored"] and which == "running":
                checks.recheck(self.store, device_id, now=now)
        return outcome

    # ----------------------------------------------------------------- Reviews

    def finish_review(self, version_id, user, verdicts, reason, seconds=0.0, started=None, self_review=False):
        with self.lock:
            return self.store.finish_review(version_id, user, verdicts, reason, seconds, started, self_review)

    def close_raised(self, version_id, user, outcome, note):
        with self.lock:
            return self.store.close_raised(version_id, user, outcome, note)

    def acknowledge(self, version_ids, user, reason):
        with self.lock:
            return self.store.acknowledge(version_ids, user, reason)

    def pushes_for_version(self, version_id):
        with self.lock:
            return self.store.pushes_for_version(version_id)

    def record_push(self, user, source, target, names, lines):
        with self.lock:
            return self.store.record_push(user, source, target, names, lines)

    def review_log(self, limit=5000):
        with self.lock:
            return self.store.review_log(limit)

    def set_excluded(self, device_id, excluded):
        with self.lock:
            return self.store.set_excluded(device_id, excluded)

    def merge_devices(self, sources, target):
        with self.lock:
            revision = self.store.merge_devices(sources, target)
            checks.recheck(self.store, target)
            return revision

    def forget_devices(self, device_ids):
        with self.lock:
            return self.store.forget_devices(device_ids)

    def save_standard(self, name, source, user):
        with self.lock:
            self.store.save_standard(name, source, user, time.time())
            checks.recheck_all(self.store, names={name})

    def delete_standard(self, name):
        with self.lock:
            return self.store.delete_standard(name)

    def set_settings(self, values):
        with self.lock:
            return self.store.set_settings(values)
