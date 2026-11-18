"""Scheduled backups on one computer (a NOMAD window, or the Map Watcher service): ask the archive for a few due
devices, pull each one's running-config and keep it, or say why it couldn't so another computer gets it. Qt-free and
driven by step(), like the Map Watcher's engine."""
import logging
import time
from dataclasses import dataclass

from . import archive, pull

log = logging.getLogger(__name__)
STEP_SECONDS = 30  # How often a runner asks for work
PER_STEP = 3


@dataclass
class Done:
    device_id: str
    name: str
    ok: bool
    note: str  # "changed", "no change", or why it failed
    when: float


class BackupRunner:
    def __init__(self, configs, pusher_factory, holder, computer, user, kind=archive.GUI, clock=time.time,
                 should_stop=lambda: False, limit=PER_STEP):
        """configs: local.LocalConfigs or tribe.TribeConfigs. pusher_factory(): a configpush.Pusher with this
        computer's logins (closed after each step)."""
        self.configs, self.pusher_factory = configs, pusher_factory
        self.holder, self.computer, self.user, self.kind = holder, computer, user, kind
        self.clock, self.should_stop, self.limit = clock, should_stop, limit
        self.recent = []  # [Done], newest last (the last 50)
        self.status = "Starting"  # How the last round went, told to the archive with the next claim

    def step(self):
        """Back up the devices due (a few). Returns [Done]."""
        devices = self.configs.claim(self.holder, self.computer, self.kind, self.limit, status=self.status,
                                     user=self.user)
        if not devices:
            if not self.status.startswith("Backed up"):
                self.status = f"Nothing due (checked {time.strftime('%H:%M', time.localtime(self.clock()))})"
            return []
        done = []
        pusher = self.pusher_factory()
        try:
            for device in devices:
                if self.should_stop():
                    break
                done.append(self.back_up(pusher, device))
        finally:
            pusher.close()
        self.recent = (self.recent + done)[-50:]
        good = sum(1 for item in done if item.ok)
        failed = [item.name for item in done if not item.ok]
        self.status = f"Backed up {good} of {len(done)} at {time.strftime('%H:%M', time.localtime(self.clock()))}" + \
            (f" (couldn't: {', '.join(failed)})" if failed else "")
        return done

    def back_up(self, pusher, device):
        name = device.get("name") or device["id"]
        try:
            result = pull.pull_device(pusher, device.get("address") or device["id"], device.get("names") or (),
                                      device.get("platform") or "")
        except Exception as error:  # Never let one device stop the rest
            log.exception("Backing up %s failed", name)
            result = pull.PullResult(problem=f"NOMAD failed reading it: {error}")
        now = self.clock()
        if not result.ok:
            reason = result.problem or "It gave no configuration."
            self.configs.report_failure(device["id"], self.computer, reason, by=self.user)
            return Done(device["id"], name, False, reason, now)
        outcome = self.configs.upload(device["id"], pull.RUNNING, result.texts[pull.RUNNING], self.user,
                                      archive.SCHEDULED, result.changed_by, name, device.get("address") or "",
                                      result.platform)
        note = "first copy" if outcome.get("first") else "changed" if outcome.get("stored") else "no change"
        return Done(device["id"], name, True, note, now)
