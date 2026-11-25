"""Watching whether the devices on a map are up: ping each one every so often and note when one goes down or comes
back. A device is down only after missing FAILS_FOR_DOWN polls in a row, so one lost ping doesn't make it flap.

A device with an IP SLA probe on a router (probes.py) is checked from that router instead: each new result of the
probe counts as one poll, and while the router can't be read (or the probe isn't running) the device is unknown,
not down."""
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Optional

UP, DOWN, UNKNOWN = "up", "down", "unknown"
STATUS_NAMES = {UP: "Up", DOWN: "Down", UNKNOWN: "Not checked yet"}
FAILS_FOR_DOWN = 2  # Polls in a row with no answer before a device counts as down
PING_TRIES = 2  # Pings per poll: one answer is enough
PING_TIMEOUT_MS = 1000
WORKERS = 32
INTERVALS = [10, 30, 60, 120, 300, 600]  # Seconds between polls on offer
DEFAULT_INTERVAL = 30


@dataclass
class DeviceStatus:
    status: str = UNKNOWN
    rtt: Optional[int] = None  # Milliseconds, from the last answer
    since: float = 0.0  # time.time() of the last change of status
    fails: int = 0  # Polls in a row with no answer
    checked: float = 0.0  # time.time() of the last poll
    via: str = ""  # Checked from a router: "R5 (vrf MGMT-B)" ("" for a ping from this computer)
    # Unknown: why it can't be checked ("R5 isn't answering SNMP"). Up: a warning, for a device checked on a port or
    # web address that answers with trouble ("HTTP 503 Service Unavailable"). Down: why, for one checked that way
    # ("TCP 443 refused (nothing listening)"). Ping leaves it "" while up or down
    problem: str = ""
    # How it's shown (monitor_record fills these in; the tracker leaves them be):
    exact: bool = True  # False: since is only when monitoring first saw it like this ("up for at least...")
    uptime: dict = field(default_factory=dict)  # "24h"/"7d"/"30d" -> fraction of the time it was up
    source: str = ""  # Whose monitoring this is: "" (this computer's), or "the Map Watcher on PC1"
    stale_at: float = 0.0  # The Map Watcher's last round of checks, once it has stopped checking (0.0: it hasn't)


@dataclass
class Change:
    key: str
    status: str
    when: float
    lasted: Optional[float] = None  # How long it had been in the status before, in seconds (None the first time)
    rtt: Optional[int] = None
    via: str = ""
    problem: str = ""  # Why it can't be checked, why it's down, or a warning while up (DeviceStatus.problem)
    noted: bool = False  # Not a change of status: an up device's warning started, changed or ended


def ping(address, tries=PING_TRIES, timeout=PING_TIMEOUT_MS):
    """Round trip time in ms, or None if no try got an answer (Windows' ICMP API)."""
    from ..sweep import ping_once
    for _ in range(tries):
        try:
            rtt = ping_once(address, timeout)
        except OSError:
            return None
        if rtt is not None:
            return rtt
    return None


def poll(targets, pinger=ping, workers=WORKERS, checks=None, notes=None, runner=None):
    """Ping every {key: address} at once. Returns {key: rtt or None}. checks: {key: checks.CheckSpec} for the devices
    checked some other way (a TCP port, a web address), run by runner (checks.run); notes, a dict, gets each of
    their notes (why there was no answer, or a warning)."""
    if not targets:
        return {}
    checks = {key: spec for key, spec in (checks or {}).items() if key in targets and not spec.pings}
    if checks and runner is None:
        from .checks import run as runner

    def check(key):
        if key not in checks:
            return pinger(targets[key]), ""
        try:
            outcome = runner(checks[key], targets[key])
        except Exception as error:  # One device's trouble shouldn't stop the poll
            return None, str(error) or "the check failed"
        return outcome.rtt, outcome.note

    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        found = dict(zip(targets, executor.map(check, list(targets))))
    if notes is not None:
        notes.update({key: note for key, (_, note) in found.items() if key in checks})
    return {key: rtt for key, (rtt, _) in found.items()}


class StatusTracker:
    """Each device's status, updated from polls. Qt-free, so the rules can be tested on their own."""

    def __init__(self, fails_for_down=FAILS_FOR_DOWN, clock=time.time):
        self.fails_for_down, self.clock = fails_for_down, clock
        self.devices = {}  # key -> DeviceStatus

    def get(self, key):
        return self.devices.get(key) or DeviceStatus()

    def forget_others(self, keys):
        """Drop devices no longer on the map."""
        self.devices = {key: status for key, status in self.devices.items() if key in keys}

    def update(self, results, via=None, notes=None):
        """Take a poll's {key: rtt or None} (via: {key: the router it was checked from}; notes: {key: why there was
        no answer, or a warning while it answers}, for devices checked on a port or web address). Returns the
        Changes it caused: of status, and of an up device's warning."""
        now = self.clock()
        via, notes = via or {}, notes or {}
        changes = []
        for key, rtt in results.items():
            state = self.devices.setdefault(key, DeviceStatus(since=now, exact=False))
            was_status, was_note = state.status, state.problem
            note = notes.get(key, "")
            state.checked, state.via = now, via.get(key, "")
            if rtt is not None:
                state.fails, state.rtt, state.problem = 0, rtt, note
                new = UP
            else:
                state.fails += 1
                state.rtt = None
                new = DOWN if state.fails >= self.fails_for_down else state.status
                if new == UNKNOWN:
                    state.problem = ""
                    continue  # Not heard from yet: wait for the second miss before calling it down
                if new == DOWN:
                    state.problem = note
                # Up, but missed once: still up, and its warning stands until it answers again
            if new != was_status:
                lasted = now - state.since if was_status != UNKNOWN else None
                changes.append(Change(key, new, now, lasted, rtt, state.via, state.problem))
                state.status, state.since, state.exact = new, now, lasted is not None
            elif new == UP and rtt is not None and state.problem != was_note:
                changes.append(Change(key, UP, now, now - state.since, rtt, state.via, state.problem, noted=True))
        return changes

    def cannot_check(self, problems, via=None):
        """Devices that couldn't be checked this time ({key: why}, such as their router not answering): unknown
        until they can be, with a Change when that starts or the reason changes."""
        now = self.clock()
        via = via or {}
        changes = []
        for key, problem in problems.items():
            state = self.devices.setdefault(key, DeviceStatus(since=now, exact=False))
            state.checked, state.via, state.fails, state.rtt = now, via.get(key, ""), 0, None
            changed = state.problem != problem
            state.problem = problem
            if state.status != UNKNOWN:
                changes.append(Change(key, UNKNOWN, now, now - state.since, None, state.via, problem))
                state.status, state.since, state.exact = UNKNOWN, now, True
            elif changed:
                changes.append(Change(key, UNKNOWN, now, None, None, state.via, problem))
        return changes

    def counts(self):
        counts = {UP: 0, DOWN: 0, UNKNOWN: 0}
        for state in self.devices.values():
            counts[state.status] += 1
        return counts


def duration_text(seconds):
    """3 min 12 s, 2 h 5 min, 4 days 3 h."""
    seconds = int(seconds)
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 24:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    days, hours = divmod(hours, 24)
    return f"{days} day{'' if days == 1 else 's'} {hours} h" if hours else f"{days} day{'' if days == 1 else 's'}"


def change_text(change, label, address, how=""):
    """A line for the Monitor log. how: what checks the device when it isn't ping ("TCP 443")."""
    name = f"{label} ({address})" if address and address != label else label
    if change.status == UNKNOWN:
        return f"{name} can't be checked: {change.problem or 'no reason given'}"
    if change.noted:
        if not change.problem:
            return f"{name} answers without a warning again"
        return f"{name} answers with a warning: {change.problem}" + \
            (f" ({change.rtt} ms)" if change.rtt is not None else "")
    if change.status == DOWN:
        if change.problem:
            text = f"{name} is down: {change.problem}" + (f" (checked from {change.via})" if change.via else "")
        else:
            text = f"{name} is down: no answer to " + (f"the IP SLA ping from {change.via}" if change.via else "ping")
        if change.lasted is not None:
            text += f" (it had been up for {duration_text(change.lasted)})"
        return text
    text = f"{name} is up"
    if change.lasted is not None:
        text += f" again, after being down for {duration_text(change.lasted)}"
    details = [f"{change.rtt} ms" + (f" on {how}" if how else "")] if change.rtt is not None else []
    if change.via:
        details.append(f"checked from {change.via}" if how else f"pinged from {change.via}")
    if change.problem:
        details.append(f"with a warning: {change.problem}")
    return text + (f" ({', '.join(details)})" if details else "")
