"""Watching whether the devices on a map are up: ping each one every so often and note when one goes down or comes
back. A device is down only after missing FAILS_FOR_DOWN polls in a row, so one lost ping doesn't make it flap.

A device with an IP SLA probe on a router (probes.py) is checked from that router instead: each new result of the
probe counts as one poll, and while the router can't be read (or the probe isn't running) the device is unknown,
not down."""
import datetime
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

UP, DOWN, UNKNOWN = "up", "down", "unknown"
STATUS_NAMES = {UP: "Up", DOWN: "Down", UNKNOWN: "Not checked yet"}
FAILS_FOR_DOWN = 2  # Polls in a row with no answer before a device counts as down
PING_TRIES = 2  # Pings per poll: one answer is enough
PING_TIMEOUT_MS = 1000
WORKERS = 32
HISTORY_LIMIT = 5000  # Status changes kept with the map
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
    problem: str = ""  # Unknown because it can't be checked: why ("R5 isn't answering SNMP")


@dataclass
class Change:
    key: str
    status: str
    when: float
    lasted: Optional[float] = None  # How long it had been in the status before, in seconds (None the first time)
    rtt: Optional[int] = None
    via: str = ""
    problem: str = ""


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


def poll(targets, pinger=ping, workers=WORKERS):
    """Ping every {key: address} at once. Returns {key: rtt or None}."""
    if not targets:
        return {}
    with ThreadPoolExecutor(max_workers=min(workers, len(targets))) as executor:
        results = dict(zip(targets, executor.map(pinger, targets.values())))
    return results


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

    def update(self, results, via=None):
        """Take a poll's {key: rtt or None} (via: {key: the router it was checked from}). Returns the Changes of
        status it caused."""
        now = self.clock()
        via = via or {}
        changes = []
        for key, rtt in results.items():
            state = self.devices.setdefault(key, DeviceStatus(since=now))
            state.checked, state.via, state.problem = now, via.get(key, ""), ""
            if rtt is not None:
                state.fails, state.rtt = 0, rtt
                new = UP
            else:
                state.fails += 1
                state.rtt = None
                new = DOWN if state.fails >= self.fails_for_down else state.status
                if state.status == UNKNOWN and new == UNKNOWN:
                    continue  # Not heard from yet: wait for the second miss before calling it down
            if new != state.status:
                lasted = now - state.since if state.status != UNKNOWN else None
                changes.append(Change(key, new, now, lasted, rtt, state.via))
                state.status, state.since = new, now
        return changes

    def cannot_check(self, problems, via=None):
        """Devices that couldn't be checked this time ({key: why}, such as their router not answering): unknown
        until they can be, with a Change when that starts or the reason changes."""
        now = self.clock()
        via = via or {}
        changes = []
        for key, problem in problems.items():
            state = self.devices.setdefault(key, DeviceStatus(since=now))
            state.checked, state.via, state.fails, state.rtt = now, via.get(key, ""), 0, None
            changed = state.problem != problem
            state.problem = problem
            if state.status != UNKNOWN:
                changes.append(Change(key, UNKNOWN, now, now - state.since, None, state.via, problem))
                state.status, state.since = UNKNOWN, now
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


def change_text(change, label, address):
    """A line for the Monitor log."""
    name = f"{label} ({address})" if address and address != label else label
    if change.status == UNKNOWN:
        return f"{name} can't be checked: {change.problem or 'no reason given'}"
    if change.status == DOWN:
        text = f"{name} is down: no answer to " + (f"the IP SLA ping from {change.via}" if change.via else "ping")
        if change.lasted is not None:
            text += f" (it had been up for {duration_text(change.lasted)})"
        return text
    text = f"{name} is up"
    if change.lasted is not None:
        text += f" again, after being down for {duration_text(change.lasted)}"
    details = [f"{change.rtt} ms"] if change.rtt is not None else []
    if change.via:
        details.append(f"pinged from {change.via}")
    return text + (f" ({', '.join(details)})" if details else "")


def history_entry(change, label, text):
    return [datetime.datetime.fromtimestamp(change.when).isoformat(timespec="seconds"), change.key, label,
            change.status, text]
