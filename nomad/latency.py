"""Latency monitoring (formerly the Latenct tool): ping several targets continuously and keep their history."""
import csv
import os
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

HISTORY_SECONDS = 8 * 60 * 60  # History kept per target, so the view window can be changed at any time
WINDOW_OPTIONS = [("Last 1 min", 60), ("Last 5 min", 300), ("Last 10 min", 600), ("Last 30 min", 1800),
                  ("Last 1 hour", 3600), ("Last 8 hours", HISTORY_SECONDS)]
DEFAULT_WINDOW_SECONDS = 600
DEFAULT_SCALE = (0.0, 200.0)
AUTOSCALE_PAD_RATIO = 0.10
AUTOSCALE_MIN_SPAN = 10.0
GOOD_MS, FAIR_MS = 60, 150  # Below GOOD_MS is good, below FAIR_MS fair, otherwise poor
CSV_HEADER = ["timestamp", "target_name", "target_host", "status", "rtt_ms", "ttl", "error"]
DEFAULT_TARGETS = [("Google DNS", "8.8.8.8"), ("Cloudflare DNS", "1.1.1.1")]


def latency_level(ms):
    """"good", "fair" or "poor" for a round trip time, or None when there is none."""
    if ms is None:
        return None
    return "good" if ms < GOOD_MS else "fair" if ms < FAIR_MS else "poor"


@dataclass
class WindowStats:
    last: Optional[float]  # Latest reply's round trip time
    last_lost: bool  # Whether the latest ping got no reply
    average: Optional[float]
    minimum: Optional[float]
    maximum: Optional[float]
    sent: int  # Pings in the window
    lost: int

    @property
    def loss_percent(self):
        return 100.0 * self.lost / self.sent if self.sent else 0.0


@dataclass
class LatencyTarget:
    name: str
    host: str
    enabled: bool = True
    color_index: int = 0
    samples: deque = field(default_factory=deque)  # (time, rtt ms) for a reply, (time, None) for a lost ping
    last_error: str = ""

    def reset(self):
        self.samples.clear()
        self.last_error = ""

    def add(self, timestamp, rtt, error=""):
        """Record one ping: rtt in ms for a reply, or None with an error for a lost ping."""
        self.samples.append((timestamp, rtt))
        self.last_error = error if rtt is None else ""
        cutoff = timestamp - HISTORY_SECONDS
        while self.samples and self.samples[0][0] < cutoff:
            self.samples.popleft()

    @property
    def last_lost(self):
        return bool(self.samples) and self.samples[-1][1] is None

    def window(self, seconds, now=None):
        """The samples from the last `seconds` seconds."""
        cutoff = (time.time() if now is None else now) - seconds
        return [sample for sample in self.samples if sample[0] >= cutoff]

    def stats(self, seconds, now=None):
        samples = self.window(seconds, now)
        replies = [rtt for _, rtt in samples if rtt is not None]
        last = next((rtt for _, rtt in reversed(self.samples) if rtt is not None), None)
        return WindowStats(last, self.last_lost, sum(replies) / len(replies) if replies else None,
                           min(replies, default=None), max(replies, default=None),
                           len(samples), len(samples) - len(replies))

    def to_dict(self):
        return {"name": self.name, "host": self.host, "enabled": self.enabled}


def targets_from_dicts(items):
    """Rebuild saved targets, skipping malformed entries. Falls back to the defaults when there are none."""
    targets = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        name, host = str(item.get("name", "")).strip(), str(item.get("host", "")).strip()
        if name and host:
            targets.append(LatencyTarget(name, host, bool(item.get("enabled", True)), len(targets)))
    return targets or [LatencyTarget(name, host, True, index) for index, (name, host) in enumerate(DEFAULT_TARGETS)]


def autoscale(values):
    """A (minimum, maximum) scale in ms that fits the values with some padding."""
    if not values:
        return DEFAULT_SCALE
    low, high = min(values), max(values)
    padding = max(AUTOSCALE_MIN_SPAN, high - low) * AUTOSCALE_PAD_RATIO
    return max(0.0, low - padding), max(high + padding, low - padding + AUTOSCALE_MIN_SPAN)


class CsvLog:
    """Appends every ping to a CSV file, writing the header when the file is new."""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        new = not os.path.exists(path) or os.path.getsize(path) == 0
        self.file = open(path, "a", newline="", encoding="utf-8")
        self.writer = csv.writer(self.file)
        if new:
            self.writer.writerow(CSV_HEADER)

    def write(self, timestamp, target, rtt, ttl, error):
        self.writer.writerow([time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp)), target.name,
                              target.host, "OK" if rtt is not None else "FAIL",
                              "" if rtt is None else f"{rtt:.1f}", "" if ttl is None else ttl, error])
        self.file.flush()

    def close(self):
        self.file.close()
