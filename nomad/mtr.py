"""Traceroute with per-hop statistics, like MTR / WinMTR.

Each round sends one probe to every hop at once (TTL 1, 2, 3...), so the path is found in the first round and
later rounds build up loss and latency figures for each router. Loss that starts at one hop and carries on to
the destination shows where a problem is; loss at a single router in the middle usually just means that
router doesn't bother answering probes.
"""
import math
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from .icmp import IP_REQ_TIMED_OUT, TTL_EXPIRED_STATUSES


@dataclass(frozen=True)
class HopRow:
    """A point-in-time copy of one hop's figures, safe to hand to the UI thread."""
    ttl: int
    address: str  # The router that answered most often, or "" if none has
    other_addresses: tuple  # Other routers seen at this hop (load-balanced paths)
    sent: int
    received: int
    last: Optional[float]
    average: Optional[float]
    best: Optional[float]
    worst: Optional[float]
    stdev: Optional[float]
    note: str
    last_lost: bool

    @property
    def loss_percent(self):
        return 0.0 if not self.sent else 100.0 * (self.sent - self.received) / self.sent


@dataclass
class HopStats:
    ttl: int
    sent: int = 0
    received: int = 0
    last: Optional[float] = None
    best: Optional[float] = None
    worst: Optional[float] = None
    mean: float = 0.0
    squares: float = 0.0  # Sum of squared differences from the mean (Welford's method)
    addresses: Counter = field(default_factory=Counter)
    note: str = ""
    last_lost: bool = False

    def add(self, reply):
        """Record one probe's reply (an icmp.EchoReply)."""
        self.sent += 1
        answered = reply.ok or reply.status in TTL_EXPIRED_STATUSES
        if reply.address and reply.status != IP_REQ_TIMED_OUT and reply.address not in ("0.0.0.0", "::"):
            self.addresses[reply.address] += 1
        if not reply.ok and reply.status not in TTL_EXPIRED_STATUSES and reply.status != IP_REQ_TIMED_OUT:
            self.note = reply.message
        self.last_lost = not answered
        if not answered or reply.rtt is None:
            return
        rtt = float(reply.rtt)
        self.received += 1
        self.last = rtt
        self.best = rtt if self.best is None else min(self.best, rtt)
        self.worst = rtt if self.worst is None else max(self.worst, rtt)
        delta = rtt - self.mean
        self.mean += delta / self.received
        self.squares += delta * (rtt - self.mean)

    def row(self):
        ranked = [address for address, _ in self.addresses.most_common()]
        return HopRow(self.ttl, ranked[0] if ranked else "", tuple(ranked[1:]), self.sent, self.received, self.last,
                      self.mean if self.received else None, self.best, self.worst,
                      math.sqrt(self.squares / self.received) if self.received else None, self.note, self.last_lost)


class MtrTrace:
    """Collects probe replies round by round and works out which hops make up the path."""

    def __init__(self, max_hops):
        self.max_hops = max_hops
        self.hops = {ttl: HopStats(ttl) for ttl in range(1, max_hops + 1)}
        self.destination_ttl = None  # First hop where the destination itself answered
        self.stop_ttl = None  # First hop that reported the destination unreachable
        self.rounds = 0

    @property
    def reached(self):
        return self.destination_ttl is not None

    def probe_ttls(self):
        """The TTLs to probe next round: up to the destination once it's known, otherwise every hop."""
        return list(range(1, (self.destination_ttl or self.stop_ttl or self.max_hops) + 1))

    def add_round(self, replies):
        """Record a round of replies, given as {ttl: EchoReply}."""
        self.rounds += 1
        for ttl in sorted(replies):
            reply = replies[ttl]
            if reply.ok and (self.destination_ttl is None or ttl < self.destination_ttl):
                self.destination_ttl = ttl
            elif (not reply.ok and reply.status not in TTL_EXPIRED_STATUSES and reply.status != IP_REQ_TIMED_OUT
                  and (self.stop_ttl is None or ttl < self.stop_ttl)):
                self.stop_ttl = ttl
        last = self.destination_ttl or self.stop_ttl or self.max_hops
        for ttl, reply in replies.items():
            if ttl <= last:
                self.hops[ttl].add(reply)

    def shown_ttls(self):
        """The hops worth showing: up to the destination (or the hop that gave up), else one past the last router
        that answered, so a target that drops pings doesn't leave a long tail of empty rows."""
        if self.destination_ttl or self.stop_ttl:
            return min(ttl for ttl in (self.destination_ttl, self.stop_ttl) if ttl)
        answered = [ttl for ttl, hop in self.hops.items() if hop.addresses]
        return min(self.max_hops, (max(answered) if answered else 0) + 1)

    def rows(self):
        return [self.hops[ttl].row() for ttl in range(1, self.shown_ttls() + 1)]


@dataclass(frozen=True)
class HopLoss:
    """Where a hop's loss happens, split the way pathping does.

    path: loss that carries on past this hop, so real traffic is lost by here (None: no reply to judge by).
    router: the rest of the hop's loss, the router itself not answering probes while it forwards traffic fine.
    added: path loss that first appears at this hop, on the link to it or in the router before it.
    """
    path: Optional[float]
    router: float
    added: float
    note: str


def hop_losses(rows):
    """A HopLoss for each row. Traffic that's lost at one hop is lost at every hop after it too, so a hop's real
    loss is at most the lowest loss of any later hop that answers; anything above that is the router skipping
    probes sent to itself (ICMP rate limiting), which ordinary traffic passing through never notices."""
    losses = []
    lowest_later = None
    for row in reversed(rows):
        if not row.sent or (not row.received and lowest_later is None):
            losses.append((None, 0.0))  # Nothing answered here or after: can't tell where probes were lost
            continue
        path = row.loss_percent if lowest_later is None else min(row.loss_percent, lowest_later)
        losses.append((path, row.loss_percent - path))
        if row.received:
            lowest_later = row.loss_percent if lowest_later is None else min(row.loss_percent, lowest_later)
    losses.reverse()
    result = []
    before = 0.0
    seen_loss = False
    for row, (path, router) in zip(rows, losses):
        added = 0.0 if path is None else max(0.0, path - before)
        notes = []
        if router >= 0.5:
            notes.append("Router doesn't answer probes; traffic passes it fine" if not row.received else
                         f"Router skips {router:.0f}% of probes; traffic passes it fine")
        if added >= 0.5:
            notes.append(f"{added:.0f}% more lost here" if seen_loss else f"Loss starts here ({added:.0f}%)")
            seen_loss = True
        result.append(HopLoss(path, router, added, "; ".join(notes)))
        if path is not None:
            before = path
    return result


def format_ms(value):
    if value is None:
        return ""
    return "<1" if value < 1 else f"{value:.0f}" if value >= 10 else f"{value:.1f}"


REPORT_COLUMNS = ["Hop", "Host", "Loss%", "Path%", "Sent", "Last", "Avg", "Best", "Worst", "StDev", "Note"]


def format_percent(value):
    return "" if value is None else f"{value:.0f}%"


def hop_note(row, loss):
    """The Note shown for a hop: where its loss happens, then any error the router sent back."""
    return "; ".join(note for note in (loss.note, row.note) if note)


def report_text(title, rows, names=None):
    """A plain-text table of the results, for pasting into an email or ticket."""
    names = names or {}
    lines = [[str(row.ttl), (f"{names[row.address]} ({row.address})" if names.get(row.address) else row.address)
              or "???", format_percent(row.loss_percent), format_percent(loss.path), str(row.sent),
              format_ms(row.last), format_ms(row.average), format_ms(row.best), format_ms(row.worst),
              format_ms(row.stdev), hop_note(row, loss)] for row, loss in zip(rows, hop_losses(rows))]
    widths = [max(len(column), *(len(line[index]) for line in lines)) if lines else len(column)
              for index, column in enumerate(REPORT_COLUMNS)]

    def render(cells):
        return "  ".join(cell.ljust(width) if index in (1, len(cells) - 1) else cell.rjust(width)
                         for index, (cell, width) in enumerate(zip(cells, widths))).rstrip()

    return "\n".join([title, "", render(REPORT_COLUMNS)] + [render(line) for line in lines]) + "\n"
