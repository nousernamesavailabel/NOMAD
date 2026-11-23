"""The syslog collector: listens for syslog (UDP, and TCP if asked) and keeps every message (store.SyslogStore),
writing every second.

The receiver's threads only queue what comes in; one thread writes, so a slow disk never loses messages. The port is
taken exclusively: only one program can listen for syslog on it, which is why a shared server runs the NOMAD Syslog
Collector service for everyone (and the Map Watcher reads it) instead of each listening for itself.
"""
import collections
import logging
import threading
import time
from pathlib import Path

from ..syslog import SYSLOG_PORT, SyslogReceiver
from .store import KEEP_DAYS, MAX_BYTES, SyslogStore

log = logging.getLogger(__name__)

FLUSH_SECONDS = 1.0
PRUNE_SECONDS = 600
MAX_QUEUED = 100000  # Messages waiting to be written; past this the oldest are dropped (and counted)
PORT_IN_USE = 10048  # WSAEADDRINUSE


def port_problem(error, port):
    """A sentence for why the port couldn't be listened on."""
    if getattr(error, "winerror", None) == PORT_IN_USE or getattr(error, "errno", None) in (98, 48, 10048):
        return (f"Port {port} is in use: another program is listening for syslog on it (the NOMAD Syslog Collector "
                "service, the Map Watcher, NOMAD's Syslog page, or another syslog server).")
    return f"Couldn't listen on port {port}: {getattr(error, 'strerror', None) or error}."


class SyslogCollector:
    def __init__(self, path, port=SYSLOG_PORT, address="0.0.0.0", tcp=False, keep_days=KEEP_DAYS,
                 max_bytes=MAX_BYTES, clock=time.time, receiver_class=SyslogReceiver):
        self.path, self.port, self.address, self.tcp = Path(path), port, address, tcp
        self.keep_days, self.max_bytes, self.clock = keep_days, max_bytes, clock
        self.receiver_class = receiver_class
        self.receiver = None
        self.store = None
        self.queue = collections.deque()
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.thread = None
        self.lock = threading.Lock()
        self.started = 0.0
        self.counts = collections.Counter()
        self.senders = {}  # Address -> [messages since started, last seen]
        self.last_error = ""
        self.latest_id = 0

    # ----------------------------------------------------------------- Running

    def start(self):
        """Raises OSError if the port can't be listened on."""
        self.store = SyslogStore(self.path, self.keep_days, self.max_bytes, self.clock)
        # What's kept already: status() says 0 otherwise until a message comes in, and a feed that had read up to the
        # newest took 0 as the messages deleted and handed them all over again (every 30 s)
        self.latest_id = self.store.latest_id()
        receiver = self.receiver_class(self.on_message, self.address, self.port, self.tcp, exclusive=True)
        try:
            receiver.start()
        except OSError:
            self.store.close()
            self.store = None
            raise
        self.receiver = receiver
        self.port = receiver.port
        self.stopping.clear()
        self.started = self.clock()
        self.thread = threading.Thread(target=self.work, name="Syslog store", daemon=True)
        self.thread.start()
        log.info("Collecting syslog on %s port %s (%s) into %s", self.address, self.port,
                 "UDP and TCP" if self.tcp else "UDP", self.path)

    def stop(self):
        if self.receiver is not None:
            self.receiver.stop()
            self.receiver = None
        self.stopping.set()
        self.wake.set()
        if self.thread is not None:
            self.thread.join(15)
            self.thread = None
        if self.store is not None:
            self.write_queued()
            self.store.close()
            self.store = None

    @property
    def running(self):
        return self.receiver is not None

    def on_message(self, message):
        """From the receiver's threads."""
        with self.lock:
            if len(self.queue) >= MAX_QUEUED:
                self.queue.popleft()
                self.counts["dropped"] += 1
            self.queue.append(message)
            self.counts["received"] += 1
            entry = self.senders.setdefault(message.source, [0, 0.0])
            entry[0] += 1
            entry[1] = self.clock()
        self.wake.set()

    def work(self):
        next_prune = self.clock()
        while not self.stopping.is_set():
            self.wake.wait(FLUSH_SECONDS)
            if self.stopping.is_set():
                break
            time.sleep(0.05)  # Let a burst gather into one write
            self.wake.clear()
            self.write_queued()
            if self.clock() >= next_prune:
                next_prune = self.clock() + PRUNE_SECONDS
                try:
                    self.store.prune()
                except Exception as error:
                    self.last_error = f"Couldn't delete old messages: {error}"
                    log.exception("Couldn't delete old syslog messages")

    def write_queued(self):
        with self.lock:
            batch = list(self.queue)
            self.queue.clear()
        if not batch:
            return
        try:
            latest = self.store.add(batch)
        except Exception as error:  # Disk full, locked file...: keep listening, say so
            self.last_error = f"Couldn't write messages: {error}"
            self.counts["lost"] += len(batch)
            log.exception("Couldn't write syslog messages")
            return
        self.counts["stored"] += len(batch)
        self.latest_id = latest or self.latest_id
        if self.last_error.startswith("Couldn't write"):
            self.last_error = ""

    # ----------------------------------------------------------------- Status

    def status(self):
        with self.lock:
            senders = {address: {"messages": count, "last_seen": seen}
                       for address, (count, seen) in self.senders.items()}
        try:
            size = self.path.stat().st_size
        except OSError:
            size = 0
        return {"running": self.running, "port": self.port, "address": self.address, "tcp": self.tcp,
                "started": self.started, "received": self.counts["received"], "stored": self.counts["stored"],
                "dropped": self.counts["dropped"], "lost": self.counts["lost"], "error": self.last_error,
                "keep_days": self.keep_days, "max_bytes": self.max_bytes, "size": size,
                "latest_id": self.latest_id, "senders": senders}
