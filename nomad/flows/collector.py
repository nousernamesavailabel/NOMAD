"""The flow collector: listens on UDP (2055 by default) for NetFlow and IPFIX, reads each packet and keeps the flows
(store.Summarizer), writing every few seconds.

One thread takes packets off the socket (a large receive buffer rides out bursts), another reads and stores them, so
a slow write never drops packets. Only one program can listen on the port, which is why a shared server runs the
NOMAD Flow Collector service for everyone instead of each NOMAD listening for itself.
"""
import collections
import logging
import socket
import threading
import time

from .decode import DecodeError, Decoder
from .store import RAW_SECONDS, SUMMARY_DAYS, Summarizer

log = logging.getLogger(__name__)

FLOW_PORT = 2055
RECEIVE_BUFFER = 8 * 1024 * 1024
FLUSH_SECONDS = 5
MAX_QUEUED = 50000  # Packets waiting to be read; past this the oldest are dropped (and counted)
PORT_IN_USE = 10048  # WSAEADDRINUSE


def port_problem(error, port):
    """A sentence for why the port couldn't be listened on."""
    if getattr(error, "winerror", None) == PORT_IN_USE or getattr(error, "errno", None) in (98, 48, 10048):
        return (f"UDP {port} is in use: another program is collecting flows on it (the NOMAD Flow Collector service, "
                "another NOMAD on this computer, or another NetFlow collector).")
    return f"Couldn't listen on UDP {port}: {getattr(error, 'strerror', None) or error}."


class FlowCollector:
    def __init__(self, path, port=FLOW_PORT, address="0.0.0.0", raw_seconds=RAW_SECONDS, summary_days=SUMMARY_DAYS,
                 clock=time.time):
        self.path, self.port, self.address = path, port, address
        self.raw_seconds, self.summary_days, self.clock = raw_seconds, summary_days, clock
        self.decoder = Decoder(clock)
        self.queue = collections.deque()
        self.wake = threading.Event()
        self.stopping = threading.Event()
        self.socket = None
        self.threads = []
        self.summarizer = None
        self.started = 0.0
        self.counts = collections.Counter()
        self.last_error = ""
        self.lock = threading.Lock()
        self.exporter_counts = {}  # Exporter -> [packets, last seen, version, last problem]

    # ----------------------------------------------------------------- Running

    def start(self):
        """Raises OSError if the port can't be listened on."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):  # Windows: nobody else may take the port alongside
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind((self.address, self.port))
        except OSError:
            sock.close()
            raise
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER)
        except OSError:
            pass
        sock.settimeout(0.5)
        self.socket = sock
        if self.port == 0:
            self.port = sock.getsockname()[1]
        self.summarizer = Summarizer(self.path, self.raw_seconds, self.summary_days, self.clock)
        self.stopping.clear()
        self.started = self.clock()
        for target, name in ((self.receive, "NetFlow receive"), (self.work, "NetFlow store")):
            thread = threading.Thread(target=target, name=name, daemon=True)
            self.threads.append(thread)
            thread.start()
        log.info("Collecting NetFlow on %s UDP %s into %s", self.address, self.port, self.path)

    def stop(self):
        self.stopping.set()
        self.wake.set()
        for thread in self.threads:
            thread.join(10)
        self.threads = []
        if self.socket is not None:
            self.socket.close()
            self.socket = None
        if self.summarizer is not None:
            try:
                self.summarizer.flush()
            except Exception:
                log.exception("Couldn't write the last flows")
            self.summarizer.close()
            self.summarizer = None

    @property
    def running(self):
        return self.socket is not None

    def receive(self):
        sock = self.socket
        while not self.stopping.is_set():
            try:
                data, sender = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                continue
            if len(self.queue) >= MAX_QUEUED:
                self.queue.popleft()
                self.counts["dropped"] += 1
            self.queue.append((data, sender[0], self.clock()))
            self.wake.set()

    def work(self):
        next_flush = self.clock() + FLUSH_SECONDS
        while not self.stopping.is_set():
            self.wake.wait(max(0.01, min(1.0, next_flush - self.clock())))
            self.wake.clear()
            self.read_queued()
            if self.clock() >= next_flush:
                next_flush = self.clock() + FLUSH_SECONDS
                try:
                    self.summarizer.flush()
                except Exception as error:  # Disk full, locked file...: keep listening, say so
                    self.last_error = f"Couldn't write flows: {error}"
                    log.exception("Couldn't write flows")
        self.read_queued()

    def read_queued(self):
        while self.queue:
            data, sender, received = self.queue.popleft()
            self.feed(data, sender, received)

    def feed(self, data, sender, received=None):
        """Read one packet and keep its flows (the work thread, or a test)."""
        received = self.clock() if received is None else received
        version = int.from_bytes(data[:2], "big") if len(data) >= 2 else 0
        with self.lock:
            entry = self.exporter_counts.setdefault(sender, [0, 0.0, version, ""])
            entry[0] += 1
            entry[1], entry[2] = received, version
        self.counts["packets"] += 1
        try:
            decoded = self.decoder.feed(data, sender, received)
        except DecodeError as error:
            self.counts["not NetFlow"] += 1
            with self.lock:
                entry[3] = str(error)
            return None
        except Exception as error:  # A packet NOMAD reads wrong mustn't stop the collecting
            self.counts["unreadable"] += 1
            log.exception("Couldn't read a NetFlow packet from %s", sender)
            with self.lock:
                entry[3] = f"unreadable packet: {error}"
            return None
        self.counts["flows"] += len(decoded.flows)
        self.summarizer.add_names(decoded.interfaces, decoded.applications)
        self.summarizer.add_packet(sender, version, decoded.flows)
        self.summarizer.add_flows(decoded.flows, received)
        return decoded

    # ----------------------------------------------------------------- Status

    def status(self):
        with self.lock:
            exporters = {address: {"packets": packets, "last_seen": seen, "version": version, "problem": problem,
                                   "templates": self.decoder.template_count(address),
                                   "waiting": len(self.decoder.waiting.get(address, ()))}
                         for address, (packets, seen, version, problem) in self.exporter_counts.items()}
        return {"running": self.running, "port": self.port, "address": self.address, "started": self.started,
                "packets": self.counts["packets"], "flows": self.counts["flows"],
                "dropped": self.counts["dropped"], "not_netflow": self.counts["not NetFlow"],
                "unreadable": self.counts["unreadable"], "error": self.last_error,
                "raw_seconds": self.raw_seconds, "summary_days": self.summary_days, "exporters": exporters,
                "waiting_for_template": self.decoder.stats["waiting for template"]}
