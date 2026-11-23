"""Handing new syslog messages to whoever wants them: from the NOMAD Syslog Collector service when it runs on this
computer (it has the port), or by listening on the port itself when it doesn't.

ServiceFeed asks the service every couple of seconds for what came in since last time. SyslogListener is what the
Map Watcher uses: it picks between the two, and check() moves over when the service is installed or removed.
"""
import datetime
import logging
import threading

from . import service
from .api import SyslogServiceSource, SyslogSourceError

log = logging.getLogger(__name__)


def service_running():
    """The Syslog Collector service runs on this computer (looked up each time, so tests can stand in for it)."""
    return service.running()

POLL_SECONDS = 2.0
BATCH = 1000
RESTART_CHECK_POLLS = 15


class ServiceFeed:
    """Calls callback(message) from its thread for each new message the service keeps. backlog: start with the
    newest that many already kept (0: only what comes in from now). on_problem(text) is called (from its thread)
    when the service stops answering, and on_problem("") when it answers again."""

    def __init__(self, callback, backlog=0, source=None, interval=POLL_SECONDS, on_problem=None):
        self.callback, self.backlog, self.interval, self.on_problem = callback, backlog, interval, on_problem
        self.source = source or SyslogServiceSource(timeout=5)
        self.stopping = threading.Event()
        self.thread = None
        self.last_id = None
        self.last_received = None  # When the newest message handed over came in
        self.rewound = False  # The service's IDs went back: only messages newer than last_received are new
        self.idle = 0
        self.problem = ""

    def start(self):
        self.stopping.clear()
        self.thread = threading.Thread(target=self.run, name="Syslog feed", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(self.source.timeout + 2)
            self.thread = None

    def run(self):
        while not self.stopping.is_set():
            try:
                more = self.poll()
                self.set_problem("")
            except SyslogSourceError as error:
                self.set_problem(str(error))
                more = False
            except Exception as error:  # A bug here mustn't end the feed
                log.exception("Reading the Syslog Collector failed")
                self.set_problem(str(error))
                more = False
            if not more:
                self.stopping.wait(self.interval)

    def poll(self):
        """One question to the service. Returns True if there's more waiting."""
        if self.last_id is None:
            if self.backlog:
                messages = self.source.latest(self.backlog)
                self.last_id = messages[-1].id if messages else self.source.status().get("latest_id", 0)
                self.deliver(messages)
            else:
                self.last_received = datetime.datetime.now()  # Before asking: only what comes in from now is new
                self.last_id = int(self.source.status().get("latest_id", 0) or 0)
                self.rewound = True  # A service that says 0 while it keeps messages mustn't hand them all over
            return False
        messages = self.source.since(self.last_id, BATCH)
        if messages:
            self.idle = 0
            self.last_id = messages[-1].id
            count = len(messages)
            if self.rewound:
                if self.last_received is not None:  # Those handed over already aren't new, whatever their IDs
                    messages = [message for message in messages if message.received > self.last_received]
                self.rewound = count >= BATCH  # Until caught up
            self.deliver(messages)
            return count >= BATCH
        self.idle += 1
        if self.idle >= RESTART_CHECK_POLLS:  # Its messages were deleted and it started counting again?
            self.idle = 0
            latest = int(self.source.status().get("latest_id", 0) or 0)
            if latest < self.last_id:
                self.last_id = latest
                self.rewound = True
        return False

    def deliver(self, messages):
        for message in messages:
            if self.stopping.is_set():
                return
            if self.last_received is None or message.received > self.last_received:
                self.last_received = message.received
            try:
                self.callback(message)
            except Exception:
                log.exception("Handling a syslog message failed")

    def set_problem(self, text):
        if text == self.problem:
            return
        self.problem = text
        if text:
            log.info("Syslog Collector service: %s", text)
        if self.on_problem is not None:
            self.on_problem(text)


class SyslogListener:
    """Gets syslog messages to callback(message): from the Syslog Collector service while it runs on this computer,
    else by listening on the port (listen() raises OSError if it can't; unlisten() stops)."""
    SERVICE, PORT = "service", "port"

    def __init__(self, callback, listen, unlisten, running=service_running, feed_factory=ServiceFeed):
        self.callback, self.listen, self.unlisten = callback, listen, unlisten
        self.running, self.feed_factory = running, feed_factory
        self.mode = ""
        self.wanted = False
        self.feed = None

    def start(self):
        """Start getting messages. Returns SERVICE or PORT; raises OSError if the port can't be listened on (check()
        tries again)."""
        self.wanted = True
        if self.mode:
            return self.mode
        if self.running():
            self.feed = self.feed_factory(self.callback)
            self.feed.start()
            self.mode = self.SERVICE
        else:
            self.listen()
            self.mode = self.PORT
        return self.mode

    def stop(self):
        self.wanted = False
        self._stop()

    def _stop(self):
        if self.mode == self.SERVICE and self.feed is not None:
            self.feed.stop()
            self.feed = None
        elif self.mode == self.PORT:
            self.unlisten()
        self.mode = ""

    def check(self):
        """Move to the service if it started, or back to the port if it stopped (or try the port again, if it
        couldn't be listened on). Returns the new mode if it changed, else "". Raises OSError if the port is wanted
        but can't be listened on."""
        if not self.wanted:
            return ""
        wanted = self.SERVICE if self.running() else self.PORT
        if wanted == self.mode:
            return ""
        self._stop()
        return self.start()
