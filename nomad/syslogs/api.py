"""How NOMAD reads the NOMAD Syslog Collector service on this computer: over HTTP on 127.0.0.1, read-only, with the
same protection as the Flow Collector's API (the X-NOMAD header and a 127.0.0.1 or localhost host, so a web page
open in a browser here can't read it).
"""
from ..flows.api import FlowApi, FlowSourceError, ServiceSource
from .store import message_from_dict

API_PORT = 20557
SyslogSourceError = FlowSourceError


class SyslogApi(FlowApi):
    """Answers from queries (a store.SyslogQueries) and status() (the collector's)."""
    name = "Syslog API"

    def answer(self, path, query):
        def number(name, default=None):
            value = query.get(name)
            return float(value) if value not in (None, "") else default

        if path == "/v1/status":
            return self.status()
        if path == "/v1/messages":
            limit = int(number("limit", 1000))
            if query.get("after") not in (None, ""):
                return self.queries.since(int(number("after")), limit)
            return self.queries.search(query.get("text", ""), int(number("severity", 7)), query.get("source", ""),
                                       number("start"), number("end"), number("before"), limit)
        if path == "/v1/senders":
            return self.queries.senders()
        if path == "/v1/summary":
            return self.queries.summary()
        if path == "/v1/counts":
            return self.queries.counts(number("start", 0.0), number("end"))
        raise KeyError(path)


class SyslogServiceSource(ServiceSource):
    """The NOMAD Syslog Collector service on this computer. Messages come back as syslog.SyslogMessages."""
    description = "the NOMAD Syslog Collector service on this computer"
    service_name = "Syslog Collector"

    def __init__(self, port=API_PORT, timeout=10):
        super().__init__(port, timeout)

    def status(self):
        return self.get("/v1/status")

    def since(self, after, limit=1000):
        """Messages after the ID `after`, oldest first."""
        return [message_from_dict(item) for item in self.get("/v1/messages", after=int(after), limit=limit)]

    def search(self, text="", severity=7, source="", start=None, end=None, before=None, limit=2000):
        """The newest messages matching (store.SyslogQueries.search), oldest first."""
        return [message_from_dict(item) for item in self.get(
            "/v1/messages", text=text or None, severity=severity, source=source or None, start=start, end=end,
            before=before, limit=limit)]

    def latest(self, limit):
        """The newest `limit` messages, oldest first."""
        return self.search(limit=limit)

    def senders(self):
        return self.get("/v1/senders")

    def summary(self):
        return self.get("/v1/summary")

    def counts(self, start, end=None):
        """[[source, severity, how many]] from start to end (store.SyslogQueries.counts)."""
        return self.get("/v1/counts", start=start, end=end)
