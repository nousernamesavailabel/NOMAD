"""How NOMAD reads flows: from the NOMAD Flow Collector service on this computer (over HTTP on 127.0.0.1), or from a
collector running inside this NOMAD. Both answer the same questions (FlowSource).

The service's API listens on 127.0.0.1 only, so only programs on this computer can ask; it's read-only. Every request
must carry the X-NOMAD header and name 127.0.0.1 or localhost as its host, so a web page open in a browser here can't
read it (a browser can't add that header to another site's request without asking first, which the API never allows).
"""
import http.client
import json
import logging
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .store import BOTH, TOP_N, FlowQueries

log = logging.getLogger(__name__)

API_PORT = 20556
HEADER = "X-NOMAD"
TIMEOUT = 30  # A fortnight of a busy router's minutes takes a while to sum


class FlowSourceError(Exception):
    pass


# --------------------------------------------------------------------- Serving


class FlowApi:
    """Answers from queries (a store.FlowQueries) and status() (the collector's). serve() runs until stop().

    The Syslog Collector's API is one of these too, answering its own questions (answer())."""
    name = "NetFlow API"

    def __init__(self, queries, status, port=API_PORT, address="127.0.0.1"):
        self.queries, self.status = queries, status
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                api.handle(self)

        self.server = ThreadingHTTPServer((address, port), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = None

    def start(self):
        self.thread = threading.Thread(target=self.server.serve_forever, name=self.name, daemon=True)
        self.thread.start()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        if self.thread is not None:
            self.thread.join(5)

    def handle(self, request):
        host = (request.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
        if request.headers.get(HEADER) != "1" or host not in ("127.0.0.1", "localhost", "::1"):
            self.reply(request, 403, {"error": "Not allowed."})
            return
        url = urllib.parse.urlsplit(request.path)
        query = {name: values[-1] for name, values in urllib.parse.parse_qs(url.query).items()}
        try:
            answer = self.answer(url.path, query)
        except KeyError:
            self.reply(request, 404, {"error": f"No {url.path}."})
            return
        except ValueError as error:
            self.reply(request, 400, {"error": str(error)})
            return
        except Exception as error:
            log.exception("The %s couldn't answer %s", self.name, request.path)
            self.reply(request, 500, {"error": str(error)})
            return
        self.reply(request, 200, answer)

    def answer(self, path, query):
        def number(name, default=None):
            value = query.get(name)
            return float(value) if value not in (None, "") else default

        def ifindex():
            value = query.get("ifindex")
            return int(value) if value not in (None, "") else None

        if path == "/v1/status":
            return self.status()
        if path == "/v1/exporters":
            return self.queries.exporters()
        if path == "/v1/interfaces":
            return self.queries.interfaces(query.get("exporter", ""))
        if path == "/v1/top":
            return self.queries.top(query.get("exporter", ""), ifindex(), query.get("direction", BOTH),
                                    query.get("kind", "src"), number("start", 0.0), number("end", time.time()),
                                    int(number("limit", TOP_N)))
        if path == "/v1/series":
            return self.queries.series(query.get("exporter", ""), ifindex(), number("start", 0.0),
                                       number("end", time.time()))
        if path == "/v1/flows":
            return self.queries.flows(query.get("address", ""), number("start", 0.0), number("end"),
                                      query.get("exporter", ""), int(number("limit", 500)))
        if path == "/v1/summary":
            return self.queries.summary()
        raise KeyError(path)

    @staticmethod
    def reply(request, code, body):
        data = json.dumps(body).encode("utf-8")
        request.send_response(code)
        request.send_header("Content-Type", "application/json")
        request.send_header("Content-Length", str(len(data)))
        request.send_header("Cache-Control", "no-store")
        request.end_headers()
        request.wfile.write(data)


# --------------------------------------------------------------------- Asking


class FlowSource:
    """What the Flows page asks. description: where the flows come from, for the page to say."""
    description = ""

    def status(self):
        raise NotImplementedError

    def exporters(self):
        raise NotImplementedError

    def interfaces(self, exporter):
        raise NotImplementedError

    def top(self, exporter, ifindex, direction, kind, start, end, limit=TOP_N):
        raise NotImplementedError

    def series(self, exporter, ifindex, start, end):
        raise NotImplementedError

    def flows(self, address="", start=0.0, end=None, exporter="", limit=500):
        raise NotImplementedError

    def close(self):
        pass


class ServiceSource(FlowSource):
    """The NOMAD Flow Collector service on this computer."""
    description = "the NOMAD Flow Collector service on this computer"
    service_name = "Flow Collector"

    def __init__(self, port=API_PORT, timeout=TIMEOUT):
        self.port, self.timeout = port, timeout

    def get(self, path, **parameters):
        """Ask the service over plain HTTP to 127.0.0.1 (http.client: never through a proxy, and nothing to do with
        TLS; urllib's opener loaded Windows' certificate store on every call, holding Python's lock meanwhile)."""
        query = urllib.parse.urlencode({name: value for name, value in parameters.items() if value is not None})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
        try:
            connection.request("GET", path + (f"?{query}" if query else ""), headers={HEADER: "1"})
            response = connection.getresponse()
            status, body = response.status, response.read()
        except (OSError, http.client.HTTPException) as error:
            raise FlowSourceError(f"The {self.service_name} service isn't answering ({error}).") from None
        finally:
            connection.close()
        if status >= 400:
            try:
                message = json.loads(body.decode("utf-8")).get("error", "")
            except (ValueError, AttributeError):
                message = ""
            raise FlowSourceError(message or f"The {self.service_name} service said {status}.")
        try:
            return json.loads(body.decode("utf-8"))
        except ValueError as error:
            raise FlowSourceError(f"The {self.service_name} service isn't answering ({error}).") from None

    def status(self):
        return self.get("/v1/status")

    def exporters(self):
        return self.get("/v1/exporters")

    def interfaces(self, exporter):
        return self.get("/v1/interfaces", exporter=exporter)

    def top(self, exporter, ifindex, direction, kind, start, end, limit=TOP_N):
        return self.get("/v1/top", exporter=exporter, ifindex=ifindex, direction=direction, kind=kind, start=start,
                        end=end, limit=limit)

    def series(self, exporter, ifindex, start, end):
        return self.get("/v1/series", exporter=exporter, ifindex=ifindex, start=start, end=end)

    def flows(self, address="", start=0.0, end=None, exporter="", limit=500):
        return self.get("/v1/flows", address=address, start=start, end=end, exporter=exporter, limit=limit)


class LocalSource(FlowSource):
    """A collector running inside this NOMAD (collector.FlowCollector)."""

    def __init__(self, collector):
        self.collector = collector
        self.queries = FlowQueries(collector.path)
        self.description = f"this NOMAD, listening on UDP {collector.port}"

    def status(self):
        return self.collector.status()

    def exporters(self):
        return self.queries.exporters()

    def interfaces(self, exporter):
        return self.queries.interfaces(exporter)

    def top(self, exporter, ifindex, direction, kind, start, end, limit=TOP_N):
        return self.queries.top(exporter, ifindex, direction, kind, start, end, limit)

    def series(self, exporter, ifindex, start, end):
        return self.queries.series(exporter, ifindex, start, end)

    def flows(self, address="", start=0.0, end=None, exporter="", limit=500):
        return self.queries.flows(address, start, end, exporter, limit)

    def close(self):
        self.queries.close()
