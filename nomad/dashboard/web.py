"""The NOMAD Dashboard's web server: HTTPS, a sign-in for each person, and read-only pages.

    GET  /login, /                      the sign-in page and the dashboard itself (static files, nomad/data/dashboard)
    GET  /static/<file>                 their scripts and styles (only the files in STATIC_FILES)
    POST /api/login {"user", "password"}  signs in: sets the session cookie (HttpOnly, Secure, SameSite=Strict)
    POST /api/logout                    signs out
    GET  /api/me                        who's signed in
    GET  /api/page/<page>?...           a page's data (views.py)
    GET  /api/details?map=&key=         a device's (or L3 subnet's) details, as NOMAD's map details pane has them
    GET  /api/series/<port|subnet>?...  a trend's points
    GET  /api/stream                    Server-Sent Events: "revision" each time the data changes
    GET  /export/<table>.csv            a page's table

Everything but the sign-in page and its script needs a session. POSTs need the X-NOMAD-Dashboard header (which a
page on another site can't send without asking, and isn't allowed to) and, when the browser gives one, an Origin of
this server. Every answer carries a strict Content-Security-Policy (only this server's scripts and styles, no frames).
"""
import http.server
import json
import logging
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import views
from .accounts import AccountError

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent.parent / "data" / "dashboard"
STATIC_FILES = {"app.js": "text/javascript", "map.js": "text/javascript", "login.js": "text/javascript",
                "app.css": "text/css", "icon.svg": "image/svg+xml"}
COOKIE = "nomad_dashboard"
HEADER = "X-NOMAD-Dashboard"
MAX_BODY = 16 * 1024
MAX_STREAMS = 64
MAX_STREAMS_PER_SESSION = 4
STREAM_PING_SECONDS = 20
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                               "connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; "
                               "frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class DashboardServer:
    """The HTTPS listener (serve() until stop()), answering from an engine.Engine with accounts.Accounts."""

    def __init__(self, engine, accounts, context, port, host=""):
        from ..ipam.server import _TlsServer
        self.engine, self.accounts = engine, accounts
        self.streams = {}  # Session token hash -> open streams
        self.stream_lock = threading.Lock()
        handler = type("Handler", (_Handler,), {"app": self})
        try:
            self.httpd = _TlsServer((host, port), handler, context)
        except OSError as error:
            raise OSError(f"Couldn't listen on TCP {port}: {error.strerror or error}. Another program may be using "
                          f"it (see which with: netstat -ano | findstr :{port}).") from error
        self.port = self.httpd.server_address[1]

    def serve(self):
        log.info("NOMAD Dashboard listening on HTTPS port %s", self.port)
        try:
            self.httpd.serve_forever(poll_interval=0.5)
        finally:
            self.httpd.server_close()

    def stop(self):
        stopper = threading.Thread(target=self.httpd.shutdown, name="Dashboard stop", daemon=True)
        stopper.start()
        stopper.join(10)

    def open_stream(self, key):
        with self.stream_lock:
            if sum(self.streams.values()) >= MAX_STREAMS or self.streams.get(key, 0) >= MAX_STREAMS_PER_SESSION:
                return False
            self.streams[key] = self.streams.get(key, 0) + 1
            return True

    def close_stream(self, key):
        with self.stream_lock:
            self.streams[key] = max(0, self.streams.get(key, 1) - 1)

    # ----------------------------------------------------------------- Answers

    def page(self, name, query):
        engine = self.engine
        snapshot = engine.snapshot
        if name == "overview":
            return views.overview(snapshot, engine.history)
        if name == "devices":
            return views.devices(snapshot)
        if name == "events":
            return views.events(snapshot, engine.history)
        if name == "traffic":
            return views.traffic(snapshot)
        if name == "vpns":
            return views.vpns(snapshot)
        if name == "ipam":
            return views.ipam(snapshot)
        if name == "hosts":
            return views.hosts(snapshot, engine, query.get("window", "1h"))
        if name == "sites":
            return views.sites(snapshot)
        if name == "map":
            maps = views.map_list(snapshot)
            if not query.get("id"):
                return {"maps": maps, "nodes": [], "links": [], "groups": [], "tunnels": [],
                        "freshness": views.freshness(snapshot, time.time())}
            return views.topology(snapshot, int(query["id"]), query.get("view", "l2"))
        if name == "trends":
            return views.trends(snapshot)
        raise KeyError(name)


class _Handler(http.server.BaseHTTPRequestHandler):
    app = None  # Set per server
    server_version = "NOMAD-Dashboard"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        log.debug("%s %s", self.client_address[0], format % args)

    # ----------------------------------------------------------------- Replies

    def send(self, status, body, content_type="application/json", headers=None, cache=False):
        data = body if isinstance(body, bytes) else (json.dumps(body).encode("utf-8")
                                                     if content_type == "application/json" else body.encode("utf-8"))
        self.send_response(status)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or
                                                         content_type == "application/json" else ""))
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "private, max-age=300" if cache else "no-store")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def redirect(self, where):
        self.send_response(303)
        self.send_header("Location", where)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        self.end_headers()

    def static(self, name):
        content_type = STATIC_FILES.get(name) or ("text/html" if name in ("index.html", "login.html") else None)
        if content_type is None:
            return self.send(404, {"error": "Not found."})
        try:
            data = (WEB_DIR / name).read_bytes()
        except OSError:
            return self.send(404, {"error": "Not found."})
        self.send(200, data, content_type, cache=name in STATIC_FILES)

    # ----------------------------------------------------------------- Who's asking

    def token(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            name, _, value = part.strip().partition("=")
            if name == COOKIE:
                return value
        return ""

    def session(self):
        return self.app.accounts.session(self.token())

    def same_origin(self):
        """A POST from this server's own pages: the custom header, and the Origin (if any) is this server."""
        if self.headers.get(HEADER) != "1":
            return False
        origin = self.headers.get("Origin")
        if origin is None:
            return True
        host = (self.headers.get("Host") or "").lower()
        return urlparse(origin).netloc.lower() == host and urlparse(origin).scheme == "https"

    def cookie(self, value, max_age):
        return (f"{COOKIE}={value}; Path=/; HttpOnly; Secure; SameSite=Strict"
                + (f"; Max-Age={max_age}" if max_age is not None else ""))

    # ----------------------------------------------------------------- Requests

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        try:
            url = urlparse(self.path)
            path = url.path
            query = {name: values[-1] for name, values in parse_qs(url.query).items()}
            if path == "/login":
                return self.static("login.html")
            if path.startswith("/static/"):
                name = path[len("/static/"):]
                if name in ("login.js", "app.css", "icon.svg") or self.session() is not None:
                    return self.static(name)
                return self.send(401, {"error": "Sign in first."})
            if path == "/favicon.ico":
                return self.static("icon.svg")
            session = self.session()
            if session is None:
                if path == "/" or path == "/index.html":
                    return self.redirect("/login")
                return self.send(401, {"error": "Sign in first.", "signed_out": True})
            if path in ("/", "/index.html"):
                return self.static("index.html")
            if path == "/api/me":
                return self.send(200, {"user": session.user, "kiosk": session.kiosk})
            if path.startswith("/api/page/"):
                return self.send(200, self.app.page(path[len("/api/page/"):], query))
            if path == "/api/details":
                return self.send(200, views.node_details(self.app.engine.snapshot, int(query["map"]), query["key"]))
            if path.startswith("/api/series/"):
                return self.send(200, views.series(self.app.engine.history, path[len("/api/series/"):], query))
            if path == "/api/stream":
                return self.stream()
            if path.startswith("/export/") and path.endswith(".csv"):
                name = path[len("/export/"):-len(".csv")]
                engine = self.app.engine
                filename, text = views.csv_table(name, engine.snapshot, engine.history, engine, query)
                return self.send(200, "﻿" + text, "text/csv",
                                 {"Content-Disposition": f'attachment; filename="{filename}"'})
            return self.send(404, {"error": "Not found."})
        except KeyError:
            return self.send(404, {"error": "Not found."})
        except (ValueError, TypeError) as error:
            return self.send(400, {"error": f"That request isn't right ({error})."})
        except (ConnectionError, TimeoutError):
            return None
        except Exception:
            log.exception("Request failed: GET %s", self.path)
            return self.send(500, {"error": "The dashboard had a problem with that; details are in its log."})

    def do_POST(self):
        try:
            path = urlparse(self.path).path
            if not self.same_origin():
                return self.send(403, {"error": "Not allowed."})
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self.send(413, {"error": "Too large."})
            try:
                body = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.send(400, {"error": "That isn't JSON."})
            if path == "/api/login":
                return self.login(body if isinstance(body, dict) else {})
            if path == "/api/logout":
                self.app.accounts.sign_out(self.token())
                return self.send(200, {"ok": True}, headers={"Set-Cookie": self.cookie("", 0)})
            return self.send(404, {"error": "Not found."})
        except (ConnectionError, TimeoutError):
            return None
        except Exception:
            log.exception("Request failed: POST %s", self.path)
            return self.send(500, {"error": "The dashboard had a problem with that; details are in its log."})

    def login(self, body):
        name, password = str(body.get("user") or ""), str(body.get("password") or "")
        address = self.client_address[0]
        try:
            token = self.app.accounts.sign_in(name, password, address)
        except AccountError as error:
            log.info("Sign-in refused for %r from %s: locked out", name, address)
            return self.send(429, {"error": str(error)})
        if token is None:
            log.info("Sign-in failed for %r from %s", name, address)
            if not self.app.accounts.has_users():
                return self.send(401, {"error": "No logins have been set up yet: add one in NOMAD (Tools > NOMAD "
                                                "Dashboard Service)."})
            return self.send(401, {"error": "That login name or password isn't right."})
        session = self.app.accounts.session(token)
        log.info("%s signed in from %s", session.user, address)
        from .accounts import KIOSK_DAYS
        return self.send(200, {"ok": True, "user": session.user, "kiosk": session.kiosk},
                         headers={"Set-Cookie": self.cookie(token, KIOSK_DAYS * 86400 if session.kiosk else None)})

    def stream(self):
        """Server-Sent Events: the revision now, then each new one, with a comment now and then to keep it open."""
        import hashlib
        key = hashlib.sha256(self.token().encode("utf-8")).hexdigest()
        if not self.app.open_stream(key):
            return self.send(429, {"error": "Too many pages open."})
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            for name, value in SECURITY_HEADERS.items():
                self.send_header(name, value)
            self.end_headers()
            self.close_connection = True
            engine = self.app.engine
            revision = engine.snapshot.revision
            self.wfile.write(f"retry: 5000\nevent: revision\ndata: {revision}\n\n".encode("ascii"))
            self.wfile.flush()
            last_check = time.monotonic()
            while not engine.stop_event.is_set():
                latest = engine.wait_for_change(revision, STREAM_PING_SECONDS)
                if latest != revision:
                    revision = latest
                    self.wfile.write(f"event: revision\ndata: {revision}\n\n".encode("ascii"))
                else:
                    self.wfile.write(b": still here\n\n")
                self.wfile.flush()
                if time.monotonic() - last_check > 60:  # Signed out (or its login removed) meanwhile: stop
                    last_check = time.monotonic()
                    if self.session() is None:
                        break
        except (ConnectionError, TimeoutError, OSError):
            pass
        finally:
            self.app.close_stream(key)
