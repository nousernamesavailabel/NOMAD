"""The NOMAD Dashboard's web server over real HTTPS: signing in, what needs a session, the security headers, the live
stream and the CSV exports."""
import http.client
import json
import ssl
import threading

import pytest

from nomad.dashboard import tls
from nomad.dashboard.accounts import Accounts, UserFile
from nomad.dashboard.engine import Engine
from nomad.dashboard.web import COOKIE, DashboardServer
from test_dashboard import FakeCollectors, FakeReader, small_map, snapshot_of


@pytest.fixture
def dashboard(tmp_path):
    tls.make_self_signed(tmp_path)
    UserFile(tmp_path).add("alice", "correct horse")
    engine = Engine(tmp_path, status_reader=FakeReader(), collectors=FakeCollectors())
    engine.publish(tribe=snapshot_of(small_map()).tribe)
    engine.step()
    server = DashboardServer(engine, Accounts(tmp_path), tls.server_context(tmp_path), 0, host="127.0.0.1")
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    engine.stop_event.set()
    server.stop()
    engine.stop()
    thread.join(10)


def ask(server, method, path, body=None, headers=None):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Self-signed, made by the test
    connection = http.client.HTTPSConnection("127.0.0.1", server.port, context=context, timeout=10)
    try:
        connection.request(method, path, body=json.dumps(body) if body is not None else None, headers=headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def sign_in(server, password="correct horse"):
    return ask(server, "POST", "/api/login", {"user": "alice", "password": password},
               {"Content-Type": "application/json", "X-NOMAD-Dashboard": "1"})


def cookie_of(headers):
    return headers["Set-Cookie"].split(";")[0]


def test_nothing_without_signing_in(dashboard):
    status, headers, _ = ask(dashboard, "GET", "/")
    assert status == 303 and headers["Location"] == "/login"
    assert ask(dashboard, "GET", "/api/page/devices")[0] == 401
    assert ask(dashboard, "GET", "/export/devices.csv")[0] == 401
    assert ask(dashboard, "GET", "/static/app.js")[0] == 401
    status, headers, body = ask(dashboard, "GET", "/login")
    assert status == 200 and b"Sign In" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert "unsafe-inline" not in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert ask(dashboard, "GET", "/static/login.js")[0] == 200
    assert ask(dashboard, "GET", "/static/../service.py")[0] in (401, 404)


def test_signing_in_needs_the_header_and_the_right_password(dashboard):
    status, _, _ = ask(dashboard, "POST", "/api/login", {"user": "alice", "password": "correct horse"},
                       {"Content-Type": "application/json"})
    assert status == 403  # No X-NOMAD-Dashboard header: another site's form
    status, _, _ = ask(dashboard, "POST", "/api/login", {"user": "alice", "password": "correct horse"},
                       {"X-NOMAD-Dashboard": "1", "Origin": "https://evil.example"})
    assert status == 403
    status, _, body = sign_in(dashboard, "wrong")
    assert status == 401 and b"isn't right" in body
    status, headers, body = sign_in(dashboard)
    assert status == 200 and json.loads(body)["user"] == "alice"
    cookie = headers["Set-Cookie"]
    assert cookie.startswith(f"{COOKIE}=") and "HttpOnly" in cookie and "Secure" in cookie and \
        "SameSite=Strict" in cookie


def test_pages_exports_and_the_stream_once_signed_in(dashboard):
    _, headers, _ = sign_in(dashboard)
    cookie = {"Cookie": cookie_of(headers)}
    for page in ("overview", "devices", "events", "syslog", "traffic", "vpns", "ipam", "hosts", "sites", "map", "trends",
                 "reviews"):
        status, headers, body = ask(dashboard, "GET", f"/api/page/{page}", headers=cookie)
        assert status == 200, page
        assert headers["Cache-Control"] == "no-store"
        json.loads(body)
    status, _, body = ask(dashboard, "GET", "/api/page/map?id=1&view=l2", headers=cookie)
    assert {node["key"] for node in json.loads(body)["nodes"]} == {"r1", "s1", "s2"}
    status, _, body = ask(dashboard, "GET", "/api/details?map=1&key=r1", headers=cookie)
    assert status == 200 and json.loads(body)["title"] == "R1"
    assert ask(dashboard, "GET", "/api/details?map=1&key=nothing", headers=cookie)[0] == 404
    assert ask(dashboard, "GET", "/api/details?map=x&key=r1", headers=cookie)[0] == 400
    assert ask(dashboard, "GET", "/api/details?map=1&key=r1")[0] == 401
    status, _, body = ask(dashboard, "GET", "/api/series/port?map=1&device=r1&port=Gi0/0&span=24h", headers=cookie)
    assert status == 200 and json.loads(body)["points"] == []  # The fake's sample is from 1970
    status, headers, body = ask(dashboard, "GET", "/export/devices.csv", headers=cookie)
    assert status == 200 and headers["Content-Type"].startswith("text/csv") and b"S1" in body
    assert "attachment" in headers["Content-Disposition"]
    assert ask(dashboard, "GET", "/api/page/nothing", headers=cookie)[0] == 404
    assert ask(dashboard, "GET", "/static/app.js", headers=cookie)[0] == 200
    status, _, body = ask(dashboard, "GET", "/", headers=cookie)
    assert status == 200 and b"/static/app.js" in body

    context = ssl.create_default_context()
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    connection = http.client.HTTPSConnection("127.0.0.1", dashboard.port, context=context, timeout=10)
    connection.request("GET", "/api/stream", headers=cookie)
    response = connection.getresponse()
    assert response.status == 200 and response.getheader("Content-Type").startswith("text/event-stream")
    response.readline()  # retry
    assert response.readline().startswith(b"event: revision")
    dashboard.engine.publish()  # The data changed
    response.readline()
    response.readline()
    assert response.readline().startswith(b"event: revision")
    connection.close()

    status, headers, _ = ask(dashboard, "POST", "/api/logout", {}, dict(cookie, **{"X-NOMAD-Dashboard": "1"}))
    assert status == 200
    assert ask(dashboard, "GET", "/api/page/devices", headers=cookie)[0] == 401
