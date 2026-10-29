"""Traceroute's Stop doesn't wait on DNS: the target's name or the routers' names."""
import socket
import threading
import time

import pytest
from PyQt5.QtWidgets import QApplication

from nomad.icmp import IP_SUCCESS, IP_TTL_EXPIRED_TRANSIT, EchoReply
from nomad.ui import traceroute_tab
from nomad.ui.traceroute_tab import TracerouteThread


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class FakeIcmp:
    """Two hops: a router at TTL 1, the target at TTL 2."""

    def __init__(self, family):
        pass

    def echo(self, destination, timeout=1000, ttl=128, **kwargs):
        if ttl == 1:
            return EchoReply(IP_TTL_EXPIRED_TRANSIT, "10.0.0.1", 1)
        return EchoReply(IP_SUCCESS, destination, 2)

    def close(self):
        pass


@pytest.fixture
def slow_dns(monkeypatch):
    """Name lookups that hang until released (as a DNS server that never answers a PTR query)."""
    release = threading.Event()

    def hang(*args):
        release.wait(10)
        raise socket.herror("no answer")

    monkeypatch.setattr(traceroute_tab, "IcmpClient", FakeIcmp)
    monkeypatch.setattr(traceroute_tab.socket, "gethostbyaddr", hang)
    yield hang
    release.set()


def run_and_stop_after(thread, seconds):
    """Run the trace here, pressing Stop after the given time; how long run() took, and its finish message."""
    finished = []
    thread.finished_trace.connect(lambda message, reached: finished.append(message))
    threading.Timer(seconds, thread.stop).start()
    started = time.monotonic()
    thread.run()
    return time.monotonic() - started, finished


def test_stop_while_router_names_are_looked_up(app, slow_dns, monkeypatch):
    monkeypatch.setattr(traceroute_tab, "resolve_host", lambda host: ("192.0.2.9", socket.AF_INET))
    thread = TracerouteThread("192.0.2.9", 5, 100, 1, False, True)
    waiting = []
    thread.waiting_for_names.connect(waiting.append)
    took, finished = run_and_stop_after(thread, 0.3)
    assert took < 2
    assert finished == ["Stopped."]
    assert waiting == [2]  # The router and the target, still to be named when the probes were done


def test_stop_while_the_target_is_resolving(app, slow_dns, monkeypatch):
    monkeypatch.setattr(traceroute_tab, "resolve_host", slow_dns)
    thread = TracerouteThread("slow.example", 5, 100, 1, False, True)
    took, finished = run_and_stop_after(thread, 0.3)
    assert took < 2
    assert finished == ["Stopped."]


def test_names_come_in_before_the_trace_is_done(app, monkeypatch):
    monkeypatch.setattr(traceroute_tab, "IcmpClient", FakeIcmp)
    monkeypatch.setattr(traceroute_tab, "resolve_host", lambda host: ("192.0.2.9", socket.AF_INET))
    monkeypatch.setattr(traceroute_tab.socket, "gethostbyaddr", lambda address: (f"r-{address}", [], [address]))
    thread = TracerouteThread("192.0.2.9", 5, 100, 1, False, True)
    names, finished = {}, []
    thread.name_resolved.connect(names.__setitem__)
    thread.finished_trace.connect(lambda message, reached: finished.append((message, reached)))
    thread.run()
    app.processEvents()  # Names are sent from the lookup threads
    assert names == {"10.0.0.1": "r-10.0.0.1", "192.0.2.9": "r-192.0.2.9"}
    assert finished == [("Trace complete: 192.0.2.9 is 2 hops away.", True)]
