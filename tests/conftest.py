"""Shared test set-up: free the Qt objects each test left for deletion, and keep the map monitor off the network.

Tests end with window.deleteLater() and processEvents(), but outside a running event loop processEvents() doesn't
carry out deferred deletes: every test's windows stayed alive until the interpreter shut down, and freeing them all
then crashed now and then (a Windows access violation after the last test, with every test passed).
"""
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    try:
        from PyQt5.QtCore import QCoreApplication, QEvent
    except ImportError:
        return
    if QCoreApplication.instance() is not None:
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


class _NoSnmp:
    """Stands in for SnmpClient where a page reads devices in the background on its own (the map's monitor looking
    for IP SLA probes): no packets leave a test, and every device is silent."""

    def __init__(self, host, *args, **kwargs):
        from nomad.snmp import SnmpError
        raise SnmpError(f"No answer from {host} (tests don't use the network).")


@pytest.fixture(autouse=True)
def _no_monitor_snmp(monkeypatch):
    try:
        from nomad.ui import netmap_monitor
    except ImportError:
        return
    monkeypatch.setattr(netmap_monitor, "SnmpClient", _NoSnmp)
