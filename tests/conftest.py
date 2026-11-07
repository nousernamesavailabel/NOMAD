"""Shared test set-up: free the Qt objects each test left for deletion, let go of keys a test left held, and keep the
map monitor off the network.

Tests end with window.deleteLater() and processEvents(), but outside a running event loop processEvents() doesn't
carry out deferred deletes: every test's windows stayed alive until the interpreter shut down, and freeing them all
then crashed now and then (a Windows access violation after the last test, with every test passed).

QTest.keyClick(widget, key, Qt.ShiftModifier) ends with Shift's release still carrying Shift, so Qt thinks Shift (or
Ctrl, or Alt) is held into every later test: there, selectRow() on a multi-select table extends (or toggles) the
selection instead of choosing one row.
"""
import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    yield
    try:
        from PyQt5.QtCore import QCoreApplication, QEvent, Qt
        from PyQt5.QtTest import QTest
        from PyQt5.QtWidgets import QApplication, QWidget
    except ImportError:
        return
    app = QCoreApplication.instance()
    if app is not None:
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
    if isinstance(app, QApplication) and app.keyboardModifiers():
        QTest.keyRelease(QWidget(), Qt.Key_Shift)  # A release with no modifiers: nothing's held now


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
