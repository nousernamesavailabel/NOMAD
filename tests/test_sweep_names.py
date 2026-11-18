"""Sweeps without host names, and skipping the name lookups still running once the pings are done."""
import os
import threading
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QSettings  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from nomad.sweep import SweepHit  # noqa: E402
from nomad.ui import sweep_tab  # noqa: E402
from nomad.ui.sweep_tab import SweepThread  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def fake_sweep(monkeypatch, lookup):
    def run_sweep(hosts, probe, workers, should_stop, found, progress):
        for host in hosts:
            found(host, SweepHit(1.0, ""))
        return [(host, SweepHit(1.0, "")) for host in hosts]

    monkeypatch.setattr(sweep_tab, "make_probe", lambda *args: None)
    monkeypatch.setattr(sweep_tab, "run_sweep", run_sweep)
    monkeypatch.setattr(sweep_tab, "lookup_host", lookup)


def test_no_lookups_when_names_are_off(app, monkeypatch):
    looked_up = []
    fake_sweep(monkeypatch, lambda address: looked_up.append(address) or ("host", ""))
    thread = SweepThread(["10.0.0.1", "10.0.0.2"], 10, 100, [], False, False)
    messages = []
    thread.finished_sweep.connect(messages.append)
    thread.run()
    assert looked_up == []
    assert messages[0].startswith("Sweep complete: 2 hosts")


def test_names_are_waited_for(app, monkeypatch):
    fake_sweep(monkeypatch, lambda address: (f"host-{address}", ""))
    thread = SweepThread(["10.0.0.1", "10.0.0.2"], 10, 100, [], False, True)
    names = []
    thread.host_details.connect(lambda address, name, mac: names.append(name))
    thread.run()
    QApplication.processEvents()
    assert sorted(names) == ["host-10.0.0.1", "host-10.0.0.2"]


def test_skip_names_finishes_the_sweep_without_waiting(app, monkeypatch):
    release = threading.Event()
    fake_sweep(monkeypatch, lambda address: release.wait(10) and (f"host-{address}", ""))
    thread = SweepThread([f"10.0.0.{n}" for n in range(1, 40)], 10, 100, [], False, True)
    names, messages = [], []
    thread.host_details.connect(lambda address, name, mac: names.append(name))
    thread.looking_up_names.connect(lambda remaining: thread.skip_names())
    thread.finished_sweep.connect(messages.append)
    started = time.monotonic()
    thread.run()
    assert time.monotonic() - started < 5
    release.set()
    time.sleep(0.2)
    QApplication.processEvents()
    assert names == []  # Lookups already running when skipped aren't reported
    assert messages[0].startswith("Sweep complete")  # Skipping names isn't stopping the sweep
    assert not thread.stopping


def test_ipam_page_remembers_look_up_names(app, tmp_path):
    from nomad.ui.ipam_tab import IpamTab
    check = IpamTab.__new__(IpamTab)  # Only the setting is under test
    from PyQt5.QtWidgets import QCheckBox
    check.sweep_names_check, check.hide_free_check, check.network_id = QCheckBox(), QCheckBox(), ""
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    check.restore_settings(settings)
    assert check.sweep_names_check.isChecked()  # On until unticked
    check.sweep_names_check.setChecked(False)
    check.save_settings(settings)
    check.sweep_names_check.setChecked(True)
    check.restore_settings(settings)
    assert not check.sweep_names_check.isChecked()
