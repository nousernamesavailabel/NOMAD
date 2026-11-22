"""Latency page: Add / Update renames the target for an address, or points the target with a name at a new address."""
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import QApplication, QWidget

from nomad.latency import same_host
from nomad.ui.latency_tab import LatencyTab


class FakeWindow(QWidget):
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)

    @staticmethod
    def current_adapter():
        return None

    def set_busy(self, *_):
        pass

    def clear_busy(self, *_):
        pass


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app):
    window = FakeWindow()
    tab = LatencyTab(window)
    yield tab
    tab.shutdown()
    window.close()
    window.deleteLater()


def targets(page):
    return [(target.name, target.host) for target in page.targets]


def submit(page, name, host):
    page.name_input.setText(name)
    page.host_input.setText(host)
    page.add_or_update_target()


def test_same_host():
    assert same_host("10.0.0.1", " 10.0.0.1 ")
    assert same_host("2001:DB8:0::1", "2001:db8::1")
    assert same_host("R1.Lab.", "r1.lab")
    assert not same_host("10.0.0.1", "10.0.0.10")


def test_new_name_for_an_address_renames_its_target(page):
    page.targets[0].add(time.time(), 12.0)
    submit(page, "Google", "8.8.8.8")
    assert targets(page) == [("Google", "8.8.8.8"), ("Cloudflare DNS", "1.1.1.1")]
    assert page.targets[0].samples  # Same host: its history is kept
    assert page.name_input.text() == "" and page.host_input.text() == ""


def test_new_address_for_a_name_moves_its_target(page):
    submit(page, "google dns", "8.8.4.4")
    assert targets(page) == [("google dns", "8.8.4.4"), ("Cloudflare DNS", "1.1.1.1")]


def test_new_name_and_address_adds_a_target(page):
    submit(page, "R1", "10.0.0.1")
    assert targets(page)[-1] == ("R1", "10.0.0.1") and len(page.targets) == 3


def test_name_of_one_target_and_address_of_another_is_refused(page):
    submit(page, "Google DNS", "1.1.1.1")
    assert targets(page) == [("Google DNS", "8.8.8.8"), ("Cloudflare DNS", "1.1.1.1")]
    assert "already monitored as Cloudflare DNS" in page.status_label.text()
    assert page.name_input.text() == "Google DNS"  # Left for the user to change

    submit(page, "Cloudflare", "1.1.1.1")  # A good entry clears the message
    assert targets(page)[1] == ("Cloudflare", "1.1.1.1")
    assert page.status_label.text() == ""


def test_add_target_from_a_menu_keeps_names_unique(page):
    """Monitor Latency from the map: the target for the address is switched on, keeping its name when the device's
    name belongs to another target."""
    page.targets[1].enabled = False
    page.add_target("Google DNS", "1.1.1.1")
    assert targets(page) == [("Google DNS", "8.8.8.8"), ("Cloudflare DNS", "1.1.1.1")]
    assert page.targets[1].enabled


def test_gauge_x_switches_its_target_off(page, app):
    """The x on a gauge unticks the target's On box: its gauge goes and the target stays in the table."""
    assert len(page.gauges) == 2
    gauge = page.gauges[id(page.targets[1])]
    gauge.off_button.click()
    assert page.table.item(1, 0).checkState() == Qt.Unchecked
    assert not page.targets[1].enabled and page.targets[0].enabled
    app.processEvents()  # The table rebuilds once the click is done
    assert list(page.gauges) == [id(page.targets[0])]
    assert targets(page) == [("Google DNS", "8.8.8.8"), ("Cloudflare DNS", "1.1.1.1")]
