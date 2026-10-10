"""The MAC Finder page: Find on the map and in the history, Locate Now on a fake network, lists and the history."""
import os
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget

from netmap_fakes import LAB_MACS, PC1_MAC, PRINTER_MAC, build_network

from nomad.netmap import macfind
from nomad.netmap.crawl import CrawlSettings, Crawler
from nomad.netmap.sightings import SightingLog
from nomad.snapshot import NetworkSnapshot
from nomad.ui import mac_finder_tab
from nomad.ui.mac_finder_tab import COL_NOTE, COL_PORT, COL_SOURCE, COL_SWITCH, MacFinderTab


class MapPage(QObject):
    """What MAC Finder uses of the Network Map page."""
    map_shown = pyqtSignal()

    def __init__(self, network_map):
        super().__init__()
        self.network_map, self.worker = network_map, None

    def map_name(self):
        return "Test map"

    def crawl_settings(self, seeds):
        return CrawlSettings(seeds=seeds, overrides=[("10.0.0.12/32", "secret")])


class Window(QMainWindow):
    def __init__(self, map_page=None):
        super().__init__()
        self.snapshot = NetworkSnapshot()
        self.navigator = QStackedWidget()
        self.setCentralWidget(self.navigator)
        self.statuses = []
        if map_page is not None:
            self.netmap_tab = map_page

    def show_status(self, message, kind="success", timeout=10000):
        self.statuses.append(message)

    def set_busy(self, key, text):
        pass

    def clear_busy(self, key):
        pass


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def network():
    return build_network()


@pytest.fixture
def setup(app, network, tmp_path, monkeypatch):
    monkeypatch.setattr(macfind, "reverse_names", lambda addresses, timeout=2.0: {"10.10.0.21": "pc1.corp.example"})
    network_map = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                          client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    map_page = MapPage(network_map)
    window = Window(map_page)
    page = MacFinderTab(window, history=SightingLog(tmp_path / "history.db"))
    page.client_factory = network.client
    window.navigator.addWidget(page)
    yield window, page, map_page
    page.shutdown()
    window.deleteLater()
    app.processEvents()


def wait_for(condition, seconds=20):
    deadline = time.monotonic() + seconds
    while not condition() and time.monotonic() < deadline:
        QApplication.processEvents()
        time.sleep(0.01)
    QApplication.processEvents()
    assert condition()


def cells(page, column):
    return [page.table.item(row, column).text() for row in range(page.table.rowCount())]


def test_find_searches_the_map_without_asking_the_network(setup, network):
    _, page, _ = setup
    network.requests.clear()
    page.search_input.setText("3c52.8200.0001")
    page.find()
    assert cells(page, COL_SWITCH) == ["acc1.corp.example"] and cells(page, COL_PORT) == ["Gi1/0/5"]
    assert cells(page, COL_SOURCE) == ["Map"]
    assert network.requests == []
    assert "Found on the map" in page.status_label.text()
    html = page.details.toHtml()
    assert "core.corp.example" in html and "Te1/0/1" in html  # The way there


def test_find_says_what_it_did_not_find(setup):
    _, page, _ = setup
    page.search_input.setText("02:00:00:00:00:99")
    page.find()
    assert "Locate Now asks the switches" in cells(page, COL_NOTE)[0]


def test_locate_now_asks_the_switches_and_notes_the_history(setup, network):
    _, page, map_page = setup
    network.devices["10.0.0.11"].learned(PC1_MAC, 7, 7, vlan=10)  # Moved since the crawl
    page.search_input.setText(PC1_MAC)
    assert page.locate_button.isEnabled()
    page.locate()
    assert cells(page, COL_SOURCE) == ["Map"]  # The map's answer, until the switches say
    wait_for(lambda: page.worker is None)
    assert cells(page, COL_PORT) == ["Gi1/0/7"] and cells(page, COL_SOURCE) == ["Live"]
    assert "pc1.corp.example" in cells(page, mac_finder_tab.COL_NAME)  # Reverse DNS
    assert "Found it on the network now" in page.status_label.text()
    sightings = page.history.history(PC1_MAC)
    assert [sighting.port for sighting in sightings] == ["Gi1/0/7"]
    page.show_details()
    assert "Where it's been" in page.details.toHtml()


def test_the_maps_hosts_go_in_the_history_once(setup):
    _, page, map_page = setup
    page.on_map_shown()
    wait_for(lambda: page.recorder is None)
    macs, _ = page.history.count()
    assert macs == len({host.mac for host in map_page.network_map.hosts if host.mac})
    first = page.recorded
    page.on_map_shown()
    assert page.recorder is None and page.recorded == first  # The same crawl: not again
    assert page.history_label.text().startswith("History:")


def test_find_falls_back_to_the_history(setup):
    _, page, map_page = setup
    page.on_map_shown()
    wait_for(lambda: page.recorder is None)
    map_page.network_map.hosts = [host for host in map_page.network_map.hosts if host.mac != PRINTER_MAC]
    page.search_input.setText(PRINTER_MAC)
    page.find()
    assert cells(page, COL_SOURCE) == ["History"] and cells(page, COL_PORT) == ["Gi1/0/7"]


def test_a_list_of_macs(setup):
    _, page, _ = setup
    page.list_button.setChecked(True)
    assert not page.search_input.isEnabled() and page.list_panel.isVisibleTo(page)
    page.list_input.setPlainText("\n".join(["Name,MAC", f"PC,{PC1_MAC}", LAB_MACS[0], "nope!"]))
    page.find()
    assert cells(page, COL_PORT) == ["Gi1/0/5", "Eth1/10"]
    assert not page.table.isColumnHidden(mac_finder_tab.COL_QUERY)
    assert "skipped" in page.status_label.text()


def test_part_of_a_mac_live_lists_every_match(setup):
    _, page, _ = setup
    page.search_input.setText("52:54:00")
    page.locate()
    wait_for(lambda: page.worker is None)
    assert cells(page, COL_PORT) == ["Eth1/10"] * len(LAB_MACS)
    assert set(cells(page, COL_SOURCE)) == {"Live"}


def test_locate_needs_a_map(app, tmp_path):
    window = Window()
    page = MacFinderTab(window, history=SightingLog(tmp_path / "history.db"))
    page.search_input.setText(PC1_MAC)
    assert page.find_button.isEnabled() and not page.locate_button.isEnabled()
    assert "No map is open" in page.map_label.text()
    page.locate()
    assert "crawl or open one" in page.status_label.text()
    page.find()
    assert "no map is open" in cells(page, COL_NOTE)[0]
    page.deleteLater()


def test_stop(setup, network):
    _, page, _ = setup
    page.search_input.setText("52:54:00")
    page.locate()
    page.stop()
    wait_for(lambda: page.worker is None)
    assert page.locate_button.isEnabled()


def test_export_csv(setup, tmp_path, monkeypatch):
    window, page, _ = setup
    page.search_input.setText(PC1_MAC)
    page.find()
    path = tmp_path / "results.csv"
    monkeypatch.setattr(mac_finder_tab.QFileDialog, "getSaveFileName", lambda *args, **kwargs: (str(path), ""))
    page.export_csv()
    text = path.read_text(encoding="utf-8")
    assert "MAC Address" in text and "Gi1/0/5" in text


def test_settings_round_trip(setup, tmp_path):
    from PyQt5.QtCore import QSettings
    _, page, _ = setup
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    page.search_input.setText("aabb.ccdd.eeff")
    page.list_input.setPlainText("10.10.0.21")
    page.list_button.setChecked(True)
    page.save_settings(settings)
    page.list_button.setChecked(False)
    page.search_input.clear()
    page.restore_settings(settings)
    assert page.search_input.text() == "aabb.ccdd.eeff" and page.list_button.isChecked()
    assert page.list_input.toPlainText() == "10.10.0.21"


def test_the_main_window_has_its_sessions_before_mac_finder():
    """MAC Finder's SSH row needs the saved sessions and credentials when it's made: without them it's hidden."""
    from pathlib import Path
    source = (Path(mac_finder_tab.__file__).parent / "main_window.py").read_text(encoding="utf-8")
    assert source.index("self.session_store = SessionStore()") < source.index("MacFinderTab(self)")
