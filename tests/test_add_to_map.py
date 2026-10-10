"""Add Device to Map from an address on any page (the user picks the map), and the Network Map's Key."""
import os
from unittest.mock import Mock

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QDialog, QMenu, QMessageBox, QWidget  # noqa: E402

from nomad.netmap import store  # noqa: E402
from nomad.netmap.model import ROUTER, SWITCH, UNCHECKED, Device, NetworkMap  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.host_menu import ADD_TO_MAP, HostActions  # noqa: E402
from nomad.ui.netmap_dialogs import DeviceDialog, MapChoiceDialog  # noqa: E402
from nomad.ui.netmap_key import SECTIONS, MapKeyDialog  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)

    def __init__(self):
        super().__init__()
        self.statuses = []
        self.navigator = Mock()

    def current_adapter(self):
        return None

    def show_status(self, message, kind="success", timeout=10000):
        self.statuses.append((message, kind))

    def __getattr__(self, name):
        return lambda *args, **kwargs: None


class FakeMaps:
    """TribeMaps with one shared map."""

    def __init__(self):
        self.network_map = NetworkMap(started="2026-10-01T09:00:00")
        self.network_map.devices["core"] = Device(key="core", name="core", mgmt_ip="10.0.0.1", kind=ROUTER)

    def maps(self):
        return [{"id": 7, "name": "Campus"}]

    def map_info(self, map_id):
        return {"id": 7, "name": "Campus"} if map_id == 7 else None

    def snapshot(self, map_id):
        return self.network_map, {"seeds": "10.0.0.1"}, {}

    def pending_count(self, map_id=None):
        return 0


class FakeTribe:
    """TribeSync with no server."""
    available = True

    def __init__(self):
        self.maps = FakeMaps()
        self.saved = []

    def ensure(self):
        return self.maps

    def save(self, map_id, network_map, settings, seen=None):
        self.saved.append((map_id, network_map, settings))
        return 1

    def pending_count(self, map_id=None):
        return 0

    def status_text(self, map_id):
        return ""

    def reset(self, forget=False):
        pass

    def shutdown(self):
        pass


@pytest.fixture
def tab(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    page.tribe = FakeTribe()
    yield page
    page.shutdown()


def saved_map(tmp_path, name="Office"):
    network_map = NetworkMap(started="2026-09-30T10:00:00")
    network_map.devices["sw1"] = Device(key="sw1", name="sw1", mgmt_ip="10.0.0.2", kind=SWITCH)
    return store.save(network_map, tmp_path / f"{name}{store.EXTENSION}")


def answer(monkeypatch, choose, show=False, accept_device=True, name=None):
    """Answer the two dialogs: choose(choices) picks the map's (kind, value); the device dialog is accepted as filled
    in (with name typed in, if given)."""
    seen = {}

    def choice_exec(dialog):
        seen["choices"] = [dialog.map_combo.itemData(index) for index in range(dialog.map_combo.count())]
        seen["texts"] = [dialog.map_combo.itemText(index) for index in range(dialog.map_combo.count())]
        wanted = choose(seen["choices"])
        dialog.map_combo.setCurrentIndex(seen["choices"].index(wanted))
        dialog.show_check.setChecked(show)
        return QDialog.Accepted

    def device_exec(dialog):
        seen["prefilled"] = dialog.ip_input.text(), dialog.name_input.text()
        seen["title"] = dialog.windowTitle()
        if name is not None:
            dialog.name_input.setText(name)
        return QDialog.Accepted if accept_device else QDialog.Rejected

    monkeypatch.setattr(MapChoiceDialog, "exec_", choice_exec)
    monkeypatch.setattr(DeviceDialog, "exec_", device_exec)
    return seen


def test_choices_list_the_open_map_saved_maps_tribe_maps_and_new(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    other = saved_map(tmp_path, "Warehouse")
    tab.show_map(store.load(office), office)
    choices = tab.map_choices()
    kinds = [(kind, value) for _, kind, value in choices]
    assert kinds[0] == (netmap_tab.OPEN_MAP, None)
    assert (netmap_tab.FILE_MAP, office) not in kinds  # The open one is listed once, as open
    assert (netmap_tab.FILE_MAP, other) in kinds
    assert (netmap_tab.TRIBE_MAP, 7) in kinds
    assert kinds[-2:] == [(netmap_tab.NEW_MAP, None), (netmap_tab.FILE_MAP, None)]
    assert choices[0][0] == "Open map: Office"


def test_add_to_a_saved_map_that_is_not_open(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    seen = answer(monkeypatch, lambda choices: (netmap_tab.FILE_MAP, office), name="printer-room-sw")
    key = tab.add_address("10.0.0.50%12", "printer-room")
    assert seen["prefilled"] == ("10.0.0.50", "printer-room")
    assert seen["title"] == "Add Device to Office"
    assert tab.network_map is None  # Nothing was opened
    device = store.load(office).devices[key]
    assert (device.mgmt_ip, device.name, device.manual, device.source) == ("10.0.0.50", "printer-room-sw", True,
                                                                           UNCHECKED)
    assert tab.window.statuses[-1] == ("Added printer-room-sw to Office. Open that map to see it.", "success")


def test_add_to_a_tribe_map_saves_it_for_the_tribe(tab, monkeypatch):
    answer(monkeypatch, lambda choices: (netmap_tab.TRIBE_MAP, 7))
    key = tab.add_address("10.0.0.60")
    map_id, network_map, settings = tab.tribe.saved[-1]
    assert map_id == 7 and settings == {"seeds": "10.0.0.1"}
    assert network_map.devices[key].mgmt_ip == "10.0.0.60" and "core" in network_map.devices
    assert "Campus" in tab.window.statuses[-1][0]


def test_add_to_the_open_map_and_show_it(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    tab.show_map(store.load(office), office)
    monkeypatch.setattr(tab, "check_devices", lambda keys, announce=False: None)
    answer(monkeypatch, lambda choices: choices[0], show=True)
    key = tab.add_address("10.0.0.70", "lab-sw")
    assert key in tab.network_map.devices and tab.network_map.devices[key].name == "lab-sw"
    assert key in store.load(office).devices  # Saved where it came from
    tab.window.navigator.setCurrentWidget.assert_called_with(tab)
    assert tab.show_added  # Remembered for next time


def test_add_to_a_new_map(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    tab.show_map(store.load(office), office)
    before = set(tmp_path.glob(f"*{store.EXTENSION}"))
    answer(monkeypatch, lambda choices: (netmap_tab.NEW_MAP, None))
    key = tab.add_address("10.0.0.80")
    new = set(tmp_path.glob(f"*{store.EXTENSION}")) - before
    assert len(new) == 1 and key in store.load(new.pop()).devices
    assert tab.map_path == office and key not in tab.network_map.devices  # The open map is untouched


def test_an_address_already_on_the_map_is_not_added_again(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    seen = answer(monkeypatch, lambda choices: (netmap_tab.FILE_MAP, office))
    told = []
    monkeypatch.setattr(QMessageBox, "information", lambda *args: told.append(args[2]))
    assert tab.add_address("10.0.0.2") is None
    assert "prefilled" not in seen and told == ["10.0.0.2 is already on Office: it's sw1."]
    assert list(store.load(office).devices) == ["sw1"]


def test_cancelling_the_device_leaves_the_map_alone(tab, tmp_path, monkeypatch):
    office = saved_map(tmp_path)
    written = office.read_bytes()
    answer(monkeypatch, lambda choices: (netmap_tab.FILE_MAP, office), accept_device=False)
    assert tab.add_address("10.0.0.90") is None
    assert office.read_bytes() == written


def test_ip_menus_offer_add_device_to_map(app):
    window = Mock()
    window.terminal_tab.saved_matches.return_value = []
    window.scp_tab.saved_matches.return_value = []
    window.rdp_tab.saved_matches.return_value = []
    menu = QMenu()
    actions = HostActions(window, None).add_to(menu, "10.0.0.5", name="edge")
    action = next(action for action in actions if action.text() == ADD_TO_MAP)
    actions[action]()
    window.netmap_tab.add_address.assert_called_once_with("10.0.0.5", "edge")
    menu.deleteLater()


def test_key_explains_every_color_and_line(tab, app):
    titles = [title for title, _ in SECTIONS]
    assert any(title.startswith("Devices") for title in titles)
    assert any(title.startswith("Links") for title in titles)
    assert any("VLAN" in title for title in titles)
    tab.update_map_menu()
    entry = next(entry for entry, button in tab.map_entries if button is tab.key_button)
    entry.trigger()
    dialog = tab.key_dialog
    assert isinstance(dialog, MapKeyDialog) and dialog.isVisible() and not dialog.isModal()
    dialog.grab()  # Every sample draws
    entry.trigger()
    assert tab.key_dialog is dialog  # One key, raised again
    dialog.close()
