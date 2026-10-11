"""The Port Mirroring page: filled in from the map, Plan (reading the switches over SSH), Set Up, checking it took,
Take Away, This PC, and the list of mirrors kept."""
import ipaddress
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402
from test_mirror import ConfigChannel, FakePushShell, campus  # noqa: E402

from nomad.netmap import macssh, mirror  # noqa: E402
from nomad.terminal.sessions import Session, SessionStore  # noqa: E402
from nomad.ui import mirror_tab  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class MapPage(QWidget):
    map_shown = pyqtSignal()

    def __init__(self, network_map):
        super().__init__()
        self.network_map = network_map

    def map_name(self):
        return "Campus"

    def session_hints(self, network_map, device):
        return {"aliases": [], "name": device.name, "folder": ""}


class Window(QWidget):
    def __init__(self, network_map, sessions, adapters=()):
        super().__init__()
        self.netmap_tab = MapPage(network_map)
        self.session_store = sessions
        self.snapshot = SimpleNamespace(real_adapters=lambda: list(adapters))
        self.busy = []

    def set_busy(self, key, text):
        self.busy.append(text)

    def clear_busy(self, key):
        pass


class Switch(ConfigChannel):
    """A switch whose show monitor lists the sessions set up and taken away on it."""

    def __init__(self):
        super().__init__(start="sw1#")
        self.made = {}

    def send(self, text):
        word = text.strip()
        if word.startswith("monitor session") and " destination interface " in word:
            number = int(word.split()[2])
            self.made[number] = (f"Session {number}\n---------\nType : Local Session\nSource Ports :\n"
                                 f"    Both : Gi1/0/1\nDestination Ports : {word.split()[-1]}\n")
        elif word.startswith("no monitor session"):
            self.made.pop(int(word.split()[-1]), None)
        elif word.startswith("show monitor"):
            self.sent.append(text)
            listing = "\n".join(self.made.values()) or "No SPAN configuration is present in the system."
            self.out.append(word + "\r\n" + listing.replace("\n", "\r\n") + "\r\n" + self.prompt())
            return
        super().send(text)


@pytest.fixture
def page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    switch = Switch()
    FakePushShell.channels = {"10.0.0.1": switch}
    sessions = SessionStore(str(tmp_path / "sessions.json"))
    adapter = SimpleNamespace(name="Ethernet", mac="00-50-56-AA-00-09",
                              ipv4=[ipaddress.IPv4Interface("10.0.10.9/24")])
    window = Window(campus(), sessions, [adapter])
    tab = mirror_tab.MirrorTab(window, store=mirror.MirrorStore(tmp_path / "mirrors.json"))
    tab.shell_factory = FakePushShell
    tab.logins = lambda: (macssh.SshLogins(fallback=Session("", username="admin"), password="pw"), "")
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    tab.switch = switch
    yield tab
    tab.shutdown()
    window.deleteLater()


def wait(tab):
    for _ in range(500):
        thread = tab.reader or tab.pusher_thread
        if thread is None:
            break
        thread.wait(50)
        QApplication.processEvents()
    QApplication.processEvents()


def test_routers_mirror_from_but_destinations_are_switches(page):
    def keys(combo):
        return [combo.itemData(index) for index in range(1, combo.count())]
    assert "R1" in keys(page.source_combo) and "SW1" in keys(page.source_combo)
    assert "R1" not in keys(page.dest_combo) and "SW1" in keys(page.dest_combo)
    assert page.source_combo.itemText(0) == "Choose a switch or router" and page.dest_combo.itemText(0) == \
        "Choose a switch"


def test_plan_set_up_check_and_take_away(page):
    page.prefill(source="SW1", ports=["Gi1/0/1"], dest="SW1", dest_port="Gi1/0/10")
    assert [item.port for item in page.sources()] == ["Gi1/0/1"]
    page.remove_check.setChecked(False)
    page.switch.made[1] = "Session 1\n---------\nType : Local Session\nDestination Ports : Gi1/0/40\n"
    page.start_plan()
    wait(page)
    assert page.plan is not None and page.plan.ok, [finding.text for finding in page.plan.findings]
    assert page.plan.kind == mirror.SPAN and page.plan.steps[0].session == 2  # 1 is in use on the switch
    assert page.steps_table.rowCount() == 1 and "session 2" in page.steps_table.item(0, 3).text()
    assert "monitor session 2 destination interface Gi1/0/10" in page.preview.toPlainText()

    page.set_up()
    wait(page)
    record = page.mirrors.records[0]
    assert record.state == mirror.ACTIVE and record.steps[0].state == mirror.STEP_SET
    assert 2 in page.switch.made
    assert page.statuses[0] == "Done"  # Read again after: the switch shows it
    assert page.records_table.rowCount() == 1 and page.records_table.item(0, 6).text() == "Set up"
    sessions = [page.sessions_table.item(row, 4).text() for row in range(page.sessions_table.rowCount())]
    # Its session, another one, and an applet (NOMAD-MIRROR-OLD) of a mirror this PC doesn't have
    assert sorted(sessions) == ["NOMAD (" + record.id + ")", "NOMAD (another PC?)", "Not NOMAD"]

    page.records_table.selectRow(0)
    page.take_away()
    wait(page)
    assert 2 not in page.switch.made and 1 in page.switch.made  # Only NOMAD's
    assert page.mirrors.records[0].state == mirror.REMOVED
    again = mirror.MirrorStore(page.mirrors.path)
    again.load()
    assert again.records[0].state == mirror.REMOVED


def test_a_refused_set_up_offers_to_take_back_what_was_done(page, monkeypatch):
    page.prefill(source="SW1", ports=["Gi1/0/5"], dest="SW2", dest_port="Gi1/0/24")  # RSPAN: SW2 first, then SW1
    page.remove_check.setChecked(False)
    second = Switch()
    second.refuse = {"monitor session 1 source interface Gi1/0/5 both"}
    FakePushShell.channels = {"10.0.0.1": second, "10.0.0.2": page.switch}
    page.start_plan()
    wait(page)
    assert page.plan.ok and page.plan.kind == mirror.RSPAN
    asked = []
    monkeypatch.setattr(QMessageBox, "exec_", lambda box: asked.append(box.text()) or QMessageBox.Yes)
    page.set_up()
    wait(page)
    assert asked and "SW1 refused it" in asked[0]
    record = page.mirrors.records[0]
    assert [step.label for step in record.steps] == ["SW2", "SW1"]
    assert record.steps[0].state == mirror.STEP_REMOVED  # Taken back
    assert any("no vlan 999" in text for text in page.switch.sent)


def test_this_pc_on_the_port_it_reaches_the_switches_through_gets_erspan(page, monkeypatch):
    monkeypatch.setattr(mirror_tab, "local_address_toward", lambda address: "10.0.10.9")
    page.prefill(source="SW1", ports=["Gi1/0/5"])
    page.to_pc_radio.setChecked(True)
    page.fill_adapters()
    request = page.build_request()
    assert request.to == mirror.TO_ADDRESS and request.dest_ip == "10.0.10.9" and request.to_this_pc
    assert "keeps working" in page.pc_note
    monkeypatch.setattr(mirror_tab, "local_address_toward", lambda address: "10.9.9.9")  # A second adapter
    request = page.build_request()
    assert request.to == mirror.TO_PORT and (request.dest_device, request.dest_port) == ("SW2", "Gi1/0/9")
    assert not request.own_port


def test_a_host_by_name_fills_in_its_port(page):
    assert page.mirror_host("printer")
    assert page.source_combo.currentData() == "SW1" and [item.port for item in page.sources()] == ["Gi1/0/5"]
    assert not page.mirror_host("nothing-like-it")


def test_this_pc_on_wifi_gets_erspan_to_its_address(page, monkeypatch):
    """Wi-Fi has no switch port: the copies go to its address, whatever the switch says it runs, and a MAC seen on an
    access point's port (its clients) is never taken for this PC's port."""
    from nomad.netmap.model import AP, Device, Host, Link
    network_map = page.network_map()
    network_map.devices["SW1"].sys_descr = "Cisco IOS Software [Everest], Catalyst L3 Switch Software " \
                                           "(CAT3K_CAA-UNIVERSALK9-M), Version 16.6.4"
    network_map.devices["AP1"] = Device("AP1", "AP1", kind=AP)
    network_map.links.append(Link("SW2", "Gi1/0/30", "AP1", "Gi0"))
    network_map.hosts.append(Host("00-50-56-AA-00-77", "SW2", "Gi1/0/30", ip="10.0.20.7"))
    wifi = SimpleNamespace(name="Wi-Fi", description="Intel(R) Wi-Fi 6 AX201 160MHz", mac="00-50-56-AA-00-77",
                           ipv4=[ipaddress.IPv4Interface("10.0.20.7/24")])
    page.window.snapshot = SimpleNamespace(real_adapters=lambda: [wifi])
    monkeypatch.setattr(mirror_tab, "local_address_toward", lambda address: "10.0.20.7")
    page.prefill(source="SW1", ports=["Gi1/0/5"])
    page.to_pc_radio.setChecked(True)
    page.fill_adapters()
    request = page.build_request()
    assert request.to == mirror.TO_ADDRESS and request.dest_ip == "10.0.20.7" and request.to_this_pc
    assert "is on Wi-Fi" in page.pc_note
    page.request, page.states = request, {"SW1": mirror.SwitchState(read=True)}
    page.make_plan()
    assert page.plan.ok and page.plan.kind == mirror.ERSPAN  # A 16.x switch is IOS XE: no warning to refuse it
    assert not any("classic IOS" in finding.text for finding in page.plan.findings)

    wifi.name, wifi.description = "Ethernet 3", "Some USB adapter"  # Not Wi-Fi, but its MAC is behind the AP
    page.fill_adapters()
    request = page.build_request()
    assert request.to == mirror.TO_ADDRESS and "isn't on a port the map has" in page.pc_note

    page.kind_combo.setCurrentIndex(page.kind_combo.findData(mirror.SPAN))
    assert page.build_request() is None and "SPAN needs one" in page.status_label.text()
