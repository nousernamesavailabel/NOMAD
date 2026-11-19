"""The network map and IPAM: what the map has that its IPAM network lacks, recording it (after review), the Hosts
tab's IPAM column, IPAM names on the logical view, and the Watch log noting new hosts and subnets IPAM lacks."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from test_integration import Navigator, Window, app, key, pages  # noqa: E402,F401 (fixtures)
from test_ipam_server import offline_store, plan, server, team_store  # noqa: E402,F401 (fixture)
from test_placement import lab  # noqa: E402

from nomad.ipam.map_compare import DEVICE, HOST, compare_map, map_addresses, short_name  # noqa: E402
from nomad.ipam.reconcile import MAC_DIFFERS, NOT_RECORDED, RECORDED  # noqa: E402
from nomad.ipam.server import ADMIN  # noqa: E402
from nomad.ipam.store import IpamStore  # noqa: E402
from nomad.netmap import l3  # noqa: E402
from nomad.netmap.model import Host  # noqa: E402
from nomad.netmap.watch import WatchResult  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.map_ipam_dialog import COL_NAME, COL_TICK, RecordDialog  # noqa: E402


def lab_with_hosts():
    network_map = lab()
    network_map.devices["sw1"].mgmt_ip = "10.50.0.2"
    network_map.devices["sw1"].name = "sw1.home.lab"
    network_map.hosts = [Host("aa-aa-aa-aa-aa-01", "sw1", "Gi1/0/5", "10.50.0.20", name="printer"),
                         Host("aa-aa-aa-aa-aa-02", "sw1", "Gi1/0/6", "10.50.0.21"),
                         Host("aa-aa-aa-aa-aa-03", "sw1", "Gi1/0/7", "172.31.0.9"),  # Outside the network
                         Host("aa-aa-aa-aa-aa-04", "sw1", "Gi1/0/8", "0.0.0.0")]
    return network_map


@pytest.fixture
def local(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    yield store
    store.close()


def lab_network(store):
    network = store.add_network("Lab")
    for cidr in ("10.50.0.0/24", "10.0.12.0/30"):
        store.add_subnet(network.id, cidr)
    return network


def test_map_addresses_and_their_names():
    found = {item.ip: item for item in map_addresses(lab_with_hosts())}
    assert short_name("R1S1.home.lab") == "R1S1" and short_name("10.0.0.1") == "10.0.0.1"
    assert (found["10.50.0.2"].kind, found["10.50.0.2"].name) == (DEVICE, "sw1")  # How it's managed: its name
    assert found["10.50.0.2"].where == "sw1 Vlan50"
    assert found["10.0.12.1"].name == "r1 Gi0/0" and found["10.50.0.3"].name == "sw2 Vlan50"
    assert (found["10.50.0.20"].kind, found["10.50.0.20"].name, found["10.50.0.20"].mac) == \
        (HOST, "printer", "aa-aa-aa-aa-aa-01")
    assert found["10.50.0.20"].where == "sw1 Gi1/0/5"
    assert "0.0.0.0" not in found  # Not worth recording
    assert list(found).count("192.168.1.1") == 1  # On r1 and r2: listed once


def test_compared_with_an_ipam_network(local):
    network = lab_network(local)
    local.set_address(network.id, "10.50.0.20", name="printer", mac="AA:AA:AA:AA:AA:01")
    local.set_address(network.id, "10.50.0.21", name="pc", mac="bb-bb-bb-bb-bb-bb")
    found = {item.ip: item for item in compare_map(lab_with_hosts(), local, network.id)}
    assert found["10.50.0.20"].finding.state == RECORDED  # The same MAC, written another way
    assert found["10.50.0.21"].finding.state == MAC_DIFFERS
    assert found["10.50.0.2"].finding.state == NOT_RECORDED
    assert found["172.31.0.9"].finding is None  # Outside the network's subnets: not judged


def test_record_dialog_writes_only_what_is_ticked(app, local):
    network = lab_network(local)
    local.set_address(network.id, "10.50.0.21", name="pc", mac="bb-bb-bb-bb-bb-bb")
    before = {address.ip for address in local.addresses(network.id)}
    dialog = RecordDialog(None, local, network.id, "Lab", compare_map(lab_with_hosts(), local, network.id))
    rows = {dialog.table.item(row, 1).text(): row for row in range(dialog.table.rowCount())}
    assert set(rows) == {"10.0.12.1", "10.0.12.2", "10.50.0.2", "10.50.0.3", "10.50.0.20", "10.50.0.21"}
    assert dialog.table.item(rows["10.50.0.21"], COL_TICK).checkState() == Qt.Unchecked  # MAC differs: you decide
    assert dialog.table.item(rows["10.50.0.20"], COL_TICK).checkState() == Qt.Checked
    assert "Not in IPAM" in dialog.table.item(rows["10.50.0.2"], 6).text()
    assert local.addresses(network.id) and {address.ip for address in local.addresses(network.id)} == before
    dialog.table.item(rows["10.0.12.2"], COL_TICK).setCheckState(Qt.Unchecked)
    dialog.table.item(rows["10.50.0.20"], COL_NAME).setText("lab-printer")  # Renamed first
    dialog.table.item(rows["10.50.0.21"], COL_TICK).setCheckState(Qt.Checked)  # And update that MAC
    dialog.show_combo.setCurrentIndex(1)  # Filtered: what was ticked stays ticked
    assert "4 to record, 1 MAC address to update" in dialog.status_label.text()
    dialog.record()
    recorded = {address.ip: address for address in local.addresses(network.id)}
    assert set(recorded) == {"10.0.12.1", "10.50.0.2", "10.50.0.3", "10.50.0.20", "10.50.0.21"}
    assert recorded["10.50.0.20"].name == "lab-printer" and recorded["10.50.0.20"].mac == "aa-aa-aa-aa-aa-01"
    assert recorded["10.50.0.2"].name == "sw1" and recorded["10.0.12.1"].name == "r1 Gi0/0"
    assert (recorded["10.50.0.21"].name, recorded["10.50.0.21"].mac) == ("pc", "aa-aa-aa-aa-aa-02")


def test_recording_offline_in_a_tribe_network_waits(app, server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])  # 10.0.0.0/24, with 10.0.0.5 sw1
    team_store(server, tmp_path, "alice").close()
    laptop = offline_store(server, tmp_path)
    network_map = lab_with_hosts()
    network_map.hosts.append(Host("cc-cc-cc-cc-cc-cc", "sw1", "Gi1/0/9", "10.0.0.77", name="field-pc"))
    dialog = RecordDialog(None, laptop, network.id, "11AB SIPR", compare_map(network_map, laptop, network.id),
                          offline=True)
    dialog.record()
    assert laptop.address(network.id, "10.0.0.77").name == "field-pc"
    assert laptop.pending_count() == 1  # Sent when the server can be reached
    laptop.close()


# --------------------------------------------------------------------- On the map page

def test_map_page_shows_and_records_ipam(pages, tmp_path, monkeypatch):
    window, store, network, _, _ = pages
    page = window.netmap_tab
    store.set_address(network.id, "10.50.0.21", name="pc", mac="bb-bb-bb-bb-bb-bb")
    page.show_map(lab_with_hosts(), tmp_path / "lab.nomadmap")
    page.set_ipam_network(key(network))
    table = page.hosts_table
    column = table.columnCount() - 1
    texts = {table.item(row, 1).text(): table.item(row, column).text() for row in range(table.rowCount())}
    assert texts["10.50.0.20"] == "Not in IPAM" and texts["10.50.0.21"].startswith("MAC differs")
    assert texts["172.31.0.9"] == ""  # Another network's, maybe

    nodes = page.l3_nodes
    users = nodes[l3.subnet_key(__import__("ipaddress").ip_network("10.50.0.0/24"))]
    assert users.detail == "" and page.l3_stale  # Worked out only once the logical view is shown
    page.tabs.setCurrentWidget(page.l3_view)
    assert not page.l3_stale
    assert users.detail == "Users · VLAN" and users.tone == ""  # Linked to VLAN 50, where the map has it: well
    elsewhere = next(node for node in nodes.values() if node.kind == l3.SUBNET and node.label == "10.30.0.0/24")
    assert (elsewhere.detail, elsewhere.tone) == ("not in IPAM", "muted")

    def record_all(dialog):
        dialog.record()
        return True
    monkeypatch.setattr(netmap_tab.RecordDialog, "exec_", record_all)
    page.record_in_ipam(device="sw1")
    assert {address.ip for address in store.addresses(network.id)} == {"10.50.0.2", "10.50.0.21"}
    assert "Recorded 1 address in Lab" in page.status_label.text()
    page.record_in_ipam(addresses=["10.50.0.20"])
    assert store.address(network.id, "10.50.0.20").name == "printer"
    texts = {table.item(row, 1).text(): table.item(row, column).text() for row in range(table.rowCount())}
    assert texts["10.50.0.20"] == "In IPAM: printer"

    page.network_map.hosts.append(Host("dd-dd-dd-dd-dd-dd", "sw1", "Gi1/0/10", "10.50.0.99", name="new-pc"))
    page.network_map.devices["r2"].interfaces_l3.append(["10.77.0.1", 24, "Gi0/8"])
    page.log_ipam_news(WatchResult(hosts=["dd-dd-dd-dd-dd-dd"], subnets=[("", "10.77.0.0/24")]))
    log = "\n".join(page.watcher.lines)
    assert "Not in IPAM (Lab): 10.50.0.99 (new-pc)" in log and "Subnet 10.77.0.0/24 isn't in IPAM (Lab)" in log


def test_recording_needs_the_maps_network(pages, tmp_path, monkeypatch):
    window, store, network, _, _ = pages
    page = window.netmap_tab
    page.show_map(lab_with_hosts(), tmp_path / "lab.nomadmap")
    asked = []
    monkeypatch.setattr(page, "choose_ipam_network", lambda: asked.append(True))
    page.record_in_ipam()  # Not tied to a network: asked which first (and nothing recorded when not said)
    assert asked == [True] and store.addresses(network.id) == []


def test_record_in_ipam_from_the_bar_and_map_menu(pages, tmp_path, monkeypatch):
    """The button's clicked signal passes checked=False: it mustn't be taken for a device."""
    window, store, network, _, _ = pages
    page = window.netmap_tab
    page.show_map(lab_with_hosts(), tmp_path / "lab.nomadmap")
    page.set_ipam_network(key(network))
    shown = []

    def look(dialog):
        shown.append(len(dialog.addresses))
        return False
    monkeypatch.setattr(netmap_tab.RecordDialog, "exec_", look)
    page.ipam_record_button.click()
    page.update_map_menu()
    next(action for action in page.map_menu.actions() if action.text() == "Record in IPAM...").trigger()
    assert shown == [7, 7]  # Every address on the map in the network's subnets, both times
