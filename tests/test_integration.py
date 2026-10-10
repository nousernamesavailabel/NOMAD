"""The IP Addresses, VLANs and Subnet Placement pages and the Network Map working as one: the network chosen on one
is chosen on the others, a map remembers which IPAM network it's of, and the pages link to each other."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtGui import QShowEvent  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402
from test_netmap_tab import Window as MapWindow  # noqa: E402
from test_placement import lab  # noqa: E402

from nomad.ipam.store import IpamStore  # noqa: E402
from nomad.ipam.vlans import VlanStore  # noqa: E402
from nomad.netmap import shared, store as map_store  # noqa: E402
from nomad.netmap.model import NetworkMap  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.integration import IPAM, MAP_SUBNET, PLACEMENT, VLAN, Integration, MapNetworkDialog, hub, link  # noqa
from nomad.ui.ipam_tab import IpamTab  # noqa: E402
from nomad.ui.placement_tab import PlacementTab  # noqa: E402
from nomad.ui.vlan_tab import VlanTab  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Navigator:
    def __init__(self):
        self.current = None

    def setCurrentWidget(self, widget):
        self.current = widget


class Window(MapWindow):
    def __init__(self):
        super().__init__()
        self.navigator = Navigator()


@pytest.fixture
def pages(app, tmp_path, monkeypatch):
    monkeypatch.setattr(map_store, "maps_dir", lambda: tmp_path)
    window = Window()
    window.integration = Integration(window)
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    window.ipam_tab = IpamTab(window)
    window.ipam_tab.local_store = store
    window.netmap_tab = netmap_tab.NetworkMapTab(window)
    window.vlan_tab = VlanTab(window)
    window.placement_tab = PlacementTab(window)
    window.integration.connect_pages()
    lab_network = store.add_network("Lab")
    for cidr, name in (("10.50.0.0/24", "Users"), ("10.0.12.0/30", "Transit"), ("192.168.1.0/24", "Printers")):
        store.add_subnet(lab_network.id, cidr, name)
    other = store.add_network("Other")
    store.add_subnet(other.id, "172.16.0.0/16", "Elsewhere")
    vlans = VlanStore(store)
    domain = vlans.add_domain("Lab switches", lab_network.id)
    vlans.set_vlan(domain.id, 50, "USERS", subnets=["10.50.0.0/24"])
    vlans.add_domain("Other switches", other.id)
    yield window, store, lab_network, other, domain
    window.netmap_tab.shutdown()
    window.ipam_tab.sync_timer.stop()
    store.close()


def key(network):
    return f"local:{network.id}"


def test_choosing_a_network_on_one_page_chooses_it_on_the_others(pages):
    window, store, lab_network, other, domain = pages
    assert hub(window) is window.integration and hub(object()) is None
    window.ipam_tab.fill_networks(key(lab_network))
    assert window.integration.network == key(lab_network)
    window.placement_tab.fill_networks()
    window.vlan_tab.fill_domains()
    assert window.placement_tab.network_id == lab_network.id
    assert window.vlan_tab.domain_id == domain.id

    window.placement_tab.network_combo.setCurrentIndex(window.placement_tab.network_combo.findData(key(other)))
    assert window.integration.network == key(other)
    assert window.ipam_tab.network_id == other.id  # Followed
    assert window.vlan_tab.domain().name == "Other switches"  # The domain of that network

    window.vlan_tab.fill_domains(f"local:{domain.id}")  # Choosing a domain chooses its network
    assert window.ipam_tab.network_id == lab_network.id and window.placement_tab.network_id == lab_network.id


def test_a_map_remembers_its_network(pages, tmp_path):
    window, store, lab_network, other, _ = pages
    window.ipam_tab.fill_networks(key(other))
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    dialog = MapNetworkDialog(page, window.integration, page.network_map, "lab")
    assert dialog.combo.currentData() == key(lab_network)  # Suggested: it holds the map's subnets
    assert "3 of the map's subnets" in dialog.combo.currentText()
    page.set_ipam_network(key(lab_network))
    assert window.integration.network == key(lab_network)  # The pages follow the map
    assert window.ipam_tab.network_id == lab_network.id
    assert map_store.load(page.map_path).ipam_network == key(lab_network)  # Saved with it
    window.ipam_tab.fill_networks(key(other))  # Looking at another network...
    page.map_changed()  # ...while the map is redrawn (by watching, say): the pages stay where they are
    assert window.ipam_tab.network_id == other.id
    window.ipam_tab.fill_networks(key(lab_network))

    placement = window.placement_tab
    placement.fill_networks()
    assert placement.network_map() is page.network_map
    placement.network_combo.setCurrentIndex(placement.network_combo.findData(key(other)))
    assert placement.network_map() is None  # A map of another network isn't checked against this one
    assert "is of Lab" in placement.map_label.text()
    assert window.integration.map_for(key(other)) is None and window.integration.map_for(key(lab_network))


def test_tribe_maps_share_their_network():
    network_map = NetworkMap(seeds=["10.0.0.1"], ipam_network="team:abc")
    items = shared.flatten(network_map)
    assert items[(shared.META, shared.IPAM)] == {"network": "team:abc"}
    assert shared.build(items).ipam_network == "team:abc"
    assert (shared.META, shared.IPAM) not in shared.flatten(NetworkMap())
    assert NetworkMap.from_json(network_map.to_json()).ipam_network == "team:abc"


def test_subnet_line_and_links_between_the_pages(pages, tmp_path):
    window, store, lab_network, _, domain = pages
    window.netmap_tab.show_map(lab(), tmp_path / "lab.nomadmap")
    window.netmap_tab.set_ipam_network(key(lab_network))
    ipam = window.ipam_tab
    users = next(subnet for subnet in store.subnets(lab_network.id) if subnet.cidr == "10.50.0.0/24")
    ipam.fill_tree(select=users)
    text = ipam.subnet_label.text()
    assert "role: vlan" in text and "VLAN 50 USERS" in text and "placement: OK" in text
    assert "on the map: 1 place" in text and "nomad://vlan?" in text

    integration = window.integration
    integration.open_link(link(VLAN, src="local", domain=domain.id, vlan=50))
    assert window.navigator.current is window.vlan_tab and window.vlan_tab.selected_vlan().vlan == 50
    assert "Subnet Placement" in window.vlan_tab.details.toHtml()  # Its subnets link onwards

    integration.open_link(link(PLACEMENT, src="local", net=lab_network.id, cidr="10.0.12.0/30"))
    assert window.navigator.current is window.placement_tab
    assert window.placement_tab.selected_row().cidr == "10.0.12.0/30"
    assert "IP Addresses" in window.placement_tab.details.toHtml()

    integration.open_link(link(PLACEMENT, src="local", net=lab_network.id, find="sw1"))
    shown = [row for row in range(window.placement_tab.table.rowCount())
             if not window.placement_tab.table.isRowHidden(row)]
    assert shown and window.placement_tab.search_input.text() == "sw1"

    integration.open_link(link(MAP_SUBNET, cidr="10.50.0.0/24"))
    page = window.netmap_tab
    assert window.navigator.current is page and page.tabs.currentWidget() is page.l3_view

    integration.open_link(link(IPAM, src="local", net=lab_network.id, ip="10.50.0.2"))
    assert window.navigator.current is ipam and ipam.current.cidr == "10.50.0.0/24"

    integration.open_link(link(VLAN, src="local", net=lab_network.id, vlan=50, vtp=""))  # A number from the map
    assert window.vlan_tab.domain_id == domain.id and window.vlan_tab.selected_vlan().vlan == 50
    assert not integration.open_link("https://example.com")


def test_map_menus_reach_the_other_pages(pages, tmp_path):
    window, store, lab_network, _, _ = pages
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    page.set_ipam_network(key(lab_network))
    from PyQt5.QtWidgets import QMenu
    menu, actions = QMenu(), {}
    page.add_subnet_links(menu, actions, "10.50.0.0/24")
    assert [action.text() for action in actions] == ["Show in IP Addresses", "Show VLAN 50 on the VLANs Page",
                                                    "Show in Subnet Placement"]
    menu, actions = QMenu(), {}
    page.device_ipam_menu(menu, actions, page.network_map.devices["sw1"])
    labels = [action.text() for action in actions]
    assert "10.50.0.2  (Vlan50)" in labels and "Show Its Subnets in Subnet Placement" in labels
    actions[next(action for action in actions if action.text() == "10.50.0.2  (Vlan50)")]()
    assert window.ipam_tab.current.cidr == "10.50.0.0/24"


# --------------------------------------------------------------------- Networks without a map or a VLAN domain

def test_vlans_page_for_a_network_without_a_domain(pages, monkeypatch):
    window, store, lab_network, _, domain = pages
    from nomad.ui import vlan_tab
    third = store.add_network("Third")
    window.vlan_tab.saved_domain = f"local:{domain.id}"  # Remembered from last time NOMAD ran
    window.vlan_tab.fill_domains(f"local:{domain.id}")
    window.ipam_tab.fill_networks(key(third))
    page = window.vlan_tab
    page.showEvent(QShowEvent())  # Opening the page fills its list again: still none, not the remembered one
    assert page.domain() is None and window.ipam_tab.network_id == third.id
    assert page.domain() is None and page.domain_combo.currentIndex() == -1  # Not another network's domain
    assert "Third</b> (the network the other pages are on) has no VLAN domain yet" in page.domain_label.text()
    assert page.network_domain_button.isVisibleTo(page) and page.network_domain_button.text() == \
        "New Domain for Third..."
    page.fill_domains()  # Shown again (synced, say): still none
    assert page.domain() is None

    def make(dialog):
        dialog.save()
        return True
    monkeypatch.setattr(vlan_tab.DomainDialog, "exec_", make)
    page.new_domain_for_network()
    assert page.domain().name == "Third" and page.domain().network_id == third.id
    assert not page.network_domain_button.isVisibleTo(page)

    window.ipam_tab.fill_networks(key(lab_network))  # A network with a domain: shown
    assert page.domain_id == domain.id


def test_map_bar_says_what_network_the_map_is_of(pages, tmp_path):
    window, store, lab_network, other, _ = pages
    page = window.netmap_tab
    page.show_map(lab(), tmp_path / "lab.nomadmap")
    page.write_map(page.network_map, page.map_path)
    assert page.network_bar.isVisibleTo(page) and "isn't tied to an IPAM network" in page.network_bar_label.text()
    page.set_ipam_network(key(lab_network))
    assert not page.network_bar.isVisibleTo(page)

    window.ipam_tab.fill_networks(key(other))  # The pages move to a network with no map
    assert page.network_bar.isVisibleTo(page)
    assert "This map is of Lab; the other pages are on Other, which has no map yet" in page.network_bar_label.text()
    assert not page.network_open_button.isVisibleTo(page) and page.network_back_button.text() == "Back to Lab"
    page.back_to_map_network()
    assert window.integration.network == key(lab_network) and window.ipam_tab.network_id == lab_network.id
    assert not page.network_bar.isVisibleTo(page)

    other_map = NetworkMap(started="2026-10-01T09:00:00", ipam_network=key(other))
    other_path = map_store.save(other_map, tmp_path / "other site.nomadmap")
    window.ipam_tab.fill_networks(key(other))
    assert "which has its own map" in page.network_bar_label.text()
    assert page.network_open_button.text() == "Open other site"
    page.open_network_map()
    assert page.map_path == other_path and page.network_map.ipam_network == key(other)
    assert not page.network_bar.isVisibleTo(page)


def test_tribe_map_without_a_network_is_asked_about_once(pages, monkeypatch, tmp_path):
    window, _, _, _, _ = pages
    page = window.netmap_tab
    from nomad.netmap.tribe import TribeMaps
    maps = TribeMaps("server", None, path=tmp_path / "maps-team.db")
    monkeypatch.setattr(type(page.tribe), "maps", property(lambda self: maps), raising=False)
    asked = []
    monkeypatch.setattr(page, "choose_ipam_network", lambda: asked.append(True))
    page.show_map(lab(), None)
    page.tribe_map_id = 3
    page.ask_tribe_map_network()
    page.ask_tribe_map_network()  # Not again, on this computer
    assert asked == [True] and maps.asked(3, "ipam_network")
    maps.close()


def test_map_reopened_at_start_shows_its_network_once_ipam_is_open(pages, tmp_path):
    window, store, lab_network, other, _ = pages
    ipam = window.ipam_tab
    network_map = lab()
    network_map.ipam_network = key(lab_network)
    ipam.local_store = None  # At start: IPAM's databases aren't open yet when the last map is reopened
    window.netmap_tab.show_map(network_map, tmp_path / "lab.nomadmap")
    assert window.integration.waiting_network == key(lab_network)
    assert window.netmap_tab.ipam_network_button.text() == "IPAM Network..."  # Its name isn't known yet
    ipam.local_store = store
    ipam.saved_network_id = key(other)  # The IP Addresses page was on another network last time
    ipam.fill_networks()
    window.integration.stores_opened()
    assert window.integration.network == key(lab_network) and ipam.network_id == lab_network.id
    assert window.netmap_tab.ipam_network_button.text() == "IPAM Network: Lab..."  # Says which, always


def test_placement_follows_away_from_the_maps_network_with_a_mapped_subnet_selected(pages, tmp_path):
    """The rows left in the table mid-refill are the old network's (with places on the map), while the page is on
    the new one (no map): they mustn't be shown with the wrong map (it was an error after Move to Another Network)."""
    window, store, lab_network, other, _ = pages
    window.netmap_tab.show_map(lab(), tmp_path / "lab.nomadmap")
    window.netmap_tab.set_ipam_network(key(lab_network))
    placement = window.placement_tab
    placement.fill_networks()
    placement.go_to_subnet("local", lab_network.id, "10.50.0.0/24")
    assert placement.selected_row().found is not None and "On the map" in placement.details.toHtml()
    window.ipam_tab.fill_networks(key(other))  # The pages go to a network the map isn't of
    assert placement.network_id == other.id and placement.rows_map is None
    assert all(row.found is None for row in placement.rows)
    placement.go_to_subnet("local", lab_network.id, "10.50.0.0/24")  # And back
    assert placement.rows_map is window.netmap_tab.network_map and "On the map" in placement.details.toHtml()


# --------------------------------------------------------------------- Addresses on the map, on IP Addresses

def test_ip_addresses_say_whether_each_address_is_on_the_map(pages, tmp_path, monkeypatch):
    from PyQt5.QtCore import Qt
    from nomad.netmap.model import Host
    from nomad.ui.ipam_tab import COL_MAP
    window, store, lab_network, other, _ = pages
    ipam, page = window.ipam_tab, window.netmap_tab
    store.set_address(lab_network.id, "10.50.0.2", name="sw1")  # A switch's SVI
    store.set_address(lab_network.id, "10.50.0.9", name="printer")  # Not on the map
    users = next(subnet for subnet in store.subnets(lab_network.id) if subnet.cidr == "10.50.0.0/24")
    ipam.fill_networks(key(lab_network))
    ipam.fill_tree(select=users)
    assert ipam.table.isColumnHidden(COL_MAP)  # No map open: nothing to say

    network_map = lab()
    network_map.hosts.append(Host("aa:bb:cc:00:00:20", "sw1", "Gi1/0/5", ip="10.50.0.20"))
    page.show_map(network_map, tmp_path / "lab.nomadmap")
    page.set_ipam_network(key(lab_network))
    ipam.fill_tree(select=users)

    def cell(ip, role=Qt.DisplayRole):
        model = ipam.model
        row = next(row for row in range(model.rowCount()) if str(model.address_at(row)) == ip)
        return model.data(model.index(row, COL_MAP), role)

    assert not ipam.table.isColumnHidden(COL_MAP)
    assert cell("10.50.0.2") == "sw1 Vlan50"
    assert cell("10.50.0.3") == "sw2 Vlan50"  # On the map, not recorded in IPAM...
    assert "no record" in cell("10.50.0.3", Qt.ToolTipRole)  # ...which the tooltip says
    assert cell("10.50.0.20") == "Host on sw1 Gi1/0/5"
    assert cell("10.50.0.9") == "Not on the map"
    assert cell("10.50.0.100") is None  # Free, and nothing on the map has it

    ipam.hide_free_check.setChecked(True)  # Only addresses in use: the map's unrecorded ones are listed too
    assert [str(ipam.model.address_at(row)) for row in range(ipam.model.rowCount())] == \
        ["10.50.0.0", "10.50.0.2", "10.50.0.3", "10.50.0.9", "10.50.0.20", "10.50.0.255"]

    monkeypatch.setattr(ipam, "isVisible", lambda: True)
    network_map.hosts.append(Host("aa:bb:cc:00:00:09", "sw2", "Gi1/0/9", ip="10.50.0.9"))
    page.map_changed()  # Watching found the printer: the column says so without choosing the subnet again
    assert cell("10.50.0.9") == "Host on sw2 Gi1/0/9"
    network_map.hosts.append(Host("aa:bb:cc:00:00:30", "sw2", "Gi1/0/3", ip="10.50.0.30"))
    page.map_changed()  # A new address: listed (only addresses in use are)
    assert cell("10.50.0.30") == "Host on sw2 Gi1/0/3"

    ipam.fill_networks(key(other))  # A network the map isn't of
    assert ipam.table.isColumnHidden(COL_MAP)
