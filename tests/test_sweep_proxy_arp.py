"""The Sweep page and a router's proxy ARP: addresses only a router or firewall answered ARP for (with its own MAC)
say so, and aren't offered for recording in IPAM."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QVBoxLayout  # noqa: E402

from nomad.ipam.reconcile import PROXY_ARP  # noqa: E402
from nomad.ipam.store import USED, IpamStore, parse_subnet  # noqa: E402
from nomad.snapshot import NetworkSnapshot  # noqa: E402
from nomad.sweep import SweepHit  # noqa: E402
from nomad.ui.ipam_tab import LOCAL, IpamTab  # noqa: E402
from nomad.ui.sweep_tab import COL_IPAM, COL_RTT, SweepTab  # noqa: E402

from test_find_switch_port import Window  # noqa: E402

ROUTER, FIREWALL = "00-1E-BD-BC-92-BF", "CC-70-ED-B9-61-44"


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app, tmp_path):
    store = IpamStore(str(tmp_path / "proxy.db"), user="tester")
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.10.10.0/24", "LAN")
    store.set_address(network.id, "10.10.10.43", USED, "fw", FIREWALL)
    store.set_address(network.id, "10.10.10.50", USED, "rtr", ROUTER)
    store.set_address(network.id, "10.10.10.60", USED, "gone")
    window = Window()
    window.snapshot = NetworkSnapshot()
    QVBoxLayout(window)
    window.ipam_tab = IpamTab(window)
    window.ipam_tab.local_store, window.ipam_tab.source, window.ipam_tab.network_id = store, LOCAL, network.id
    sweep = SweepTab(window)
    yield sweep
    sweep.deleteLater()
    window.deleteLater()
    store.close()


def test_proxy_arp_on_the_sweep_page(page):
    for ip, hit in (("10.10.10.43", SweepHit(None, FIREWALL)), ("10.10.10.44", SweepHit(None, FIREWALL)),
                    ("10.10.10.46", SweepHit(None, ROUTER)), ("10.10.10.50", SweepHit(1, ROUTER)),
                    ("10.10.10.60", SweepHit(None, ROUTER)), ("10.10.10.70", SweepHit(None, "AA-AA-AA-AA-AA-AA"))):
        page.add_host(ip, hit)
    page.ipam_bar.compare_now()
    cells = {page.table.item(row, 0).text(): (page.table.item(row, COL_RTT).text(),
                                              page.table.item(row, COL_IPAM).text())
             for row in range(page.table.rowCount())}
    assert cells["10.10.10.43"] == ("No ping reply", "In IPAM: fw")  # The firewall's own reply
    assert cells["10.10.10.44"] == ("Proxy ARP from 10.10.10.43", "Proxy ARP from 10.10.10.43")
    assert cells["10.10.10.46"][0] == "Proxy ARP from 10.10.10.50"
    assert cells["10.10.10.60"][1] == "Proxy ARP from 10.10.10.50: IPAM has gone, which didn't answer"
    assert cells["10.10.10.70"] == ("No ping reply", "Not in IPAM")  # A device that drops ping
    findings = page.ipam_bar.findings
    assert {ip for ip, finding in findings.items() if finding.state == PROXY_ARP} == \
        {"10.10.10.44", "10.10.10.46", "10.10.10.60"}
    assert page.ipam_bar.record_button.text() == "Record Not in IPAM (1)..."
    assert page.ipam_bar.menu_actions("10.10.10.44", FIREWALL, "") == []
    # Once the sweep has tried every address, a recorded one only proxy ARP answered for is silent
    page.ipam_bar.set_devices(page.devices(), [parse_subnet("10.10.10.0/24")], complete=True, soon=False,
                              arp_only=page.arp_only())
    assert [record.ip for record in page.ipam_bar.quiet] == ["10.10.10.60"]
