"""The VPNs page: routers read (and the VPNs on them found), a new VPN built, sent to both ends with the revert
timer, checked from each end and confirmed (or all put back), read back as the same VPN, taken away; certificates'
steps; the map's tunnels."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402

from nomad.netmap import configpush, macssh, vpn, vpnpki  # noqa: E402
from nomad.netmap.model import Link, NetworkMap  # noqa: E402
from nomad.netmap.model import Device as MapDevice  # noqa: E402
from nomad.netmap.model import ROUTER, SNMP  # noqa: E402
from nomad.terminal.sessions import Session, SessionStore  # noqa: E402
from nomad.ui import vpn_tab  # noqa: E402

R6 = """hostname R6
interface Loopback250
 ip address 10.250.6.1 255.255.255.0
interface GigabitEthernet1
 ip address 8.0.0.22 255.255.255.252
router bgp 180
 neighbor 8.0.0.21 remote-as 30
"""
R7 = """hostname R7
interface Loopback250
 ip address 10.250.7.1 255.255.255.0
interface GigabitEthernet1
 ip address 8.0.0.26 255.255.255.252
router bgp 181
 neighbor 8.0.0.25 remote-as 30
"""
ROUTES = """Gateway of last resort is not set

      8.0.0.0/8 is variably subnetted, 3 subnets, 2 masks
B        8.0.0.20/30 [20/0] via {hop}, 00:15:38
B        8.0.0.24/30 [20/0] via {hop}, 00:15:38
C        {own}/30 is directly connected, GigabitEthernet1
"""
FILE_SYSTEMS = """File Systems:

     Size(b)       Free(b)      Type  Flags  Prefixes
*  6286540800    5268013056      disk     rw   bootflash:
"""


class Router:
    """A router's command line that keeps a running-config and applies the configuration lines typed into it (enough
    of IOS for the VPNs page: modes by indentation, no to remove, a later line in a slot replacing an earlier one)."""

    def __init__(self, hostname, running, routes, refuse=(), pings_fail=False):
        self.hostname = hostname
        self.tree = vpn.parse_tree(running)
        self.routes = routes
        self.refuse = set(refuse)
        self.pings_fail = pings_fail
        self.mode = "exec"
        self.stack = []
        self.out = ["\r\n" + self.prompt()]
        self.closed = False
        self.sent = []
        self.archive = ""
        self.saved_tree = None
        self.confirms = self.reverts = 0
        self.question = None

    def prompt(self):
        return f"{self.hostname}(config)#" if self.mode == "config" else f"{self.hostname}#"

    def recv_ready(self):
        return bool(self.out)

    def recv(self, size):
        return self.out.pop(0).encode()

    def exit_status_ready(self):
        return False

    def running(self):
        return "Building configuration...\n" + "\n".join(vpn.render(self.tree)) + "\nend"

    def answer(self, word):
        if word == "show running-config":
            return self.running()
        if word == "show ip route":
            return self.routes
        if word.startswith("show version"):
            return "Cisco IOS XE Software, Version 17.04.02"
        if word == "show clock":
            return "*01:02:03.000 UTC Wed Oct 14 2026"  # Not authoritative: no NTP
        if word.startswith("show ip interface brief"):
            return "\n".join(f"{block.line.split()[1]}  172.31.0.1  YES manual up up" for block in self.tree
                             if block.line.startswith("interface Tunnel"))
        if word.startswith("show"):
            if word == "show running-config | section archive":
                return f"archive\n path {self.archive}" if self.archive else ""
            if word == "show file systems":
                return FILE_SYSTEMS
            return ""
        if word.startswith("ping"):
            return "Success rate is 0 percent (0/5)" if self.pings_fail else \
                "!!!!!\nSuccess rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms"
        if word == "configure confirm":
            self.confirms += 1
            self.saved_tree = None
            return ""
        if word == "configure revert now":
            self.reverts += 1
            if self.saved_tree is None:
                return "%No Rollback Confirmed Change pending"
            self.tree, self.saved_tree = self.saved_tree, None
            # As IOS XE 17.4 says it putting back a named EIGRP process: the % note doesn't mean it didn't
            return ("Rollback Confirmed Change: rolling to:bootflash:nomad-revert-Oct-14-04-54-22.135-2\n"
                    "%EIGRP: Deleting base topology is not allowed.\nTotal number of passes: 1\nRollback Done")
        if word.startswith("clear crypto"):
            return ""
        return None

    def send(self, text):
        self.sent.append(text)
        line = text.rstrip("\n")
        word = line.strip()
        if self.mode == "exec":
            reply = self.answer(word)
            if word.startswith("configure terminal"):
                self.mode, self.stack = "config", []
                if "revert timer" in word:
                    self.saved_tree = [block.copy() for block in self.tree]
                self.out.append(line + "\r\nEnter configuration commands, one per line.  End with CNTL/Z.\r\n" +
                                self.prompt())
                return
            self.out.append(line + "\r\n" + (reply or "").replace("\n", "\r\n") + ("\r\n" if reply else "") +
                            self.prompt())
            return
        if word == "end":
            self.mode = "exec"
            self.out.append(line + "\r\n" + self.prompt())
            return
        if word in self.refuse:
            self.out.append(line + "\r\n                   ^\r\n% Invalid input detected at '^' marker.\r\n" +
                            self.prompt())
            return
        self.configure(line)
        self.out.append(line + "\r\n" + self.prompt())

    def configure(self, line):
        depth = len(line) - len(line.lstrip(" "))
        word = line.strip()
        if word.startswith("do ") or word == "exit":
            return
        if word.startswith("path ") and depth == 1:
            self.archive = word.split()[1]
        self.stack = self.stack[:depth]
        siblings = self.tree if depth == 0 else self.stack[-1].children
        parent_line = "" if depth == 0 else self.stack[-1].line
        if word.startswith("no "):
            target = word[3:]
            wanted = vpn.key_of(target, parent_line)
            for block in list(siblings):
                key = vpn.key_of(block.line, parent_line)
                if key == wanted or block.line == target or block.line.startswith(target + " ") or \
                        (vpn.parent_type(parent_line) == "acl" and block.line.split()[0] == target):
                    siblings.remove(block)
                    break
            else:
                if depth and not wanted.startswith(("crypto", "ip ")):  # A default turned off: shown as no ...
                    siblings.append(vpn.Block(word))
            return
        positive = next((block for block in siblings if block.line == "no " + word), None)
        if positive is not None:
            siblings.remove(positive)
            return
        wanted = vpn.key_of(word, parent_line)
        existing = next((block for block in siblings if vpn.key_of(block.line, parent_line) == wanted), None)
        if existing is None:
            existing = vpn.Block(word)
            siblings.append(existing)
        else:
            existing.line = word
        self.stack.append(existing)


class FakeVpnShell:
    """A VpnShell on a Router."""
    channels = {}
    opened = 0

    def __init__(self, session, vault=None, known_hosts=None, trust_new=False, password=None,
                 should_stop=lambda: False, enable_secret=""):
        self.inner = configpush.VpnShell(session, enable_secret=enable_secret)
        self.inner.channel = self.channels[session.host]

    def open(self):
        FakeVpnShell.opened += 1
        channel = self.inner.channel
        if not channel.out:
            channel.out.append("\r\n" + channel.prompt())
        self.inner.prompt = self.inner.read(5).rstrip().splitlines()[-1].strip()

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def close(self):
        pass


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class MapPage(QWidget):
    map_shown = pyqtSignal()

    def __init__(self, network_map):
        super().__init__()
        self.network_map = network_map

    def session_hints(self, network_map, device):
        return {"aliases": [], "name": device.name, "folder": ""}


class Window(QWidget):
    def __init__(self, network_map, sessions):
        super().__init__()
        self.netmap_tab = MapPage(network_map)
        self.session_store = sessions

    def set_busy(self, key, text):
        pass

    def clear_busy(self, key):
        pass


def lab_map():
    network_map = NetworkMap()
    network_map.devices = {key: MapDevice(key, key, mgmt_ip=ip, kind=ROUTER, source=SNMP)
                           for key, ip in (("R6", "8.0.0.22"), ("R7", "8.0.0.26"))}
    network_map.links = [Link("R6", "Gi1", "R7", "Gi1")]
    return network_map


def routers(**options):
    return {"8.0.0.22": Router("R6", R6, ROUTES.format(hop="8.0.0.21", own="8.0.0.20"), **options.get("r6", {})),
            "8.0.0.26": Router("R7", R7, ROUTES.format(hop="8.0.0.25", own="8.0.0.24"), **options.get("r7", {}))}


@pytest.fixture
def page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    monkeypatch.setattr(vpn_tab, "VERIFY_WAIT", 1)
    FakeVpnShell.channels = routers()
    FakeVpnShell.opened = 0
    monkeypatch.setattr(vpn_tab, "local_address_toward", lambda address: "192.168.5.25")
    sessions = SessionStore(str(tmp_path / "sessions.json"))
    window = Window(lab_map(), sessions)
    store = vpn.VpnStore(tmp_path / "vpns.json", protect=lambda text: "P" + text, unprotect=lambda text: text[1:])
    tab = vpn_tab.VpnTab(window, store=store)
    tab.shell_factory = FakeVpnShell
    tab.login_row.logins = lambda status=None: (macssh.SshLogins(fallback=Session("", username="admin"),
                                                                 password="pw"))
    tab.login_row.pusher_maker = lambda logins, factory: (
        lambda should_stop: configpush.Pusher(logins, enable_secret="", should_stop=should_stop,
                                              shell_factory=factory))
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    monkeypatch.setattr(QMessageBox, "warning", lambda *args, **kwargs: QMessageBox.Ok)
    yield tab
    tab.shutdown()
    window.deleteLater()


def wait(tab):
    for _ in range(1200):
        threads = [thread for thread in (tab.reader, tab.sender, tab.actor, tab.pki) if thread is not None]
        if not threads:
            break
        threads[0].wait(50)
        QApplication.processEvents()
    for _ in range(5):
        QApplication.processEvents()


def read_both(page):
    page.start_read(["map:R6", "map:R7"])
    wait(page)
    assert page.read["map:R6"].read and page.read["map:R7"].read, page.notes


def new_vti(page, routing=vpn.STATIC):
    read_both(page)
    page.make_new("LAB", vpn.VTI, [("map:R6", vpn.PEER), ("map:R7", vpn.PEER)])
    design = page.editable()
    for member in design.members:
        member.lans = [f"10.250.{member.key[-1]}.0/24"]
    design.routing.kind = routing
    page.show_design()
    return design


def test_lists_the_maps_routers(page):
    keys = [page.router_list.item(row).data(vpn_tab.Qt.UserRole) for row in range(page.router_list.count())]
    assert {"map:R6", "map:R7"} <= set(keys)


def test_a_new_vti_is_planned_with_both_ends_and_keys_hidden(page):
    design = new_vti(page)
    assert [member.wan for member in design.members] == ["GigabitEthernet1", "GigabitEthernet1"]
    assert [member.local_ip for member in design.members] == ["8.0.0.22", "8.0.0.26"]
    assert design.subnet == "172.31.0.0/30" and design.members[1].tunnel_ip == "172.31.0.2"
    changes = page.changes_for(design.id)
    assert set(changes) == {"map:R6", "map:R7"}
    text = page.preview.toPlainText()
    assert "! R6" in text and "! R7" in text and "configure terminal revert timer 10" in text
    assert design.auth.psk not in text and "pre-shared-key ********" in text
    page.show_keys_check.setChecked(True)
    assert design.auth.psk in page.preview.toPlainText()
    assert page.send_button.isEnabled(), page.blocked(design.id)


def test_send_checks_both_ends_then_confirms_and_reads_it_back(page):
    design = new_vti(page)
    page.send()
    wait(page)
    r6, r7 = FakeVpnShell.channels["8.0.0.22"], FakeVpnShell.channels["8.0.0.26"]
    sent = [text.strip() for text in r6.sent]
    assert "configure terminal revert timer 10" in sent and "tunnel mode ipsec ipv4" in sent
    assert any(text.startswith("ping 172.31.0.2 source Tunnel10") for text in sent)
    assert any(text.startswith("ping 10.250.7.1 source 10.250.6.1") for text in sent)  # LAN to LAN
    assert r6.confirms == 1 and r7.confirms == 1 and r6.reverts == r7.reverts == 0
    assert all(entry.outcome.startswith("Confirmed") for entry in page.store.history[:2])
    assert "bootflash:nomad-revert" in page.store.history[0].outcome  # NOMAD set the archive path for the timer
    assert "********" in page.store.history[0].lines and design.auth.psk in page.store.unmasked(
        page.store.history[0])[0]
    assert design.id in page.store.keys  # The key kept, protected
    found = next(item for item in page.found if item.name == "LAB")
    assert found.kind == vpn.VTI and found.auth.psk == design.auth.psk
    assert not page.changes_for(found.id)  # Read back: nothing more to send


def test_a_refused_line_puts_every_router_back(page):
    FakeVpnShell.channels = routers(r7={"refuse": {"tunnel mode ipsec ipv4"}})
    new_vti(page)
    page.send()
    wait(page)
    r6, r7 = FakeVpnShell.channels["8.0.0.22"], FakeVpnShell.channels["8.0.0.26"]
    assert r6.reverts == 1 and r6.confirms == 0  # R6 went first and was put back
    assert r7.reverts == 1  # R7 put back right away after the refusal
    assert "tunnel mode ipsec ipv4" in page.status_label.text()
    assert not any("interface Tunnel10" in line for line in vpn.render(r6.tree))


def test_a_failed_check_puts_every_router_back(page):
    FakeVpnShell.channels = routers(r7={"pings_fail": True})
    new_vti(page)
    page.send()
    wait(page)
    r6, r7 = FakeVpnShell.channels["8.0.0.22"], FakeVpnShell.channels["8.0.0.26"]
    assert r6.reverts == 1 and r7.reverts == 1 and r6.confirms == r7.confirms == 0
    assert "answers" in page.status_label.text()
    assert all(entry.outcome.startswith("Put back") for entry in page.store.history[:2]),         [entry.outcome for entry in page.store.history[:2]]


def test_a_hub_aims_its_wan_at_the_spokes_not_its_default_route(page):
    """The hub is set up first: its WAN is still the way to the spokes, not where its default route goes (R5's
    management VLAN, which the spokes couldn't reach)."""
    hub = FakeVpnShell.channels["8.0.0.22"]
    hub.tree = vpn.parse_tree("interface GigabitEthernet0.172\n ip address 172.18.0.16 255.255.255.0\n" + R6)
    hub.routes += "S*    0.0.0.0/0 [1/0] via 172.18.0.1\n" \
                  "C        172.18.0.0/24 is directly connected, GigabitEthernet0.172\n"
    read_both(page)
    page.make_new("CLOUD", vpn.DMVPN, [("map:R6", vpn.HUB), ("map:R7", vpn.SPOKE)])
    design = page.editable()
    assert [(member.wan, member.local_ip) for member in design.members] == \
        [("GigabitEthernet1", "8.0.0.22"), ("GigabitEthernet1", "8.0.0.26")]


def test_left_for_me_to_confirm(page):
    new_vti(page)
    page.confirm_combo.setCurrentIndex(page.confirm_combo.findData(vpn_tab.CONFIRM_MANUAL))
    design_id = page.current_id
    page.send()
    wait(page)
    found = next(item for item in page.found if item.name == "LAB")
    page.current_id = found.id
    assert found.id in page.waiting and page.waiting_box.isVisibleTo(page)
    page.confirm_waiting()
    wait(page)
    r6 = FakeVpnShell.channels["8.0.0.22"]
    assert r6.confirms == 1 and found.id not in page.waiting
    assert design_id == found.id


def test_take_away_a_found_vpn(page):
    new_vti(page, vpn.EIGRP)
    page.send()
    wait(page)
    found = next(item for item in page.found if item.name == "LAB")
    assert found.routing.kind == vpn.EIGRP
    page.current_id = found.id
    page.drafts[found.id] = None
    page.originals[found.id] = found
    page.refresh_changes()
    text = page.preview_text(reveal=True)
    assert "no interface Tunnel10" in text and "no router eigrp 100" in text
    page.send()
    wait(page)
    r6 = FakeVpnShell.channels["8.0.0.22"]
    assert not any(line.startswith(("interface Tunnel10", "router eigrp")) for line in vpn.render(r6.tree))
    assert not [item for item in page.found if item.name == "LAB"]


def test_map_tunnels_for_the_overlay(page):
    new_vti(page)
    page.send()
    wait(page)
    lines = page.map_tunnels()
    assert len(lines) == 1 and {lines[0][0], lines[0][1]} == {"R6", "R7"}
    from nomad.netmap import overlays
    overlay = overlays.build(lab_map(), overlays.VPNS, lines)
    assert len(overlay.extra_lines) == 1 and set(overlay.devices) == {"R6", "R7"}


def test_certificate_steps_planned_for_a_router_ca(page):
    design = new_vti(page)
    design.auth.method = vpn.CERT
    design.auth.ca_kind, design.auth.ca_device, design.auth.ca_name = "router", "map:R6", "LAB-CA"
    steps = vpnpki.plan(design, page.devices(), "Passphrase1", "")
    titles = [step.title for step in steps]
    assert titles[0].startswith("Set up certificate server LAB-CA on R6")
    assert any(title.startswith("Make R6's clock") for title in titles)  # No NTP: kept from the CA router
    assert any(title.startswith("Keep R7's clock in step") for title in titles)
    assert any(title.startswith("Enroll R7") for title in titles) and any(title.startswith("Enroll R6")
                                                                          for title in titles)
    enroll = next(step for step in steps if step.title.startswith("Enroll R7"))
    lines = [line for line, _ in enroll.steps]
    assert " enrollment url http://8.0.0.22:80" in lines and "crypto pki authenticate LAB-TP" in lines
    # The CA certificate is accepted only when it shows the expected fingerprint
    answer = vpnpki.accepts("0A1B 2C3D 4E5F 6071 8293 A4B5 C6D7 E8F9")
    assert answer("Fingerprint MD5: 0A1B2C3D 4E5F6071 8293A4B5 C6D7E8F9\n% Do you accept this certificate?") == "yes"
    assert answer("Fingerprint MD5: FFFFFFFF 4E5F6071 8293A4B5 C6D7E8F9\n% Do you accept this certificate?") is None
    assert page.blocked(design.id).startswith("Get certificates first")
