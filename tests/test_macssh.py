"""MAC Finder over SSH: parsing Cisco show commands, the command line itself, and following a MAC from switch to
switch with no SNMP (and no map)."""
import os
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest

from nomad.netmap import macfind, macssh
from nomad.netmap.crawl import CrawlSettings
from nomad.netmap.macfind import LIVE, Locator, parse_query
from nomad.oui import format_mac
from nomad.netmap.model import NEIGHBOR, SNMP, SWITCH, Device, NetworkMap
from nomad.terminal.sessions import Session
from nomad.terminal.transports import ConnectionFailed

PRINTER = format_mac("0050.56aa.0001")

IOS_ONE = """          Mac Address Table
-------------------------------------------

Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
  10    0050.56aa.0001    DYNAMIC     Gi1/0/48
Total Mac Addresses for this criterion: 1
"""

NXOS_TABLE = """Legend:
        * - primary entry, G - Gateway MAC, (R) - Routed MAC, O - Overlay MAC
        age - seconds since last seen,+ - primary entry using vPC Peer-Link,
   VLAN     MAC Address      Type      age     Secure NTFY Ports
---------+-----------------+--------+---------+------+----+------------------
*   10     0050.56aa.0001   dynamic  0         F      F    Eth1/5
G    -     5254.0012.3456   static   -         F      F    sup-eth1(R)
*   20     0050.56aa.0009   dynamic  0         F      F    vPC Peer-Link
"""

OLD_IOS_TABLE = """Legend: * - primary entry
  vlan   mac address     type    learn     age              ports
------+----------------+--------+-----+----------+--------------------------
*   30  0050.56aa.0002   dynamic  Yes          0   Gi1/1
  All    0100.0ccc.cccc    STATIC      CPU
"""

CORE_CDP = """-------------------------
Device ID: acc1.corp.example
Entry address(es):
  IP address: 10.0.0.21
Platform: cisco WS-C2960X-48FPD-L,  Capabilities: Switch IGMP
Interface: GigabitEthernet1/0/48,  Port ID (outgoing port): GigabitEthernet1/0/52
Holdtime : 150 sec

-------------------------
Device ID: SEP001122334455
Entry address(es):
  IP address: 10.20.0.50
Platform: Cisco IP Phone 8845,  Capabilities: Host Phone Two-port Mac Relay
Interface: GigabitEthernet1/0/5,  Port ID (outgoing port): Port 1
"""

NXOS_LLDP = """Capability codes:
  (R) Router, (B) Bridge, (T) Telephone, (C) DOCSIS Cable Device
Chassis id: 0011.2233.4455
Port id: Ethernet1/1
Local Port id: Eth1/49
Port Description: Ethernet1/1
System Name: dist2
System Description: Cisco Nexus Operating System (NX-OS) Software 9.3(8)
Time remaining: 95 seconds
System Capabilities: B, R
Enabled Capabilities: B, R
Management Address: 10.0.0.3
Vlan ID: 1

Chassis id: 0050.56aa.0003
Port id: 0050.56aa.0003
Local Port id: Eth1/7
System Name: ws-17
System Description: Windows 11
Enabled Capabilities: S
"""

ETHERCHANNEL = """Group  Port-channel  Protocol    Ports
------+-------------+-----------+-----------------------------------------------
1      Po1(SU)         LACP      Gi1/0/49(P) Gi1/0/50(P)
                                 Gi1/0/51(D)
2      Po2(SD)         -
"""

ARP = """Protocol  Address          Age (min)  Hardware Addr   Type   Interface
Internet  10.10.0.21              3   0050.56aa.0001  ARPA   Vlan10
Internet  10.10.0.99              0   Incomplete      ARPA
"""

DESCRIPTION = """Interface                      Status         Protocol Description
Gi1/0/7                        up             up       Printer room 2
"""


def test_mac_tables_of_each_kind():
    entry, = macssh.parse_mac_table(IOS_ONE)
    assert (entry.mac, entry.vlan, entry.port, entry.own) == (PRINTER, 10, "Gi1/0/48", False)
    nxos = macssh.parse_mac_table(NXOS_TABLE)
    assert [(item.vlan, item.port, item.own) for item in nxos] == [(10, "Eth1/5", False), (0, "", True),
                                                                   (20, macssh.PEER_LINK, False)]
    old = macssh.parse_mac_table(OLD_IOS_TABLE)
    assert [(item.mac, item.vlan, item.port, item.own) for item in old] == [
        (format_mac("005056aa0002"), 30, "Gi1/1", False), (format_mac("01000ccccccc"), 0, "", True)]
    assert macssh.cisco_mac("00-50-56-AA-00-01") == "0050.56aa.0001"


def test_neighbors_from_cdp_and_lldp():
    switch, phone = macssh.parse_cdp(CORE_CDP)
    assert (switch.local_port, switch.name, switch.port, switch.address) == \
        ("Gi1/0/48", "acc1.corp.example", "Gi1/0/52", "10.0.0.21")
    assert switch.capabilities == {"switch"} and "WS-C2960X" in switch.platform
    assert "phone" in phone.capabilities
    dist, computer = macssh.parse_lldp(NXOS_LLDP)
    assert (dist.local_port, dist.name, dist.port, dist.address) == ("Eth1/49", "dist2", "Eth1/1", "10.0.0.3")
    assert dist.capabilities == {"bridge", "router"} and computer.capabilities == {"station"}


def test_channels_arp_and_descriptions():
    assert macssh.parse_channels(ETHERCHANNEL) == {"Po1": ["Gi1/0/49", "Gi1/0/50", "Gi1/0/51"], "Po2": []}
    assert macssh.parse_arp(ARP) == {PRINTER: ["10.10.0.21"]}
    assert macssh.parse_description(DESCRIPTION, "GigabitEthernet1/0/7") == "Printer room 2"
    assert macssh.parse_description("Eth1/5   eth  1000   Uplink to core", "Ethernet1/5") == "Uplink to core"
    assert macssh.clean("sh\x08\x08show\r\nsw1#") == "show\nsw1#"


# --------------------------------------------------------------------- The command line

class FakeChannel:
    """A switch's command line: answers each command line with replies[command] and the prompt."""

    def __init__(self, banner, prompt, replies, pages=False):
        self.out = [banner + "\r\n" + prompt]
        self.prompt, self.replies, self.pages = prompt, replies, pages
        self.closed = False
        self.sent = []

    def recv_ready(self):
        return bool(self.out)

    def recv(self, size):
        return self.out.pop(0).encode()

    def exit_status_ready(self):
        return False

    def send(self, text):
        self.sent.append(text)
        if text == " ":
            self.out.append("\r\nsecond page\r\n" + self.prompt)
            return
        command = text.strip()
        reply = self.replies.get(command, "% Invalid input detected at '^' marker.")
        if self.pages and command == "show long":
            self.out.append(command + "\r\n" + reply + "\r\n --More-- ")
            return
        self.out.append(command + "\r\n" + reply.replace("\n", "\r\n") + "\r\n" + self.prompt)


def shell_on(channel, monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    shell = macssh.SshShell(Session("sw1", host="10.0.0.1"))
    shell.channel = channel
    return shell


def test_shell_reads_to_the_prompt(monkeypatch):
    channel = FakeChannel("Authorized access only\r\n#####", "sw1#", {"terminal length 0": "", "show long": "first page",
                                                                        "show mac address-table": IOS_ONE})
    shell = shell_on(channel, monkeypatch)
    text = shell.read(5)
    shell.prompt = text.rstrip().splitlines()[-1].strip()
    assert shell.prompt == "sw1#"
    assert shell.run("show mac address-table").strip().startswith("Mac Address Table")
    assert "sw1#" not in shell.run("show mac address-table")
    assert "Invalid input" in shell.run("show nothing")
    channel.pages = True
    assert "second page" in shell.run("show long") and " " in channel.sent  # Paging still on: next page


def test_shell_gives_up_on_silence(monkeypatch):
    channel = FakeChannel("", "sw1#", {})
    channel.out = ["no prompt here"]
    shell = shell_on(channel, monkeypatch)
    monkeypatch.setattr(macssh, "POLL", 0.001)
    with pytest.raises(ConnectionFailed, match="No answer"):
        shell.read(0.05)


def test_batch_prompter_never_asks():
    prompter = macssh.BatchPrompter(trust_new=False, password="pw")
    assert prompter.host_key("h", 22, "ssh-ed25519", "SHA256:x", False, "") == "cancel"
    assert "hasn't connected" in prompter.problem
    assert macssh.BatchPrompter(trust_new=True).host_key("h", 22, "k", "f", False, "") == "trust"
    assert macssh.BatchPrompter(trust_new=True).host_key("h", 22, "k", "f", True, "old") == "cancel"
    assert prompter.secret("Password", "Password for x:", True) == ("pw", False)
    assert prompter.secret("Password", "That didn't work", True) is None  # Given once only
    assert prompter.username("h") is None


def test_logins_prefer_the_switchs_saved_session():
    own = Session("sw2", host="sw2.corp.example", username="local-admin")
    logins = macssh.SshLogins([own], fallback=Session("", username="tacacs"))
    assert logins.for_device("10.0.0.2", ["sw2"]).username == "local-admin"
    other = logins.for_device("10.0.0.3", ["sw3"])
    assert (other.username, other.host, other.port) == ("tacacs", "10.0.0.3", 22)
    assert macssh.SshLogins([own]).for_device("10.0.0.3") is None


# --------------------------------------------------------------------- Following a MAC with no SNMP

SWITCHES = {
    "10.0.0.1": {  # core: the printer is beyond Gi1/0/48, where acc1 is
        "show mac address-table address 0050.56aa.0001": IOS_ONE,
        "show cdp neighbors detail": CORE_CDP,
        "show lldp neighbors detail": "% LLDP is not enabled",
        "show interface Gi1/0/48 description": "",
        "show ip arp 10.10.0.21": ARP,
    },
    "10.0.0.21": {  # acc1: the printer's own port
        "show mac address-table address 0050.56aa.0001": IOS_ONE.replace("Gi1/0/48", "Gi1/0/7"),
        "show cdp neighbors detail": "",
        "show lldp neighbors detail": "",
        "show interface Gi1/0/7 description": DESCRIPTION,
        "show mac address-table interface Gi1/0/7": IOS_ONE.replace("Gi1/0/48", "Gi1/0/7"),
    },
}


class FakeShell:
    """SshShell on SWITCHES: logs in (unless refused), then answers from the switch's replies."""
    refused = {}
    logins = []

    def __init__(self, session, vault=None, known_hosts=None, trust_new=False, password=None,
                 should_stop=lambda: False):
        self.session = session

    def open(self):
        FakeShell.logins.append((self.session.host, self.session.username))
        if self.session.host in FakeShell.refused:
            raise ConnectionFailed(FakeShell.refused[self.session.host])

    def run(self, command, timeout=0):
        return SWITCHES.get(self.session.host, {}).get(command, "% Invalid input detected at '^' marker.")

    def close(self):
        pass


@pytest.fixture
def asker():
    FakeShell.refused, FakeShell.logins = {}, []
    logins = macssh.SshLogins(fallback=Session("", username="tacacs"))
    made = macssh.SshAsker(logins, shell_factory=FakeShell)
    yield made
    made.close()


def no_map_locator(asker, start="10.0.0.1"):
    network_map = NetworkMap()
    network_map.devices["start"] = Device("start", name="", mgmt_ip=start, kind=SWITCH, source=NEIGHBOR)
    network_map.root = "start"
    return Locator(network_map, CrawlSettings(seeds=[]), ssh=asker, start="start", workers=2)


def test_a_mac_is_followed_from_switch_to_switch(asker):
    locator = no_map_locator(asker)
    found, problem = locator.run_one(parse_query("0050.56aa.0001"), [])
    location, = found
    assert problem == "" and location.source == LIVE
    assert (location.switch, location.port, location.vlan) == ("acc1.corp.example", "Gi1/0/7", 10)
    assert location.description == "Printer room 2" and location.port_macs == 1
    assert location.path == [["10.0.0.1", "Gi1/0/48"], ["acc1.corp.example", "Gi1/0/7"]]
    assert location.seen_on == [["10.0.0.1", "Gi1/0/48"]]
    assert [host for host, _ in FakeShell.logins] == ["10.0.0.1", "10.0.0.21"]  # Each logged into once
    reports = {report.address: report for report in locator.reports.values()}
    assert [(reports[address].ssh, reports[address].login) for address in ("10.0.0.1", "10.0.0.21")] ==         [(macfind.LOGGED_IN, "user tacacs")] * 2
    assert reports["10.0.0.21"].name == "acc1.corp.example" and not any(r.failed for r in reports.values())


def test_an_ip_address_is_found_in_the_start_switchs_arp(asker):
    locator = no_map_locator(asker)
    found, problem = locator.run_one(parse_query("10.10.0.21"), [])
    assert problem == "" and found[0].port == "Gi1/0/7" and found[0].ip == "10.10.0.21"


def test_a_switch_that_refuses_the_login_is_said(asker):
    FakeShell.refused["10.0.0.21"] = "Login failed: the user name or password wasn't accepted."
    locator = no_map_locator(asker)
    location, = locator.run_one(parse_query("0050.56aa.0001"), [])[0]
    assert (location.switch, location.port) == ("10.0.0.1", "Gi1/0/48")  # As far as it got
    assert "acc1.corp.example, which NOMAD couldn't ask over SSH" in location.note
    assert "wasn't accepted" in asker.problems["10.0.0.21"]
    failed, = [report for report in locator.reports.values() if report.failed]
    assert (failed.name, failed.ssh) == ("acc1.corp.example", macfind.LOGIN_FAILED) and "wasn't accepted" in failed.note


def test_steps_say_each_login(asker):
    FakeShell.refused["10.0.0.21"] = "Login failed: the user name or password wasn't accepted."
    events = []
    locator = no_map_locator(asker)
    locator.events = lambda kind, *details: events.append((kind, details))
    locator.run_one(parse_query("0050.56aa.0001"), [])
    steps = [details[0] for kind, details in events if kind == "step"]
    assert "Logged in to 10.0.0.1 over SSH (user tacacs)" in steps
    assert any(step.startswith("acc1.corp.example: couldn't ask over SSH: Login failed") for step in steps)
    devices = [details[0] for kind, details in events if kind == "device"]
    assert {report.ssh for report in devices} == {macfind.LOGGED_IN, macfind.LOGIN_FAILED}


def test_trying_one_login_again(asker):
    FakeShell.refused["10.0.0.21"] = "Login failed: the user name or password wasn't accepted."
    told = []
    asker.listener = lambda *details: told.append(details)
    assert asker.try_login("10.0.0.21") == (False, "user tacacs", FakeShell.refused["10.0.0.21"])
    FakeShell.refused.clear()  # The password fixed
    assert asker.try_login("10.0.0.21") == (True, "user tacacs", "")
    assert [ok for _, ok, _, _ in told] == [False, True] and "10.0.0.21" not in asker.shells


def test_the_summary_counts_each_way():
    from nomad.ui.mac_finder_tab import summary_text
    report = macfind.DeviceReport
    reports = [report("core", "core", "10.0.0.1", snmp=macfind.ANSWERED),
               report("acc1", "acc1", "10.0.0.21", snmp=macfind.NO_ANSWER, ssh=macfind.LOGGED_IN),
               report("acc2", "acc2", "10.0.0.22", snmp=macfind.NO_ANSWER, ssh=macfind.LOGIN_FAILED,
                      note="Login failed: the user name or password wasn't accepted.")]
    text = summary_text(reports, ssh=True)
    assert "Asked 2 switches: 1 over SNMP, 1 over SSH." in text
    assert "1 switch couldn't be asked (acc2: Login failed: the user name or password wasn't accepted)" in text
    assert summary_text(reports[:1] + [report("x", "x", "10.0.0.9", snmp=macfind.NO_ANSWER)], ssh=False) ==         " 1 device didn't answer SNMP: x."


def test_ssh_asks_only_the_switches_snmp_cannot():
    network_map = NetworkMap()
    network_map.devices["core"] = Device("core", name="core", mgmt_ip="10.0.0.1", kind=SWITCH, source=SNMP)
    network_map.devices["acc1"] = Device("acc1", name="acc1", mgmt_ip="10.0.0.21", kind=SWITCH, source=NEIGHBOR)
    snmp_only = Locator(network_map, CrawlSettings(seeds=[]))
    assert snmp_only.switches() == ["core"]  # Without SSH, only what answered SNMP
    with_ssh = Locator(network_map, CrawlSettings(seeds=[]), ssh=SimpleNamespace(listener=None))
    assert with_ssh.switches() == ["core", "acc1"]


def test_the_page_locates_over_ssh_with_no_map(tmp_path, monkeypatch):
    from PyQt5.QtWidgets import QApplication, QMainWindow, QStackedWidget
    from nomad.netmap.sightings import SightingLog
    from nomad.snapshot import NetworkSnapshot
    from nomad.terminal.sessions import Credential, SessionStore
    from nomad.ui.mac_finder_tab import COL_PORT, COL_SWITCH, MacFinderTab
    app = QApplication.instance() or QApplication([])
    FakeShell.refused, FakeShell.logins = {}, []

    class Window(QMainWindow):
        def __init__(self):
            super().__init__()
            self.snapshot = NetworkSnapshot()
            self.navigator = QStackedWidget()
            self.session_store = SessionStore(str(tmp_path / "sessions.json"))

        def show_status(self, *args):
            pass

    window = Window()
    store = window.session_store
    store.credentials.put(Credential("TACACS", username="jsmith", saved_password=store.vault.protect("pw")),
                          default=True)
    monkeypatch.setattr(macfind, "reverse_names", lambda addresses, timeout=2.0: {})
    page = MacFinderTab(window, history=SightingLog(tmp_path / "history.db"))
    page.shell_factory = FakeShell
    try:
        page.search_input.setText("0050.56aa.0001")
        assert not page.locate_button.isEnabled()  # No map, no SSH
        page.ssh_check.setChecked(True)
        assert not page.locate_button.isEnabled()  # No switch to start at
        page.start_input.setText("10.0.0.1")
        assert page.locate_button.isEnabled() and "SSH" in page.locate_button.toolTip()
        assert page.login_picker.credential().name == "TACACS"
        page.locate()
        deadline = time.monotonic() + 20
        while page.worker is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        rows = [(page.table.item(row, COL_SWITCH).text(), page.table.item(row, COL_PORT).text())
                for row in range(page.table.rowCount())]
        assert rows == [("acc1.corp.example", "Gi1/0/7")]
        assert ("10.0.0.21", "jsmith") in FakeShell.logins  # With the credential
        assert "Found it" in page.status_label.text()
        assert "Asked 2 switches: 0 over SNMP, 2 over SSH." in page.status_label.text()
        assert page.bottom_tabs.tabText(1) == "Switches Asked (2)"
        from nomad.ui.mac_finder_tab import DEV_LOGIN, DEV_SSH
        assert {page.devices_table.item(row, DEV_SSH).text() for row in range(2)} == {macfind.LOGGED_IN}
        assert page.devices_table.item(0, DEV_LOGIN).text() == "credential TACACS"
        acc1 = next(report for report in page.device_reports.values() if report.address == "10.0.0.21")
        page.on_login_tried(acc1, (False, "credential TACACS", "Login failed: wrong password."))
        assert page.bottom_tabs.tabText(1) == "Switches Asked (2, 1 couldn't be)"
        assert page.devices_table.item(0, DEV_SSH).text() == macfind.LOGIN_FAILED  # Failures first
        assert "wrong password" in page.status_label.text()
    finally:
        page.shutdown()
        window.deleteLater()
        app.processEvents()


def run_cisco_server(host_key, replies):
    """A switch's SSH command line on a free port (password "secret" for admin): answers each line it gets with
    replies[line] (or IOS's complaint) and its prompt, the way IOS does."""
    import socket
    import threading

    import paramiko
    from test_terminal_transports import FakeServer

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    server = FakeServer()

    def serve():
        connection, _ = listener.accept()
        transport = paramiko.Transport(connection)
        transport.add_server_key(host_key)
        try:
            transport.start_server(server=server)
            channel = transport.accept(60)
            if channel is None:
                return
            server.shell.wait(5)
            channel.sendall(b"\r\nUnauthorized access prohibited\r\n\r\nsw1#")
            line = b""
            while True:
                data = channel.recv(1024)
                if not data:
                    break
                line += data
                while b"\n" in line:
                    command, line = line.split(b"\n", 1)
                    command = command.strip().decode()
                    reply = replies.get(command, "% Invalid input detected at '^' marker.")
                    channel.sendall((command + "\r\n" + reply.replace("\n", "\r\n") + "\r\nsw1#").encode())
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()
            listener.close()

    threading.Thread(target=serve, daemon=True).start()
    return port


def test_a_real_ssh_login_runs_show_commands(tmp_path, monkeypatch):
    import paramiko
    from nomad.terminal.hostkeys import KnownHosts
    monkeypatch.setattr(macssh, "QUIET", 0.05)
    port = run_cisco_server(paramiko.RSAKey.generate(2048), {
        "terminal length 0": "", "terminal width 511": "", "show mac address-table address 0050.56aa.0001": IOS_ONE})
    session = Session("sw1", host="127.0.0.1", port=port, username="admin")
    known = KnownHosts(str(tmp_path / "known_hosts"))
    asker = macssh.SshAsker(macssh.SshLogins([session], password="secret"), known_hosts=known, trust_new=True)
    try:
        entries = asker.mac_entries("127.0.0.1", "0050.56aa.0001")
        assert [(entry.port, entry.vlan) for entry in entries] == [("Gi1/0/48", 10)]
        assert asker.shells["127.0.0.1"].prompt == "sw1#"
        assert asker.problems == {}
        assert asker.mac_table("127.0.0.1") == []  # Refused: none
    finally:
        asker.close()
    assert known.keys.lookup(f"[127.0.0.1]:{port}")  # Its key, trusted and remembered


def test_an_unknown_key_is_not_trusted_unless_allowed(tmp_path):
    import paramiko
    from nomad.terminal.hostkeys import KnownHosts
    port = run_cisco_server(paramiko.RSAKey.generate(2048), {})
    session = Session("sw1", host="127.0.0.1", port=port, username="admin")
    asker = macssh.SshAsker(macssh.SshLogins([session], password="secret"),
                            known_hosts=KnownHosts(str(tmp_path / "known_hosts")), trust_new=False)
    try:
        assert asker.mac_entries("127.0.0.1", "0050.56aa.0001") is None
        assert "hasn't connected to it over SSH before" in asker.problems["127.0.0.1"]
    finally:
        asker.close()


def test_what_snmp_misses_is_asked_again_over_ssh(asker, monkeypatch):
    """Every switch answers SNMP, but the MAC isn't in what SNMP reads: SSH's show mac address-table has it."""
    from netmap_fakes import build_network
    network = build_network()
    network_map = macfind.Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                                  client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    acc2 = next(key for key, device in network_map.devices.items() if device.mgmt_ip == "10.0.0.12")
    monkeypatch.setitem(SWITCHES, "10.0.0.12", {
        "show mac address-table address 0050.56aa.0001": IOS_ONE.replace("Gi1/0/48", "Gi1/0/9")})
    events = []
    locator = Locator(macfind.snapshot_map(network_map), CrawlSettings(seeds=[], overrides=[("10.0.0.12/32",
                                                                                             "secret")]),
                      client_factory=network.client, ssh=asker, workers=2,
                      events=lambda kind, *details: events.append((kind, details)))
    location, = locator.run_one(parse_query("0050.56aa.0001"), [])[0]
    assert (location.device, location.port, location.vlan) == (acc2, "Gi1/0/9", 10)
    steps = [details[0] for kind, details in events if kind == "step"]
    assert any("not found over SNMP; asking the switches over SSH" in step for step in steps)
    reports = list(locator.reports.values())
    snmp = [report for report in reports if locator.map.devices[report.key].source == SNMP]
    assert snmp and all(report.snmp == macfind.ANSWERED for report in snmp)
    assert {report.ssh for report in reports} == {macfind.LOGGED_IN}  # Each switch logged into for the second look
    from nomad.ui.mac_finder_tab import summary_text
    assert f"Asked {len(reports)} switches: {len(snmp)} over SNMP, {len(reports)} over SSH." in         summary_text(reports, ssh=True)


def snmp_map_locator(asker, events):
    from netmap_fakes import build_network
    network = build_network()
    settings = CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")])
    network_map = macfind.Crawler(settings, client_factory=network.client, pinger=network.ping,
                                  echo=network.echo).run()
    locator = Locator(macfind.snapshot_map(network_map), settings, client_factory=network.client, ssh=asker,
                      workers=2, events=lambda kind, *details: events.append((kind, details)))
    return locator, network_map


def test_part_of_a_mac_snmp_misses_is_read_over_ssh(asker, monkeypatch):
    """Searching for part of a MAC reads every switch's whole table: over SSH too, when SNMP's have nothing."""
    events = []
    locator, network_map = snmp_map_locator(asker, events)
    acc2 = next(key for key, device in network_map.devices.items() if device.mgmt_ip == "10.0.0.12")
    monkeypatch.setitem(SWITCHES, "10.0.0.12", {"show mac address-table": IOS_ONE.replace("Gi1/0/48", "Gi1/0/9")})
    results = locator.run([parse_query("a865"), parse_query("56aa")])
    assert results[0] == ([], "")  # In no table, either way
    location, = results[1][0]
    assert (location.device, location.port, location.mac) == (acc2, "Gi1/0/9", PRINTER)
    steps = [details[0] for kind, details in events if kind == "step"]
    assert sum("reading them over SSH" in step for step in steps) == 1  # Read over SSH once, for both
    assert all(report.ssh == macfind.LOGGED_IN for report in locator.reports.values()
               if network_map.devices[report.key].mgmt_ip)


def test_an_ip_address_snmp_has_no_arp_for_is_asked_over_ssh(asker, monkeypatch):
    events = []
    locator, network_map = snmp_map_locator(asker, events)
    router = next(key for key, device in network_map.devices.items() if device.interfaces_l3 and
                  any(interface[0].startswith("10.10.") for interface in device.interfaces_l3))
    address = network_map.devices[router].mgmt_ip
    monkeypatch.setitem(SWITCHES, address, {"show ip arp 10.10.0.77": ARP.replace("10.10.0.21", "10.10.0.77")})
    mac, how = locator.mac_for_ip("10.10.0.77")
    assert (mac, how) == (PRINTER, "ARP")
    assert any("ARP, over SSH" in details[0] for kind, details in events if kind == "step")
