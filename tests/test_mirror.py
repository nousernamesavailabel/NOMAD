"""Port Mirroring: choosing SPAN, RSPAN or ERSPAN, the safety checks, the lines sent and taken away, the switches'
own sessions, the EEM applet, the record kept, and sending over SSH."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from nomad.netmap import configpush, mirror
from nomad.netmap.mirror import ERSPAN, RSPAN, RX, SPAN, TO_ADDRESS, MirrorStore, Request, Source, SwitchState, plan
from nomad.netmap.model import ROUTER, SNMP, SWITCH, Host, Link, NetworkMap
from nomad.netmap.model import Device as MapDevice
from nomad.netmap.vlans import ERROR, WARNING

XE = "Cisco IOS XE Software, Version 17.09.04a, C9300-48P"
CLASSIC = "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E3"


def trunk(allowed="1-4094"):
    return {"mode": "trunk", "native": 1, "allowed": allowed}


def access(vlan):
    return {"mode": "access", "vlan": vlan}


def switch(key, ip, ports=None, vlans=(1, 10), descr=XE, kind=SWITCH, speeds=None):
    return MapDevice(key, key, mgmt_ip=ip, kind=kind, source=SNMP, sys_descr=descr, vtp_mode="transparent",
                     vlans=[[vlan, f"V{vlan}"] for vlan in vlans], port_vlans=dict(ports or {}),
                     port_status={port: {"oper": "up", "speed": speed} for port, speed in (speeds or {}).items()})


def campus():
    """SW1 - SW2 by a trunk, SW2 - R1 (a router) - SW9 beyond it. A printer on SW1 Gi1/0/5, this PC on SW2 Gi1/0/9."""
    network_map = NetworkMap()
    devices = [
        switch("SW1", "10.0.0.1", {"Gi1/0/1": access(10), "Gi1/0/2": access(10), "Gi1/0/5": access(10),
                                   "Gi1/0/48": trunk("1,10")},
               speeds={"Gi1/0/1": 1000, "Gi1/0/2": 1000, "Gi1/0/5": 1000}),
        switch("SW2", "10.0.0.2", {"Gi1/0/9": access(10), "Gi1/0/24": access(10), "Gi1/0/48": trunk("1,10"),
                                   "Gi1/0/47": access(10)}),
        switch("R1", "10.0.0.254", kind=ROUTER),
        switch("SW9", "10.9.0.9", {"Gi1/0/3": access(10)}, descr=XE),
    ]
    network_map.devices = {device.key: device for device in devices}
    network_map.links = [Link("SW1", "Gi1/0/48", "SW2", "Gi1/0/48"), Link("SW2", "Gi1/0/47", "R1", "Gi0/0"),
                         Link("R1", "Gi0/1", "SW9", "Gi1/0/1")]
    network_map.hosts = [Host("00-50-56-AA-00-05", "SW1", "Gi1/0/5", ip="10.0.10.5", name="printer"),
                         Host("00-50-56-AA-00-09", "SW2", "Gi1/0/9", ip="10.0.10.9", name="pc")]
    return network_map


def read(*numbers):
    """A switch read with sessions of these numbers in use."""
    return SwitchState(read=True, sessions={number: mirror.MonitorSession(number, "Local Session")
                                            for number in numbers})


def states(**sessions):
    found = {key: read() for key in ("SW1", "SW2", "R1", "SW9")}
    found.update(sessions)
    return found


def errors(result):
    return [finding.text for finding in result.findings if finding.severity == ERROR]


# --------------------------------------------------------------------- Choosing the kind

def test_same_switch_is_span_with_a_free_session():
    request = Request("SW1", [Source("Gi1/0/1"), Source("Gi1/0/2", direction=RX)], dest_device="SW1",
                      dest_port="Gi1/0/3")
    result = plan(campus(), request, states(SW1=read(1, 2)))
    assert result.ok and result.kind == SPAN and "same device" in result.why
    step, = result.steps
    assert step.session == 3
    assert step.lines == ["monitor session 3 source interface Gi1/0/1 both",
                          "monitor session 3 source interface Gi1/0/2 rx",
                          "monitor session 3 destination interface Gi1/0/3"]
    assert mirror.config_text(step).splitlines()[0] == "configure terminal"
    assert mirror.undo_text(step) == "configure terminal\nno monitor session 3\nend"


def test_service_instance_sources():
    assert Source("Gi6.SI.6").ios() == "service instance 6 gigabitEthernet 6 both"
    assert Source("GigabitEthernet6.SI.6", direction=RX).ios() == "service instance 6 gigabitEthernet 6 rx"
    assert Source("Te1/0/1.SI.200").ios() == "service instance 200 tenGigabitEthernet 1/0/1 both"
    assert Source("Gi1/0/1").ios() == "interface Gi1/0/1 both"
    network_map = campus()
    network_map.devices["SW1"].port_vlans["Gi6.SI.6"] = {}
    request = Request("SW1", [Source("Gi6.SI.6")], to=TO_ADDRESS, dest_ip="10.0.10.9")
    result = plan(network_map, request, states())
    assert result.ok and result.kind == ERSPAN
    assert " source service instance 6 gigabitEthernet 6 both" in result.steps[0].lines
    warning, = [finding.text for finding in result.findings if finding.severity == WARNING]
    assert "copy nothing" in warning and "mirror Gi6 instead" in warning
    plain = plan(network_map, Request("SW1", [Source("Gi1/0/5")], to=TO_ADDRESS, dest_ip="10.0.10.9"), states())
    assert not any("service instance" in finding.text for finding in plain.findings)


def test_destination_options():
    request = Request("SW1", [Source("Gi1/0/1")], dest_device="SW1", dest_port="Gi1/0/3", replicate=True,
                      ingress_vlan=10)
    step, = plan(campus(), request, states()).steps
    assert step.lines[-1] == ("monitor session 1 destination interface Gi1/0/3 encapsulation replicate "
                              "ingress untagged vlan 10")


def test_switched_way_is_rspan_with_a_free_remote_span_vlan():
    request = Request("SW1", [Source("Gi1/0/5")], dest_device="SW2", dest_port="Gi1/0/24")
    result = plan(campus(), request, states())
    assert result.ok, errors(result)
    assert result.kind == RSPAN and result.rspan_vlan == 999 and result.route == ["SW1", "SW2"]
    by_device = {step.device: step for step in result.steps}
    assert [step.device for step in result.steps] == ["SW2", "SW1"]  # Destination first, the source last
    source, destination = by_device["SW1"], by_device["SW2"]
    assert source.lines[:3] == ["vlan 999", " remote-span", " name NOMAD_RSPAN"]
    assert "interface Gi1/0/48" in source.lines and " switchport trunk allowed vlan add 999" in source.lines
    assert source.lines[-2:] == ["monitor session 1 source interface Gi1/0/5 both",
                                 "monitor session 1 destination remote vlan 999"]
    assert destination.lines[-2:] == ["monitor session 1 source remote vlan 999",
                                      "monitor session 1 destination interface Gi1/0/24"]
    assert source.undo_lines[0] == "no monitor session 1" and source.undo_lines[-1] == "no vlan 999"
    assert " switchport trunk allowed vlan remove 999" in source.undo_lines


def test_rspan_vlan_must_be_unused():
    request = Request("SW1", [Source("Gi1/0/5")], dest_device="SW2", dest_port="Gi1/0/24", rspan_vlan=10)
    result = plan(campus(), request, states())
    assert not result.ok and any("VLAN 10 is in use" in text for text in errors(result))


def test_routed_way_is_erspan():
    request = Request("SW1", [Source("Gi1/0/5")], dest_device="SW9", dest_port="Gi1/0/3")
    result = plan(campus(), request, states())
    assert result.ok, errors(result)
    assert result.kind == ERSPAN and result.erspan_id == 1
    assert result.origin_ip == "10.0.0.1" and result.dest_ip == "10.9.0.9"
    destination, source = result.steps
    assert destination.device == "SW9" and destination.lines[0] == "monitor session 1 type erspan-destination"
    assert " destination interface Gi1/0/3" in destination.lines and "  ip address 10.9.0.9" in destination.lines
    assert source.lines[0] == "monitor session 1 type erspan-source"
    assert source.lines[2:] == [" source interface Gi1/0/5 both", " destination", "  erspan-id 1",
                                "  ip address 10.9.0.9", "  origin ip address 10.0.0.1", " exit", " no shutdown",
                                " exit"]


def test_erspan_to_an_address_and_classic_ios_warned():
    network_map = campus()
    network_map.devices["SW1"].sys_descr = CLASSIC
    request = Request("SW1", [Source("Gi1/0/5")], to=TO_ADDRESS, dest_ip="10.0.10.9", to_this_pc=True,
                      vrf="Mgmt-vrf")
    result = plan(network_map, request, states())
    assert result.ok and result.kind == ERSPAN and len(result.steps) == 1
    assert "   vrf Mgmt-vrf" in result.steps[0].lines
    warnings = [finding.text for finding in result.findings if finding.severity == WARNING]
    assert any("classic IOS" in text for text in warnings)
    assert plan(network_map, Request("SW1", [Source("Gi1/0/5")], to=TO_ADDRESS, dest_ip="", kind=ERSPAN)).ok is False
    span = Request("SW1", [Source("Gi1/0/5")], to=TO_ADDRESS, dest_ip="10.0.10.9", kind=SPAN)
    assert any("ERSPAN only" in text for text in errors(plan(network_map, span, states())))


# --------------------------------------------------------------------- Safety

def test_destination_never_a_link_trunk_or_busy_port():
    network_map = campus()
    to_link = Request("SW2", [Source("Gi1/0/24")], dest_device="SW2", dest_port="Gi1/0/48")
    found = errors(plan(network_map, to_link, states()))
    assert any("goes to SW1" in text for text in found) and any("trunk" in text for text in found)
    busy = SwitchState(read=True, sessions={1: mirror.MonitorSession(1, "Local Session", destinations=["Gi1/0/3"])})
    in_use = Request("SW1", [Source("Gi1/0/1")], dest_device="SW1", dest_port="Gi1/0/3")
    assert any("in session 1 already" in text for text in errors(plan(network_map, in_use, states(SW1=busy))))
    same = Request("SW1", [Source("Gi1/0/3")], dest_device="SW1", dest_port="Gi1/0/3")
    assert any("both mirrored and the destination" in text for text in errors(plan(network_map, same, states())))
    mixed = Request("SW1", [Source("Gi1/0/1"), Source(vlan=10)], dest_device="SW1", dest_port="Gi1/0/3")
    assert any("ports or VLANs, not both" in text for text in errors(plan(network_map, mixed, states())))


def test_hosts_on_the_destination_and_oversubscription_are_warned():
    network_map = campus()
    network_map.devices["SW1"].port_status["Gi1/0/5"] = {"oper": "up", "speed": 100}
    request = Request("SW1", [Source("Gi1/0/1"), Source("Gi1/0/2")], dest_device="SW1", dest_port="Gi1/0/5")
    warnings = [finding.text for finding in plan(network_map, request, states()).findings
                if finding.severity == WARNING]
    assert any("printer" in text and "lose the network" in text for text in warnings)
    assert any("4000 Mb/s" in text and "100 Mb/s" in text for text in warnings)


def test_own_port_needs_remove_after():
    request = Request("SW2", [Source("Gi1/0/24")], dest_device="SW2", dest_port="Gi1/0/9", to_this_pc=True,
                      own_port=True)
    result = plan(campus(), request, states())
    assert any("needs Remove after" in text for text in errors(result))
    request.remove_after = 30
    result = plan(campus(), request, states(), applet_tag="ABC123")
    assert result.ok


def test_unread_sessions_need_a_number_chosen():
    request = Request("SW1", [Source("Gi1/0/1")], dest_device="SW1", dest_port="Gi1/0/3")
    unread = {"SW1": SwitchState(problem="no saved SSH session or login to log in with.")}
    assert any("couldn't be read" in text and "no saved SSH" in text for text in errors(plan(campus(), request, unread)))
    request.session = 4
    result = plan(campus(), request, unread)
    assert result.ok and result.steps[0].session == 4
    assert any("weren't read" in finding.text for finding in result.findings)
    assert not plan(campus(), request, {"SW1": read(4)}).ok


# --------------------------------------------------------------------- Taking it away by itself

def test_applet_takes_the_step_away_and_itself():
    request = Request("SW1", [Source("Gi1/0/5")], dest_device="SW2", dest_port="Gi1/0/24", remove_after=90,
                      name="printer")
    result = plan(campus(), request, states(), applet_tag="ABC123")
    source = result.step_for("SW1")
    assert source.applet_name == "NOMAD-MIRROR-ABC123"
    applet = source.applet
    assert applet[0] == "event manager applet NOMAD-MIRROR-ABC123"
    assert applet[1] == " event timer countdown time 5400"
    assert ' action 003 cli command "no monitor session 1"' in applet
    assert any('"no vlan 999"' in line for line in applet)
    assert applet[-2] .endswith('cli command "no event manager applet NOMAD-MIRROR-ABC123"')
    labels = [line.split()[1] for line in applet if line.startswith(" action")]
    assert labels == sorted(labels)  # EEM runs actions in label order (as text)
    assert mirror.undo_text(source).splitlines()[1] == "no event manager applet NOMAD-MIRROR-ABC123"
    assert "event manager applet" in mirror.config_text(source)
    assert "event manager applet" not in mirror.config_text(source, applet=False)
    assert "1 hour" not in mirror.minutes_text(90) and mirror.minutes_text(120) == "2 hours"


# --------------------------------------------------------------------- The switches' own sessions

SHOW_MONITOR = """Session 1
---------
Type                   : Local Session
Source Ports           :
    Both               : Gi1/0/1-3,Gi1/0/5
Destination Ports      : Gi1/0/24
    Encapsulation      : Native
          Ingress      : Disabled

Session 2
---------
Type                   : Remote Source Session
Source VLANs           :
    RX Only            : 10
Dest RSPAN VLAN        : 999

Session 3
---------
Type                     : ERSPAN Source Session
Status                   : Admin Enabled
Source Ports             :
    Both                 : Gi1/0/7
Destination IP Address   : 10.1.1.50
Destination ERSPAN ID    : 12
Origin IP Address        : 10.0.0.1
"""


def test_show_monitor_is_read():
    sessions = mirror.parse_sessions(SHOW_MONITOR)
    assert sorted(sessions) == [1, 2, 3]
    local, remote, erspan = sessions[1], sessions[2], sessions[3]
    assert local.kind == SPAN and local.source_ports == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/5"]
    assert local.destinations == ["Gi1/0/24"]
    assert remote.kind == RSPAN and remote.rspan_vlan == 999 and remote.sources == ["Rx Only: VLAN 10"]
    assert erspan.kind == ERSPAN and erspan.erspan_id == 12 and erspan.dest_ip == "10.1.1.50"
    assert erspan.origin_ip == "10.0.0.1" and erspan.status == "Admin Enabled"
    state = SwitchState(read=True, sessions=sessions)
    assert state.free_session() == 4 and state.session_using("GigabitEthernet1/0/2").number == 1
    assert mirror.parse_sessions("No SPAN configuration is present in the system.") == {}
    assert mirror.parse_applets("event manager applet NOMAD-MIRROR-ABC123\nevent manager applet BACKUP") == \
        ["NOMAD-MIRROR-ABC123"]
    # show running-config | include event manager applet also lists the applet's own last action (seen on IOL)
    listing = 'event manager applet NOMAD-MIRROR-LAB001\n action 007 cli command "no event manager applet ' \
              'NOMAD-MIRROR-LAB001"'
    assert mirror.parse_applets(listing) == ["NOMAD-MIRROR-LAB001"]
    assert mirror.free_erspan_id({"SW1": state}) == 1


def test_check_step():
    step = mirror.Step("SW1", mirror.SOURCE, session=3)
    state = SwitchState(read=True, sessions=mirror.parse_sessions(SHOW_MONITOR))
    assert mirror.check_step(step, ERSPAN, state, erspan_id=12) == []
    assert "ERSPAN ID 12, not 5" in mirror.check_step(step, ERSPAN, state, erspan_id=5)[0]
    assert mirror.check_step(mirror.Step("SW1", mirror.SOURCE, session=9), SPAN, state) == ["Session 9 isn't there."]


# --------------------------------------------------------------------- The record

def test_records_are_kept(tmp_path):
    request = Request("SW1", [Source("Gi1/0/5")], dest_device="SW2", dest_port="Gi1/0/24", remove_after=30,
                      name="printer")
    result = plan(campus(), request, states(), applet_tag="ABC123")
    record = mirror.record_from(campus(), result, "ABC123", "Campus")
    assert record.kind == RSPAN and record.expires and not record.expired
    assert [step.label for step in record.steps] == ["SW2", "SW1"]
    assert record.steps[1].names == ["SW1"] and record.steps[1].address == "10.0.0.1"
    store = MirrorStore(tmp_path / "mirrors.json")
    store.put(record)
    for step in record.steps:
        step.state = mirror.STEP_SET
    record.update_state()
    store.put(record)
    again = MirrorStore(tmp_path / "mirrors.json")
    again.load()
    loaded = again.get("ABC123")
    assert loaded.state == mirror.ACTIVE and loaded.what == "SW1 Gi1/0/5 (both ways) to SW2 Gi1/0/24"
    assert loaded.steps[0].undo.startswith("configure terminal\nno event manager applet NOMAD-MIRROR-ABC123")
    loaded.steps[0].state = mirror.STEP_REMOVED
    assert loaded.update_state() == mirror.PARTIAL
    loaded.steps[1].state = mirror.STEP_REMOVED
    assert loaded.update_state() == mirror.REMOVED
    loaded.nomad_timer, loaded.expires, loaded.state = True, "2000-01-01T00:00:00", mirror.ACTIVE
    assert again.overdue() == [loaded]


# --------------------------------------------------------------------- Sending over SSH

class ConfigChannel:
    """A switch's command line that goes to enable and configure: refuses lines in refuse."""

    def __init__(self, start="sw1>", secret="enable", refuse=()):
        self.mode, self.secret, self.refuse = start, secret, set(refuse)
        self.out = ["\r\n" + self.prompt()]
        self.closed = False
        self.sent = []
        self.asking = False

    def prompt(self):
        return {"sw1>": "sw1>", "sw1#": "sw1#", "config": "sw1(config)#", "sub": "sw1(config-mon-erspan-src)#"}[
            self.mode]

    def recv_ready(self):
        return bool(self.out)

    def recv(self, size):
        return self.out.pop(0).encode()

    def exit_status_ready(self):
        return False

    def send(self, text):
        self.sent.append(text)
        line = text.rstrip("\n")
        if self.asking:
            self.asking = False
            if line == self.secret:
                self.mode = "sw1#"
                self.out.append("\r\n" + self.prompt())
            else:
                self.out.append("\r\n% Bad secrets\r\n\r\n" + self.prompt())
            return
        word = line.strip()
        reply = ""
        if word == "enable":
            self.asking = True
            self.out.append("enable\r\nPassword: ")
            return
        if word in self.refuse:
            reply = "                   ^\r\n% Invalid input detected at '^' marker.\r\n"
        elif word.startswith("configure"):
            self.mode = "config"
            reply = "Enter configuration commands, one per line.  End with CNTL/Z.\r\n"
        elif word == "end":
            self.mode = "sw1#"
        elif word.startswith("monitor session") and "type erspan" in word:
            self.mode = "sub"
        elif word == "exit" and self.mode == "sub" and not line.startswith("  "):
            self.mode = "config"
        elif word.startswith("show monitor"):
            reply = SHOW_MONITOR.replace("\n", "\r\n")
        elif word.startswith("show running"):
            reply = "event manager applet NOMAD-MIRROR-OLD\r\n"
        self.out.append(line + "\r\n" + reply + self.prompt())


def config_shell(channel, monkeypatch, secret="enable"):
    from nomad.netmap import macssh
    from nomad.terminal.sessions import Session
    monkeypatch.setattr(macssh, "QUIET", 0)
    shell = configpush.ConfigShell(Session("sw1", host="10.0.0.1"), enable_secret=secret)
    shell.channel = channel
    shell.prompt = shell.read(5).rstrip().splitlines()[-1].strip()
    return shell


def test_enable_then_configure(monkeypatch):
    channel = ConfigChannel()
    shell = config_shell(channel, monkeypatch)
    shell.enable()
    assert shell.prompt == "sw1#"
    transcript, refused = shell.configure("configure terminal\nmonitor session 1 source interface Gi1/0/1 both\n"
                                          "monitor session 1 destination interface Gi1/0/3\nend")
    assert refused == [] and channel.mode == "sw1#"
    assert "monitor session 1 destination interface Gi1/0/3" in transcript
    state_text = shell.run("show monitor session all")
    assert sorted(mirror.parse_sessions(state_text)) == [1, 2, 3]


def test_a_refused_line_stops_and_leaves_config_mode(monkeypatch):
    channel = ConfigChannel(start="sw1#", refuse={"monitor session 1 type erspan-source"})
    shell = config_shell(channel, monkeypatch)
    transcript, refused = shell.configure("configure terminal\nmonitor session 1 type erspan-source\n"
                                          " source interface Gi1/0/1 both\nend")
    assert refused[0][0] == "monitor session 1 type erspan-source" and "Invalid input" in refused[0][1][0]
    assert channel.mode == "sw1#"  # end was sent
    assert not any("source interface" in text for text in channel.sent)


def test_wrong_enable_secret(monkeypatch):
    import pytest
    from nomad.terminal.transports import ConnectionFailed
    shell = config_shell(ConfigChannel(), monkeypatch, secret="wrong")
    with pytest.raises(ConnectionFailed, match="refused the enable password|didn't give"):
        shell.enable()
    shell = config_shell(ConfigChannel(), monkeypatch, secret="")
    with pytest.raises(ConnectionFailed, match="Enable password"):
        shell.enable()


class FakePushShell:
    """A ConfigShell on a ConfigChannel, for Pusher."""
    channels = {}

    def __init__(self, session, vault=None, known_hosts=None, trust_new=False, password=None,
                 should_stop=lambda: False, enable_secret=""):
        self.inner = configpush.ConfigShell(session, enable_secret=enable_secret)
        self.inner.channel = self.channels[session.host]

    def open(self):
        channel = self.inner.channel
        if not channel.out:  # Logged in again: a new prompt
            channel.out.append("\r\n" + channel.prompt())
        self.inner.prompt = self.inner.read(5).rstrip().splitlines()[-1].strip()
        if self.inner.prompt.endswith(">"):
            self.inner.enable()

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def close(self):
        pass


def pusher(monkeypatch, channels):
    from nomad.netmap import macssh
    from nomad.terminal.sessions import Session
    monkeypatch.setattr(macssh, "QUIET", 0)
    FakePushShell.channels = channels
    logins = macssh.SshLogins(fallback=Session("", username="admin"), password="pw")
    return configpush.Pusher(logins, enable_secret="enable", shell_factory=FakePushShell)


def test_pusher_reads_sets_up_and_takes_away(monkeypatch):
    channel = ConfigChannel(refuse={"event manager applet NOMAD-MIRROR-X"})
    push = pusher(monkeypatch, {"10.0.0.1": channel})
    state = push.read_state("10.0.0.1")
    assert state.read and sorted(state.sessions) == [1, 2, 3] and state.applets == ["NOMAD-MIRROR-OLD"]
    step = mirror.Step("SW1", mirror.SOURCE, 4, ["monitor session 4 source interface Gi1/0/1 both"],
                       ["no monitor session 4"], [" event timer countdown time 60"], "NOMAD-MIRROR-X")
    step.applet = ["event manager applet NOMAD-MIRROR-X", " event timer countdown time 60"]
    outcome = push.set_up("10.0.0.1", mirror.config_text(step, applet=False),
                          "configure terminal\n" + "\n".join(step.applet) + "\nend")
    assert outcome.ok and outcome.applet_ok is False  # The applet refused: NOMAD's timer instead
    assert any("no event manager applet NOMAD-MIRROR-X" in text for text in channel.sent)  # Cleaned away
    channel.refuse = {"no event manager applet NOMAD-MIRROR-X"}
    taken = push.take_away("10.0.0.1", mirror.undo_text(step))
    assert taken.ok  # The applet being gone isn't a failure
    channel.refuse = {"no monitor session 4"}
    taken = push.take_away("10.0.0.1", mirror.undo_text(step))
    assert not taken.ok and "no monitor session 4" in taken.problem
    push.close()


def test_pusher_without_a_login():
    from nomad.netmap import macssh
    push = configpush.Pusher(macssh.SshLogins())
    outcome = push.set_up("10.0.0.1", "configure terminal\nend")
    assert not outcome.ok and "Couldn't log in" in outcome.problem
    assert not push.read_state("10.0.0.1").read


def test_ios_xe_is_told_from_its_description():
    from nomad.netmap.model import Device
    assert mirror.is_ios_xe(Device("a", sys_descr=XE))
    assert mirror.is_ios_xe(Device("a", sys_descr="Cisco IOS Software [Everest], Catalyst L3 Switch Software "
                                                  "(CAT3K_CAA-UNIVERSALK9-M), Version 16.6.4, RELEASE SOFTWARE"))
    assert mirror.is_ios_xe(Device("a", sys_descr="Cisco IOS Software [Cupertino], Catalyst L3 Switch Software "
                                                  "(CAT9K_IOSXE), Version 17.9.4"))
    assert mirror.is_ios_xe(Device("a", sys_descr=CLASSIC)) is False
    assert mirror.is_ios_xe(Device("a")) is None


def test_an_access_points_port_is_never_a_destination():
    from nomad.netmap.model import AP
    network_map = campus()
    network_map.devices["AP1"] = MapDevice("AP1", "AP1", kind=AP)
    network_map.links.append(Link("SW1", "Gi1/0/7", "AP1", "Gi0"))
    request = Request("SW1", [Source("Gi1/0/1")], dest_device="SW1", dest_port="Gi1/0/7")
    assert any("cut AP1 off" in text for text in errors(plan(network_map, request, states())))
    assert mirror.shared_port(network_map, "SW1", "Gi1/0/7") and not mirror.shared_port(network_map, "SW1", "Gi1/0/5")
