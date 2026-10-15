"""Tunnels on the map: TUNNEL-MIB and the IKE sessions read over SNMP (as IOS XE 17.4 answers them), and the tunnels
drawn between the map's devices from them."""
from nomad.netmap import collect, overlays, tunnels
from nomad.netmap.model import Device, NetworkMap, ROUTER, SNMP
from nomad.snmp import INTEGER, OCTET_STRING, Value, parse_oid


def row(oid, tag, value):
    return parse_oid(oid), Value(tag, value)


def test_tunnel_mib_as_ios_xe_answers_it():
    entry = collect.TUNNEL_IF_ENTRY
    rows = [row(f"{entry}.5.17", INTEGER, 2), row(f"{entry}.5.18", INTEGER, 2),
            row(f"{entry}.9.17", OCTET_STRING, bytes([8, 0, 0, 22])),
            row(f"{entry}.9.18", OCTET_STRING, bytes([8, 0, 0, 22])),
            row(f"{entry}.10.17", OCTET_STRING, bytes([8, 0, 0, 26])),
            row(f"{entry}.10.18", OCTET_STRING, b"")]  # A multipoint tunnel names no far end
    assert collect.tunnels(rows) == {17: ("8.0.0.22", "8.0.0.26", True), 18: ("8.0.0.22", "", True)}


def test_tunnel_mib_old_columns():
    entry = collect.TUNNEL_IF_ENTRY
    rows = [row(f"{entry}.1.5", 0x40, "10.0.0.1"), row(f"{entry}.2.5", 0x40, "10.0.0.2"),
            row(f"{entry}.5.5", INTEGER, 1)]
    assert collect.tunnels(rows) == {5: ("10.0.0.1", "10.0.0.2", False)}


def test_ike_sessions_up_only():
    entry = collect.IKE_TUNNEL_ENTRY
    rows = [row(f"{entry}.4.49", OCTET_STRING, bytes([8, 0, 0, 18])),
            row(f"{entry}.4.50", OCTET_STRING, bytes([8, 0, 0, 18])),
            row(f"{entry}.8.49", OCTET_STRING, bytes([8, 0, 0, 22])),
            row(f"{entry}.8.50", OCTET_STRING, bytes([8, 0, 0, 26])),
            row(f"{entry}.35.49", INTEGER, 1), row(f"{entry}.35.50", INTEGER, 2)]  # 2: being torn down
    assert collect.ike_sessions(rows) == [("8.0.0.18", "8.0.0.22")]


def router(key, wan, tunnels_read, sessions=(), status=None, ike_read=True):
    device = Device(key, key, mgmt_ip=wan, addresses=[wan], kind=ROUTER, source=SNMP)
    device.tunnels = {port: {"local": local, "remote": remote, "ipsec": True}
                      for port, (local, remote) in tunnels_read.items()}
    device.ike_sessions = [list(item) for item in sessions]
    device.ike_read = ike_read
    device.port_status = status if status is not None else {port: {"oper": "up"} for port in tunnels_read}
    return device


CLOUD_IPS = {"r5": "172.31.251.1", "r6": "172.31.251.2", "r7": "172.31.251.3"}


def lab(r7_tu10="up"):
    """The lab as crawled: a VTI R6-R7 (Tu10) and a DMVPN cloud, R5 hub and R6/R7 spokes (Tu100)."""
    network_map = NetworkMap()
    r7_status = {"Tu100": {"oper": "up"}}
    if r7_tu10 == "up":
        r7_status["Tu10"] = {"oper": "up"}
    network_map.devices = {
        "r5": router("r5", "8.0.0.18", {"Tu100": ("8.0.0.18", "")},
                     [("8.0.0.18", "8.0.0.22"), ("8.0.0.18", "8.0.0.26")]),
        "r6": router("r6", "8.0.0.22", {"Tu10": ("8.0.0.22", "8.0.0.26"), "Tu100": ("8.0.0.22", "")},
                     [("8.0.0.22", "8.0.0.18")] + ([("8.0.0.22", "8.0.0.26")] if r7_tu10 == "up" else []),
                     {"Tu10": {"oper": r7_tu10}, "Tu100": {"oper": "up"}}),
        "r7": router("r7", "8.0.0.26", {"Tu10": ("8.0.0.26", "8.0.0.22"), "Tu100": ("8.0.0.26", "")},
                     [("8.0.0.26", "8.0.0.18")] + ([("8.0.0.26", "8.0.0.22")] if r7_tu10 == "up" else []),
                     r7_status),
    }
    for key, address in CLOUD_IPS.items():  # The cloud's tunnel subnet, as ipAddrTable gives it
        network_map.devices[key].interfaces_l3.append([address, 24, "Tu100"])
    return network_map


def found(network_map):
    return {(tunnel.a, tunnel.a_port, tunnel.b, tunnel.b_port, tunnel.multipoint, tunnel.state)
            for tunnel in tunnels.find(network_map)}


def test_vti_and_dmvpn_found_once_each():
    assert found(lab()) == {("r5", "Tu100", "r6", "Tu100", True, tunnels.UP),
                            ("r5", "Tu100", "r7", "Tu100", True, tunnels.UP),
                            ("r6", "Tu10", "r7", "Tu10", False, tunnels.UP)}  # The VTI's session isn't a shortcut


def test_a_tunnel_shut_at_one_end_is_down():
    states = {(tunnel.a, tunnel.b, tunnel.multipoint): tunnel.state for tunnel in tunnels.find(lab("down"))}
    assert states[("r6", "r7", False)] == tunnels.DOWN
    assert states[("r5", "r6", True)] == tunnels.UP


def test_a_spoke_to_spoke_shortcut():
    network_map = lab()
    for key in ("r6", "r7"):  # No VTI: their session is the DMVPN shortcut
        network_map.devices[key].tunnels.pop("Tu10")
        network_map.devices[key].port_status.pop("Tu10")
    assert ("r6", "Tu100", "r7", "Tu100", True, tunnels.UP) in found(network_map)


def hub_states(network_map):
    return {tunnel.b if tunnel.a == "r5" else tunnel.a: tunnel.state
            for tunnel in tunnels.find(network_map) if "r5" in (tunnel.a, tunnel.b) and tunnel.multipoint}


def test_a_spoke_with_no_session_to_its_hub():
    network_map = lab()
    network_map.devices["r8"] = router("r8", "8.0.0.30", {"Tu100": ("8.0.0.30", "")}, [("8.0.0.30", "8.0.0.18")])
    network_map.devices["r8"].interfaces_l3.append(["172.31.251.4", 24, "Tunnel100"])  # (Long name: the same port)
    network_map.devices["r6"].ike_sessions = [["8.0.0.22", "8.0.0.26"]]  # None with the hub
    network_map.devices["r5"].ike_sessions = [["8.0.0.18", "8.0.0.26"], ["8.0.0.18", "8.0.0.30"]]
    network_map.devices["r5"].interfaces_l3.append(["10.9.9.1", 24, "Gi3"])  # Not a tunnel: not in the cloud
    assert hub_states(network_map) == {"r6": tunnels.NEGOTIATING, "r7": tunnels.UP, "r8": tunnels.UP}
    network_map.devices["r6"].port_status["Tu100"] = {"oper": "down"}
    assert hub_states(network_map)["r6"] == tunnels.DOWN
    network_map.devices["r5"].ike_read = False  # Who the hub has sessions with isn't known
    assert hub_states(network_map) == {"r7": tunnels.UP, "r8": tunnels.UP}


def test_no_guess_when_the_hub_cant_be_told():
    network_map = lab()  # The hub has one session left, and so has the spoke still up: either could be the hub
    network_map.devices["r6"].ike_sessions = [["8.0.0.22", "8.0.0.26"]]
    network_map.devices["r5"].ike_sessions = [["8.0.0.18", "8.0.0.26"]]
    assert hub_states(network_map) == {"r7": tunnels.UP}


def test_a_phase_1_spoke_names_its_hub():
    network_map = lab()
    network_map.devices["r6"].tunnels["Tu100"]["remote"] = "8.0.0.18"
    network_map.devices["r6"].ike_sessions = []
    network_map.devices["r5"].ike_sessions = [["8.0.0.18", "8.0.0.26"]]
    assert hub_states(network_map)["r6"] == tunnels.NEGOTIATING
    assert len([tunnel for tunnel in tunnels.find(network_map) if {tunnel.a, tunnel.b} == {"r5", "r6"}]) == 1


def test_two_routers_in_a_cloud_with_no_session():
    network_map = lab()
    del network_map.devices["r7"]
    network_map.devices["r6"].tunnels.pop("Tu10")
    for key in ("r5", "r6"):
        network_map.devices[key].ike_sessions = []
    assert hub_states(network_map) == {"r6": tunnels.NEGOTIATING}


def test_far_end_not_read_and_not_on_the_map():
    network_map = lab()
    del network_map.devices["r7"]
    network_map.devices["far"] = Device("far", "far", mgmt_ip="8.0.0.26", addresses=["8.0.0.26"])  # A neighbor
    tunnel = next(tunnel for tunnel in tunnels.find(network_map) if not tunnel.multipoint)
    assert (tunnel.a, tunnel.b, tunnel.b_port, tunnel.state) == ("r6", "far", "", tunnels.UP)
    del network_map.devices["far"]
    assert not [tunnel for tunnel in tunnels.find(network_map) if not tunnel.multipoint]


def test_unknown_without_ike_or_status():
    network_map = lab()
    for device in network_map.devices.values():
        device.ike_read, device.ike_sessions, device.port_status = False, [], {}
    assert {tunnel.state for tunnel in tunnels.find(network_map)} == {tunnels.UNKNOWN}


def test_saved_and_loaded_with_the_map():
    network_map = lab()
    again = NetworkMap.from_json(network_map.to_json())
    assert found(again) == found(network_map)


def test_overlay_from_the_map_tunnels():
    network_map = lab("down")
    overlay = overlays.build(network_map, overlays.VPNS, tunnels.lines(network_map))
    assert len(overlay.extra_lines) == 3 and overlay.summary == ["3 tunnels", "1 down"]
    assert overlay.devices["r6"].color == "error"


# --------------------------------------------------------------------- Read by the crawl, and again while monitoring

def fake_router(network, name, wan, tunnel_rows, sessions):
    """A router answering SNMP as the lab's C8000Vs do: tunnel_rows [(ifIndex, name, local, remote, tunnel IP)]."""
    from netmap_fakes import CISCO_ROUTER, Device as FakeDevice
    device = network.add(wan, FakeDevice(name, "Cisco IOS XE Software, Version 17.04.02", CISCO_ROUTER))
    device.interface(1, "GigabitEthernet1")
    device.address(wan, 1)
    for index in [1] + [row[0] for row in tunnel_rows]:
        device.set(collect.IF_ADMIN_STATUS, index, Value(INTEGER, 1))
        device.set(collect.IF_OPER_STATUS, index, Value(INTEGER, 1))
    for index, port, local, remote, address in tunnel_rows:
        device.interface(index, port)
        device.address(address, index)
        device.set(collect.TUNNEL_IF_ENTRY, 5, index, Value(INTEGER, 2))
        device.set(collect.TUNNEL_IF_ENTRY, 9, index, Value(OCTET_STRING, ip_bytes(local)))
        device.set(collect.TUNNEL_IF_ENTRY, 10, index, Value(OCTET_STRING, ip_bytes(remote) if remote else b""))
    set_sessions(device, sessions)
    return device


def ip_bytes(address):
    return bytes(int(part) for part in address.split("."))


def set_sessions(device, sessions):
    """Its IKE sessions up, as CISCO-IPSEC-FLOW-MONITOR-MIB gives them (any before taken away)."""
    entry = parse_oid(collect.IKE_TUNNEL_ENTRY)
    for oid in [oid for oid in device.mib if oid[:len(entry)] == entry]:
        del device.mib[oid]
    device.set(collect.IKE_ACTIVE_COUNT, 0, Value(INTEGER, len(sessions)))
    for number, (local, remote) in enumerate(sessions, start=49):
        device.set(collect.IKE_TUNNEL_ENTRY, 4, number, Value(OCTET_STRING, ip_bytes(local)))
        device.set(collect.IKE_TUNNEL_ENTRY, 8, number, Value(OCTET_STRING, ip_bytes(remote)))
        device.set(collect.IKE_TUNNEL_ENTRY, collect.IKE_STATUS, number, Value(INTEGER, 1))


def fake_lab():
    """The lab: a VTI R6-R7 (Tunnel10) and a DMVPN cloud with R5 the hub (Tunnel100); private WANs (the scope)."""
    from netmap_fakes import FakeNetwork
    network = FakeNetwork()
    fake_router(network, "R5", "10.8.0.18", [(14, "Tunnel100", "10.8.0.18", "", "172.31.251.1")],
                [("10.8.0.18", "10.8.0.22"), ("10.8.0.18", "10.8.0.26")])
    fake_router(network, "R6", "10.8.0.22", [(17, "Tunnel10", "10.8.0.22", "10.8.0.26", "172.31.250.1"),
                                            (18, "Tunnel100", "10.8.0.22", "", "172.31.251.2")],
                [("10.8.0.22", "10.8.0.18"), ("10.8.0.22", "10.8.0.26")])
    fake_router(network, "R7", "10.8.0.26", [(17, "Tunnel10", "10.8.0.26", "10.8.0.22", "172.31.250.2"),
                                            (18, "Tunnel100", "10.8.0.26", "", "172.31.251.3")],
                [("10.8.0.26", "10.8.0.18"), ("10.8.0.26", "10.8.0.22")])
    return network


def crawl_lab(network):
    from nomad.netmap.crawl import CrawlSettings, Crawler
    return Crawler(CrawlSettings(seeds=["10.8.0.18", "10.8.0.22", "10.8.0.26"], trace=False, collect_hosts=False),
                   client_factory=network.client, pinger=network.ping).run()


def test_the_crawl_reads_the_tunnels():
    network_map = crawl_lab(fake_lab())
    r6 = network_map.devices["r6"]
    assert r6.tunnels == {"Tunnel10": {"local": "10.8.0.22", "remote": "10.8.0.26", "ipsec": True},
                          "Tunnel100": {"local": "10.8.0.22", "remote": "", "ipsec": True}}
    assert r6.ike_read and r6.ike_sessions == [["10.8.0.22", "10.8.0.18"], ["10.8.0.22", "10.8.0.26"]]
    assert {(tunnel.a, tunnel.b, tunnel.state) for tunnel in tunnels.find(network_map)} == {
        ("r5", "r6", tunnels.UP), ("r5", "r7", tunnels.UP), ("r6", "r7", tunnels.UP)}


def test_monitoring_reads_them_again():
    from nomad.netmap import counters
    network = fake_lab()
    network_map = crawl_lab(network)
    targets = [(key, network_map.devices[key].mgmt_ip, "public", 2, 1000, ports)
               for key, ports in tunnels.tunnel_routers(network_map).items()]
    r7 = network.devices["10.8.0.26"]
    r7.set(collect.IF_OPER_STATUS, 17, Value(INTEGER, 2))  # Its VTI went down
    set_sessions(r7, [("10.8.0.26", "10.8.0.18")])
    found = tunnels.poll(targets, {}, network.client, counters.interface_index)
    live = {key: reading for key, (_, reading) in found.items()}
    assert live["r7"] == {"status": {"Tunnel10": "down", "Tunnel100": "up"}, "ike": [["10.8.0.26", "10.8.0.18"]]}
    before = tunnels.by_ends(tunnels.find(network_map))
    after = tunnels.by_ends(tunnels.find(network_map, live))
    said = tunnels.changes(network_map, before, after)
    assert said == ["Tunnel R6 Tunnel10 to R7 Tunnel10: point-to-point over IPsec, down"]
    assert network_map.devices["r7"].port_status["Tunnel10"]["oper"] == "up"  # The map itself left as crawled
