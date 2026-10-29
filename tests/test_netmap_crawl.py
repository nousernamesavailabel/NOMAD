import re
import threading

import pytest

from netmap_fakes import (ACC1_MAC, CORE_MAC, FW_MAC, LAB_MACS, PC1_MAC, PHONE_MAC, PRINTER_MAC, FakeAgentClient,
                          build_network)

from nomad.netmap.crawl import NO_ANSWER, PINGS_NO_SNMP, CrawlSettings, Crawler
from nomad.netmap.model import FIREWALL, NEIGHBOR, NO_SNMP, ROUTER, SNMP, SWITCH, UNREACHABLE


def crawl(network, **options):
    settings = CrawlSettings(seeds=options.pop("seeds", ["10.0.0.1"]),
                             overrides=options.pop("overrides", [("10.0.0.12/32", "secret")]), **options)
    return Crawler(settings, client_factory=network.client, pinger=network.ping,
                   echo=network.echo).run()


def test_crawl_finds_every_device_and_link():
    network_map = crawl(build_network())
    devices = network_map.devices
    assert set(devices) == {"core", "acc1", "acc2", "rtr1", "pa-fw1"}
    assert {key: devices[key].source for key in devices} == {
        "core": SNMP, "acc1": SNMP, "acc2": SNMP, "rtr1": NO_SNMP, "pa-fw1": SNMP}
    assert devices["core"].kind == SWITCH
    assert devices["rtr1"].kind == ROUTER
    assert devices["pa-fw1"].kind == FIREWALL
    assert devices["acc2"].hops == 1
    links = {(link.a, link.a_port, link.b, link.b_port, tuple(link.protocols)) for link in network_map.links}
    assert links == {
        ("core", "Te1/0/1", "acc1", "Te1/1/1", ("cdp",)),
        ("core", "Te1/0/2", "acc2", "Eth1/49", ("cdp",)),
        ("core", "Gi1/0/48", "rtr1", "Gi0/0/0", ("cdp",)),
        ("core", "Te1/0/3", "pa-fw1", "Eth1/1", ("lldp",)),
    }
    assert "10.10.0.1" in devices["core"].addresses


def test_windows_lldp_neighbor_is_a_host_not_a_device():
    """A Windows PC's LLDP agent announces no capabilities and its MAC as the port ID: it goes on its port as a
    named host, not on the map as a device."""
    network = build_network()
    acc1 = network.devices["10.0.0.11"]
    acc1.interface(15, "GigabitEthernet1/0/15", ACC1_MAC)
    acc1.lldp(15, "Gi1/0/15", 1, "WAAAAANB3704Q2", "", capabilities=0, port_mac="64-4E-D7-1E-E9-8A")
    acc1.learned("64-4E-D7-1E-E9-8A", 15, 15, vlan=10)
    network_map = crawl(network)
    assert "WAAAAANB3704Q2" not in network_map.devices
    assert not any(device.name == "WAAAAANB3704Q2" for device in network_map.devices.values())
    hosts = {host.mac: host for host in network_map.hosts}
    host = hosts["64-4E-D7-1E-E9-8A"]
    assert (host.device, host.port, host.name) == ("acc1", "Gi1/0/15", "WAAAAANB3704Q2")
    assert [h for h in network_map.hosts if h.name == "WAAAAANB3704Q2"] == [host]  # Placed once


def test_hosts_on_edge_ports_only():
    network_map = crawl(build_network())
    hosts = {host.mac: host for host in network_map.hosts}
    assert hosts[PC1_MAC].device == "acc1" and hosts[PC1_MAC].port == "Gi1/0/5"  # Not the core's uplink
    assert hosts[PC1_MAC].ip == "10.10.0.21" and hosts[PC1_MAC].vlan == 10
    assert hosts[PHONE_MAC].name == "SEP00AABBCCDDEE" and hosts[PHONE_MAC].port == "Gi1/0/5"
    assert hosts[PRINTER_MAC].port == "Gi1/0/7"
    assert all(hosts[mac].port == "Eth1/10" for mac in LAB_MACS)
    assert {hosts[mac].vlan for mac in LAB_MACS} == {30, 31}  # From the NX-OS switch's Q-BRIDGE table
    for mac in (CORE_MAC, ACC1_MAC, FW_MAC):  # Network devices' own MACs, and anything on an uplink
        assert mac not in hosts
    assert "SEP00AABBCCDDEE" not in network_map.devices  # Phones are hosts, not map devices


def test_per_vlan_community_used_on_catalyst_only():
    network = build_network()
    crawl(network)
    communities = {community for host, community in network.requests}
    assert {"public@10", "public@1"} <= communities
    acc1 = {community for host, community in network.requests if host == "10.0.0.11"}
    assert not acc1 & {"public@20", "public@30", "public@40"}  # VLANs none of its ports use
    assert not any(community.startswith("secret@") for community in communities)  # acc2 is NX-OS


def test_override_community_tried_first_and_default_for_the_rest():
    network = build_network()
    crawl(network)
    acc2_communities = [community for host, community in network.requests if host == "10.0.0.12"]
    assert acc2_communities[0] == "secret"
    assert "public" not in acc2_communities


def test_scope_and_hops_limit_the_crawl():
    network_map = crawl(build_network(), scope=["10.0.0.0/30"])  # Only the core itself
    assert network_map.devices["core"].source == SNMP
    assert all(device.source != SNMP for key, device in network_map.devices.items() if key != "core")
    assert len(network_map.links) == 4  # Neighbors still shown

    network_map = crawl(build_network(), max_hops=0)
    assert [key for key, device in network_map.devices.items() if device.source == SNMP] == ["core"]


def test_unreachable_seed():
    network = build_network()
    network_map = crawl(network, seeds=["10.9.9.9"])
    assert list(network_map.devices) == ["ip:10.9.9.9"]
    assert network_map.devices["ip:10.9.9.9"].source == UNREACHABLE


@pytest.mark.parametrize("answers", [(), ("10.0.0.5",), ("10.0.0.6",)])
def test_crawl_pings_every_lldp_address_before_marking_device_unreachable(answers):
    network = build_network()
    del network.devices["10.0.0.5"]  # Neither management address answers SNMP
    network.pingable.discard("10.0.0.5")
    network.pingable.update(answers)
    network.devices["10.0.0.1"].lldp(3, "TenGigabitEthernet1/0/3", 1, "pa-fw1", "ethernet1/1",
                                      "10.0.0.6", "00-1B-17-00-00-05", 0x08, "Palo Alto PA-3220")
    pinged = []

    def ping(address):
        pinged.append(address)
        return network.ping(address)

    crawler = Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False), client_factory=network.client,
                      pinger=ping)
    network_map = crawler.run()
    firewall = network_map.devices["pa-fw1"]
    assert {"10.0.0.5", "10.0.0.6"} <= set(pinged)
    assert firewall.addresses == ["10.0.0.5", "10.0.0.6"]
    assert firewall.source == (NO_SNMP if answers else UNREACHABLE)
    assert firewall.error == (PINGS_NO_SNMP if answers else NO_ANSWER)
    if answers:
        assert firewall.mgmt_ip == answers[0]
    assert len(network_map.links_of("pa-fw1")) == 1
    assert crawler.counts["unreachable"] == (0 if answers else 1)


@pytest.mark.parametrize("first", [NO_ANSWER, PINGS_NO_SNMP])
def test_a_failed_address_does_not_override_a_ping_reply_or_pending_address(first):
    crawler = Crawler(CrawlSettings(seeds=[], trace=False))
    device = crawler.add_device("fw", mgmt_ip="10.0.0.5")
    crawler.aliases["10.0.0.6"] = "fw"
    crawler.asked.update(["10.0.0.5", "10.0.0.6"])
    crawler.record("10.0.0.5", 1, "fw", None, first)
    assert device.source == (NO_SNMP if first == PINGS_NO_SNMP else NEIGHBOR)
    crawler.record("10.0.0.6", 1, "fw", None, NO_ANSWER)
    assert device.source == (NO_SNMP if first == PINGS_NO_SNMP else UNREACHABLE)
    assert crawler.counts["no_snmp"] == int(first == PINGS_NO_SNMP)
    assert crawler.counts["unreachable"] == int(first == NO_ANSWER)


@pytest.mark.parametrize("responds", [False, True])
def test_a_failed_device_read_still_checks_ping(responds):
    pinged = []

    def client(*args, **kwargs):
        raise ValueError("Unexpected SNMP response")

    def ping(address):
        pinged.append(address)
        return responds

    network_map = Crawler(CrawlSettings(seeds=["10.0.0.5"], trace=False), client_factory=client,
                          pinger=ping).run()
    assert pinged == ["10.0.0.5"]
    assert network_map.devices["ip:10.0.0.5"].source == (NO_SNMP if responds else UNREACHABLE)


def test_crawl_ping_tries_again_after_a_lost_echo(monkeypatch):
    """One lost echo (a router dropping the first while it ARPs) doesn't make a device unreachable."""
    from nomad import sweep
    from nomad.netmap import crawl as crawl_module
    replies = iter([None, 3])
    monkeypatch.setattr(sweep, "ping_once", lambda address, timeout: next(replies))
    assert crawl_module._ping("10.0.0.5") is True
    monkeypatch.setattr(sweep, "ping_once", lambda address, timeout: None)
    assert crawl_module._ping("10.0.0.5") is False


def test_same_device_at_two_addresses_is_one_device():
    network = build_network()
    network.devices["10.10.0.1"] = network.devices["10.0.0.1"]
    network_map = crawl(network, seeds=["10.0.0.1", "10.10.0.1"])
    assert sorted(network_map.devices) == ["acc1", "acc2", "pa-fw1", "rtr1", "core"] or \
        set(network_map.devices) == {"core", "acc1", "acc2", "pa-fw1", "rtr1"}
    assert len(network_map.links) == 4


def test_stop_returns_a_partial_map():
    stop = threading.Event()
    network = build_network()
    original = network.client

    def client(host, *args, **kwargs):
        stop.set()  # Stop as soon as the first device is asked
        return original(host, *args, **kwargs)
    network.client = client
    settings = CrawlSettings(seeds=["10.0.0.1"])
    network_map = Crawler(settings, client_factory=network.client, pinger=network.ping,
                          echo=network.echo, should_stop=stop.is_set).run()
    assert network_map.stopped
    assert network_map.finished


def test_crawl_over_real_udp():
    """One device served over UDP by the SNMP tests' agent, to check the crawler with the real client."""
    agent = FakeAgentClient(build_network().devices["10.0.0.1"])
    try:
        network_map = Crawler(CrawlSettings(seeds=["127.0.0.1"], scope=["127.0.0.1/32"], timeout=500, retries=0,
                                            trace=False),
                              client_factory=agent.factory, pinger=lambda address: False).run()
    finally:
        agent.close()
    core = network_map.devices["core"]
    assert core.source == SNMP and core.kind == SWITCH
    assert len(network_map.links) == 4


def crawl_with_events(**options):
    network = build_network()
    events = []
    settings = CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")], **options)
    network_map = Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo,
                          events=lambda kind, *details: events.append((kind, *details))).run()
    return network_map, events


def test_progress_events():
    network_map, events = crawl_with_events()
    started = [event[1] for event in events if event[0] == "started"]
    finished = {}
    for event in events:
        if event[0] == "finished":
            finished.setdefault(event[1], event[2])  # rtr1 finishes again after its traceroute
    assert set(started) == set(finished)  # Everything started also finished
    assert finished["10.0.0.1"] == SNMP and finished["10.0.0.254"] == NO_SNMP
    assert finished["10.50.0.1"] == "traced"
    assert ("finished", "10.0.0.254", "traced") in events
    counts = [event[1] for event in events if event[0] == "counts"][-1]
    assert counts["read"] == 4 and counts["no_snmp"] == 1 and counts["reading"] == 0 and counts["queued"] == 0
    steps = {event[2] for event in events if event[0] == "step" and event[1] == "10.0.0.11"}
    assert {"Trying community 1 of 1", "CDP", "MAC tables: 2 of 2 VLANs read"} <= steps
    log_lines = [event[1] for event in events if event[0] == "log"]
    assert any(line.startswith("Found acc1.corp.example (10.0.0.11) through CDP on core.corp.example Te1/0/1")
               for line in log_lines)
    assert any(re.match(r"Read core\.corp\.example \(10\.0\.0\.1\) in \d+\.\d s.*: switch, 4 neighbors", line)
               for line in log_lines)
    assert "acc1.corp.example: MAC tables for the 2 of 5 VLANs its ports use (1, 10)" in log_lines
    assert any("no answer with community 1 of 1" in line for line in log_lines)  # rtr1
    assert not any("secret" in line or "public" in line for line in log_lines)  # Communities stay out of the log
    snapshots = [event[1] for event in events if event[0] == "map"]
    assert snapshots and set(snapshots[-1].devices) == set(network_map.devices)
    assert snapshots[-1].devices["core"] is not network_map.devices["core"]  # A copy, safe to draw meanwhile


def test_log_says_why_devices_are_not_asked():
    _, events = crawl_with_events(scope=["10.0.0.0/30"])
    log_lines = [event[1] for event in events if event[0] == "log"]
    assert "Not asking acc2 (10.0.0.12): it's outside the scope" in log_lines
    _, events = crawl_with_events(max_devices=2)
    assert any(event[1].startswith("Reached the limit of 2 devices") for event in events if event[0] == "log")


def test_crawl_from_here_adds_to_a_map():
    from nomad.netmap.model import Host
    first = crawl(build_network(), scope=["10.0.0.0/30"])  # Only the core read; the rest seen as neighbors
    assert first.devices["acc1"].source != SNMP
    first.hosts.append(Host(mac="", device="acc1", port="Gi1/0/20", name="old-printer", manual=True))
    core_hosts = [host for host in first.hosts if host.device == "core"]

    network = build_network()
    settings = CrawlSettings(seeds=["10.0.0.11"], overrides=[("10.0.0.12/32", "secret")], trace=False)
    newer = Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo,
                    known=first).run()
    assert not any(host == "10.0.0.1" for host, _ in network.requests)  # The core was read already
    assert newer.devices["acc1"].source == SNMP and "core" in newer.devices  # Same key, not a second core

    links_before = len(first.links)
    added, read = first.merge_crawl(newer)
    assert read == {"acc1"} and added == []  # acc1 was already on the map, as a neighbor
    assert first.devices["acc1"].source == SNMP and first.devices["core"].source == SNMP
    assert len(first.links) == links_before  # The core-acc1 link, seen from both ends, is one link
    acc1_hosts = {host.port for host in first.hosts if host.device == "acc1"}
    assert {"Gi1/0/5", "Gi1/0/7", "Gi1/0/20"} <= acc1_hosts  # Found ones, and the one added by hand
    assert [host for host in first.hosts if host.device == "core"] == core_hosts


def test_preview_leaves_the_map_alone():
    first = crawl(build_network(), scope=["10.0.0.0/30"])
    network = build_network()
    newer = Crawler(CrawlSettings(seeds=["10.0.0.11"], trace=False), client_factory=network.client,
                    pinger=network.ping, echo=network.echo, known=first).run()
    sources = {key: device.source for key, device in first.devices.items()}
    preview = first.preview_with(newer)
    assert preview.devices["acc1"].source == SNMP
    assert {key: device.source for key, device in first.devices.items()} == sources


def test_deleted_devices_are_left_out_and_not_crawled_through():
    network = build_network()
    network_map = crawl(network, deleted={"acc2": ["10.0.0.12"]})
    assert "acc2" not in network_map.devices
    assert not any("acc2" in (link.a, link.b) for link in network_map.links)
    assert not any(host == "10.0.0.12" for host, _ in network.requests)  # Not crawled through
    assert {"core", "acc1", "rtr1", "pa-fw1"} <= set(network_map.devices)


def test_a_deleted_device_the_crawl_starts_from_is_mapped():
    network_map = crawl(build_network(), seeds=["10.0.0.12"], deleted={"acc2": ["10.0.0.12"]})
    assert "acc2" in network_map.devices


def test_v3_only_switch_is_crawled_with_its_user_and_vlan_contexts():
    from nomad.snmpv3 import V3User
    user = V3User("nomad", "sha", "authpass1", "aes128", "privpass1")
    network = build_network()
    acc1 = network.devices["10.0.0.11"]
    acc1.communities, acc1.v3_users = set(), {user}
    events = []
    settings = CrawlSettings(seeds=["10.0.0.1"], communities=["public", user],
                             overrides=[("10.0.0.12/32", "secret")])
    network_map = Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo,
                          events=lambda kind, *details: events.append((kind, *details))).run()
    assert network_map.devices["acc1"].source == SNMP
    assert ("community", "10.0.0.11", user) in events
    hosts = {host.mac: host for host in network_map.hosts}
    assert hosts[PC1_MAC].device == "acc1" and hosts[PC1_MAC].vlan == 10  # From the VLAN 10 context
    assert not any(isinstance(community, str) and community.startswith("public@") and host == "10.0.0.11"
                   for host, community in network.requests)


def test_a_switch_without_per_vlan_tables_has_its_one_table_read():
    network = build_network()
    acc1 = network.devices["10.0.0.11"]
    acc1.vlan_instances = False  # Like IOL: VTP VLANs, but community@vlan doesn't answer
    for table in acc1.contexts.values():
        acc1.mib.update(table)  # Its one table has every VLAN's MACs
    log = []
    network_map = Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                          client_factory=network.client, pinger=network.ping, echo=network.echo,
                          events=lambda kind, *details: log.append(details[0]) if kind == "log" else None).run()
    hosts = {host.mac: host for host in network_map.hosts}
    assert hosts[PC1_MAC].device == "acc1" and hosts[PC1_MAC].port == "Gi1/0/5"
    assert any("No per-VLAN MAC tables" in line for line in log)


def advertise_acc1_at(network, address):
    """The core's CDP says acc1 is at address (an old or out-of-scope one) instead of 10.0.0.11."""
    from netmap_fakes import oid, string
    from nomad.netmap import collect
    import socket
    network.devices["10.0.0.1"].mib[oid(collect.CDP_CACHE_ENTRY, 4, 1, 1)] = string(socket.inet_aton(address))


def test_the_address_a_device_answered_at_is_its_management_address():
    network = build_network()
    advertise_acc1_at(network, "192.0.2.11")  # Not private, so not asked; acc1 is read from its own seed
    network_map = crawl(network, seeds=["10.0.0.1", "10.0.0.11"])
    assert network_map.devices["acc1"].source == SNMP
    assert network_map.devices["acc1"].mgmt_ip == "10.0.0.11"  # Not the address CDP advertised


def test_an_address_corrected_by_hand_still_wins():
    network = build_network()
    settings = CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")],
                             corrections={"acc1": {"mgmt_ip": "10.0.0.111"}})
    network.add("10.0.0.111", network.devices["10.0.0.11"])
    network_map = Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo).run()
    assert network_map.devices["acc1"].mgmt_ip == "10.0.0.111"


def namesake_network(names=("Switch", "Switch"), addresses=("10.0.0.2", "10.0.0.3")):
    """A router with a switch on each of two ports, the switches both named names (a switch's default name, or the
    same name in two domains), each with an access switch of its own behind it."""
    from netmap_fakes import CISCO_ROUTER, CISCO_SWITCH, Device, FakeNetwork
    network = FakeNetwork()
    router = network.add("10.0.0.1", Device("R3", "Cisco IOS Software, ISR Software", CISCO_ROUTER))
    router.address("10.0.0.1", 1)
    for number, (name, address) in enumerate(zip(names, addresses), start=1):
        router.interface(number, f"Ethernet0/{number}")
        router.cdp(number, 1, name, "Ethernet0/0", address, "cisco WS-C2960", 0x28)
        if not address:
            continue
        switch = network.add(address, Device(name, "Cisco IOS Software, Catalyst Software", CISCO_SWITCH))
        switch.interface(1, "Ethernet0/0")
        switch.interface(2, "Ethernet0/1")
        switch.address(address, 1)
        switch.cdp(1, 1, "R3", f"Ethernet0/{number}", "10.0.0.1", "cisco ISR4331", 0x01)
        access = f"10.0.1.{number}"
        switch.cdp(2, 1, f"acc{number}", "Ethernet0/0", access, "cisco WS-C2960", 0x28)
        network.add(access, Device(f"acc{number}", "Cisco IOS Software, Catalyst Software", CISCO_SWITCH)) \
            .address(access, 1)
    return network


def links_of(network_map):
    """Links as {(device, port), (device, port)}, whichever end was read first."""
    return {frozenset([(link.a, link.a_port), (link.b, link.b_port)]) for link in network_map.links}


def link(a, a_port, b, b_port):
    return frozenset([(a, a_port), (b, b_port)])



@pytest.mark.parametrize("seeds", [["10.0.0.1"], ["10.0.0.2", "10.0.0.1"], ["10.0.0.3", "10.0.0.1"]])
def test_two_switches_with_one_name_are_two_devices(seeds):
    """Whichever is read first (and whether before or after the router that sees both), both are read, and keyed by
    address."""
    network_map = crawl(namesake_network(), seeds=seeds, overrides=[], workers=1, trace=False)
    devices = network_map.devices
    assert {key: devices[key].source for key in devices} == {
        "r3": SNMP, "switch@10.0.0.2": SNMP, "switch@10.0.0.3": SNMP, "acc1": SNMP, "acc2": SNMP}
    assert devices["switch@10.0.0.2"].mgmt_ip == "10.0.0.2" and devices["switch@10.0.0.3"].name == "Switch"
    assert links_of(network_map) == {
        link("r3", "Eth0/1", "switch@10.0.0.2", "Eth0/0"), link("r3", "Eth0/2", "switch@10.0.0.3", "Eth0/0"),
        link("switch@10.0.0.2", "Eth0/1", "acc1", "Eth0/0"), link("switch@10.0.0.3", "Eth0/1", "acc2", "Eth0/0")}


def test_one_name_in_two_domains_is_two_devices():
    network_map = crawl(namesake_network(("idf1.site-a.corp", "idf1.site-b.corp")), overrides=[], trace=False)
    devices = network_map.devices
    assert devices["idf1@10.0.0.2"].name == "idf1.site-a.corp"
    assert devices["idf1@10.0.0.3"].name == "idf1.site-b.corp"
    assert {"acc1", "acc2"} <= set(devices)


def test_switches_with_one_name_and_no_address_are_two_devices():
    """Like IOL switches left named "Switch" with no IP: both on Ethernet0/0, so not one switch on two ports."""
    network_map = crawl(namesake_network(addresses=("", "")), overrides=[], trace=False)
    assert set(network_map.devices) == {"r3", "switch@r3/Eth0/1", "switch@r3/Eth0/2"}
    assert links_of(network_map) == {link("r3", "Eth0/1", "switch@r3/Eth0/1", "Eth0/0"),
                                     link("r3", "Eth0/2", "switch@r3/Eth0/2", "Eth0/0")}


def test_a_switch_on_two_ports_with_no_address_is_one_device():
    from netmap_fakes import oid, string
    from nomad.netmap import collect
    network = namesake_network(addresses=("", ""))
    network.devices["10.0.0.1"].mib[oid(collect.CDP_CACHE_ENTRY, 7, 2, 1)] = string("Ethernet0/1")  # Its other port
    network_map = crawl(network, overrides=[], trace=False)
    assert set(network_map.devices) == {"r3", "switch"}
    assert len(network_map.links) == 2


def test_a_device_at_an_address_it_does_not_list_is_still_one_device():
    """Like an NX-OS mgmt0 address (in its own VRF): the neighbors give it, the device answers there, but its address
    table doesn't have it. Only enough is read to tell it's the same one."""
    network = build_network()
    network.devices["10.0.0.99"] = network.devices["10.0.0.1"]
    network.devices["10.0.0.11"].cdp(1, 1, "core.corp.example(FOC999)", "TenGigabitEthernet1/0/1", "10.0.0.99",
                                     "cisco C9500-24Y4C", 0x29)
    network_map = crawl(network)
    assert set(network_map.devices) == {"core", "acc1", "acc2", "rtr1", "pa-fw1"}
    assert len(network_map.links) == 4
    assert [community for host, community in network.requests if host == "10.0.0.99"] == ["public"] * 3


def test_crawl_from_here_keeps_a_switch_with_the_name_of_one_on_the_map():
    first = crawl(namesake_network(), seeds=["10.0.0.2"], scope=["10.0.0.2/32"], overrides=[], trace=False)
    assert first.devices["switch"].source == SNMP
    network = namesake_network()
    newer = Crawler(CrawlSettings(seeds=["10.0.0.1"], trace=False), client_factory=network.client,
                    pinger=network.ping, echo=network.echo, known=first).run()
    first.merge_crawl(newer)
    assert first.devices["switch"].mgmt_ip == "10.0.0.2" and first.devices["switch"].source == SNMP
    assert first.devices["switch@10.0.0.3"].source == SNMP
    assert link("r3", "Eth0/2", "switch@10.0.0.3", "Eth0/0") in links_of(first)
    assert link("r3", "Eth0/2", "switch", "Eth0/0") not in links_of(first)
