import ipaddress

import pytest

from nomad.sweep import SweepHit, local_networks, make_probe, run_sweep, sweep_hosts


def test_sweep_hosts():
    network, hosts = sweep_hosts(" 192.168.1.77/24 ")
    assert str(network) == "192.168.1.0/24"
    assert len(hosts) == 254 and str(hosts[0]) == "192.168.1.1" and str(hosts[-1]) == "192.168.1.254"


def test_sweep_single_address():
    _, hosts = sweep_hosts("10.0.0.5")
    assert hosts == [ipaddress.ip_address("10.0.0.5")]


@pytest.mark.parametrize("subnet, message", [("", "Enter a subnet"), ("192.168.1.0/33", "not a valid subnet"),
                                             ("fe80::/64", "IPv4")])
def test_sweep_hosts_rejects(subnet, message):
    with pytest.raises(ValueError, match=message):
        sweep_hosts(subnet)


def test_hosts_that_miss_are_retried_on_later_passes():
    _, hosts = sweep_hosts("10.0.0.0/29")  # 6 hosts
    attempts = {}
    answers_on = {hosts[0]: 1, hosts[1]: 2, hosts[2]: 3}  # The rest never answer

    def probe(address):
        attempts[address] = attempts.get(address, 0) + 1
        return 5 if attempts[address] == answers_on.get(address) else None

    found = []
    alive = run_sweep(hosts, probe, workers=4, passes=3, found=lambda address, rtt: found.append(address))
    assert sorted(address for address, _ in alive) == hosts[:3] and sorted(found) == hosts[:3]
    assert attempts[hosts[0]] == 1 and attempts[hosts[1]] == 2  # Not probed again once it answered
    assert all(attempts[address] == 3 for address in hosts[2:])


def test_progress_reaches_total_and_credits_skipped_passes():
    _, hosts = sweep_hosts("10.0.0.0/30")  # 2 hosts, both answer on the first pass
    reports = []
    run_sweep(hosts, lambda address: 1, workers=2, passes=3,
              progress=lambda done, total, pass_number, remaining: reports.append((done, total, pass_number)))
    assert reports[-1] == (6, 6, 1)


def test_stop_request():
    _, hosts = sweep_hosts("10.0.0.0/24")
    probed = []
    alive = run_sweep(hosts, lambda address: probed.append(address), workers=4, should_stop=lambda: True)
    assert alive == [] and probed == []


def test_probe_finds_hosts_by_arp_on_local_subnets_only():
    local = [ipaddress.ip_network("192.168.1.0/24")]
    pings = {ipaddress.ip_address("192.168.1.1"): 3, ipaddress.ip_address("10.0.0.1"): 9}
    macs = {ipaddress.ip_address("192.168.1.1"): "00-11-22-33-44-55",
            ipaddress.ip_address("192.168.1.7"): "66-77-88-99-AA-BB"}
    arp_calls = []

    def arp(address):
        arp_calls.append(address)
        return macs.get(address)

    probe = make_probe(1000, local, ping=lambda address, timeout: pings.get(address), arp=arp)
    assert probe(ipaddress.ip_address("192.168.1.1")) == SweepHit(3, "00-11-22-33-44-55")
    assert probe(ipaddress.ip_address("192.168.1.7")) == SweepHit(None, "66-77-88-99-AA-BB")  # Blocks ping
    assert probe(ipaddress.ip_address("10.0.0.1")) == SweepHit(9)  # Routed subnet: no ARP
    assert probe(ipaddress.ip_address("192.168.1.8")) is None
    assert probe(ipaddress.ip_address("192.168.1.8")) is None  # Only ARPed on the first try
    assert arp_calls.count(ipaddress.ip_address("192.168.1.8")) == 1
    assert ipaddress.ip_address("10.0.0.1") not in arp_calls

    ping_only = make_probe(1000, local, find_by_arp=False, ping=lambda address, timeout: None, arp=arp)
    assert ping_only(ipaddress.ip_address("192.168.1.7")) is None


def test_local_networks():
    from nomad.snapshot import Adapter, NetworkSnapshot
    up = Adapter("1", "Ethernet", status="Up", is_adapter=True,
                 ipv4=[ipaddress.ip_interface("192.168.1.10/24"), ipaddress.ip_interface("10.9.9.9/32")])
    down = Adapter("2", "Wi-Fi", status="Disconnected", is_adapter=True,
                   ipv4=[ipaddress.ip_interface("172.16.0.5/16")])
    snapshot = NetworkSnapshot({"1": up, "2": down})
    assert local_networks(snapshot) == [ipaddress.ip_network("192.168.1.0/24")]
