"""Links that are gone: Crawl from Here and Watch read devices again, and the links they no longer have go (or, when
the device at the other end may still have them, are kept faint until it's read too)."""
import pytest

from netmap_fakes import add_aruba, build_network, oid

from nomad.netmap import collect, export, watch
from nomad.netmap.crawl import CrawlSettings, Crawler
from nomad.netmap.model import Link, NetworkMap


def crawl(network, seeds, **options):
    settings = CrawlSettings(seeds=list(seeds), overrides=[("10.0.0.12/32", "secret")], trace=False, **options)
    return Crawler(settings, client_factory=network.client, pinger=network.ping, echo=network.echo).run()


def forget(device, entry, index):
    """Take a row out of one of a fake device's tables (every column), as if the neighbor had gone."""
    prefix = oid(entry)
    for key in list(device.mib):
        if key[:len(prefix)] == prefix and key[len(prefix) + 1:len(prefix) + 1 + len(index)] == index:
            del device.mib[key]


def between(network_map, a, b):
    return [link for link in network_map.links if {link.a, link.b} == {a, b}]


@pytest.fixture
def network():
    return build_network()


@pytest.fixture
def mapped(network):
    return crawl(network, ["10.0.0.1"])


def test_link_neither_end_has_any_more_goes(network, mapped):
    assert between(mapped, "core", "acc2")
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    forget(network.devices["10.0.0.12"], collect.CDP_CACHE_ENTRY, (1, 1))
    before = mapped.links_before()
    mapped.merge_crawl(crawl(network, ["10.0.0.1", "10.0.0.12"], max_hops=0))
    assert not between(mapped, "core", "acc2")
    assert between(mapped, "core", "acc1")  # Still there
    gone, unseen = mapped.link_changes(before)
    assert [{link.a, link.b} for link in gone] == [{"core", "acc2"}] and unseen == []


def test_link_one_end_no_longer_has_is_kept_unseen_until_the_other_is_read(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    forget(network.devices["10.0.0.12"], collect.CDP_CACHE_ENTRY, (1, 1))
    newer = crawl(network, ["10.0.0.1"], max_hops=0)
    mapped.merge_crawl(newer)
    [link] = between(mapped, "core", "acc2")
    assert link.unseen_by == "core" and link.unseen_since == newer.finished
    assert mapped.unseen_links() == [link]
    assert "not seen by core.corp.example since" in export.seen_by(link, mapped)
    mapped.merge_crawl(crawl(network, ["10.0.0.1"], max_hops=0))  # The same end again: still waiting, since then
    assert between(mapped, "core", "acc2")[0].unseen_since == newer.finished
    mapped.merge_crawl(crawl(network, ["10.0.0.12"], max_hops=0))  # The other end hasn't it either
    assert not between(mapped, "core", "acc2")


def test_link_the_other_end_still_has_is_seen_again(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))  # Only the core's CDP lost it
    mapped.merge_crawl(crawl(network, ["10.0.0.1"], max_hops=0))
    assert between(mapped, "core", "acc2")[0].unseen_by == "core"
    mapped.merge_crawl(crawl(network, ["10.0.0.12"], max_hops=0))
    [link] = between(mapped, "core", "acc2")
    assert (link.unseen_by, link.unseen_since) == ("", "")


def test_link_to_a_device_that_doesnt_answer_any_more_goes(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    network.devices["10.0.0.12"].communities = {"not-this-one"}
    network.pingable.discard("10.0.0.12")
    newer = crawl(network, ["10.0.0.1", "10.0.0.12"], max_hops=0)
    assert all(device.source != "snmp" for device in newer.devices.values() if device.mgmt_ip == "10.0.0.12")
    mapped.merge_crawl(newer)
    assert not between(mapped, "core", "acc2")


def test_access_point_moved_off_a_switch_port_goes_from_it(network):
    add_aruba(network)
    mapped = crawl(network, ["10.0.0.1"])
    assert between(mapped, "acc1", "ap1")
    forget(network.devices["10.0.0.11"], collect.LLDP_REM_ENTRY, (0, 8, 1))  # Unplugged from acc1 Gi1/0/8
    mapped.merge_crawl(crawl(network, ["10.0.0.11"], max_hops=0))
    assert not between(mapped, "acc1", "ap1")  # Nothing else could have given it: no need to wait
    assert "ap1" in mapped.devices


def test_links_are_left_when_they_cant_be_trusted(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    forget(network.devices["10.0.0.12"], collect.CDP_CACHE_ENTRY, (1, 1))
    stopped = crawl(network, ["10.0.0.1", "10.0.0.12"], max_hops=0)
    stopped.stopped = True  # It may not have read everything
    mapped.merge_crawl(stopped)
    assert between(mapped, "core", "acc2")[0].unseen_by == ""
    partial = crawl(network, ["10.0.0.1", "10.0.0.12"], max_hops=0)
    for key in ("core", "acc2"):
        partial.devices[key].neighbors_partial = True  # Their CDP walks timed out
    mapped.merge_crawl(partial)
    assert between(mapped, "core", "acc2")[0].unseen_by == ""


def test_links_drawn_by_hand_or_traced_stay(network, mapped):
    mapped.links.append(Link("core", "Gi1/0/40", "acc2", "Eth1/40", manual=True))
    mapped.links.append(Link("core", "", "acc1", "", ["icmp"]))
    mapped.merge_crawl(crawl(network, ["10.0.0.1", "10.0.0.11", "10.0.0.12"], max_hops=0))
    assert any(link.manual for link in between(mapped, "core", "acc2"))
    assert any(link.protocols == ["icmp"] for link in between(mapped, "core", "acc1"))


def test_neighbor_walk_timing_out_marks_the_device(network):
    class Flaky:
        def __init__(self, client):
            self.client = client

        def __getattr__(self, name):
            return getattr(self.client, name)

        def walk(self, root, **options):
            if ".".join(map(str, root)).startswith(collect.CDP_CACHE_ENTRY):
                raise OSError("timed out")
            return self.client.walk(root, **options)

    def client(host, *args, **options):
        made = network.client(host, *args, **options)
        return Flaky(made) if host == "10.0.0.1" else made

    settings = CrawlSettings(seeds=["10.0.0.1"], trace=False, max_hops=0)
    newer = Crawler(settings, client_factory=client, pinger=network.ping, echo=network.echo).run()
    assert newer.devices["core"].neighbors_partial


def test_watch_logs_links_gone_and_unseen(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (1, 1))
    forget(network.devices["10.0.0.11"], collect.CDP_CACHE_ENTRY, (1, 1))
    result = watch.apply_refresh(mapped, crawl(network, ["10.0.0.1", "10.0.0.11"], max_hops=0))
    assert len(result.links) == 2 and result
    assert any(line.startswith("Link gone: core.corp.example") and "acc1" in line for line in result.lines)
    assert any(line.startswith("Link not seen by core.corp.example:") and "until acc2 is read again" in line
               for line in result.lines)


def test_unseen_links_save_and_load(network, mapped):
    forget(network.devices["10.0.0.1"], collect.CDP_CACHE_ENTRY, (2, 1))
    mapped.merge_crawl(crawl(network, ["10.0.0.1"], max_hops=0))
    loaded = NetworkMap.from_json(mapped.to_json())
    [link] = between(loaded, "core", "acc2")
    assert link.unseen_by == "core" and link.unseen_since
