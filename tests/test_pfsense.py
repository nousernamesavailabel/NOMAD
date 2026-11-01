"""pfSense firewalls: how full their disks are, read over SNMP and shown in the map's device details. The rows are
from a walk of a real pfSense 2.8.1 on ZFS."""
from netmap_fakes import Device, build_network, number, oid, string

from nomad.netmap import collect, pfsense
from nomad.netmap.crawl import CrawlSettings, Crawler, apply_inventory, read_inventory_of
from nomad.netmap.model import FIREWALL, Device as MapDevice, NetworkMap
from nomad.snmp import OBJECT_ID, Value, parse_oid
from nomad.ui import netmap_tab

DESCR = "pfSense Home-PFSense.home.arpa 2.8.1-RELEASE FreeBSD 15.0-CURRENT amd64"
FREEBSD = "1.3.6.1.4.1.12325.1.1.2.1.1"
RAM, SWAP = "1.3.6.1.2.1.25.2.1.2", "1.3.6.1.2.1.25.2.1.3"
FS_OTHER, FS_UNKNOWN = "1.3.6.1.2.1.25.3.9.1", "1.3.6.1.2.1.25.3.9.2"
ROWS = [(1, RAM, "Real Memory Metrics", 4096, 133891, 130917),
        (3, SWAP, "Swap:/dev/gpt/swap1", 4096, 262112, 0),
        (4, FS_OTHER, "/, type: zfs, dev: pfSense/ROOT/default", 512, 213028142, 2281872),
        (5, FS_OTHER, "/dev, type: devfs, dev: devfs", 512, 2, 0),
        (6, FS_OTHER, "/var, type: zfs, dev: pfSense/var", 512, 210747366, 1096),
        (9, FS_OTHER, "/var/log, type: zfs, dev: pfSense/var/log", 512, 210755158, 8888),
        (14, FS_OTHER, "/var/cache/pkg, type: zfs, dev: pfSense/ROOT/default/var_cache_pkg", 512, 211633862, 887592),
        (16, FS_UNKNOWN, "/var/run, type: tmpfs, dev: tmpfs", 4096, 1024, 42),
        (93, RAM, "UMA: mbuf", 256, 3207116, 11349)]
FREE = 210746270 * 512
USED = (2281872 + 1096 + 8888 + 887592) * 512


def set_rows(device, rows=ROWS):
    for index, kind, descr, units, size, used in rows:
        device.set(pfsense.STORAGE_ENTRY, pfsense.STORAGE_TYPE, index, Value(OBJECT_ID, parse_oid(kind)))
        device.set(pfsense.STORAGE_ENTRY, pfsense.STORAGE_DESCR, index, string(descr))
        device.set(pfsense.STORAGE_ENTRY, pfsense.STORAGE_UNITS, index, number(units))
        device.set(pfsense.STORAGE_ENTRY, pfsense.STORAGE_SIZE, index, number(size))
        device.set(pfsense.STORAGE_ENTRY, pfsense.STORAGE_USED, index, number(used))


def pfsense_network(rows=ROWS):
    network = build_network()
    firewall = network.add("10.0.0.30", Device("Home-PFSense.home.arpa", DESCR, parse_oid(FREEBSD)))
    set_rows(firewall, rows)
    return network, firewall


def settings(seeds=("10.0.0.30",), **options):
    return CrawlSettings(seeds=list(seeds), overrides=[("10.0.0.12/32", "secret")], trace=False, **options)


def crawl(network, **options):
    return Crawler(settings(**options), client_factory=network.client, pinger=network.ping, echo=network.echo).run()


def details_rows(rows=ROWS):
    device = Device("fw", DESCR, parse_oid(FREEBSD))
    set_rows(device, rows)
    return sorted(device.mib.items())


def disk_details(rows):
    """What a crawl asks for by GET, of a table's walked rows."""
    wanted = set(pfsense.detail_oids(pfsense.disk_indexes(rows)))
    return [row for row in rows if row[0] in wanted]


def test_recognized_from_sysdescr():
    assert collect.is_pfsense(DESCR)
    assert not collect.is_pfsense("FreeBSD fw 14.1-RELEASE amd64") and not collect.is_pfsense("")
    assert not collect.is_pfsense("Cisco IOS Software, pfsense-lab")


def test_it_is_a_firewall():
    assert collect.classify(FREEBSD, DESCR) == FIREWALL
    assert collect.classify(platform=DESCR) == FIREWALL  # As a neighbor's LLDP gives it
    assert collect.classify(FREEBSD, "pfSense phone-gw.home.arpa 2.8.1-RELEASE FreeBSD") == FIREWALL  # Its hostname
    assert collect.classify(descr="Linux pfsense-backup 6.1.0 x86_64") != FIREWALL


def test_a_crawl_maps_it_as_a_firewall():
    network, _ = pfsense_network()
    mapped = crawl(network)
    assert next(item for item in mapped.devices.values() if item.name == "Home-PFSense.home.arpa").kind == FIREWALL


def test_only_the_file_systems_are_asked_for():
    assert pfsense.disk_indexes(details_rows()) == [4, 5, 6, 9, 14, 16]
    assert pfsense.detail_oids([4])[0] == oid(pfsense.STORAGE_ENTRY, pfsense.STORAGE_DESCR, 4)


def test_a_zfs_pool_is_one_disk_counting_its_free_space_once():
    assert pfsense.disks(disk_details(details_rows())) == \
        [{"name": "pfSense", "total": USED + FREE, "used": USED, "free": FREE}]


def test_other_file_systems_stand_alone_and_a_fixed_disk_counts():
    rows = details_rows([(1, pfsense.FIXED_DISK, "/, type: ufs, dev: /dev/ufsid/abc", 4096, 1000, 250),
                         (2, "1.3.6.1.2.1.25.3.9.3", "/data, type: ufs, dev: /dev/ada1p1", 4096, 2000, 500)])
    assert pfsense.disk_indexes(rows) == [1, 2]
    found = pfsense.disks(disk_details(rows))
    assert [(disk["name"], disk["total"], disk["used"], disk["free"]) for disk in found] == \
        [("/", 4096000, 1024000, 3072000), ("/data", 8192000, 2048000, 6144000)]


def test_a_row_missing_a_column_is_left_out():
    rows = [row for row in disk_details(details_rows())
            if row[0] != oid(pfsense.STORAGE_ENTRY, pfsense.STORAGE_USED, 4)]
    assert pfsense.disks(rows)[0]["used"] == USED - 2281872 * 512


def test_a_crawl_reads_them_only_on_pfsense():
    network, firewall = pfsense_network()
    mapped = crawl(network)
    device = next(item for item in mapped.devices.values() if item.name == "Home-PFSense.home.arpa")
    assert device.disks == [{"name": "pfSense", "total": USED + FREE, "used": USED, "free": FREE}]
    assert device.disks_read

    network = build_network()
    set_rows(network.devices["10.0.0.1"])
    mapped = crawl(network, seeds=("10.0.0.1",))
    assert not any(item.disks for item in mapped.devices.values())


def test_a_crawl_reads_them_without_reading_hardware():
    network, firewall = pfsense_network()
    mapped = crawl(network, read_inventory=False)
    assert any(item.disks for item in mapped.devices.values())


def test_no_host_resources_is_noted():
    network, firewall = pfsense_network(rows=())
    client = network.client("10.0.0.30", "public", 2)
    crawler = Crawler(settings(), client_factory=network.client)
    tables = collect.DeviceTables(info=collect.SystemInfo(descr=DESCR))
    crawler.read_disks(client, tables)
    assert tables.disks == [] and any("Host Resources" in note for note in tables.notes)


def test_read_hardware_again_brings_them_up_to_date():
    network, firewall = pfsense_network()
    tables, _ = read_inventory_of(settings(), "10.0.0.30", client_factory=network.client)
    device = MapDevice(key="fw", disks=[{"name": "old", "total": 1, "used": 1, "free": 0}],
                       disks_read="2026-01-01T00:00:00")
    apply_inventory(device, tables)
    assert device.disks[0]["name"] == "pfSense" and device.disks_read != "2026-01-01T00:00:00"


def test_a_read_that_finds_none_keeps_the_last_one():
    device = MapDevice(key="fw", disks=[{"name": "pool", "total": 1, "used": 1, "free": 0}], disks_read="2026-01-01")
    apply_inventory(device, collect.DeviceTables(info=collect.SystemInfo(descr=DESCR)))
    assert device.disks[0]["name"] == "pool" and device.disks_read == "2026-01-01"


def test_saved_with_the_map():
    network_map = NetworkMap()
    network_map.devices["fw"] = MapDevice(key="fw", disks=[{"name": "pool", "total": 4, "used": 1, "free": 3}],
                                          disks_read="2026-10-31T17:51:00")
    again = NetworkMap.from_json(network_map.to_json()).devices["fw"]
    assert again.disks == network_map.devices["fw"].disks and again.disks_read == "2026-10-31T17:51:00"


def test_details_show_it_between_status_and_management_ip():
    network_map = NetworkMap()
    network_map.devices["fw"] = MapDevice(key="fw", mgmt_ip="10.0.0.30", disks_read="2026-10-31T17:51:00",
                                          disks=[{"name": "pfSense", "total": USED + FREE, "used": USED, "free": FREE}])
    html = netmap_tab.device_html(network_map, "fw")
    assert "<b>Disk</b>" in html and "(1.5%)" in html and "read 2026-10-31 17:51" in html
    assert netmap_tab.disk_rows(network_map.devices["fw"])[0][1].startswith("1.5 GB of 102.0 GB used")
    assert html.index("<b>Disk</b>") < html.index("Management IP")


def test_each_disk_gets_a_row_when_there_are_several():
    device = MapDevice(key="fw", disks=[{"name": "zroot", "total": 4, "used": 1, "free": 3},
                                        {"name": "/data", "total": 0, "used": 0, "free": 0}])
    assert [label for label, _ in netmap_tab.disk_rows(device)] == ["Disk zroot", "Disk /data"]
    assert netmap_tab.disk_rows(MapDevice(key="other")) == []
