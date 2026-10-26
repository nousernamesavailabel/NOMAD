import json

import pytest

from nomad.ipam.spreadsheet import DETAIL, SKIP, SUMMARY, SpreadsheetError, import_page, parse_page, read_pages
from nomad.ipam.store import DESCRIPTION, MAC, NAME, RESERVED, USED, VALUE, IpamError, IpamStore, parse_subnet


@pytest.fixture
def store(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    yield store
    store.close()


def test_networks_are_separate_and_names_unique(store):
    first = store.add_network("11AB", fields={"ASN": "65139"})
    second = store.add_network("22CD")
    store.add_subnet(first.id, "10.0.0.0/24", "LAN")
    store.add_subnet(second.id, "10.0.0.0/24", "Same range, other network")
    with pytest.raises(IpamError, match="already in this network"):
        store.add_subnet(first.id, "10.0.0.0 255.255.255.0")
    with pytest.raises(IpamError, match="already a network"):
        store.add_network(" 11ab ")
    store.update_network(second.id, name="22CD renamed")
    assert [network.name for network in store.networks()] == ["11AB", "22CD renamed"]
    assert store.network(first.id).fields == {"ASN": "65139"}


def test_subnet_validation(store):
    network = store.add_network("n")
    with pytest.raises(IpamError, match="isn't a subnet"):
        store.add_subnet(network.id, "10.0.0.2000/28")
    with pytest.raises(IpamError, match="isn't in"):
        store.add_subnet(network.id, "10.0.0.0/28", gateway="10.0.1.1")
    assert str(parse_subnet("10.1.2.0 255.255.255.0")) == "10.1.2.0/24"
    assert parse_subnet("2001:db8::/64").version == 6


def test_addresses_nesting_and_next_free(store):
    network = store.add_network("n")
    block = store.add_subnet(network.id, "10.0.0.0/20", "Unit block")
    lan = store.add_subnet(network.id, "10.0.0.0/29", "LAN", gateway="10.0.0.1")
    store.add_subnet(network.id, "10.0.0.8/29", "Other")
    store.set_address(network.id, "10.0.0.2", USED, "sw1")
    store.set_address(network.id, "10.0.0.3", RESERVED)
    store.set_address(network.id, "10.0.1.5", USED, "in the block")
    assert [subnet.name for subnet in store.subnets(network.id)] == ["Unit block", "LAN", "Other"]
    assert store.subnet_for(network.id, "10.0.0.2").id == lan.id
    assert store.subnet_for(network.id, "10.0.1.5").id == block.id
    assert store.subnet_for(network.id, "192.168.0.1") is None
    assert store.count_addresses(network.id, lan.network) == 2
    assert str(store.next_free(lan)) == "10.0.0.4"  # .0 network, .1 gateway, .2 and .3 taken
    assert str(store.next_free(block)) == "10.0.0.16"  # Skips the nested /29s

    store.set_address(network.id, "10.0.0.2", USED, "sw1-renamed")
    assert store.address(network.id, "10.0.0.2").version == 2
    store.free_address(network.id, "10.0.0.2")
    assert store.address(network.id, "10.0.0.2") is None
    store.set_address(network.id, "10.0.0.2", USED, "back again")  # A freed address can be used again
    assert store.address(network.id, "10.0.0.2").name == "back again"

    store.delete_subnet(lan.id, with_addresses=True)
    assert store.address(network.id, "10.0.0.3") is None
    assert store.address(network.id, "10.0.1.5") is not None


def test_every_change_is_logged_for_sync(store):
    network = store.add_network("n")
    store.set_address(network.id, "10.0.0.5", USED, "host")
    store.set_address(network.id, "10.0.0.5", USED, "host")  # No change, nothing logged
    store.free_address(network.id, "10.0.0.5")
    rows = store.db.execute("SELECT entity, op, version, modified_by, data FROM changes ORDER BY seq").fetchall()
    assert [(row["entity"], row["op"], row["version"]) for row in rows] == [
        ("networks", "create", 1), ("addresses", "create", 1), ("addresses", "delete", 2)]
    assert all(row["modified_by"] == "tester" for row in rows)
    assert json.loads(rows[1]["data"])["name"] == "host"
    assert store.pending_changes() == 3


def test_failed_change_rolls_back(store):
    network = store.add_network("n")
    with pytest.raises(IpamError):
        with store.transaction():
            store.add_subnet(network.id, "10.0.0.0/24")
            store.add_subnet(network.id, "10.0.0.0/24")
    assert store.subnets(network.id) == []


def test_search(store):
    first = store.add_network("A")
    second = store.add_network("B")
    store.add_subnet(first.id, "10.0.0.0/24", "Core switches")
    store.set_address(first.id, "10.0.0.7", USED, "CORE-SW1")
    store.set_address(second.id, "10.0.0.7", USED, "other-host")
    assert {(network.name, address.name) for network, _, address in store.search("10.0.0.7")} == \
           {("A", "CORE-SW1"), ("B", "other-host")}
    results = store.search("core")
    assert [(subnet.name if subnet else None, address.ip if address else None) for _, subnet, address in results] \
           == [("Core switches", None), ("Core switches", "10.0.0.7")]
    free = store.search("10.0.0.9")
    assert len(free) == 1 and free[0][2].status == ""  # In a subnet but not recorded


def test_search_by_network_and_kind(store):
    first = store.add_network("A")
    second = store.add_network("B")
    store.add_subnet(first.id, "10.0.0.0/24", "68890 HSM IN-CT", fields={"Telephony Rng": "68890"})
    store.set_address(first.id, "10.0.0.7", USED, "HSM-68890-SW1")
    store.set_address(first.id, "10.0.0.8", RESERVED, "68890 spare")
    store.add_subnet(second.id, "10.0.0.0/24", "68890 other")
    store.set_address(second.id, "10.0.0.7", USED, "68890-host")

    def found(text, **options):
        return {(network.name, subnet.cidr if subnet else None, address.ip if address else None)
                for network, subnet, address in store.search(text, **options)}

    assert len(found("68890")) == 5
    assert found("68890", network_id=first.id) == {("A", "10.0.0.0/24", None), ("A", "10.0.0.0/24", "10.0.0.7"),
                                                   ("A", "10.0.0.0/24", "10.0.0.8")}
    assert found("68890", addresses=False) == {("A", "10.0.0.0/24", None), ("B", "10.0.0.0/24", None)}
    assert found("68890", subnets=False, network_id=second.id) == {("B", "10.0.0.0/24", "10.0.0.7")}
    assert found("68890", subnets=False, status=RESERVED) == {("A", "10.0.0.0/24", "10.0.0.8")}
    assert found("68890", subnets=False, status=USED) == {("A", "10.0.0.0/24", "10.0.0.7"),
                                                         ("B", "10.0.0.0/24", "10.0.0.7")}
    # Searching for an address by value keeps to the same choices
    assert found("10.0.0.7", addresses=False, network_id=first.id) == {("A", "10.0.0.0/24", None)}
    assert found("10.0.0.8", subnets=False, status=USED) == set()
    assert found("10.0.0.9", subnets=False, status=RESERVED) == set()  # Free, so neither used nor reserved
    assert found("10.0.0.9", subnets=False) == {("A", "10.0.0.0/24", "10.0.0.9"), ("B", "10.0.0.0/24", "10.0.0.9")}


HEADER = ["", "Network Name", "Telephony Rng", "Subnet", "Mask", "Gateway", "Reserved", "Assignment"]


def page(*rows):
    return [HEADER] + [[""] + list(row) + [""] * (7 - len(row)) for row in rows]


def sample_page():
    return page(
        ["11AB", "HQ", "2025-04-25", "", "", "02"],
        ["MAIN Loopback", "68900", "10.0.0.0", "255.255.255.248", "", "", "Loopback0"],
        ["MAIN IN-CT", "68900", "10.0.0.8", "255.255.255.248", "10.0.0.9"],
        ["Only in summary", "68900", "10.0.1.0", "255.255.255.0"],
        ["Renamed", "68900", "10.0.2.0", "255.255.255.252"],
        ["Template Net=1:20", "68900", "10.(125+Net).0.0", "255.255.0.0"],
        [],
        ["Unit Base Info"],
        ["ASN", "65139"],
        ["Unit IP"],
        ["10.0.0.0"],
        ["Telephony", "6890", "", "RO String", "", "", "secret-ro"],
        ["", "", "", "RW String", "", "", "secret-rw"],
        ["Detailed Info"],
        ["MAIN Loopback", "68900", "10.0.0.0", "255.255.255.255", "", "Y", "RTR1"],
        ["", "", "10.0.0.1", "255.255.255.255", "", "Y", ""],
        ["", "", "10.0.0.2", "255.255.255.255", "", "", ""],
        ["", "", "10.0.0.7", "255.255.255.255", "", "Y", "Broadcast"],
        ["MAIN IN-CT", "68900", "10.0.0.8", "255.255.255.248", "", "Y", "Network"],
        ["", "", "10.0.0.9", "255.255.255.248", "10.0.0.9", "", "RTR1-INCT"],
        ["", "", "10.0.0.2000", "255.255.255.248", "", "", "typo"],
        ["", "", "10.0.0.15", "255.255.255.248", "", "Y", "Broadcast"],
        ["Renamed differently", "68900", "10.0.2.0", "255.255.255.252", "", "Y", "Network"],
        ["", "", "10.0.2.1", "255.255.255.252", "", "Y", "Reserved for Peer Connection"],
        ["Only in detail", "68900", "10.0.3.0", "255.255.255.252"],
        ["Misaligned", "68900", "10.0.4.4", "255.255.255.248", "", "", ""],
        ["", "", "10.0.4.5", "", "", "", "stray-host"],
        ["End"],
        ["Ignored after End", "", "10.9.9.0", "255.255.255.0"],
    )


def test_parse_page():
    sheet = parse_page("Page 1", sample_page())
    assert sheet.fields == {"Unit": "11AB", "Location": "HQ", "Revision date": "2025-04-25", "Revision": "02",
                            "ASN": "65139", "Unit IP": "10.0.0.0", "Telephony": "6890"}
    assert "secret-ro" not in repr(sheet)
    assert sheet.suggested_name == "11AB Page 1"

    matched = {subnet.cidr: subnet for subnet in sheet.matched}
    assert set(matched) == {"10.0.0.0/29", "10.0.0.8/29"}  # The /32 loopback rows cover a /29
    assert matched["10.0.0.0/29"].description == "Loopback0"  # From the summary
    assert matched["10.0.0.0/29"].loopbacks and not matched["10.0.0.8/29"].loopbacks
    assert matched["10.0.0.8/29"].gateway == "10.0.0.9"
    assert matched["10.0.0.8/29"].fields == {"Telephony Rng": "68900"}

    differences = {difference.cidr: difference for difference in sheet.differences}
    assert set(differences) == {"10.0.1.0/24", "10.0.2.0/30", "10.0.3.0/30", "10.0.4.0/29"}
    assert "Only in the summary" in differences["10.0.1.0/24"].describe()
    assert "'Renamed' vs 'Renamed differently'" in differences["10.0.2.0/30"].describe()
    assert [choice for choice, _ in differences["10.0.2.0/30"].options()] == [SUMMARY, DETAIL, SKIP]

    assert [(address.ip, address.status, address.name) for address in sheet.addresses] == [
        ("10.0.0.0", RESERVED, "RTR1"), ("10.0.0.1", RESERVED, ""), ("10.0.0.9", USED, "RTR1-INCT"),
        ("10.0.2.1", RESERVED, "Reserved for Peer Connection"), ("10.0.4.5", USED, "stray-host")]
    problems = " / ".join(message for _, message in sheet.problems)
    assert "Template Net=1:20" in problems
    assert "10.0.0.2000" in problems
    assert "boundary" not in problems  # 10.0.4.4 with a /29 mask stands for its subnet, 10.0.4.0/29
    assert differences["10.0.4.0/29"].detail.written == "10.0.4.4/29"
    assert "10.9.9.0" not in problems


def test_import_needs_choices_then_fills_network(store):
    sheet = parse_page("Page 1", sample_page())
    with pytest.raises(SpreadsheetError, match="need a choice"):
        import_page(store, sheet, "11AB")
    for difference in sheet.differences:
        difference.choice = SKIP if difference.cidr == "10.0.1.0/24" else DETAIL if difference.detail else SUMMARY
    network = import_page(store, sheet, "11AB")
    assert network.fields["ASN"] == "65139" and network.fields["Imported from"] == "Page 1"
    subnets = {subnet.cidr: subnet.name for subnet in store.subnets(network.id)}
    assert subnets == {"10.0.0.0/29": "MAIN Loopback", "10.0.0.8/29": "MAIN IN-CT", "10.0.2.0/30": "Renamed differently",
                       "10.0.3.0/30": "Only in detail", "10.0.4.0/29": "Misaligned"}
    assert len(store.addresses(network.id)) == 5
    loopbacks = next(subnet for subnet in store.subnets(network.id) if subnet.cidr == "10.0.0.0/29")
    assert loopbacks.loopbacks and loopbacks.special_addresses() == {}
    assert store.address(network.id, "10.0.0.7") is None  # "Broadcast" on a /32 row is just a free loopback

    # Importing again over the same network replaces its contents
    for difference in sheet.differences:
        difference.choice = SKIP
    import_page(store, sheet, "11AB", replace=True)
    assert len(store.networks()) == 1
    assert {subnet.cidr for subnet in store.subnets(network.id)} == {"10.0.0.0/29", "10.0.0.8/29"}


def test_read_csv_and_bad_pages(tmp_path):
    path = tmp_path / "net.csv"
    path.write_text("\n".join(",".join(row) for row in sample_page()), encoding="utf-8")
    [(title, rows)] = read_pages(path)
    assert title == "net" and parse_page(title, rows).fields["Unit"] == "11AB"
    with pytest.raises(SpreadsheetError, match="no header row"):
        parse_page("Notes", [["just some text"]])
    with pytest.raises(SpreadsheetError, match=".xls"):
        read_pages(tmp_path / "old.xls")


def test_read_xlsx(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    import datetime
    workbook = openpyxl.Workbook()
    workbook.active.title = "11AB"
    for row in sample_page():
        workbook.active.append(row)
    workbook.active["D2"] = datetime.datetime(2025, 4, 25)
    workbook.active["C3"] = 68900  # Numbers come back without ".0"
    other = workbook.create_sheet("22CD")
    other.append(HEADER)
    path = tmp_path / "plan.xlsx"
    workbook.save(path)
    pages = read_pages(path)
    assert [title for title, _ in pages] == ["11AB", "22CD"]
    sheet = parse_page(*pages[0])
    assert sheet.fields["Revision date"] == "2025-04-25"
    assert sheet.summary[0].fields == {"Telephony Rng": "68900"}


def test_enclave_header_and_bad_summary_gateway():
    rows = sample_page()
    rows[0] = ["", "SIPR", "Telephony Rng", "Subnet", "Mask", "Gateway", "Reserved", "Assignment"]
    rows[3][5] = "10.0.9.9"  # MAIN IN-CT's summary gateway isn't in its subnet
    sheet = parse_page("SIPR Template", rows)
    assert sheet.fields["Enclave"] == "SIPR"
    assert sheet.suggested_name == "11AB SIPR Template"  # Every page of the workbook has unit 11AB
    [fix] = sheet.gateway_fixes
    assert (fix.section, fix.given, fix.gateway) == ("Summary", "10.0.9.9", "10.0.0.9")
    assert "Detailed Info" in fix.reason  # The other section's gateway for the same subnet
    assert any(subnet.cidr == "10.0.0.8/29" and subnet.gateway == "10.0.0.9" for subnet in sheet.matched)


def test_pages_without_detailed_info():
    subnets_only = parse_page("ISP DMVPN", [
        ["Colorless", "Subnet", "Mask", "Gateway", "Reserved", "Assignment"],
        ["OVPN", "10.9.0.0/23", "255.255.254.0"],
        ["Temp Management", "10.10.100.0", "255.255.255.0"],
        ["", "10.10.106.0", "255.255.255.0"],
        ["Wrong mask", "10.10.108.0/24", "255.255.0.0"],
    ])
    assert subnets_only.differences == []  # Nothing to compare the summary with, so nothing to decide
    assert [subnet.cidr for subnet in subnets_only.subnets_to_import()] == ["10.9.0.0/23", "10.10.100.0/24",
                                                                           "10.10.106.0/24"]
    assert "doesn't match the mask" in subnets_only.problems[0][1]

    hosts = parse_page("HSMC XLESS", [
        ["Colorless", "Vlan 10", "Subnet", "Mask", "Gateway", "Reserved", "Assignment"],
        ["MGT", "Vlan 10", "10.10.10.0", "255.255.255.0", "10.10.10.10", "", "Network"],
        ["SW-1", "Vlan 10", "10.10.10.1", "255.255.255.0", "10.10.10.10"],
        ["SW-2", "Vlan 10", "10.10.10.2", "255.255.255.0", "10.10.10.10", "Y", "Uplink"],
        ["Elsewhere", "Vlan 10", "10.10.11.5", "255.255.255.0"],
    ])
    assert [subnet.cidr for subnet in hosts.subnets_to_import()] == ["10.10.10.0/24", "10.10.11.0/24"]
    assert hosts.subnets_to_import()[0].gateway == "10.10.10.10"
    assert [(address.ip, address.status, address.name) for address in hosts.addresses] == [
        ("10.10.10.1", USED, "SW-1"), ("10.10.10.2", RESERVED, "Uplink")]
    assert hosts.problems == []  # A row outside the listed subnet is a block of its own


def test_address_with_mask_stands_for_its_subnet(store):
    network = store.add_network("n")
    vlan = store.add_subnet(network.id, "172.28.101.0/16", "Vlan 6")
    assert vlan.cidr == "172.28.0.0/16"
    with pytest.raises(IpamError, match="already in this network"):
        store.add_subnet(network.id, "172.28.5.9 255.255.0.0")

    sheet = parse_page("NIPR", page(
        ["Vlan 6", "68900", "172.28.101.0", "255.255.0.0"],
        ["B652 INE", "68890", "10.175.11.1", "255.255.255.0"],
        ["MTC INE", "68890", "10.175.11.2", "255.255.255.0"],  # A device in the subnet just listed
        ["Detailed Info"],
        ["First", "68900", "155.28.91.136", "255.255.255.224"],
        ["", "", "155.28.91.137", "255.255.255.224", "", "", "host-a"],
        ["Second", "68900", "155.28.91.144", "255.255.255.224"],
        ["", "", "155.28.91.145", "255.255.255.224", "", "", "host-b"],
        ["End"],
    ))
    for difference in sheet.differences:
        difference.choice = SUMMARY if difference.summary else DETAIL
    assert [(subnet.cidr, subnet.name) for subnet in sheet.subnets_to_import()] == [
        ("10.175.11.0/24", "B652 INE"), ("155.28.91.128/27", "First"), ("172.28.0.0/16", "Vlan 6")]
    assert [(address.ip, address.name) for address in sheet.addresses] == [
        ("10.175.11.2", "MTC INE"), ("155.28.91.137", "host-a"), ("155.28.91.145", "host-b")]
    [(row, message)] = sheet.problems
    assert row == 8 and "155.28.91.144/27 (Second) is in the same subnet, 155.28.91.128/27, as row 6" in message


def test_gateway_suggestions():
    from nomad.ipam.spreadsheet import GatewayFix, SheetSubnet

    def suggest(cidr, given):
        fix = GatewayFix(SheetSubnet(1, cidr), "Summary", given)
        fix.suggest()
        return fix.gateway, fix.reason

    assert suggest("148.38.206.96/27", "144.38.206.126")[0] == "148.38.206.126"  # Typo in the network part
    assert suggest("155.28.80.64/26", "155.28.87.126")[0] == "155.28.80.126"
    gateway, reason = suggest("22.226.57.0/25", "22.226.57.128")
    assert gateway == "22.226.57.126"
    assert reason == ("The subnet's last usable address, where gateways usually are (keeping the end of "
                      "22.226.57.128 would give the subnet's network address, 22.226.57.0).")
    assert "typo" in suggest("148.38.206.96/27", "144.38.206.126")[1]
    assert suggest("155.28.81.128/25", "155.28.81.256")[0] == "155.28.81.254"  # Not an address at all
    assert suggest("10.116.80.200/28", "10.116.80.214")[0] == "10.116.80.198"  # The /28 is .192 to .207

    fix = GatewayFix(SheetSubnet(1, "10.0.0.0/24"), "Summary", "10.0.1.1")
    assert fix.problem == "10.0.1.1 is outside 10.0.0.0/24, which only holds 10.0.0.1 to 10.0.0.254."
    assert GatewayFix(SheetSubnet(1, "10.0.0.0/24"), "Summary", "10.0.0.256").problem ==            "'10.0.0.256' isn't a valid IP address."
    assert fix.set_gateway("10.0.0.1") is None and fix.subnet.gateway == "10.0.0.1"
    assert fix.set_gateway("10.0.5.1") == ("10.0.5.1 is outside 10.0.0.0/24. Use an address from 10.0.0.1 to "
                                           "10.0.0.254, or clear it to leave the gateway out.")
    assert "broadcast address, which can't be a gateway" in fix.set_gateway("10.0.0.255")
    assert fix.subnet.gateway == "10.0.0.1"  # Unchanged by the rejected entries
    assert fix.set_gateway("") is None and fix.subnet.gateway == ""  # Leave it out


def test_comparing_the_network_with_ipam(store):
    from nomad.ipam.reconcile import MAC_DIFFERS, NOT_RECORDED, RECORDED, RESERVED_IN_USE, candidate_networks, \
        compare, silent
    from nomad.ipam.store import parse_subnet
    lab = store.add_network("Lab")
    other = store.add_network("Other site")  # Same range in a separate network
    store.add_subnet(lab.id, "10.0.0.0/24", "LAN")
    store.add_subnet(other.id, "10.0.0.0/25", "LAN")
    store.set_address(lab.id, "10.0.0.5", USED, "sw1", mac="aa:bb:cc:00:00:05")
    store.set_address(lab.id, "10.0.0.6", USED, "printer", mac="AA-BB-CC-00-00-06")
    store.set_address(lab.id, "10.0.0.7", RESERVED)
    store.set_address(lab.id, "10.0.0.8", USED, "gone")
    store.set_address(lab.id, "10.0.0.9", RESERVED, "future")

    found = {"10.0.0.5": ("AA-BB-CC-00-00-05", "sw1"), "10.0.0.6": ("AA-BB-CC-00-00-99", ""),
             "10.0.0.7": ("", ""), "10.0.0.200": ("AA-BB-CC-00-00-C8", "new-host"),
             "169.254.1.1": ("AA-BB-CC-00-01-01", "")}  # Outside every subnet: not judged
    assert [(source, network.name, held) for source, network, held in
            candidate_networks([("local", store)], found)] == [("local", "Lab", 4), ("local", "Other site", 3)]
    assert "169.254.1.1" not in compare(found, store, lab.id)
    findings = compare(found, store, lab.id)
    assert {ip: finding.state for ip, finding in findings.items()} == {
        "10.0.0.5": RECORDED, "10.0.0.6": MAC_DIFFERS, "10.0.0.7": RESERVED_IN_USE, "10.0.0.200": NOT_RECORDED}
    assert findings["10.0.0.5"].text == "In IPAM: sw1"
    assert "IPAM has AA-BB-CC-00-00-06 for printer" in findings["10.0.0.6"].text
    quiet = silent(store, lab.id, found, [parse_subnet("10.0.0.0/24")])
    assert [record.ip for record in quiet] == ["10.0.0.8"]  # Reserved addresses needn't answer


def test_loopback_subnets(store):
    network = store.add_network("Lab")
    pool = store.add_subnet(network.id, "10.0.0.0/29", "Loopbacks", loopbacks=True)
    assert pool.special_addresses() == {}
    assert str(store.next_free(pool)) == "10.0.0.0"  # The first and last addresses can be handed out too
    for last in range(7):
        store.set_address(network.id, f"10.0.0.{last}", USED, f"rtr{last}")
    assert str(store.next_free(pool)) == "10.0.0.7"
    with pytest.raises(IpamError, match="no gateway"):
        store.add_subnet(network.id, "10.0.1.0/30", loopbacks=True, gateway="10.0.1.1")
    with pytest.raises(IpamError, match="no gateway"):
        store.update_subnet(pool.id, gateway="10.0.0.1")

    # Turning a subnet into loopbacks drops its gateway; turning it back gives the network and broadcast back
    lan = store.add_subnet(network.id, "10.0.2.0/29", "LAN", gateway="10.0.2.1")
    lan = store.update_subnet(lan.id, loopbacks=True)
    assert lan.loopbacks and lan.gateway == ""
    lan = store.update_subnet(lan.id, loopbacks=False)
    assert set(lan.special_addresses().values()) == {"Network", "Broadcast"}
    assert store.subnet(lan.id).loopbacks is False


def test_database_from_before_loopbacks_is_upgraded(tmp_path):
    import sqlite3
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.executescript(SCHEMA_V1)
    old.close()
    upgraded = IpamStore(path, user="tester")
    network = upgraded.add_network("Lab")
    assert upgraded.add_subnet(network.id, "10.0.0.0/30", loopbacks=True).loopbacks
    assert upgraded.get_meta("schema") == "7"  # The VLAN, placement, role, asset and target tables were added too
    assert upgraded.db.execute("SELECT COUNT(*) FROM vlans").fetchone()[0] == 0
    upgraded.close()


SCHEMA_V1 = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
INSERT INTO meta VALUES ('schema', '1');
CREATE TABLE subnets (
    id TEXT PRIMARY KEY, network_id TEXT NOT NULL, cidr TEXT NOT NULL, sort_key TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '', gateway TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
    fields TEXT NOT NULL DEFAULT '{}',
    version INTEGER NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL, deleted INTEGER NOT NULL DEFAULT 0);
"""


def test_loopback_rows_outside_one_block_keep_their_name():
    sheet = parse_page("Page 1", page(
        ["11AB", "HQ", "2025-04-25", "", "", "02"],
        ["Detailed Info"],
        ["POP Loopback", "68900", "10.0.0.2", "255.255.255.255", "", "Y", "POP-XT2R"],
        ["", "", "10.0.0.3", "255.255.255.255", "", "Y", "POP-XFWH"],
        ["", "", "10.0.0.4", "255.255.255.255", "", "", ""],
        ["", "", "10.0.0.5", "255.255.255.255", "", "Y", "Network"],
        ["End"],
    ))
    found = [(difference.cidr, difference.detail.name, difference.detail.loopbacks)
             for difference in sheet.differences]
    assert found == [("10.0.0.2/31", "POP Loopback", True), ("10.0.0.4/31", "POP Loopback", True)]
    assert not sheet.problems
    assert [address.ip for address in sheet.addresses] == ["10.0.0.2", "10.0.0.3"]


def test_search_in_one_field(store):
    network = store.add_network("A")
    store.add_subnet(network.id, "10.0.0.0/24", "68890 HSM IN-CT", fields={"Telephony Rng": "68900"})
    store.add_subnet(network.id, "10.0.1.0/24", "MAIN IN-CT", "", "for 68890", fields={"Telephony Rng": "68890"})
    store.set_address(network.id, "10.0.1.7", USED, "sw-68890", mac="00-68-89-00-00-01", fields={"Rack": "68890"})

    def found(text, match):
        return {(subnet.cidr if subnet else None, address.ip if address else None)
                for _, subnet, address in store.search(text, match=match)}

    assert len(found("68890", "anywhere")) == 3
    assert found("68890", "Telephony Rng") == {("10.0.1.0/24", None)}  # Not the subnet with 68890 in its name
    assert found("68890", NAME) == {("10.0.0.0/24", None), ("10.0.1.0/24", "10.0.1.7")}
    assert found("68890", DESCRIPTION) == {("10.0.1.0/24", None)}
    assert found("00-68-89", MAC) == {("10.0.1.0/24", "10.0.1.7")}
    assert found("68890", "Rack") == {("10.0.1.0/24", "10.0.1.7")}
    assert found("10.0.1", VALUE) == {("10.0.1.0/24", None), ("10.0.1.0/24", "10.0.1.7")}
    assert found("10.0.1.7", NAME) == set()  # An address typed in, but only names are searched
    assert found("68890", "No such detail") == set()
    assert store.detail_names() == ["Rack", "Telephony Rng"]
