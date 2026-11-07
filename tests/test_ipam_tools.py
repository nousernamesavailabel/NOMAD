"""IPAM tools: checking data, comparing with the workbook, exporting to it, free blocks, changing many at once,
what sweeps found (last seen), and picking an address for an adapter."""
import ipaddress
import os
import time
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication  # noqa: E402

from nomad.ipam.checks import ERROR, INFO, WARNING, check_network  # noqa: E402
from nomad.ipam.compare import ADD, ADDRESS, NETWORK, REMOVE, SUBNET, UPDATE, apply_changes, compare_network  # noqa
from nomad.ipam.spreadsheet import DETAIL, SUMMARY, import_page, import_plan, parse_page, read_pages  # noqa: E402
from nomad.ipam.store import RESERVED, USED, IpamStore, parse_subnet  # noqa: E402
from nomad.ipam.workbook import export_workbook, outside_subnets  # noqa: E402
from nomad.ui.ipam_tab import AddressModel, SweepResults  # noqa: E402
from nomad.ui.ipam_tools import AddressPickerDialog, apply_to_addresses, apply_to_subnets  # noqa: E402


@pytest.fixture
def store(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    yield store
    store.close()


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def sample_network(store):
    network = store.add_network("11AB SIPR", fields={"Unit": "11AB", "Location": "HQ", "Revision date": "2026-04-23",
                                                     "Revision": "02", "Enclave": "SIPR", "ASN": "65139",
                                                     "Imported from": "SIPR Template"})
    store.add_subnet(network.id, "10.0.0.0/29", "68900 MAIN Loopback", fields={"Telephony Rng": "68900"},
                     loopbacks=True)
    store.add_subnet(network.id, "10.0.0.8/29", "68900 MAIN IN-CT", "10.0.0.9", "In-CT",
                     {"Telephony Rng": "68900"})
    store.add_subnet(network.id, "10.1.0.0/16", "Vlan 7")
    store.add_subnet(network.id, "10.2.0.0/22", "Block")
    store.add_subnet(network.id, "10.2.1.0/24", "Inside the block", fields={"Telephony Rng": "68910",
                                                                           "Vlan": "101"})
    store.add_subnet(network.id, "10.3.0.0/30", "")
    for ip, status, name in (("10.0.0.0", RESERVED, "RTR1"), ("10.0.0.7", USED, "RTR8"), ("10.0.0.9", RESERVED, "GW"),
                             ("10.0.0.10", USED, ""), ("10.1.2.3", USED, "big-host"), ("10.2.0.5", USED, "in-block"),
                             ("10.2.1.9", RESERVED, "nested-host"), ("10.3.0.1", USED, "p2p")):
        store.set_address(network.id, ip, status, name)
    return network


# --------------------------------------------------------------------- Checking data

def test_check_data_finds_likely_mistakes(store):
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.0/24", "68900 MAIN IN-CT", fields={"Telephony Rng": "68890"})
    store.add_subnet(network.id, "10.0.1.0/24", "rojason.")
    store.add_subnet(network.id, "10.0.2.0/29", "68900 HSM CP Loopback")
    store.add_subnet(network.id, "10.0.3.0/24", "68900 Voice", "10.0.3.77", fields={"Telephony Rng": "CAN"})
    store.add_subnet(network.id, "10.0.4.0/24", "")
    store.set_address(network.id, "10.0.2.0", RESERVED, "HSM-JB-XT2R")  # On the network address
    store.set_address(network.id, "10.9.9.9", USED, "stray")  # In no subnet
    store.set_address(network.id, "10.0.0.5", RESERVED, "")  # Reserved for nothing named
    store.set_address(network.id, "10.0.0.6", USED, "a", "00-11-22-33-44-55")
    store.set_address(network.id, "10.0.0.7", USED, "b", "00:11:22:33:44:55")  # The same MAC

    found = {(finding.severity, finding.check, finding.where) for finding in check_network(store, network.id)}
    assert (WARNING, "Name and Telephony Rng differ", "10.0.0.0/24 68900 MAIN IN-CT") in found
    assert (WARNING, "Name looks out of place", "10.0.1.0/24 rojason.") in found
    assert (WARNING, "Named loopback but not a loopback subnet", "10.0.2.0/29 68900 HSM CP Loopback") in found
    assert (ERROR, "Address on the network or broadcast address", "10.0.2.0") in found
    assert (WARNING, "Address outside every subnet", "10.9.9.9") in found
    assert (INFO, "Reserved without a name", "10.0.0.5") in found
    assert (INFO, "Gateway in an unusual place", "10.0.3.0/24 68900 Voice") in found
    assert (INFO, "Subnet has no name", "10.0.4.0/24") in found
    assert {where for _, check, where in found if check == "Same MAC on more than one address"} == \
        {"10.0.0.6", "10.0.0.7"}
    assert not any("68900 Voice" in where and check == "Name and Telephony Rng differ" for _, check, where in found)
    assert check_network(store, network.id)[0].severity == ERROR  # Most serious first


def test_clean_network_has_no_findings(store):
    network = store.add_network("Clean")
    store.add_subnet(network.id, "10.0.0.0/24", "68900 LAN", "10.0.0.1", fields={"Telephony Rng": "68900"})
    store.add_subnet(network.id, "10.0.1.0/29", "68900 Loopback", loopbacks=True)
    store.set_address(network.id, "10.0.1.0", RESERVED, "RTR1")
    assert check_network(store, network.id) == []


# --------------------------------------------------------------------- Exporting to the workbook layout

def round_trip(store, network, tmp_path):
    path = str(tmp_path / "export.xlsx")
    [title] = export_workbook(path, [(store, network)])
    [(page, rows)] = read_pages(path)
    assert page == title
    return parse_page(page, rows)


def test_export_imports_back_the_same(store, tmp_path):
    network = sample_network(store)
    sheet = round_trip(store, network, tmp_path)
    assert sheet.title == "SIPR Template"  # The page it was imported from
    assert not sheet.differences and not sheet.problems and not sheet.gateway_fixes
    assert compare_network(store, network.id, import_plan(sheet, network.name)) == []

    copy = IpamStore(str(tmp_path / "copy.db"), user="tester")
    imported = import_page(copy, sheet, "Copy")
    assert [(subnet.cidr, subnet.name, subnet.gateway, subnet.fields, subnet.loopbacks)
            for subnet in copy.subnets(imported.id)] == \
        [(subnet.cidr, subnet.name, subnet.gateway, subnet.fields, subnet.loopbacks)
         for subnet in store.subnets(network.id)]
    assert [(address.ip, address.status, address.name) for address in copy.addresses(imported.id)] == \
        [(address.ip, address.status, address.name) for address in store.addresses(network.id)]
    assert copy.network(imported.id).fields["ASN"] == "65139"
    copy.close()


def test_export_keeps_mistakes_and_reports_what_it_cannot_hold(store, tmp_path):
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.8/29", "HSM CP Loopback")  # A /29 that's really loopbacks
    store.set_address(network.id, "10.0.0.8", RESERVED, "HSM-JB-XT2R")  # So a device sits on its network address
    store.set_address(network.id, "10.0.0.15", USED, "on-broadcast")
    store.set_address(network.id, "10.9.9.9", USED, "stray")
    sheet = round_trip(store, network, tmp_path)
    assert {(address.ip, address.name) for address in sheet.addresses} == \
        {("10.0.0.8", "HSM-JB-XT2R"), ("10.0.0.15", "on-broadcast")}
    assert [address.ip for address in outside_subnets(store, network)] == ["10.9.9.9"]


def test_export_keeps_unit_details_in_their_columns(store, tmp_path):
    network = store.add_network("Lab", fields={"Revision date": "2026-09-01", "Revision": "03", "ASN": "64512"})
    store.add_subnet(network.id, "10.0.0.0/24", "LAN")
    sheet = round_trip(store, network, tmp_path)
    assert sheet.fields == {"Revision date": "2026-09-01", "Revision": "03", "ASN": "64512"}  # No Unit or Location


# --------------------------------------------------------------------- Comparing with the workbook

def edited_workbook_plan(store, network, tmp_path):
    """The network exported, then changed as someone would change the spreadsheet."""
    sheet = round_trip(store, network, tmp_path)
    plan = import_plan(sheet, network.name)
    plan["fields"]["Revision"] = "03"
    for subnet in plan["subnets"]:
        if subnet["cidr"] == "10.0.0.8/29":
            subnet["name"] = "68900 MAIN IN-CT (renamed)"
        if subnet["cidr"] == "10.1.0.0/16":
            subnet["name"] = "Vlan 7 renamed in the sheet"
    plan["subnets"] = [subnet for subnet in plan["subnets"] if subnet["cidr"] != "10.3.0.0/30"]
    plan["subnets"].append({"cidr": "10.4.0.0/24", "name": "New in the sheet", "gateway": "10.4.0.1",
                            "description": "", "fields": {}, "loopbacks": False})
    plan["addresses"] = [address for address in plan["addresses"] if address["ip"] != "10.1.2.3"]
    plan["addresses"].append({"ip": "10.4.0.20", "status": USED, "name": "new-host"})
    for address in plan["addresses"]:
        if address["ip"] == "10.0.0.7":
            address["name"] = "RTR8-renamed"
    return plan


def test_compare_lists_differences_and_protects_nomad_edits(store, tmp_path):
    network = sample_network(store)
    vlan = next(subnet for subnet in store.subnets(network.id) if subnet.cidr == "10.1.0.0/16")
    store.update_subnet(vlan.id, name="Vlan 7 fixed in NOMAD")  # Edited since the import
    plan = edited_workbook_plan(store, network, tmp_path)
    changes = {(change.kind, change.action, change.key): change for change in
               compare_network(store, network.id, plan)}

    assert changes[(NETWORK, UPDATE, "Revision")].chosen
    assert changes[(SUBNET, UPDATE, "10.0.0.8/29")].chosen
    assert not changes[(SUBNET, UPDATE, "10.1.0.0/16")].chosen  # NOMAD's edit is probably newer
    assert "Changed in NOMAD" in changes[(SUBNET, UPDATE, "10.1.0.0/16")].note
    assert not changes[(SUBNET, REMOVE, "10.3.0.0/30")].chosen  # Only IPAM has it: kept unless ticked
    assert changes[(SUBNET, ADD, "10.4.0.0/24")].chosen
    assert changes[(ADDRESS, ADD, "10.4.0.20")].chosen
    assert changes[(ADDRESS, UPDATE, "10.0.0.7")].describe() == "Name: RTR8 → RTR8-renamed"
    assert not changes[(ADDRESS, REMOVE, "10.1.2.3")].chosen

    made, failed = apply_changes(store, network.id, list(changes.values()))
    assert failed == [] and made == 5
    subnets = {subnet.cidr: subnet for subnet in store.subnets(network.id)}
    assert subnets["10.0.0.8/29"].name == "68900 MAIN IN-CT (renamed)"
    assert subnets["10.1.0.0/16"].name == "Vlan 7 fixed in NOMAD"
    assert subnets["10.4.0.0/24"].gateway == "10.4.0.1" and "10.3.0.0/30" in subnets
    assert store.address(network.id, "10.4.0.20").name == "new-host"
    assert store.address(network.id, "10.1.2.3") is not None
    assert store.network(network.id).fields["Revision"] == "03"


def test_compare_does_not_bring_back_what_nomad_deleted(store, tmp_path):
    network = sample_network(store)
    plan = import_plan(round_trip(store, network, tmp_path), network.name)
    p2p = next(subnet for subnet in store.subnets(network.id) if subnet.cidr == "10.3.0.0/30")
    store.delete_subnet(p2p.id)
    store.free_address(network.id, "10.1.2.3")
    changes = {(change.kind, change.action, change.key): change for change in
               compare_network(store, network.id, plan)}
    assert not changes[(SUBNET, ADD, "10.3.0.0/30")].chosen
    assert not changes[(ADDRESS, ADD, "10.1.2.3")].chosen
    assert "Marked free in NOMAD" in changes[(ADDRESS, ADD, "10.1.2.3")].note


def test_compare_with_the_original_workbook_after_import(store, tmp_path):
    from test_ipam import sample_page
    sheet = parse_page("Page 1", sample_page())
    for difference in sheet.differences:
        difference.choice = DETAIL if difference.detail else SUMMARY
    network = import_page(store, sheet, "11AB")
    assert compare_network(store, network.id, import_plan(sheet, "11AB")) == []  # Nothing changed since


# --------------------------------------------------------------------- Free blocks

def test_free_blocks(store):
    network = store.add_network("Lab")
    block = store.add_subnet(network.id, "10.0.0.0/24", "Block", "10.0.0.254")
    store.add_subnet(network.id, "10.0.0.0/26", "Used subnet")
    store.set_address(network.id, "10.0.0.130", USED, "host")
    blocks, free = store.free_blocks(block)
    assert free == 256 - 64 - 1 - 1
    assert str(blocks[0]) == "10.0.0.64/26"  # Largest first
    assert "10.0.0.130/32" not in [str(found) for found in blocks]
    blocks, _ = store.free_blocks(block, 28)
    assert [str(found) for found in blocks] == ["10.0.0.64/28", "10.0.0.80/28", "10.0.0.96/28", "10.0.0.112/28",
                                                "10.0.0.144/28", "10.0.0.160/28", "10.0.0.176/28", "10.0.0.192/28",
                                                "10.0.0.208/28", "10.0.0.224/28"]  # Not .128 (host), .240 (gateway)


# --------------------------------------------------------------------- Changing many at once

def test_changing_several_addresses_and_subnets(store):
    network = store.add_network("Lab")
    first = store.add_subnet(network.id, "10.0.0.0/24", "LAN", "10.0.0.1")
    second = store.add_subnet(network.id, "10.0.1.0/29", "Loops", fields={"Telephony Rng": "1"})
    store.set_address(network.id, "10.0.0.5", USED, "sw1", "aa-bb", "old")
    changed, failed = apply_to_addresses(store, network.id, [ipaddress.ip_address("10.0.0.5"),
                                                             ipaddress.ip_address("10.0.0.6")],
                                         {"status": RESERVED, "detail": ("Rack", "R1")})
    assert (changed, failed) == (2, [])
    kept = store.address(network.id, "10.0.0.5")
    assert (kept.status, kept.name, kept.mac, kept.description, kept.fields) == (RESERVED, "sw1", "aa-bb", "old",
                                                                                 {"Rack": "R1"})
    assert store.address(network.id, "10.0.0.6").status == RESERVED  # A free one is recorded

    changed, failed = apply_to_subnets(store, [first, second], {"detail": ("Telephony Rng", "68900"),
                                                                "loopbacks": True})
    assert (changed, failed) == (2, [])
    first, second = store.subnets(network.id)
    assert first.fields == second.fields == {"Telephony Rng": "68900"}
    assert first.loopbacks and first.gateway == ""
    apply_to_subnets(store, [first], {"detail": ("Telephony Rng", "")})
    assert store.subnet(first.id).fields == {}


# --------------------------------------------------------------------- What sweeps found (last seen)

def test_sweep_results_last_across_sessions(store):
    network = store.add_network("Lab")
    swept = time.time() - 3600
    store.record_sightings(network.id, [{"ip": "10.0.0.5", "seen": swept, "rtt": 3, "mac": "aa", "name": "sw1"},
                                        {"ip": "10.0.0.6", "seen": swept - 86400 * 3, "rtt": 1, "mac": "", "name": ""}],
                           [{"cidr": "10.0.0.0/24", "started": swept - 10, "finished": swept + 10}])
    results = SweepResults.load(store, network.id)
    five, six = ipaddress.ip_address("10.0.0.5"), ipaddress.ip_address("10.0.0.6")
    assert results.result(five)[0] == "answered" and results.names[five] == "sw1"
    kind, when, last_seen = results.result(six)  # Seen days ago, silent in the latest sweep
    assert kind == "silent" and last_seen == pytest.approx(swept - 86400 * 3)
    assert results.result(ipaddress.ip_address("10.0.0.7"))[0] == "silent"
    assert results.result(ipaddress.ip_address("10.9.0.1")) is None  # Never swept
    assert results.current(five) == (3, "aa") and results.current(six) is None

    # A new sweep: covered addresses show only what it finds; then it's kept
    results.start(parse_subnet("10.0.0.0/24"))
    assert results.result(five) is None  # Not reached yet
    results.found("10.0.0.6", 2, "cc")
    results.add_name("10.0.0.6", "sw2")
    swept_range = results.finish(parse_subnet("10.0.0.0/24"))
    store.record_sightings(network.id, results.take_unsaved(), [swept_range])
    again = SweepResults.load(store, network.id)
    assert again.result(six)[0] == "answered" and again.names[six] == "sw2"
    assert again.result(five)[0] == "silent" and again.result(five)[2] == pytest.approx(swept)


def test_swept_mac_shows_where_ipam_has_none(app, store):
    network = store.add_network("Lab")
    store.add_subnet(network.id, "10.0.0.0/24", "LAN")
    store.set_address(network.id, "10.0.0.5", USED, "blank", "")
    store.set_address(network.id, "10.0.0.6", USED, "kept", "AA-AA-AA-AA-AA-AA")
    results = SweepResults()
    results.start(parse_subnet("10.0.0.0/24"))
    results.found("10.0.0.5", 3, "BB-BB-BB-BB-BB-BB")
    results.found("10.0.0.6", 3, "CC-CC-CC-CC-CC-CC")
    results.finish(parse_subnet("10.0.0.0/24"))
    model = AddressModel()
    recorded = {ipaddress.ip_address(item.ip): item for item in store.addresses(network.id)}
    model.load(ipaddress.ip_network("10.0.0.0/24"), recorded, {}, [], False, sweep=results)
    macs = {model.data(model.index(row, 0)): model.data(model.index(row, 4)) for row in range(model.rowCount())}
    assert macs == {"10.0.0.5": "BB-BB-BB-BB-BB-BB", "10.0.0.6": "AA-AA-AA-AA-AA-AA"}  # IPAM's own MAC wins


# --------------------------------------------------------------------- An address for an adapter

def test_address_picker_starts_with_the_adapters_subnet(app, store):
    sample_network(store)
    other = store.add_network("Other")
    store.add_subnet(other.id, "192.168.1.0/24", "Home", "192.168.1.1")
    store.set_address(other.id, "192.168.1.2", USED, "printer")
    adapter = SimpleNamespace(ipv4=[ipaddress.ip_interface("192.168.1.50/24")], gateways4=["192.168.1.1"])
    dialog = AddressPickerDialog(None, [("Local", store)], adapter)
    _, chosen_network, subnet, address = dialog.choice()
    assert (chosen_network.name, subnet.cidr, str(address)) == ("Other", "192.168.1.0/24", "192.168.1.3")
    assert dialog.gateway_label.text() == "192.168.1.1"
    dialog.address_input.setText("192.168.1.2")
    assert not dialog.use_button.isEnabled() and "printer" in dialog.status_label.text()
    dialog.address_input.setText("192.168.1.0")
    assert not dialog.use_button.isEnabled()  # The network address
    dialog.address_input.setText("192.168.1.99")
    assert dialog.use_button.isEnabled()
    dialog.network_combo.setCurrentIndex(dialog.network_combo.findText("11AB SIPR"))
    subnets = [dialog.subnet_combo.itemData(index).cidr for index in range(dialog.subnet_combo.count())]
    assert "10.0.0.0/29" not in subnets and "10.0.0.8/29" in subnets  # Loopbacks aren't for adapters
