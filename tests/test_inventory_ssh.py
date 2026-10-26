"""Reading a device's hardware at its command line (show inventory, show version) when its SNMP doesn't say, and
keeping it on the map and in the asset list."""
from nomad import hostinfo
from nomad.ipam.asset_compare import NEW, UPDATE, apply, network_sightings, plan, sightings
from nomad.ipam.assets import AssetStore
from nomad.ipam.store import IpamStore
from nomad.netmap import hardware, inventory_ssh
from nomad.netmap.model import NO_SNMP, ROUTER, SNMP, SSH_READ, SWITCH, Device, NetworkMap, apply_ssh_hardware

CAT9K_INVENTORY = """
NAME: "c93xx Stack", DESCR: "c93xx Stack"
PID: C9300-48P         , VID: V02  , SN: FOC1111A1AA

NAME: "Switch 1", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FOC1111A1AA

NAME: "Switch 1 - Power Supply A", DESCR: "Switch 1 - Power Supply A"
PID: PWR-C1-715WAC     , VID: V02  , SN: LIT1111

NAME: "Switch 1 FRU Uplink Module 1", DESCR: "8x10G Uplink Module"
PID: C9300-NM-8X       , VID: V02  , SN: FOC1111NM01

NAME: "Te1/1/1", DESCR: "SFP-10GBase-SR"
PID: SFP-10G-SR          , VID: V03  , SN: AVM1111

NAME: "Switch 2", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FOC2222B2BB

NAME: "Switch 2 - Power Supply A", DESCR: "Switch 2 - Power Supply A"
PID: PWR-C1-715WAC     , VID: V02  , SN: LIT2222

NAME: "Switch 2 - Fan - FAN 1", DESCR: "Switch 2 - Fan - FAN 1"
PID: FAN-T1            , VID:      , SN:
"""

CAT9K_VERSION = """Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.9.1r, RELEASE SOFTWARE (P)

acc1 uptime is 3 weeks, 2 days, 4 hours, 12 minutes
Base Ethernet MAC Address          : 70:1f:53:00:10:00
Motherboard Serial Number          : FOC1111MB00
Model Number                       : C9300-48P
System Serial Number               : FOC1111A1AA

Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
*    1 65    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL
     2 65    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL


Switch 02
---------
Switch uptime                      : 3 weeks, 2 days, 4 hours, 10 minutes
Base Ethernet MAC Address          : 70:1f:53:00:20:00
Motherboard Serial Number          : FOC2222MB00
Model Number                       : C9300-48P
System Serial Number               : FOC2222B2BB
"""

ISR_INVENTORY = """NAME: "Chassis", DESCR: "Cisco ISR4331 Chassis"
PID: ISR4331/K9        , VID: V04  , SN: FDO2213A0BC

NAME: "Power Supply Module 0", DESCR: "250W AC Power Supply for Cisco ISR 4330"
PID: PWR-4330-AC       , VID: V02  , SN: PST2211B1CD

NAME: "Fan Tray", DESCR: "Cisco ISR4330 Fan Assembly"
PID: ACS-4330-FANASSY  , VID:      , SN:

NAME: "module 0", DESCR: "Cisco ISR4331 Built-In NIM controller"
PID: ISR4331/K9        , VID:      , SN:

NAME: "NIM subslot 0/2", DESCR: "NIM-ES2-4"
PID: NIM-ES2-4         , VID: V01  , SN: FOC22014XYZ

NAME: "subslot 0/0 transceiver 0", DESCR: "GE T"
PID: GLC-TE              , VID: V01  , SN: APC1234ABCD

NAME: "module R0", DESCR: "Cisco ISR4331 Route Processor"
PID: ISR4331/K9        , VID: V04  , SN: FDO2213A0BC
"""

ISR_VERSION = """Cisco IOS XE Software, Version 16.09.05
Cisco IOS Software [Fuji], ISR Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.9.5, RELEASE SOFTWARE (fc1)
wan-rtr1 uptime is 1 year, 3 weeks
cisco ISR4331/K9 (1RU) processor with 1795999K/6147K bytes of memory.
Processor board ID FDO2213A0BC
"""

NXOS_INVENTORY = """NAME: "Chassis",  DESCR: "Nexus9000 C93180YC-EX chassis"
PID: N9K-C93180YC-EX     ,  VID: V03  ,  SN: FDO21330XYZ

NAME: "Slot 1",  DESCR: "48x10/25G + 6x40/100G Ethernet Module"
PID: N9K-C93180YC-EX     ,  VID: V03  ,  SN: FDO21330XYZ

NAME: "Power Supply 1",  DESCR: "Nexus9000 C93180YC-EX chassis Power Supply"
PID: NXA-PAC-650W-PE     ,  VID: V01  ,  SN: ART2134F0AB

NAME: "Fan 1",  DESCR: "Nexus9000 C93180YC-EX chassis Fan Module"
PID: NXA-FAN-30CFM-B     ,  VID: V01  ,  SN: N/A

NAME: "Ethernet1/49",  DESCR: "Cisco QSFP 100G SR4 Transceiver"
PID: QSFP-100G-SR4-S     ,  VID: V03  ,  SN: AVF2101XYZ1
"""

NXOS_VERSION = """Cisco Nexus Operating System (NX-OS) Software
TAC support: http://www.cisco.com/tac
Software
  BIOS: version 07.69
  NXOS: version 9.3(8)
  BIOS compile time:  04/08/2021
Hardware
  cisco Nexus9000 C93180YC-EX chassis
  Device name: leaf1
Kernel uptime is 12 day(s), 3 hour(s), 2 minute(s), 9 second(s)
"""

ASA_INVENTORY = """Name: "Chassis", DESCR: "ASA 5516-X with FirePOWER services, 8GE, AC, DES"
PID: ASA5516           , VID: V05     , SN: JAD2035XYZW

Name: "Storage Device 1", DESCR: "ASA 5516-X SSD"
PID: ASA5516-SSD       , VID: N/A     , SN: MSA2033ABCD
"""

ASA_VERSION = """Cisco Adaptive Security Appliance Software Version 9.16(3)19
SSP Operating System Version 2.10(1.180)
Device Manager Version 7.18(1)

Compiled on Fri 25-Feb-22 11:18 GMT by builders
System image file is "disk0:/asa9-16-3-19-lfbff-k8.SPA"
Config file at boot was "startup-config"

fw1 up 30 days 4 hours
"""

C2960_INVENTORY = """NAME: "1", DESCR: "WS-C2960X-48FPD-L"
PID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC1922X1AB

NAME: "Switch 1 - FlexStackPlus Module", DESCR: "Stacking Module"
PID: C2960X-STACK      , VID: V01  , SN: FOC19221XYZ
"""

C2960_VERSION = """Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)
idf2 uptime is 10 weeks, 1 day
Base ethernet MAC Address       : A0:EC:F9:00:00:80
"""


def summary(parts):
    return [(part["class"], part["name"], part["model"], part["serial"]) for part in parts]


def test_a_stack_from_show_inventory_and_show_version():
    parts, info = inventory_ssh.device_hardware(CAT9K_INVENTORY, CAT9K_VERSION)
    members = hardware.chassis(parts)
    assert [(part["name"], part["serial"], part["position"], part["mac"]) for part in members] == [
        ("Switch 1", "FOC1111A1AA", 1, "70-1F-53-00-10-00"), ("Switch 2", "FOC2222B2BB", 2, "70-1F-53-00-20-00")]
    by_serial = {part["serial"]: part for part in parts if part["class"] != hardware.CHASSIS and part["serial"]}
    assert by_serial["LIT2222"]["class"] == hardware.POWER and by_serial["LIT2222"]["chassis"] == members[1]["index"]
    assert by_serial["FOC1111NM01"]["class"] == hardware.MODULE
    assert by_serial["AVM1111"]["class"] == hardware.TRANSCEIVER and by_serial["AVM1111"]["chassis"] == \
        members[0]["index"]
    assert not any(part["name"] == "c93xx Stack" for part in parts)  # The stack itself isn't hardware
    assert any(part["class"] == hardware.FAN and part["serial"] == "" for part in parts)
    assert (info["software"], info["hostname"], info["os"]) == ("17.09.04a", "acc1", "Cisco IOS XE Software")


def test_a_router_a_nexus_an_asa_and_an_old_switch():
    parts, info = inventory_ssh.device_hardware(ISR_INVENTORY, ISR_VERSION)
    assert summary(hardware.chassis(parts)) == [(hardware.CHASSIS, "Chassis", "ISR4331/K9", "FDO2213A0BC")]
    kinds = {part["name"]: part["class"] for part in parts}
    assert kinds["Power Supply Module 0"] == hardware.POWER and kinds["Fan Tray"] == hardware.FAN
    assert kinds["subslot 0/0 transceiver 0"] == hardware.TRANSCEIVER and kinds["NIM subslot 0/2"] == hardware.MODULE
    assert (info["software"], info["hostname"]) == ("16.09.05", "wan-rtr1")

    parts, info = inventory_ssh.device_hardware(NXOS_INVENTORY, NXOS_VERSION)
    assert summary(hardware.chassis(parts)) == [(hardware.CHASSIS, "Chassis", "N9K-C93180YC-EX", "FDO21330XYZ")]
    kinds = {part["name"]: (part["class"], part["serial"]) for part in parts}
    assert kinds["Power Supply 1"] == (hardware.POWER, "ART2134F0AB") and kinds["Fan 1"] == (hardware.FAN, "")
    assert kinds["Ethernet1/49"][0] == hardware.TRANSCEIVER
    assert info["software"] == "9.3(8)" and info["hostname"] == ""  # Not "Kernel": the prompt says it, over SSH
    assert info["os"] == "Cisco Nexus Operating System (NX-OS) Software"

    parts, info = inventory_ssh.device_hardware(ASA_INVENTORY, ASA_VERSION)
    assert summary(hardware.chassis(parts)) == [(hardware.CHASSIS, "Chassis", "ASA5516", "JAD2035XYZW")]
    assert (info["software"], info["os"]) == ("9.16(3)19", "Cisco Adaptive Security Appliance Software")

    parts, info = inventory_ssh.device_hardware(C2960_INVENTORY, C2960_VERSION)
    [member] = hardware.chassis(parts)
    assert (member["serial"], member["mac"]) == ("FOC1922X1AB", "A0-EC-F9-00-00-80")
    assert info["software"] == "15.2(7)E4" and info["hostname"] == "idf2"


def test_show_version_alone_when_there_is_no_inventory():
    parts, info = inventory_ssh.device_hardware("", ISR_VERSION)
    assert summary(hardware.chassis(parts)) == [(hardware.CHASSIS, "", "ISR4331/K9", "FDO2213A0BC")]


class FakeShell:
    prompt = "acc1#"


class FakeAsker:
    """macssh.SshAsker, answering from canned output."""

    def __init__(self, answers, problem=""):
        self.answers, self.problem = answers, problem
        self.shells, self.problems, self.closed = {}, {}, False

    def __call__(self, logins, vault=None, known_hosts=None, trust_new=False):
        return self

    def run(self, address, commands, names=(), timeout=0):
        if self.problem:
            self.problems[address] = self.problem
            return None
        self.shells[address] = FakeShell()
        return self.answers.get(commands[0], "")

    def close(self):
        self.closed = True


def test_network_details_over_ssh():
    asker = FakeAsker({"show inventory": CAT9K_INVENTORY, "show version": CAT9K_VERSION})
    details = hostinfo.network_details("10.0.0.11", logins=None, asker_factory=asker)
    assert details.ok and asker.closed
    assert (details.hostname, details.serial, details.software) == ("acc1", "FOC1111A1AA, FOC2222B2BB", "17.09.04a")
    assert len(hardware.chassis(details.parts)) == 2
    failed = hostinfo.network_details("10.0.0.12", None, asker_factory=FakeAsker({}, "Authentication failed."))
    assert failed.error == "Authentication failed."
    nothing = hostinfo.network_details("10.0.0.13", None, asker_factory=FakeAsker({"show version": ""}))
    assert "didn't answer show inventory" in nothing.error


def network_map_with_unreadable_switch():
    network_map = NetworkMap()
    network_map.devices["acc1"] = Device(key="acc1", name="acc1", mgmt_ip="10.0.0.11", kind=SWITCH, source=NO_SNMP,
                                         platform="cisco C9300-48P")
    return network_map


def test_ssh_hardware_on_the_map_survives_crawls_that_dont_say(tmp_path):
    network_map = network_map_with_unreadable_switch()
    parts, info = inventory_ssh.device_hardware(CAT9K_INVENTORY, CAT9K_VERSION)
    device = network_map.devices["acc1"]
    apply_ssh_hardware(device, parts, info["software"])
    assert device.inventory_source == SSH_READ and device.software == "17.09.04a"
    # Mapped again: its SNMP still says nothing of its hardware (or it doesn't answer SNMP at all)
    again = network_map_with_unreadable_switch()
    again.carry_ssh_hardware(network_map)
    assert len(hardware.chassis(again.devices["acc1"].parts)) == 2
    # Crawl from Here: the same
    crawled = network_map_with_unreadable_switch()
    crawled.devices["acc1"].source = SNMP
    network_map.merge_crawl(crawled)
    assert network_map.devices["acc1"].inventory_source == SSH_READ
    # Its SNMP says, now: that counts
    from nomad.netmap.collect import DeviceTables, SystemInfo
    from nomad.netmap.crawl import apply_inventory
    tables = DeviceTables(info=SystemInfo())
    tables.inventory_read, tables.parts = True, [dict(hardware.blank_chassis("FOC9999"), index=1)]
    apply_inventory(network_map.devices["acc1"], tables)
    assert network_map.devices["acc1"].inventory_source == "" and \
        [part["serial"] for part in network_map.devices["acc1"].parts] == ["FOC9999"]


def test_what_it_said_over_ssh_is_brought_in_as_the_map_device(tmp_path):
    ipam = IpamStore(str(tmp_path / "ipam.db"), user="alice")
    store = AssetStore(ipam)
    network_map = network_map_with_unreadable_switch()
    network_map.devices["wan-rtr1"] = Device(key="wan-rtr1", name="wan-rtr1", mgmt_ip="10.0.0.1", kind=ROUTER)
    first = sightings(network_map)
    assert {sighting.serial for sighting in first} == {""}  # SNMP couldn't say
    stack_parts, _ = inventory_ssh.device_hardware(CAT9K_INVENTORY, CAT9K_VERSION)
    answers = [hostinfo.HostDetails("10.0.0.11", hostinfo.NETWORK, hostname="acc1", software="17.09.04a",
                                    parts=stack_parts),
               hostinfo.HostDetails("10.9.9.9", hostinfo.NETWORK, hostname="branch-rtr", model="ISR4331/K9",
                                    os="Cisco IOS XE Software", software="16.09.05",
                                    parts=inventory_ssh.device_hardware(ISR_INVENTORY, ISR_VERSION)[0])]
    found = network_sightings(answers, network_map)
    members = [sighting for sighting in found if sighting.serial.startswith("FOC") and not sighting.is_part]
    assert {(sighting.serial, sighting.slot, sighting.map_device) for sighting in members} == {
        ("FOC1111A1AA", "Switch 1", "acc1"), ("FOC2222B2BB", "Switch 2", "acc1")}
    branch = next(sighting for sighting in found if sighting.serial == "FDO2213A0BC")
    assert branch.kind == ROUTER and branch.map_device == "" and branch.hostname == "branch-rtr"  # Not on the map
    changes = plan(store, found)
    assert {change.action for change in changes} == {NEW}
    apply(store, changes, when="2026-10-26")
    assert store.by_serial("FOC2222B2BB").slot == "Switch 2"
    assert store.by_serial("FDO2213A0BC").mgmt_ip == "10.9.9.9"
    # The next crawl, whose SNMP still says nothing of acc1's hardware, doesn't make a serial-less acc1 of it, but
    # what it does say (an upgrade) reaches its members
    network_map.devices["acc1"].software = "17.12.1"
    later = {change.sighting.ref: change for change in plan(store, sightings(network_map))
             if change.sighting.map_device == "acc1"}
    assert set(later) == {"FOC1111A1AA", "FOC2222B2BB"}
    assert {change.action for change in later.values()} == {UPDATE}
    assert later["FOC1111A1AA"].changes == {"software": ("17.09.04a", "17.12.1")}
    assert not any(change.action == NEW for change in plan(store, sightings(network_map)) if
                   change.sighting.map_device == "acc1")
    ipam.close()
