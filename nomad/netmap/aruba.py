"""Aruba wireless: the access points an ArubaOS 8 Mobility Controller has, and the Wi-Fi clients on them, from the
controller's own MIBs (WLSX-WLAN-MIB, WLSX-USER-MIB, WLSX-SYSTEMEXT-MIB).

What ArubaOS 8.10 does, as walked from a controller:
- wlsxWlanAPTable is keyed by each AP's wired MAC, which is also the chassis ID its LLDP gives the switch it's
  plugged into: that's how an AP the controller lists is matched with the one a switch sees.
- An AP that's down is still listed, with its name, address, model and serial number (its software and uptime blank).
- wlsxUserTable (WLSX-USER-MIB) is keyed by the client's MAC and IPv4 address, in that order. (WLSX-SWITCH-MIB's
  older user table has the address backwards, so isn't used.) Wired users of the controller's own ports are in it
  too, marked wired.
- wlsxWlanStationTable gives each associated client's BSSID and SSID; wlanAPBssidTable, keyed by the AP's MAC, its
  radio and the BSSID, says which AP a BSSID is.
- ENTITY-MIB isn't answered, even by a virtual controller: the serial number is in WLSX-SYSTEMEXT-MIB
  (hardware.ARUBA_SERIAL), and the model in sysDescr.

The parsers take the (oid, Value) pairs a walk returns, like collect's, so they can be tested without a network.
"""
import re
from dataclasses import dataclass, field

from ..oui import format_mac
from .collect import ARUBA, classify, column, columns, mac_text, text
from .model import WLC

# wlsxWlanAPTable (index: the AP's MAC)
AP_ENTRY = f"{ARUBA}.2.2.1.5.2.1.4.1"
AP_IP, AP_NAME, AP_GROUP, AP_SERIAL, AP_UPTIME, AP_MODEL, AP_STATUS, AP_SOFTWARE = 2, 3, 4, 6, 12, 13, 19, 34
AP_COLUMNS = (AP_IP, AP_NAME, AP_GROUP, AP_SERIAL, AP_UPTIME, AP_MODEL, AP_STATUS, AP_SOFTWARE)
AP_UP = 1  # wlanAPStatus: 1 up, 2 down
# wlanAPBssidTable (index: AP MAC, radio, BSSID): its ESSID column, which says which AP and SSID each BSSID is
BSSID_ESSID = f"{ARUBA}.2.2.1.5.2.1.7.1.2"
# wlsxWlanStationTable (index: the client's MAC): the BSSID it's on, its VLAN, the SSID, and the AP's name
STATION_ENTRY = f"{ARUBA}.2.2.1.5.2.2.1"
STATION_BSSID, STATION_VLAN, STATION_ESSID, STATION_AP = 2, 7, 12, 20
STATION_COLUMNS = (STATION_BSSID, STATION_VLAN, STATION_ESSID, STATION_AP)
# wlsxUserTable (index: the client's MAC, its IPv4 address): user name, AP name, BSSID (as text), VLAN, wired
USER_ENTRY = f"{ARUBA}.2.2.1.4.1.2.1"
USER_NAME, USER_AP, USER_BSSID, USER_VLAN, USER_WIRED = 3, 10, 11, 22, 23
USER_COLUMNS = (USER_NAME, USER_AP, USER_BSSID, USER_VLAN, USER_WIRED)
USER_IS_WIRED = 1  # TruthValue
MODEL_IN_DESCR = re.compile(r"\(MODEL:\s*([^)]+)\)", re.IGNORECASE)
NO_ADDRESS = "0.0.0.0"
MACHINE_PREFIX = "host/"  # A user name that's a computer's (802.1X machine authentication): "host/PC-0142"
WIFI = "Wi-Fi"  # A client's "port" when its SSID isn't known


@dataclass
class AccessPoint:
    mac: str
    name: str = ""
    ip: str = ""
    group: str = ""
    model: str = ""
    serial: str = ""
    software: str = ""
    up: bool = False
    uptime: int = 0  # Seconds


@dataclass
class WirelessClient:
    mac: str
    ip: str = ""
    name: str = ""  # Its computer name, when it authenticated as the computer (host/...)
    user: str = ""  # The user name it authenticated with, when that's a person's
    ap: str = ""  # The AP's MAC, as the AP table keys it ("" when only its name is known)
    ap_name: str = ""
    ssid: str = ""
    vlan: int = 0


@dataclass
class Controller:
    """What a controller said of its APs and clients."""
    aps: list = field(default_factory=list)  # [AccessPoint]
    clients: list = field(default_factory=list)  # [WirelessClient]
    model: str = ""
    serial: str = ""


def is_controller(object_id, descr=""):
    """Whether a device that answered SNMP is an Aruba controller (worth asking for its APs)."""
    return object_id.startswith(ARUBA + ".") and classify(object_id, descr) == WLC


def controller_model(descr):
    """The model ArubaOS's sysDescr names: "ArubaOS (MODEL: ArubaMC-VA-US), Version 8.10..." -> "ArubaMC-VA-US"."""
    match = MODEL_IN_DESCR.search(descr or "")
    return match.group(1).strip() if match else ""


def ap_model(name):
    """The AP's model as Aruba writes it: the AP table's "635" is an "AP-635"."""
    name = (name or "").strip()
    return f"AP-{name}" if name[:1].isdigit() else name


def _mac_index(index):
    """A MAC from the first six numbers of a table index."""
    return format_mac(bytes(index[:6]).hex()) if len(index) >= 6 and all(0 <= part < 256 for part in index[:6]) \
        else ""


def _address(value):
    address = value.value if value is not None and isinstance(value.value, str) else text(value)
    return "" if address in ("", NO_ADDRESS) else address


def _number(value):
    return value.value if value is not None and isinstance(value.value, int) else 0


def _mac_value(value):
    """A MAC given as 6 bytes or as text ("54-F0-B1-3A-B0-10")."""
    return "" if value is None else mac_text(value.value) or format_mac(text(value))


def access_points(rows):
    """[AccessPoint] from the walked columns of wlsxWlanAPTable."""
    found = []
    for index, row in columns(rows, AP_ENTRY).items():
        mac = _mac_index(index)
        if not mac or len(index) != 6:
            continue
        found.append(AccessPoint(
            mac=mac, name=text(row.get(AP_NAME)), ip=_address(row.get(AP_IP)), group=text(row.get(AP_GROUP)),
            model=ap_model(text(row.get(AP_MODEL))), serial=text(row.get(AP_SERIAL)),
            software=text(row.get(AP_SOFTWARE)), up=_number(row.get(AP_STATUS)) == AP_UP,
            uptime=_number(row.get(AP_UPTIME)) // 100))
    return sorted(found, key=lambda ap: (ap.name.lower(), ap.mac))


def bssids(rows):
    """{BSSID: (AP MAC, SSID)} from wlanAPBssidTable's ESSID column."""
    found = {}
    for index, value in column(rows, BSSID_ESSID).items():
        if len(index) == 13:
            ap, bssid = _mac_index(index[:6]), _mac_index(index[7:])
            if ap and bssid:
                found[bssid] = (ap, text(value))
    return found


def user_name(name):
    """(computer name, user name) from what a client authenticated as: "host/PC-0142" is a computer."""
    name = (name or "").strip()
    if name.lower().startswith(MACHINE_PREFIX):
        return name[len(MACHINE_PREFIX):], ""
    return "", name


def clients(station_rows, user_rows, bssid_rows=(), aps=()):
    """[WirelessClient] from wlsxWlanStationTable (the clients associated now) and wlsxUserTable (their addresses and
    user names), with wlanAPBssidTable to tell which AP each is on. Wired users of the controller are left out."""
    by_bssid = bssids(bssid_rows)
    ap_names = {ap.name: ap.mac for ap in aps if ap.name}
    found = {}
    for index, row in columns(station_rows, STATION_ENTRY).items():
        mac = _mac_index(index)
        if not mac or len(index) != 6:
            continue
        bssid = _mac_value(row.get(STATION_BSSID))
        ap, ssid = by_bssid.get(bssid, ("", ""))
        ap_name = text(row.get(STATION_AP))
        found[mac] = WirelessClient(mac=mac, ap=ap or ap_names.get(ap_name, ""), ap_name=ap_name,
                                    ssid=text(row.get(STATION_ESSID)) or ssid, vlan=_number(row.get(STATION_VLAN)))
    for index, row in columns(user_rows, USER_ENTRY).items():
        mac = _mac_index(index)
        if not mac or len(index) != 10 or _number(row.get(USER_WIRED)) == USER_IS_WIRED:
            continue
        ip = ".".join(str(part) for part in index[6:])
        computer, person = user_name(text(row.get(USER_NAME)))
        client = found.get(mac)
        if client is None:
            bssid = _mac_value(row.get(USER_BSSID))
            ap, ssid = by_bssid.get(bssid, ("", ""))
            ap_name = text(row.get(USER_AP))
            client = found[mac] = WirelessClient(mac=mac, ap=ap or ap_names.get(ap_name, ""), ap_name=ap_name,
                                                 ssid=ssid, vlan=_number(row.get(USER_VLAN)))
        if ip != NO_ADDRESS and not client.ip:
            client.ip = ip
        client.name, client.user = client.name or computer, client.user or person
        client.vlan = client.vlan or _number(row.get(USER_VLAN))
    for client in found.values():
        if not client.ap_name and client.ap:
            client.ap_name = next((ap.name for ap in aps if ap.mac == client.ap), "")
    return sorted(found.values(), key=lambda client: client.mac)
