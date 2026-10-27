"""Bringing a network map's hardware into the asset list: what the map found (each chassis, phone and part, with its
serial number, model, hostname and software), matched with the assets recorded.

The serial number is what an asset is: found again under a new hostname it's renamed, running other software it was
upgraded, and a hostname (or stack member, or chassis slot) that now has a different serial number had its hardware
replaced: the old asset is marked Replaced, pointing at the new one. Hardware without a readable serial is matched by
its MAC address (a phone's; a chassis' base MAC), or by the map device and slot it is.

plan lists what would change as AssetChanges; the user ticks the ones to make (or the Assets page makes the ticked
ones by itself after a crawl) and apply makes them, all at once.
"""
import uuid
from dataclasses import dataclass, field, replace

from ..netmap import hardware
from ..netmap.collect import PHONE as MAP_PHONE, classify
from ..netmap.model import AP, FIREWALL, PHONE, ROUTER, SERVER, SWITCH, UNKNOWN, WLC, display_name
from .assets import IN_SERVICE, OUT_OF_SERVICE, PART_KINDS, REPLACED, STATUSES, is_part, label, today
from .store import serial_key

NEW, UPDATE, REPLACE, SAME, CONFLICT = "new", "update", "replace", "same", "conflict"
ACTION_LABELS = {NEW: "New", UPDATE: "Changed", REPLACE: "Replaced", SAME: "No change", CONFLICT: "Conflict"}
DEVICE_KINDS = {SWITCH, ROUTER, FIREWALL, WLC, AP, PHONE, SERVER, UNKNOWN}  # Map devices that become assets
COMPARED = ("hostname", "model", "maker", "software", "mgmt_ip", "mac", "kind", "slot", "map_device", "location",
            "serial", "parent_id")
FIELD_NAMES = {"hostname": "Hostname", "model": "Model", "maker": "Maker", "software": "Software",
               "mgmt_ip": "Management IP", "mac": "MAC", "kind": "Kind", "slot": "Slot", "map_device": "Map device",
               "location": "Location", "serial": "Serial", "parent_id": "In", "status": "Status"}
QUIET = {"map_device", "parent_id"}  # Changes worth making but not worth a line each


@dataclass
class Sighting:
    """One piece of hardware as a map has it."""
    ref: str  # Unique within the map: its serial, or where it is (map device and slot), or its MAC
    kind: str
    serial: str = ""
    model: str = ""
    maker: str = ""
    hostname: str = ""
    software: str = ""
    mgmt_ip: str = ""
    mac: str = ""
    slot: str = ""
    map_device: str = ""
    location: str = ""
    parent_ref: str = ""  # A part's chassis (its ref)

    @property
    def is_part(self):
        return self.kind in PART_KINDS

    def values(self):
        return {name: getattr(self, name) for name in ("kind", "serial", "model", "maker", "hostname", "software",
                                                        "mgmt_ip", "mac", "slot", "map_device", "location")}

    def describe(self):
        parts = [self.model, self.serial or (f"MAC {self.mac}" if self.mac else "no serial number")]
        if self.software:
            parts.append(f"software {self.software}")
        return ", ".join(part for part in parts if part)

    @property
    def name(self):
        return self.hostname + (f" {self.slot}" if self.slot else "") if self.hostname else (self.model or self.ref)


@dataclass
class AssetChange:
    action: str  # NEW, UPDATE, REPLACE, SAME or CONFLICT (only pointed out)
    sighting: Sighting
    asset: object = None  # The Asset as recorded (UPDATE, SAME), or the one replaced (REPLACE)
    changes: dict = field(default_factory=dict)  # {field: (recorded, found)}
    chosen: bool = True
    note: str = ""
    new_id: str = ""  # NEW and REPLACE: the id the new asset gets

    @property
    def can_apply(self):
        return self.action != CONFLICT

    def describe(self):
        if self.action == NEW:
            return self.sighting.describe()
        if self.action == REPLACE:
            old = self.asset
            return f"{old.model or 'Hardware'} {old.serial or '(no serial)'} replaced by " \
                   f"{self.sighting.model or 'hardware'} {self.sighting.serial}"
        if self.action == CONFLICT:
            return self.note
        shown = [f"{FIELD_NAMES[name]}: {before or '(none)'} → {after or '(none)'}"
                 for name, (before, after) in self.changes.items() if name not in QUIET]
        return "; ".join(shown) or ("Seen again" if self.action == SAME else "Where it is on the map")


# --------------------------------------------------------------------- What a map has

def chassis_slot(part, count):
    """A stack member's slot: its name ("Switch 2") when the device has more than one chassis, else ""."""
    if count < 2:
        return ""
    return part.get("name") or (f"Member {part['position']}" if part.get("position") else f"Chassis {part['index']}")


def part_slot(part):
    return part.get("name") or part.get("descr") or f"{hardware.PART_NAMES.get(part['class'], 'Part')} " \
                                                     f"{part['index']}"


def sightings(network_map, track_parts=True):
    """[Sighting] of every piece of hardware on a map: each device's chassis (a stack's members each), with their
    parts when track_parts, and the phones its switches see. Devices only drawn by hand, and computers, aren't."""
    found = []
    for key, device in sorted(network_map.devices.items()):
        if device.kind not in DEVICE_KINDS or (device.manual and not device.serial):
            continue
        found += device_sightings(key, device.kind, device.parts, display_name(device.name), device.software,
                                  device.mgmt_ip, network_map.device_group_label(key), device.platform,
                                  device.serial, device.mac, track_parts)
    for host in network_map.hosts:
        phone = classify(platform=host.platform) == MAP_PHONE or (host.name or "").upper().startswith("SEP")
        if not phone and not host.serial:
            continue
        switch = network_map.devices.get(host.device)
        where = f"{display_name(switch.name) if switch is not None else host.device} {host.port}".strip()
        serial = serial_key(host.serial)
        found.append(Sighting(serial or f"mac:{host.mac}", PHONE if phone else UNKNOWN, serial=serial,
                              model=host.platform, hostname=host.name, software=host.software, mgmt_ip=host.ip,
                              mac=host.mac, slot=where, location=network_map.device_group_label(host.device)))
    return found


def device_sightings(key, kind, parts, hostname="", software="", mgmt_ip="", location="", platform="", serial="",
                     mac="", track_parts=True):
    """[Sighting] of one device: each chassis (a stack's members each), and its parts with serial numbers when
    track_parts; one with no chassis read is one Sighting from what else is known of it. key: its map device ("" for
    one that isn't on a map)."""
    place = key or mgmt_ip
    common = dict(hostname=hostname, software=software, mgmt_ip=mgmt_ip, map_device=key, location=location)
    chassis = hardware.chassis(parts)
    if not chassis:
        if not hostname and not mgmt_ip:
            return []
        serial = serial_key(serial)
        return [Sighting(serial or f"{place}|", kind, serial=serial, model=platform, mac=mac, **common)]
    found, refs = [], {}
    for part in chassis:
        slot = chassis_slot(part, len(chassis))
        serial = serial_key(part["serial"])
        ref = serial or f"{place}|{slot}"
        refs[part["index"]] = ref
        found.append(Sighting(ref, kind, serial=serial, model=part["model"] or platform, maker=part["maker"],
                              mac=part.get("mac", ""), slot=slot, **common))
    if not track_parts:
        return found
    taken = set(refs.values())  # A router's route processor (R0) often has its chassis' serial number
    for part in parts:
        serial = serial_key(part["serial"])
        if part["class"] == hardware.CHASSIS or not serial or serial in taken:
            continue
        taken.add(serial)
        parent = refs.get(part["chassis"]) or (next(iter(refs.values())) if len(refs) == 1 else "")
        found.append(Sighting(serial, part["class"], serial=serial, model=part["model"] or part["descr"],
                              maker=part["maker"], hostname=hostname, software=part["software"],
                              slot=part_slot(part), map_device=key, location=location, parent_ref=parent))
    return found


def map_device_at(network_map, address):
    """The map device with this address (its management address first), or None."""
    if network_map is None or not address:
        return None
    devices = list(network_map.devices.values())
    return next((device for device in devices if device.mgmt_ip == address), None) or \
        next((device for device in devices if device.owns(address)), None)


def network_sightings(details, network_map=None, track_parts=True):
    """[Sighting] of what network devices said of themselves over SSH (hostinfo.HostDetails with parts): each the
    map device it is, when the open map has one at its address (so it's matched by where it is, as a crawl's are)."""
    found = []
    for item in details:
        if not item.ok or not item.parts:
            continue
        device = map_device_at(network_map, item.address)
        if device is not None:
            kind = device.kind if device.kind in DEVICE_KINDS else UNKNOWN
            found += device_sightings(device.key, kind, item.parts, display_name(device.name) or item.hostname,
                                      item.software or device.software, item.address,
                                      network_map.device_group_label(device.key), device.platform,
                                      track_parts=track_parts)
            continue
        kind = classify(descr=item.os, platform=item.model)
        found += device_sightings("", kind if kind in DEVICE_KINDS else UNKNOWN, item.parts, item.hostname,
                                  item.software, item.address, track_parts=track_parts)
    return found


def detail_sightings(details, kind):
    """[Sighting] of what servers or phones said of themselves (hostinfo.HostDetails, those that answered)."""
    found = []
    for item in details:
        if not item.ok:
            continue
        serial = serial_key(item.serial)
        software = item.software if kind == PHONE else " ".join(part for part in (item.os, item.software) if part)
        ref = serial or (f"mac:{item.mac}" if item.mac else f"ip:{item.address}")
        found.append(Sighting(ref, kind, serial=serial, model=item.model, maker=item.maker, hostname=item.hostname,
                              software=software, mgmt_ip=item.address, mac=item.mac))
    return found


# --------------------------------------------------------------------- Matching them with the assets recorded

def _same_place(asset, sighting, renamed):
    """Whether a recorded asset was where the sighting is: the same map device (or hostname) and slot, and both
    whole devices or both parts. renamed: {map device or hostname recorded: what it is on this map}, for devices
    renamed since (known by their other members' serial numbers)."""
    if (asset.kind in PART_KINDS) != sighting.is_part or asset.slot != sighting.slot:
        return False
    if asset.map_device and sighting.map_device:
        return renamed.get(asset.map_device, asset.map_device) == sighting.map_device
    hostname = asset.hostname.lower()
    if hostname and sighting.hostname:
        return renamed.get(hostname, hostname) == sighting.hostname.lower()
    # A server asked by its address (no map device, perhaps no hostname): the same address and kind
    return bool(asset.mgmt_ip) and asset.mgmt_ip == sighting.mgmt_ip and asset.kind == sighting.kind


def _says_nothing(sighting):
    """A whole device seen with nothing that tells its hardware: no serial number, MAC or slot."""
    return not sighting.is_part and not sighting.serial and not sighting.mac and not sighting.slot


def _macs_agree(asset, sighting):
    """Whether a MAC doesn't say they're different hardware: with no serial number on one side, another MAC (another
    phone on that port) is. With both serial numbers it's those that tell (a replaced chassis has another MAC)."""
    if not asset.mac or not sighting.mac or asset.mac == sighting.mac:
        return True
    return bool(asset.serial and sighting.serial)


def plan(store, found, user="", when=None):
    """How the assets recorded (store: an AssetStore-like) differ from what a map found (sightings'). Returns
    [AssetChange]: conflicts first, then replacements, new, changed and unchanged."""
    when = when or today()
    assets = store.assets()
    by_serial = {asset.serial: asset for asset in assets if asset.serial}
    by_mac = {asset.mac: asset for asset in assets if asset.mac and not asset.serial}
    deleted = store.deleted_serials()
    serials_found = {}
    for sighting in found:
        if sighting.serial:
            serials_found.setdefault(sighting.serial, []).append(sighting)
    renamed = {}
    for sighting in found:
        asset = by_serial.get(sighting.serial) if sighting.serial else None
        if asset is not None and not sighting.is_part:
            if asset.map_device and sighting.map_device:
                renamed.setdefault(asset.map_device, sighting.map_device)
            if asset.hostname and sighting.hostname:
                renamed.setdefault(asset.hostname.lower(), sighting.hostname.lower())
    changes, matched = [], set()
    at_device = {}  # Map device -> its whole-device assets with serial numbers
    for asset in assets:
        if asset.map_device and asset.serial and not is_part(asset.kind) and asset.status != REPLACED:
            at_device.setdefault(asset.map_device, []).append(asset)
    for sighting in found:
        if _says_nothing(sighting) and sighting.map_device in at_device:
            # A device its SNMP says nothing of the hardware of, read before (over SSH): what it does say (its
            # hostname, software) for each of its chassis, without a model or slot to undo theirs
            for asset in at_device[sighting.map_device]:
                if asset.id not in matched:
                    matched.add(asset.id)
                    changes.append(_compare(asset, replace(sighting, ref=asset.serial, kind=asset.kind, model="",
                                                           maker="", slot=asset.slot)))
            continue
        if sighting.serial and len({item.map_device or item.ref for item in serials_found[sighting.serial]}) > 1:
            if sighting is serials_found[sighting.serial][0]:
                places = ", ".join(item.name for item in serials_found[sighting.serial])
                changes.append(AssetChange(CONFLICT, sighting, by_serial.get(sighting.serial), chosen=False,
                                           note=f"Serial number {sighting.serial} is on {places}: one of them is "
                                                "misreporting it (lab images often share one), so neither is brought "
                                                "in."))
            continue
        if sighting.serial and sighting is not serials_found[sighting.serial][0]:
            continue  # Listed twice by one device: once is enough
        asset = by_serial.get(sighting.serial) if sighting.serial else None
        if asset is None and sighting.mac:
            asset = by_mac.get(sighting.mac)  # Recorded by its MAC (its serial wasn't known then)
        occupant = None
        if asset is None:
            # What was recorded where it is: the same hardware not read with its serial before, or what it replaced
            candidates = [item for item in assets if item.id not in matched and item.status != REPLACED
                          and _same_place(item, sighting, renamed) and _macs_agree(item, sighting)]
            for item in candidates:
                if not item.serial or not sighting.serial:
                    asset = item  # No serial on one side: it's the same, now (or still) without one
                    break
                if item.serial not in serials_found and item.status == IN_SERVICE:
                    occupant = item
                    break
        if asset is not None:
            matched.add(asset.id)
            changes.append(_compare(asset, sighting))
        elif occupant is not None:
            matched.add(occupant.id)
            changes.append(AssetChange(REPLACE, sighting, occupant, new_id=uuid.uuid4().hex,
                                       note=f"{label(occupant)} was {occupant.serial}: it's marked Replaced, pointing "
                                            "at the new one, which keeps its location and owner"))
        else:
            change = AssetChange(NEW, sighting, new_id=uuid.uuid4().hex)
            if sighting.serial in deleted:
                change.chosen = False
                change.note = "It was deleted from the asset list before: tick it to record it again"
            changes.append(change)
    order = {CONFLICT: 0, REPLACE: 1, NEW: 2, UPDATE: 3, SAME: 4}
    changes.sort(key=lambda change: (order[change.action], change.sighting.hostname.lower(), change.sighting.is_part,
                                     change.sighting.slot))
    return changes


def _compare(asset, sighting):
    """UPDATE (or SAME) for an asset found again: what the map says now that it doesn't. Blanks on the map never wipe
    what's recorded, and a location typed by hand isn't overwritten without asking."""
    changes, notes = {}, []
    chosen = True
    found = sighting.values()
    for name in COMPARED:
        if name == "parent_id":
            continue  # Resolved when applied (the chassis may be new too)
        new = found.get(name, "")
        old = getattr(asset, name)
        if not new or new == old:
            continue
        if name == "kind" and old != UNKNOWN and (old in PART_KINDS) == sighting.is_part:
            continue  # Said by hand (a server), or the map's guess changed: keep it
        if name == "location" and old:
            notes.append(f"the map has it in {new} (the asset list says {old})")
            chosen = False
        changes[name] = (old, new)
    if asset.status in OUT_OF_SERVICE:
        changes["status"] = (asset.status, IN_SERVICE)
        notes.append(f"it's recorded as {STATUSES[asset.status].lower()} but is on the network")
        chosen = False
    action = UPDATE if changes else SAME
    return AssetChange(action, sighting, asset, changes, chosen=chosen, note="; ".join(notes))


def apply(store, changes, user="", when=None):
    """Make the ticked changes (and note every asset seen as seen today), all at once. Returns the Assets made or
    changed."""
    when = when or today()
    chosen = [change for change in changes if change.can_apply and change.chosen]
    seen_only = [change for change in changes if change.can_apply and not change.chosen and change.asset is not None
                 and change.action in (UPDATE, SAME)]
    ids = {}  # Sighting ref -> the asset id it is (for parts' parent_id)
    for change in changes:
        if change.action in (NEW, REPLACE) and change.chosen:
            ids[change.sighting.ref] = change.new_id
        elif change.asset is not None and change.action in (UPDATE, SAME):
            ids[change.sighting.ref] = change.asset.id
    items = []
    seen = dict(last_seen=when, seen_by=user)
    for change in chosen:
        sighting = change.sighting
        parent = ids.get(sighting.parent_ref, "") if sighting.parent_ref else ""
        if change.action == NEW:
            items.append(dict(sighting.values(), id=change.new_id, parent_id=parent, status=IN_SERVICE,
                              first_seen=when, **seen))
        elif change.action == REPLACE:
            old = change.asset
            items.append(dict(sighting.values(), id=change.new_id, parent_id=parent, status=IN_SERVICE,
                              location=sighting.location or old.location, owner=old.owner, first_seen=when,
                              description=f"Replaced {old.serial or label(old)} ({when})", **seen))
            items.append(dict(id=old.id, status=REPLACED, replaced_by=change.new_id))
        else:
            values = {name: after for name, (_, after) in change.changes.items()}
            if sighting.is_part and parent and parent != change.asset.parent_id:
                values["parent_id"] = parent
            if values or not _seen_already(change.asset, when, user):
                items.append(dict(values, id=change.asset.id, **seen))
    for change in seen_only:  # Not changed as the map says, but seen
        if not _seen_already(change.asset, when, user):
            items.append(dict(id=change.asset.id, **seen))
    if not items:
        return []
    return store.set_assets(items)


def _seen_already(asset, when, user):
    return asset.last_seen == when and asset.seen_by == user


def summary(changes):
    """"3 new, 1 replaced, 2 changed" for the chosen changes, or ""."""
    counts = {}
    for change in changes:
        if change.chosen and change.can_apply and change.action != SAME:
            counts[change.action] = counts.get(change.action, 0) + 1
    words = {NEW: "new", REPLACE: "replaced", UPDATE: "changed"}
    return ", ".join(f"{counts[action]} {words[action]}" for action in (NEW, REPLACE, UPDATE) if counts.get(action))
