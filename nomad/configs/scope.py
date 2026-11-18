"""Which devices scheduled backups cover: the routers, switches, firewalls and WLCs on the maps (tribe maps on the
Tribe server; the open map without a tribe) that have a management address, with what standards can ask about
them."""
from ..netmap import model
from . import standards, text


def device_id(device):
    """A device's place in the archive: its management address (the same device on two maps is one), else its name."""
    return (device.mgmt_ip or device.name or device.key).strip().lower()


def rows_for_map(network_map, rows=None):
    """Scope rows ({"id", "name", "address", "names", "platform", "kind", "facts"}) for a map's network devices,
    added to rows (a dict by id: a device on several maps is listed once)."""
    rows = {} if rows is None else rows
    for device in network_map.devices.values():
        if device.kind not in model.NETWORK_KINDS or not device.mgmt_ip:
            continue
        key = device_id(device)
        if key in rows:
            continue
        facts = standards.device_facts(network_map, device)
        names = [name for name in dict.fromkeys([device.name, *(device.addresses or [])]) if name and name != key]
        rows[key] = {"id": key, "name": device.label, "address": device.mgmt_ip, "names": names,
                     "platform": facts["platform"], "kind": device.kind, "facts": facts}
    return rows


def rows_for_map_store(map_store):
    """Scope rows for every tribe map (the server's netmap.shared.MapStore)."""
    from ..netmap import shared
    rows = {}
    for item in map_store.maps():
        rows_for_map(shared.build(map_store.items(item["id"])), rows)
    return list(rows.values())


def facts_for_text(config, address=""):
    """What can be said of a device known only by its configuration (a file, a terminal's save)."""
    return {"hostname": text.hostname_in(config) or address, "mgmt_ip": address, "kind": "",
            "platform": text.platform_of(config), "site": "", "building": "", "room": "", "groups": []}
