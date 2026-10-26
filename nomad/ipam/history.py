"""IPAM history, from the change log: what happened to an address, a subnet or a whole network, and what a network
looked like at any moment.

The log records each change: a create with the whole row, an update with just the fields that changed, a delete.
Replaying it gives each change's before and after. A local network's log is its store's own changes table; a
tribe network's is the copy of the server's log that each laptop keeps (TeamStore's history table), so history
works offline too.
"""
import datetime
import json
from dataclasses import dataclass, field

from .store import STATUSES, IpamStore, ip_key, parse_address, parse_subnet, subnet_key

FIELD_LABELS = {"name": "Name", "status": "Status", "mac": "MAC", "description": "Description",
                "gateway": "Gateway", "loopbacks": "Loopbacks", "subnets": "Subnets", "vtp_domain": "VTP domain",
                "ranges": "Ranges", "fields": "Details",
                # Assets'
                "hostname": "Hostname", "serial": "Serial", "kind": "Kind", "model": "Model", "maker": "Maker",
                "software": "Software", "mgmt_ip": "Management IP", "slot": "Slot", "location": "Location",
                "asset_tag": "Asset tag", "owner": "Owner", "purchased": "Purchased", "warranty_end": "Warranty ends",
                "eol": "End of life",
                # Software targets'
                "target": "Target", "allowed": "Also allowed", "note": "Note"}
# Addresses', VLANs' (vlans.STATUSES) and assets' (assets.STATUSES)
SHOWN_STATUSES = dict(STATUSES, active="Active", planned="Planned", in_service="In service", spare="Spare",
                      repair="In repair (RMA)", replaced="Replaced", retired="Retired")
CREATED, CHANGED, DELETED = "create", "update", "delete"


@dataclass
class Event:
    seq: int
    when: str  # UTC, ISO 8601
    who: str
    entity: str  # networks, subnets, addresses, vlan_domains or vlans
    entity_id: str
    op: str
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)

    @property
    def local_time(self):
        """The time in this computer's time zone, like 2026-09-28 14:05."""
        moment = datetime.datetime.fromisoformat(self.when)
        return moment.astimezone().strftime("%Y-%m-%d %H:%M")

    @property
    def subject(self):
        """What it happened to: an address, a subnet (with its name), or the network."""
        row = self.after or self.before
        if self.entity == "addresses":
            return row.get("ip", "")
        if self.entity == "subnets":
            name = row.get("name")
            return f"{row.get('cidr', '')}" + (f" ({name})" if name else "")
        if self.entity == "vlans":
            name = row.get("name")
            return f"VLAN {row.get('vlan', '')}" + (f" ({name})" if name else "")
        if self.entity == "vlan_domains":
            return f"VLAN domain {row.get('name', '')}"
        if self.entity == "software_targets":
            return f"Software target for {row.get('model', '')}"
        if self.entity == "assets":
            name = " ".join(part for part in (row.get("hostname"), row.get("slot")) if part)
            what = " ".join(part for part in (row.get("model"), row.get("serial")) if part)
            return f"{name} ({what})" if name and what else name or what or "Asset"
        return f"Network {row.get('name', '')}"

    @property
    def action(self):
        if self.entity == "addresses":
            return {CREATED: "Recorded", CHANGED: "Changed", DELETED: "Marked free"}[self.op]
        return {CREATED: "Added", CHANGED: "Changed", DELETED: "Deleted"}[self.op]

    @property
    def details(self):
        """What changed, in words: "Name: sw1 → sw1-core; Status: Used → Reserved"."""
        if self.op == CREATED:
            return describe_row(self.entity, self.after)
        if self.op == DELETED:
            return f"was {describe_row(self.entity, self.before)}" if self.before else ""
        parts = []
        for name in FIELD_LABELS:
            if name in self.after and self.after.get(name) != self.before.get(name):
                parts.append(f"{FIELD_LABELS[name]}: {show(name, self.before.get(name))} → "
                             f"{show(name, self.after.get(name))}")
        return "; ".join(parts)


def show(name, value):
    if name == "status":
        return SHOWN_STATUSES.get(value, value or "(none)")
    if name == "subnets":
        return ", ".join(value or []) or "(none)"
    if name == "ranges":
        listed = [f"{item['first']}-{item['last']} {item.get('name', '')}".strip() for item in value or []]
        return ", ".join(listed) or "(none)"
    if name == "loopbacks":
        return "Yes" if value else "No"
    if name == "fields":
        return ", ".join(f"{key} {text}" for key, text in (value or {}).items()) or "(none)"
    return value if value else "(none)"


def describe_row(entity, row):
    if entity == "addresses":
        parts = [STATUSES.get(row.get("status"), row.get("status", ""))]
        parts += [row[name] for name in ("name", "mac") if row.get(name)]
        return ", ".join(parts)
    if entity == "subnets":
        parts = [row.get("cidr", "")]
        if row.get("gateway"):
            parts.append(f"gateway {row['gateway']}")
        if row.get("loopbacks"):
            parts.append("loopbacks")
        return ", ".join(parts)
    if entity == "assets":
        parts = [SHOWN_STATUSES.get(row.get("status"), row.get("status", ""))]
        parts += [row[name] for name in ("model", "serial", "software", "mgmt_ip", "location") if row.get(name)]
        return ", ".join(parts)
    if entity == "software_targets":
        text = row.get("target", "")
        return text + (f", also {row['allowed']}" if row.get("allowed") else "")
    if entity == "vlans":
        parts = [SHOWN_STATUSES.get(row.get("status"), row.get("status", ""))]
        parts += [row["name"]] if row.get("name") else []
        parts += list(row.get("subnets") or [])
        return ", ".join(parts)
    return row.get("name", "")


def source_of(store):
    """(database, log table) holding a store's history."""
    copy = getattr(store, "copy", None)
    return (copy.db, "history") if copy is not None else (store.db, "changes")


def _rows(db, table, where="", params=()):
    return db.execute(f"SELECT seq, entity, entity_id, op, data, modified, modified_by FROM {table} {where} "
                      "ORDER BY seq", params).fetchall()


def replay(rows):
    """Events with each change's before and after, from log rows in order."""
    state, events = {}, []
    for row in rows:
        data = json.loads(row["data"] or "{}")
        before = dict(state.get(row["entity_id"], {}))
        if row["op"] == CREATED:
            after = dict(data)
        elif row["op"] == CHANGED:
            after = dict(before, **data)
        else:
            after = {}
        state[row["entity_id"]] = after if row["op"] != DELETED else {}
        events.append(Event(row["seq"], row["modified"], row["modified_by"], row["entity"], row["entity_id"],
                            row["op"], before, after))
    return events


def _ids_created(db, table, entity, network_id, extra="", params=()):
    rows = db.execute(f"SELECT DISTINCT entity_id FROM {table} WHERE entity = ? AND op = 'create' AND "
                      f"json_extract(data, '$.network_id') = ? {extra}", (entity, network_id) + params)
    return [row[0] for row in rows]


def _events_for(db, table, ids):
    if not ids:
        return []
    marks = ", ".join("?" * len(ids))
    return replay(_rows(db, table, f"WHERE entity_id IN ({marks})", tuple(ids)))


def address_history(store, network_id, ip):
    """Everything that happened at one address in a network, including each time it was freed and recorded
    again (each of those is a new row in IPAM), newest first."""
    db, table = source_of(store)
    ip = str(parse_address(ip))
    ids = _ids_created(db, table, "addresses", network_id, "AND json_extract(data, '$.ip') = ?", (ip,))
    return list(reversed(_events_for(db, table, ids)))


def subnet_history(store, subnet_id):
    db, table = source_of(store)
    return list(reversed(_events_for(db, table, [subnet_id])))


def network_history(store, network_id, since=None):
    """Every change in a network (its details, subnets and addresses), newest first; `since` is a UTC ISO time."""
    db, table = source_of(store)
    ids = [network_id] + _ids_created(db, table, "subnets", network_id) + \
        _ids_created(db, table, "addresses", network_id)
    events = _events_for(db, table, ids)
    if since:
        events = [event for event in events if event.when >= since]
    return list(reversed(events))


def network_as_of(store, network_id, moment):
    """The network as it was at `moment` (UTC ISO), as a read-only in-memory IpamStore holding just that network,
    or None if the network didn't exist yet."""
    db, table = source_of(store)
    ids = [network_id] + _ids_created(db, table, "subnets", network_id) + \
        _ids_created(db, table, "addresses", network_id)
    marks = ", ".join("?" * len(ids))
    rows = _rows(db, table, f"WHERE entity_id IN ({marks}) AND modified <= ?", tuple(ids) + (moment,))
    live = {}
    for event in replay(rows):
        if event.op == DELETED:
            live.pop(event.entity_id, None)
        else:
            live[event.entity_id] = (event.entity, dict(live.get(event.entity_id, (None, {}))[1], **event.after),
                                     event)
    if network_id not in live:
        return None
    snapshot = IpamStore(":memory:", user="history")
    items = []
    for entity_id, (entity, row, event) in live.items():
        row = dict(row, id=entity_id, version=row.get("version", 1), modified=event.when, modified_by=event.who,
                   deleted=0)
        row["fields"] = json.dumps(row.get("fields") or {})
        if entity == "subnets":
            row["sort_key"] = subnet_key(parse_subnet(row["cidr"]))
        elif entity == "addresses":
            row["sort_key"] = ip_key(parse_address(row["ip"]))
        items.append({"entity": entity, "row": row})
    items.sort(key=lambda item: ("networks", "subnets", "addresses").index(item["entity"]))
    snapshot.apply_rows(items)
    return snapshot
