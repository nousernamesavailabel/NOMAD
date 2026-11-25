"""What each NOMAD Dashboard page shows, as JSON, from the engine's Snapshot (and its history for trends), and the
CSV of each page's table. Pure functions: the web server calls them, and the tests call them with made-up snapshots.

Nothing here gives a syslog message's text, a device's config, or any credential. The Reviews page shows config
changes' sizes, who reviewed them and the reviewers' notes, never the configuration lines.
"""
import csv
import io
import ipaddress
import time

from .. import __version__, whats_new as whats_new_notes
from ..configs import review as config_review
from ..netmap import checks, details, layout, monitor, monitor_record, traffic_history, tunnels as tunnel_module
from ..netmap.monitor import duration_text
from ..netmap.monitor_record import UPTIME_NAMES, uptime_text
from ..netmap.model import AP_DOWN, FIREWALL, NETWORK_KINDS, ROUTER, SWITCH, WLC, port_key

UP, DOWN, UNKNOWN, CANT, UNMONITORED = "up", "down", "unknown", "cant", "unmonitored"
STATUS_TEXT = {UP: "Up", DOWN: "Down", UNKNOWN: "Checking", CANT: "Can't check", UNMONITORED: "Not monitored"}
SEVERITIES = ["Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Info", "Debug"]
WINDOWS = {"15m": 900, "1h": 3600, "24h": 86400, "7d": 7 * 86400}
OVERVIEW_WINDOW = "1h"  # The Overview's host count: the Hosts page's for the same window, and a trend's newest point
SPANS = traffic_history.SPANS  # NOMAD's Traffic Graphs page offers the same
STALE_WATCHER = monitor_record.STALE_SECONDS  # Seconds without a poll before the watcher counts as stopped
KIND_WEIGHTS = {FIREWALL: 3, ROUTER: 2, SWITCH: 1, WLC: 1}
PAGES = ("overview", "devices", "events", "syslog", "traffic", "vpns", "ipam", "hosts", "sites", "map", "trends",
         "reviews", "whatsnew")
# The Syslog page's choice: the least severe level a sender's messages must reach to be listed ("" lists every sender).
# "error" lists the senders the Overview's Syslog errors count comes from
SYSLOG_LEVELS = {"error": 3, "warning": 4}


# --------------------------------------------------------------------- Bits

def device_status(snapshot, map_id, key):
    """(status, status.db row or None) of a device."""
    row = snapshot.statuses.get((map_id, key))
    if row is None:
        return UNMONITORED, None
    if row["status"] == "unknown" and row.get("problem"):
        return CANT, row
    return row["status"], row


def check_text(device):
    """"TCP 443": what checks a device that monitoring doesn't ping (a web server), or ""."""
    return checks.short_text(checks.spec_of(device))


def place_of(network_map, key):
    """{"site", "building", "room"}: the names of the groups a device is in, by their kind ("" where it's in none)."""
    place = {"site": "", "building": "", "room": ""}
    for group in network_map.group_path(key):
        if group.kind in place:
            place[group.kind] = group.name
    return place


def utilization(rate):
    """Percent of the port's speed used (the busier direction), or None without a speed."""
    if rate is None or not rate.get("speed"):
        return None
    return round(100.0 * max(rate["in_bps"], rate["out_bps"]) / (rate["speed"] * 1e6), 1)


def watcher_state(snapshot, now):
    watcher = snapshot.watcher or {}
    if not watcher.get("available"):
        return {"ok": False, "text": "The Map Watcher's monitoring can't be read on this computer: install the Map "
                                     "Watcher here, with Monitor ticked."}
    age = now - float(watcher.get("monitor_at") or 0)
    if age > STALE_WATCHER:
        return {"ok": False, "text": f"The Map Watcher hasn't checked the devices for {int(age // 60)} min: is it "
                                     "running?"}
    return {"ok": True, "text": f"Devices checked every {int(watcher.get('interval') or 60)} s by the Map Watcher"}


def freshness(snapshot, now):
    tribe = snapshot.tribe
    return {"watcher": watcher_state(snapshot, now),
            "tribe": {"ok": tribe.online, "text": (f"Tribe server {tribe.server}" if tribe.online else
                                                   f"Tribe server not reachable: {tribe.error}" if tribe.error else
                                                   "Connecting to the tribe server..."),
                      "synced_at": tribe.synced_at},
            "syslog": collector_state("Syslog Collector", snapshot.syslog),
            "flows": collector_state("Flow Collector", snapshot.flows),
            "revision": snapshot.revision, "now": now}


def collector_state(name, read):
    if read.get("available"):
        return {"ok": True, "text": name}
    error = read.get("error") or ""
    if error.startswith("No /v1/"):  # A collector from before the dashboard: it doesn't know the question
        return {"ok": False, "text": f"The {name} on this computer is from an older NOMAD: update it (Tools > "
                                     "Services & Firewall)"}
    return {"ok": False, "text": f"The {name} isn't answering on this computer"}


def monitored_maps(snapshot):
    return {int(map_id) for map_id in (snapshot.watcher or {}).get("maps", [])}


# --------------------------------------------------------------------- Devices

def device_rows(snapshot):
    rows = []
    for entry in snapshot.tribe.maps:
        network_map = entry.network_map
        for key, device in network_map.devices.items():
            status, row = device_status(snapshot, entry.id, key)
            uptimes = {name: snapshot.uptime.get(name, {}).get((entry.id, key)) for name in ("24h", "7d", "30d")}
            rows.append({
                "map_id": entry.id, "map": entry.name, "key": key, "name": device.label, "address": device.mgmt_ip,
                "kind": device.kind, "platform": device.platform, **place_of(network_map, key),
                "group": network_map.device_group_label(key), "status": status, "status_text": STATUS_TEXT[status],
                "since": row["since"] if row else None, "exact": bool(row.get("exact", True)) if row else True,
                "checked": row["checked"] if row else None, "rtt": row["rtt"] if row else None,
                "via": row["via"] if row else "", "check": check_text(device),
                "problem": row["problem"] if row else "",
                "stale_text": stale_text(row),
                "ap_down": device.ap_status == AP_DOWN,
                **{f"uptime_{name}": None if value is None else round(100 * value, 2)
                   for name, value in uptimes.items()}})
    order = {DOWN: 0, CANT: 1, UNKNOWN: 2, UP: 3, UNMONITORED: 4}
    rows.sort(key=lambda row: (order[row["status"]], row["map"].lower(), row["group"].lower(), row["name"].lower()))
    return rows


def devices(snapshot, now=None):
    now = time.time() if now is None else now
    return {"devices": device_rows(snapshot), "freshness": freshness(snapshot, now)}


# --------------------------------------------------------------------- Overview and sites

def counts(rows):
    found = {UP: 0, DOWN: 0, UNKNOWN: 0, CANT: 0, UNMONITORED: 0}
    for row in rows:
        found[row["status"]] += 1
    return found


def sites(snapshot, now=None):
    """A tile per site (top-level group) of each map, and one for each map's devices in no site."""
    now = time.time() if now is None else now
    rows = device_rows(snapshot)
    tiles = {}
    for row in rows:
        outer = row["site"] or row["building"] or row["room"]  # A building or room in no site gets its own tile
        tile = tiles.setdefault((row["map_id"], outer), {"map_id": row["map_id"], "map": row["map"],
                                                         "site": outer or "(no site)", "devices": []})
        tile["devices"].append(row)
    result = []
    for tile in tiles.values():
        tally = counts(tile["devices"])
        down = [row["name"] for row in tile["devices"] if row["status"] == DOWN]
        result.append({"map_id": tile["map_id"], "map": tile["map"], "site": tile["site"], "counts": tally,
                       "total": len(tile["devices"]), "down": down[:12], "down_count": len(down),
                       "state": DOWN if down else (CANT if tally[CANT] else UP if tally[UP] else UNMONITORED)})
    result.sort(key=lambda tile: (tile["state"] != DOWN, tile["map"].lower(), tile["site"].lower()))
    return {"sites": result, "freshness": freshness(snapshot, now)}


def overview(snapshot, history=None, now=None, engine=None):
    now = time.time() if now is None else now
    rows = device_rows(snapshot)
    tally = counts(rows)
    maps = []
    for entry in snapshot.tribe.maps:
        mine = [row for row in rows if row["map_id"] == entry.id]
        maps.append({"id": entry.id, "name": entry.name, "counts": counts(mine), "total": len(mine),
                     "hosts": len(entry.network_map.hosts), "monitored": entry.id in monitored_maps(snapshot)})
    seen = active_hosts(snapshot, engine, OVERVIEW_WINDOW)
    on_maps = map_subnet_hosts(snapshot.tribe, seen["subnets"])
    for item in maps:
        item["hosts"] = sum(row["total"] for row in on_maps if row["map_id"] == item["id"])
    severe = syslog_severe(snapshot)
    fullest = sorted((subnet_row(subnet) for subnet in snapshot.tribe.subnets if subnet.size >= 4),
                     key=lambda row: -row["percent"])[:8]
    busiest = sorted(link_rows(snapshot), key=lambda row: -(row["percent"] or 0))[:8]
    return {"counts": tally, "total": len(rows), "down": [row for row in rows if row["status"] == DOWN][:20],
            "maps": maps, "events": event_rows(snapshot, history, now)[:12], "syslog_severe": severe,
            "flows": {"available": snapshot.flows.get("available", False),
                      "bytes": (snapshot.flows.get("total") or [0])[0], "span": snapshot.flows.get("span", 3600)},
            "fullest": fullest, "busiest": busiest, "freshness": freshness(snapshot, now),
            "hosts": {"window": OVERVIEW_WINDOW, "total": seen["total"], "mac_only": seen["mac_only_total"]},
            "map_subnets": on_maps, "reviews": review_counts(snapshot)}


# --------------------------------------------------------------------- What's New

def whats_new(snapshot, now=None, entries=None):
    """NOMAD's Help > What's New: each version's short notes, newest first, and the version this dashboard runs.
    Lines keep their **bold** and `code` marks for the page to draw as text."""
    now = time.time() if now is None else now
    entries = whats_new_notes.read_entries() if entries is None else entries
    return {"version": __version__, "freshness": freshness(snapshot, now),
            "entries": [{"version": version, "date": date.isoformat() if date else None, "lines": lines}
                        for version, date, lines in entries]}


# --------------------------------------------------------------------- Config change reviews

REVIEW_KINDS = {config_review.KIND_REVIEW: "Review", config_review.KIND_CLOSE: "Closed",
                config_review.KIND_ACKNOWLEDGE: "Acknowledged", config_review.KIND_SEEN: "Opened by an older NOMAD"}
REVIEW_SHOWS = ("attention", "raised", "flagged")  # The Reviews page's choices ("" shows every change)


def review_counts(snapshot):
    data = snapshot.tribe.reviews or {}
    return {"available": bool(data), "to_review": int(data.get("to_review") or 0),
            "raised": int(data.get("raised") or 0)}


def block_notes(blocks):
    """The blocks a reviewer said something about (or found unexpected), as text."""
    parts = []
    for block in blocks or []:
        if not block.get("note") and block.get("verdict") != config_review.UNEXPECTED:
            continue
        where = block.get("path") or "top level"
        verdict = "unexpected" if block.get("verdict") == config_review.UNEXPECTED else "expected"
        parts.append(f"{block.get('index', 0) + 1} ({where}, {verdict})" + (f": {block['note']}" if block.get("note")
                                                                           else ""))
    return "; ".join(parts)


def review_log_rows(snapshot):
    rows = []
    for row in (snapshot.tribe.reviews or {}).get("reviews", []):
        rows.append({"at": row.get("at"), "device": row.get("device_name") or row.get("device_id") or "",
                     "which": row.get("which") or "", "pulled_at": row.get("pulled_at"),
                     "change": f"+{row.get('added') or 0} −{row.get('removed') or 0}",
                     "changed_by": row.get("changed_by") or "",
                     "kind": row.get("kind") or "", "kind_text": REVIEW_KINDS.get(row.get("kind"), row.get("kind")),
                     "outcome": row.get("outcome") or "",
                     "outcome_text": config_review.STATE_NAMES.get(row.get("outcome"), row.get("outcome") or ""),
                     "user": row.get("user") or "", "reason": row.get("reason") or "", "total": row.get("total"),
                     "unexpected": row.get("unexpected"), "seen": row.get("seen"), "seconds": row.get("seconds"),
                     "self_review": bool(row.get("self_review")), "quick": bool(row.get("quick")),
                     "notes": block_notes(row.get("blocks"))})
    return rows


def review_change_rows(snapshot, show=""):
    """The newest changes with how each was reviewed (its latest review, close or acknowledgement)."""
    data = snapshot.tribe.reviews or {}
    latest = {}
    flags = {}
    for row in sorted(data.get("reviews", []), key=lambda item: item.get("id") or 0):
        if row.get("kind") == config_review.KIND_SEEN:
            continue
        latest[row.get("version_id")] = row
        if row.get("kind") == config_review.KIND_REVIEW:
            flags[row.get("version_id")] = row
    rows = []
    for version in data.get("changes", []):
        state = config_review.state_of(version)
        last = latest.get(version.get("id")) or {}
        reviewed = flags.get(version.get("id")) or {}
        rows.append({"id": version.get("id"), "pulled_at": version.get("pulled_at"),
                     "device": version.get("device_name") or version.get("device_id") or "",
                     "which": version.get("which") or "",
                     "change": f"+{version.get('added') or 0} −{version.get('removed') or 0}",
                     "changed_by": version.get("changed_by") or "", "pulled_by": version.get("pulled_by") or "",
                     "state": state or "to_review", "state_text": config_review.STATE_NAMES.get(state, "To review"),
                     "reviewed_by": (version.get("reviewed_by") or "") if state else "",
                     "reviewed_at": version.get("reviewed_at") if state else None,
                     "reason": last.get("reason") or "", "blocks": reviewed.get("total"),
                     "unexpected": reviewed.get("unexpected"), "seconds": reviewed.get("seconds"),
                     "self_review": bool(reviewed.get("self_review")), "quick": bool(reviewed.get("quick")),
                     "attention": config_review.needs_attention(version)})
    if show == "attention":
        rows = [row for row in rows if row["attention"]]
    elif show == "raised":
        rows = [row for row in rows if row["state"] == config_review.RAISED]
    elif show == "flagged":
        rows = [row for row in rows if row["self_review"] or row["quick"]]
    return rows


def reviews(snapshot, show="", now=None):
    now = time.time() if now is None else now
    show = show if show in REVIEW_SHOWS else ""
    data = snapshot.tribe.reviews or {}
    return {"available": bool(data), "show": show, "counts": review_counts(snapshot),
            "changes": review_change_rows(snapshot, show), "log": review_log_rows(snapshot),
            "allow_acknowledge": bool(data.get("allow_acknowledge")), "freshness": freshness(snapshot, now)}


def map_subnet_hosts(tribe, rows):
    """The hosts seen in each subnet on each map: [{map_id, map, network, subnet, name, total, size, percent}].

    A map's subnets are the ones its devices have addresses in (point-to-point links left out). For a map of an IPAM
    network they're that network's IPAM subnets inside them, or the most specific one round a subnet with none
    inside. rows: count_hosts's (with percent), whose counts these are, so they add up the same way."""
    from .engine import map_subnets, subnet_groups
    groups, map_networks = subnet_groups(tribe)
    counted = {(row["network"], row["subnet"]): row for row in rows}
    found = []
    for entry in tribe.maps:
        key = map_networks.get(entry.id)
        if key is None:
            continue
        index, subnets, _name = groups[key]
        known = {}
        for cidr in subnets:
            try:
                known[cidr] = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                pass
        chosen = set()
        for cidr in map_subnets(entry):
            block = ipaddress.ip_network(cidr, strict=False)
            if block.prefixlen >= 30:
                continue
            inside = {name for name, network in known.items()
                      if network.version == block.version and network.subnet_of(block)}
            if not inside:
                around = index.find(str(block.network_address))
                if around is not None and block.subnet_of(known[around]):
                    inside = {around}
            chosen |= inside
        for cidr in chosen:
            row = counted.get((key, cidr))
            subnet = subnets.get(cidr)
            size = row["size"] if row else subnet.size if subnet is not None else \
                max(1, known[cidr].num_addresses - 2)
            total = row["total"] if row else 0
            found.append({"map_id": entry.id, "map": entry.name, "network": key, "subnet": cidr,
                          "name": subnet.name if subnet is not None else "", "total": total, "size": size,
                          "percent": round(100.0 * total / max(1, size), 1)})
    found.sort(key=lambda row: (row["map"].lower(), _sort_cidr(row["subnet"])))
    return found


# --------------------------------------------------------------------- Events

def event_rows(snapshot, history=None, now=None, since=86400):
    """Status changes, new devices and hosts, links gone quiet and failed backups, newest first."""
    now = time.time() if now is None else now
    events = []
    names = {entry.id: entry.name for entry in snapshot.tribe.maps}
    if history is not None:
        for change in history.recent_changes(now - since, 300):
            kind = {"up": "up", "down": "down"}.get(change["status"], "unknown")
            events.append({"at": change["at"], "kind": kind, "map": names.get(change["map_id"], ""),
                           "text": change["text"]})
        for start, end in history.gaps(now - since):
            events.append({"at": end, "kind": "watcher", "map": "",
                           "text": f"The Map Watcher wasn't monitoring for {duration_text(end - start)}, from "
                                   f"{time.strftime('%Y-%m-%d %H:%M', time.localtime(start))} (left out of the "
                                   "uptime)"})
    for entry in snapshot.tribe.maps:
        network_map = entry.network_map
        for ref, item in network_map.news.items():
            kind, _, key = ref.partition(":")
            when = _iso_time(item.get("when"))
            if when is None or when < now - since * 7:
                continue
            if kind == "device" and key in network_map.devices:
                text = f"New device {network_map.devices[key].label}"
            elif kind == "host":
                text = f"New host {key}"
            else:
                continue
            where = item.get("where")
            events.append({"at": when, "kind": "new", "map": entry.name,
                           "text": text + (f" on {where}" if where else "")})
        for link in network_map.unseen_links():
            when = _iso_time(link.unseen_since)
            a, b = network_map.devices.get(link.a), network_map.devices.get(link.b)
            if a is None or b is None:
                continue
            events.append({"at": when or now, "kind": "stale", "map": entry.name,
                           "text": f"Link {a.label} {link.a_port} - {b.label} {link.b_port} not seen lately"})
    for result in snapshot.tribe.backups:
        if not result.get("ok"):
            when = _iso_time(result.get("at"))
            if when is not None and when >= now - since:
                events.append({"at": when, "kind": "backup", "map": "",
                               "text": f"Config backup of {result.get('device_name') or result.get('device_id')} "
                                       f"failed: {result.get('note', '')}".strip()})
    events.sort(key=lambda event: -(event["at"] or 0))
    return events


def syslog_rows(snapshot, level=""):
    """Messages per sender in the last day, by severity (counts only). With a level (SYSLOG_LEVELS), only the senders
    with a message that bad or worse."""
    senders = {}
    for source, severity, count in snapshot.syslog.get("counts", []):
        row = senders.setdefault(source, {"source": source, "name": "", "total": 0,
                                          **{name.lower(): 0 for name in SEVERITIES}})
        row[SEVERITIES[max(0, min(7, int(severity)))].lower()] += count
        row["total"] += count
    by_address = {}
    for entry in snapshot.tribe.maps:
        for device in entry.network_map.devices.values():
            for address in [device.mgmt_ip, *device.addresses]:
                if address:
                    by_address.setdefault(address, device.label)
    for row in senders.values():
        row["name"] = by_address.get(row["source"], "")
    rows = senders.values()
    if level in SYSLOG_LEVELS:
        names = [name.lower() for name in SEVERITIES[:SYSLOG_LEVELS[level] + 1]]
        rows = [row for row in rows if any(row[name] for name in names)]
    return sorted(rows, key=lambda row: (-(row["emergency"] + row["alert"] + row["critical"] + row["error"]),
                                         -row["total"]))


def syslog_severe(snapshot):
    """Messages from Emergency to Error in the last day: the Overview's Syslog errors count."""
    return sum(count for _source, severity, count in snapshot.syslog.get("counts", []) if severity <= 3)


def events(snapshot, history=None, now=None):
    now = time.time() if now is None else now
    return {"events": event_rows(snapshot, history, now), "freshness": freshness(snapshot, now)}


def syslog(snapshot, level="", now=None):
    now = time.time() if now is None else now
    level = level if level in SYSLOG_LEVELS else ""
    return {"senders": syslog_rows(snapshot, level), "level": level, "severe": syslog_severe(snapshot),
            "available": snapshot.syslog.get("available", False), "freshness": freshness(snapshot, now)}


def _iso_time(text):
    if not text:
        return None
    if isinstance(text, (int, float)):
        return float(text)
    import datetime
    try:
        return datetime.datetime.fromisoformat(str(text)).timestamp()
    except ValueError:
        return None


# --------------------------------------------------------------------- Traffic

def link_rows(snapshot):
    """Each port the Map Watcher reads (link ends and graphed ports), with its latest rates."""
    rows = []
    for entry in snapshot.tribe.maps:
        network_map = entry.network_map
        far = {}
        for link in network_map.links:
            far[(link.a, port_key(link.a_port))] = (link.b, link.b_port)
            far[(link.b, port_key(link.b_port))] = (link.a, link.a_port)
        for (map_id, key, port), rate in snapshot.rates.items():
            if map_id != entry.id or key not in network_map.devices:
                continue
            other = far.get((key, port_key(port)))
            peak = snapshot.peaks.get((map_id, key, port))
            graphed = port in network_map.graphed.get(key, [])
            rows.append({"map_id": map_id, "map": entry.name, "device": key,
                         "name": network_map.devices[key].label, "port": port,
                         "to": f"{network_map.devices[other[0]].label} {other[1]}" if other and other[0] in
                         network_map.devices else "", "graphed": graphed,
                         "in_bps": rate["in_bps"], "out_bps": rate["out_bps"], "speed": rate["speed"],
                         "percent": utilization(rate), "at": rate["at"],
                         "peak_percent": utilization({"in_bps": peak[0], "out_bps": peak[1], "speed": peak[2]})
                         if peak else None})
    rows.sort(key=lambda row: (-(row["percent"] or 0), row["name"].lower(), row["port"]))
    return rows


def traffic(snapshot, now=None):
    now = time.time() if now is None else now
    flows = snapshot.flows or {}
    top = flows.get("top", {})
    return {"links": link_rows(snapshot), "flows": {
        "available": flows.get("available", False), "error": flows.get("error", ""), "span": flows.get("span", 3600),
        "total": flows.get("total", [0, 0, 0]), "exporters": flows.get("exporters", []),
        "sources": top.get("src", []), "destinations": top.get("dst", []), "applications": top.get("app", []),
        "conversations": top.get("conv", [])}, "freshness": freshness(snapshot, now)}


# --------------------------------------------------------------------- VPNs and probes

def live_tunnels(snapshot, map_id):
    return {key: row["data"] for (mine, key), row in snapshot.tunnels.items() if mine == map_id}


def vpns(snapshot, now=None):
    now = time.time() if now is None else now
    found, probed = [], []
    for entry in snapshot.tribe.maps:
        network_map = entry.network_map
        for tunnel in tunnel_module.find(network_map, live_tunnels(snapshot, entry.id)):
            a, b = network_map.devices[tunnel.a], network_map.devices[tunnel.b]
            found.append({"map": entry.name, "a": a.label, "a_port": tunnel.a_port, "b": b.label,
                          "b_port": tunnel.b_port, "kind": "DMVPN" if tunnel.multipoint else "Point-to-point",
                          "ipsec": tunnel.ipsec, "state": tunnel.state,
                          "state_text": tunnel_module.STATE_TEXT[tunnel.state]})
        for key, device in network_map.devices.items():
            status, row = device_status(snapshot, entry.id, key)
            if row is not None and row.get("via"):
                probed.append({"map": entry.name, "name": device.label, "address": device.mgmt_ip,
                               "via": row["via"], "status": status, "status_text": STATUS_TEXT[status],
                               "rtt": row["rtt"], "problem": row["problem"], "since": row["since"]})
    order = {"down": 0, "negotiating": 1, "unknown": 2, "up": 3}
    found.sort(key=lambda row: (order.get(row["state"], 2), row["map"].lower(), row["a"].lower()))
    return {"tunnels": found, "probes": probed, "freshness": freshness(snapshot, now)}


# --------------------------------------------------------------------- IPAM

def subnet_row(subnet, names=None):
    return {"network_id": subnet.network_id, "network": (names or {}).get(subnet.network_id, ""),
            "subnet": subnet.cidr, "name": subnet.name, "vlan": subnet.vlan, "used": subnet.used,
            "size": subnet.size, "percent": round(100.0 * subnet.used / max(1, subnet.size), 1),
            "swept": subnet.swept or None}


def ipam(snapshot, now=None):
    now = time.time() if now is None else now
    names = {network["id"]: network["name"] for network in snapshot.tribe.networks}
    rows = [subnet_row(subnet, names) for subnet in snapshot.tribe.subnets]
    rows.sort(key=lambda row: (row["network"].lower(), _sort_cidr(row["subnet"])))
    return {"subnets": rows, "networks": snapshot.tribe.networks, "freshness": freshness(snapshot, now)}


def _sort_cidr(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return network.version, int(network.network_address), network.prefixlen
    except ValueError:
        return 9, 0, 0


# --------------------------------------------------------------------- Hosts per subnet

def active_hosts(snapshot, engine, window="1h"):
    """The one count of hosts the pages show (the Hosts page, the Overview, a subnet's trend): addresses seen in the
    window on the maps' switch tables, in sweeps or in NetFlow, once per network, network devices left out; and the
    hosts the maps list with no address."""
    from .engine import mac_only_hosts
    rows = engine.hosts(WINDOWS.get(window, 3600)) if engine is not None else []
    for row in rows:
        row["percent"] = round(100.0 * row["total"] / max(1, row["size"]), 1)
    mac_only = mac_only_hosts(snapshot.tribe)
    return {"subnets": rows, "total": sum(row["total"] for row in rows), "mac_only": mac_only,
            "mac_only_total": sum(row["count"] for row in mac_only)}


def hosts(snapshot, engine, window="1h", now=None):
    now = time.time() if now is None else now
    window = window if window in WINDOWS else "1h"
    return {"window": window, "windows": list(WINDOWS), **active_hosts(snapshot, engine, window),
            "freshness": freshness(snapshot, now)}


# --------------------------------------------------------------------- The map

def map_list(snapshot):
    return [{"id": entry.id, "name": entry.name, "devices": len(entry.network_map.devices)}
            for entry in sorted(snapshot.tribe.maps, key=lambda entry: entry.name.lower())]


def topology(snapshot, map_id, view="l2", now=None):
    """The map drawn as the app draws it: {"nodes", "links", "groups", "tunnels"} with positions (centers)."""
    now = time.time() if now is None else now
    entry = next((item for item in snapshot.tribe.maps if item.id == int(map_id)), None)
    if entry is None:
        return {"error": "No such map.", "maps": map_list(snapshot)}
    network_map = entry.network_map
    if view == "l3":
        from ..netmap.l3 import DEVICE, l3_graph
        nodes, links = l3_graph(network_map)
        saved = network_map.l3_positions
        keys = list(nodes)
        edges = [(link.a, link.b) for link in links]
        positions = layout.merge_positions(keys, edges, saved)
        drawn = []
        for key, node in nodes.items():
            x, y = positions.get(key, (0, 0))
            item = {"key": key, "label": node.label, "kind": node.kind if node.kind != DEVICE else node.device.kind,
                    "node": node.kind, "detail": node.detail, "x": x, "y": y}
            if node.kind == DEVICE:
                item.update(address=node.device.mgmt_ip, platform=node.device.platform,
                            **node_status(snapshot, entry.id, node.device.key))
            drawn.append(item)
        lines = [{"a": link.a, "b": link.b, "a_port": link.a_port, "b_port": link.b_port, "kind": "l3"}
                 for link in links]
        return {"map": {"id": entry.id, "name": entry.name}, "view": "l3", "nodes": drawn, "links": lines,
                "groups": [], "tunnels": [], "maps": map_list(snapshot), "freshness": freshness(snapshot, now)}
    keys = list(network_map.devices)
    root = network_map.root if network_map.root in network_map.devices else None
    positions = layout.merge_positions(keys, network_map.layout_edges(), dict(network_map.positions), root=root,
                                       weight=lambda key: KIND_WEIGHTS.get(network_map.devices[key].kind, 0))
    drawn = []
    for key, device in network_map.devices.items():
        x, y = positions.get(key, (0, 0))
        drawn.append({"key": key, "label": device.label, "kind": device.kind, "node": "device", "x": x, "y": y,
                      "address": device.mgmt_ip, "platform": device.platform,
                      "group": network_map.device_group_label(key), "hosts": 0,
                      **node_status(snapshot, entry.id, key)})
    host_counts = {}
    for host in network_map.hosts:
        host_counts[host.device] = host_counts.get(host.device, 0) + 1
    for item in drawn:
        item["hosts"] = host_counts.get(item["key"], 0)
    lines = []
    for link in network_map.links:
        rate_a = snapshot.rates.get((entry.id, link.a, link.a_port))
        rate_b = snapshot.rates.get((entry.id, link.b, link.b_port))
        rate = rate_a or rate_b
        lines.append({"a": link.a, "b": link.b, "a_port": link.a_port, "b_port": link.b_port,
                      "unseen": bool(link.unseen_by), "manual": link.manual,
                      "percent": utilization(rate), "in_bps": rate["in_bps"] if rate else None,
                      "out_bps": rate["out_bps"] if rate else None})
    tunnels = [{"a": tunnel.a, "b": tunnel.b, "state": tunnel.state, "text": tunnel.text(network_map)}
               for tunnel in tunnel_module.find(network_map, live_tunnels(snapshot, entry.id))]
    return {"map": {"id": entry.id, "name": entry.name}, "view": "l2", "nodes": drawn, "links": lines,
            "groups": group_boxes(network_map, positions), "tunnels": tunnels, "maps": map_list(snapshot),
            "freshness": freshness(snapshot, now)}


def node_status(snapshot, map_id, key):
    """A device's status for its box on the map, with its uptime over the last 24 hours (percent, or None)."""
    status, row = device_status(snapshot, map_id, key)
    uptime = snapshot.uptime.get("24h", {}).get((map_id, key))
    return {"status": status, "status_text": STATUS_TEXT[status], "rtt": row["rtt"] if row else None,
            "since": row["since"] if row else None, "exact": bool(row.get("exact", True)) if row else True,
            "via": row["via"] if row else "", "stale_text": stale_text(row),
            "problem": row["problem"] if row else "", "uptime": None if uptime is None else round(100 * uptime, 2)}


def stale_text(row, now=None):
    """"Not checked since 14:02" once the Map Watcher has stopped checking (as NOMAD's boxes say it), else ""."""
    if not row or not row.get("stale_at"):
        return ""
    return monitor_record.not_checked_text(monitor.DeviceStatus(stale_at=row["stale_at"]), now)




def status_text(status, row, now):
    """What the Map Watcher's monitoring says of a device, as NOMAD's details pane says it (the same function)."""
    if row is None:
        return "Not monitored by the Map Watcher"
    state = monitor.DeviceStatus(UNKNOWN if status == CANT else status, row.get("rtt"), float(row.get("since") or 0),
                                 0, float(row.get("checked") or 0), row.get("via") or "", row.get("problem") or "",
                                 bool(row.get("exact", True)), stale_at=float(row.get("stale_at") or 0))
    return monitor_record.status_text(state, now)


def node_details(snapshot, map_id, key, now=None):
    """A device's (or, on the logical view, a subnet's) details, as NOMAD's details pane shows them, with the Map
    Watcher's status and the device's uptime: see netmap.details."""
    now = time.time() if now is None else now
    entry = next((item for item in snapshot.tribe.maps if item.id == int(map_id)), None)
    if entry is None:
        raise KeyError(map_id)
    network_map = entry.network_map
    if key not in network_map.devices:
        from ..netmap.l3 import SUBNET, l3_graph
        node = l3_graph(network_map)[0].get(key) if key.startswith("net:") else None
        if node is None or node.kind != SUBNET:
            raise KeyError(key)
        return details.subnet_details(network_map, node.label)
    status, row = device_status(snapshot, entry.id, key)
    rows = []
    uptime = uptime_text({name: snapshot.uptime.get(name, {}).get((entry.id, key)) for name in UPTIME_NAMES})
    if uptime:
        rows.append(("Uptime", uptime))
    if row is not None and row.get("checked"):
        rows.append(("Last checked", f"{duration_text(now - row['checked'])} ago"))
    return details.device_details(network_map, key, status_text(status, row, now), rows,
                                  live=live_tunnels(snapshot, entry.id))


GROUP_PAD = 24  # Round a group's devices, and round the groups inside it
GROUP_TITLE = 32  # The band at the top of a group's box with its name


def group_boxes(network_map, positions):
    """Each site, building and room as a box round its devices: [{"key", "name", "kind", "x", "y", "w", "h"}],
    outermost first. A box holds the boxes of the groups inside it, with room above them for its own title."""
    boxes = {}
    deepest_first = sorted(network_map.groups, key=lambda group: -len(network_map.group_chain(group)))
    for group in deepest_first:
        edges = []  # (left, top, right, bottom) of what the box goes round
        for key in network_map.members(group.key, deep=False):
            if key in positions and key in network_map.devices:
                x, y = positions[key]
                edges.append((x - layout.NODE_WIDTH / 2 - GROUP_PAD, y - layout.NODE_HEIGHT / 2 - GROUP_PAD - GROUP_TITLE,
                              x + layout.NODE_WIDTH / 2 + GROUP_PAD, y + layout.NODE_HEIGHT / 2 + GROUP_PAD))
        for inner in network_map.subgroups(group.key):
            box = boxes.get(inner.key)
            if box is not None:
                edges.append((box["x"] - GROUP_PAD, box["y"] - GROUP_PAD / 2 - GROUP_TITLE,
                              box["x"] + box["w"] + GROUP_PAD, box["y"] + box["h"] + GROUP_PAD))
        if not edges:
            continue
        left, top = min(edge[0] for edge in edges), min(edge[1] for edge in edges)
        right, bottom = max(edge[2] for edge in edges), max(edge[3] for edge in edges)
        boxes[group.key] = {"key": group.key, "name": group.name, "kind": group.kind,
                            "depth": len(network_map.group_chain(group)), "x": left, "y": top, "w": right - left,
                            "h": bottom - top}
    return sorted(boxes.values(), key=lambda box: box["depth"])


# --------------------------------------------------------------------- Trends

def trends(snapshot, now=None):
    """What can be graphed: the ports with traffic, the subnets hosts are counted in (as the Hosts page names them),
    and each device's uptime."""
    from .engine import host_subnets
    now = time.time() if now is None else now
    ports = [{"map_id": row["map_id"], "device": row["device"], "name": row["name"], "port": row["port"],
              "to": row["to"], "map": row["map"]} for row in link_rows(snapshot)]
    ports.sort(key=lambda row: (row["map"].lower(), row["name"].lower(), row["port"]))
    subnets = host_subnets(snapshot.tribe)
    uptime = [{"map": row["map"], "name": row["name"], "status": row["status"], "uptime_24h": row["uptime_24h"],
               "uptime_7d": row["uptime_7d"], "uptime_30d": row["uptime_30d"]}
              for row in device_rows(snapshot) if row["status"] != UNMONITORED]
    uptime.sort(key=lambda row: (row["uptime_30d"] if row["uptime_30d"] is not None else 101, row["name"].lower()))
    return {"ports": ports, "subnets": subnets, "uptime": uptime, "spans": list(SPANS),
            "freshness": freshness(snapshot, now)}


def series(history, kind, query, now=None, engine=None):
    now = time.time() if now is None else now
    span = SPANS.get(query.get("span", "24h"), 86400)
    if kind == "port":
        points = history.rate_series(int(query.get("map", 0)), query.get("device", ""), query.get("port", ""),
                                     now - span, now)
        return {"kind": "port", "span": query.get("span", "24h"), "points": points}
    if kind == "subnet":
        subnet, network = query.get("subnet", ""), query.get("network") or None
        points = history.host_series(subnet, now - span, now, network=network)
        if engine is not None and network is not None and (not points or points[-1][0] < now - 60) and \
                span <= 3 * 86400:  # Raw samples (every few minutes): end on the count the Hosts page has now
            from .engine import HOST_TREND_WINDOW
            live = next((row["total"] for row in engine.hosts(HOST_TREND_WINDOW)
                         if row["subnet"] == subnet and row["network"] == network), 0)
            points.append([now, live, live])
        return {"kind": "subnet", "span": query.get("span", "24h"), "points": points}
    raise KeyError(kind)


# --------------------------------------------------------------------- CSV

def _when(value):
    if not value:
        return ""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))


def csv_table(name, snapshot, history=None, engine=None, query=None):
    """(filename, CSV text) of a page's table."""
    query = query or {}
    if name == "devices":
        rows = device_rows(snapshot)
        header = ["Map", "Site", "Building", "Room", "Name", "Address", "Kind", "Status", "Since", "Response (ms)",
                  "Checked with", "Checked from", "Problem", "Uptime 24 h %", "Uptime 7 d %", "Uptime 30 d %"]
        body = [[row["map"], row["site"], row["building"], row["room"], row["name"], row["address"], row["kind"], row["status_text"],
                 _when(row["since"]), row["rtt"] if row["rtt"] is not None else "", row["check"] or "Ping",
                 row["via"], row["problem"],
                 row["uptime_24h"], row["uptime_7d"], row["uptime_30d"]] for row in rows]
    elif name == "events":
        header = ["When", "Kind", "Map", "What happened"]
        body = [[_when(row["at"]), row["kind"], row["map"], row["text"]] for row in event_rows(snapshot, history)]
    elif name == "syslog":
        header = ["Sender", "Name", "Total"] + SEVERITIES
        body = [[row["source"], row["name"], row["total"]] + [row[severity.lower()] for severity in SEVERITIES]
                for row in syslog_rows(snapshot, query.get("level", ""))]
    elif name == "traffic":
        header = ["Map", "Device", "Port", "Linked to", "In (b/s)", "Out (b/s)", "Speed (Mb/s)", "Use %",
                  "Peak today %", "Read"]
        body = [[row["map"], row["name"], row["port"], row["to"], round(row["in_bps"]), round(row["out_bps"]),
                 row["speed"], row["percent"], row["peak_percent"], _when(row["at"])] for row in link_rows(snapshot)]
    elif name == "vpns":
        header = ["Map", "End A", "Interface A", "End B", "Interface B", "Kind", "IPsec", "State"]
        body = [[row["map"], row["a"], row["a_port"], row["b"], row["b_port"], row["kind"],
                 "yes" if row["ipsec"] else "no", row["state_text"]] for row in vpns(snapshot)["tunnels"]]
    elif name == "ipam":
        header = ["Network", "Subnet", "Name", "Addresses used", "Size", "Used %", "Last swept"]
        body = [[row["network"], row["subnet"], row["name"], row["used"], row["size"], row["percent"],
                 _when(row["swept"])] for row in ipam(snapshot)["subnets"]]
    elif name == "hosts":
        data = hosts(snapshot, engine, query.get("window", "1h"))
        header = ["Network", "Subnet", "Name", "Hosts", "On the map", "Answered sweeps", "In NetFlow", "Size",
                  "Used %"]
        body = [[row["network_name"], row["subnet"], row["name"], row["total"], row["map"], row["sweep"],
                 row["flow"], row["size"], row["percent"]] for row in data["subnets"]]
    elif name == "reviews":
        header = ["Pulled", "Device", "Configuration", "Change", "Changed by", "Review", "By", "When", "Reason",
                  "Blocks", "Unexpected", "Time (s)", "Self-reviewed", "Quick"]
        body = [[_when(row["pulled_at"]), row["device"], row["which"], row["change"], row["changed_by"],
                 row["state_text"], row["reviewed_by"], _when(row["reviewed_at"]), row["reason"], row["blocks"],
                 row["unexpected"], row["seconds"], "yes" if row["self_review"] else "",
                 "yes" if row["quick"] else ""] for row in review_change_rows(snapshot, query.get("show", ""))]
    elif name == "review-log":
        header = ["When", "Device", "Configuration", "Change pulled", "Change", "Changed by", "What", "Outcome", "Who",
                  "Reason", "Blocks", "Unexpected", "Blocks seen", "Time (s)", "Self-reviewed", "Quick", "Block notes"]
        body = [[_when(row["at"]), row["device"], row["which"], _when(row["pulled_at"]), row["change"],
                 row["changed_by"], row["kind_text"], row["outcome_text"], row["user"], row["reason"], row["total"], row["unexpected"],
                 row["seen"], row["seconds"], "yes" if row["self_review"] else "", "yes" if row["quick"] else "",
                 row["notes"]] for row in review_log_rows(snapshot)]
    elif name == "uptime":
        header = ["Map", "Name", "Status", "Uptime 24 h %", "Uptime 7 d %", "Uptime 30 d %"]
        body = [[row["map"], row["name"], STATUS_TEXT[row["status"]], row["uptime_24h"], row["uptime_7d"],
                 row["uptime_30d"]] for row in trends(snapshot)["uptime"]]
    else:
        raise KeyError(name)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(header)
    for row in body:
        writer.writerow(["" if value is None else _safe_cell(value) for value in row])
    stamp = time.strftime("%Y%m%d-%H%M")
    return f"nomad-{name}-{stamp}.csv", output.getvalue()


def _safe_cell(value):
    """Text that starts like a formula is quoted, so a spreadsheet doesn't run it (CSV injection)."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


__all__ = ["PAGES", "overview", "devices", "events", "syslog", "traffic", "vpns", "ipam", "hosts", "sites", "topology",
           "trends", "series", "csv_table", "reviews", "whats_new", "NETWORK_KINDS"]
