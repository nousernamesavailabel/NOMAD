"""Checking archived configurations against the standards, as they arrive (the Tribe server, or NOMAD on its own) and
when a standard changes."""
import time

from . import standards


def result_dicts(results):
    return [{"status": result.status, "rule": result.rule, "path": list(result.path), "detail": result.detail,
             "line_number": result.line_number, "fix": list(result.fix)} for result in results]


def results_from(dicts):
    return [standards.Result(item.get("status", ""), item.get("rule", ""), list(item.get("path") or []),
                             item.get("detail", ""), item.get("line_number"), list(item.get("fix") or []))
            for item in dicts or ()]


def facts_for(store, device_id):
    """What standards can ask about an archived device: what its map said (when it's on one), else its name."""
    device = store.device(device_id) or {}
    facts = dict(device.get("facts") or {})
    facts.setdefault("hostname", device.get("name") or device_id)
    facts.setdefault("mgmt_ip", device.get("address") or "")
    facts.setdefault("kind", device.get("kind") or "")
    facts.setdefault("platform", device.get("platform") or "")
    facts.setdefault("groups", [])
    for name in ("site", "building", "room"):
        facts.setdefault(name, "")
    return facts


def recheck(store, device_id, names=None, now=None):
    """Check a device's newest running-config against every standard that applies to it (names: only these
    standards). Returns whether anything was written."""
    now = time.time() if now is None else now
    latest = store.latest(device_id, "running")
    if latest is None or latest.get("text") is None:
        return False
    facts = facts_for(store, device_id)
    had = {row["standard"] for row in store.compliance(device_id)}
    wrote = False
    for row in store.standards():
        if names is not None and row["name"] not in names:
            continue
        standard = standards.parse(row["text"], row["name"])
        standard.name = row["name"]
        if not standards.applies(standard, facts):
            if row["name"] in had:
                store.drop_compliance(device_id, row["name"])
                wrote = True
            continue
        results = standards.check(standard, latest["text"], facts)
        store.save_compliance(device_id, row["name"], result_dicts(results), latest["id"], now)
        wrote = True
    return wrote


def recheck_all(store, names=None, now=None):
    """recheck for every archived device (after a standard is saved)."""
    wrote = False
    for device in store.devices():
        wrote = recheck(store, device["id"], names, now) or wrote
    return wrote
