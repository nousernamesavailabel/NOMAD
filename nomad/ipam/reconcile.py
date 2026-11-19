"""Comparing what's on the network (a sweep, or the ARP table) with what IPAM has recorded.

Each device found is either recorded (with its name), not recorded, recorded with a different MAC address, or
answering on an address IPAM holds as reserved; and each address IPAM records as used that didn't answer is listed
as silent (it may be off, gone, or firewalled: worth checking, not proof it's free).

Several IPAM networks can hold the same range (separate, air-gapped networks), so the caller picks which network
to compare with; candidate_networks suggests them, best match first.
"""
import ipaddress
from dataclasses import dataclass

from ..oui import normalize_mac
from .store import RESERVED

RECORDED, NOT_RECORDED, MAC_DIFFERS, RESERVED_IN_USE = "recorded", "not recorded", "mac differs", "reserved in use"
PROXY_ARP = "proxy arp"  # Only a router or firewall answered ARP for it, with its own MAC: nothing's there


@dataclass
class Finding:
    ip: str
    state: str
    text: str  # For the IPAM column
    record: object = None  # The Address, when IPAM has one


def candidate_networks(stores, addresses):
    """Networks whose subnets hold any of `addresses`: [(source, network, how many they hold)], most first."""
    addresses = [ipaddress.ip_address(address) for address in addresses]
    candidates = []
    for source, store in stores:
        for network in store.networks():
            blocks = [subnet.network for subnet in store.subnets(network.id)]
            held = sum(1 for address in addresses if any(address in block for block in blocks))
            if held:
                candidates.append((source, network, held))
    return sorted(candidates, key=lambda candidate: (-candidate[2], candidate[1].name.lower()))


def proxy_arp(found, arp_only, records=None):
    """Which ARP-only replies were proxy ARP: a router or firewall answering ARP, with its own MAC, for addresses it
    can reach though nothing is there. That's an ARP-only reply whose MAC another address answered ping with, or
    IPAM records at another address.

    found: {ip: (mac, name)}; arp_only: the ips that answered ARP but not ping; records: {ip: Address or None}
    IPAM has for them. Returns {ip: the address the MAC belongs to, or "" when several addresses answered ARP alone
    with it and none owns it}."""
    records = records or {}
    by_mac = {}
    for ip, (mac, _name) in found.items():
        if normalize_mac(mac):
            by_mac.setdefault(normalize_mac(mac), []).append(ip)
    proxied = {}
    for ip in arp_only:
        mac = normalize_mac(found.get(ip, ("", ""))[0])
        if not mac:
            continue
        sharing = by_mac.get(mac, [])
        recorded = {other for other in sharing if records.get(other) is not None and
                    normalize_mac(records[other].mac) == mac}
        if ip in recorded:
            continue  # IPAM says this MAC is the device at this address
        others = [other for other in sharing if other != ip]
        owners = sorted({other for other in others if other not in arp_only} | recorded, key=ipaddress.ip_address)
        if owners:
            proxied[ip] = owners[0]
        elif others:
            proxied[ip] = ""
    return proxied


def compare(found, store, network_id, arp_only=()):
    """found: {ip: (mac, name)} from the network; arp_only: those that answered ARP but not ping. Returns
    {ip: Finding} for the addresses in the IPAM network's subnets (or recorded in it); others (another network's,
    link-local...) aren't judged against it."""
    blocks = [subnet.network for subnet in store.subnets(network_id)]
    records = {ip: store.address(network_id, ip) for ip in found}
    proxied = proxy_arp(found, arp_only, records)
    findings = {}
    for ip, (mac, _name) in found.items():
        record = records[ip]
        if record is None and not any(ipaddress.ip_address(ip) in block for block in blocks):
            continue
        if ip in proxied:
            owner = proxied[ip]
            text = f"Proxy ARP from {owner}" if owner else "Proxy ARP (MAC shared, owner unknown)"
            if record is not None and record.status != RESERVED:
                text += f": IPAM has {record.name or 'no name'}, which didn't answer"
            findings[ip] = Finding(ip, PROXY_ARP, text, record)
            continue
        if record is None:
            findings[ip] = Finding(ip, NOT_RECORDED, "Not in IPAM")
            continue
        label = record.name or "no name"
        if mac and record.mac and normalize_mac(mac) != normalize_mac(record.mac):
            findings[ip] = Finding(ip, MAC_DIFFERS, f"MAC differs (IPAM has {record.mac} for {label})", record)
        elif record.status == RESERVED and not record.name:
            findings[ip] = Finding(ip, RESERVED_IN_USE, "Reserved in IPAM, but a device answers", record)
        else:
            findings[ip] = Finding(ip, RECORDED, f"In IPAM: {label}", record)
    return findings


def silent(store, network_id, answered, within):
    """Addresses IPAM records as used in the `within` range(s) (Blocks or networks) that didn't answer."""
    answered = {ipaddress.ip_address(address) for address in answered}
    quiet = []
    seen = set()
    for block in within:
        for record in store.addresses(network_id, block):
            if record.status != RESERVED and record.address not in answered and record.ip not in seen:
                seen.add(record.ip)
                quiet.append(record)
    return sorted(quiet, key=lambda record: (record.address.version, record.address))
