"""Subnet placement: where each subnet is planned to be (the VLANs it's linked to on the VLANs page), where the
network map finds it, and whether it's advertised, so a subnet that must be in one place isn't in two.

Kept in the IPAM database beside the VLANs: per subnet of a network, its scope when the map's routing tables
don't say it right (Placement: advertised or local, or its places one L2 segment the map can't see), and moves
(SubnetMove) between VLANs or devices, including routed destinations without a VLAN. Finishing a move removes the
old VLAN link and adds the new one when specified, in the same change. And what a subnet is for (its role, see
roles.py) where someone set it. As with VLANs,
nothing is written to IPAM's networks, subnets or addresses.

evaluate() puts the database and a map's netmap.placement.analyze() together into Rows, with what's wrong with each.
"""
import datetime
import ipaddress
import uuid
from dataclasses import dataclass, field

from ..netmap.placement import GLOBAL, segment_text, vrf_text
from .roles import LOOPBACK, ONE_PLACE, POINT_TO_POINT, ROLE_NAMES, TUNNEL, VLAN, inside, loopback_pool, role_info, \
    single_address
from .store import IpamError, Placement, SubnetMove, SubnetRole, _from_row, parse_subnet, subnet_key
from .vlans import ACTIVE, VlanStore, check_number

AUTO, ADVERTISED, LOCAL, UNKNOWN = "auto", "advertised", "local", "unknown"
SCOPES = {AUTO: "Automatic (from the routing tables)", ADVERTISED: "Advertised: must be in one place",
          LOCAL: "Local only: may be in several places"}
PLANNED, IN_PROGRESS, DONE, CANCELLED = "planned", "in progress", "done", "cancelled"
MOVE_STATUSES = {PLANNED: "Planned", IN_PROGRESS: "In progress", DONE: "Done", CANCELLED: "Cancelled"}
OPEN = (PLANNED, IN_PROGRESS)
PROBLEM, WARNING, NOTE = "problem", "warning", "note"
SEVERITY_ORDER = {PROBLEM: 0, WARNING: 1, NOTE: 2}
SEVERITY_LABELS = {PROBLEM: "Problem", WARNING: "Warning", NOTE: "Note"}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class PlacementStore:
    """Placements and moves in an IpamStore (this computer's, the server's, or a laptop's copy of the server's)."""

    def __init__(self, store):
        self.store = store

    @property
    def db(self):
        return self.store.db

    # ----------------------------------------------------------------- How subnets are treated

    def placements(self, network_id):
        """{CIDR: Placement} for the network."""
        rows = self.db.execute("SELECT * FROM placements WHERE network_id = ? AND deleted = 0", (network_id,))
        return {row["cidr"]: _from_row(Placement, row) for row in rows}

    def placement(self, network_id, cidr):
        return self.placements(network_id).get(str(parse_subnet(cidr)))

    def set_placement(self, network_id, cidr, scope=AUTO, one_segment=False, note=""):
        """How to treat a subnet; back to automatic (and no note) forgets it."""
        if scope not in SCOPES:
            raise IpamError(f"Unknown scope {scope!r}.")
        cidr = str(parse_subnet(cidr))
        values = dict(scope=scope, one_segment=bool(one_segment), note=note.strip())
        with self.store.transaction():
            self.store.network(network_id)
            existing = self.placement(network_id, cidr)
            if scope == AUTO and not one_segment and not values["note"]:
                if existing is not None:
                    self.store._delete("placements", existing)
                return None
            if existing is not None:
                return self.store._update("placements", existing, values)
            return self.store._insert("placements", Placement(uuid.uuid4().hex, network_id, cidr, **values))

    # ----------------------------------------------------------------- What subnets are for

    def roles(self, network_id):
        """{CIDR: SubnetRole} for the network's subnets someone set a role for."""
        rows = self.db.execute("SELECT * FROM subnet_roles WHERE network_id = ? AND deleted = 0", (network_id,))
        return {row["cidr"]: _from_row(SubnetRole, row) for row in rows}

    def role(self, network_id, cidr):
        return self.roles(network_id).get(str(parse_subnet(cidr)))

    def set_role(self, network_id, cidr, role=AUTO):
        """What a subnet is for (roles.ROLE_NAMES); back to automatic forgets it."""
        if role != AUTO and role not in ROLE_NAMES:
            raise IpamError(f"Unknown role {role!r}.")
        cidr = str(parse_subnet(cidr))
        with self.store.transaction():
            self.store.network(network_id)
            existing = self.role(network_id, cidr)
            if role == AUTO:
                if existing is not None:
                    self.store._delete("subnet_roles", existing)
                return None
            if existing is not None:
                return self.store._update("subnet_roles", existing, {"role": role})
            return self.store._insert("subnet_roles", SubnetRole(uuid.uuid4().hex, network_id, cidr, role))

    # ----------------------------------------------------------------- Moves

    def moves(self, network_id, cidr=None, open_only=False):
        """The network's moves (of one subnet), newest first."""
        query, arguments = "SELECT * FROM subnet_moves WHERE network_id = ? AND deleted = 0", [network_id]
        if cidr is not None:
            query += " AND sort_key = ?"
            arguments.append(subnet_key(parse_subnet(cidr)))
        moves = [_from_row(SubnetMove, row) for row in self.db.execute(query + " ORDER BY modified DESC", arguments)]
        return [move for move in moves if move.status in OPEN] if open_only else moves

    def move(self, move_id):
        return self.store._get("subnet_moves", move_id)

    def open_move(self, network_id, cidr):
        moves = self.moves(network_id, cidr, open_only=True)
        return moves[0] if moves else None

    def plan_move(self, network_id, cidr, from_domain_id="", from_vlan=0, from_device="", to_domain_id="", to_vlan=0,
                  to_device="", planned_for="", note=""):
        cidr = str(parse_subnet(cidr))
        if bool(to_domain_id) != bool(to_vlan):
            raise IpamError("Choose the VLAN and domain it's moving to, or neither for a move without a VLAN.")
        from_device, to_device = from_device.strip(), to_device.strip()
        if not to_vlan and not to_device:
            raise IpamError("Choose the device it's moving to without a VLAN.")
        to_vlan = check_number(to_vlan) if to_vlan else 0
        from_vlan = check_number(from_vlan) if from_vlan else 0
        if (from_domain_id, from_vlan, from_device) == (to_domain_id, to_vlan, to_device):
            raise IpamError("It's moving to where it is already.")
        with self.store.transaction():
            self.store.network(network_id)
            vlans = VlanStore(self.store)
            for domain_id in {from_domain_id, to_domain_id} - {""}:
                vlans.domain(domain_id)
            current = self.open_move(network_id, cidr)
            if current is not None:
                raise IpamError(f"{cidr} is being moved already ({MOVE_STATUSES[current.status].lower()}, by "
                                f"{current.modified_by}): finish or cancel that move first.")
            return self.store._insert("subnet_moves", SubnetMove(
                uuid.uuid4().hex, network_id, cidr, from_domain_id, from_vlan, from_device.strip(), to_domain_id,
                to_vlan, to_device.strip(), PLANNED, planned_for.strip(), note.strip()))

    def update_move(self, move_id, **changes):
        """Change a move that isn't finished: its details, or start it (status IN_PROGRESS), or cancel it."""
        with self.store.transaction():
            move = self.move(move_id)
            if move.status not in OPEN:
                raise IpamError(f"That move is {MOVE_STATUSES[move.status].lower()} already.")
            status = changes.get("status", move.status)
            if status == DONE:
                raise IpamError("Finish a move with Complete Move, which also relinks the subnet's VLANs.")
            if status not in MOVE_STATUSES:
                raise IpamError(f"Unknown move status {status!r}.")
            if status == CANCELLED:
                changes["finished"] = now()
            for name in ("from_vlan", "to_vlan"):
                if changes.get(name):
                    changes[name] = check_number(changes[name])
            return self.store._update("subnet_moves", move, changes)

    def complete_move(self, move_id):
        """Mark a move done and relink the subnet: out of the VLAN it moved from, into the one it moved to (added to
        that domain if it isn't there yet), or without a new link for a routed move, all at once."""
        with self.store.transaction():
            move = self.move(move_id)
            if move.status not in OPEN:
                raise IpamError(f"That move is {MOVE_STATUSES[move.status].lower()} already.")
            vlans = VlanStore(self.store)
            for vlan in vlans.vlans(move.from_domain_id) if move.from_domain_id else []:
                if move.cidr in vlan.subnets and (not move.from_vlan or vlan.vlan == move.from_vlan or
                                                  move.from_domain_id != move.to_domain_id):
                    vlans.set_vlan(vlan.domain_id, vlan.vlan, vlan.name, vlan.status,
                                   [cidr for cidr in vlan.subnets if cidr != move.cidr], vlan.description, vlan.fields)
            for vlan in vlans.vlans(move.to_domain_id) if move.to_domain_id else []:
                if move.cidr in vlan.subnets and vlan.vlan != move.to_vlan:
                    vlans.set_vlan(vlan.domain_id, vlan.vlan, vlan.name, vlan.status,
                                   [cidr for cidr in vlan.subnets if cidr != move.cidr], vlan.description, vlan.fields)
            if move.to_domain_id and move.to_vlan:
                target = vlans.vlan(move.to_domain_id, move.to_vlan)
                if target is None:
                    vlans.set_vlan(move.to_domain_id, move.to_vlan, "", ACTIVE, [move.cidr])
                elif move.cidr not in target.subnets:
                    vlans.set_vlan(target.domain_id, target.vlan, target.name, target.status,
                                   target.subnets + [move.cidr], target.description, target.fields)
            return self.store._update("subnet_moves", move, {"status": DONE, "finished": now()})


# --------------------------------------------------------------------- Putting the plan and the map together

@dataclass
class Finding:
    severity: str
    text: str


@dataclass
class Row:
    """One subnet (in one VRF) on the Subnet Placement page."""
    vrf: str
    cidr: str
    subnet: object = None  # The IPAM Subnet, or None
    found: object = None  # netmap.placement.MapSubnet, or None when the map doesn't have it
    planned: list = field(default_factory=list)  # [(VlanDomain, Vlan)] it's linked to
    placement: object = None  # Placement, or None (automatic)
    move: object = None  # The SubnetMove under way, or None
    scope: str = UNKNOWN  # ADVERTISED, LOCAL or UNKNOWN, after any override
    scope_why: str = ""
    role: object = None  # roles.RoleInfo: what it's for
    pool: object = None  # For a single address on the map: IPAM's loopback subnet holding it, or None
    findings: list = field(default_factory=list)

    @property
    def network(self):
        return ipaddress.ip_network(self.cidr)

    @property
    def severity(self):
        """The worst finding's, or ""."""
        return min((finding.severity for finding in self.findings), key=SEVERITY_ORDER.get, default="")

    @property
    def places(self):
        return [place for segment in (self.found.segments if self.found else []) for place in segment]

    @property
    def map_vlans(self):
        return sorted({place.vlan for place in self.places if place.vlan})

    @property
    def one_segment(self):
        """Whether its places count as one: marked so, or a tunnel's or point-to-point link's ends."""
        return (self.placement is not None and self.placement.one_segment) or \
            (self.role is not None and self.role.role in ONE_PLACE)


def evaluate(network_map, ipam_store, vlan_store, placement_store, network_id):
    """Rows for the network's subnets and every subnet on the map (None: no map), with their findings, worst first
    within each, sorted by VRF then address."""
    from ..netmap.placement import analyze
    subnets = {subnet.cidr: subnet for subnet in ipam_store.subnets(network_id)} if network_id else {}
    domains = [domain for domain in vlan_store.domains() if not network_id or domain.network_id == network_id]
    planned = {}
    for domain in domains:
        for vlan in vlan_store.vlans(domain.id):
            for cidr in vlan.subnets:
                planned.setdefault(cidr, []).append((domain, vlan))
    placements = placement_store.placements(network_id) if network_id else {}
    roles = placement_store.roles(network_id) if network_id else {}
    moves = {}
    for move in (placement_store.moves(network_id, open_only=True) if network_id else []):
        moves.setdefault(move.cidr, move)
    found = analyze(network_map) if network_map is not None else []

    rows = {}
    for item in found:
        rows[(item.vrf, item.cidr)] = Row(item.vrf, item.cidr, found=item)
    on_map = {cidr for _, cidr in rows}
    for cidr in set(subnets) | set(planned) | set(placements) | set(moves) | set(roles):
        if cidr not in on_map:
            rows[(GLOBAL, cidr)] = Row(GLOBAL, cidr)
    for row in rows.values():
        row.subnet = subnets.get(row.cidr)
        row.planned = planned.get(row.cidr, [])
        row.placement = placements.get(row.cidr)
        row.move = moves.get(row.cidr)
        if row.subnet is None:
            row.pool = loopback_pool(subnets.values(), row.network)
        row.role = role_info(row.cidr, roles.get(row.cidr), subnet=row.subnet, places=row.places,
                             network_map=network_map, linked=[vlan.vlan for _, vlan in row.planned],
                             inner=inside(row.subnet, subnets.values()) if row.subnet is not None else (),
                             pool=row.pool)
        _scope(row, network_map is not None, network_map)
        _findings(row, network_map, subnets, network_id, bool(domains))
    _overlaps(rows.values(), network_map)
    for row in rows.values():
        row.findings.sort(key=lambda finding: SEVERITY_ORDER[finding.severity])
    return sorted(rows.values(), key=lambda row: (row.vrf, row.network.version, row.network))


def _scope(row, have_map, network_map=None):
    placement, item = row.placement, row.found

    def labels(keys):
        devices = network_map.devices if network_map is not None else {}
        return [devices[key].label if key in devices else key for key in keys]

    learned = item.learned if item is not None else []
    if learned:
        routers = {route.device for route in learned}
        detected = (ADVERTISED, f"{', '.join(item.protocols)}: {len(routers)} other device"
                                f"{'s' if len(routers) != 1 else ''} {'have' if len(routers) != 1 else 'has'} a route to it"
                                + (f", leading to {', '.join(labels(item.advertisers))}" if item.advertisers else ""))
    elif item is not None and item.advertised is None:
        detected = (UNKNOWN, "no other device has a route to it, but some routes in its VRF couldn't be read")
    elif item is not None:
        detected = (LOCAL, "no other device has a route to it")
        if item.summaries:
            summary, keys = item.summaries[0]
            detected = (LOCAL, f"only covered by the summary {summary} (on {len(keys)} device"
                               f"{'s' if len(keys) != 1 else ''})")
    else:
        detected = (UNKNOWN, "not on the map" if have_map else "no network map open")
    if placement is not None and placement.scope != AUTO:
        row.scope = placement.scope
        row.scope_why = f"set by {placement.modified_by}" + (f" ({placement.note})" if placement.note else "") + \
            f"; the map: {detected[1]}"
    else:
        row.scope, row.scope_why = detected


def _findings(row, network_map, subnets, network_id, has_domains=False):
    add = row.findings.append
    item, move, role = row.found, row.move, row.role.role
    one_segment = row.one_segment
    segments = item.segments if item is not None else []
    devices = sorted({place.device for place in row.places})
    duplicate_loopback = role == LOOPBACK and single_address(row.network) and len(devices) > 1
    if duplicate_loopback:
        add(Finding(PROBLEM, f"The same loopback address on {len(devices)} devices: "
                             f"{'; '.join(segment_text(network_map, segment) for segment in segments)}. Each device's "
                             "loopback must be its own (it's often the router ID)."))
    if role == POINT_TO_POINT and len(devices) > 2:
        add(Finding(WARNING, f"A point-to-point subnet, but {len(devices)} devices have addresses in it: "
                             f"{'; '.join(segment_text(network_map, segment) for segment in segments)}."))
    if row.role.mismatch():
        add(Finding(WARNING, row.role.mismatch()))
    if row.planned and role in (TUNNEL, LOOPBACK):
        where = ", ".join(f"VLAN {vlan.vlan} ({domain.name})" for domain, vlan in row.planned)
        add(Finding(WARNING, f"Linked to {where} on the VLANs page, but it's a {ROLE_NAMES[role].lower()}: those "
                             "aren't in VLANs."))
    if row.scope == ADVERTISED and len(segments) > 1 and not one_segment and not duplicate_loopback:
        where = "; ".join(segment_text(network_map, segment) for segment in segments)
        if move is not None and move.status == IN_PROGRESS:
            add(Finding(PROBLEM, f"Advertised from both its old and new place while it moves: {where}. Remove it from "
                                 "the old place to finish the move."))
        else:
            add(Finding(PROBLEM, f"Advertised, but in {len(segments)} places: {where}. An advertised subnet can be in "
                                 "one place only (if these are one L2 segment the map can't see, mark it One Segment)."))
    if item is not None and len(item.origins) > 1 and not one_segment:
        reach = {}
        for route in item.learned:
            if route.origin is not None:
                reach.setdefault(route.origin, []).append(network_map.devices[route.device].label
                                                          if route.device in network_map.devices else route.device)
        parts = [f"{', '.join(sorted(devices)[:4])} reach it at {segment_text(network_map, segments[origin])}"
                 for origin, devices in sorted(reach.items())]
        add(Finding(PROBLEM, "Routers reach it in different places: " + "; ".join(parts) + "."))
    placement = row.placement
    if placement is not None and placement.scope == LOCAL and item is not None and item.learned:
        routers = sorted({route.device for route in item.learned})
        names = ", ".join(network_map.devices[key].label for key in routers[:4] if key in network_map.devices)
        add(Finding(WARNING, f"Marked local only, but {len(routers)} other device{'s' if len(routers) != 1 else ''} "
                             f"({names}) {'have' if len(routers) != 1 else 'has'} a route to it "
                             f"({', '.join(item.protocols)}): it's leaking."))
    if placement is not None and placement.scope == ADVERTISED and item is not None and item.advertised is False:
        add(Finding(WARNING, "Marked advertised, but no other device has a route to it."))
    plan_vlans = sorted({vlan.vlan for _, vlan in row.planned})
    advertised = row.scope == ADVERTISED
    if advertised and len(row.planned) > 1:
        where = ", ".join(f"VLAN {vlan.vlan} in {domain.name}" for domain, vlan in row.planned)
        add(Finding(PROBLEM, f"Advertised, but linked to {len(row.planned)} VLANs: {where}. It can be in one place "
                             "only (Move Subnet keeps one link)."))
    if item is not None and row.planned:
        expected = set(plan_vlans)
        if move is not None:
            expected |= {move.to_vlan}
        stray = [place for place in row.places if place.vlan and place.vlan not in expected]
        if stray:
            where = ", ".join(f"{network_map.devices[place.device].label} {place.port}" for place in stray[:4])
            add(Finding(WARNING, f"On the map in VLAN {', '.join(str(vlan) for vlan in sorted({place.vlan for place in stray}))} "
                                 f"({where}), but linked to VLAN {', '.join(str(vlan) for vlan in plan_vlans)}"
                                 + (" (plan a move, or link it where it is)" if move is None else "") + "."))
    if item is not None and not row.planned and row.map_vlans and row.subnet is not None and role == VLAN:
        add(Finding(NOTE, f"In VLAN {', '.join(str(vlan) for vlan in row.map_vlans)} on the map, but not linked to a "
                          "VLAN on the VLANs page."))
    elif not row.planned and not row.map_vlans and row.subnet is not None and role == VLAN and has_domains:
        add(Finding(NOTE, f"A VLAN's subnet ({row.role.why}), but not linked to a VLAN on the VLANs page."))
    if item is None and row.planned and network_map is not None:
        add(Finding(NOTE, "Linked to " + ", ".join(f"VLAN {vlan.vlan} ({domain.name})" for domain, vlan in row.planned)
                          + ", but no device on the map has an address in it."))
    if item is not None and network_id and row.subnet is None and row.pool is None:
        add(Finding(NOTE, "Not a subnet in this IPAM network."))
    left_over = [what for what, there in (("linked to " + ", ".join(f"VLAN {vlan.vlan} ({domain.name})"
                                                                    for domain, vlan in row.planned), row.planned),
                                          ("given a role", row.role.set is not None),
                                          ("given a scope", row.placement is not None)) if there]
    if network_id and row.subnet is None and row.pool is None and left_over:
        add(Finding(WARNING, f"Not a subnet in IPAM now (deleted, or moved to another network?), but still "
                             f"{' and '.join(left_over)}: unlink it on the VLANs page, or set it back to automatic "
                             "(Role and Scope)."))
    if item is not None and not item.learned and item.summaries:
        summary, keys = item.summaries[0]
        names = ", ".join(network_map.devices[key].label for key in keys[:4] if key in network_map.devices)
        add(Finding(NOTE, f"Only covered by the summary {summary} ({names}), so it's counted as local."))
    if item is not None and (item.unseen or item.unread):
        devices = network_map.devices
        parts = []
        for address, keys in item.unseen.items():
            users = ", ".join(devices[key].label for key in keys[:3] if key in devices)
            parts.append(f"{address} (a next hop of {users}'s routes)")
        for key, on, port in item.unread:
            parts.append(f"{devices[key].label} (linked to {devices[on].label} {port}, didn't answer SNMP)")
        add(Finding(NOTE, "Also on it, but not read by the map: " + "; ".join(parts) + ". A router there may "
                          "advertise it too; map it with SNMP to see."))
    if item is not None and item.routes_unknown:
        add(Finding(NOTE, f"The routes in VRF {vrf_text(row.vrf)} couldn't be read on "
                          f"{len(item.routes_unknown)} device{'s' if len(item.routes_unknown) != 1 else ''}."))
    if item is not None and row.scope != ADVERTISED and len(segments) > 1 and not one_segment and \
            not duplicate_loopback:
        add(Finding(NOTE, f"Local, in {len(segments)} places (a local subnet may be)."))
    if move is not None:
        add(Finding(NOTE, f"Moving ({MOVE_STATUSES[move.status].lower()}): {move_check(row, move, network_map)[1]}"))


def _overlaps(rows, network_map):
    """An advertised subnet inside another advertised one connected somewhere else: traffic for it goes to the more
    specific one, which is easy to do by mistake."""
    advertised = [row for row in rows if row.scope == ADVERTISED and row.found is not None]
    for inner in advertised:
        for outer in advertised:
            if outer is inner or outer.vrf != inner.vrf or outer.network.version != inner.network.version:
                continue
            if inner.network.subnet_of(outer.network) and inner.network != outer.network:
                inner_devices = {place.device for place in inner.places}
                outer_devices = {place.device for place in outer.places}
                if not inner_devices & outer_devices:
                    where = "; ".join(segment_text(network_map, segment) for segment in outer.found.segments)
                    inner.findings.append(Finding(WARNING, f"Inside {outer.cidr}, which is advertised from {where}: "
                                                           "traffic for it goes here instead."))


def move_check(row, move, network_map):
    """Whether a move looks done on the map: (done, why), done True when the subnet is only at the new place (its
    VLAN, and device when one was given) and every route to it leads there."""
    item = row.found
    if network_map is None:
        return False, "no network map open to check it on"
    if item is None:
        return False, "no device on the map has an address in it (read the routes again once it's up at the new place)"

    def at(place, vlan, device):
        return place.vlan == vlan and (not device or place.device == device)

    def label(place):
        device = network_map.devices.get(place.device)
        return f"{device.label if device is not None else place.device} {place.port}"

    places = item_places(item)
    new = [place for place in places if at(place, move.to_vlan, move.to_device)]
    knows_old = bool(move.from_vlan or move.from_device)  # Else anywhere but the new place is the old one
    old = [place for place in places if place not in new and (not knows_old or at(place, move.from_vlan,
                                                                                    move.from_device))]
    others = [place for place in places if place not in new and place not in old]
    if not new:
        destination = f"VLAN {move.to_vlan}" if move.to_vlan else "no VLAN"
        return False, f"not at the new place yet ({destination}" + (f" on {move.to_device}" if move.to_device
                                                                      else "") + ")"
    if old:
        return False, f"still at the old place too: {', '.join(label(place) for place in old[:3])}"
    if others and row.scope == ADVERTISED:
        return False, f"also at {', '.join(label(place) for place in others[:3])}"
    new_segments = {number for number, segment in enumerate(item.segments) if any(place in new for place in segment)}
    astray = [route for route in item.learned if route.origin is not None and route.origin not in new_segments]
    if astray:
        names = ", ".join(network_map.devices[route.device].label for route in astray[:3]
                          if route.device in network_map.devices)
        return False, f"{names} still reach it at the old place"
    return True, f"it's only at {', '.join(label(place) for place in new[:3])}" + \
        (" and every route to it leads there" if item.learned else "")


def item_places(item):
    return [place for segment in item.segments for place in segment]
