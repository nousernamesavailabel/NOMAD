"""Moving a subnet from one IPAM network to another: once the addressing is imported, a plan changes and a block turns
out to belong to another network (another enclave's page, say).

The subnet goes with its recorded addresses, and (if asked) the subnets inside it with theirs. What's said about it
beside IPAM goes too: its role and how it's treated (Subnet Placement). Its VLAN links belong to the old network's
VLAN domains, so they're dropped, and it can be linked to a VLAN of the new network's instead. It's refused while
the new network has anything in the way (a subnet overlapping it, or an address recorded in it) or a placement move
of it is under way.

plan() says what would happen; move() does it within one database (this computer's, or the server's for the tribe:
one change, all or nothing). From this computer to the tribe, payload() is sent for the server to receive() and
then remove() takes it from here. In the old network it shows as deleted, and in the new one as made (history).

A whole network of this computer's can become a tribe network too, with its VLAN domains and their VLANs (when a map
of it is shared with the tribe): share_network(), which is the one way a laptop can add a network to the tribe.
"""
import uuid
from dataclasses import dataclass, field

from .placement import PlacementStore
from .roles import AUTO
from .store import Address, IpamError, Subnet, parse_subnet
from .vlans import ACTIVE, VlanStore


@dataclass
class MovePlan:
    network_id: str  # Where it is
    cidr: str
    subnets: list = field(default_factory=list)  # Subnets moving: it, then the ones inside it taken along
    left: list = field(default_factory=list)  # Subnets inside it staying behind
    addresses: list = field(default_factory=list)  # Addresses moving
    links: list = field(default_factory=list)  # [(VlanDomain, Vlan)] in the old network linking a moving subnet
    roles: dict = field(default_factory=dict)  # CIDR -> role set, for the moving subnets
    placements: dict = field(default_factory=dict)  # CIDR -> Placement, for the moving subnets
    problems: list = field(default_factory=list)  # Why it can't move (empty: it can)

    @property
    def cidrs(self):
        return [subnet.cidr for subnet in self.subnets]


def inside(subnet, subnets):
    network = subnet.network
    return [other for other in subnets if other.id != subnet.id and other.network.version == network.version
            and other.network != network and other.network.subnet_of(network)]


def plan(store, network_id, cidr, take_nested=True):
    """What moving a subnet (and the ones inside it, with take_nested) out of a network would take."""
    cidr = str(parse_subnet(cidr))
    subnets = store.subnets(network_id)
    subnet = next((item for item in subnets if item.cidr == cidr), None)
    if subnet is None:
        raise IpamError(f"{cidr} isn't a subnet of that network now.")
    nested = inside(subnet, subnets)
    result = MovePlan(network_id, cidr, [subnet] + (nested if take_nested else []), [] if take_nested else nested)
    staying = [item.network for item in result.left]
    result.addresses = [address for address in store.addresses(network_id, subnet.network)
                        if not any(address.address in block for block in staying)]
    copy = getattr(store, "copy", store)  # The tribe's: read from this computer's copy
    vlans, placements = VlanStore(copy), PlacementStore(copy)
    moving = set(result.cidrs)
    for domain in vlans.domains():
        if domain.network_id == network_id:
            for vlan in vlans.vlans(domain.id):
                if moving & set(vlan.subnets):
                    result.links.append((domain, vlan))
    result.roles = {cidr: role.role for cidr, role in placements.roles(network_id).items() if cidr in moving}
    result.placements = {cidr: item for cidr, item in placements.placements(network_id).items() if cidr in moving}
    for item in result.subnets:
        for move in placements.moves(network_id, item.cidr, open_only=True):
            result.problems.append(f"{item.cidr} is being moved on the Subnet Placement page ("
                                   f"{move.status}): finish or cancel that first.")
    return result


def check_target(target_store, to_network_id, cidrs):
    """Problems with putting subnets (CIDRs, the block moving first) into a network: [text]. A subnet there
    overlapping one, or an address recorded there in the block, is in the way."""
    problems = []
    target_store.network(to_network_id)
    blocks = [parse_subnet(cidr) for cidr in cidrs]
    for other in target_store.subnets(to_network_id):
        theirs = other.network
        clash = next((block for block in blocks if block.version == theirs.version
                      and block.first <= theirs.last and theirs.first <= block.last), None)
        if clash is not None:
            problems.append(f"{other.cidr}" + (f" ({other.name})" if other.name else "") + f" is in the way: it "
                            f"overlaps {clash}.")
    taken = [address.ip for address in target_store.addresses(to_network_id, blocks[0])] if blocks else []
    if taken:
        listed = ", ".join(taken[:6]) + (f" and {len(taken) - 6} more" if len(taken) > 6 else "")
        problems.append(f"Addresses in it are recorded there already: {listed}.")
    return problems


def payload(move):
    """What the new network receives, as plain data (for the server)."""
    return {"subnets": [dict(cidr=item.cidr, name=item.name, gateway=item.gateway, description=item.description,
                             fields=dict(item.fields), loopbacks=bool(item.loopbacks)) for item in move.subnets],
            "addresses": [dict(ip=item.ip, status=item.status, name=item.name, mac=item.mac,
                               description=item.description, fields=dict(item.fields)) for item in move.addresses],
            "roles": dict(move.roles),
            "placements": {cidr: dict(scope=item.scope, one_segment=bool(item.one_segment), note=item.note)
                           for cidr, item in move.placements.items()}}


def receive(store, to_network_id, data, link=None):
    """Put moved subnets and addresses into a network (inside the caller's transaction), with their roles and
    placements, and link the first subnet to a VLAN: link = (domain id, VLAN number) of a domain of that network."""
    problems = check_target(store, to_network_id, [item["cidr"] for item in data["subnets"]])
    if problems:
        raise IpamError("It can't go there: " + " ".join(problems))
    for item in data["subnets"]:
        store._insert("subnets", Subnet(uuid.uuid4().hex, to_network_id, str(parse_subnet(item["cidr"])),
                                        item.get("name", ""), item.get("gateway", ""), item.get("description", ""),
                                        dict(item.get("fields") or {}), bool(item.get("loopbacks"))))
    for item in data["addresses"]:
        store._insert("addresses", Address(uuid.uuid4().hex, to_network_id, item["ip"], item.get("status", "used"),
                                           item.get("name", ""), item.get("mac", ""), item.get("description", ""),
                                           dict(item.get("fields") or {})))
    placements = PlacementStore(store)
    for cidr, role in (data.get("roles") or {}).items():
        if role and role != AUTO:
            placements.set_role(to_network_id, cidr, role)
    for cidr, values in (data.get("placements") or {}).items():
        placements.set_placement(to_network_id, cidr, values.get("scope", AUTO), bool(values.get("one_segment")),
                                 values.get("note", ""))
    if link and data["subnets"]:
        domain_id, number = link
        vlans = VlanStore(store)
        domain = vlans.domain(domain_id)
        if domain.network_id != to_network_id:
            raise IpamError(f"The VLAN domain {domain.name} isn't the new network's.")
        cidr = str(parse_subnet(data["subnets"][0]["cidr"]))
        vlan = vlans.vlan(domain_id, number)
        if vlan is None:
            vlans.set_vlan(domain_id, number, "", ACTIVE, [cidr])
        elif cidr not in vlan.subnets:
            vlans.set_vlan(domain_id, number, vlan.name, vlan.status, vlan.subnets + [cidr], vlan.description,
                           vlan.fields)


def remove(store, move):
    """Take what moved out of the old network (inside the caller's transaction): its subnets and addresses, their
    roles and placements, and their VLAN links."""
    for item in move.addresses:
        store._delete("addresses", store._get("addresses", item.id))
    for item in move.subnets:
        store._delete("subnets", store._get("subnets", item.id))
    placements = PlacementStore(store)
    for cidr in move.roles:
        placements.set_role(move.network_id, cidr, AUTO)
    for cidr in move.placements:
        placements.set_placement(move.network_id, cidr)
    vlans = VlanStore(store)
    moving = set(move.cidrs)
    for domain, vlan in move.links:
        current = vlans.vlan(domain.id, vlan.vlan)
        if current is not None:
            vlans.set_vlan(domain.id, current.vlan, current.name, current.status,
                           [cidr for cidr in current.subnets if cidr not in moving], current.description,
                           current.fields)


def to_tribe(local, team, network_id, cidr, to_network_id, take_nested=True, link=None):
    """Move a subnet from one of this computer's networks into one of the tribe's: the server takes it (refusing it
    if something's in the way), then it's taken out of this computer's. Returns the MovePlan done."""
    done = plan(local, network_id, cidr, take_nested)
    if done.problems:
        raise IpamError(" ".join(done.problems))
    team.take_subnets(to_network_id, payload(done), link)
    with local.transaction():
        remove(local, done)
    return done


@dataclass
class NetworkPlan:
    """What sharing a whole network of this computer's with the tribe would take."""
    network: object
    move: MovePlan  # Its subnets, addresses, roles and placements, as a move of them
    domains: list = field(default_factory=list)  # [(VlanDomain, [Vlan])] of the network


def plan_network(store, network_id):
    """A whole network, as plan() says for a subnet: everything in it goes, with its VLAN domains."""
    network = store.network(network_id)
    subnets = store.subnets(network_id)
    vlans, placements = VlanStore(store), PlacementStore(store)
    moving = {subnet.cidr for subnet in subnets}
    move = MovePlan(network_id, "", subnets, [], store.addresses(network_id))
    move.roles = {cidr: role.role for cidr, role in placements.roles(network_id).items() if cidr in moving}
    move.placements = {cidr: item for cidr, item in placements.placements(network_id).items() if cidr in moving}
    for item in subnets:
        for planned in placements.moves(network_id, item.cidr, open_only=True):
            move.problems.append(f"{item.cidr} is being moved on the Subnet Placement page ({planned.status}): finish "
                                 "or cancel that first.")
    domains = [(domain, vlans.vlans(domain.id)) for domain in vlans.domains() if domain.network_id == network_id]
    return NetworkPlan(network, move, domains)


def network_payload(plan_made, name):
    """What the server needs to make a tribe network of it, as plain data."""
    data = payload(plan_made.move)
    data["network"] = dict(name=name, description=plan_made.network.description, fields=dict(plan_made.network.fields))
    data["domains"] = [dict(name=domain.name, vtp_domain=domain.vtp_domain, description=domain.description,
                            ranges=list(domain.ranges), fields=dict(domain.fields),
                            vlans=[dict(vlan=vlan.vlan, name=vlan.name, status=vlan.status, subnets=list(vlan.subnets),
                                        description=vlan.description, fields=dict(vlan.fields)) for vlan in vlans])
                       for domain, vlans in plan_made.domains]
    return data


def receive_network(store, data):
    """Make a network from network_payload's data (inside the caller's transaction). Returns it."""
    details = data["network"]
    network = store.add_network(details["name"], details.get("description", ""), details.get("fields"))
    receive(store, network.id, data)
    vlans = VlanStore(store)
    for item in data.get("domains") or ():
        domain = vlans.add_domain(item["name"], network.id, item.get("vtp_domain", ""), item.get("description", ""),
                                  item.get("ranges"), item.get("fields"))
        for vlan in item.get("vlans") or ():
            vlans.set_vlan(domain.id, vlan["vlan"], vlan.get("name", ""), vlan.get("status", ACTIVE),
                           vlan.get("subnets") or (), vlan.get("description", ""), vlan.get("fields"))
    return network


def share_problems(local, team, network_id, name):
    """Why a network of this computer's can't be shared with the tribe under this name now: [text]."""
    if team is None:
        return ["This computer isn't connected to the tribe's IPAM server."]
    if not team.online:
        return ["The IPAM server can't be reached: networks can only be shared while it can."]
    if not team.server_takes_networks:
        return ["The IPAM server needs updating before it can take a network (Tools > Tribe Management > Update "
                "Service, on the server)."]
    plan_made = plan_network(local, network_id)
    problems = list(plan_made.move.problems)
    if not name.strip():
        problems.append("Give the network a name.")
    elif any(network.name.lower() == name.strip().lower() for network in team.networks()):
        problems.append(f"The tribe already has a network called {name.strip()}.")
    vlans = VlanStore(team.copy)
    problems += [f"The tribe already has a VLAN domain called {domain.name}: rename this computer's first."
                 for domain, _ in plan_made.domains if vlans.domain_named(domain.name) is not None]
    return problems


def share_network(local, team, network_id, name):
    """Make a network of this computer's a tribe network, with its VLAN domains: the server takes it all (or refuses
    it all), then it's taken out of this computer's. Returns the tribe's network."""
    problems = share_problems(local, team, network_id, name)
    if problems:
        raise IpamError(" ".join(problems))
    plan_made = plan_network(local, network_id)
    network = team.take_network(network_payload(plan_made, name.strip()))
    with local.transaction():
        remove(local, plan_made.move)
        vlans = VlanStore(local)
        for domain, _ in plan_made.domains:
            vlans.delete_domain(domain.id)
        local.delete_network(network_id)
    return network


def move(store, network_id, cidr, to_network_id, take_nested=True, link=None):
    """Move a subnet to another network in the same database, all at once. Returns the MovePlan done."""
    if to_network_id == network_id:
        raise IpamError("It's in that network already.")
    with store.transaction():
        done = plan(store, network_id, cidr, take_nested)
        if done.problems:
            raise IpamError(" ".join(done.problems))
        data = payload(done)
        remove(store, done)
        receive(store, to_network_id, data, link)
    return done

