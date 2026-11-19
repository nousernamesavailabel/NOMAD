"""Host names in fields that need an IP address.

What's typed is used as it is when it's an address. A name gets its address from DNS (or the hosts file) and, when DNS
doesn't know it, from names NOMAD already has (the map, IPAM, saved sessions). Configs NOMAD builds for devices always
get the address, never the name.
"""
import ipaddress
import re
import socket
import threading
from dataclasses import dataclass, field

DNS_TIMEOUT = 5.0
DNS = "DNS"
LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?")


class NameNotFound(ValueError):
    """A name that's spelled right but has no address (of the kind wanted) anywhere NOMAD looked."""


@dataclass
class Resolved:
    text: str  # What was typed
    address: str  # The address to use
    source: str = ""  # Where a name's address came from (DNS, the map...); "" when an address was typed
    others: list = field(default_factory=list)  # More addresses the name has (of the kind wanted)

    @property
    def is_name(self):
        return bool(self.source)

    def note(self):
        """"core-sw1 → 10.1.2.3 (DNS)" for a name, "" for an address."""
        if not self.source:
            return ""
        more = ""
        if self.others:
            more = ", also " + ", ".join(self.others[:2]) + (" ..." if len(self.others) > 2 else "")
        return f"{self.text} → {self.address} ({self.source}{more})"


def kind_name(family):
    return {4: "IPv4", 6: "IPv6"}.get(family, "IP")


def fits(address, family):
    return family is None or ipaddress.ip_address(address.partition("%")[0]).version == family


def is_host_name(text):
    """Whether text is spelled like a host name or FQDN (letters, digits, - and _, labels separated by dots)."""
    name = text[:-1] if text.endswith(".") else text
    if not name or len(name) > 253 or all(character.isdigit() or character == "." for character in name):
        return False
    return all(LABEL.fullmatch(label) for label in name.split("."))


def parse(text, family=None):
    """A Resolved for an address typed (normalized), or None for a host name to look up. family is 4 or 6 for one
    kind only, None for either. Raises ValueError for anything else, or an address of the other kind."""
    text = (text or "").strip()
    if not text:
        raise ValueError(f"Enter an {kind_name(family)} address or a host name.")
    try:
        address = ipaddress.ip_address(text.partition("%")[0])
    except ValueError:
        address = None
    if address is not None:
        if family is not None and address.version != family:
            raise ValueError(f"'{text}' is an {kind_name(address.version)} address: this needs "
                             f"{kind_name(family)}.")
        return Resolved(text, str(address) + (f"%{text.partition('%')[2]}" if "%" in text else ""))
    if is_host_name(text):
        return None
    raise ValueError(f"'{text}' isn't an {kind_name(family)} address or a host name.")


def dns_addresses(name, family=None, timeout=DNS_TIMEOUT):
    """The addresses DNS (or the hosts file) gives name, IPv4 first; [] when it has none. Raises TimeoutError when
    there's no answer in time (the question is left running on its own thread: Windows can't cancel it)."""
    answer = {}

    def ask():
        socket_family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(family, socket.AF_UNSPEC)
        try:
            answer["infos"] = socket.getaddrinfo(name, None, socket_family, socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            answer["infos"] = []

    thread = threading.Thread(target=ask, daemon=True, name="name-lookup")
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise TimeoutError(f"DNS didn't answer for '{name}' within {timeout:g} seconds.")
    addresses = list(dict.fromkeys(info[4][0] for info in answer.get("infos", [])))
    return sorted(addresses, key=lambda address: ":" in address)  # Stable: IPv4 first, each in DNS's order


def normalize(name):
    return name.strip().rstrip(".").lower()


def match_known(name, entries, family=None):
    """Resolved for name from [(name, address, source)] NOMAD already has (most trusted first), or None.

    The same name (ignoring case and a trailing dot) wins; failing that, a short name matches the FQDN it starts
    (core-sw1 finds core-sw1.example.com) and an FQDN matches its short name."""
    wanted = normalize(name)
    usable = []
    for entry_name, address, source in entries:
        try:
            if entry_name and address and fits(address, family):
                usable.append((normalize(entry_name), str(address), source))
        except ValueError:
            continue
    found = [(address, source) for entry_name, address, source in usable if entry_name == wanted]
    if not found:
        short = wanted.split(".")[0]
        found = [(address, source) for entry_name, address, source in usable
                 if ("." not in wanted and entry_name.split(".")[0] == wanted) or
                 ("." in wanted and "." not in entry_name and entry_name == short)]
    if not found:
        return None
    address, source = found[0]
    others = [other for other in dict.fromkeys(other for other, _ in found) if other != address]
    return Resolved(name, address, source, others)


def from_dns(name, family, addresses):
    """Resolved for name from DNS's addresses, or None when none are of the kind wanted."""
    wanted = [address for address in addresses if fits(address, family)]
    return Resolved(name, wanted[0], DNS, wanted[1:]) if wanted else None


def not_found(name, family, addresses, dns_problem="", looked_further=True):
    """The NameNotFound for a name with no usable address."""
    if addresses and family is not None:
        other = kind_name(6 if family == 4 else 4)
        return NameNotFound(f"'{name}' has only {other} addresses ({addresses[0]}): this needs {kind_name(family)}.")
    where = "the map, IPAM or a saved session" if looked_further else ""
    if dns_problem:
        return NameNotFound(dns_problem + (f" It isn't on {where} either." if where else ""))
    return NameNotFound(f"Couldn't find '{name}': DNS doesn't know it" + (f", and nor does {where}." if where else "."))


def resolve(text, family=None, known=None, timeout=DNS_TIMEOUT):
    """Resolved for what's typed: an address as it is, a name from DNS and then known(name) -> [(name, address,
    source)]. Raises ValueError (NameNotFound for a name with no address)."""
    parsed = parse(text, family)
    if parsed is not None:
        return parsed
    name = text.strip()
    addresses, problem = [], ""
    try:
        addresses = dns_addresses(name, family=None, timeout=timeout)
    except TimeoutError as error:
        problem = str(error)
    found = from_dns(name, family, addresses)
    if found is None and known is not None:
        found = match_known(name, known(name), family)
    if found is None:
        raise not_found(name, family, addresses, problem, known is not None)
    return found
