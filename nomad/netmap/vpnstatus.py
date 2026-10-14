"""What a router says about its VPNs now (show crypto session detail, IKE SAs, DMVPN peers, certificates, its clock and
its log), and what's wrong with one that isn't up, in plain words.

parse() takes the show commands' answers (Pusher.read_vpns runs SHOW_COMMANDS); diagnose() looks at one member of a
vpn.Vpn as its router (and the far ones, when read) say it is.

Qt-free.
"""
import datetime
import ipaddress
import re
from dataclasses import dataclass, field

from . import vpn as V

SHOW_COMMANDS = [
    "show clock",
    "show ntp status",
    "show ip interface brief | include Tunnel",
    "show crypto session detail",
    "show crypto ikev2 sa",
    "show crypto isakmp sa",
    "show dmvpn",
    "show crypto pki certificates",
    "show crypto pki server",
    "show logging | include CRYPTO|IKEV2|IKMP|ISAKMP|NHRP|DMVPN|IPSEC|PKI",
]
LOG_LINES = 40

UP, DOWN, NEGOTIATING, UNKNOWN = "up", "down", "negotiating", "unknown"
ERROR, WARNING, INFO, GOOD = "error", "warning", "info", "good"


@dataclass
class Session:
    """A crypto session as the router shows it (one per peer and interface)."""
    interface: str = ""
    profile: str = ""
    status: str = ""  # UP-ACTIVE, UP-IDLE, UP-NO-IKE, DOWN, DOWN-NEGOTIATING...
    peer: str = ""
    uptime: str = ""
    ike: str = ""  # "IKEv2" or "IKEv1"
    ike_state: str = ""  # Active / Inactive (from the session) or the SA's state
    encaps: int = 0
    decaps: int = 0
    encap_drops: int = 0
    decap_drops: int = 0
    flows: int = 0

    @property
    def up(self):
        return self.status.upper().startswith("UP-ACTIVE")


@dataclass
class IkeSa:
    version: str  # "IKEv2" or "IKEv1"
    local: str
    remote: str
    state: str  # READY, IN-NEG, DELETE (IKEv2); QM_IDLE, MM_NO_STATE, MM_KEY_EXCH... (IKEv1)
    details: str = ""


@dataclass
class NhrpPeer:
    interface: str
    nbma: str
    tunnel_ip: str
    state: str
    uptime: str = ""
    attributes: str = ""


@dataclass
class Certificate:
    kind: str  # "identity", "ca", "self-signed"
    status: str = ""
    subject: str = ""
    issuer: str = ""
    start: object = None  # datetime (UTC)
    end: object = None
    trustpoints: list = field(default_factory=list)


@dataclass
class Status:
    clock: object = None  # datetime (as the router says it is, UTC when it says so)
    clock_text: str = ""
    clock_set: bool = True  # False when IOS marks it unauthoritative (*)
    ntp: object = None  # True synchronized, False not, None no NTP
    tunnels: dict = field(default_factory=dict)  # Tunnel name -> (status, protocol)
    sessions: list = field(default_factory=list)  # [Session]
    ike: list = field(default_factory=list)  # [IkeSa]
    dmvpn: list = field(default_factory=list)  # [NhrpPeer]
    dmvpn_types: dict = field(default_factory=dict)  # Tunnel -> "Hub" / "Spoke"
    certificates: list = field(default_factory=list)  # [Certificate]
    pki_server: str = ""  # The CA server's state ("enabled", "disabled"...) when it has one
    log: list = field(default_factory=list)

    def session_for(self, peer, interface=""):
        for item in self.sessions:
            if item.peer == peer and (not interface or same_interface(item.interface, interface)):
                return item
        return None

    def sa_for(self, peer):
        return [item for item in self.ike if item.remote == peer]


def same_interface(a, b):
    return V.full_interface(a).lower() == V.full_interface(b).lower()


# ----------------------------------------------------------------- Reading

MONTHS = {name: number for number, name in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
                                                      "Oct", "Nov", "Dec"], start=1)}


def parse_clock(text):
    """(datetime, set) of show clock ("*01:23:45.678 UTC Wed Oct 14 2026"), or (None, True)."""
    found = re.search(r"([*.]?)(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\S+)\s+\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{4})",
                      text or "")
    if not found:
        return None, True
    marker, hour, minute, second, _, month, day, year = found.groups()
    try:
        moment = datetime.datetime(int(year), MONTHS.get(month, 1), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return None, True
    return moment, marker != "*"


def parse_date(text):
    """A certificate date ("01:02:03 UTC Oct 14 2026"), or None."""
    found = re.search(r"(\d{1,2}):(\d{2}):(\d{2})\s+\S+\s+(\w{3})\s+(\d{1,2})\s+(\d{4})", text or "")
    if not found:
        return None
    hour, minute, second, month, day, year = found.groups()
    try:
        return datetime.datetime(int(year), MONTHS.get(month, 1), int(day), int(hour), int(minute), int(second))
    except ValueError:
        return None


def parse_sessions(text):
    sessions, current = [], None
    for raw in (text or "").splitlines():
        line = raw.strip()
        interface = re.match(r"^Interface:\s*(\S+)", line)
        if interface:
            current = Session(interface=interface.group(1))
            sessions.append(current)
            continue
        if current is None:
            continue
        if line.startswith("Profile:"):
            current.profile = line.split(":", 1)[1].strip()
        elif line.startswith("Uptime:"):
            current.uptime = line.split(":", 1)[1].strip()
        elif line.startswith("Session status:"):
            current.status = line.split(":", 1)[1].strip()
        elif line.startswith("Peer:"):
            peer = re.match(r"Peer:\s*(\S+)", line)
            if peer:
                if current.peer:  # A second peer on the interface (DMVPN): a session of its own
                    current = Session(interface=current.interface, profile=current.profile, status=current.status)
                    sessions.append(current)
                current.peer = peer.group(1)
        elif re.match(r"IKEv[12] SA:", line) or line.startswith("IKE SA:"):
            current.ike = "IKEv2" if "IKEv2" in line else "IKEv1"
            current.ike_state = line.split()[-1]
        elif line.startswith("IPSEC FLOW:"):
            current.flows += 1
        elif "#pkts dec'ed" in line or "#pkts decaps" in line:
            numbers = re.search(r"#pkts dec'ed (\d+) drop (\d+)", line)
            if numbers:
                current.decaps += int(numbers.group(1))
                current.decap_drops += int(numbers.group(2))
        elif "#pkts enc'ed" in line:
            numbers = re.search(r"#pkts enc'ed (\d+) drop (\d+)", line)
            if numbers:
                current.encaps += int(numbers.group(1))
                current.encap_drops += int(numbers.group(2))
    for session in sessions:  # A status line given before a later peer belongs to each of the interface's peers
        session.status = session.status or next((item.status for item in sessions
                                                 if item.interface == session.interface and item.status), "")
    return sessions


def parse_ikev2(text):
    found = []
    for line in (text or "").splitlines():
        words = line.split()
        if len(words) >= 5 and words[0].isdigit() and "/" in words[1] and "/" in words[2]:
            found.append(IkeSa("IKEv2", words[1].split("/")[0], words[2].split("/")[0], words[-1]))
        elif found and line.startswith(" ") and ("Encr:" in line or "Auth" in line):
            found[-1].details += line.strip() + " "
    return found


def parse_isakmp(text):
    found = []
    for line in (text or "").splitlines():
        words = line.split()
        if len(words) >= 4 and V.ipaddress_like(words[0]) and V.ipaddress_like(words[1]):
            found.append(IkeSa("IKEv1", words[1], words[0], words[2]))
    return found


def parse_dmvpn(text):
    peers, types, interface = [], {}, ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        header = re.match(r"^Interface:\s*(\S+?),", line)
        if header:
            interface = header.group(1)
            continue
        kind = re.match(r"^Type:\s*(\w+)", line)
        if kind and interface:
            types[interface] = kind.group(1)
            continue
        words = line.split()
        if len(words) >= 5 and words[0].isdigit() and V.ipaddress_like(words[1]) and V.ipaddress_like(words[2]):
            peers.append(NhrpPeer(interface, words[1], words[2], words[3], words[4] if len(words) > 4 else "",
                                  words[5] if len(words) > 5 else ""))
    return peers, types


def parse_certificates(text):
    found, current, section = [], None, ""
    for raw in (text or "").splitlines():
        line = raw.strip()
        if line in ("Certificate", "CA Certificate", "Router Self-Signed Certificate") or \
                line.endswith("Certificate") and not line.startswith(("Associated", "Status")):
            kind = "ca" if line.startswith("CA") else "self-signed" if "Self-Signed" in line else "identity"
            current = Certificate(kind)
            found.append(current)
            section = ""
            continue
        if current is None:
            continue
        if line.startswith("Status:"):
            current.status = line.split(":", 1)[1].strip()
        elif line.startswith("Issuer:"):
            section = "issuer"
        elif line.startswith("Subject:"):
            section = "subject"
        elif line.startswith("start date:"):
            current.start = parse_date(line)
        elif line.startswith("end") and "date:" in line:
            current.end = parse_date(line)
        elif line.startswith("Associated Trustpoints:"):
            current.trustpoints = line.split(":", 1)[1].split()
        elif line.startswith(("cn=", "CN=", "hostname=", "Name:")) and section:
            text = line.split("=", 1)[1] if "=" in line and not line.startswith("Name:") else line[5:].strip()
            if section == "issuer" and not current.issuer:
                current.issuer = text
            elif section == "subject" and not current.subject:
                current.subject = text
    return found


def parse(raw):
    """Status from {command: what it said}."""
    status = Status()
    status.clock, status.clock_set = parse_clock(raw.get("show clock", ""))
    status.clock_text = (raw.get("show clock", "") or "").strip()
    ntp = raw.get("show ntp status", "")
    status.ntp = None if not ntp or "not enabled" in ntp.lower() else \
        ("synchronized" in ntp.lower() and "unsynchronized" not in ntp.lower())
    for line in (raw.get("show ip interface brief | include Tunnel", "") or "").splitlines():
        words = line.split()
        if len(words) >= 6 and words[0].lower().startswith("tunnel"):
            status.tunnels[words[0]] = (" ".join(words[4:-1]), words[-1])
    status.sessions = parse_sessions(raw.get("show crypto session detail", ""))
    status.ike = parse_ikev2(raw.get("show crypto ikev2 sa", "")) + parse_isakmp(raw.get("show crypto isakmp sa", ""))
    status.dmvpn, status.dmvpn_types = parse_dmvpn(raw.get("show dmvpn", ""))
    status.certificates = parse_certificates(raw.get("show crypto pki certificates", ""))
    server = raw.get("show crypto pki server", "") or ""
    state = re.search(r"Status:\s*(\w+)", server)
    status.pki_server = state.group(1).lower() if state else ""
    status.log = [line.strip() for line in (raw.get(SHOW_COMMANDS[-1], "") or "").splitlines()
                  if line.strip()][-LOG_LINES:]
    return status


# ----------------------------------------------------------------- What's wrong

@dataclass
class Finding:
    severity: str
    text: str
    member: str = ""  # Member key


LOG_MEANINGS = [
    (r"Auth exchange failed|AUTHENTICATION_FAILED|authentication failed", "IKE authentication failed: the pre-shared "
     "keys don't match, or a certificate wasn't accepted."),
    (r"NO_PROPOSAL_CHOSEN|no proposal chosen|Failed to find a matching policy|IKMP_NO_SA|NO_PROPOSAL",
     "No proposal both ends accept: their encryption, integrity or DH groups (or transform sets) don't match."),
    (r"Failed to locate an item in the database|IKEv2:% ?Failed to find the peer", "The router has no IKE profile or "
     "key for the peer that asked: its identity or address doesn't match a profile's match identity."),
    (r"RECVD_PKT_INV_SPI|invalid spi", "Packets arrived for an IPsec SA the router no longer has (one end was "
     "cleared or restarted); it should settle once IKE renegotiates."),
    (r"PKT_REPLAY_ERR|replay check failed", "Replay drops: packets arriving out of order (QoS or load sharing on the "
     "path)."),
    (r"IKMP_BAD_MESSAGE|bad message|Hash failure|HASH_FAILURE", "IKEv1 failed to decrypt the peer's message: almost "
     "always a pre-shared key mismatch."),
    (r"NHRP-3-PAKREPLY|NHRP.*(?:Error Indication|protocol generic error)", "The hub refused this spoke's NHRP "
     "registration: NHRP authentication, network ID or tunnel key differ."),
    (r"NHRP.*(?:NHS .* DOWN|nhs.*down)", "The spoke lost its NHS (hub): it registers again once the hub answers."),
    (r"PKI-3-CERTIFICATE_INVALID_NOT_YET_VALID|not yet valid", "A certificate isn't valid yet: a router's clock is "
     "behind the CA's. Set the clocks (NTP)."),
    (r"PKI-3-CERTIFICATE_INVALID_EXPIRED|has expired", "A certificate has expired: enroll again."),
    (r"PKI-3-CRL_FETCH_FAIL|CRL fetch|revocation", "A router couldn't fetch the CA's CRL: let it reach the CA, or set "
     "revocation-check none."),
    (r"PKI.*(?:CERTIFICATE_INVALID|validation failed|chain)", "A certificate wasn't accepted: the routers don't trust "
     "the same CA, or the certificate map doesn't match its issuer."),
]


def explain_log(lines):
    """[(meaning, the line)] of log lines NOMAD knows the meaning of (each meaning once, newest line)."""
    found = {}
    for line in lines:
        for pattern, meaning in LOG_MEANINGS:
            if re.search(pattern, line, re.IGNORECASE):
                found[meaning] = line
    return [(meaning, line) for meaning, line in found.items()]


def diagnose(vpn, member, device, far_devices=None):
    """[Finding] for one member of a VPN, as its router says it is now."""
    far_devices = far_devices or {}
    findings = []
    status = device.status if device is not None else None
    if status is None:
        return [Finding(INFO, f"{member.title()} hasn't been read.", member.key)]
    say = lambda severity, text: findings.append(Finding(severity, text, member.key))  # noqa: E731
    others = vpn.others(member)
    if vpn.kind == V.DMVPN and member.role == V.SPOKE:
        others = vpn.hubs()
    tunnel = f"Tunnel{member.tunnel}" if vpn.kind != V.CRYPTO_MAP else ""
    if tunnel:
        state = next((value for name, value in status.tunnels.items() if same_interface(name, tunnel)), None)
        if state is None:
            say(ERROR, f"{tunnel} isn't on {member.title()}.")
        elif "admin" in state[0]:
            say(ERROR, f"{tunnel} is shut down on {member.title()}.")
        elif state[1] != "up":
            say(ERROR, f"{tunnel} is up but its line protocol is down on {member.title()}" +
                (": for an IPsec VTI that means IPsec isn't up (see below)." if vpn.kind == V.VTI else
                 ": its tunnel source is down, or it has no route to the tunnel destination."))
        else:
            say(GOOD, f"{tunnel} is up on {member.title()}.")
    if vpn.protected:
        for other in others:
            peer = other.reached_at
            if not peer:
                continue
            sessions = [item for item in status.sessions if item.peer == peer and
                        (not tunnel or not item.interface or same_interface(item.interface, tunnel))]
            sas = status.sa_for(peer)
            session = next(iter(sessions), None)
            if session is not None and session.up:
                if session.encaps and not session.decaps:
                    say(WARNING, f"IPsec to {other.title()} is up but nothing has come back ({session.encaps} sent, "
                        f"0 received): the far end isn't routing back into it, its crypto ACL doesn't mirror this "
                        f"one, or ESP is dropped on the way.")
                elif session.decaps and not session.encaps:
                    say(WARNING, f"IPsec to {other.title()} is up and receiving, but {member.title()} sends nothing "
                        f"into it ({session.decaps} received): its routes don't point into the tunnel.")
                else:
                    say(GOOD, f"IPsec to {other.title()} is up ({session.encaps} sent, {session.decaps} received"
                        f"{', up ' + session.uptime if session.uptime else ''}).")
                if session.encap_drops or session.decap_drops:
                    say(WARNING, f"IPsec to {other.title()} dropped {session.encap_drops} going out and "
                        f"{session.decap_drops} coming in.")
                continue
            if not sas:
                if device.routes and device.route_to(peer) is None:
                    say(ERROR, f"No IKE with {other.title()}: {member.title()} has no route to {peer}. If that's "
                        f"the wrong address for {other.title()}, change its WAN interface (Edit...).")
                    continue
                say(ERROR, f"No IKE with {other.title()} ({peer}): no answer from it on UDP 500/4500 (an ACL or "
                    f"firewall on the way, the wrong address, or it has no IKE profile for {member.title()}).")
                continue
            for sa in sas:
                state = sa.state.upper()
                if state in ("READY", "QM_IDLE"):
                    say(WARNING, f"IKE with {other.title()} is up ({sa.state}) but there's no IPsec SA: the transform "
                        f"sets don't match, or (crypto map) the crypto ACLs aren't mirror images.")
                elif state == "MM_NO_STATE":
                    say(ERROR, f"IKEv1 with {other.title()} is stuck at MM_NO_STATE: it isn't answering on UDP 500, or "
                        f"no ISAKMP policy matches.")
                elif state in ("MM_KEY_EXCH", "MM_SA_SETUP"):
                    say(ERROR, f"IKEv1 with {other.title()} is stuck at {state}: almost always the pre-shared keys "
                        f"don't match (or NAT on the way without NAT-T).")
                elif state in ("IN-NEG", "DELETE"):
                    say(ERROR, f"IKEv2 with {other.title()} is stuck ({state}): the proposals or the authentication "
                        f"don't match (keys, identities or certificates).")
                else:
                    say(WARNING, f"IKE with {other.title()} is {sa.state}.")
    if vpn.kind == V.DMVPN:
        mine = [peer for peer in status.dmvpn if same_interface(peer.interface, tunnel)]
        if member.role == V.SPOKE:
            for hub in vpn.hubs():
                entry = next((peer for peer in mine if peer.tunnel_ip == hub.tunnel_ip), None)
                if entry is None:
                    say(ERROR, f"{member.title()} has no NHRP entry for hub {hub.title()}: it never registered "
                        f"(NHRP authentication, network ID, tunnel key or IPsec).")
                elif entry.state.upper() != "UP":
                    say(ERROR, f"{member.title()}'s NHRP entry for hub {hub.title()} is {entry.state}.")
                else:
                    say(GOOD, f"{member.title()} is registered with hub {hub.title()} (up {entry.uptime}).")
            if vpn.dmvpn.phase in (2, 3):
                direct = [peer for peer in mine if "D" in peer.attributes and peer.tunnel_ip not in
                          {hub.tunnel_ip for hub in vpn.hubs()}]
                if direct:
                    say(INFO, f"Spoke-to-spoke tunnels from {member.title()} now: " +
                        ", ".join(f"{peer.tunnel_ip} ({peer.nbma})" for peer in direct) + ".")
        else:
            up = [peer for peer in mine if peer.state.upper() == "UP"]
            say(GOOD if up else WARNING, f"Hub {member.title()} has {len(up)} spoke(s) registered" +
                (": " + ", ".join(peer.tunnel_ip for peer in up) if up else ".") )
            missing = [spoke for spoke in vpn.spokes() if spoke.tunnel_ip not in {peer.tunnel_ip for peer in mine}]
            for spoke in missing:
                say(WARNING, f"Spoke {spoke.title()} ({spoke.tunnel_ip}) isn't registered with {member.title()}.")
    if vpn.auth.method == V.CERT:
        findings += certificate_findings(vpn, member, status)
    for meaning, line in explain_log(status.log):
        say(INFO, f"The log says: {meaning} ({line[-140:]})")
    return findings


def certificate_findings(vpn, member, status):
    findings = []
    trustpoint = V.names(vpn, member)["trustpoint"]
    mine = [item for item in status.certificates if trustpoint in item.trustpoints]
    identity = next((item for item in mine if item.kind == "identity"), None)
    if identity is None:
        findings.append(Finding(ERROR, f"{member.title()} has no certificate in trustpoint {trustpoint}: enroll it.",
                                member.key))
        return findings
    now = status.clock
    if identity.status and identity.status.lower() != "available":
        findings.append(Finding(ERROR, f"{member.title()}'s certificate is {identity.status}.", member.key))
    if now is not None and identity.start is not None and now < identity.start:
        findings.append(Finding(ERROR, f"{member.title()}'s certificate isn't valid until "
                                       f"{identity.start:%Y-%m-%d %H:%M} UTC, and its clock says "
                                       f"{now:%Y-%m-%d %H:%M}: set its clock (NTP).", member.key))
    if now is not None and identity.end is not None:
        if now > identity.end:
            findings.append(Finding(ERROR, f"{member.title()}'s certificate expired {identity.end:%Y-%m-%d}.",
                                    member.key))
        elif (identity.end - now).days < 30:
            findings.append(Finding(WARNING, f"{member.title()}'s certificate expires {identity.end:%Y-%m-%d}.",
                                    member.key))
    if not status.clock_set or status.ntp is None:
        findings.append(Finding(WARNING, f"{member.title()}'s clock isn't kept by NTP: certificates fail when routers' "
                                         f"clocks drift apart.", member.key))
    return findings


def vpn_state(vpn, devices):
    """UP, DOWN, NEGOTIATING or UNKNOWN for a whole VPN (for the list and the map)."""
    states = []
    for member in vpn.members:
        device = devices.get(member.key)
        if device is None or device.status is None:
            continue
        status = device.status
        if vpn.kind != V.CRYPTO_MAP:
            state = next((value for name, value in status.tunnels.items()
                          if same_interface(name, f"Tunnel{member.tunnel}")), None)
            if state is None or state[1] != "up":
                states.append(DOWN)
                continue
        if vpn.protected:
            peers = [other.reached_at for other in (vpn.hubs() if vpn.kind == V.DMVPN and member.role == V.SPOKE
                                                    else vpn.others(member)) if other.reached_at]
            if vpn.kind == V.DMVPN and member.role == V.HUB:
                peers = []
            up = [peer for peer in peers if any(item.peer == peer and item.up for item in status.sessions)]
            one_way = [peer for peer in up if any(item.peer == peer and item.up and item.encaps and not item.decaps
                                                  for item in status.sessions)]
            if one_way:  # Up, but nothing comes back: not working
                states.append(NEGOTIATING)
                continue
            if peers and not up:
                negotiating = any(status.sa_for(peer) for peer in peers)
                states.append(NEGOTIATING if negotiating else DOWN)
                continue
        states.append(UP)
    if not states:
        return UNKNOWN
    if all(state == UP for state in states):
        return UP
    if any(state == UP for state in states) or NEGOTIATING in states:
        return NEGOTIATING if NEGOTIATING in states else DOWN
    return DOWN


def address_text(prefix):
    try:
        return str(ipaddress.IPv4Network(prefix, strict=False))
    except ValueError:
        return prefix
