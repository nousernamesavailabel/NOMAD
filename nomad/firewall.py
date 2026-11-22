"""NOMAD's Windows Firewall rules: which ones there are, reading them all at once, and opening or removing one.

Every rule NOMAD makes is an inbound "allow" rule for one local port, named so it can be found again. The services
open theirs when they're installed (and remove them when uninstalled); the pages open theirs from an Open Firewall
Port button. Tools > Services & Firewall lists them all (ui/services_dialog.py).

Reading goes through Windows Firewall's own COM object (HNetCfg.FwPolicy2), which takes a fraction of a second;
PowerShell's Get-NetFirewallRule takes ten. Changing a rule uses netsh and needs administrator rights.
"""
import logging
from dataclasses import dataclass, field

from .system import CommandError, run_command

log = logging.getLogger(__name__)

TCP, UDP = "TCP", "UDP"
PROTOCOL_NUMBERS = {6: TCP, 17: UDP}
INBOUND, ALLOW = 1, 1  # NET_FW_RULE_DIR_IN, NET_FW_ACTION_ALLOW
PROFILE_NAMES = {1: "Domain", 2: "Private", 4: "Public"}
GP_OVERRIDE, INBOUND_BLOCKED = 1, 2  # LocalPolicyModifyState: rules made here are ignored / all inbound blocked
NAME_PREFIXES = ("NOMAD", "NICManager")  # NICManager: NOMAD's name before it was renamed

# Each rule's state in the list
OPEN, NOT_OPEN, MISSING, NEEDS_FIXING, TURNED_OFF, LEFT_OVER, UNKNOWN = (
    "Open", "Not open", "Missing", "Needs fixing", "Turned off", "Left over", "Not NOMAD's")


@dataclass(frozen=True)
class Rule:
    name: str
    used_by: str
    protocols: tuple
    port: int  # The usual port: the service's or page's setting decides the one wanted
    service: str = ""  # The services_catalog key of the service that opens it, "" for a page's rule
    page: str = ""  # The main window's attribute of the page that opens it
    legacy: tuple = ()  # Older names for it, replaced when it's opened


RULES = [
    Rule("NOMAD IPAM Server", "Tribe Server service", (TCP,), 8443, service="tribe"),
    Rule("NOMAD Syslog Collector", "Syslog Collector service", (UDP,), 514, service="syslog"),
    Rule("NOMAD Flow Collector", "Flow Collector service", (UDP,), 2055, service="flows"),
    Rule("NOMAD Map Watcher syslog", "Map Watcher service (syslog)", (UDP,), 514, service="watcher"),
    Rule("NOMAD Map Watcher traps", "Map Watcher service (SNMP traps)", (UDP,), 162, service="watcher"),
    Rule("NOMAD Dashboard", "NOMAD Dashboard service (HTTPS)", (TCP,), 8444, service="dashboard"),
    Rule("NOMAD syslog", "Syslog page", (UDP,), 514, page="syslog_tab"),
    Rule("NOMAD NetFlow", "NetFlow page", (UDP,), 2055, page="flows_tab"),
    Rule("NOMAD TFTP server", "TFTP page", (UDP,), 69, page="tftp_tab"),
    Rule("NOMAD DHCP test", "DHCP Servers page", (UDP,), 68, page="dhcp_tab"),
    Rule("NOMAD-iperf-server", "iperf page (server)", (TCP, UDP), 5201, page="iperf_tab",
         legacy=("NICManager-iperf-server",)),
]


def rule_named(name):
    return next((rule for rule in RULES if rule.name == name), None)


# --------------------------------------------------------------------- Reading

@dataclass
class Found:
    """One Windows Firewall rule with a NOMAD name. netsh makes one per protocol, so a rule can be found twice."""
    name: str
    enabled: bool = True
    inbound: bool = True
    allow: bool = True
    protocol: str = ""  # TCP, UDP, or the protocol number for anything else
    ports: str = ""  # As Windows Firewall has them: "514", "5000-5010", "*"


@dataclass
class Profile:
    name: str
    enabled: bool = True
    active: bool = False  # The network this computer is on now is of this kind


@dataclass
class FirewallState:
    found: list = field(default_factory=list)  # Found
    profiles: list = field(default_factory=list)  # Profile
    local_rules_ignored: bool = False  # Group Policy applies only its own rules: the ones made here do nothing
    inbound_blocked: bool = False  # "Block all incoming connections" is on

    def named(self, name):
        return [item for item in self.found if item.name == name]

    def unknown(self):
        """NOMAD-named rules that aren't in RULES (nor an older name of one)."""
        known = {rule.name for rule in RULES} | {name for rule in RULES for name in rule.legacy}
        return sorted({item.name for item in self.found} - known)

    def legacy_found(self):
        return [(rule, name) for rule in RULES for name in rule.legacy if self.named(name)]

    def warnings(self):
        """What makes the rules not matter, or not work, in a sentence each."""
        lines = []
        if self.local_rules_ignored:
            lines.append("Group Policy tells Windows Firewall to ignore rules made on this computer, so NOMAD's "
                         "rules let nothing through. Ask whoever manages Group Policy to allow NOMAD's ports.")
        if self.inbound_blocked:
            lines.append("Windows Firewall is set to block all incoming connections, even the ones NOMAD's rules "
                         "allow (Windows Security > Firewall & network protection).")
        off = [profile.name for profile in self.profiles if profile.active and not profile.enabled]
        if off:
            lines.append(f"Windows Firewall is off for the {' and '.join(off)} network this computer is on now, so "
                         "it blocks nothing there. The rules matter when it's on, or on another network.")
        return lines


def read_state(policy=None):
    """Every NOMAD rule in Windows Firewall, and whether rules made here count (no administrator rights needed).
    policy: a stand-in for the HNetCfg.FwPolicy2 COM object, for tests."""
    if policy is not None:
        return _read(policy)
    import pythoncom
    import win32com.client
    pythoncom.CoInitialize()  # Called on a worker thread
    try:
        return _read(win32com.client.Dispatch("HNetCfg.FwPolicy2"))  # Its objects are all let go of on return
    finally:
        pythoncom.CoUninitialize()


def _read(policy):
    state = FirewallState()
    for rule in policy.Rules:
        name = rule.Name or ""
        if name.startswith(NAME_PREFIXES):
            state.found.append(Found(name, bool(rule.Enabled), rule.Direction == INBOUND, rule.Action == ALLOW,
                                     PROTOCOL_NUMBERS.get(rule.Protocol, str(rule.Protocol)),
                                     str(rule.LocalPorts or "*")))
    active = int(policy.CurrentProfileTypes)
    for number, name in PROFILE_NAMES.items():
        state.profiles.append(Profile(name, bool(policy.FirewallEnabled(number)), bool(active & number)))
    modify = int(policy.LocalPolicyModifyState)
    state.local_rules_ignored = modify == GP_OVERRIDE
    state.inbound_blocked = modify == INBOUND_BLOCKED
    return state


def assess(rule, found, port=None, protocols=None, needed=None):
    """(state, details) for one of RULES. found: its Found entries. port and protocols: what its service or page
    wants now (port None: not known, so not checked). needed: True if its service is installed, False if not,
    None for a page's rule (opened only when the page needs it)."""
    protocols = tuple(protocols or rule.protocols)
    if not found:
        return (MISSING, f"{rule.used_by} is installed, but Windows Firewall may block it") if needed else \
            (NOT_OPEN, "")
    if needed is False:
        return LEFT_OVER, f"{rule.used_by.split(' (')[0]} isn't installed"
    if not all(item.enabled for item in found):
        return TURNED_OFF, "Turned off in Windows Firewall"
    problems = []
    if not all(item.inbound and item.allow for item in found):
        problems.append("changed to block, or to outbound")
    have = {item.protocol for item in found}
    missing = [protocol for protocol in protocols if protocol not in have]
    if missing:
        problems.append(f"no {' or '.join(missing)}")
    if port is not None:
        wrong = sorted({item.ports for item in found if item.ports != str(port)})
        if wrong:
            problems.append(f"port {', '.join(wrong)}, should be {port}")
    if problems:
        return NEEDS_FIXING, "; ".join(problems)
    return OPEN, ""


def describe(protocols, port):
    return f"{' and '.join(protocols)} {port}"


# --------------------------------------------------------------------- Changing (needs administrator rights)

def open_rule(name, port, protocols=(UDP,), legacy=()):
    """Add (or replace) an inbound rule allowing a local port, one rule per protocol, for every network type."""
    for old in (name, *legacy):
        close_rule(old)
    for protocol in protocols:
        run_command(["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=allow",
                     f"protocol={protocol}", f"localport={int(port)}", "profile=any"])
    log.info("Opened %s %s in Windows Firewall (%s)", "/".join(protocols), port, name)


def close_rule(name):
    """Remove every rule with this name (nothing to remove is fine)."""
    try:
        run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
    except CommandError:
        pass  # No such rule
