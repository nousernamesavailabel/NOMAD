"""MAC Finder over SSH, for switches NOMAD can't read over SNMP: the same questions asked at the command line of Cisco
IOS, IOS XE and NX-OS (show mac address-table, show cdp/lldp neighbors detail, show etherchannel summary, show ip
arp), with the answers parsed here.

Each switch is logged into once for a search, with its saved SSH session if it has one, else the login chosen for
MAC Finder (a saved credential, or a user name and password asked for once), and the connection is kept open until
the search is done. Nothing is changed on the switches: every command is a show command.

Qt-free: macfind.Locator calls it from its worker threads.
"""
import logging
import re
import threading
import time
from dataclasses import dataclass

import paramiko

from ..oui import format_mac, normalize_mac
from ..terminal.sessions import same_host
from ..terminal.transports import Cancelled, ConnectionFailed, Prompter, SshTransport
from . import collect
from .model import port_key, short_port

log = logging.getLogger(__name__)

COMMAND_TIMEOUT = 30  # Seconds to wait for one command's output
TABLE_TIMEOUT = 120  # For a whole MAC table, which takes a while on a big switch
LOGIN_PROMPT_TIMEOUT = 20  # For the prompt after logging in (past any banner)
QUIET = 0.3  # Seconds with nothing more coming that make a prompt the end of the output
POLL = 0.05

ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]")
MORE = re.compile(r"\s*(?:--More--|<--- More --->|-- More --)\s*", re.IGNORECASE)
PROMPT = re.compile(r"^\S[^\r\n]{0,79}[>#]$")
INVALID = re.compile(r"^\s*% ?(?:Invalid|Incomplete|Ambiguous|Unknown|Unrecognized)|Invalid command|Syntax error",
                     re.IGNORECASE | re.MULTILINE)
MAC_TOKEN = re.compile(r"^(?:[0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4}|(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})$",
                       re.IGNORECASE)
PORT_TOKEN = re.compile(r"^[A-Za-z][A-Za-z\-]*\d[\w/.:]*$")
IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
OWN_PORTS = ("cpu", "router", "switch", "sup-eth", "drop")  # Ports a switch's own MACs show on
PEER_LINK = "vPC Peer-Link"
CDP_WORDS = {"router": "router", "trans-bridge": "bridge", "source-route-bridge": "bridge", "switch": "switch",
             "host": "host", "phone": "phone"}
LLDP_LETTERS = {"R": "router", "B": "bridge", "T": "phone", "W": "ap", "S": "station"}


# --------------------------------------------------------------------- What the switches say

@dataclass
class MacEntry:
    mac: str  # As format_mac writes it, like the MAC tables read over SNMP
    vlan: int
    port: str  # Short name ("" for the switch's own)
    own: bool = False  # The switch's own MAC (on CPU, Router, sup-eth...)


def cisco_mac(mac):
    """aabb.ccdd.eeff, as Cisco's commands take a MAC."""
    digits = normalize_mac(mac).lower()
    return ".".join(digits[start:start + 4] for start in (0, 4, 8))


def parse_mac_table(text):
    """[MacEntry] from show mac address-table (IOS, IOS XE, NX-OS; the older show mac-address-table too)."""
    entries = []
    for line in (text or "").splitlines():
        tokens = line.replace("*", " ").split()
        at = next((index for index, token in enumerate(tokens) if MAC_TOKEN.match(token)), None)
        if at is None or at == len(tokens) - 1:
            continue
        mac = format_mac(normalize_mac(tokens[at]))
        vlan = next((int(token) for token in tokens[:at] if token.isdigit()), 0)
        rest = tokens[at + 1:]
        if "peer-link" in " ".join(rest[-2:]).lower():
            entries.append(MacEntry(mac, vlan, PEER_LINK))
            continue
        port = rest[-1].split(",")[0]
        lower = port.lower()
        if lower.startswith(OWN_PORTS) or lower.endswith("(r)"):
            entries.append(MacEntry(mac, vlan, "", own=True))
        elif PORT_TOKEN.match(port):
            entries.append(MacEntry(mac, vlan, short_port(port)))
    return entries


def parse_channels(text):
    """{port-channel's short name: [its members' short names]} from show etherchannel summary (IOS) or show
    port-channel summary (NX-OS)."""
    channels, current = {}, None
    for line in (text or "").splitlines():
        for token in line.split():
            match = re.match(r"^([A-Za-z][A-Za-z\-]*[\d/.:]+)\((\w+)\)$", token)
            if match is None:
                continue
            name = short_port(match.group(1))
            if port_key(name).startswith("po"):
                current = name
                channels.setdefault(current, [])
            elif current is not None:
                channels[current].append(name)
    return channels


def blocks(text, starts):
    """A neighbors detail listing cut into one block per neighbor: at lines of dashes, else before each line that
    starts one (starts: a pattern)."""
    lines = (text or "").splitlines()
    if any(re.match(r"^\s*-{5,}\s*$", line) for line in lines):
        found, block = [], []
        for line in lines:
            if re.match(r"^\s*-{5,}\s*$", line):
                found.append(block)
                block = []
            else:
                block.append(line)
        found.append(block)
    else:
        found, block = [], []
        for line in lines:
            if re.match(starts, line) and block:
                found.append(block)
                block = []
            block.append(line)
        found.append(block)
    return ["\n".join(block) for block in found if any(line.strip() for line in block)]


def field(pattern, text):
    match = re.search(pattern, text, re.MULTILINE | re.IGNORECASE)
    return match.group(1).strip() if match else ""


def parse_cdp(text):
    """[collect.Neighbor] from show cdp neighbors detail."""
    found = []
    for block in blocks(text, r"^\s*Device ID:"):
        name = field(r"^\s*Device ID:\s*(\S+)", block)
        local = field(r"^\s*Interface:\s*([^,]+),", block)
        if not name or not local:
            continue
        caps = field(r"Capabilities:\s*(.*)$", block).lower().split()
        found.append(collect.Neighbor(
            local_port=short_port(local), name=re.sub(r"\(.*\)$", "", name),
            port=short_port(field(r"Port ID \(outgoing port\):\s*(\S+)", block)),
            address=field(r"^\s*(?:IP address|IPv4 Address|IP Address):\s*(\d{1,3}(?:\.\d{1,3}){3})", block),
            platform=field(r"^\s*Platform:\s*([^,\n]+)", block),
            capabilities=frozenset(CDP_WORDS[word] for word in caps if word in CDP_WORDS), protocol="cdp"))
    return found


def parse_lldp(text):
    """[collect.Neighbor] from show lldp neighbors detail."""
    found = []
    for block in blocks(text, r"^\s*(?:Chassis id|Local Intf):"):
        local = field(r"^\s*Local (?:Intf|Port id):\s*(\S+)", block)
        name = field(r"^\s*System Name:\s*(\S+)", block)
        if not local or not (name or field(r"^\s*Chassis id:\s*(\S+)", block)):
            continue
        letters = field(r"^\s*Enabled Capabilities:\s*([A-Za-z, ]+)$", block) or \
            field(r"^\s*System Capabilities:\s*([A-Za-z, ]+)$", block)
        description = field(r"^\s*System Description:\s*\n?\s*(.+)$", block)
        address = field(r"^\s*(?:IP|IPv4|Management Address):\s*(\d{1,3}(?:\.\d{1,3}){3})", block)
        found.append(collect.Neighbor(
            local_port=short_port(local), name=name or field(r"^\s*Chassis id:\s*(\S+)", block),
            port=short_port(field(r"^\s*Port id:\s*(\S+)", block)), address=address, platform=description,
            capabilities=frozenset(LLDP_LETTERS[letter] for letter in re.findall(r"[A-Z]", letters.upper())
                                   if letter in LLDP_LETTERS), protocol="lldp"))
    return found


def parse_arp(text):
    """{MAC: [IP address]} from show ip arp (IOS or NX-OS)."""
    found = {}
    for line in (text or "").splitlines():
        tokens = line.split()
        mac = next((token for token in tokens if MAC_TOKEN.match(token)), None)
        address = next((token for token in tokens if IPV4.fullmatch(token)), None)
        if mac and address:
            found.setdefault(format_mac(normalize_mac(mac)), []).append(address)
    return found


def parse_description(text, port):
    """A port's description from show interface <port> description (IOS: Interface Status Protocol Description;
    NX-OS: Port Type Speed Description)."""
    for line in (text or "").splitlines():
        tokens = line.split()
        if not tokens or port_key(tokens[0]) != port_key(port):
            continue
        ios = re.match(r"^\S+\s+(?:admin down|up|down|deleted)\s+(?:up|down)\s*(.*)$", line.strip())
        if ios:
            return ios.group(1).strip()
        described = " ".join(tokens[3:]).strip()
        return "" if described == "--" else described
    return ""


def clean(text):
    """Terminal output as plain lines: no escape sequences, backspaces applied, no carriage returns."""
    text = ANSI.sub("", text)
    while True:
        erased = re.sub("[^\x08\n]\x08", "", text)
        if erased == text:
            break
        text = erased
    return text.replace("\x08", "").replace("\r\n", "\n").replace("\r", "\n")


# --------------------------------------------------------------------- Logging in and asking

class BatchPrompter(Prompter):
    """Answers a login with no one to ask: new host keys trusted only when allowed, changed ones never; a password
    typed once for the whole search given once."""

    def __init__(self, trust_new=False, password=None):
        self.trust_new, self.password = trust_new, password
        self.given = False
        self.problem = ""

    def host_key(self, host, port, key_type, fingerprint, changed, old_fingerprint):
        if changed:
            self.problem = ("its SSH key has changed since NOMAD last connected to it. Connect from the Terminal page "
                            "to check it.")
            return "cancel"
        if self.trust_new:
            return "trust"
        self.problem = ("NOMAD hasn't connected to it over SSH before. Connect once from the Terminal page to check "
                        "its key, or tick Trust new SSH keys.")
        return "cancel"

    def secret(self, title, prompt, can_save):
        if title == "Password" and self.password and not self.given:
            self.given = True
            return self.password, False
        self.problem = "it needs a password NOMAD doesn't have: save one in the credential or the switch's session."
        return None

    def username(self, host):
        self.problem = "there's no user name to log in with."
        return None


class SshLogins:
    """How to log in to each switch: its saved SSH session (matched by address or name), else the fallback login."""

    def __init__(self, sessions=(), fallback=None, password=None, fallback_label=""):
        self.sessions = list(sessions)  # Copies, with their credentials filled in
        self.fallback = fallback  # A Session with the user name (and credential) to use, or None
        self.password = password  # Typed for this search, for logins with no saved password
        self.fallback_label = fallback_label  # What the fallback is called, such as "credential TACACS"

    def login_for(self, address, names=()):
        """(Session, what it is, such as "saved session sw1"), or (None, "")."""
        hosts = [address, *names]
        for session in self.sessions:
            if any(same_host(session.host, host) for host in hosts if host):
                return session.copy(host=address), f"saved session {session.name}"
        if self.fallback is not None:
            label = self.fallback_label or f"user {self.fallback.username}"
            return self.fallback.copy(host=address, port=22, name=names[0] if names else address), label
        return None, ""

    def for_device(self, address, names=()):
        return self.login_for(address, names)[0]


class SshShell:
    """A command line on one switch: logs in, turns paging off, runs show commands and returns their output."""

    def __init__(self, session, vault=None, known_hosts=None, trust_new=False, password=None,
                 should_stop=lambda: False):
        self.session, self.vault, self.known_hosts = session, vault, known_hosts
        self.trust_new, self.password, self.should_stop = trust_new, password, should_stop
        self.ssh = self.channel = None
        self.prompt = ""

    def open(self):
        prompter = BatchPrompter(self.trust_new, self.password)
        self.ssh = SshTransport(self.session, prompter, known_hosts=self.known_hosts)
        if self.vault is not None:
            self.ssh.vault = self.vault
        try:
            self.ssh.login()
        except Cancelled:
            raise ConnectionFailed(prompter.problem or "Login was cancelled.") from None
        try:
            self.channel = self.ssh.channel = self.ssh.transport.open_session()
            self.channel.get_pty(term="vt100", width=511, height=200)
            self.channel.invoke_shell()
        except paramiko.SSHException as error:
            raise ConnectionFailed(f"Logged in, but it wouldn't open a command line: {error}") from None
        text = self.read(LOGIN_PROMPT_TIMEOUT)
        self.prompt = text.rstrip().splitlines()[-1].strip()
        for setup in ("terminal length 0", "terminal width 511"):
            self.run(setup)

    def read(self, timeout, prompt=""):
        """What comes until the prompt (prompt, or anything that looks like one) ends it with nothing after it."""
        buffer, deadline, last = "", time.monotonic() + timeout, time.monotonic()
        while True:
            if self.should_stop():
                raise Cancelled()
            if self.channel.recv_ready():
                buffer += self.channel.recv(65536).decode("utf-8", "replace")
                last = time.monotonic()
                if MORE.search(buffer[-40:]):  # Paging still on (terminal length refused): next page
                    buffer = MORE.sub("\n", buffer)
                    self.channel.send(" ")
                continue
            if self.channel.closed or self.channel.exit_status_ready():
                raise ConnectionFailed("The switch closed the connection.")
            text = clean(buffer)
            lines = text.rstrip().splitlines()
            tail = lines[-1].strip() if lines else ""
            if (tail == prompt if prompt else PROMPT.match(tail)) and time.monotonic() - last >= QUIET:
                return text
            if time.monotonic() > deadline:
                raise ConnectionFailed(f"No answer within {timeout} seconds.")
            time.sleep(POLL)

    def run(self, command, timeout=COMMAND_TIMEOUT):
        """A command's output: without the command echoed and the prompt after it."""
        self.channel.send(command + "\n")
        lines = self.read(timeout, self.prompt).rstrip().splitlines()
        echoed = next((index for index, line in enumerate(lines) if command in line), None)
        if echoed is not None:
            lines = lines[echoed + 1:]
        if lines and lines[-1].strip() == self.prompt:
            lines = lines[:-1]
        return "\n".join(lines)

    def close(self):
        if self.ssh is not None:
            self.ssh.close()


class SshAsker:
    """Asks switches about MACs over SSH for one MAC Finder search. Each switch is logged into once (the connection
    kept for the search's later questions), and each is asked by one thread at a time. close() when done."""

    def __init__(self, logins, vault=None, known_hosts=None, trust_new=False, should_stop=lambda: False,
                 shell_factory=SshShell, listener=None):
        """listener(address, ok, login, problem): told as each switch is logged into (ok True) or can't be (ok
        False, and why), from the thread that tried; login says what with ("saved session sw1")."""
        self.logins, self.vault, self.known_hosts = logins, vault, known_hosts
        self.trust_new, self.should_stop, self.shell_factory = trust_new, should_stop, shell_factory
        self.listener = listener
        self.login_labels = {}  # Address -> what it was logged into with
        self.lock = threading.Lock()
        self.device_locks = {}
        self.shells = {}  # Address -> SshShell, or None when it couldn't be logged into
        self.problems = {}  # Address -> why it couldn't be asked
        self.cache = {}  # (address, what) -> parsed answer

    def device_lock(self, address):
        with self.lock:
            return self.device_locks.setdefault(address, threading.Lock())

    def tell(self, address, ok, problem=""):
        if self.listener is not None:
            self.listener(address, ok, self.login_labels.get(address, ""), problem)

    def fail(self, address, problem):
        log.info("MAC Finder: SSH to %s: %s", address, problem)
        self.problems[address] = problem
        shell = self.shells.get(address)
        if shell is not None:
            shell.close()
        self.shells[address] = None
        self.tell(address, False, problem)

    def shell(self, address, names=()):
        """The switch's command line (logging in the first time), or None. Call with its device_lock held."""
        if address in self.shells:
            return self.shells[address]
        session, self.login_labels[address] = self.logins.login_for(address, names)
        if session is None:
            self.fail(address, "no saved session or credential to log in with.")
            return None
        shell = self.shell_factory(session, self.vault, self.known_hosts, self.trust_new, self.logins.password,
                                   self.should_stop)
        self.shells[address] = shell
        try:
            shell.open()
        except Cancelled:
            shell.close()
            self.shells[address] = None
        except ConnectionFailed as error:
            self.fail(address, str(error))
        except (paramiko.SSHException, OSError, EOFError) as error:
            self.fail(address, f"SSH failed: {error}")
        else:
            self.tell(address, True)
        return self.shells[address]

    def try_login(self, address, names=()):
        """Log in to one switch afresh (forgetting how it went before) and out again: (ok, login, problem)."""
        with self.device_lock(address):
            old = self.shells.pop(address, None)
            if old is not None:
                old.close()
            self.problems.pop(address, None)
            shell = self.shell(address, names)
            if shell is not None:
                shell.close()
                self.shells.pop(address, None)
        return shell is not None, self.login_labels.get(address, ""), self.problems.get(address, "")

    def run(self, address, commands, names=(), timeout=COMMAND_TIMEOUT):
        """The output of the first of commands (alternatives, such as an older spelling) the switch accepts, "" when
        it accepts none, or None when it can't be asked."""
        if self.should_stop():
            return None
        with self.device_lock(address):
            shell = self.shell(address, names)
            if shell is None:
                return None
            text = ""
            try:
                for command in commands:
                    text = shell.run(command, timeout)
                    if not INVALID.search(text):
                        return text
            except Cancelled:
                return None
            except ConnectionFailed as error:
                self.fail(address, str(error))
                return None
            except (paramiko.SSHException, OSError, EOFError) as error:
                self.fail(address, f"SSH failed: {error}")
                return None
            return ""

    def cached(self, address, what, make):
        key = (address, what)
        with self.lock:
            if key in self.cache:
                return self.cache[key]
        value = make()
        if value is not None:
            with self.lock:
                self.cache[key] = value
        return value

    def mac_entries(self, address, mac, names=()):
        """Where a switch has one MAC now: [MacEntry] (usually one), or None when it can't be asked."""
        wanted = cisco_mac(mac)
        text = self.run(address, [f"show mac address-table address {wanted}",
                                  f"show mac-address-table address {wanted}"], names)
        if text is None:
            return None
        return [entry for entry in parse_mac_table(text) if entry.mac == format_mac(normalize_mac(mac))]

    def mac_table(self, address, names=()):
        """A switch's whole MAC table: [MacEntry], or None."""
        text = self.run(address, ["show mac address-table", "show mac-address-table"], names, TABLE_TIMEOUT)
        return parse_mac_table(text) if text is not None else None

    def port_macs(self, address, port, names=()):
        """How many MACs a switch has on a port now, or None."""
        text = self.run(address, [f"show mac address-table interface {port}",
                                  f"show mac-address-table interface {port}"], names)
        return sum(1 for entry in parse_mac_table(text) if not entry.own) if text else None

    def description(self, address, port, names=()):
        text = self.run(address, [f"show interface {port} description"], names)
        return parse_description(text, port) if text else ""

    def channels(self, address, names=()):
        """{port-channel: [members]} of a switch ({} when it has none or can't say)."""
        def read():
            text = self.run(address, ["show etherchannel summary", "show port-channel summary"], names)
            return parse_channels(text) if text is not None else None
        return self.cached(address, "channels", read) or {}

    def neighbors(self, address, names=()):
        """The switch's CDP and LLDP neighbors: [collect.Neighbor] ([] when it can't say)."""
        def read():
            cdp = self.run(address, ["show cdp neighbors detail"], names)
            if cdp is None:
                return None
            lldp = self.run(address, ["show lldp neighbors detail"], names)
            return parse_cdp(cdp) + parse_lldp(lldp or "")
        return self.cached(address, "neighbors", read) or []

    def arp(self, address, ip="", names=()):
        """{MAC: [IP address]} from a router's (or layer 3 switch's) ARP table, just for ip if given; None when it
        can't be asked."""
        text = self.run(address, [f"show ip arp {ip}".strip()], names)
        return parse_arp(text) if text is not None else None

    def close(self):
        with self.lock:
            shells, self.shells = list(self.shells.values()), {}
        for shell in shells:
            if shell is not None:
                shell.close()
