"""Reading a device's configuration over SSH, and who changed it last.

Cisco IOS / IOS XE, NX-OS and ASA: show running-config (and show startup-config when asked). ArubaOS: no paging, then
show running-config. pfSense: cat /conf/config.xml, run on its own (not typed at a prompt: its shell's prompt isn't
one NOMAD knows, and the admin user gets the console menu instead of a shell).

Who changed it: the running-config's "! Last configuration change at ... by user" line; for IOS without a user there,
the last entry of show archive log config all (when archive logging is on); pfSense's last <revision> user."""
import re
import time
from dataclasses import dataclass, field

import paramiko

from ..netmap import macssh
from ..terminal.transports import Cancelled, ConnectionFailed, SshTransport
from . import text

RUNNING, STARTUP = "running", "startup"
WHICH_NAMES = {RUNNING: "running-config", STARTUP: "startup-config"}
SHOW = {RUNNING: "show running-config", STARTUP: "show startup-config"}
COMMANDS = {text.IOS: SHOW, text.NXOS: SHOW, text.ASA: SHOW, text.ARUBA: {RUNNING: "show running-config"},
            text.OTHER: {RUNNING: "show running-config"}}
PFSENSE_COMMAND = "cat /conf/config.xml"
EXEC_TIMEOUT = 60
REFUSED = re.compile(r"%\s*(?:Permission denied|Authorization failed)|Command authorization failed|"
                     r"not authorized|startup-config is not present|No configuration present", re.IGNORECASE)
LAST_CHANGE = re.compile(r"^!\s*Last configuration change at .*?(?:\s+by\s+(\S+))?\s*$", re.MULTILINE)
ARCHIVE_ROW = re.compile(r"^\s*\d+\s+\d+\s+(\S+?)@\S+\s+\|", re.MULTILINE)
PFSENSE_USER = re.compile(r"<revision>.*?<username>\s*([^<@(]+)", re.DOTALL)


@dataclass
class PullResult:
    texts: dict = field(default_factory=dict)  # {RUNNING: text, STARTUP: text}
    changed_by: str = ""
    platform: str = ""
    problem: str = ""
    login: str = ""  # What it logged in with ("saved session sw1")

    @property
    def ok(self):
        return bool(self.texts.get(RUNNING)) and not self.problem


def clean(output):
    lines = (output or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return "\n".join(line.rstrip() for line in lines) + "\n"


def refused(output):
    return bool(macssh.INVALID.search(output or "") or REFUSED.search(output or "")) or \
        len((output or "").strip().splitlines()) < 3


def who_changed(config):
    """The user the running-config says changed it last, or ""."""
    found = LAST_CHANGE.search(config or "")
    if found and found.group(1):
        return found.group(1)
    found = PFSENSE_USER.search(config or "")
    return found.group(1).strip() if found else ""


def archive_user(log_text):
    """The user of the last change show archive log config all lists, or ""."""
    if not log_text or macssh.INVALID.search(log_text):
        return ""
    users = ARCHIVE_ROW.findall(log_text)
    return users[-1] if users else ""


def pull_device(pusher, address, names=(), platform="", which=(RUNNING,), keep=False):
    """PullResult for one device, logging in with pusher (configpush.Pusher: its logins, vault, known hosts). The
    login is let go afterwards unless keep."""
    if platform == text.PFSENSE:
        return pull_pfsense(pusher, address, names)
    result = PullResult(platform=platform)
    shell = pusher.shell(address, names)
    result.login = pusher.login_labels.get(address, "")
    if shell is None:
        result.problem = f"Couldn't log in: {pusher.problems.get(address) or 'no reason given'}"
        return result
    try:
        if platform == text.ARUBA:
            shell.run("no paging")
        commands = COMMANDS.get(platform) or SHOW
        for kind in which:
            command = commands.get(kind)
            if not command:
                continue
            output = shell.run(command, timeout=macssh.TABLE_TIMEOUT)
            if refused(output):
                if kind == RUNNING:
                    result.problem = "It wouldn't show its running-config (not enabled, or not allowed)."
                    return result
                continue
            result.texts[kind] = clean(output)
        running = result.texts.get(RUNNING, "")
        if not result.platform:
            result.platform = text.platform_of(running)
        result.changed_by = who_changed(running)
        if not result.changed_by and result.platform == text.IOS and running:
            result.changed_by = archive_user(shell.run("show archive log config all"))
    except Cancelled:
        result.problem = "Stopped."
    except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
        keep = False
        result.problem = f"The connection failed: {error}"
    finally:
        if not keep:
            pusher.forget(address)
    return result


def pull_pfsense(pusher, address, names=()):
    """pfSense's config.xml, read by running cat on its own (needs a user whose login can run commands)."""
    result = PullResult(platform=text.PFSENSE)
    session, result.login = pusher.logins.login_for(address, names)
    if session is None:
        result.problem = "Couldn't log in: no saved SSH session or login to log in with."
        return result
    prompter = macssh.BatchPrompter(pusher.trust_new, pusher.logins.password)
    transport = SshTransport(session, prompter, known_hosts=pusher.known_hosts)
    if pusher.vault is not None:
        transport.vault = pusher.vault
    try:
        transport.login()
        channel = transport.transport.open_session()
        channel.exec_command(PFSENSE_COMMAND)
        output = read_all(channel, pusher.should_stop)
    except Cancelled:
        result.problem = "Stopped." if not prompter.problem else f"Couldn't log in: {prompter.problem}"
        return result
    except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
        result.problem = f"Couldn't read it: {prompter.problem or error}"
        return result
    finally:
        transport.close()
    if "<pfsense" not in output:
        result.problem = ("It didn't give its config.xml: the login needs a shell (not the console menu) and to be "
                          "allowed to read /conf/config.xml.")
        return result
    result.texts[RUNNING] = clean(output)
    result.changed_by = who_changed(output)
    return result


def read_all(channel, should_stop=lambda: False, timeout=EXEC_TIMEOUT):
    chunks = []
    deadline = time.monotonic() + timeout
    while True:
        if should_stop():
            raise Cancelled()
        if channel.recv_ready():
            chunks.append(channel.recv(65536))
            continue
        if channel.exit_status_ready() and not channel.recv_ready():
            break
        if time.monotonic() > deadline:
            raise ConnectionFailed(f"No end to its answer within {timeout} seconds.")
        time.sleep(0.05)
    return b"".join(chunks).decode("utf-8", "replace")
