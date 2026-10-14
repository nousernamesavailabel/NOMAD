"""Sending configuration to Cisco IOS / IOS-XE switches over SSH with no one watching (Port Mirroring's Set Up and
Take Away, Carry VLAN, ACLs): log in (the switch's saved SSH session, else the login chosen), go to the enable (#)
prompt, type the lines one at a time, and stop at the first one the switch refuses.

Nothing is saved (no write memory) unless asked for (the ACLs page's Save to Startup Config): a switch that reloads
comes back without what was sent.

ACL and VPN changes go in guarded (set_up_guarded): `configure terminal revert timer N` first, so the device puts its old
configuration back by itself after N minutes unless told `configure confirm`, which NOMAD only says from a new login
made after the change (proof it can still get in). A line refused, or no new login, has NOMAD revert right away.

Qt-free: the Port Mirroring page runs it on a worker thread.
"""
import datetime
import logging
import re
import threading
import time
from dataclasses import dataclass, field

import paramiko

from ..terminal.transports import Cancelled, ConnectionFailed
from . import acl, macssh, mirror, routepolicy, vpn, vpnstatus

log = logging.getLogger(__name__)

LINE_TIMEOUT = 30  # Seconds for one configuration line (creating a VLAN can take a while on a Catalyst 9000)
ENABLE_TIMEOUT = 15
PASSWORD_PROMPT = re.compile(r"(?:password|secret)\s*:\s*$", re.IGNORECASE)
CONFIRM_PROMPT = re.compile(r"\[(?:confirm|yes/no|y/n)\]\s*:?\s*$", re.IGNORECASE)
ROLLBACK_NOTE = re.compile(r"rollback|backing up|archive|confirmed change", re.IGNORECASE)
ROLLED_BACK = re.compile(r"rolling to|rollback done", re.IGNORECASE)  # What configure revert now says when it does
NOTHING_PENDING = re.compile(r"no rollback confirmed change pending", re.IGNORECASE)
FILE_SYSTEMS = ("bootflash:", "flash:", "unix:", "disk0:", "flash0:", "nvram:")
ARCHIVE_NAME = "nomad-revert"
SAVE_TIMEOUT = 90


class ConfigShell(macssh.SshShell):
    """A switch's command line that can go to enable and configure."""
    errors_in = staticmethod(mirror.errors_in)  # The lines of an answer that say a line was refused

    def __init__(self, session, vault=None, known_hosts=None, trust_new=False, password=None,
                 should_stop=lambda: False, enable_secret=""):
        super().__init__(session, vault, known_hosts, trust_new, password, should_stop)
        self.enable_secret = enable_secret

    def open(self):
        super().open()
        if self.prompt.endswith(">"):
            self.enable()

    def enable(self):
        """From the > prompt to the # one, with the enable password given (if it asks for one)."""
        self.channel.send("enable\n")
        text = self.read(ENABLE_TIMEOUT, done=lambda tail: bool(PASSWORD_PROMPT.search(tail) or
                                                                 macssh.PROMPT.match(tail)))
        tail = last_line(text)
        if PASSWORD_PROMPT.search(tail):
            if not self.enable_secret:
                self.channel.send("\n")  # Give up on it (IOS asks three times, then says it's bad)
                self.read(ENABLE_TIMEOUT, done=lambda tail: bool(PASSWORD_PROMPT.search(tail) or
                                                                  macssh.PROMPT.match(tail)))
                raise ConnectionFailed("it logs in at the > prompt and asks for an enable password: enter it in "
                                       "Enable password.")
            self.channel.send(self.enable_secret + "\n")
            text = self.read(ENABLE_TIMEOUT, done=lambda tail: bool(PASSWORD_PROMPT.search(tail) or
                                                                     macssh.PROMPT.match(tail)))
            tail = last_line(text)
            if PASSWORD_PROMPT.search(tail):
                self.channel.send("\x03")
                raise ConnectionFailed("it refused the enable password.")
        if not tail.endswith("#"):
            raise ConnectionFailed(f"enable didn't give the # prompt ({tail or 'nothing'}).")
        self.prompt = tail

    def line(self, line, timeout=LINE_TIMEOUT):
        """Type one configuration line: what the switch answered (without the line echoed and the prompt after)."""
        self.channel.send(line + "\n")
        text = self.read(timeout, done=lambda tail: bool(macssh.PROMPT.match(tail) or CONFIRM_PROMPT.search(tail)))
        lines = text.rstrip().splitlines()
        if lines and CONFIRM_PROMPT.search(lines[-1]):
            self.channel.send("\n")  # Take the default ([confirm] is yes)
            lines += self.read(timeout).rstrip().splitlines()
        wanted = line.strip()
        echoed = next((index for index, item in enumerate(lines) if wanted and wanted in item), None)
        if echoed is not None:
            lines = lines[echoed + 1:]
        if lines and macssh.PROMPT.match(lines[-1].strip()):
            lines = lines[:-1]
        return "\n".join(lines)

    def configure(self, text, stop_on_error=True):
        """Type each line of text. Returns (transcript, [(line, [error lines])] of the lines refused). Stops at the
        first refused when stop_on_error (and leaves configuration mode)."""
        transcript, refused = [], []
        in_config = False
        for line in text.splitlines():
            if not line.strip():
                continue
            answer = self.line(line)
            transcript.append(line.rstrip())
            if answer.strip():
                transcript.append(answer.rstrip())
            word = line.strip()
            if word.startswith("conf"):
                in_config = True
            elif word == "end":
                in_config = False
            errors = self.errors_in(answer)
            if errors:
                refused.append((word, errors))
                if stop_on_error:
                    if in_config:
                        self.line("end")
                    break
        return "\n".join(transcript), refused


def last_line(text):
    lines = (text or "").rstrip().splitlines()
    return lines[-1].strip() if lines else ""


@dataclass
class Outcome:
    """How sending to one switch went."""
    ok: bool = False
    transcript: str = ""
    refused: list = field(default_factory=list)  # [(line, [error lines])]
    applet_ok: object = None  # True, False (refused), None (none sent)
    problem: str = ""  # Couldn't log in, or what was refused, in a sentence
    confirmed: object = None  # Guarded: True (configure confirm said from a new login), False, None (not guarded)
    reverted: bool = False  # Guarded: put back right away (a line refused, or no new login)
    reverts_at: str = ""  # Guarded, not confirmed and not put back: when the device puts it back itself (HH:MM)
    archive_added: str = ""  # The archive path NOMAD set up for the revert timer
    waiting: bool = False  # Guarded, in and a new login works, but left for the user to confirm (by reverts_by)
    reverts_by: object = None  # Guarded: when the device puts it back unless confirmed (datetime), roughly

    @property
    def first_error(self):
        if self.refused:
            line, errors = self.refused[0]
            return f"{line}: {errors[0]}"
        return self.problem


class Pusher:
    """Logs in to each switch once (kept until close) and sends to it."""

    def __init__(self, logins, vault=None, known_hosts=None, trust_new=False, enable_secret="",
                 should_stop=lambda: False, shell_factory=ConfigShell):
        self.logins, self.vault, self.known_hosts = logins, vault, known_hosts
        self.trust_new, self.enable_secret, self.should_stop = trust_new, enable_secret, should_stop
        self.shell_factory = shell_factory
        self.shells = {}
        self.problems = {}
        self.login_labels = {}
        self.lock = threading.Lock()

    def shell(self, address, names=()):
        """The switch's command line at the # prompt, or None (and why in problems[address])."""
        if address in self.shells:
            return self.shells[address]
        shell = self.new_shell(address, names)
        self.shells[address] = shell
        return shell

    def new_shell(self, address, names=()):
        """A login of its own (not the one kept), or None (and why in problems[address])."""
        session, self.login_labels[address] = self.logins.login_for(address, names)
        if session is None:
            self.problems[address] = "no saved SSH session or login to log in with."
            return None
        shell = self.shell_factory(session, self.vault, self.known_hosts, self.trust_new, self.logins.password,
                                   self.should_stop, enable_secret=self.enable_secret)
        try:
            shell.open()
        except Cancelled:
            shell.close()
            shell = None
            self.problems[address] = "stopped."
        except ConnectionFailed as error:
            shell.close()
            shell = None
            self.problems[address] = str(error)
        except (paramiko.SSHException, OSError, EOFError) as error:
            shell.close()
            shell = None
            self.problems[address] = f"SSH failed: {error}"
        return shell

    def forget(self, address):
        shell = self.shells.pop(address, None)
        if shell is not None:
            shell.close()

    def read_state(self, address, names=()):
        """mirror.SwitchState: the switch's sessions and NOMAD's applets."""
        shell = self.shell(address, names)
        if shell is None:
            return mirror.SwitchState(problem=self.problems.get(address, ""))
        try:
            text = ""
            for command in ("show monitor session all", "show monitor"):
                text = shell.run(command)
                if not macssh.INVALID.search(text):
                    break
            else:
                return mirror.SwitchState(problem="it doesn't know show monitor (no SPAN on it?).")
            applets = shell.run("show running-config | include event manager applet")
        except Cancelled:
            return mirror.SwitchState(problem="stopped.")
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            return mirror.SwitchState(problem=str(error))
        return mirror.SwitchState(read=True, sessions=mirror.parse_sessions(text), applets=mirror.parse_applets(applets))

    def set_up(self, address, setup, applet="", names=()):
        """Send a step's lines (setup, then the applet, if any). ok when every setup line was taken; an applet
        refused leaves applet_ok False (and is cleaned away)."""
        outcome = Outcome()
        shell = self.shell(address, names)
        if shell is None:
            outcome.problem = f"Couldn't log in: {self.problems.get(address, 'no reason given')}"
            return outcome
        try:
            outcome.transcript, outcome.refused = shell.configure(setup)
            outcome.ok = not outcome.refused
            if outcome.ok and applet:
                transcript, refused = shell.configure(applet)
                outcome.transcript += "\n" + transcript
                outcome.applet_ok = not refused
                if refused:
                    name = re.search(r"event manager applet (\S+)", applet)
                    if name:
                        shell.configure(f"configure terminal\nno event manager applet {name.group(1)}\nend",
                                        stop_on_error=False)
        except Cancelled:
            outcome.problem = "Stopped."
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            outcome.ok = False
            outcome.problem = f"The connection failed partway: {error}"
        if outcome.refused and not outcome.problem:
            outcome.problem = f"It refused {outcome.first_error}"
        return outcome

    def take_away(self, address, undo, names=()):
        """Send a step's undo, carrying on past lines refused. ok when the session (and VLAN, trunks) went: a missing
        applet (it already ran) or something already gone isn't a failure."""
        outcome = Outcome()
        shell = self.shell(address, names)
        if shell is None:
            outcome.problem = f"Couldn't log in: {self.problems.get(address, 'no reason given')}"
            return outcome
        try:
            outcome.transcript, refused = shell.configure(undo, stop_on_error=False)
        except Cancelled:
            outcome.problem = "Stopped."
            return outcome
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            outcome.problem = f"The connection failed partway: {error}"
            return outcome
        outcome.refused = [(line, errors) for line, errors in refused if not harmless_undo(line, errors)]
        outcome.ok = not outcome.refused
        if outcome.refused:
            outcome.problem = f"It refused {outcome.first_error}"
        return outcome

    # ----------------------------------------------------------------- ACLs

    def read_acls(self, address, names=(), pc_ip=""):
        """acl.DeviceAcls read from the device (problem set when it couldn't be)."""
        shell = self.shell(address, names)
        if shell is None:
            return acl.DeviceAcls(problem=self.problems.get(address, ""))
        try:
            running = shell.run("show running-config", timeout=macssh.TABLE_TIMEOUT)
            if macssh.INVALID.search(running) or ("interface" not in running and "access-list" not in running):
                return acl.DeviceAcls(problem="it wouldn't show its running-config (not enabled, or not allowed).")
            shown = shell.run("show ip access-lists", timeout=macssh.TABLE_TIMEOUT)
            shown6 = shell.run("show ipv6 access-list", timeout=macssh.TABLE_TIMEOUT)
            if macssh.INVALID.search(shown6):
                shown6 = ""
            toward = ""
            if pc_ip and ":" not in pc_ip:
                toward = shell.run(f"show ip cef {pc_ip}")
                if macssh.INVALID.search(toward):
                    toward = shell.run(f"show ip route {pc_ip}")
            prefixes = maps = ""
            if "prefix-list " in running:
                prefixes = shell.run("show ip prefix-list detail", timeout=macssh.TABLE_TIMEOUT)
                if "ipv6 prefix-list " in running:
                    prefixes += "\n" + shell.run("show ipv6 prefix-list detail", timeout=macssh.TABLE_TIMEOUT)
            if "\nroute-map " in running:
                maps = shell.run("show route-map", timeout=macssh.TABLE_TIMEOUT)
        except Cancelled:
            return acl.DeviceAcls(problem="stopped.")
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            return acl.DeviceAcls(problem=str(error))
        device = acl.parse_running(running)
        acl.merge_show(device, acl.parse_show(f"{shown}\n{shown6}"))
        if prefixes and not macssh.INVALID.search(prefixes):
            routepolicy.merge_show_prefix(device, prefixes)
        if maps and not macssh.INVALID.search(maps):
            routepolicy.merge_show_maps(device, maps)
        device.toward_pc = acl.parse_toward(toward) if toward and not macssh.INVALID.search(toward) else ""
        device.when = acl.now_text()
        return device

    def archive_ready(self, shell):
        """The archive path the revert timer needs: the one set, else one NOMAD sets on the device's default file
        system. (path, whether NOMAD added it), or ("", False) when it couldn't."""
        text = shell.run("show running-config | section archive")
        found = re.search(r"^\s+path\s+(\S+)", text, re.MULTILINE)
        if found:
            return found.group(1), False
        systems = shell.run("show file systems")
        chosen = ""
        for line in systems.splitlines():
            prefixes = re.findall(r"(\S+:)", line)
            words = line.split()
            if line.lstrip().startswith("*") and prefixes and "disk" in words and "rw" in words:
                chosen = prefixes[0]
                break
        if not chosen:
            chosen = next((name for name in FILE_SYSTEMS if name in systems), "")
        if not chosen:
            return "", False
        path = f"{chosen}{ARCHIVE_NAME}"
        _, refused = shell.configure(f"configure terminal\narchive\n path {path}\n maximum 3\nend",
                                     stop_on_error=False)
        if any(line.startswith("path") for line, _ in refused):
            return "", False
        return path, True

    def set_up_guarded(self, address, text, minutes, names=(), confirm=True):
        """Send ACL changes with the revert timer (text's first line is configure terminal revert timer N), then
        confirm them from a new login (or, confirm False, only check a new login works and leave the confirming to
        the user: Outcome.waiting). A line refused, or no new login, puts the old configuration back right away
        (configure revert now); if even that can't be said, the device does it itself after minutes."""
        outcome = Outcome()
        shell = self.shell(address, names)
        if shell is None:
            outcome.problem = f"Couldn't log in: {self.problems.get(address, 'no reason given')}"
            return outcome
        reverts = (datetime.datetime.now() + datetime.timedelta(minutes=minutes)).strftime("%H:%M")
        try:
            path, added = self.archive_ready(shell)
            if not path:
                outcome.problem = ("It has no archive path for the revert timer, and NOMAD couldn't find a file "
                                   "system to set one on. Send without the revert timer, or set archive / path on "
                                   "it first.")
                return outcome
            outcome.archive_added = path if added else ""
            outcome.reverts_by = datetime.datetime.now() + datetime.timedelta(minutes=minutes)
            outcome.transcript, outcome.refused = self.configure_past_notes(shell, text)
            if outcome.refused:
                outcome.reverted = self.revert_now(shell)
                outcome.reverts_at = "" if outcome.reverted else reverts
                outcome.problem = f"It refused {outcome.first_error}"
                return outcome
        except Cancelled:
            outcome.problem = "Stopped."
            outcome.reverts_at = reverts
            return outcome
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            outcome.problem = f"The connection failed partway: {error}"
            outcome.reverts_at = reverts
            return outcome
        fresh = self.new_shell(address, names)  # Prove a new login still gets in, and confirm from it
        if fresh is None:
            why = self.problems.get(address, "no reason given")
            outcome.confirmed = False
            outcome.reverted = self.revert_now(shell)
            outcome.reverts_at = "" if outcome.reverted else reverts
            outcome.problem = f"A new login failed after the change ({why})" + \
                (", so it was put back." if outcome.reverted else f"; the device puts it back at {reverts}.")
            return outcome
        if not confirm:
            fresh.close()
            outcome.transcript += "\n(a new login works; left for you to confirm)"
            outcome.ok, outcome.confirmed, outcome.waiting, outcome.reverts_at = True, False, True, reverts
            return outcome
        try:
            answer = fresh.run("configure confirm")
            outcome.transcript += "\n(new login) configure confirm\n" + answer
            outcome.confirmed = not macssh.INVALID.search(answer)
            if not outcome.confirmed:
                outcome.problem = f"configure confirm was refused: {answer.strip()[:200]}"
                outcome.reverts_at = reverts
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            outcome.confirmed = False
            outcome.problem = f"configure confirm failed: {error}"
            outcome.reverts_at = reverts
        finally:
            fresh.close()
        outcome.ok = bool(outcome.confirmed)
        return outcome

    @staticmethod
    def configure_past_notes(shell, text):
        """shell.configure(text), carrying on past lines whose only "errors" are the revert timer's own notes."""
        lines = [line for line in text.splitlines() if line.strip()]
        transcript, refused = [], []
        while lines:
            part, said = shell.configure("\n".join(lines))
            transcript.append(part)
            if not said:
                break
            line, errors = said[0]
            real = [error for error in errors if not ROLLBACK_NOTE.search(error)]
            if real:
                refused = [(line, real)]
                break
            at = next((index for index, item in enumerate(lines) if item.strip() == line), None)
            if at is None or at + 1 >= len(lines):
                break
            rest = lines[at + 1:]
            if rest[0].startswith(" "):  # Inside a mode: go back into it
                mode = next((item for item in reversed(lines[:at + 1]) if not item.startswith(" ") and
                             not item.startswith("conf")), None)
                rest = ([mode] if mode else []) + rest
            lines = (["configure terminal"] if rest[0].strip() != "end" else []) + rest
        return "\n".join(transcript), refused

    def confirm(self, address, names=()):
        """configure confirm from a new login (so it shows logins still work): (ok, what it said)."""
        fresh = self.new_shell(address, names)
        if fresh is None:
            return False, f"A new login failed: {self.problems.get(address, 'no reason given')}"
        try:
            answer = fresh.run("configure confirm")
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            return False, str(error)
        finally:
            fresh.close()
        refused = macssh.INVALID.search(answer) or mirror.errors_in(answer)
        return not refused, answer.strip()

    def revert(self, address, names=()):
        """configure revert now: (ok, what went wrong)."""
        shell = self.shell(address, names)
        if shell is None:
            return False, f"Couldn't log in: {self.problems.get(address, 'no reason given')}"
        if self.revert_now(shell):
            return True, ""
        return False, "configure revert now wasn't taken (nothing waiting to be put back?)"

    def revert_now(self, shell):
        """configure revert now on a login still open: whether it was taken."""
        try:
            answer = shell.line("configure revert now", timeout=LINE_TIMEOUT * 2)
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError):
            return False
        if macssh.INVALID.search(answer) or NOTHING_PENDING.search(answer):
            return False
        # Notes IOS prints while it puts the old configuration back (%EIGRP: Deleting base topology is not allowed)
        # don't mean it didn't
        return bool(ROLLED_BACK.search(answer)) or not mirror.errors_in(answer)

    def run_commands(self, address, commands, names=()):
        """Exec commands (BGP soft clears): [(command, what it said, whether it took)]."""
        shell = self.shell(address, names)
        if shell is None:
            return [(command, f"Couldn't log in: {self.problems.get(address, 'no reason given')}", False)
                    for command in commands]
        results = []
        for command in commands:
            try:
                answer = shell.run(command, timeout=LINE_TIMEOUT * 2)
            except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
                self.forget(address)
                results.append((command, str(error), False))
                break
            refused = macssh.INVALID.search(answer) or mirror.errors_in(answer) or \
                re.search(r"^\s*%", answer, re.MULTILINE)
            results.append((command, answer.strip(), not refused))
        return results

    def save_config(self, address, names=()):
        """write memory: (ok, what it said)."""
        shell = self.shell(address, names)
        if shell is None:
            return False, self.problems.get(address, "")
        try:
            answer = shell.line("write memory", timeout=SAVE_TIMEOUT)
        except (Cancelled, ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            return False, str(error)
        return "[OK]" in answer or not mirror.errors_in(answer), answer.strip()

    # ----------------------------------------------------------------- VPNs

    def read_vpns(self, address, names=(), pc_ip=""):
        """vpn.DeviceVpns read from the router: running-config, routes, version, and what its show commands say about
        the VPNs up now (raw, for vpnstatus). problem set when it couldn't be read."""
        shell = self.shell(address, names)
        if shell is None:
            return vpn.DeviceVpns(problem=self.problems.get(address, ""))
        try:
            running = shell.run("show running-config", timeout=macssh.TABLE_TIMEOUT)
            if macssh.INVALID.search(running) or "interface" not in running:
                return vpn.DeviceVpns(problem="it wouldn't show its running-config (not enabled, or not allowed).")
            routes = shell.run("show ip route", timeout=macssh.TABLE_TIMEOUT)
            version = shell.run("show version | include IOS|Version")
            raw = {}
            for command in vpnstatus.SHOW_COMMANDS:
                if command.startswith("show crypto pki") and "crypto pki trustpoint" not in running:
                    continue
                if (command.startswith("show dmvpn") or command.startswith("show ip nhrp")) and \
                        " nhrp " not in running:
                    continue
                answer = shell.run(command, timeout=macssh.TABLE_TIMEOUT)
                raw[command] = "" if macssh.INVALID.search(answer) else answer
            toward = ""
            if pc_ip and ":" not in pc_ip:
                toward = shell.run(f"show ip cef {pc_ip}")
                if macssh.INVALID.search(toward):
                    toward = ""
        except Cancelled:
            return vpn.DeviceVpns(problem="stopped.")
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            return vpn.DeviceVpns(problem=str(error))
        device = vpn.parse_device(running, routes if not macssh.INVALID.search(routes) else "", version)
        device.status = vpnstatus.parse(raw)
        device.toward_pc = acl.parse_toward(toward) if toward else ""
        device.pc_ip = pc_ip
        device.when = acl.now_text()
        return device

    def verify(self, address, checks, names=(), wait=90, should_stop=None):
        """Run a VPN's checks on a router until each passes (or wait seconds go by: a tunnel takes a few to come up,
        a routing neighbor longer): [(command, passed, what it said, what it means)]."""
        shell = self.shell(address, names)
        if shell is None:
            return [(command, False, f"Couldn't log in: {self.problems.get(address, 'no reason given')}", meaning)
                    for command, _, meaning in checks]
        results = []
        deadline = time.monotonic() + wait
        for command, wanted, meaning in checks:
            answer, passed = "", False
            while True:
                if (should_stop or self.should_stop)():
                    raise Cancelled()
                try:
                    answer = shell.run(command, timeout=LINE_TIMEOUT * 2)
                except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
                    self.forget(address)
                    answer = str(error)
                    break
                passed = bool(re.search(wanted, answer))
                if passed or time.monotonic() > deadline:
                    break
                time.sleep(3)
            results.append((command, passed, answer.strip(), meaning))
        return results

    def dialog(self, address, steps, names=(), timeout=120):
        """Exec or configuration lines that ask questions (crypto pki authenticate / enroll, crypto pki server no
        shutdown...). steps: [(line, [(regex of a question, answer)])]; a question no rule answers stops it.
        Returns (ok, transcript, problem)."""
        shell = self.shell(address, names)
        if shell is None:
            return False, "", f"Couldn't log in: {self.problems.get(address, 'no reason given')}"
        transcript = []
        try:
            for line, answers in steps:
                ok, said, problem = shell.dialog(line, answers, timeout)
                transcript.append(said)
                if not ok:
                    return False, "\n".join(transcript), problem
        except Cancelled:
            return False, "\n".join(transcript), "Stopped."
        except (ConnectionFailed, paramiko.SSHException, OSError, EOFError) as error:
            self.forget(address)
            return False, "\n".join(transcript), f"The connection failed partway: {error}"
        return True, "\n".join(transcript), ""

    def close(self):
        shells, self.shells = list(self.shells.values()), {}
        for shell in shells:
            if shell is not None:
                shell.close()


QUESTION = re.compile(r"(?:\[(?:yes/no|confirm|y/n|no|yes)\]\s*:?|password\s*:|passphrase\s*:|\?\s*\[[^\]]*\]\s*:?|"
                      r"Re-enter password\s*:|\?)\s*$", re.IGNORECASE)


class VpnShell(ConfigShell):
    """A router's command line for VPN changes: crypto refusals don't always start with %, and some % lines are only
    notes; and some commands ask questions (dialog)."""
    errors_in = staticmethod(vpn.refusals)

    def dialog(self, line, answers, timeout=120):
        """Type a line and answer what it asks: (ok, transcript, problem)."""
        self.channel.send(line + "\n")
        transcript = [line]
        deadline = time.monotonic() + timeout
        while True:
            remaining = max(5, deadline - time.monotonic())
            text = self.read(remaining, done=lambda tail: bool(
                macssh.PROMPT.match(tail) or QUESTION.search(tail) or
                any(re.search(pattern, tail, re.IGNORECASE) for pattern, _ in answers)))
            lines = text.rstrip().splitlines()
            tail = lines[-1].strip() if lines else ""
            body = "\n".join(item for item in lines if item.strip() != line.strip())
            transcript.append(body)
            refused = vpn.refusals(body)
            if macssh.PROMPT.match(tail) and not QUESTION.search(tail):
                if refused:
                    return False, "\n".join(transcript), refused[0]
                return True, "\n".join(transcript), ""
            reply = next((answer for pattern, answer in answers if re.search(pattern, tail, re.IGNORECASE)), None)
            if reply is None:
                reply = next((answer for pattern, answer in answers if re.search(pattern, body, re.IGNORECASE)), None)
            if callable(reply):  # An answer that depends on what it said (a CA's fingerprint checked)
                reply = reply("\n".join(transcript))
                if reply is None:
                    self.channel.send("no\n")
                    self.read(30)
                    return False, "\n".join(transcript), "NOMAD said no (what it showed wasn't what was expected)."
            if reply is None:
                self.channel.send("\x03")  # Nothing says what to answer: give up on it
                self.read(15)
                return False, "\n".join(transcript), f"It asked something NOMAD has no answer for: {tail}"
            self.channel.send(reply + "\n")
            transcript.append(vpn.mask(f"(answered) {reply}") if "assword" not in tail and "passphrase" not in tail
                              else "(answered)")
            if time.monotonic() > deadline:
                return False, "\n".join(transcript), "It took too long."


def harmless_undo(line, errors):
    """A line of an undo refused only because what it takes away is gone already."""
    text = " ".join(errors).lower()
    if line.startswith("no event manager applet"):
        return True
    return any(word in text for word in ("not found", "does not exist", "not exist", "no such", "not configured",
                                         "not present"))
