"""Asking a server or phone what it is (maker, model, serial number, operating system or firmware), for the Assets
page: the network map reads switches, routers and firewalls over SNMP, but servers rarely answer SNMP with any of
that, and phones only tell their switch some of it.

- Windows: WMI (CIM) over WinRM, or DCOM when WinRM isn't on, as this Windows login or a user name and password
  (Win32_BIOS's serial number, Win32_ComputerSystem's maker and model, Win32_OperatingSystem's name and version).
  PowerShell does the asking; the password goes to it on its standard input, never on its command line.
- Linux: over SSH (a saved session or a login given for the read), from /sys/class/dmi/id and /etc/os-release. The
  serial number is readable only by root: sudo -n is tried, which works where sudo needs no password.
- Cisco IP phones: their web page's DeviceInformationX (when the phone's web access is on).

Each returns a HostDetails; problems are in its error, not raised. Qt-free: the page runs these on worker threads.
"""
import base64
import json
import logging
import re
import subprocess
import time
import urllib.request
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass

import paramiko

from .oui import format_mac

log = logging.getLogger(__name__)

WINDOWS, LINUX, PHONE = "windows", "linux", "phone"
METHODS = {WINDOWS: "Windows server (WMI)", LINUX: "Linux server (SSH)", PHONE: "Cisco IP phone (web page)"}
WINDOWS_TIMEOUT = 90  # Seconds: WinRM, then DCOM, each with their own waits
SSH_TIMEOUT = 30
PHONE_TIMEOUT = 6
MARK = "@@NOMAD@@"
PLACEHOLDER_SERIALS = {"", "0", "none", "default string", "to be filled by o.e.m.", "system serial number",
                       "not specified", "not applicable", "0123456789"}

WINDOWS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ask = [Console]::In.ReadToEnd() | ConvertFrom-Json
$options = @{ComputerName = $ask.computer; OperationTimeoutSec = 30}
if ($ask.user) {
    $secret = ConvertTo-SecureString $ask.password -AsPlainText -Force
    $options.Credential = New-Object System.Management.Automation.PSCredential($ask.user, $secret)
}
try { $session = New-CimSession @options }
catch {
    $first = $_.Exception.Message
    try { $session = New-CimSession @options -SessionOption (New-CimSessionOption -Protocol Dcom) }
    catch { throw "WinRM: $first DCOM: $($_.Exception.Message)" }
}
$bios = Get-CimInstance -CimSession $session -ClassName Win32_BIOS
$system = Get-CimInstance -CimSession $session -ClassName Win32_ComputerSystem
$os = Get-CimInstance -CimSession $session -ClassName Win32_OperatingSystem
$nic = Get-CimInstance -CimSession $session -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled = True' |
    Select-Object -First 1
Remove-CimSession $session
[pscustomobject]@{
    hostname = $system.DNSHostName; domain = $system.Domain; maker = $system.Manufacturer; model = $system.Model
    serial = $bios.SerialNumber; os = $os.Caption; version = $os.Version; mac = $nic.MACAddress
} | ConvertTo-Json -Compress
"""

LINUX_COMMAND = "; ".join([
    "hostname", f"echo {MARK}",
    "cat /sys/class/dmi/id/sys_vendor 2>/dev/null", f"echo {MARK}",
    "cat /sys/class/dmi/id/product_name 2>/dev/null", f"echo {MARK}",
    "cat /sys/class/dmi/id/product_serial 2>/dev/null || sudo -n cat /sys/class/dmi/id/product_serial 2>/dev/null",
    f"echo {MARK}",
    "(. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\")", f"echo {MARK}",
    "uname -r", f"echo {MARK}",
    "cat /sys/class/net/$(ip route show default 2>/dev/null | awk '{print $5; exit}')/address 2>/dev/null",
])


@dataclass
class HostDetails:
    address: str
    method: str
    hostname: str = ""
    maker: str = ""
    model: str = ""
    serial: str = ""
    os: str = ""  # The operating system (or a phone's firmware), as it names itself
    software: str = ""  # Its version
    mac: str = ""
    error: str = ""
    note: str = ""  # Worth knowing, such as why the serial number is missing

    @property
    def ok(self):
        return not self.error


def clean_serial(text):
    text = (text or "").strip()
    return "" if text.lower() in PLACEHOLDER_SERIALS else text


# --------------------------------------------------------------------- Windows

def windows_details(address, user="", password="", runner=None, timeout=WINDOWS_TIMEOUT):
    """Ask a Windows computer over WMI. runner(arguments, input text, timeout) -> (exit code, output, errors) runs
    PowerShell (tests give their own)."""
    runner = runner or _run_powershell
    encoded = base64.b64encode(WINDOWS_SCRIPT.encode("utf-16-le")).decode("ascii")
    arguments = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", encoded]
    request = json.dumps({"computer": address, "user": user or "", "password": password or ""})
    try:
        code, output, errors = runner(arguments, request, timeout)
    except subprocess.TimeoutExpired:
        return HostDetails(address, WINDOWS, error=f"No answer within {timeout} seconds (WMI is blocked, or it's "
                                                    "not a Windows computer).")
    except OSError as error:
        return HostDetails(address, WINDOWS, error=f"Couldn't run PowerShell: {error}")
    return parse_windows(address, code, output, errors)


def parse_windows(address, code, output, errors):
    line = next((line for line in reversed(output.strip().splitlines()) if line.startswith("{")), "")
    if code != 0 or not line:
        message = " ".join(_powershell_error(errors).split()) or "WMI didn't answer."
        if "Access is denied" in message or "Access denied" in message:
            message = "Access is denied: log in with an account that's an administrator on it. " + message
        return HostDetails(address, WINDOWS, error=message[:400])
    try:
        data = json.loads(line)
    except ValueError:
        return HostDetails(address, WINDOWS, error="WMI's answer couldn't be read.")
    hostname = data.get("hostname") or ""
    domain = data.get("domain") or ""
    if hostname and "." in domain and "." not in hostname:
        hostname = f"{hostname}.{domain}"  # In a domain: its full name
    serial = clean_serial(data.get("serial"))
    return HostDetails(address, WINDOWS, hostname=hostname, maker=(data.get("maker") or "").strip(),
                       model=(data.get("model") or "").strip(), serial=serial, os=(data.get("os") or "").strip(),
                       software=(data.get("version") or "").strip(), mac=format_mac(data.get("mac") or ""),
                       note="" if serial else "Its firmware doesn't give a serial number (a virtual machine?).")


def _powershell_error(text):
    """The message of PowerShell's error output, without its CLIXML wrapping and position lines."""
    text = re.sub(r"<[^>]+>", " ", text or "").replace("_x000D__x000A_", " ")
    lines = [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith(("At ", "+",
                                                                                                    "#< CLIXML"))]
    return " ".join(lines)


def _run_powershell(arguments, request, timeout):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    done = subprocess.run(arguments, input=request, capture_output=True, text=True, timeout=timeout,
                          creationflags=flags, encoding="utf-8", errors="replace")
    return done.returncode, done.stdout, done.stderr


# --------------------------------------------------------------------- Linux

def linux_details(address, session, known_hosts=None, prompter=None, vault=None, transport_factory=None,
                  timeout=SSH_TIMEOUT):
    """Ask a Linux computer over SSH, logging in with session (a terminal Session: saved, or made for the read) and
    prompter (macssh.BatchPrompter: no one to ask)."""
    from .terminal.transports import Cancelled, ConnectionFailed, SshTransport
    factory = transport_factory or SshTransport
    ssh = factory(session, prompter, known_hosts=known_hosts)
    if vault is not None:
        ssh.vault = vault
    try:
        ssh.login()
        output = _exec(ssh.transport, LINUX_COMMAND, timeout)
    except Cancelled:
        return HostDetails(address, LINUX, error=getattr(prompter, "problem", "") or "Login was cancelled.")
    except ConnectionFailed as error:
        return HostDetails(address, LINUX, error=str(error))
    except (paramiko.SSHException, OSError, EOFError) as error:
        return HostDetails(address, LINUX, error=f"SSH failed: {error}")
    finally:
        try:
            ssh.close()
        except Exception:  # Closing a half-open connection: nothing more to do
            pass
    return parse_linux(address, output)


def _exec(transport, command, timeout):
    channel = transport.open_session()
    channel.settimeout(timeout)
    channel.exec_command(command)
    chunks, deadline = [], time.monotonic() + timeout
    while time.monotonic() < deadline:
        data = channel.recv(65536)
        if not data:
            break
        chunks.append(data)
    channel.close()
    return b"".join(chunks).decode("utf-8", "replace")


def parse_linux(address, output):
    fields = [part.strip() for part in output.split(MARK)]
    fields += [""] * (7 - len(fields))
    hostname, maker, model, serial, os_name, kernel, mac = fields[:7]
    if not any(fields[:6]):
        return HostDetails(address, LINUX, error="It didn't answer like a Linux computer.")
    serial = clean_serial(serial)
    note = "" if serial else "The serial number needs root: give the login sudo without a password for " \
                             "'cat /sys/class/dmi/id/product_serial', or fill it in by hand."
    return HostDetails(address, LINUX, hostname=hostname.splitlines()[0] if hostname else "", maker=maker,
                       model=model, serial=serial, os=os_name, software=kernel, mac=format_mac(mac), note=note)


# --------------------------------------------------------------------- Cisco IP phones

def phone_details(address, fetch=None, timeout=PHONE_TIMEOUT):
    """Ask a Cisco IP phone's web page. fetch(url, timeout) -> text (tests give their own)."""
    fetch = fetch or _fetch
    try:
        text = fetch(f"http://{address}/DeviceInformationX", timeout)
    except OSError as error:
        reason = getattr(error, "reason", error)
        return HostDetails(address, PHONE, error=f"Its web page didn't answer ({reason}): its web access may be "
                                                 "turned off in Unified CM.")
    return parse_phone(address, text)


def parse_phone(address, text):
    try:
        root = ElementTree.fromstring(text.strip())
    except ElementTree.ParseError:
        return HostDetails(address, PHONE, error="Its web page isn't a Cisco phone's device information.")
    values = {element.tag.lower(): (element.text or "").strip() for element in root.iter()}
    if not values.get("serialnumber") and not values.get("modelnumber"):
        return HostDetails(address, PHONE, error="Its web page doesn't say its model or serial number.")
    return HostDetails(address, PHONE, hostname=values.get("hostname", ""), maker="Cisco",
                       model=values.get("modelnumber", ""), serial=clean_serial(values.get("serialnumber")),
                       os=values.get("appLoadID".lower(), ""), software=values.get("versionid", ""),
                       mac=format_mac(values.get("macaddress", "")))


def _fetch(url, timeout):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # The phone is on this network
    with opener.open(url, timeout=timeout) as response:
        return response.read(256 * 1024).decode("utf-8", "replace")
