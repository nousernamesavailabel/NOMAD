"""Running Windows commands, PowerShell, and administrator elevation."""
import base64
import ctypes
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

log = logging.getLogger(__name__)

# Keep console windows from flashing up when running without a console (pythonw / packaged exe)
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)
APP_NAME = "NOMAD"
APP_FULL_NAME = "Network Operations, Monitoring And Diagnostics"
LEGACY_APP_NAME = "NIC Manager"  # Name before the rename; its data folders and settings are moved over


class CommandError(Exception):
    """A command failed. str() gives a message suitable for showing to the user."""

    def __init__(self, command, output):
        self.command = command
        self.output = output.strip() or "The command failed without printing an error."
        super().__init__(self.output)


def run_command(command, timeout=120):
    """Run a console command (a list of arguments, never through a shell).

    Returns the combined stdout/stderr. Raises CommandError if it fails.
    """
    command_line = subprocess.list2cmdline(command)
    log.debug("Running: %s", command_line)
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="oem", errors="replace",
                                timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise CommandError(command, f"'{command_line}' did not finish within {timeout} seconds.") from None
    output = "\n".join(part.strip() for part in (result.stdout, result.stderr) if part and part.strip())
    log.debug("Exit code %s, output:\n%s", result.returncode, output)
    # netsh prints its usage text but exits with 0 when given bad arguments
    if result.returncode != 0 or "Usage:" in output:
        raise CommandError(command, output)
    return output


def allow_inbound_port(rule_name, port, protocols=("UDP",)):
    """Add (or replace) a Windows Firewall rule allowing inbound traffic to a local port. Needs administrator
    rights."""
    try:
        run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"])
    except CommandError:
        pass  # No existing rule
    for protocol in protocols:
        run_command(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in",
                     "action=allow", f"protocol={protocol}", f"localport={int(port)}"])


def ps_quote(value):
    """Quote a value as a PowerShell single-quoted string literal."""
    return "'" + str(value).replace("'", "''") + "'"


def run_powershell(script, timeout=120):
    """Run a PowerShell script and return its stdout. Raises CommandError with the error message on failure."""
    wrapped = (
        "$ErrorActionPreference = 'Stop'\n"
        "$ProgressPreference = 'SilentlyContinue'\n"
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
        "try {\n" + script + "\n} catch {\n"
        "    [Console]::Error.WriteLine($_.Exception.Message)\n"
        "    exit 1\n"
        "}\n"
    )
    encoded = base64.b64encode(wrapped.encode("utf-16-le")).decode("ascii")
    command = ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
               "-EncodedCommand", encoded]
    log.debug("Running PowerShell:\n%s", script)
    try:
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                timeout=timeout, creationflags=CREATE_NO_WINDOW)
    except subprocess.TimeoutExpired:
        raise CommandError(command, f"PowerShell did not finish within {timeout} seconds.") from None
    if result.returncode != 0:
        log.debug("PowerShell failed (%s): %s", result.returncode, result.stderr)
        raise CommandError(command, result.stderr or result.stdout)
    return result.stdout


def run_powershell_json(script, timeout=120):
    """Run a PowerShell script that writes JSON and return the parsed result."""
    output = run_powershell(script, timeout).strip()
    return json.loads(output) if output else None


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


RESTARTED_FLAG = "--restarted"  # Started by a copy that's closing: don't hand over to it as to a copy left open
ELEVATED_FOR_FLAG = "--elevated-for="  # Started as administrator by Always Start as Administrator, for this account
RELAUNCH_FLAGS = (RESTARTED_FLAG, ELEVATED_FOR_FLAG)
VK_SHIFT = 0x10


def account_name():
    """This Windows account, as DOMAIN\\user (the administrator's, when elevated with another account's login)."""
    domain, user = os.environ.get("USERDOMAIN", ""), os.environ.get("USERNAME", "")
    return f"{domain}\\{user}" if domain else user


def shift_held():
    """Whether Shift is held down now (to start without administrator rights for once)."""
    try:
        return bool(ctypes.windll.user32.GetAsyncKeyState(VK_SHIFT) & 0x8000)
    except (AttributeError, OSError):
        return False


def relaunch_arguments(arguments, extra=()):
    """The arguments for a relaunched copy: these, less the flags one copy passes the next, then extra."""
    kept = [argument for argument in arguments if not argument.startswith(RELAUNCH_FLAGS)]
    return kept + list(extra)


def elevated_for(arguments):
    """The account Always Start as Administrator started this copy for, or None."""
    for argument in arguments:
        if argument.startswith(ELEVATED_FOR_FLAG):
            return argument[len(ELEVATED_FOR_FLAG):]
    return None


def relaunch_as_admin(extra_arguments=()):
    """Start a new elevated copy of the app, with extra_arguments. Returns False if the user declined the UAC prompt
    (Windows waits for the answer before returning)."""
    if getattr(sys, "frozen", False):
        executable, arguments = sys.executable, relaunch_arguments(sys.argv[1:], extra_arguments)
    else:
        executable = sys.executable
        # Prefer pythonw so the elevated copy doesn't open a console window
        pythonw = Path(executable).with_name("pythonw.exe")
        if pythonw.exists():
            executable = str(pythonw)
        arguments = [os.path.abspath(sys.argv[0])] + relaunch_arguments(sys.argv[1:], extra_arguments)
    result = ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, subprocess.list2cmdline(arguments),
                                                 os.getcwd(), 1)
    log.info("Relaunch as administrator returned %s", result)
    return result > 32


def _data_dir(environment_variable):
    """The app's folder under %APPDATA% or %LOCALAPPDATA%, moving over the folder from before the rename."""
    base = Path(os.environ.get(environment_variable, Path.home()))
    path = base / APP_NAME
    legacy = base / LEGACY_APP_NAME
    if not path.exists() and legacy.is_dir():
        try:
            legacy.rename(path)
        except OSError as error:  # In use by a running copy of the old version; start fresh
            log.warning("Couldn't move %s to %s: %s", legacy, path, error)
    path.mkdir(parents=True, exist_ok=True)
    return path


def app_data_dir():
    """Roaming folder for settings that should follow the user (profiles)."""
    return _data_dir("APPDATA")


def log_dir():
    return _data_dir("LOCALAPPDATA")


REPLACE_TRIES = 20  # 50 ms apart: a second at most


def replace_file(source, target):
    """os.replace(source, target), putting a fully written file in place. Windows refuses it while something else has
    either file open for a moment, as the virus scanner does just after one's written (about 1 in 30 saves in quick
    succession): try again for a little while before giving up."""
    for attempt in range(REPLACE_TRIES):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if attempt == REPLACE_TRIES - 1:
                raise
            time.sleep(0.05)
