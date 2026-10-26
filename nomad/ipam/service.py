"""Running the IPAM server as the "NOMAD IPAM Server" Windows service, and installing, starting and removing it.

Installing (from NOMAD running as administrator on the server) sets up %ProgramData%\\NOMAD\\server (readable only
by Administrators, SYSTEM and the service), copies NOMAD's exe to %ProgramFiles%\\NOMAD so the service doesn't
depend on where NOMAD was started from, registers the service to start with Windows (restarting it if it fails),
opens the port in Windows Firewall and starts it. The packaged exe runs as Network Service; when running from
source, the service runs Python as Local System instead (Network Service can't read a user's profile folder).
Installing again updates the exe and settings in place and keeps the data and the tribe key.
"""
import logging
import os
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .server import IpamServer, load_config, log_to_file, server_dir, set_up

log = logging.getLogger(__name__)

SERVICE_NAME = "NOMADIpamServer"
DISPLAY_NAME = "NOMAD IPAM Server"
DESCRIPTION = "Shares the tribe's IP address management (IPAM) data with NOMAD on every laptop."
FIREWALL_RULE = "NOMAD IPAM Server"
SERVICE_ARGUMENT = "--ipam-service"
NETWORK_SERVICE = r"NT AUTHORITY\NetworkService"
START_WAIT_SECONDS = 20
KILL_WAIT_SECONDS = 10  # After ending a service's process that wouldn't stop, for Windows to see it stopped
COPY_TRIES = 40  # 250 ms apart: the exe can stay locked a moment after its process ends
NOT_INSTALLED, STOPPED, STARTING, RUNNING, STOPPING = "Not installed", "Stopped", "Starting", "Running", "Stopping"
# icacls grants by SID, so they work in any Windows language: SYSTEM, Administrators, Network Service
FOLDER_GRANTS = ["*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-20:(OI)(CI)M"]


class ServiceError(Exception):
    pass


@dataclass(frozen=True)
class ServiceSpec:
    """One of NOMAD's Windows services: the IPAM server, or the Map Watcher."""
    name: str
    display_name: str
    description: str
    argument: str  # On NOMAD's command line, to run as the service
    log_file: object  # () -> Path of its log, to explain a failed start


IPAM = ServiceSpec(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION, SERVICE_ARGUMENT, lambda: server_dir() / "server.log")


def install_dir():
    return Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "NOMAD"


def _hidden():
    return subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0


def _run(arguments):
    result = subprocess.run(arguments, capture_output=True, text=True, creationflags=_hidden())
    if result.returncode != 0:
        raise ServiceError(f"{arguments[0]} failed: {(result.stdout + result.stderr).strip()}")
    return result.stdout


# --------------------------------------------------------------------- The service itself

def _service_class():
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class IpamService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, arguments):
            super().__init__(arguments)
            self.stopped = win32event.CreateEvent(None, 0, 0, None)
            self.server = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.server is not None:
                self.server.stop()
            win32event.SetEvent(self.stopped)

        def SvcDoRun(self):
            log_to_file()
            try:
                self.server = IpamServer()
            except Exception as error:  # Port in use, unreadable folder...: say why in the log and Event Viewer
                log.exception("The IPAM server couldn't start")
                servicemanager.LogErrorMsg(f"{DISPLAY_NAME} couldn't start: {error}")
                return
            thread = threading.Thread(target=self.serve, name="IPAM server", daemon=True)
            thread.start()
            while win32event.WaitForSingleObject(self.stopped, 2000) == win32event.WAIT_TIMEOUT:
                if not thread.is_alive():  # It stopped serving by itself: end, so Windows starts it again
                    servicemanager.LogErrorMsg(f"{DISPLAY_NAME} stopped serving by itself (see server.log)")
                    logging.shutdown()
                    os._exit(1)
            thread.join(15)

        def serve(self):
            try:
                self.server.serve()
            except Exception:
                log.exception("The IPAM server stopped serving")
                raise

    return IpamService


def run_service_dispatcher():
    """Hand this process to Windows' service manager (NOMAD.exe --ipam-service, started by Windows)."""
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


# --------------------------------------------------------------------- Managing it (needs administrator rights)

def status(spec=IPAM):
    """NOT_INSTALLED, STOPPED, STARTING, RUNNING or STOPPING."""
    import pywintypes
    import win32service
    import win32serviceutil
    try:
        state = win32serviceutil.QueryServiceStatus(spec.name)[1]
    except pywintypes.error:
        return NOT_INSTALLED
    return {win32service.SERVICE_STOPPED: STOPPED, win32service.SERVICE_START_PENDING: STARTING,
            win32service.SERVICE_RUNNING: RUNNING, win32service.SERVICE_STOP_PENDING: STOPPING}.get(state, STOPPED)


def _command(argument=SERVICE_ARGUMENT):
    """(command line, account) for the service: the packaged exe copied to Program Files, or Python and Main.py."""
    if getattr(sys, "frozen", False):
        target = install_dir() / "NOMAD.exe"
        target.parent.mkdir(parents=True, exist_ok=True)
        if Path(sys.executable).resolve() != target.resolve():
            _copy_exe(Path(sys.executable), target)
        return f'"{target}" {argument}', NETWORK_SERVICE
    python = Path(sys.executable).with_name("python.exe")
    main = Path(__file__).resolve().parents[2] / "Main.py"
    return f'"{python}" "{main}" {argument}', None  # None: Local System


def _copy_exe(source, target):
    for attempt in range(COPY_TRIES):
        try:
            shutil.copy2(source, target)
            return
        except PermissionError as error:
            if attempt == COPY_TRIES - 1:
                raise ServiceError(f"Couldn't update {target}: {error.strerror or error}. A NOMAD service (or "
                                   "NOMAD itself, started from there) is still running it: stop it, or end that "
                                   "NOMAD.exe in Task Manager (Details tab), and try again.") from None
            time.sleep(0.25)


def shared_exe_specs():
    """The services that run the same copy of NOMAD.exe in Program Files: the IPAM server and the Map Watcher."""
    from ..netmap.watch_service import spec as watcher_spec
    return [IPAM, watcher_spec()]


def secure_folder(directory, grants=FOLDER_GRANTS):
    """Only Administrators, SYSTEM and the service may read the server's folder (it holds the secrets).

    The permissions are set on the folder alone, then everything in it is reset to inherit them (so files the
    server creates later get them too). Setting them on the files directly doesn't work: icacls gives a file no
    permissions at all when handed the folder-only (OI)(CI) flags.
    """
    _run(["icacls", str(directory), "/inheritance:r", "/grant:r", *grants, "/C", "/Q"])
    if any(Path(directory).iterdir()):
        _run(["icacls", str(Path(directory) / "*"), "/reset", "/T", "/C", "/Q"])


def open_firewall(port, rule=FIREWALL_RULE, protocol="TCP"):
    close_firewall(rule)
    _run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule}", "dir=in", "action=allow",
          f"protocol={protocol}", f"localport={port}", "profile=any"])


def close_firewall(rule=FIREWALL_RULE):
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                   capture_output=True, creationflags=_hidden())


def register(spec):
    """Create the service (or point it at this copy of NOMAD again), starting with Windows and restarting if it
    fails. Returns the command line. The other NOMAD service running the same exe is stopped while it's replaced,
    and started again after."""
    import win32service
    others = []
    if getattr(sys, "frozen", False):
        others = [other for other in shared_exe_specs() if other.name != spec.name and status(other) in (
            RUNNING, STARTING, STOPPING)]
    for item in [spec] + others:
        if status(item) in (RUNNING, STARTING, STOPPING):
            stop(item, force=True)  # So the exe can be replaced
    command, account = _command(spec.argument)
    manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_ALL_ACCESS)
    try:
        try:
            service = win32service.OpenService(manager, spec.name, win32service.SERVICE_ALL_ACCESS)
            win32service.ChangeServiceConfig(service, win32service.SERVICE_WIN32_OWN_PROCESS,
                                             win32service.SERVICE_AUTO_START, win32service.SERVICE_ERROR_NORMAL,
                                             command, None, 0, None, account or "LocalSystem", "", spec.display_name)
        except win32service.error:
            service = win32service.CreateService(manager, spec.name, spec.display_name,
                                                 win32service.SERVICE_ALL_ACCESS,
                                                 win32service.SERVICE_WIN32_OWN_PROCESS,
                                                 win32service.SERVICE_AUTO_START,
                                                 win32service.SERVICE_ERROR_NORMAL, command, None, 0, None,
                                                 account, None)
        try:
            win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_DESCRIPTION, spec.description)
            win32service.ChangeServiceConfig2(service, win32service.SERVICE_CONFIG_FAILURE_ACTIONS, {
                "ResetPeriod": 86400, "RebootMsg": None, "Command": None,
                "Actions": [(win32service.SC_ACTION_RESTART, 60000)] * 3})
        finally:
            win32service.CloseServiceHandle(service)
    finally:
        win32service.CloseServiceHandle(manager)
    log.info("Installed the %s service: %s", spec.display_name, command)
    for other in others:
        try:
            start(other)
        except Exception as error:  # Its own problem: this service is installed all the same
            log.warning("Couldn't start the %s service again: %s", other.display_name, error)
    return command


def install(port=None):
    """Install (or update) and start the service. Returns the server's config."""
    directory = server_dir()
    directory.mkdir(parents=True, exist_ok=True)
    secure_folder(directory)  # First, so it also repairs a folder whose files can't be read
    config = set_up(directory, port or 8443)
    if port and config["port"] != port:
        from .server import save_config
        config["port"] = port
        save_config(config, directory)
    register(IPAM)
    open_firewall(config["port"])
    start()
    return config


def start(spec=IPAM):
    import win32serviceutil
    win32serviceutil.StartService(spec.name)
    deadline = time.monotonic() + START_WAIT_SECONDS
    while time.monotonic() < deadline:
        state = status(spec)
        if state == RUNNING:
            return
        if state == STOPPED:
            break
        time.sleep(0.5)
    raise ServiceError(f"The service didn't start. {last_log_error(spec)}")


def stop(spec=IPAM, force=False):
    """Stop the service. force: if it doesn't stop (Windows' error 1053: it isn't answering), end its process, and
    raise ServiceError if even that doesn't stop it."""
    import win32serviceutil
    try:
        win32serviceutil.StopServiceWithDeps(spec.name, waitSecs=START_WAIT_SECONDS)
    except Exception as error:  # Already stopped, or it doesn't exist, or it isn't answering
        log.info("Stopping the service: %s", error)
    if not force or status(spec) in (STOPPED, NOT_INSTALLED):
        return
    pid = service_pid(spec)
    if pid:
        log.warning("The %s service didn't stop: ending its process (%s)", spec.display_name, pid)
        subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True, creationflags=_hidden())
    deadline = time.monotonic() + KILL_WAIT_SECONDS
    while time.monotonic() < deadline and status(spec) not in (STOPPED, NOT_INSTALLED):
        time.sleep(0.25)
    if status(spec) not in (STOPPED, NOT_INSTALLED):
        raise ServiceError(f"The {spec.display_name} service won't stop. End its NOMAD.exe in Task Manager (Details "
                           f"tab; the one run by NETWORK SERVICE, process {pid or '?'}) and try again.")


def service_pid(spec=IPAM):
    """The process ID of the running service, or 0."""
    import win32service
    try:
        manager = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    except win32service.error:
        return 0
    try:
        handle = win32service.OpenService(manager, spec.name, win32service.SERVICE_QUERY_STATUS)
        try:
            return int(win32service.QueryServiceStatusEx(handle).get("ProcessId") or 0)
        finally:
            win32service.CloseServiceHandle(handle)
    except win32service.error:
        return 0
    finally:
        win32service.CloseServiceHandle(manager)


def remove(spec):
    import win32serviceutil
    stop(spec, force=True)
    win32serviceutil.RemoveService(spec.name)


def uninstall():
    """Stop and remove the service and its firewall rule. The data in %ProgramData%\\NOMAD\\server is kept."""
    remove(IPAM)
    close_firewall()


def last_log_error(spec=IPAM):
    """The last error in the service's log, to explain a failed start."""
    try:
        lines = spec.log_file().read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return "Details may be in Event Viewer (Windows Logs > Application)."
    errors = [line for line in lines if " ERROR " in line or " CRITICAL " in line]
    return errors[-1].split(": ", 1)[-1] if errors else "See the server's log for details."


def configured_port():
    try:
        return load_config()["port"]
    except (OSError, KeyError, ValueError):
        return None
