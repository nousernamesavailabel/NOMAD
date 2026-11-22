"""The NOMAD Dashboard Windows service: the dashboard's web server and engine, running whether anyone is signed in or
not, on the computer with the Map Watcher and the Syslog and Flow Collectors (it reads them there).

Its folder (%ProgramData%\\NOMAD\\dashboard, readable by Administrators, SYSTEM and the service) holds config.json
(the port, how long to keep history, and the tribe's viewer key with its secret encrypted for this computer),
users.json (the logins, hashed), sessions.json, the certificate and its key, history.db, its copies of the tribe and
its log. Tools > NOMAD Dashboard Service in NOMAD sets it up.
"""
import json
import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path

from . import history, tls

log = logging.getLogger(__name__)

SERVICE_NAME = "NOMADDashboard"
DISPLAY_NAME = "NOMAD Dashboard"
DESCRIPTION = ("Serves the read-only NOMAD Dashboard web site: the network's state, from the Map Watcher, the Syslog "
               "and Flow Collectors and the tribe, for people without NOMAD.")
SERVICE_ARGUMENT = "--dashboard-service"
FIREWALL_RULE = "NOMAD Dashboard"
DEFAULT_PORT = 8444


def dashboard_dir():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "dashboard"


def default_config():
    return make_config()


def make_config(port=DEFAULT_PORT, raw_days=history.RAW_DAYS, hourly_days=history.HOURLY_DAYS,
                max_gb=history.MAX_GB, session_hours=12, key=None, protect=None, tribe=None):
    """The service's config. key: the tribe's viewer key (a TeamKey), its secret encrypted for this computer; or
    tribe: an already encrypted one (kept from the config before)."""
    config = {"port": int(port), "raw_days": int(raw_days), "hourly_days": int(hourly_days), "max_gb": float(max_gb),
              "session_hours": int(session_hours)}
    if key is not None:
        if protect is None:
            from ..terminal.credentials import protect as dpapi

            def protect(text):
                return dpapi(text, machine=True)
        config["tribe"] = {"server_id": key.server_id, "hosts": list(key.hosts), "port": key.port,
                           "fingerprint": key.fingerprint, "secret": protect(key.secret), "role": key.role}
    elif tribe:
        config["tribe"] = dict(tribe)
    return config


def load_config(directory=None):
    config = default_config()
    try:
        config.update(json.loads((Path(directory or dashboard_dir()) / "config.json").read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return config


def save_config(config, directory=None):
    directory = Path(directory or dashboard_dir())
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "config.json.tmp"
    temporary.write_text(json.dumps(config, indent=2), encoding="utf-8")
    temporary.replace(directory / "config.json")


def key_from_config(config, unprotect=None):
    """The tribe key in the config (None if it has none)."""
    tribe = config.get("tribe")
    if not tribe:
        return None
    from ..ipam.client import TeamKey
    if unprotect is None:
        from ..terminal.credentials import unprotect
    data = {name: tribe[name] for name in ("server_id", "hosts", "port", "fingerprint")}
    data.update(secret=unprotect(tribe["secret"]), format=1, role=tribe.get("role", ""))
    return TeamKey.from_dict(data)


class DashboardService:
    """The engine and the web server, from the folder's config."""

    def __init__(self, directory=None, config=None, unprotect=None):
        from .accounts import Accounts
        from .engine import Engine
        from .web import DashboardServer
        self.directory = Path(directory or dashboard_dir())
        self.directory.mkdir(parents=True, exist_ok=True)
        config = config or load_config(self.directory)
        tls.ensure_certificate(self.directory)
        key = None
        try:
            key = key_from_config(config, unprotect)
        except Exception as error:  # Shown on the pages: no tribe until a viewer key is given again
            log.error("Couldn't read the tribe's viewer key: %s", error)

        def remember_moved(moved):  # The tribe server moved to another computer: keep its new address
            latest = load_config(self.directory)
            if latest.get("tribe"):
                latest["tribe"].update(hosts=list(moved.hosts), port=moved.port)
                save_config(latest, self.directory)

        self.engine = Engine(self.directory, key, config, on_moved=remember_moved)
        self.accounts = Accounts(self.directory, idle_hours=int(config.get("session_hours", 12)))
        self.server = DashboardServer(self.engine, self.accounts, tls.server_context(self.directory),
                                      int(config.get("port", DEFAULT_PORT)))
        self.thread = None
        self.stop_event = threading.Event()

    def start(self):
        self.engine.start()
        self.thread = threading.Thread(target=self.server.serve, name="Dashboard web", daemon=True)
        self.thread.start()

    def shutdown(self):
        self.server.stop()
        self.engine.stop()
        log.info("%s stopped", DISPLAY_NAME)

    def run(self):
        self.start()
        try:
            self.stop_event.wait()
        finally:
            self.shutdown()

    def stop(self):
        self.stop_event.set()


def log_to_file(directory=None):
    directory = Path(directory or dashboard_dir())
    directory.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(directory / "dashboard.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


# --------------------------------------------------------------------- The Windows service

def spec():
    from ..ipam.service import ServiceSpec
    return ServiceSpec(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION, SERVICE_ARGUMENT,
                       lambda: dashboard_dir() / "dashboard.log")


def _service_class():
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class DashboardWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, arguments):
            super().__init__(arguments)
            self.stopped = win32event.CreateEvent(None, 0, 0, None)
            self.service = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.stopped)

        def SvcDoRun(self):
            log_to_file()
            try:
                self.service = DashboardService()
                self.service.start()
            except Exception as error:  # Port in use, no certificate...: say why in the log and Event Viewer
                log.exception("The NOMAD Dashboard couldn't start")
                servicemanager.LogErrorMsg(f"{DISPLAY_NAME} couldn't start: {error}")
                return
            win32event.WaitForSingleObject(self.stopped, win32event.INFINITE)
            self.service.shutdown()

    return DashboardWindowsService


def run_service_dispatcher():
    """Hand this process to Windows' service manager (NOMAD.exe --dashboard-service, started by Windows)."""
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def install(config):
    """Install (or update) and start the service with this config (needs administrator rights)."""
    from ..ipam import service
    directory = dashboard_dir()
    service.secure_service_folder(directory)
    save_config(config, directory)
    tls.ensure_certificate(directory)
    service.register(spec())
    service.open_firewall(int(config["port"]), FIREWALL_RULE, "TCP")
    service.start(spec())


def restart():
    """Stop and start it again (after its logins' file or certificate changed it needs no restart; its port does)."""
    from ..ipam import service
    if service.status(spec()) in (service.RUNNING, service.STARTING):
        service.stop(spec(), force=True)
    service.start(spec())


def uninstall():
    """Stop and remove the service and its firewall rule. Its folder (logins, history) is kept."""
    from ..ipam import service
    service.remove(spec())
    service.close_firewall(FIREWALL_RULE)


def status():
    from ..ipam import service
    return service.status(spec())


def running():
    try:
        from ..ipam import service
        return service.status(spec()) == service.RUNNING
    except Exception:
        return False


def run_in_foreground(directory=None):
    """Run the dashboard in this console until Ctrl+C (NOMAD.exe --dashboard), for trying it out."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    dashboard = DashboardService(directory)
    thread = threading.Thread(target=dashboard.run, daemon=True)
    thread.start()
    print(f"NOMAD Dashboard on https://localhost:{dashboard.server.port}/ - press Ctrl+C to stop.")
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        dashboard.stop()
        thread.join(30)
