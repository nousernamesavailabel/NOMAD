"""The NOMAD Syslog Collector service: one syslog server per computer, running whether anyone is signed in or not.

Devices send syslog to one address and port, and only one program can listen on that port, so on a server several
people use over Remote Desktop, NOMAD in each session can't listen for itself. The service keeps every message for
everyone (90 days by default, within a size limit), and NOMAD in each session reads it over 127.0.0.1 (api.py). The
Map Watcher (the service, or NOMAD watching a map) reads it too instead of listening on the port.

Its folder (%ProgramData%\\NOMAD\\syslog, readable by Administrators, SYSTEM and the service) holds config.json (the
port, TCP or not, how long to keep messages and the most space they may take), syslog.db and its log. Tools > Syslog
Collector Service in NOMAD sets it up.
"""
import json
import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path

from ..syslog import SYSLOG_PORT
from .api import API_PORT, SyslogApi
from .collector import SyslogCollector
from .store import KEEP_DAYS, MAX_BYTES, SyslogQueries

log = logging.getLogger(__name__)

SERVICE_NAME = "NOMADSyslogCollector"
DISPLAY_NAME = "NOMAD Syslog Collector"
DESCRIPTION = ("Keeps the syslog messages switches, routers, firewalls and access points send, so everyone using "
               "NOMAD on this computer sees the same messages.")
SERVICE_ARGUMENT = "--syslog-collector-service"
FIREWALL_RULE = "NOMAD Syslog Collector"
GB = 1024 ** 3


def collector_dir():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "syslog"


def default_config():
    return make_config()


def make_config(port=SYSLOG_PORT, tcp=False, keep_days=KEEP_DAYS, max_gb=MAX_BYTES / GB, api_port=API_PORT):
    return {"port": int(port), "tcp": bool(tcp), "api_port": int(api_port), "keep_days": int(keep_days),
            "max_gb": float(max_gb)}


def load_config(directory=None):
    path = Path(directory or collector_dir()) / "config.json"
    config = default_config()
    try:
        config.update(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return config


def save_config(config, directory=None):
    directory = Path(directory or collector_dir())
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "config.json.tmp"
    temporary.write_text(json.dumps(config, indent=2), encoding="utf-8")
    temporary.replace(directory / "config.json")


class CollectorEngine:
    """The collector and the API answering from its store."""

    def __init__(self, directory=None, config=None):
        directory = Path(directory or collector_dir())
        directory.mkdir(parents=True, exist_ok=True)
        config = config or load_config(directory)
        self.collector = SyslogCollector(directory / "syslog.db", int(config["port"]), tcp=bool(config["tcp"]),
                                         keep_days=int(config["keep_days"]),
                                         max_bytes=int(float(config["max_gb"]) * GB))
        self.api_port = int(config.get("api_port", API_PORT))
        self.api = None
        self.queries = None
        self.stop_event = threading.Event()

    def start(self):
        self.collector.start()
        self.queries = SyslogQueries(self.collector.path)
        try:
            self.api = SyslogApi(self.queries, self.collector.status, self.api_port)
        except OSError:
            self.queries.close()
            self.collector.stop()
            raise
        self.api.start()
        log.info("%s answering NOMAD on 127.0.0.1:%s", DISPLAY_NAME, self.api.port)

    def run(self):
        try:
            self.start()
        except OSError as error:
            log.error("%s couldn't start: %s", DISPLAY_NAME, error)
            raise
        try:
            self.stop_event.wait()
        finally:
            self.shutdown()

    def shutdown(self):
        if self.api is not None:
            self.api.stop()
            self.api = None
        if self.queries is not None:
            self.queries.close()
            self.queries = None
        self.collector.stop()
        log.info("%s stopped", DISPLAY_NAME)

    def stop(self):
        self.stop_event.set()


def log_to_file(directory=None):
    directory = Path(directory or collector_dir())
    directory.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(directory / "collector.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


# --------------------------------------------------------------------- The Windows service


def spec():
    from ..ipam.service import ServiceSpec
    return ServiceSpec(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION, SERVICE_ARGUMENT,
                       lambda: collector_dir() / "collector.log")


def _service_class():
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class SyslogCollectorService(win32serviceutil.ServiceFramework):
        _svc_name_ = SERVICE_NAME
        _svc_display_name_ = DISPLAY_NAME
        _svc_description_ = DESCRIPTION

        def __init__(self, arguments):
            super().__init__(arguments)
            self.stopped = win32event.CreateEvent(None, 0, 0, None)
            self.engine = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            if self.engine is not None:
                self.engine.stop()
            win32event.SetEvent(self.stopped)

        def SvcDoRun(self):
            log_to_file()
            try:
                self.engine = CollectorEngine()
                self.engine.start()
            except Exception as error:  # Port in use, unreadable folder...: say why in the log and Event Viewer
                log.exception("The Syslog Collector couldn't start")
                servicemanager.LogErrorMsg(f"{DISPLAY_NAME} couldn't start: {error}")
                return
            win32event.WaitForSingleObject(self.stopped, win32event.INFINITE)
            self.engine.shutdown()

    return SyslogCollectorService


def run_service_dispatcher():
    """Hand this process to Windows' service manager (NOMAD.exe --syslog-collector-service, started by Windows)."""
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def install(config):
    """Install (or update) and start the service with this config (needs administrator rights).

    The Map Watcher service, if it's running here, listens on the syslog port itself: it's stopped while this one
    starts and started again after, when it reads syslog from this service instead."""
    from ..ipam import service
    from ..netmap.watch_service import spec as watcher_spec
    from ..system import allow_inbound_port
    directory = collector_dir()
    service.secure_service_folder(directory)
    save_config(config, directory)
    service.register(spec())  # Starts the other services sharing NOMAD.exe again, the Map Watcher among them
    watcher = watcher_spec()
    restart_watcher = service.status(watcher) in (service.RUNNING, service.STARTING)
    if restart_watcher:
        service.stop(watcher, force=True)
    allow_inbound_port(FIREWALL_RULE, config["port"], ("UDP", "TCP") if config.get("tcp") else ("UDP",))
    try:
        service.start(spec())
    finally:
        if restart_watcher:
            try:
                service.start(watcher)
            except Exception as error:  # Its own problem: this service is installed all the same
                log.warning("Couldn't start the Map Watcher service again: %s", error)


def uninstall():
    """Stop and remove the service and its firewall rule. The messages in its folder are kept. (A Map Watcher
    reading it goes back to listening on the port itself within a minute.)"""
    from ..ipam import service
    service.remove(spec())
    service.close_firewall(FIREWALL_RULE)


def status():
    from ..ipam import service
    return service.status(spec())


def running():
    """The service is running on this computer (False if that can't be told: pywin32 missing, not Windows)."""
    try:
        from ..ipam import service
        return service.status(spec()) == service.RUNNING
    except Exception:
        return False


def run_in_foreground(directory=None):
    """Run the collector in this console until Ctrl+C (NOMAD.exe --syslog-collector), for trying it out."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    engine = CollectorEngine(directory)
    thread = threading.Thread(target=engine.run, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        engine.stop()
        thread.join(30)
