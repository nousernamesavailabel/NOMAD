"""The NOMAD Flow Collector service: one collector per computer, running whether anyone is signed in or not.

Routers send their flows to one address and port, and only one program can listen on that port, so on a server
several people use over Remote Desktop, NOMAD in each session can't collect for itself. The service collects for
everyone, and NOMAD in each session reads it over 127.0.0.1 (api.py).

Its folder (%ProgramData%\\NOMAD\\flows, readable by Administrators, SYSTEM and the service) holds config.json (the
ports and how long to keep flows), flows.db and its log. Tools > Flow Collector Service in NOMAD sets it up.
"""
import json
import logging
import logging.handlers
import os
import threading
import time
from pathlib import Path

from .api import API_PORT, FlowApi
from .collector import FLOW_PORT, FlowCollector
from .store import RAW_SECONDS, SUMMARY_DAYS, FlowQueries

log = logging.getLogger(__name__)

SERVICE_NAME = "NOMADFlowCollector"
DISPLAY_NAME = "NOMAD Flow Collector"
DESCRIPTION = ("Collects NetFlow and IPFIX from routers and switches for NOMAD, so everyone using NOMAD on this "
               "computer sees the same flows.")
SERVICE_ARGUMENT = "--flow-collector-service"
FIREWALL_RULE = "NOMAD Flow Collector"


def collector_dir():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "flows"


def default_config():
    return {"port": FLOW_PORT, "api_port": API_PORT, "raw_hours": RAW_SECONDS / 3600, "summary_days": SUMMARY_DAYS}


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


def make_config(port=FLOW_PORT, raw_hours=RAW_SECONDS / 3600, summary_days=SUMMARY_DAYS, api_port=API_PORT):
    return {"port": int(port), "api_port": int(api_port), "raw_hours": float(raw_hours),
            "summary_days": int(summary_days)}


class CollectorEngine:
    """The collector and the API answering from its store."""

    def __init__(self, directory=None, config=None):
        directory = Path(directory or collector_dir())
        config = config or load_config(directory)
        self.collector = FlowCollector(directory / "flows.db", int(config["port"]),
                                       raw_seconds=float(config["raw_hours"]) * 3600,
                                       summary_days=int(config["summary_days"]))
        self.api_port = int(config.get("api_port", API_PORT))
        self.api = None
        self.queries = None
        self.stop_event = threading.Event()

    def start(self):
        self.collector.start()
        self.queries = FlowQueries(self.collector.path)
        try:
            self.api = FlowApi(self.queries, self.collector.status, self.api_port)
        except OSError:
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

    class FlowCollectorService(win32serviceutil.ServiceFramework):
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
                log.exception("The Flow Collector couldn't start")
                servicemanager.LogErrorMsg(f"{DISPLAY_NAME} couldn't start: {error}")
                return
            win32event.WaitForSingleObject(self.stopped, win32event.INFINITE)
            self.engine.shutdown()

    return FlowCollectorService


def run_service_dispatcher():
    """Hand this process to Windows' service manager (NOMAD.exe --flow-collector-service, started by Windows)."""
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def install(config):
    """Install (or update) and start the service with this config (needs administrator rights)."""
    from ..ipam import service
    directory = collector_dir()
    service.secure_service_folder(directory)
    save_config(config, directory)
    service.register(spec())
    service.open_firewall(config["port"], FIREWALL_RULE, "UDP")
    service.start(spec())


def uninstall():
    """Stop and remove the service and its firewall rule. The flows in its folder are kept."""
    from ..ipam import service
    service.remove(spec())
    service.close_firewall(FIREWALL_RULE)


def status():
    from ..ipam import service
    return service.status(spec())


def run_in_foreground(directory=None):
    """Run the collector in this console until Ctrl+C (NOMAD.exe --flow-collector), for trying it out."""
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
