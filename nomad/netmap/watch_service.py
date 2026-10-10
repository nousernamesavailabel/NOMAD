"""The NOMAD Map Watcher service: watching tribe maps for new devices and hosts from a computer that's usually on,
with nobody signed in.

It runs on a workstation that can reach the network's switches (the tribe server itself may not), keeps its own copy
of the tribe's maps, and claims the watching of the maps chosen for it from the tribe server, taking over from NOMAD
left open somewhere. What it finds is added to the tribe map, so everyone sees it, tagged NEW. Switches can send it
syslog and SNMP traps so a switch is read the moment something's plugged in.

Its folder (%ProgramData%\\NOMAD\\watcher, readable by Administrators, SYSTEM and the service) holds config.json
(the tribe key, with the secret encrypted for this computer, and the maps to watch), its copy of the maps and its
log. Tools > Map Watcher Service in NOMAD sets it up.
"""
import json
import logging
import logging.handlers
import os
import socket
import threading
import time
from pathlib import Path

from ..snmp import TRAP_PORT
from ..syslog import SYSLOG_PORT, SyslogReceiver
from . import triggers, watch
from .crawl import credentials_from_json, ordered_credentials

log = logging.getLogger(__name__)

SERVICE_NAME = "NOMADMapWatcher"
DISPLAY_NAME = "NOMAD Map Watcher"
DESCRIPTION = "Watches the tribe's network maps for new switches, access points and hosts, and adds them to the maps."
SERVICE_ARGUMENT = "--map-watcher-service"
FIREWALL_RULES = {"NOMAD Map Watcher syslog": SYSLOG_PORT, "NOMAD Map Watcher traps": TRAP_PORT}
SYNC_SECONDS = 30
LEASE_SECONDS = 60
STEP_SECONDS = 2
SERVICE_USER = "Map Watcher service"


def watcher_dir():
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "watcher"


def load_config(directory=None):
    path = Path(directory or watcher_dir()) / "config.json"
    return json.loads(path.read_text(encoding="utf-8"))


def save_config(config, directory=None):
    directory = Path(directory or watcher_dir())
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "config.json.tmp"
    temporary.write_text(json.dumps(config, indent=2), encoding="utf-8")
    temporary.replace(directory / "config.json")


def make_config(key, map_ids, listen=True, timers=None, protect=None):
    """The service's config from a tribe key (its secret encrypted for this computer). timers: {name: seconds}, as
    watch.TIMERS has them."""
    if protect is None:  # For this computer: the service runs as another account
        from ..terminal.credentials import protect as dpapi

        def protect(text):
            return dpapi(text, machine=True)
    return {"server_id": key.server_id, "hosts": list(key.hosts), "port": key.port, "fingerprint": key.fingerprint,
            "secret": protect(key.secret), "maps": [int(map_id) for map_id in map_ids], "listen": bool(listen),
            **watch.timer_values(timers)}


def config_timers(config):
    """The watch timers in a config (an older one has only the two intervals; the rest are the defaults)."""
    return watch.timer_values({name: config[name] for name in watch.TIMERS if name in config})


def key_from_config(config, unprotect=None):
    from ..ipam.client import TeamKey
    if unprotect is None:
        from ..terminal.credentials import unprotect
    data = {name: config[name] for name in ("server_id", "hosts", "port", "fingerprint")}
    data["secret"] = unprotect(config["secret"])
    data["format"] = 1
    return TeamKey.from_dict(data)


class WatchedMap:
    """What the service knows about one map it watches."""

    def __init__(self, map_id):
        self.map_id = map_id
        self.baseline = watch.NeighborBaseline()
        self.active = False  # Holding the lease (or the server can't be reached)
        self.holder_text = ""
        self.next_neighbors = 0.0
        self.next_hosts = 0.0
        self.next_recheck = 0.0
        self.started = False


class WatchEngine:
    """Watches the chosen tribe maps. step() does whatever's due; run() steps until stopped. Qt-free and driven by
    a clock, so it can be tested with fakes."""

    def __init__(self, maps, map_ids, holder, timers=None, crawl=watch.crawl_from, client_factory=None,
                 clock=time.time, listen=True, ports=(SYSLOG_PORT, TRAP_PORT)):
        """timers: {name: seconds}, as watch.TIMERS has them (the defaults for any left out)."""
        from ..snmp import SnmpClient
        self.maps, self.holder = maps, holder
        self.watched = {int(map_id): WatchedMap(int(map_id)) for map_id in map_ids}
        timers = watch.timer_values(timers)
        self.neighbor_interval, self.host_interval = timers["neighbor_interval"], timers["host_interval"]
        self.recheck_interval = timers["recheck_interval"]
        self.crawl, self.client_factory, self.clock = crawl, client_factory or SnmpClient, clock
        self.queue = triggers.TriggerQueue(delay=timers["trigger_delay"], clock=clock)
        self.listen, self.ports = listen, ports
        self.receivers = []
        self.v3_users = {}  # Map ID -> its V3Users, for checking v3 traps
        self.next_sync = self.next_lease = 0.0
        self.stop_event = threading.Event()
        self.by = f"{socket.gethostname()} ({DISPLAY_NAME})"

    # ----------------------------------------------------------------- Listening

    def start_listening(self):
        if not self.listen:
            return
        syslog_port, trap_port = self.ports
        syslog = SyslogReceiver(self.on_syslog, port=syslog_port)
        try:
            syslog.start()
            self.receivers.append(syslog)
            log.info("Listening for syslog on UDP %s", syslog_port)
        except OSError as error:
            log.warning("Couldn't listen for syslog on UDP %s: %s", syslog_port, error)
        traps = triggers.TrapReceiver(self.on_trap, port=trap_port, v3_users=self.all_v3_users)
        try:
            traps.start()
            self.receivers.append(traps)
            log.info("Listening for SNMP traps on UDP %s", trap_port)
        except OSError as error:
            log.warning("Couldn't listen for SNMP traps on UDP %s: %s", trap_port, error)

    def stop_listening(self):
        for receiver in self.receivers:
            receiver.stop()
        self.receivers = []

    def on_syslog(self, message):
        reason = triggers.syslog_reason(message.raw or message.message)
        if reason:
            self.queue.add(message.source, reason)

    def on_trap(self, trap, sender):
        reason = triggers.trap_reason(trap)
        if reason:
            self.queue.add(trap.agent or sender, reason)

    # ----------------------------------------------------------------- Each step

    def step(self):
        now = self.clock()
        if now >= self.next_sync:
            self.next_sync = now + SYNC_SECONDS
            self.sync()
        if now >= self.next_lease:
            self.next_lease = now + LEASE_SECONDS
            self.claim_all()
        due = self.queue.due()
        for watched in self.watched.values():
            if self.stop_event.is_set():
                return
            if watched.active:
                self.watch_map(watched, now, due)

    def sync(self):
        try:
            self.maps.sync()
        except Exception as error:  # Offline: carry on with the copy, and send what's found later
            log.info("Couldn't sync the tribe maps: %s", error)

    def claim_all(self):
        for watched in self.watched.values():
            if self.maps.map_info(watched.map_id) is None:
                watched.active = False
                continue
            try:
                lease = self.maps.lease(watched.map_id, self.holder, kind="service", take=True)
            except Exception as error:
                if not watched.active:
                    log.info("Tribe server not reachable (%s): watching map %s from here meanwhile", error,
                             watched.map_id)
                watched.active = True
                continue
            was = watched.active
            watched.active = bool(lease.get("yours"))
            if watched.active and not was:
                log.info("Watching %s", self.map_name(watched.map_id))
            elif not watched.active:
                holder = f"{lease.get('computer')} ({lease.get('kind')})"
                if holder != watched.holder_text:
                    log.info("%s is watched by %s", self.map_name(watched.map_id), holder)
                watched.holder_text = holder

    def all_v3_users(self):
        return list(dict.fromkeys(user for users in list(self.v3_users.values()) for user in users))

    def map_name(self, map_id):
        return (self.maps.map_info(map_id) or {}).get("name", f"map {map_id}")

    def options(self, map_id, settings):
        secrets = self.maps.secrets(map_id)
        if not secrets:
            try:
                secrets = self.maps.fetch_secrets(map_id)
            except Exception as error:
                log.info("Couldn't fetch the community strings of %s: %s", self.map_name(map_id), error)
        options = watch.WatchOptions()
        for name in ("scope", "version", "timeout", "max_hops", "max_devices", "workers"):
            if name in settings:
                setattr(options, name, settings[name])
        communities, overrides, v3_users, v3_first = credentials_from_json(secrets, options.communities)
        options.communities = ordered_credentials(communities, v3_users, v3_first)
        options.overrides = [list(item) for item in overrides]
        self.v3_users[map_id] = v3_users
        return options

    def watch_map(self, watched, now, due):
        network_map, settings = self.maps.load(watched.map_id)
        options = self.options(watched.map_id, settings)
        seeds = {}
        if not watched.started:
            watched.started = True
            watch.mark_hosts_seen(network_map)
            watched.next_neighbors, watched.next_hosts = now, now + self.host_interval
            watched.next_recheck = now
        for address, reasons in due:
            key = triggers.device_for_address(network_map, address)
            if key is not None and network_map.devices[key].source == "snmp":
                log.info("%s: %s", network_map.devices[key].label, ", ".join(reasons))
                seeds[network_map.devices[key].mgmt_ip or address] = True
        if now >= watched.next_neighbors:
            watched.next_neighbors = now + self.neighbor_interval
            targets = watch.switches(network_map)
            signatures, moved = watch.read_switches(
                targets, watch.fallback_addresses(network_map, targets, options.scope), options,
                self.client_factory, self.stop_event.is_set, options.workers)
            lines = watch.adopt_addresses(network_map, moved)
            for line in lines:
                log.info("%s: %s", self.map_name(watched.map_id), line)
            if lines:
                self.maps.save(watched.map_id, network_map, settings)
                self.send()
                targets = watch.switches(network_map)
            for key in watched.baseline.changed(network_map, signatures):
                log.info("%s: new CDP/LLDP neighbor", network_map.devices[key].label)
                seeds[targets[key]] = True
        if now >= watched.next_recheck:
            watched.next_recheck = now + self.recheck_interval
            targets = watch.unread_devices(network_map, options.scope)
            found = watch.recheck(targets, options, self.client_factory, self.stop_event.is_set, options.workers)
            for key, (address, check) in found.items():
                log.info("%s: %s answers SNMP now (%s): reading it", self.map_name(watched.map_id),
                         network_map.devices[key].label, watch.credential_text(check.community))
                seeds[address] = True
        if now >= watched.next_hosts:
            watched.next_hosts = now + self.host_interval
            seeds.update(dict.fromkeys(watch.switches(network_map).values(), True))
        if not seeds or self.stop_event.is_set():
            return
        crawled = self.crawl(network_map, options, list(seeds), should_stop=self.stop_event.is_set)
        if crawled.stopped:
            return
        # The map may have changed while the switches were read: add to the latest copy
        network_map, settings = self.maps.load(watched.map_id)
        result = watch.apply_refresh(network_map, crawled, by=self.by)
        for line in result.lines:
            log.info("%s: %s", self.map_name(watched.map_id), line)
        self.maps.save(watched.map_id, network_map, settings)
        self.send()

    def send(self):
        """Send what was saved to the tribe server (later, if it can't be reached now)."""
        try:
            self.maps.send_pending()
        except Exception as error:
            log.info("Couldn't send what was found yet: %s", error)

    def run(self):
        self.start_listening()
        log.info("%s watching %s", DISPLAY_NAME, ", ".join(str(map_id) for map_id in self.watched) or "no maps")
        try:
            while not self.stop_event.is_set():
                try:
                    self.step()
                except Exception:  # One bad step shouldn't stop the watching
                    log.exception("Watching failed this time round")
                self.stop_event.wait(STEP_SECONDS)
        finally:
            self.stop_listening()
            for map_id in self.watched:
                try:
                    self.maps.lease(map_id, self.holder, kind="service", release=True)
                except Exception:
                    pass
            log.info("%s stopped", DISPLAY_NAME)

    def stop(self):
        self.stop_event.set()


def make_engine(directory=None):
    """The engine as the service runs it, from its folder's config."""
    from ..ipam.client import TeamClient
    from ..terminal.credentials import protect, unprotect
    from .tribe import TribeMaps
    directory = Path(directory or watcher_dir())
    config = load_config(directory)
    key = key_from_config(config)

    def remember_moved(moved_key):  # The tribe server moved to another computer: keep its new address
        latest = load_config(directory)
        latest["hosts"], latest["port"] = list(moved_key.hosts), moved_key.port
        save_config(latest, directory)

    client = TeamClient(key, user=SERVICE_USER, on_moved=remember_moved)
    maps = TribeMaps(key.server_id, client, directory / "maps.db",
                     protect=lambda text: protect(text, machine=True), unprotect=unprotect)
    return WatchEngine(maps, config.get("maps", []), f"{socket.gethostname()}-service",
                       timers=config_timers(config), listen=config.get("listen", True))


def log_to_file(directory=None):
    directory = Path(directory or watcher_dir())
    directory.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(directory / "watcher.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


# --------------------------------------------------------------------- The Windows service

def spec():
    from ..ipam.service import ServiceSpec
    return ServiceSpec(SERVICE_NAME, DISPLAY_NAME, DESCRIPTION, SERVICE_ARGUMENT,
                       lambda: watcher_dir() / "watcher.log")


def _service_class():
    import servicemanager
    import win32event
    import win32service
    import win32serviceutil

    class MapWatcherService(win32serviceutil.ServiceFramework):
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
                self.engine = make_engine()
            except Exception as error:  # No config yet, unreadable key...: say why in the log and Event Viewer
                log.exception("The Map Watcher couldn't start")
                servicemanager.LogErrorMsg(f"{DISPLAY_NAME} couldn't start: {error}")
                return
            thread = threading.Thread(target=self.engine.run, name="Map Watcher", daemon=True)
            thread.start()
            win32event.WaitForSingleObject(self.stopped, win32event.INFINITE)
            thread.join(30)

    return MapWatcherService


def run_service_dispatcher():
    """Hand this process to Windows' service manager (NOMAD.exe --map-watcher-service, started by Windows)."""
    import servicemanager
    servicemanager.Initialize()
    servicemanager.PrepareToHostSingle(_service_class())
    servicemanager.StartServiceCtrlDispatcher()


def install(config):
    """Install (or update) and start the service with this config (needs administrator rights)."""
    from ..ipam import service
    directory = watcher_dir()
    directory.mkdir(parents=True, exist_ok=True)
    service.secure_folder(directory)
    save_config(config, directory)
    service.register(spec())
    for rule, port in FIREWALL_RULES.items():
        service.open_firewall(port, rule, "UDP")
    service.start(spec())


def uninstall():
    from ..ipam import service
    service.remove(spec())
    for rule in FIREWALL_RULES:
        service.close_firewall(rule)


def status():
    from ..ipam import service
    return service.status(spec())


def run_in_foreground(directory=None):
    """Run the watcher in this console until Ctrl+C (NOMAD.exe --map-watcher), for trying it out."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    engine = make_engine(directory)
    thread = threading.Thread(target=engine.run, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        engine.stop()
        thread.join(30)
