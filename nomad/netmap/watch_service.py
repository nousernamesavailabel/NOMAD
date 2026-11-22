"""The NOMAD Map Watcher service: watching tribe maps for new devices and hosts from a computer that's usually on,
with nobody signed in.

It runs on a workstation that can reach the network's switches (the tribe server itself may not), keeps its own copy
of the tribe's maps, and claims the watching of the maps chosen for it from the tribe server, taking over from NOMAD
left open somewhere. What it finds is added to the tribe map, so everyone sees it, tagged NEW. Switches can send it
syslog and SNMP traps so a switch is read the moment something's plugged in.

It also monitors the maps it watches for the NOMAD Dashboard (watch_monitor.py): it pings their devices (or reads
their IP SLA probes), reads the traffic on their links and graphed ports, and sweeps their IPAM subnets on a schedule,
keeping what it finds in status.db in its folder. Each map's monitoring (statuses and uptime, nothing secret) is
shared for NOMAD's own map: in %ProgramData%\\NOMAD\\monitoring for anyone on this computer, and through the tribe
(API 18) for everyone else.

It can monitor maps on this computer that aren't shared with the tribe too (watch_local.py), and then runs without a
tribe at all if it has no tribe maps.

It can also run the tribe's scheduled config backups (nomad/configs/runner.py): devices due are handed to it first,
and it logs in with the one login chosen for it (copied into its config, its password encrypted for this computer:
the service has no saved sessions of its own).

Its folder (%ProgramData%\\NOMAD\\watcher, readable by Administrators, SYSTEM and the service) holds config.json
(the tribe key, with the secret encrypted for this computer, the maps to watch, and the backup login), its copy of the
maps and its log. Tools > Map Watcher Service in NOMAD sets it up.
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
from ..syslogs.feed import SyslogListener
from ..syslogs.service import DISPLAY_NAME as SYSLOG_SERVICE_NAME
from . import monitor_record, triggers, watch, watch_local, watch_monitor
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
BACKUP_SECONDS = 30
SYSLOG_CHECK_SECONDS = 60  # Checking whether the Syslog Collector service has been installed or removed here
MONITORING_SEND_SECONDS = 60  # A map's monitoring goes to the tribe at most this often
MONITORING_RETRY_SECONDS = 3600  # After a tribe server too old to take it


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


def make_config(key, map_ids, listen=True, timers=None, protect=None, backups=None, monitoring=None, local_maps=None):
    """The service's config from a tribe key (its secret encrypted for this computer; None for a watcher of local
    maps only, with no tribe). local_maps: the config's watch_local entries, kept. timers: {name: seconds}, as
    watch.TIMERS has them. monitoring: watch_monitor.MONITOR_DEFAULTS' settings (the defaults for any left out).
    backups: None (no scheduled config backups), or {"username", "password", "enable", "label", "trust_new",
    "credential_id", "devices": {device id: credential id}, "logins": {credential id: {"username", "password",
    "label"}}} with the passwords as typed (they're encrypted here); or {"keep": the config's backups as they are,
    "enable", "trust_new"} when the logins haven't changed (nothing to read from the master password)."""
    if protect is None:  # For this computer: the service runs as another account
        from ..terminal.credentials import protect as dpapi

        def protect(text):
            return dpapi(text, machine=True)
    config = {"maps": [int(map_id) for map_id in map_ids] if key is not None else [], "listen": bool(listen),
              **watch.timer_values(timers), "monitor": watch_monitor.monitor_settings({"monitor": monitoring})}
    if key is not None:
        config.update(server_id=key.server_id, hosts=list(key.hosts), port=key.port, fingerprint=key.fingerprint,
                      secret=protect(key.secret))
    if local_maps:
        config["local_maps"] = [dict(entry) for entry in local_maps]
    if backups and key is not None:
        config["backups"] = protect_backups(backups, protect)
    return config


def protect_backups(backups, protect):
    """The config's backups from make_config's backups (its passwords encrypted with protect)."""
    if "keep" in backups:
        kept = dict(backups["keep"])
        kept["enable"] = protect(backups["enable"]) if backups.get("enable") else ""
        kept["trust_new"] = bool(backups.get("trust_new", kept.get("trust_new", True)))
        return kept
    logins = {credential_id: {"username": login["username"], "label": login.get("label", ""),
                              "password": protect(login["password"]) if login.get("password") else ""}
              for credential_id, login in (backups.get("logins") or {}).items()}
    return {"username": backups["username"], "label": backups.get("label", ""),
            "password": protect(backups["password"]) if backups.get("password") else "",
            "enable": protect(backups["enable"]) if backups.get("enable") else "",
            "trust_new": bool(backups.get("trust_new", True)), "credential_id": backups.get("credential_id", ""),
            "devices": {device: credential_id for device, credential_id in (backups.get("devices") or {}).items()
                        if credential_id in logins},
            "logins": logins}


def config_timers(config):
    """The watch timers in a config (an older one has only the two intervals; the rest are the defaults)."""
    return watch.timer_values({name: config[name] for name in watch.TIMERS if name in config})


def has_tribe(config):
    return bool(config.get("secret") and config.get("server_id"))


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
                 clock=time.time, listen=True, ports=(SYSLOG_PORT, TRAP_PORT), backups=None, syslog_options=None):
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
        self.syslog = None  # A syslogs.feed.SyslogListener while listening
        self.syslog_options = syslog_options or {}  # For the SyslogListener (tests)
        self.next_syslog_check = 0.0
        self.syslog_problem = ""
        self.v3_users = {}  # Map ID -> its V3Users, for checking v3 traps
        self.next_sync = self.next_lease = self.next_backup = 0.0
        self.stop_event = threading.Event()
        self.by = f"{socket.gethostname()} ({DISPLAY_NAME})"
        self.backups = backups  # A configs.runner.BackupRunner, when it runs the tribe's config backups
        self.monitoring = None  # A watch_monitor.MonitorRunner, when it monitors the maps for the NOMAD Dashboard
        self.sweeps = None  # A watch_monitor.SweepRunner, when it sweeps their IPAM subnets
        self.server_id = ""  # The tribe's (for naming the monitoring shared on this computer)
        self.shared_dir = None  # Where it's shared (None: monitor_record.shared_dir())
        self.summaries = {}  # Tribe map ID -> its monitoring summary not sent yet
        self.summaries_lock = threading.Lock()
        self.next_summaries = 0.0
        self.monitoring_refused_until = 0.0

    # ----------------------------------------------------------------- Listening

    def start_listening(self):
        if not self.listen:
            return
        syslog_port, trap_port = self.ports
        self.syslog = self.syslog_listener(syslog_port)
        try:
            self.said_syslog(self.syslog.start())
        except OSError as error:
            self.syslog_problem = str(error)
            log.warning("Couldn't listen for syslog on UDP %s: %s", syslog_port, error)
        traps = triggers.TrapReceiver(self.on_trap, port=trap_port, v3_users=self.all_v3_users)
        try:
            traps.start()
            self.receivers.append(traps)
            log.info("Listening for SNMP traps on UDP %s", trap_port)
        except OSError as error:
            log.warning("Couldn't listen for SNMP traps on UDP %s: %s", trap_port, error)

    def syslog_listener(self, port):
        """Syslog from the NOMAD Syslog Collector service when it runs here (it has the port), else from the port."""
        receiver = SyslogReceiver(self.on_syslog, port=port)
        return SyslogListener(self.on_syslog, receiver.start, receiver.stop, **self.syslog_options)

    def check_syslog(self):
        """Move to the Syslog Collector service when it's been installed here, or back to the port without it."""
        if self.syslog is None:
            return
        try:
            self.said_syslog(self.syslog.check())
        except OSError as error:
            if str(error) != self.syslog_problem:  # Once, not every minute
                log.warning("Couldn't listen for syslog on UDP %s: %s", self.ports[0], error)
            self.syslog_problem = str(error)

    def said_syslog(self, mode):
        if mode:
            self.syslog_problem = ""
        if mode == SyslogListener.SERVICE:
            log.info("Reading syslog from the %s", SYSLOG_SERVICE_NAME)
        elif mode == SyslogListener.PORT:
            log.info("Listening for syslog on UDP %s", self.ports[0])

    def stop_listening(self):
        if self.syslog is not None:
            self.syslog.stop()
            self.syslog = None
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
        if self.syslog is not None and now >= self.next_syslog_check:
            self.next_syslog_check = now + SYSLOG_CHECK_SECONDS
            self.check_syslog()
        if self.backups is not None and now >= self.next_backup:
            self.next_backup = now + BACKUP_SECONDS
            self.back_up()
        if self.summaries and now >= self.next_summaries and now >= self.monitoring_refused_until:
            self.next_summaries = now + MONITORING_SEND_SECONDS
            self.send_summaries()
        due = self.queue.due()
        for watched in self.watched.values():
            if self.stop_event.is_set():
                return
            if watched.active:
                self.watch_map(watched, now, due)

    def back_up(self):
        """The tribe's config backups that are due (a few each time)."""
        try:
            for done in self.backups.step():
                if done.ok:
                    log.info("Backed up %s: %s", done.name, done.note)
                else:
                    log.info("Couldn't back up %s: %s", done.name, done.note)
        except Exception as error:  # Offline, or an old server: try again next time
            log.info("Config backups: %s", error)

    def share_summary(self, map_id, summary):
        """A map's monitoring summary (from the monitoring's thread): written for anyone on this computer at once,
        and sent to the tribe on the next step for a tribe map."""
        tribe = map_id >= 0
        if tribe:
            name = monitor_record.record_name(server_id=self.server_id, map_id=map_id)
        else:
            info = self.maps.map_info(map_id) or {}
            name = monitor_record.record_name(record_id=info.get("record_id", ""))
        try:
            monitor_record.write_shared(name, summary, self.shared_dir)
        except OSError as error:
            log.info("Couldn't share the monitoring on this computer: %s", error)
        if tribe:
            with self.summaries_lock:
                self.summaries[map_id] = summary

    def send_summaries(self):
        from ..ipam.client import OldServerError
        with self.summaries_lock:
            summaries, self.summaries = self.summaries, {}
        for map_id, summary in summaries.items():
            try:
                self.maps.send_monitoring(map_id, summary)
            except OldServerError:  # A server before API 18: try again in an hour (it may be updated by then)
                log.info("The tribe server is too old to share the monitoring with every NOMAD (update it)")
                self.monitoring_refused_until = self.clock() + MONITORING_RETRY_SECONDS
                return
            except Exception as error:  # Offline: the next one goes when it's back
                log.info("Couldn't send the monitoring of %s: %s", self.map_name(map_id), error)
                return

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
        if not secrets and map_id >= 0:
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
                self.client_factory, self.stop_event.is_set, options.workers, watch.controllers(network_map))
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
        log.info("%s watching %s", DISPLAY_NAME, ", ".join(str(map_id) for map_id in self.watched) or "no tribe maps")
        for runner in (self.monitoring, self.sweeps):
            if runner is not None:
                runner.start()
        try:
            while not self.stop_event.is_set():
                try:
                    self.step()
                except Exception:  # One bad step shouldn't stop the watching
                    log.exception("Watching failed this time round")
                self.stop_event.wait(STEP_SECONDS)
        finally:
            self.stop_listening()
            for runner in (self.monitoring, self.sweeps):
                if runner is not None:
                    runner.stop()
            for map_id in self.watched:
                try:
                    self.maps.lease(map_id, self.holder, kind="service", release=True)
                except Exception:
                    pass
            log.info("%s stopped", DISPLAY_NAME)

    def stop(self):
        self.stop_event.set()


def _moved_server_key(key, server_directory=None):
    """The new server's key, when `key` is the admin key of this computer's tribe server and that server has been
    moved to another computer (the admin key only works on the server itself); else None."""
    from ..ipam.client import moved_server_key
    from ..ipam.server import load_config as load_server_config
    try:
        admin_secret = load_server_config(server_directory).get("admin_secret")
    except (OSError, ValueError):
        return None
    moved = moved_server_key(server_directory)
    if moved is None or moved.server_id != key.server_id or key.secret != admin_secret:
        return None
    return moved


def make_engine(directory=None):
    """The engine as the service runs it, from its folder's config."""
    from ..ipam.client import TeamClient
    from ..terminal.credentials import protect, unprotect
    from .tribe import TribeMaps
    directory = Path(directory or watcher_dir())
    config = load_config(directory)
    local = watch_local.LocalMaps(directory, config)
    if not has_tribe(config):  # Only maps on this computer: no tribe to sync with
        engine = WatchEngine(watch_local.CombinedMaps(None, local), [], f"{socket.gethostname()}-service",
                             timers=config_timers(config), listen=False)
        add_monitoring(engine, config, None, None, directory, local)
        return engine
    key = key_from_config(config)
    moved = _moved_server_key(key)
    if moved is not None:  # Installed on the tribe server with its admin key, and the server has moved away since
        log.info("The tribe server on this computer moved to %s: watching through it", ", ".join(moved.hosts))
        config.update(hosts=list(moved.hosts), port=moved.port, secret=protect(moved.secret, machine=True))
        save_config(config, directory)
        key = moved

    def remember_moved(moved_key):  # The tribe server moved to another computer: keep its new address
        latest = load_config(directory)
        latest["hosts"], latest["port"] = list(moved_key.hosts), moved_key.port
        save_config(latest, directory)

    client = TeamClient(key, user=SERVICE_USER, on_moved=remember_moved)
    maps = TribeMaps(key.server_id, client, directory / "maps.db",
                     protect=lambda text: protect(text, machine=True), unprotect=unprotect)
    engine = WatchEngine(watch_local.CombinedMaps(maps, local), config.get("maps", []),
                         f"{socket.gethostname()}-service", timers=config_timers(config),
                         listen=config.get("listen", True), backups=backup_runner(config, client, directory))
    engine.server_id = key.server_id
    add_monitoring(engine, config, key, client, directory, local)
    return engine


def add_monitoring(engine, config, key, client, directory, local=None):
    """Give the engine its monitoring and scheduled sweeps for the NOMAD Dashboard (and NOMAD's maps), unless they're
    turned off. The maps on this computer (local) are monitored too, but not swept: they have no tribe IPAM."""
    settings = watch_monitor.monitor_settings(config)
    local_ids = local.ids() if local is not None else []
    monitored = settings["enabled"] and (engine.watched or local_ids)
    names = set()
    if monitored:
        names = {monitor_record.record_name(server_id=engine.server_id, map_id=map_id) for map_id in engine.watched}
        names |= {monitor_record.record_name(record_id=(local.map_info(map_id) or {}).get("record_id", ""))
                  for map_id in local_ids}
    try:
        monitor_record.remove_shared_except(names, engine.shared_dir)
    except OSError:
        pass
    if not monitored:
        return
    from ..dashboard.history import HISTORY_FILE
    from ..dashboard.service import dashboard_dir
    store = watch_monitor.MonitorStore(Path(directory) / watch_monitor.STATUS_FILE)
    engine.monitoring = watch_monitor.MonitorRunner(engine.maps, list(engine.watched) + local_ids, store,
                                                    engine.options, settings, on_summary=engine.share_summary,
                                                    source=f"the Map Watcher on {socket.gethostname()}",
                                                    older_history=dashboard_dir() / HISTORY_FILE)
    if settings["sweep_hours"] > 0 and key is not None and engine.watched:
        from ..ipam.client import TeamStore
        engine.sweeps = watch_monitor.SweepRunner(
            engine.maps, list(engine.watched), settings=settings, store=store,
            team_factory=lambda: TeamStore(key, Path(directory) / "ipam-copy.db", client))


def backup_runner(config, client, directory, unprotect=None):
    """The runner for the tribe's scheduled config backups, from the config's backup login (None without one)."""
    settings = config.get("backups")
    if not settings or not settings.get("username"):
        return None
    from ..configs import archive, runner
    from ..configs.logins import DeviceLogins
    from ..configs.tribe import TribeConfigs
    from ..terminal.hostkeys import KnownHosts
    from ..terminal.sessions import Session
    from . import configpush, macssh
    if unprotect is None:
        from ..terminal.credentials import unprotect
    enable = unprotect(settings["enable"]) if settings.get("enable") else ""
    fallback = Session("", username=settings["username"], saved_password=settings.get("password", ""))
    label = settings.get("label") or f"user {settings['username']}"
    configs = TribeConfigs(config["server_id"], client, Path(directory) / "configs.db")
    known_hosts = KnownHosts(str(Path(directory) / "known_hosts"))
    computer = socket.gethostname()

    own = service_device_logins(settings)

    def make_pusher():
        logins = DeviceLogins(macssh.SshLogins([], fallback, None, label), own)
        return configpush.Pusher(logins, None, known_hosts, bool(settings.get("trust_new", True)), enable)
    return runner.BackupRunner(configs, make_pusher, f"{computer}-service", computer, SERVICE_USER, archive.SERVICE)


def service_device_logins(settings):
    """own(device id) -> (Session, label) or None, from the config's backups' device logins (the Device Logins
    the Editor's Backups tab sets, copied in by the Map Watcher's window)."""
    from ..terminal.sessions import Session
    devices, logins = settings.get("devices") or {}, settings.get("logins") or {}

    def own(device_id):
        login = logins.get(devices.get(device_id, ""))
        if not login or not login.get("username"):
            return None
        session = Session("", username=login["username"], saved_password=login.get("password", ""))
        return session, login.get("label") or f"user {login['username']}"
    return own


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


def install(config, copies=()):
    """Install (or update) and start the service with this config (needs administrator rights). copies: maps on this
    computer to copy in for it to monitor ([(NetworkMap, name, path, SNMP credentials JSON)], see watch_local); copies
    of maps no longer in the config go."""
    from ..ipam import service
    from ..terminal.credentials import protect
    directory = watcher_dir()
    service.secure_service_folder(directory)
    service.secure_shared_folder(monitor_record.shared_dir())
    for network_map, name, path, secrets in copies:
        watch_local.add(config, directory, network_map, name, path, secrets,
                        lambda text: protect(text, machine=True))
    watch_local.remove_others(config, directory)
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
