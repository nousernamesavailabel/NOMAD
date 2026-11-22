"""NOMAD's five Windows services in one list, for Tools > Services & Firewall (ui/services_dialog.py).

Each service keeps its own module and setup dialog; this only says, for each one, how to tell its state, which
firewall rules it opens on which ports, where its folder is, how to start, stop and remove it, whether it can be
installed without questions (with its usual settings, or the ones it was installed with before), and how to update
an installed one to this NOMAD with the settings it has (no window: update()).

They're listed in the order they're best installed: the Tribe Server first (the Map Watcher needs a tribe), the
Syslog Collector before the Map Watcher (so it has UDP 514 when the Map Watcher starts, and the Map Watcher reads
syslog from it), then the Map Watcher, and the NOMAD Dashboard last (it reads all of them).
"""
import json
from dataclasses import dataclass
from pathlib import Path

from .firewall import TCP, UDP


@dataclass(frozen=True)
class ServiceEntry:
    key: str
    title: str
    purpose: str
    spec: object  # () -> ipam.service.ServiceSpec
    folder: object  # () -> Path
    firewall: object  # () -> {rule name: (port or None if it can't be read, protocols)}
    uninstall: object  # () -> None
    install_quietly: object = None  # () -> None, or None: it's set up in its own dialog
    dialog: str = ""  # The main window's method that opens its dialog
    update_quietly: object = None  # () -> None: run this NOMAD with the settings it has (install_quietly if None)

    def update(self):
        """Point the installed service at this NOMAD and start it again, keeping its settings (administrator)."""
        (self.update_quietly or self.install_quietly)()


def _module(name):
    import importlib
    return importlib.import_module(f"nomad.{name}")


def read_config(folder, default):
    """A service's config.json, or default if it has none yet, or None if it can't be read (only administrators
    may read the services' folders)."""
    path = Path(folder) / "config.json"
    try:
        return {**default, **json.loads(path.read_text(encoding="utf-8"))}
    except FileNotFoundError:
        return dict(default)
    except (OSError, ValueError):
        return None


# --------------------------------------------------------------------- Tribe (IPAM) Server

def _tribe_spec():
    return _module("ipam.service").IPAM


def _tribe_folder():
    return _module("ipam.server").server_dir()


def _tribe_firewall():
    server = _module("ipam.server")
    config = read_config(server.server_dir(), {"port": server.DEFAULT_PORT})
    return {"NOMAD IPAM Server": (config["port"] if config else None, (TCP,))}


def _tribe_uninstall():
    _module("ipam.service").uninstall()


def _tribe_update():
    _module("ipam.service").install()  # No port: the one it has


# --------------------------------------------------------------------- Syslog Collector

def _syslog():
    return _module("syslogs.service")


def _syslog_firewall():
    module = _syslog()
    config = read_config(module.collector_dir(), module.default_config())
    if config is None:
        return {module.FIREWALL_RULE: (None, (UDP,))}
    return {module.FIREWALL_RULE: (config["port"], (UDP, TCP) if config.get("tcp") else (UDP,))}


def _syslog_install():
    module = _syslog()
    module.install(module.load_config())


# --------------------------------------------------------------------- Flow Collector

def _flows():
    return _module("flows.service")


def _flows_firewall():
    module = _flows()
    config = read_config(module.collector_dir(), module.default_config())
    return {module.FIREWALL_RULE: (config["port"] if config else None, (UDP,))}


def _flows_install():
    module = _flows()
    module.install(module.load_config())


# --------------------------------------------------------------------- Map Watcher

def _watcher():
    return _module("netmap.watch_service")


def _watcher_firewall():
    return {rule: (port, (UDP,)) for rule, port in _watcher().FIREWALL_RULES.items()}


def _watcher_update():
    module = _watcher()
    module.install(module.load_config())  # Its maps, copies and logins as they are


# --------------------------------------------------------------------- NOMAD Dashboard

def _dashboard():
    return _module("dashboard.service")


def _dashboard_firewall():
    module = _dashboard()
    config = read_config(module.dashboard_dir(), module.default_config())
    return {module.FIREWALL_RULE: (config["port"] if config else None, (TCP,))}


def _dashboard_update():
    module = _dashboard()
    module.install(module.load_config())


SERVICES = [
    ServiceEntry("tribe", "Tribe Server",
                 "Shares the tribe's IP addresses and network maps with NOMAD on every laptop. Install it on one "
                 "computer that's always on.",
                 _tribe_spec, _tribe_folder, _tribe_firewall, _tribe_uninstall, dialog="show_tribe_management",
                 update_quietly=_tribe_update),
    ServiceEntry("syslog", "Syslog Collector",
                 "Keeps every syslog message devices send to this computer, for everyone using NOMAD on it.",
                 lambda: _syslog().spec(), lambda: _syslog().collector_dir(), _syslog_firewall,
                 lambda: _syslog().uninstall(), _syslog_install, "show_syslog_collector"),
    ServiceEntry("flows", "Flow Collector",
                 "Keeps the NetFlow and IPFIX routers send to this computer, for everyone using NOMAD on it.",
                 lambda: _flows().spec(), lambda: _flows().collector_dir(), _flows_firewall,
                 lambda: _flows().uninstall(), _flows_install, "show_flow_collector"),
    ServiceEntry("watcher", "Map Watcher",
                 "Watches the tribe's maps for new switches, access points and hosts, even when nobody has NOMAD "
                 "open. Needs a tribe.",
                 lambda: _watcher().spec(), lambda: _watcher().watcher_dir(), _watcher_firewall,
                 lambda: _watcher().uninstall(), dialog="show_map_watcher", update_quietly=_watcher_update),
    ServiceEntry("dashboard", "NOMAD Dashboard",
                 "A read-only web site showing the network's state to people without NOMAD. Install it on the "
                 "computer with the Map Watcher and the collectors.",
                 lambda: _dashboard().spec(), lambda: _dashboard().dashboard_dir(), _dashboard_firewall,
                 lambda: _dashboard().uninstall(), dialog="show_dashboard_service",
                 update_quietly=_dashboard_update),
]


def entry(key):
    return next(item for item in SERVICES if item.key == key)


def status(item):
    """NOT_INSTALLED, STOPPED, STARTING, RUNNING or STOPPING (ipam.service has them), or "Unknown (why)"."""
    try:
        return _module("ipam.service").status(item.spec())
    except Exception as error:  # pywin32 missing (running from an unusual setup)
        return f"Unknown ({error})"


def start(item):
    _module("ipam.service").start(item.spec())


def stop(item):
    _module("ipam.service").stop(item.spec())


def ports_text(item, fallback=None):
    """"TCP 8443", "UDP 514 and 162"...: the ports it opens, from its settings. fallback(rule name): the port to
    show when its settings can't be read (only administrators can read them), such as its firewall rule's."""
    parts = {}
    for name, (port, protocols) in item.firewall().items():
        if port is None:
            port = (fallback(name) if fallback else None) or "?"
        parts.setdefault(" and ".join(protocols), []).append(str(port))
    return ", ".join(f"{protocols} {' and '.join(ports)}" for protocols, ports in parts.items())
