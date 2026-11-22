"""While monitoring: after each ping poll, read the counters of the map's linked ports (and those ticked to graph) on
a background thread, for the Utilization and Errors overlay and the Traffic Graphs page (each reading is kept in this
computer's traffic history, traffic_history.own_store), and the status of the routers' tunnels (their interfaces and
IKE sessions), for the tunnels drawn on the map."""
import logging
import time

from PyQt5.QtCore import QObject, QThread, pyqtSignal

from ..netmap import counters, traffic_history, tunnels
from ..netmap.model import port_key
from ..snmp import SnmpClient
from .common import release_thread

log = logging.getLogger(__name__)


class CounterThread(QThread):
    # counters.poll's {device key: (interface index, {port key: Sample})}, tunnels.poll's {device key: (interface
    # index, reading)}
    finished_poll = pyqtSignal(object, object)

    def __init__(self, targets, indexes, client_factory, tunnel_targets=(), parent=None):
        super().__init__(parent)
        self.targets, self.indexes, self.client_factory = targets, indexes, client_factory
        self.tunnel_targets = list(tunnel_targets)

    def run(self):
        found = counters.poll(self.targets, self.indexes, self.client_factory)
        indexes = dict(self.indexes, **{key: index for key, (index, _) in found.items()})
        self.finished_poll.emit(found, tunnels.poll(self.tunnel_targets, indexes, self.client_factory,
                                                    counters.interface_index))


class LinkCounters(QObject):
    """The rates of the map's linked ports (page: the Network Map page, for the map and how to ask its devices)."""
    updated = pyqtSignal()  # After a poll's counters are in

    def __init__(self, page):
        super().__init__(page)
        self.page = page
        self.client_factory = SnmpClient  # Tests swap in the fake network's
        self.tracker = counters.CounterTracker()
        self.indexes = {}  # Device key -> {port key: ifIndex}, read once per device
        self.thread = None
        self.network_map = None  # The map the counters are of
        self.live = {}  # Device key -> tunnels.read_live's reading of its tunnels, from the last poll
        self.port_names = {}  # (device key, port key) -> the port's name on the map, as last polled
        self.recorded = {}  # (device key, port key) -> the Rate kept last (each is kept once)

    @property
    def rates(self):
        return self.tracker.rates

    def reset(self):
        """Forget what was measured (monitoring stopped, or another map)."""
        self.tracker.clear()
        self.indexes = {}
        self.live = {}
        self.recorded = {}

    def poll_now(self):
        page = self.page
        network_map = page.network_map
        if self.thread is not None or network_map is None or page.worker is not None:
            return
        if network_map is not self.network_map:
            self.reset()
            self.network_map = network_map
        targets = []
        wanted = counters.graph_ports(network_map)
        self.port_names = {(key, port_key(port)): port for key, ports in wanted.items() for port in ports}
        for key, ports in wanted.items():
            address = network_map.devices[key].mgmt_ip
            credential, version = page.snmp_access(address)
            if credential is not None:
                targets.append((key, address, credential, version, page.timeout, ports))
        tunnel_targets = []
        for key, ports in tunnels.tunnel_routers(network_map).items():
            address = network_map.devices[key].mgmt_ip
            credential, version = page.snmp_access(address)
            if credential is not None:
                tunnel_targets.append((key, address, credential, version, page.timeout, ports))
        self.tracker.forget_others(set(network_map.devices))
        self.live = {key: reading for key, reading in self.live.items() if key in network_map.devices}
        if not targets and not tunnel_targets:
            return
        self.thread = CounterThread(targets, dict(self.indexes), self.client_factory, tunnel_targets, self)
        self.thread.finished_poll.connect(self.on_results)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()

    def on_thread_finished(self):
        self.thread = None

    def on_results(self, results, tunnel_results):
        if self.page.network_map is not self.network_map or not self.page.monitor.running:
            return  # Another map, or monitoring stopped meanwhile
        for key, (index, samples) in results.items():
            self.indexes[key] = index
            self.tracker.update(key, samples)
        for key, (index, reading) in tunnel_results.items():
            self.indexes[key] = index
            self.live[key] = reading
        self.record()
        self.updated.emit()

    def record(self):
        """Keep the rates that are new since the last poll in this computer's traffic history, under the map's
        record (the Traffic Graphs page draws them)."""
        name = getattr(self.page, "record_shown", None)
        store = traffic_history.own_store() if name else None
        if store is None:
            return
        now = time.time()
        rows = []
        for where, rate in self.tracker.rates.items():
            if self.recorded.get(where) is rate or where not in self.port_names:
                continue
            self.recorded[where] = rate
            rows.append({"device": where[0], "port": self.port_names[where], "at": now, "in_bps": rate.in_bps,
                         "out_bps": rate.out_bps, "speed": rate.speed})
        try:
            store.add(name, rows)
            store.prune()
        except Exception as error:  # The overlay still works: the history just misses this poll
            log.warning("Couldn't keep the ports' traffic: %s", error)

    def shutdown(self):
        if self.thread is not None:
            release_thread(self.thread, 10000)
