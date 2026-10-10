"""While monitoring: after each ping poll, read the counters of the map's linked ports on a background thread, for
the Utilization and Errors overlay."""
from PyQt5.QtCore import QObject, QThread, pyqtSignal

from ..netmap import counters
from ..snmp import SnmpClient


class CounterThread(QThread):
    finished_poll = pyqtSignal(object)  # counters.poll's {device key: (interface index, {port key: Sample})}

    def __init__(self, targets, indexes, client_factory, parent=None):
        super().__init__(parent)
        self.targets, self.indexes, self.client_factory = targets, indexes, client_factory

    def run(self):
        self.finished_poll.emit(counters.poll(self.targets, self.indexes, self.client_factory))


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

    @property
    def rates(self):
        return self.tracker.rates

    def reset(self):
        """Forget what was measured (monitoring stopped, or another map)."""
        self.tracker.clear()
        self.indexes = {}

    def poll_now(self):
        page = self.page
        network_map = page.network_map
        if self.thread is not None or network_map is None or page.worker is not None:
            return
        if network_map is not self.network_map:
            self.reset()
            self.network_map = network_map
        targets = []
        for key, ports in counters.link_ports(network_map).items():
            address = network_map.devices[key].mgmt_ip
            credential, version = page.snmp_access(address)
            if credential is not None:
                targets.append((key, address, credential, version, page.timeout, ports))
        self.tracker.forget_others(set(network_map.devices))
        if not targets:
            return
        self.thread = CounterThread(targets, dict(self.indexes), self.client_factory, self)
        self.thread.finished_poll.connect(self.on_results)
        self.thread.finished.connect(self.on_thread_finished)
        self.thread.start()

    def on_thread_finished(self):
        self.thread = None

    def on_results(self, results):
        if self.page.network_map is not self.network_map or not self.page.monitor.running:
            return  # Another map, or monitoring stopped meanwhile
        for key, (index, samples) in results.items():
            self.indexes[key] = index
            self.tracker.update(key, samples)
        self.updated.emit()

    def shutdown(self):
        if self.thread is not None:
            self.thread.wait(10000)
