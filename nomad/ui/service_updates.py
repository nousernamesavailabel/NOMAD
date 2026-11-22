"""Updating NOMAD's services on this computer to this NOMAD, with the settings each one has: no service's own window
opens (services_catalog's ServiceEntry.update). Used by the banner's Update Now button and Tools > Services &
Firewall. Needs administrator rights.

Also what this NOMAD does around a change to a service, as each service's own window does: it stops listening on a
collector's port before the collector starts (free_ports), and tells the pages after (services_changed)."""
import logging

from PyQt5.QtCore import QObject, pyqtSignal

from .common import run_in_background

log = logging.getLogger(__name__)


def free_ports(window, keys):
    """A collector is about to start: this NOMAD stops listening on its port first (the Syslog page and the Map
    Watcher for the Syslog Collector, Collect Here on the NetFlow page for the Flow Collector). Returns the Map
    Watcher it stopped listening for syslog (or None), for services_changed."""
    released = None
    if "syslog" in keys:
        from .syslog_service_dialog import free_syslog_port
        released = free_syslog_port(window)
    page = getattr(window, "flows_tab", None)
    if "flows" in keys and page is not None and getattr(page, "local", None) is not None:
        page.stop_collect_here()
    return released


def services_changed(window, keys, released=None):
    """Tell the pages about the services that changed."""
    if "syslog" in keys:
        from .syslog_service_dialog import give_syslog_port_back
        give_syslog_port_back(window, released)
        page = getattr(window, "syslog_tab", None)
        if page is not None and hasattr(page, "service_changed"):
            page.service_changed()
    if "flows" in keys:
        page = getattr(window, "flows_tab", None)
        if page is not None and hasattr(page, "check_source"):
            page.check_source()
    if "tribe" in keys and hasattr(window, "tribe_key_changed"):
        window.tribe_key_changed()


class UpdateJob:
    """Update each service in turn on a worker thread, carrying on past one that fails. Returns the problems."""

    def __init__(self, entries):
        self.entries = list(entries)

    def __call__(self):
        problems = []
        for entry in self.entries:
            try:
                log.info("Updating the %s service", entry.title)
                entry.update()
            except Exception as error:
                log.warning("Couldn't update the %s service: %s", entry.title, error)
                problems.append(f"The {entry.title} wasn't updated: {error}")
        return problems


class ServiceUpdater(QObject):
    """Updates services on a worker thread. finished(problems) once they're all done ([] if all went well)."""
    finished = pyqtSignal(list)

    def __init__(self, window, parent=None):
        super().__init__(parent)
        self.window = window
        self.running = False
        self.keys = set()
        self.released = None

    def update(self, entries):
        """Update these services (services_catalog entries), in the catalog's order. False if it's already busy."""
        from .. import services_catalog
        if self.running:
            return False
        keys = {entry.key for entry in entries}
        ordered = [entry for entry in services_catalog.SERVICES if entry.key in keys]
        self.running = True
        self.keys = keys
        self.released = free_ports(self.window, keys)
        run_in_background(UpdateJob(ordered), self.done, self.failed)
        return True

    def done(self, problems=None):
        self.after()
        self.finished.emit(list(problems or []))

    def failed(self, error):
        log.warning("Updating the services: %s", error)
        self.after()
        self.finished.emit([str(error)])

    def after(self):
        self.running = False
        keys, self.keys = self.keys, set()
        released, self.released = self.released, None
        services_changed(self.window, keys, released)
