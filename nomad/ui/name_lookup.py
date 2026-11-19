"""Host names in address fields, for the UI: resolve_now() for a button or a dialog's OK (the window keeps painting
but takes no clicks while DNS answers), and NameResolver for forms checked as they're typed (it looks a name up in
the background once typing pauses, then asks the form to check itself again).

DNS comes first; a name it doesn't know is looked for on the open map, in IPAM (when it's open) and in the saved
sessions. Answers are kept for a minute, so checking a form again doesn't ask DNS again.
"""
import ipaddress
import logging
import threading
import time
from functools import partial

from PyQt5.QtCore import QEventLoop, QObject, Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication

from ..resolve import DNS_TIMEOUT, dns_addresses, from_dns, is_host_name, match_known, normalize, not_found, parse
from .common import run_in_background

log = logging.getLogger(__name__)

FOUND_SECONDS = 60
MISSING_SECONDS = 10
TYPING_PAUSE_MS = 400
MAP, IPAM, SESSIONS = "the map", "IPAM", "a saved session"

_answers = {}  # (name, family) -> (when, Resolved or NameNotFound)


def forget_answers():
    _answers.clear()


def remembered(name, family):
    """The Resolved or NameNotFound kept for name, or None when there's none (or it's too old)."""
    entry = _answers.get((normalize(name), family))
    if entry is None:
        return None
    when, answer = entry
    if time.monotonic() - when > (MISSING_SECONDS if isinstance(answer, Exception) else FOUND_SECONDS):
        _answers.pop((normalize(name), family), None)
        return None
    return answer


def nomad_window():
    """NOMAD's main window, for dialogs that weren't handed it."""
    for widget in QApplication.topLevelWidgets():
        if hasattr(widget, "netmap_tab") and hasattr(widget, "session_store"):
            return widget
    return None


def known_names(window, name):
    """[(name, address, source)] NOMAD already has that may be name: the open map's devices and hosts, IPAM's named
    addresses (if IPAM is open) and saved sessions whose host is an address."""
    window = window if window is not None else nomad_window()
    entries = []
    if window is None:
        return entries
    netmap = getattr(window, "netmap_tab", None)
    network_map = netmap.displayed_map() if netmap is not None and hasattr(netmap, "displayed_map") else None
    if network_map is not None:
        entries += [(device.name, device.mgmt_ip, MAP) for device in network_map.devices.values()]
        entries += [(host.name, host.ip, MAP) for host in network_map.hosts]
    ipam = getattr(window, "ipam_tab", None)
    if ipam is not None:
        from ..ipam.store import NAME
        for store in (getattr(ipam, "team", None), getattr(ipam, "local_store", None)):  # Only ones already open
            if store is None:
                continue
            try:
                found = store.search(normalize(name).split(".")[0], subnets=False, match=NAME, limit=100)
            except Exception:  # A tribe server that's gone away: the other places still count
                log.exception("Couldn't look %s up in IPAM", name)
                continue
            entries += [(address.name, address.ip, IPAM) for _, _, address in found if address is not None]
    sessions = getattr(window, "session_store", None)
    for session in getattr(sessions, "sessions", None) or []:
        try:
            ipaddress.ip_address(session.host)
        except ValueError:
            continue
        entries.append((session.name, session.host, SESSIONS))
    return entries


def ask_dns(name, family):
    """(name, family, addresses, problem) for a worker thread."""
    try:
        return name, family, dns_addresses(name, timeout=DNS_TIMEOUT), ""
    except TimeoutError as error:
        return name, family, [], str(error)


def finish(window, name, family, addresses, problem):
    """Resolved for name from DNS's answer, or else from what NOMAD knows; kept for next time. Raises NameNotFound."""
    found = from_dns(name, family, addresses)
    if found is None:
        try:
            found = match_known(name, known_names(window, name), family)
        except Exception:  # Looking further is a bonus: never worse than DNS alone
            log.exception("Couldn't look %s up in what NOMAD knows", name)
    answer = found if found is not None else not_found(name, family, addresses, problem)
    _answers[(normalize(name), family)] = (time.monotonic(), answer)
    if found is None:
        raise answer
    return found


def resolve_now(text, family=None, window=None):
    """Resolved for an address or name typed, waiting for DNS with a busy cursor (painting, but not taking clicks).
    family is 4 or 6 for one kind only, None for either. Raises ValueError."""
    parsed = parse(text, family)
    if parsed is not None:
        return parsed
    name = text.strip()
    answer = remembered(name, family)
    if answer is not None:
        if isinstance(answer, Exception):
            raise answer
        return answer
    result = {}

    def ask():
        result["answer"] = ask_dns(name, family)

    thread = threading.Thread(target=ask, daemon=True, name="name-lookup-now")
    thread.start()
    QApplication.setOverrideCursor(Qt.WaitCursor)
    try:
        while thread.is_alive():
            QApplication.processEvents(QEventLoop.ExcludeUserInputEvents, 50)
            thread.join(0.02)
    finally:
        QApplication.restoreOverrideCursor()
    _, _, addresses, problem = result.get("answer", (name, family, [], ""))
    return finish(window, name, family, addresses, problem)


def name_to_address(ip_input, name_input=None, family=None, window=None):
    """When ip_input (a QLineEdit) holds a host name, put its address there instead, and the name in name_input when
    that's empty: for records that keep an address (the map's devices and hosts). Returns the Resolved, or None when
    it doesn't hold a name. Raises ValueError for a name with no address."""
    text = ip_input.text().strip()
    if not is_host_name(text):
        return None
    found = resolve_now(text, family, window)
    ip_input.setText(found.address)
    if name_input is not None and not name_input.text().strip():
        name_input.setText(text)
    return found


class NameResolver(QObject):
    """Names in a form that's checked as it's typed. address() answers at once for an address, or a name it already
    knows; for a new name it returns None and looks it up once typing pauses, then fires changed so the form checks
    itself again (and gets the answer)."""
    changed = pyqtSignal()

    def __init__(self, window=None, parent=None):
        super().__init__(parent)
        self.window = window
        self.wanted = {}  # Slot (one per field, or per item of a list) -> (name, family): only the latest typing
        self.running = set()  # (name, family) being asked
        self.timer = QTimer(self)
        self.timer.setSingleShot(True)
        self.timer.setInterval(TYPING_PAUSE_MS)
        self.timer.timeout.connect(self.start_lookups)

    def address(self, text, family=None, slot="_"):
        """Resolved, or None while a name is being looked up. Raises ValueError (NameNotFound once it's been looked
        for)."""
        parsed = parse(text, family)
        if parsed is not None:
            self.wanted.pop(slot, None)
            return parsed
        name = text.strip()
        answer = remembered(name, family)
        if answer is not None:
            self.wanted.pop(slot, None)
            if isinstance(answer, Exception):
                raise answer
            return answer
        self.wanted[slot] = (name, family)
        self.timer.start()
        return None

    def busy(self):
        return bool(self.wanted or self.running)

    def start_lookups(self):
        for name, family in list(self.wanted.values()):
            key = (normalize(name), family)
            if key not in self.running:
                self.running.add(key)
                run_in_background(partial(ask_dns, name, family), self.answered)
        self.wanted.clear()

    def answered(self, answer):
        name, family, addresses, problem = answer
        self.running.discard((normalize(name), family))
        try:
            finish(self.window, name, family, addresses, problem)
        except ValueError:
            pass  # Kept, and raised when the form asks again
        self.changed.emit()


def looking_up(name):
    return f"Looking up {name.strip()}..."
