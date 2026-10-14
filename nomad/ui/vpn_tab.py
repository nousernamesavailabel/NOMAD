"""VPNs page: build and edit VPNs between Cisco IOS / IOS-XE routers (GRE, GRE over IPsec, IPsec VTI, crypto maps,
DMVPN phases 1-3), with pre-shared keys or certificates, and see whether the ones up now work and why not.

Pick routers (the open map's, saved SSH sessions, or an address) and Read: NOMAD reads each one's running-config,
routes and VPN state, and finds the VPNs on them (vpnfind), pairing tunnels and crypto maps across routers. Pick one
to edit, or New VPN: its routers, how they authenticate, the crypto, the routing across it. Nothing goes to a router
until Send. The Changes box shows every router's exact lines (and what undoes them), with keys hidden unless Show
Keys is ticked; Checks says what would stop it working (recursive routing, a better route elsewhere, a WAN ACL
dropping IKE, NAT catching the traffic, weak crypto, routes that would leak to an ISP...).

Send over SSH puts the change on every router with the revert timer, then checks the VPN works from each end
(the tunnel answers, the LANs reach each other, spokes registered), and only then confirms them all from new logins;
if anything is refused or a check fails, every router is put back. Certificates (a CA set up on one of the routers,
a CA's SCEP URL, or pasting by hand) are got first, with NTP set up when the clocks aren't kept.

Status shows each VPN as the routers say it is now, and why one that isn't up isn't (vpnstatus). The Library keeps
designs to reuse; Changes Sent keeps every change with what undoes it (keys kept protected for this Windows account).
"""
import copy
import datetime
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, \
    QGridLayout, QGroupBox, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, \
    QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QScrollArea, QSpinBox, QSplitter, QTableWidget, \
    QTableWidgetItem, QTabWidget, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from ..netmap import configpush, vpn, vpncheck, vpnfind, vpnpki, vpnstatus
from ..netmap.model import ROUTER, SWITCH
from ..netmap.vpnstatus import DOWN, ERROR, GOOD, INFO, NEGOTIATING, UNKNOWN, UP, WARNING
from ..terminal.sessions import SSH
from .common import StoppableThread, local_address_toward, read_only_table, release_thread, set_hint
from .session_send import SessionSender
from .ssh_push import LoginRow
from .theme import COLORS, accent_button, monospace_font
from .vpn_dialogs import ChoiceDialog, IpamBlockDialog, MemberDialog, NewVpnDialog, PasteEnrollDialog

log = logging.getLogger(__name__)

READ_WORKERS = 4
DEFAULT_MINUTES = 10
VERIFY_WAIT = 120  # Seconds a check may take to pass (IKE, NHRP registration, a routing neighbor)
CONFIRM_MARGIN = 90  # Seconds kept before the revert timer runs out, to confirm (or put back) every router
CONFIRM_AUTO, CONFIRM_MANUAL = "auto", "manual"
EXPIRY_GRACE = 20
MEMBER_COLUMNS = ["Router", "Role", "WAN", "WAN Address", "Reached At", "Tunnel", "Tunnel Address", "LANs", "BGP AS"]
VPN_COLUMNS = ["VPN", "Kind", "Routers", "State"]
LIBRARY_COLUMNS = ["Name", "Kind", "Routers", "Saved", "Notes"]
HISTORY_COLUMNS = ["When", "VPN", "Router", "How", "Outcome"]
STATE_TEXT = {UP: "Up", DOWN: "Down", NEGOTIATING: "Partly up", UNKNOWN: "Not read"}
STATE_COLOR = {UP: "success", DOWN: "error", NEGOTIATING: "warning", UNKNOWN: "muted"}
SEVERITY_COLOR = {ERROR: "error", WARNING: "warning", INFO: "muted", GOOD: "success"}
NEW = "new"  # A draft's origin: not on the routers yet
CA_CHOICES = [("router", "A CA NOMAD sets up on one of the routers"), ("scep", "A CA's SCEP URL"),
              ("paste", "By hand (paste the certificates)")]


@dataclass
class Target:
    """A router VPNs can be read from."""
    key: str
    label: str
    address: str = ""
    names: list = field(default_factory=list)
    source: str = "map"  # "map", "session" or "address"
    map_key: str = ""


class ReadThread(StoppableThread):
    """Reads a few routers at once."""
    device_read = pyqtSignal(str, object)  # Target key, vpn.DeviceVpns

    def __init__(self, targets, make_pusher, parent=None):
        super().__init__(parent)
        self.targets, self.make_pusher = targets, make_pusher  # [(key, address, names, pc_ip)]

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            def read(target):
                key, address, names, pc_ip = target
                if self.stopping:
                    return
                try:
                    device = pusher.read_vpns(address, names, pc_ip) if address else \
                        vpn.DeviceVpns(problem="it has no address.")
                except Exception as error:  # One router's trouble shouldn't stop the rest
                    log.exception("Reading %s for VPNs failed", address)
                    device = vpn.DeviceVpns(problem=str(error))
                if not self.stopping:
                    self.device_read.emit(key, device)
            with ThreadPoolExecutor(max_workers=max(1, min(READ_WORKERS, len(self.targets)))) as executor:
                list(executor.map(read, self.targets))
        finally:
            pusher.close()


@dataclass
class MemberJob:
    key: str
    address: str
    names: list
    title: str
    text: str = ""  # The lines (with keys), configure terminal ... end (the revert timer added when sent)
    undo: str = ""
    checks: list = field(default_factory=list)


@dataclass
class SendResult:
    ok: bool = False
    waiting: bool = False  # In with the revert timer, every check passed, left for the user to confirm
    deadline: object = None
    problem: str = ""
    outcomes: dict = field(default_factory=dict)  # key -> what happened to it, in a sentence
    transcripts: dict = field(default_factory=dict)
    checks: list = field(default_factory=list)  # [(key, command, passed, what it said, what it means)]
    sent: list = field(default_factory=list)  # Keys whose change went in (and wasn't put back)
    archive: dict = field(default_factory=dict)  # key -> archive path NOMAD set for the revert timer


class SendThread(StoppableThread):
    """A VPN's change on every router (with the revert timer), its checks from each end, then confirmed on them all;
    a refusal or a failed check puts them all back."""
    progress = pyqtSignal(str)
    done = pyqtSignal(object)  # SendResult

    def __init__(self, jobs, make_pusher, minutes, auto_confirm=True, verify=True, parent=None):
        super().__init__(parent)
        self.jobs, self.make_pusher, self.minutes = jobs, make_pusher, minutes
        self.auto_confirm, self.verify = auto_confirm, verify

    def check_time(self, first_sent):
        """Seconds a router's checks may take: VERIFY_WAIT, but all of them over well before the first router's
        revert timer runs out (leaving time to confirm, or to put them all back)."""
        if not self.minutes or first_sent is None:
            return VERIFY_WAIT
        left = (first_sent + datetime.timedelta(minutes=self.minutes) - datetime.datetime.now()).total_seconds()
        return max(5, min(VERIFY_WAIT, left - CONFIRM_MARGIN))

    def run(self):
        result = SendResult()
        pusher = self.make_pusher(lambda: self.stopping)
        sent = []
        first_sent = None
        try:
            for job in self.jobs:
                if self.stopping:
                    result.problem = "Stopped."
                    break
                self.progress.emit(f"Sending the change to {job.title}...")
                if self.minutes:
                    outcome = pusher.set_up_guarded(job.address, job.text, self.minutes, job.names, confirm=False)
                else:
                    outcome = pusher.set_up(job.address, job.text, "", job.names)
                result.transcripts[job.key] = outcome.transcript
                if outcome.archive_added:
                    result.archive[job.key] = outcome.archive_added
                if outcome.ok:
                    sent.append(job)
                    first_sent = first_sent or datetime.datetime.now()
                    result.outcomes[job.key] = "In; checking it works"
                    continue
                why = outcome.problem or "it wasn't taken"
                explained = vpncheck.explain_refusal(*(outcome.refused[0][0], outcome.refused[0][1][0])) \
                    if outcome.refused else ""
                result.problem = f"{job.title}: {why}" + (f" ({explained})" if explained else "")
                if outcome.reverted:
                    result.outcomes[job.key] = f"Refused and put back: {why}"
                elif self.minutes and outcome.reverts_at:
                    result.outcomes[job.key] = f"Not in: {why} (it puts itself back at {outcome.reverts_at})"
                else:
                    result.outcomes[job.key] = f"Refused: {why}"
                    if not self.minutes and outcome.transcript.strip():
                        sent.append(job)  # Partly in: its undo goes too
                break
            if not result.problem and self.verify and not self.stopping:
                for job in sent:
                    if not job.checks:
                        continue
                    self.progress.emit(f"Checking the VPN from {job.title}...")
                    for command, passed, answer, meaning in pusher.verify(job.address, job.checks, job.names,
                                                                          wait=self.check_time(first_sent)):
                        result.checks.append((job.key, command, passed, answer, meaning))
                        if not passed and not result.problem:
                            result.problem = f"From {job.title}: {meaning} - no ({command})."
                    if result.problem:
                        break
            if self.stopping and not result.problem:
                result.problem = "Stopped."
            if result.problem:
                for job in reversed(sent):
                    self.progress.emit(f"Putting {job.title} back...")
                    if self.minutes:
                        ok, said = pusher.revert(job.address, job.names)
                        result.outcomes[job.key] = "Put back (configure revert now)" if ok else \
                            f"Couldn't put it back now ({said}): the revert timer does it in {self.minutes} min"
                    else:
                        outcome = pusher.take_away(job.address, job.undo, job.names)
                        result.outcomes[job.key] = "Undone" if outcome.ok else f"Undoing failed: {outcome.problem}"
                return
            if self.minutes and self.auto_confirm:
                all_confirmed = True
                for job in sent:
                    self.progress.emit(f"Confirming on {job.title} (from a new login)...")
                    ok, said = pusher.confirm(job.address, job.names)
                    result.outcomes[job.key] = "Confirmed" if ok else \
                        f"Not confirmed ({said}): it puts itself back in {self.minutes} min"
                    all_confirmed = all_confirmed and ok
                result.ok = all_confirmed
                result.problem = "" if all_confirmed else "Not every router could be confirmed."
            elif self.minutes:
                result.ok = result.waiting = True
                result.deadline = datetime.datetime.now() + datetime.timedelta(minutes=self.minutes)
                for job in sent:
                    result.outcomes[job.key] = "In and working; waiting for you to confirm"
            else:
                result.ok = True
                for job in sent:
                    result.outcomes[job.key] = "Sent"
            result.sent = [job.key for job in sent]
        except Exception as error:
            log.exception("Sending a VPN failed")
            result.problem = str(error)
        finally:
            pusher.close()
            self.done.emit(result)


@dataclass
class Action:
    """One thing to do on one router (ActionThread)."""
    kind: str  # "confirm", "revert", "commands" (exec lines), "config" (guarded when minutes), "undo"
    key: str
    address: str
    names: list
    text: str = ""
    title: str = ""


class ActionThread(StoppableThread):
    """Confirm, put back, clear sessions, or undo a change, on one router after another."""
    progress = pyqtSignal(str)
    action_done = pyqtSignal(int, bool, str)  # Index, whether it worked, what it said

    def __init__(self, actions, make_pusher, minutes=0, parent=None):
        super().__init__(parent)
        self.actions, self.make_pusher, self.minutes = actions, make_pusher, minutes

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for index, action in enumerate(self.actions):
                if self.stopping:
                    break
                self.progress.emit(action.title or f"{action.kind} on {action.address}...")
                try:
                    if action.kind == "confirm":
                        ok, said = pusher.confirm(action.address, action.names)
                    elif action.kind == "revert":
                        ok, said = pusher.revert(action.address, action.names)
                    elif action.kind == "commands":
                        results = pusher.run_commands(action.address, action.text.splitlines(), action.names)
                        ok = all(took for _, _, took in results)
                        said = "\n".join(f"{command}\n{answer}" for command, answer, _ in results)
                    elif self.minutes:
                        outcome = pusher.set_up_guarded(action.address, action.text.replace(
                            "configure terminal", f"configure terminal revert timer {self.minutes}", 1),
                            self.minutes, action.names, confirm=True)
                        ok, said = outcome.ok, outcome.problem or outcome.transcript
                    else:
                        outcome = pusher.take_away(action.address, action.text, action.names)
                        ok, said = outcome.ok, outcome.problem or outcome.transcript
                except Exception as error:
                    log.exception("%s on %s failed", action.kind, action.address)
                    ok, said = False, str(error)
                self.action_done.emit(index, ok, said)
        finally:
            pusher.close()


class PkiThread(StoppableThread):
    """Gets the VPN's routers certificates: NTP when their clocks aren't kept, the CA server on the CA router, then
    each router enrolled over SCEP (the CA's fingerprint checked), waiting for each in turn."""
    progress = pyqtSignal(str)
    step_done = pyqtSignal(object, bool, str, str)  # vpnpki.PkiStep, ok, transcript, problem
    done = pyqtSignal(bool, str, str)  # ok, problem, the CA's fingerprint

    def __init__(self, design, devices, targets, make_pusher, passphrase="", fingerprint="", parent=None):
        super().__init__(parent)
        self.design, self.devices, self.targets = design, devices, targets  # targets: key -> (address, names)
        self.make_pusher, self.passphrase, self.fingerprint = make_pusher, passphrase, fingerprint

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        ok, problem, fingerprint = False, "", self.fingerprint
        try:
            ok, problem, fingerprint = self.work(pusher)
        except Exception as error:
            log.exception("Getting certificates failed")
            problem = str(error)
        finally:
            pusher.close()
            self.done.emit(ok, problem, fingerprint)

    def run_step(self, pusher, step):
        address, names = self.targets[step.key]
        self.progress.emit(step.title + "...")
        ok, transcript, problem = pusher.dialog(address, step.steps, names)
        why = vpnpki.explain(problem, self.design) if not ok else ""
        problem = f"{problem} ({why})" if why else problem
        self.step_done.emit(step, ok, transcript, problem)
        return ok, problem

    def poll(self, pusher, key, command, wanted, seconds, what):
        address, names = self.targets[key]
        end = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
        while datetime.datetime.now() < end:
            if self.stopping:
                return False, ""
            said = pusher.run_commands(address, [command], names)
            text = said[0][1] if said else ""
            if re.search(wanted, text, re.MULTILINE):
                return True, text
            self.progress.emit(what)
            for _ in range(10):
                if self.stopping:
                    return False, ""
                self.msleep(1000)
        return False, ""

    def work(self, pusher):
        design, devices = self.design, self.devices
        fingerprint = self.fingerprint
        steps = vpnpki.ntp_steps(design, devices)
        ca = design.member(design.auth.ca_device) if design.auth.ca_kind == "router" else None
        ca_ntp = [step for step in steps if ca is not None and step.key == ca.key]
        for step in ca_ntp:
            ok, problem = self.run_step(pusher, step)
            if not ok:
                return False, problem, fingerprint
        if ca_ntp:
            ok, _ = self.poll(pusher, ca.key, "show clock", r"^\s*[^*\s]?\d{1,2}:\d{2}:\d{2}", 1800,
                              f"Waiting for {ca.title()}'s clock to become authoritative (NTP takes a few "
                              f"minutes)...")
            if not ok:
                return False, f"{ca.title()}'s clock didn't become authoritative.", fingerprint
        if ca is not None:
            name = vpnpki.ca_server_name(design)
            device = devices.get(ca.key)
            if device is not None and not vpnpki.ca_running(device, name):
                ok, problem = self.run_step(pusher, vpnpki.ca_steps(design, device, self.passphrase))
                if not ok:
                    return False, problem, fingerprint
            ok, text = self.poll(pusher, ca.key, f"show crypto pki server {name}", r"Status:\s*enabled", 180,
                                 f"Waiting for {ca.title()}'s certificate server to start...")
            if not ok:
                return False, f"{ca.title()}'s certificate server didn't start (show crypto pki server {name}).", \
                    fingerprint
            fingerprint = vpnpki.ca_fingerprint(text) or fingerprint
        for step in [item for item in steps if item not in ca_ntp]:
            ok, problem = self.run_step(pusher, step)
            if not ok:
                return False, problem, fingerprint
        for step in [item for item in steps if item not in ca_ntp]:
            member = design.member(step.key)
            ok, _ = self.poll(pusher, step.key, "show clock", r"^\s*[^*\s]?\d{1,2}:\d{2}:\d{2}", 1800,
                              f"Waiting for {member.title()}'s clock to come into step (NTP)...")
            if not ok:
                return False, f"{member.title()}'s clock didn't come into step with NTP.", fingerprint
        if not fingerprint:
            return False, "There's no CA fingerprint to check the CA's certificate against.", fingerprint
        for member in design.members:
            device = devices.get(member.key)
            if member.key not in self.targets or device is None or vpnpki.has_certificate(design, member, device):
                continue
            step = vpnpki.enroll_steps(design, member, device, fingerprint)
            ok, problem = self.run_step(pusher, step)
            if not ok:
                return False, problem, fingerprint
            ok, _ = self.poll(pusher, member.key, f"show crypto pki certificates {step.trustpoint}",
                              r"^Certificate\s*$[\s\S]*?Status:\s*Available", 180,
                              f"Waiting for {member.title()}'s certificate...")
            if not ok:
                return False, f"{member.title()} didn't get its certificate (is the CA granting automatically?).", \
                    fingerprint
        return True, "", fingerprint


class PasteThread(StoppableThread):
    """One manual enrollment step (trusting a CA, making a request, putting a certificate in) on some routers."""
    step_done = pyqtSignal(object, bool, str, str)

    def __init__(self, steps, targets, make_pusher, parent=None):
        super().__init__(parent)
        self.steps, self.targets, self.make_pusher = steps, targets, make_pusher

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for step in self.steps:
                if self.stopping:
                    break
                address, names = self.targets[step.key]
                ok, transcript, problem = pusher.dialog(address, step.steps, names)
                self.step_done.emit(step, ok, transcript, problem)
        finally:
            pusher.close()


@dataclass
class Waiting:
    """A VPN's change in on its routers with the revert timer, waiting for the user."""
    deadline: object
    keys: list
    entries: dict = field(default_factory=dict)  # key -> Changes Sent entry id
    views: dict = field(default_factory=dict)  # key -> terminal view it was typed into (Send to Session)

    @property
    def at(self):
        return self.deadline.strftime("%H:%M")


class VpnTab(QWidget):
    def __init__(self, window, store=None):
        super().__init__(window)
        self.window = window
        self.sessions = getattr(window, "session_store", None)
        self.store = store if store is not None else vpn.VpnStore.default()
        self.shell_factory = configpush.VpnShell  # Tests swap in fake routers
        self.targets = {}  # key -> Target
        self.read = {}  # key -> vpn.DeviceVpns
        self.notes = {}  # key -> what happened to it last
        self.found = []  # [vpn.Vpn] on the routers read
        self.originals = {}  # VPN id -> the Vpn as found (None: a new one)
        self.drafts = {}  # VPN id -> the Vpn as edited (None: to be taken away)
        self.current_id = ""
        self.reader = self.sender = self.actor = self.pki = None
        self.saved_logins = None
        self.after_read = None
        self.waiting = {}  # VPN id -> Waiting
        self.actions = []
        self.action_results = {}
        self.clear_offer = {}  # VPN id -> [(key, peer)] sessions offered a clear after a crypto change
        self.filling = False
        self.paste_dialog = None
        self.pending_new = None  # (name, kind, [(key, role)]) to make once its routers are read
        self.session_sender = SessionSender(self, window, None)
        self.tick = QTimer(self)
        self.tick.setInterval(1000)
        self.tick.timeout.connect(self.on_tick)
        self.status_timer = QTimer(self)
        self.status_timer.setInterval(60000)
        self.status_timer.timeout.connect(self.refresh_status)
        self.init_ui()
        self.session_sender.status_label = self.status_label
        page = self.map_page()
        if page is not None and hasattr(page, "map_shown"):
            page.map_shown.connect(self.on_map_shown)
        self.on_map_shown()
        self.fill_library()
        self.fill_history()

    # ----------------------------------------------------------------- Building the page

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Build and edit VPNs between Cisco routers (IPsec VTI, GRE over IPsec, GRE, crypto maps, "
                       "DMVPN), with keys or certificates; NOMAD writes both ends from one design, checks it, sends it "
                       "to every router with a revert timer, and confirms it only once the VPN works. Status says "
                       "why one that's down is down.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.tabs = QTabWidget()
        self.tabs.addTab(self.make_build_tab(), "VPNs")
        self.tabs.addTab(self.make_status_tab(), "Status")
        self.tabs.addTab(self.make_library_tab(), "Library")
        self.tabs.addTab(self.make_history_tab(), "Changes Sent")
        layout.addWidget(self.tabs, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.update_buttons()

    def make_build_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 4, 4, 4)
        splitter = QSplitter(Qt.Vertical)
        top = QSplitter(Qt.Horizontal)
        top.addWidget(self.make_routers_box())
        top.addWidget(self.make_vpns_box())
        top.addWidget(self.make_editor())
        top.setStretchFactor(0, 2)
        top.setStretchFactor(1, 3)
        top.setStretchFactor(2, 8)
        top.setSizes([260, 380, 1000])
        splitter.addWidget(top)
        splitter.addWidget(self.make_changes_box())
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)
        return page

    def make_routers_box(self):
        box = QGroupBox("Routers")
        layout = QVBoxLayout(box)
        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText("Find a router")
        self.find_input.setClearButtonEnabled(True)
        self.find_input.textChanged.connect(self.filter_routers)
        layout.addWidget(self.find_input)
        self.router_list = QListWidget()
        self.router_list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.router_list.itemDoubleClicked.connect(self.read_chosen)
        self.router_list.itemSelectionChanged.connect(self.update_buttons)
        layout.addWidget(self.router_list, 1)
        row = QHBoxLayout()
        self.read_button = accent_button("Read")
        self.read_button.setToolTip("Log in over SSH and read the selected routers' VPNs")
        self.read_button.clicked.connect(self.read_chosen)
        row.addWidget(self.read_button)
        self.add_button = QPushButton("Add Address...")
        self.add_button.clicked.connect(self.add_address)
        row.addWidget(self.add_button)
        layout.addLayout(row)
        self.login_row = LoginRow(self, self.sessions, "The VPNs page", stacked=True)
        layout.addWidget(self.login_row)
        return box

    def make_vpns_box(self):
        box = QGroupBox("VPNs")
        layout = QVBoxLayout(box)
        self.vpn_tree = QTreeWidget()
        self.vpn_tree.setHeaderLabels(VPN_COLUMNS)
        self.vpn_tree.setRootIsDecorated(False)
        self.vpn_tree.currentItemChanged.connect(self.on_vpn_chosen)
        self.vpn_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.vpn_tree.customContextMenuRequested.connect(self.show_vpn_menu)
        layout.addWidget(self.vpn_tree, 1)
        row = QHBoxLayout()
        self.new_button = accent_button("New VPN...")
        self.new_button.clicked.connect(self.new_vpn)
        row.addWidget(self.new_button)
        self.delete_button = QPushButton("Take Away")
        self.delete_button.setToolTip("Take the VPN off its routers (planned here; sent with Send)")
        self.delete_button.clicked.connect(self.take_away_vpn)
        row.addWidget(self.delete_button)
        self.library_save_button = QPushButton("Save to Library")
        self.library_save_button.clicked.connect(self.save_to_library)
        row.addWidget(self.library_save_button)
        row.addStretch(1)
        layout.addLayout(row)
        return box

    def make_editor(self):
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setMinimumWidth(520)
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(4, 0, 4, 0)
        self.empty_label = QLabel("Read routers, then pick a VPN they have, or New VPN.")
        self.empty_label.setWordWrap(True)
        layout.addWidget(self.empty_label)
        self.editor = QWidget()
        editor = QVBoxLayout(self.editor)
        editor.setContentsMargins(0, 0, 0, 0)
        # What it is
        head = QGroupBox("VPN")
        form = QFormLayout(head)
        self.name_input = QLineEdit()
        self.name_input.setToolTip("Names its crypto objects (NAME-PROP, NAME-IKE...) on routers it's built on")
        self.name_input.textEdited.connect(self.edited)
        form.addRow("Name:", self.name_input)
        self.kind_combo = QComboBox()
        for kind in vpn.KINDS:
            self.kind_combo.addItem(vpn.KIND_NAMES[kind], kind)
        self.kind_combo.currentIndexChanged.connect(self.on_kind_changed)
        form.addRow("Kind:", self.kind_combo)
        subnet_row = QHBoxLayout()
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("172.31.0.0/30")
        self.subnet_input.editingFinished.connect(self.on_subnet_changed)
        subnet_row.addWidget(self.subnet_input, 1)
        self.suggest_button = QPushButton("Suggest")
        self.suggest_button.setToolTip("A subnet in 172.31.0.0/16 none of the routers uses, with addresses for each")
        self.suggest_button.clicked.connect(self.suggest_subnet)
        subnet_row.addWidget(self.suggest_button)
        self.ipam_button = QPushButton("From IP Addresses...")
        self.ipam_button.setToolTip("Take a free block from a subnet on the IP Addresses page (and record it there)")
        self.ipam_button.clicked.connect(self.subnet_from_ipam)
        subnet_row.addWidget(self.ipam_button)
        self.subnet_label = QLabel("Tunnel subnet:")
        form.addRow(self.subnet_label, subnet_row)
        sizes = QHBoxLayout()
        self.mtu_spin = QSpinBox()
        self.mtu_spin.setRange(0, 9000)
        self.mtu_spin.setSpecialValueText("(none)")
        self.mtu_spin.valueChanged.connect(self.edited)
        sizes.addWidget(QLabel("IP MTU"))
        sizes.addWidget(self.mtu_spin)
        self.mss_spin = QSpinBox()
        self.mss_spin.setRange(0, 9000)
        self.mss_spin.setSpecialValueText("(none)")
        self.mss_spin.valueChanged.connect(self.edited)
        sizes.addWidget(QLabel("TCP MSS"))
        sizes.addWidget(self.mss_spin)
        self.keepalive_spin = QSpinBox()
        self.keepalive_spin.setRange(0, 255)
        self.keepalive_spin.setSpecialValueText("off")
        self.keepalive_spin.setSuffix(" s")
        self.keepalive_spin.setToolTip("GRE keepalive (plain GRE only)")
        self.keepalive_spin.valueChanged.connect(self.edited)
        self.keepalive_label = QLabel("Keepalive")
        sizes.addWidget(self.keepalive_label)
        sizes.addWidget(self.keepalive_spin)
        sizes.addStretch(1)
        self.sizes_label = QLabel("Tunnel:")
        form.addRow(self.sizes_label, sizes)
        editor.addWidget(head)
        # Its routers
        routers = QGroupBox("Routers in It")
        routers_layout = QVBoxLayout(routers)
        self.member_table = QTableWidget(0, len(MEMBER_COLUMNS))
        self.member_table.setHorizontalHeaderLabels(MEMBER_COLUMNS)
        self.member_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.member_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.member_table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.member_table.verticalHeader().setVisible(False)
        self.member_table.horizontalHeader().setStretchLastSection(True)
        self.member_table.itemDoubleClicked.connect(self.edit_member)
        self.member_table.itemSelectionChanged.connect(self.update_buttons)
        self.member_table.setMinimumHeight(150)
        self.member_table.setMinimumWidth(200)
        self.member_table.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        routers_layout.addWidget(self.member_table)
        member_row = QHBoxLayout()
        self.add_member_button = QPushButton("Add Router...")
        self.add_member_button.setToolTip("Add a read router (a spoke, or a second hub)")
        self.add_member_button.clicked.connect(self.add_member)
        member_row.addWidget(self.add_member_button)
        self.edit_member_button = QPushButton("Edit...")
        self.edit_member_button.clicked.connect(self.edit_member)
        member_row.addWidget(self.edit_member_button)
        self.remove_member_button = QPushButton("Remove")
        self.remove_member_button.clicked.connect(self.remove_member)
        member_row.addWidget(self.remove_member_button)
        member_row.addStretch(1)
        routers_layout.addLayout(member_row)
        editor.addWidget(routers)
        # How they authenticate
        auth = QGroupBox("Authentication")
        self.auth_box = auth
        auth_layout = QGridLayout(auth)
        self.psk_radio = QRadioButton("Pre-shared key")
        self.cert_radio = QRadioButton("Certificates")
        self.psk_radio.toggled.connect(self.on_auth_method)
        auth_layout.addWidget(self.psk_radio, 0, 0)
        self.psk_input = QLineEdit()
        self.psk_input.setEchoMode(QLineEdit.Password)
        self.psk_input.textEdited.connect(self.edited)
        auth_layout.addWidget(self.psk_input, 0, 1)
        self.show_key_check = QCheckBox("Show")
        self.show_key_check.toggled.connect(lambda on: self.psk_input.setEchoMode(
            QLineEdit.Normal if on else QLineEdit.Password))
        auth_layout.addWidget(self.show_key_check, 0, 2)
        self.generate_button = QPushButton("Generate")
        self.generate_button.setToolTip("A random 24-character key (letters and digits)")
        self.generate_button.clicked.connect(self.generate_key)
        auth_layout.addWidget(self.generate_button, 0, 3)
        auth_layout.addWidget(self.cert_radio, 1, 0)
        self.ca_combo = QComboBox()
        for value, text in CA_CHOICES:
            self.ca_combo.addItem(text, value)
        self.ca_combo.currentIndexChanged.connect(self.edited)
        auth_layout.addWidget(self.ca_combo, 1, 1, 1, 3)
        cert_form = QFormLayout()
        self.ca_device_combo = QComboBox()
        self.ca_device_combo.setToolTip("The router that's the CA (its certificate server is set up when the "
                                        "certificates are got)")
        self.ca_device_combo.currentIndexChanged.connect(self.edited)
        cert_form.addRow("CA router:", self.ca_device_combo)
        self.ca_name_input = QLineEdit()
        self.ca_name_input.setToolTip("The CA's name: its certificates' issuer CN (certificate maps match it)")
        self.ca_name_input.textEdited.connect(self.edited)
        cert_form.addRow("CA name:", self.ca_name_input)
        self.ca_url_input = QLineEdit()
        self.ca_url_input.setPlaceholderText("http://ca.example.com/certsrv/mscep/mscep.dll")
        self.ca_url_input.textEdited.connect(self.edited)
        cert_form.addRow("SCEP URL:", self.ca_url_input)
        self.fingerprint_input = QLineEdit()
        self.fingerprint_input.setToolTip("The CA certificate's fingerprint (MD5 or SHA-1): a router only trusts the "
                                          "CA if it shows this")
        self.fingerprint_input.textEdited.connect(self.edited)
        cert_form.addRow("CA fingerprint:", self.fingerprint_input)
        self.trustpoint_input = QLineEdit()
        self.trustpoint_input.textEdited.connect(self.edited)
        cert_form.addRow("Trustpoint:", self.trustpoint_input)
        self.revocation_combo = QComboBox()
        self.revocation_combo.addItem("Don't check revocation", "none")
        self.revocation_combo.addItem("Check the CA's CRL", "crl")
        self.revocation_combo.currentIndexChanged.connect(self.edited)
        cert_form.addRow("Revocation:", self.revocation_combo)
        auth_layout.addLayout(cert_form, 2, 1, 1, 3)
        cert_buttons = QHBoxLayout()
        self.certs_button = accent_button("Get Certificates")
        self.certs_button.setToolTip("Set up NTP and the CA where needed, and enroll each router that hasn't a "
                                     "certificate yet (before Send)")
        self.certs_button.clicked.connect(self.get_certificates)
        cert_buttons.addWidget(self.certs_button)
        self.cert_state = QLabel()
        self.cert_state.setWordWrap(True)
        cert_buttons.addWidget(self.cert_state, 1)
        auth_layout.addLayout(cert_buttons, 3, 1, 1, 3)
        auth_layout.setColumnStretch(1, 1)
        editor.addWidget(auth)
        # Crypto
        crypto = QGroupBox("Crypto")
        self.crypto_box = crypto
        crypto_layout = QFormLayout(crypto)
        self.preset_combo = QComboBox()
        for name, text in vpn.PRESET_NAMES.items():
            self.preset_combo.addItem(text, name)
        self.preset_combo.currentIndexChanged.connect(self.on_preset)
        crypto_layout.addRow("Preset:", self.preset_combo)
        self.ike_combo = QComboBox()
        self.ike_combo.addItem("IKEv2", vpn.IKEV2)
        self.ike_combo.addItem("IKEv1", vpn.IKEV1)
        self.ike_combo.currentIndexChanged.connect(self.on_custom_crypto)
        crypto_layout.addRow("IKE:", self.ike_combo)
        self.encryption_input = QLineEdit()
        self.encryption_input.setToolTip("IKEv2: aes-gcm-256 aes-cbc-256 ... (space between several); IKEv1: one, "
                                         "such as aes 256")
        self.encryption_input.textEdited.connect(self.on_custom_crypto)
        crypto_layout.addRow("Encryption:", self.encryption_input)
        self.integrity_input = QLineEdit()
        self.integrity_input.setToolTip("IKEv2 integrity (not with GCM): sha512 sha384 sha256; IKEv1 hash: sha256")
        self.integrity_input.textEdited.connect(self.on_custom_crypto)
        crypto_layout.addRow("Integrity / hash:", self.integrity_input)
        self.prf_input = QLineEdit()
        self.prf_input.setToolTip("IKEv2 PRF (with GCM): sha384 sha256")
        self.prf_input.textEdited.connect(self.on_custom_crypto)
        crypto_layout.addRow("PRF:", self.prf_input)
        self.groups_input = QLineEdit()
        self.groups_input.setToolTip("Diffie-Hellman groups: 21 20 19 14 (IKEv1 takes one)")
        self.groups_input.textEdited.connect(self.on_custom_crypto)
        crypto_layout.addRow("DH groups:", self.groups_input)
        self.esp_combo = QComboBox()
        self.esp_combo.setEditable(True)
        self.esp_combo.addItems(vpn.ESP_CHOICES)
        self.esp_combo.currentTextChanged.connect(self.on_custom_crypto)
        crypto_layout.addRow("IPsec transform:", self.esp_combo)
        more = QHBoxLayout()
        self.pfs_combo = QComboBox()
        for group in vpn.PFS_GROUPS:
            self.pfs_combo.addItem(f"group {group}" if group else "off", group)
        self.pfs_combo.currentIndexChanged.connect(self.on_custom_crypto)
        more.addWidget(QLabel("PFS"))
        more.addWidget(self.pfs_combo)
        self.dpd_spin = QSpinBox()
        self.dpd_spin.setRange(0, 3600)
        self.dpd_spin.setSpecialValueText("off")
        self.dpd_spin.setSuffix(" s")
        self.dpd_spin.setToolTip("Dead peer detection: how often to check the far end is there")
        self.dpd_spin.valueChanged.connect(self.edited)
        more.addWidget(QLabel("DPD"))
        more.addWidget(self.dpd_spin)
        self.nat_spin = QSpinBox()
        self.nat_spin.setRange(0, 3600)
        self.nat_spin.setSpecialValueText("off")
        self.nat_spin.setSuffix(" s")
        self.nat_spin.setToolTip("NAT keepalives: keep a NAT device's mapping open when a router is behind NAT")
        self.nat_spin.valueChanged.connect(self.edited)
        more.addWidget(QLabel("NAT keepalive"))
        more.addWidget(self.nat_spin)
        more.addStretch(1)
        crypto_layout.addRow("", more)
        editor.addWidget(crypto)
        # Routing
        routing = QGroupBox("Routing Across It")
        routing_layout = QFormLayout(routing)
        self.routing_combo = QComboBox()
        for kind in (vpn.STATIC, vpn.EIGRP, vpn.OSPF, vpn.BGP, vpn.NO_ROUTING):
            self.routing_combo.addItem(vpn.ROUTING_NAMES[kind], kind)
        self.routing_combo.currentIndexChanged.connect(self.edited)
        routing_layout.addRow("Routing:", self.routing_combo)
        process = QHBoxLayout()
        self.process_input = QLineEdit()
        self.process_input.setPlaceholderText("100")
        self.process_input.setToolTip("EIGRP AS or OSPF process number (an existing one is added to)")
        self.process_input.textEdited.connect(self.edited)
        process.addWidget(self.process_input)
        process.addWidget(QLabel("Area"))
        self.area_input = QLineEdit("0")
        self.area_input.textEdited.connect(self.edited)
        process.addWidget(self.area_input)
        process.addWidget(QLabel("Named EIGRP"))
        self.eigrp_name_input = QLineEdit()
        self.eigrp_name_input.setPlaceholderText("(classic)")
        self.eigrp_name_input.textEdited.connect(self.edited)
        process.addWidget(self.eigrp_name_input)
        routing_layout.addRow("Process:", process)
        self.guard_check = QCheckBox("Keep the VPN's LANs from the routers' other BGP neighbors (such as an ISP)")
        self.guard_check.toggled.connect(self.edited)
        routing_layout.addRow("", self.guard_check)
        editor.addWidget(routing)
        # DMVPN
        dmvpn = QGroupBox("DMVPN")
        self.dmvpn_box = dmvpn
        dmvpn_layout = QHBoxLayout(dmvpn)
        self.phase_combo = QComboBox()
        for phase, text in ((1, "Phase 1 (hub and spoke)"), (2, "Phase 2 (spoke to spoke)"),
                            (3, "Phase 3 (spoke to spoke, summarizable)")):
            self.phase_combo.addItem(text, phase)
        self.phase_combo.currentIndexChanged.connect(self.edited)
        dmvpn_layout.addWidget(self.phase_combo)
        dmvpn_layout.addWidget(QLabel("Network ID"))
        self.network_id_spin = QSpinBox()
        self.network_id_spin.setRange(0, 2147483647)
        self.network_id_spin.setSpecialValueText("(tunnel number)")
        self.network_id_spin.valueChanged.connect(self.edited)
        dmvpn_layout.addWidget(self.network_id_spin)
        dmvpn_layout.addWidget(QLabel("NHRP password"))
        self.nhrp_input = QLineEdit()
        self.nhrp_input.setMaxLength(8)
        self.nhrp_input.setEchoMode(QLineEdit.Password)
        self.nhrp_input.textEdited.connect(self.edited)
        dmvpn_layout.addWidget(self.nhrp_input)
        dmvpn_layout.addWidget(QLabel("Hold"))
        self.holdtime_spin = QSpinBox()
        self.holdtime_spin.setRange(0, 65535)
        self.holdtime_spin.setSuffix(" s")
        self.holdtime_spin.valueChanged.connect(self.edited)
        dmvpn_layout.addWidget(self.holdtime_spin)
        dmvpn_layout.addWidget(QLabel("Tunnel key"))
        self.tunnel_key_spin = QSpinBox()
        self.tunnel_key_spin.setRange(0, 2147483647)
        self.tunnel_key_spin.setSpecialValueText("(none)")
        self.tunnel_key_spin.valueChanged.connect(self.edited)
        dmvpn_layout.addWidget(self.tunnel_key_spin)
        editor.addWidget(dmvpn)
        editor.addStretch(1)
        layout.addWidget(self.editor, 1)
        self.editor.setVisible(False)
        scroll.setWidget(page)
        return scroll

    def make_changes_box(self):
        box = QGroupBox("Checks and Changes")
        layout = QHBoxLayout(box)
        left = QVBoxLayout()
        left.addWidget(QLabel("Checks"))
        self.findings_list = QListWidget()
        self.findings_list.setWordWrap(True)
        left.addWidget(self.findings_list, 1)
        layout.addLayout(left, 2)
        right = QVBoxLayout()
        top = QHBoxLayout()
        self.preview_combo = QComboBox()
        self.preview_combo.setToolTip("Which router's lines")
        self.preview_combo.setSizeAdjustPolicy(QComboBox.AdjustToContents)
        self.preview_combo.currentIndexChanged.connect(self.show_preview)
        top.addWidget(self.preview_combo)
        self.lines_radio = QRadioButton("Lines to send")
        self.undo_radio = QRadioButton("Lines that undo them")
        self.lines_radio.setChecked(True)
        self.lines_radio.toggled.connect(self.show_preview)
        top.addWidget(self.lines_radio)
        top.addWidget(self.undo_radio)
        self.show_keys_check = QCheckBox("Show keys")
        self.show_keys_check.toggled.connect(self.show_preview)
        top.addWidget(self.show_keys_check)
        top.addStretch(1)
        self.copy_button = QPushButton("Copy")
        self.copy_button.clicked.connect(self.copy_preview)
        top.addWidget(self.copy_button)
        self.export_button = QPushButton("Export...")
        self.export_button.clicked.connect(self.export_preview)
        top.addWidget(self.export_button)
        self.discard_button = QPushButton("Discard Changes")
        self.discard_button.clicked.connect(self.discard_changes)
        top.addWidget(self.discard_button)
        right.addLayout(top)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        right.addWidget(self.preview, 1)
        self.waiting_box = QWidget()
        waiting = QHBoxLayout(self.waiting_box)
        waiting.setContentsMargins(0, 0, 0, 0)
        self.waiting_label = QLabel()
        self.waiting_label.setWordWrap(True)
        waiting.addWidget(self.waiting_label, 1)
        self.confirm_button = accent_button("Confirm All")
        self.confirm_button.setToolTip("configure confirm on each router (from a new login, or typed into its session)")
        self.confirm_button.clicked.connect(self.confirm_waiting)
        waiting.addWidget(self.confirm_button)
        self.put_back_button = QPushButton("Put All Back Now")
        self.put_back_button.clicked.connect(self.put_back_now)
        waiting.addWidget(self.put_back_button)
        self.waiting_box.setVisible(False)
        right.addWidget(self.waiting_box)
        self.clear_box = QWidget()
        clear = QHBoxLayout(self.clear_box)
        clear.setContentsMargins(0, 0, 0, 0)
        self.clear_label = QLabel("The crypto changed: sessions up now keep the old settings until they re-key.")
        self.clear_label.setWordWrap(True)
        clear.addWidget(self.clear_label, 1)
        self.clear_button = accent_button("Clear Sessions Now...")
        self.clear_button.setToolTip("clear crypto session remote PEER on each router (they come straight back with "
                                     "the new settings; traffic drops for a moment)")
        self.clear_button.clicked.connect(self.offer_clear)
        clear.addWidget(self.clear_button)
        self.clear_dismiss_button = QPushButton("Not Now")
        self.clear_dismiss_button.clicked.connect(self.dismiss_clear)
        clear.addWidget(self.clear_dismiss_button)
        self.clear_box.setVisible(False)
        right.addWidget(self.clear_box)
        row = QHBoxLayout()
        self.revert_check = QCheckBox("Put it back after")
        self.revert_check.setChecked(True)
        self.revert_check.setToolTip("configure terminal revert timer on every router: each puts its old "
                                     "configuration back by itself unless confirmed (NOMAD sets an archive path if "
                                     "there isn't one)")
        self.revert_check.toggled.connect(self.update_buttons)
        row.addWidget(self.revert_check)
        self.minutes_input = QSpinBox()
        self.minutes_input.setRange(2, 120)
        self.minutes_input.setValue(DEFAULT_MINUTES)
        self.minutes_input.setSuffix(" min")
        row.addWidget(self.minutes_input)
        row.addWidget(QLabel("unless"))
        self.confirm_combo = QComboBox()
        self.confirm_combo.addItem("the VPN works (NOMAD confirms)", CONFIRM_AUTO)
        self.confirm_combo.addItem("I click Confirm All", CONFIRM_MANUAL)
        row.addWidget(self.confirm_combo)
        self.verify_check = QCheckBox("Check it works first")
        self.verify_check.setChecked(True)
        self.verify_check.setToolTip("Before confirming: ping across the tunnel and between the LANs from each end "
                                     "(a failure puts every router back)")
        row.addWidget(self.verify_check)
        row.addStretch(1)
        self.send_button = accent_button("Send over SSH")
        self.send_button.setToolTip("Every router's change in with the revert timer, the VPN checked from each end, "
                                    "then confirmed on all (or all put back)")
        self.send_button.clicked.connect(self.send)
        row.addWidget(self.send_button)
        self.session_button = QToolButton()
        self.session_button.setText("Send to Session")
        self.session_button.setPopupMode(QToolButton.InstantPopup)
        self.session_menu = QMenu(self.session_button)
        self.session_menu.aboutToShow.connect(self.fill_session_menu)
        self.session_button.setMenu(self.session_menu)
        row.addWidget(self.session_button)
        self.stop_button = QPushButton("Stop")
        self.stop_button.clicked.connect(self.stop)
        row.addWidget(self.stop_button)
        right.addLayout(row)
        layout.addLayout(right, 5)
        return box

    def make_status_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        top = QHBoxLayout()
        self.status_read_button = accent_button("Read Again")
        self.status_read_button.setToolTip("Read the VPNs' routers again (what's up now)")
        self.status_read_button.clicked.connect(self.refresh_status)
        top.addWidget(self.status_read_button)
        self.auto_check = QCheckBox("Every minute")
        self.auto_check.toggled.connect(self.on_auto_status)
        top.addWidget(self.auto_check)
        self.status_clear_button = QPushButton("Clear Sessions...")
        self.status_clear_button.setToolTip("clear crypto session remote PEER: the VPN's IPsec renegotiates")
        self.status_clear_button.clicked.connect(self.clear_sessions_chosen)
        top.addWidget(self.status_clear_button)
        top.addStretch(1)
        layout.addLayout(top)
        splitter = QSplitter(Qt.Horizontal)
        self.status_tree = QTreeWidget()
        self.status_tree.setHeaderLabels(VPN_COLUMNS)
        self.status_tree.setRootIsDecorated(False)
        self.status_tree.currentItemChanged.connect(self.show_status)
        splitter.addWidget(self.status_tree)
        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        self.diagnosis_list = QListWidget()
        self.diagnosis_list.setWordWrap(True)
        right_layout.addWidget(self.diagnosis_list, 3)
        right_layout.addWidget(QLabel("What the routers logged about VPNs lately"))
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(monospace_font())
        right_layout.addWidget(self.log_view, 2)
        splitter.addWidget(right)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter, 1)
        return page

    def make_library_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        about = QLabel("VPN designs kept on this PC (without their keys), to build again on other routers.")
        about.setWordWrap(True)
        layout.addWidget(about)
        self.library_table = read_only_table(LIBRARY_COLUMNS)
        self.library_table.itemSelectionChanged.connect(self.update_buttons)
        layout.addWidget(self.library_table, 1)
        row = QHBoxLayout()
        self.use_button = accent_button("Use for a New VPN...")
        self.use_button.clicked.connect(self.use_library)
        row.addWidget(self.use_button)
        self.notes_button = QPushButton("Notes...")
        self.notes_button.clicked.connect(self.edit_library_notes)
        row.addWidget(self.notes_button)
        self.library_delete_button = QPushButton("Delete")
        self.library_delete_button.clicked.connect(self.delete_library)
        row.addWidget(self.library_delete_button)
        row.addStretch(1)
        layout.addLayout(row)
        return page

    def make_history_tab(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        splitter = QSplitter(Qt.Vertical)
        self.history_table = read_only_table(HISTORY_COLUMNS)
        self.history_table.itemSelectionChanged.connect(self.on_history_selected)
        splitter.addWidget(self.history_table)
        bottom = QWidget()
        bottom_layout = QVBoxLayout(bottom)
        bottom_layout.setContentsMargins(0, 0, 0, 0)
        radios = QHBoxLayout()
        self.history_lines_radio = QRadioButton("Lines sent")
        self.history_undo_radio = QRadioButton("What undoes them")
        self.history_lines_radio.setChecked(True)
        self.history_lines_radio.toggled.connect(self.on_history_selected)
        radios.addWidget(self.history_lines_radio)
        radios.addWidget(self.history_undo_radio)
        radios.addStretch(1)
        bottom_layout.addLayout(radios)
        self.history_view = QPlainTextEdit()
        self.history_view.setReadOnly(True)
        self.history_view.setFont(monospace_font())
        bottom_layout.addWidget(self.history_view, 1)
        row = QHBoxLayout()
        self.undo_ssh_button = accent_button("Undo over SSH")
        self.undo_ssh_button.setToolTip("Send what undoes it to the router (with the revert timer when it's ticked)")
        self.undo_ssh_button.clicked.connect(self.undo_over_ssh)
        row.addWidget(self.undo_ssh_button)
        self.undo_session_button = QToolButton()
        self.undo_session_button.setText("Undo in Session")
        self.undo_session_button.setPopupMode(QToolButton.InstantPopup)
        self.undo_session_menu = QMenu(self.undo_session_button)
        self.undo_session_menu.aboutToShow.connect(self.fill_undo_session_menu)
        self.undo_session_button.setMenu(self.undo_session_menu)
        row.addWidget(self.undo_session_button)
        self.copy_undo_button = QPushButton("Copy Undo")
        self.copy_undo_button.clicked.connect(self.copy_undo)
        row.addWidget(self.copy_undo_button)
        self.forget_button = QPushButton("Forget")
        self.forget_button.clicked.connect(self.forget_history)
        row.addWidget(self.forget_button)
        row.addStretch(1)
        bottom_layout.addLayout(row)
        splitter.addWidget(bottom)
        layout.addWidget(splitter, 1)
        return page

    def focus_find(self):
        self.find_input.setFocus()

    def save_settings(self, settings):
        settings.setValue("vpns/revert", self.revert_check.isChecked())
        settings.setValue("vpns/minutes", self.minutes_input.value())
        settings.setValue("vpns/confirm", self.confirm_combo.currentData())
        settings.setValue("vpns/verify", self.verify_check.isChecked())
        self.login_row.save_settings(settings, "vpns")

    def restore_settings(self, settings):
        self.revert_check.setChecked(settings.value("vpns/revert", True, bool))
        self.minutes_input.setValue(settings.value("vpns/minutes", DEFAULT_MINUTES, int))
        index = self.confirm_combo.findData(settings.value("vpns/confirm", CONFIRM_AUTO))
        self.confirm_combo.setCurrentIndex(max(0, index))
        self.verify_check.setChecked(settings.value("vpns/verify", True, bool))
        self.login_row.restore_settings(settings, "vpns")

    def shutdown(self):
        self.tick.stop()
        self.status_timer.stop()
        self.session_sender.stop_waiting()
        for thread in (self.reader, self.sender, self.actor, self.pki):
            if thread is not None:
                thread.stop()
                release_thread(thread)
        self.reader = self.sender = self.actor = self.pki = None

    # ----------------------------------------------------------------- Routers

    def map_page(self):
        return getattr(self.window, "netmap_tab", None)

    def network_map(self):
        page = self.map_page()
        return getattr(page, "network_map", None) if page is not None else None

    def on_map_shown(self):
        keep = {key: target for key, target in self.targets.items() if target.source == "address" or key in self.read}
        targets = dict(keep)
        network_map = self.network_map()
        devices = sorted((device for device in network_map.devices.values() if device.kind in (ROUTER, SWITCH)),
                         key=lambda device: (device.kind != ROUTER, device.label.lower())) \
            if network_map is not None else []
        for device in devices:
            key = f"map:{device.key}"
            label = device.label + (f" ({device.mgmt_ip})" if device.mgmt_ip and device.mgmt_ip != device.label
                                    else "")
            names = [name for name in (device.name, *device.addresses) if name]
            targets[key] = Target(key, label, device.mgmt_ip, names, "map", device.key)
        addresses = {target.address for target in targets.values() if target.address}
        for session in (self.sessions.sessions if self.sessions is not None else []):
            if session.protocol != SSH or not session.host or session.host in addresses:
                continue
            key = f"session:{session.name}@{session.host}"
            targets[key] = Target(key, f"{session.name} ({session.host}, saved session)", session.host,
                                  [session.name], "session")
        self.targets = targets
        self.fill_routers()

    def fill_routers(self):
        chosen = set(self.chosen_keys())
        self.router_list.blockSignals(True)
        self.router_list.clear()
        order = sorted(self.targets.values(), key=lambda target: (target.key not in self.read, target.label.lower()))
        for target in order:
            device = self.read.get(target.key)
            text = target.label
            if device is not None:
                text = ("✓ " if device.read else "✗ ") + text
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, target.key)
            item.setToolTip(self.notes.get(target.key, "") or target.address)
            if device is not None and not device.read:
                item.setForeground(QColor(COLORS["error"]))
            self.router_list.addItem(item)
            item.setSelected(target.key in chosen)
        self.router_list.blockSignals(False)
        self.filter_routers(self.find_input.text())

    def filter_routers(self, text):
        words = text.lower().split()
        for row in range(self.router_list.count()):
            item = self.router_list.item(row)
            item.setHidden(not all(word in item.text().lower() for word in words))

    def add_address(self):
        address, ok = QInputDialog.getText(self, "Add a Router", "Address (or name) to log in to over SSH:")
        address = address.strip()
        if not ok or not address:
            return
        key = f"address:{address}"
        self.targets.setdefault(key, Target(key, address, address, [], "address"))
        self.fill_routers()

    def chosen_keys(self):
        return [item.data(Qt.UserRole) for item in self.router_list.selectedItems()] \
            if hasattr(self, "router_list") else []

    def title(self, key):
        target = self.targets.get(key)
        if target is not None:
            return target.label
        return key.split(":", 1)[-1]

    def device_hints(self, key):
        target = self.targets.get(key)
        if target is None or not target.address:
            return {}
        hints = {"name": target.names[0] if target.names else target.label, "aliases": list(target.names)}
        network_map, page = self.network_map(), self.map_page()
        device = network_map.devices.get(target.map_key) if network_map is not None and target.map_key else None
        if device is not None and page is not None and hasattr(page, "session_hints"):
            hints = page.session_hints(network_map, device)
        return dict(hints, address=target.address)

    # ----------------------------------------------------------------- Reading

    def logins(self):
        return self.login_row.logins(self.status_label)

    def pusher_maker(self, logins):
        return self.login_row.pusher_maker(logins, self.shell_factory)

    def busy(self):
        return any(thread is not None for thread in (self.reader, self.sender, self.actor, self.pki))

    def read_chosen(self, *_):
        keys = self.chosen_keys()
        if not keys:
            set_hint(self.status_label, "Pick the routers to read.", "warning")
            return
        self.start_read(keys)

    def start_read(self, keys, then=None, logins=None):
        if self.busy():
            return False
        edited = [vpn_id for vpn_id in self.drafts if self.changes_for(vpn_id) and any(
            member.key in keys for member in self.members_of(vpn_id))]
        if edited and then is None and QMessageBox.question(
                self, "Read Again", "Reading again drops changes not sent yet on VPNs these routers are in. Read "
                                    "anyway?") != QMessageBox.Yes:
            return False
        logins = logins or self.saved_logins or self.logins()
        if logins is None:
            return False
        self.saved_logins = logins
        targets = []
        for key in keys:
            target = self.targets.get(key)
            if target is None:
                continue
            pc_ip = local_address_toward(target.address) if target.address else ""
            targets.append((key, target.address, target.names, pc_ip))
        if not targets:
            return False
        self.after_read = then
        self.reader = ReadThread(targets, self.pusher_maker(logins), self)
        self.reader.device_read.connect(self.on_device_read)
        self.reader.finished.connect(self.on_read_finished)
        self.reader.start()
        set_hint(self.status_label, f"Reading {len(targets)} router(s) over SSH...", "info")
        self.set_busy("Reading VPNs")
        self.update_buttons()
        return True

    def on_device_read(self, key, device):
        self.read[key] = device
        if device.read:
            tunnels = len(device.tunnel_numbers())
            self.notes[key] = f"Read at {device.when[11:16]}: {tunnels} tunnel interface(s)."
        else:
            self.notes[key] = f"Couldn't read it: {device.problem}"

    def on_read_finished(self):
        reader, self.reader = self.reader, None
        if reader is not None:
            reader.deleteLater()
        self.clear_busy()
        problems = [f"{self.title(key)}: {device.problem}" for key, device in self.read.items()
                    if not device.read and key in self.targets]
        self.refind()
        self.fill_routers()
        then, self.after_read = self.after_read, None
        if problems:
            set_hint(self.status_label, "Couldn't read " + "; ".join(problems[:3]), "error")
        else:
            set_hint(self.status_label, f"Read. {len(self.found)} VPN(s) on the routers read.", "success")
        if then is not None:
            then()
        elif self.pending_new is not None:
            pending, self.pending_new = self.pending_new, None
            self.make_new(*pending)
        self.update_buttons()

    def reads(self):
        found = []
        for key, device in self.read.items():
            if device.read:
                target = self.targets.get(key)
                found.append(vpnfind.Read(key, target.label if target is not None else device.hostname,
                                          target.address if target is not None else "", device))
        return found

    def refind(self):
        """The VPNs on the routers read, found again (drafts of VPNs being edited kept)."""
        self.found = vpnfind.find(self.reads())
        for item in self.found:
            for member in item.members:
                if member.key in self.targets:
                    member.label = self.targets[member.key].label.split(" (")[0]
            item.id = self.known_id(item)
            kept = self.store.design(item.id)
            if kept is not None and not item.auth.psk:
                item.auth.psk = kept.auth.psk
        known = {item.id for item in self.found}
        for vpn_id in list(self.originals):
            if self.originals[vpn_id] is not None and vpn_id not in known and self.drafts.get(vpn_id) is not None:
                self.originals[vpn_id] = None  # Gone from the routers (put back?): what's left is a new design
            elif self.originals[vpn_id] is not None and vpn_id in known:
                found = next(item for item in self.found if item.id == vpn_id)
                if not self.changes_for(vpn_id):
                    self.drafts.pop(vpn_id, None)
                self.originals[vpn_id] = found
        for vpn_id in [vpn_id for vpn_id, draft in self.drafts.items()
                       if draft is not None and self.originals.get(vpn_id) is None and vpn_id in known]:
            self.drafts.pop(vpn_id)  # A new one now on the routers
            self.originals[vpn_id] = next(item for item in self.found if item.id == vpn_id)
        self.fill_vpns()
        self.fill_status()

    def known_id(self, item):
        """A found VPN's id: that of the design it was built from (a draft sent from here, or one kept in the store),
        so it's the same VPN before and after it's sent; else the id it was found with."""
        members = sorted(member.key for member in item.members)

        def same(design):
            return design is not None and design.name == item.name and design.kind == item.kind and \
                sorted(member.key for member in design.members) == members
        for vpn_id, draft in self.drafts.items():
            if self.originals.get(vpn_id) is None and same(draft):
                return vpn_id
        for vpn_id in self.waiting:
            original = self.originals.get(vpn_id)
            if same(original) or same(self.drafts.get(vpn_id)):
                return vpn_id
        for vpn_id, data in self.store.designs.items():
            if data.get("name") == item.name and data.get("kind") == item.kind and \
                    sorted(member.get("key", "") for member in data.get("members", [])) == members:
                return vpn_id
        return item.id

    # ----------------------------------------------------------------- The VPNs

    def vpn_ids(self):
        ids = [item.id for item in self.found]
        ids += [vpn_id for vpn_id in self.drafts if vpn_id not in ids]
        return ids

    def original(self, vpn_id):
        return next((item for item in self.found if item.id == vpn_id), None) if vpn_id not in self.originals \
            else self.originals[vpn_id]

    def design(self, vpn_id=None):
        """The VPN as edited (or as found), or None (to be taken away, or none chosen)."""
        vpn_id = vpn_id or self.current_id
        if vpn_id in self.drafts:
            return self.drafts[vpn_id]
        return self.original(vpn_id)

    def members_of(self, vpn_id):
        items = [self.drafts.get(vpn_id), self.original(vpn_id)]
        found = []
        for item in items:
            if item is not None:
                found += [member for member in item.members if member.key not in [m.key for m in found]]
        return found

    def devices(self):
        return {key: device for key, device in self.read.items() if device.read}

    def changes_for(self, vpn_id):
        """{key: MemberChange} with lines, for a VPN as edited ({} when it's as found)."""
        if vpn_id not in self.drafts:
            return {}
        before, after = self.original(vpn_id), self.drafts[vpn_id]
        try:
            changes = vpn.vpn_changes(before, after, self.devices(), self.siblings(vpn_id))
        except Exception:
            log.exception("Planning a VPN change failed")
            return {}
        return {key: change for key, change in changes.items() if change.lines}

    def siblings(self, vpn_id):
        """Tunnel blocks other VPNs being made put on each router (a second DMVPN cloud on the same WAN needs a tunnel
        key)."""
        found = {}
        for other_id, draft in self.drafts.items():
            if other_id == vpn_id or draft is None or self.original(other_id) is not None:
                continue
            for member in draft.members:
                device = self.read.get(member.key)
                if device is None:
                    continue
                for block in vpn.footprint(draft, member, device):
                    if block.line.startswith("interface Tunnel"):
                        found.setdefault(member.key, []).append(block)
        return found

    def fill_vpns(self):
        current = self.current_id
        self.vpn_tree.blockSignals(True)
        self.vpn_tree.clear()
        devices = self.devices()
        chosen = None
        for vpn_id in self.vpn_ids():
            item_vpn = self.design(vpn_id) or self.original(vpn_id)
            if item_vpn is None:
                continue
            original = self.original(vpn_id)
            state = vpnstatus.vpn_state(original, devices) if original is not None else UNKNOWN
            name = item_vpn.name
            if vpn_id in self.drafts and self.drafts[vpn_id] is None:
                name += "   [to take away]"
            elif original is None:
                name += "   [new]"
            elif self.changes_for(vpn_id):
                name += "   [changed]"
            if vpn_id in self.waiting:
                name += f"   [to confirm by {self.waiting[vpn_id].at}]"
            routers = ", ".join(member.title() for member in item_vpn.members)
            item = QTreeWidgetItem([name, vpn.kind_text(item_vpn), routers,
                                    STATE_TEXT[state] if original is not None else "Not sent"])
            item.setData(0, Qt.UserRole, vpn_id)
            item.setForeground(3, QColor(COLORS[STATE_COLOR[state]] if original is not None else COLORS["muted"]))
            if vpn_id in self.drafts:
                item.setForeground(0, QColor(COLORS["accent"]))
            self.vpn_tree.addTopLevelItem(item)
            if vpn_id == current:
                chosen = item
        for column in range(len(VPN_COLUMNS)):
            self.vpn_tree.resizeColumnToContents(column)
        if chosen is not None:
            self.vpn_tree.setCurrentItem(chosen)
        self.vpn_tree.blockSignals(False)
        if chosen is None and current:
            self.current_id = ""
        self.show_design()

    def on_vpn_chosen(self, item, *_):
        self.current_id = item.data(0, Qt.UserRole) if item is not None else ""
        self.show_design()

    def show_vpn_menu(self, position):
        item = self.vpn_tree.itemAt(position)
        if item is None:
            return
        menu = QMenu(self)
        menu.addAction("Status...", lambda: self.tabs.setCurrentIndex(1))
        menu.addAction("Read Its Routers Again", lambda: self.start_read([m.key for m in self.members_of(
            self.current_id) if m.key in self.targets]))
        menu.addSeparator()
        menu.addAction("Take Away...", self.take_away_vpn)
        menu.addAction("Save to Library", self.save_to_library)
        menu.exec_(self.vpn_tree.viewport().mapToGlobal(position))

    def editable(self):
        """The chosen VPN's draft (made from what was found the first time it's edited), or None."""
        vpn_id = self.current_id
        if not vpn_id:
            return None
        if vpn_id not in self.drafts:
            original = self.original(vpn_id)
            if original is None:
                return None
            self.drafts[vpn_id] = original.copy()
            self.originals[vpn_id] = original
        return self.drafts[vpn_id]

    # ----------------------------------------------------------------- The editor

    def show_design(self):
        design = self.design()
        self.editor.setVisible(design is not None)
        self.empty_label.setVisible(design is None)
        if design is None:
            if self.current_id in self.drafts:
                self.empty_label.setText("This VPN is to be taken away from its routers: Send to do it, or Discard "
                                         "Changes.")
            else:
                self.empty_label.setText("Read routers, then pick a VPN they have, or New VPN.")
        else:
            self.filling = True
            try:
                self.fill_form(design)
            finally:
                self.filling = False
        self.refresh_changes()

    def fill_form(self, design):
        self.name_input.setText(design.name)
        self.kind_combo.setCurrentIndex(max(0, self.kind_combo.findData(design.kind)))
        self.kind_combo.setEnabled(self.original(self.current_id) is None)
        self.subnet_input.setText(design.subnet)
        self.mtu_spin.setValue(design.mtu)
        self.mss_spin.setValue(design.mss)
        self.keepalive_spin.setValue(design.keepalive)
        tunnelled = design.kind != vpn.CRYPTO_MAP
        for widget in (self.subnet_input, self.subnet_label, self.suggest_button, self.ipam_button, self.mtu_spin,
                       self.mss_spin, self.sizes_label):
            widget.setVisible(tunnelled)
        self.keepalive_spin.setVisible(design.kind == vpn.GRE)
        self.keepalive_label.setVisible(design.kind == vpn.GRE)
        self.fill_members(design)
        self.auth_box.setVisible(design.protected)
        self.crypto_box.setVisible(design.protected)
        self.psk_radio.setChecked(design.auth.method == vpn.PSK)
        self.cert_radio.setChecked(design.auth.method == vpn.CERT)
        self.psk_input.setText(design.auth.psk)
        self.ca_combo.setCurrentIndex(max(0, self.ca_combo.findData(design.auth.ca_kind or "router")))
        self.ca_device_combo.clear()
        for member in design.members:
            if not member.key.startswith("peer:"):
                self.ca_device_combo.addItem(member.title(), member.key)
        self.ca_device_combo.setCurrentIndex(max(0, self.ca_device_combo.findData(design.auth.ca_device)))
        self.ca_name_input.setText(design.auth.ca_name)
        self.ca_url_input.setText(design.auth.ca_url)
        self.fingerprint_input.setText(design.auth.ca_fingerprint)
        self.trustpoint_input.setText(vpn.names(design, design.members[0])["trustpoint"] if design.members else "")
        self.revocation_combo.setCurrentIndex(max(0, self.revocation_combo.findData(design.auth.revocation)))
        crypto = design.crypto
        self.preset_combo.setCurrentIndex(max(0, self.preset_combo.findData(crypto.preset)))
        self.ike_combo.setCurrentIndex(max(0, self.ike_combo.findData(crypto.ike)))
        self.encryption_input.setText(" ".join(crypto.encryption))
        self.integrity_input.setText(" ".join(crypto.integrity))
        self.prf_input.setText(" ".join(crypto.prf))
        self.groups_input.setText(" ".join(str(group) for group in crypto.groups))
        self.esp_combo.setCurrentText(crypto.esp)
        self.pfs_combo.setCurrentIndex(max(0, self.pfs_combo.findData(crypto.pfs)))
        self.dpd_spin.setValue(crypto.dpd)
        self.nat_spin.setValue(crypto.nat_keepalive)
        self.routing_combo.setCurrentIndex(max(0, self.routing_combo.findData(design.routing.kind)))
        self.process_input.setText(design.routing.process)
        self.area_input.setText(design.routing.area)
        self.eigrp_name_input.setText(design.routing.eigrp_name)
        self.guard_check.setChecked(design.routing.guard)
        self.dmvpn_box.setVisible(design.kind == vpn.DMVPN)
        self.phase_combo.setCurrentIndex(max(0, self.phase_combo.findData(design.dmvpn.phase)))
        self.network_id_spin.setValue(design.dmvpn.network_id)
        self.nhrp_input.setText(design.dmvpn.auth)
        self.holdtime_spin.setValue(design.dmvpn.holdtime)
        self.tunnel_key_spin.setValue(design.dmvpn.tunnel_key)
        self.show_auth_fields()

    def show_auth_fields(self):
        cert = self.cert_radio.isChecked()
        kind = self.ca_combo.currentData()
        for widget in (self.psk_input, self.show_key_check, self.generate_button):
            widget.setEnabled(not cert)
        self.ca_combo.setEnabled(cert)
        self.ca_device_combo.setEnabled(cert and kind == "router")
        self.ca_url_input.setEnabled(cert and kind == "scep")
        self.fingerprint_input.setEnabled(cert and kind in ("scep", "paste"))
        for widget in (self.ca_name_input, self.trustpoint_input, self.revocation_combo, self.certs_button):
            widget.setEnabled(cert)
        self.certs_button.setText("Certificates by Hand..." if kind == "paste" else "Get Certificates")

    def fill_members(self, design):
        self.member_table.setRowCount(len(design.members))
        for row, member in enumerate(design.members):
            cells = [member.title(), vpn.ROLE_NAMES.get(member.role, member.role), member.wan, member.local_ip,
                     member.public_ip, f"Tunnel{member.tunnel}" if member.tunnel and design.kind != vpn.CRYPTO_MAP
                     else "", member.tunnel_ip, ", ".join(member.lans), member.bgp_as]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, member.key)
                if member.key.startswith("peer:"):
                    cell.setForeground(QColor(COLORS["muted"]))
                    cell.setToolTip("Not read: only its address is known (nothing is sent to it)")
                self.member_table.setItem(row, column, cell)
        self.member_table.setColumnHidden(1, design.kind != vpn.DMVPN)
        for column in (5, 6):
            self.member_table.setColumnHidden(column, design.kind == vpn.CRYPTO_MAP)
        self.member_table.setColumnHidden(8, design.routing.kind != vpn.BGP)
        self.member_table.resizeColumnsToContents()

    def form_to_design(self, design):
        design.name = self.name_input.text().strip() or design.name
        design.kind = self.kind_combo.currentData()
        design.subnet = self.subnet_input.text().strip()
        design.mtu, design.mss, design.keepalive = self.mtu_spin.value(), self.mss_spin.value(), \
            self.keepalive_spin.value()
        auth = design.auth
        auth.method = vpn.CERT if self.cert_radio.isChecked() else vpn.PSK
        auth.psk = self.psk_input.text()
        auth.ca_kind = self.ca_combo.currentData() if auth.method == vpn.CERT else auth.ca_kind
        auth.ca_device = self.ca_device_combo.currentData() or ""
        auth.ca_name = self.ca_name_input.text().strip()
        auth.ca_url = self.ca_url_input.text().strip()
        auth.ca_fingerprint = self.fingerprint_input.text().strip()
        auth.trustpoint = self.trustpoint_input.text().strip()
        auth.revocation = self.revocation_combo.currentData()
        crypto = design.crypto
        crypto.preset = self.preset_combo.currentData()
        crypto.ike = self.ike_combo.currentData()
        crypto.encryption = self.split_ike(self.encryption_input.text(), crypto.ike)
        crypto.integrity = self.integrity_input.text().split()
        crypto.prf = self.prf_input.text().split()
        crypto.groups = [int(item) for item in self.groups_input.text().split() if item.isdigit()]
        crypto.esp = " ".join(self.esp_combo.currentText().split())
        crypto.pfs = self.pfs_combo.currentData() or 0
        crypto.dpd = self.dpd_spin.value()
        crypto.nat_keepalive = self.nat_spin.value()
        routing = design.routing
        routing.kind = self.routing_combo.currentData()
        routing.process = self.process_input.text().strip()
        routing.area = self.area_input.text().strip() or "0"
        routing.eigrp_name = self.eigrp_name_input.text().strip()
        routing.guard = self.guard_check.isChecked()
        settings = design.dmvpn
        settings.phase = self.phase_combo.currentData()
        settings.network_id = self.network_id_spin.value()
        settings.auth = self.nhrp_input.text()
        settings.holdtime = self.holdtime_spin.value()
        settings.tunnel_key = self.tunnel_key_spin.value()

    @staticmethod
    def split_ike(text, ike):
        words = text.split()
        if ike == vpn.IKEV1:
            return [" ".join(words)] if words else []
        return words

    def edited(self, *_):
        if self.filling:
            return
        design = self.editable()
        if design is None:
            return
        self.form_to_design(design)
        self.show_auth_fields()
        self.fill_members(design)
        self.refresh_changes()
        self.mark_current()

    def mark_current(self):
        item = self.vpn_tree.currentItem()
        if item is None:
            return
        design = self.design()
        original = self.original(self.current_id)
        name = design.name if design is not None else (original.name if original else "")
        if design is None:
            name += "   [to take away]"
        elif original is None:
            name += "   [new]"
        elif self.changes_for(self.current_id):
            name += "   [changed]"
        item.setText(0, name)
        item.setForeground(0, QColor(COLORS["accent"] if self.changes_for(self.current_id) or original is None
                                     else COLORS["text"]))

    def on_kind_changed(self, *_):
        if self.filling:
            return
        design = self.editable()
        if design is None:
            return
        kind = self.kind_combo.currentData()
        if kind == design.kind:
            return
        design.kind = kind
        if kind in vpn.POINT_TO_POINT and len(design.members) > 2:
            design.members = design.members[:2]
        for member in design.members:
            member.role = vpn.PEER if kind != vpn.DMVPN else (member.role if member.role != vpn.PEER else vpn.SPOKE)
        if kind == vpn.DMVPN and not design.hubs() and design.members:
            design.members[0].role = vpn.HUB
        if kind != vpn.CRYPTO_MAP:
            self.suggest_subnet(force=True)
        self.show_design()

    def on_subnet_changed(self):
        if self.filling:
            return
        design = self.editable()
        if design is None:
            return
        subnet = self.subnet_input.text().strip()
        if subnet == design.subnet:
            return
        design.subnet = subnet
        for member in design.members:
            if member.tunnel_ip and not vpn.in_subnet(member.tunnel_ip, subnet):
                member.tunnel_ip = ""
        vpn.assign_addresses(design)
        self.show_design()

    def suggest_subnet(self, *_, force=False):
        design = self.editable()
        if design is None:
            return
        devices = [self.read.get(member.key) for member in design.members]
        taken = [item.subnet for item in self.found if item.subnet and item.id != design.id]
        taken += [draft.subnet for draft in self.drafts.values() if draft is not None and draft.id != design.id and
                  draft.subnet]
        design.subnet = vpn.suggest_subnet(design, devices, taken)
        for member in design.members:
            member.tunnel_ip = ""
        vpn.assign_addresses(design)
        self.show_design()

    def subnet_from_ipam(self):
        design = self.editable()
        ipam = getattr(self.window, "ipam_tab", None)
        store = getattr(ipam, "live_store", None) if ipam is not None else None
        if design is None or store is None:
            set_hint(self.status_label, "Open a network on the IP Addresses page first.", "warning")
            return
        if hasattr(ipam, "can_edit") and not ipam.can_edit():
            set_hint(self.status_label, "The IP Addresses page can't change that network now (a tribe network needs "
                                        "its server).", "warning")
            return
        length = 30 if design.kind in vpn.POINT_TO_POINT else 24
        dialog = IpamBlockDialog(self, store, length, design.name)
        if not dialog.exec_() or not dialog.block:
            return
        if QMessageBox.question(self, "Tunnel Subnet", f"Add {dialog.block} ({dialog.name_input.text()}) to the IP "
                                                        f"Addresses page and use it for {design.name}?") \
                != QMessageBox.Yes:
            return
        try:
            store.add_subnet(dialog.network_id(), dialog.block, name=dialog.name_input.text().strip(),
                             description=f"Tunnel subnet of VPN {design.name} (NOMAD)")
        except Exception as error:
            set_hint(self.status_label, f"Couldn't add it on the IP Addresses page: {error}", "error")
            return
        refresh = getattr(ipam, "refresh", None)
        if callable(refresh):
            refresh()
        design.subnet = dialog.block
        for member in design.members:
            member.tunnel_ip = ""
        vpn.assign_addresses(design)
        self.show_design()
        set_hint(self.status_label, f"{dialog.block} added on the IP Addresses page and used for the tunnels.",
                 "success")

    def on_auth_method(self, *_):
        self.show_auth_fields()
        self.edited()

    def generate_key(self):
        self.psk_input.setText(vpn.new_key())
        self.show_key_check.setChecked(True)
        self.edited()

    def on_preset(self, *_):
        if self.filling:
            return
        design = self.editable()
        name = self.preset_combo.currentData()
        if design is None or name == vpn.CUSTOM:
            self.edited()
            return
        chosen = vpn.preset(name)
        chosen.dpd, chosen.nat_keepalive = design.crypto.dpd, design.crypto.nat_keepalive
        design.crypto = chosen
        self.show_design()

    def on_custom_crypto(self, *_):
        if self.filling:
            return
        self.filling = True
        self.preset_combo.setCurrentIndex(self.preset_combo.findData(vpn.CUSTOM))
        self.filling = False
        self.edited()

    # ----------------------------------------------------------------- Routers in a VPN

    def selected_member(self):
        rows = sorted({index.row() for index in self.member_table.selectedIndexes()})
        design = self.design()
        if not rows or design is None or rows[0] >= len(design.members):
            return None
        return design.members[rows[0]]

    def edit_member(self, *_):
        design = self.editable()
        member = self.selected_member()
        if design is None or member is None:
            return
        if member.key.startswith("peer:"):
            set_hint(self.status_label, f"{member.title()} wasn't read: add it as a router (Add Address...) and read "
                                        "it to change its side.", "warning")
            return
        dialog = MemberDialog(self, design, member, self.read.get(member.key))
        if dialog.exec_():
            dialog.apply(member)
            self.show_design()

    def add_member(self):
        design = self.editable()
        if design is None:
            return
        if design.kind in vpn.POINT_TO_POINT + (vpn.CRYPTO_MAP,) and len(design.members) >= 2:
            set_hint(self.status_label, "This kind joins two routers: make a DMVPN for more.", "warning")
            return
        have = {member.key for member in design.members}
        choices = [(key, self.title(key)) for key, device in self.read.items() if device.read and key not in have]
        if not choices:
            set_hint(self.status_label, "Read the router to add first.", "warning")
            return
        dialog = ChoiceDialog(self, "Add Routers", f"Routers to add to {design.name}:", choices)
        if not dialog.exec_():
            return
        for key in dialog.chosen():
            design.members.append(self.new_member(design, key, vpn.SPOKE if design.kind == vpn.DMVPN else vpn.PEER))
        vpn.assign_addresses(design)
        self.show_design()

    def remove_member(self):
        design = self.editable()
        member = self.selected_member()
        if design is None or member is None:
            return
        design.members = [item for item in design.members if item.key != member.key]
        self.show_design()

    def new_member(self, design, key, role, peers=()):
        """A router's part in a VPN, filled in from what was read: its WAN toward the others (peers: the keys of
        every router going in, when they're all added at once), its tunnel number."""
        device = self.read.get(key)
        target = self.targets.get(key)
        member = vpn.Member(key, target.label.split(" (")[0] if target else key, target.address if target else "",
                            role)
        member.bgp_as = device.bgp_as() if device is not None else ""
        toward = set(peers) | {item.key for item in design.members}
        others = [self.read.get(other) for other in sorted(toward) if other != key]
        toward = vpn.wan_between(device, others)
        wans = vpn.wan_choices(device)
        if not toward and wans:
            default = device.route_to("0.0.0.0")
            toward = vpn.full_interface(default.interfaces[0]) if default is not None and default.interfaces else \
                wans[0][0]
        member.wan = toward
        member.local_ip = device.interface_address(toward)[0] if device is not None and toward else ""
        if design.members and design.members[0].tunnel:
            number = design.members[0].tunnel
            member.tunnel = number if device is None or number not in device.tunnel_numbers() else \
                vpn.suggest_tunnel([device], number)
        else:
            member.tunnel = vpn.suggest_tunnel([device], 100 if design.kind == vpn.DMVPN else 10)
        return member

    # ----------------------------------------------------------------- New VPNs

    def new_vpn(self, *_, chosen=None, name="", kind=vpn.VTI):
        routers = [(key, self.title(key)) for key, target in sorted(self.targets.items(),
                                                                    key=lambda item: item[1].label.lower())]
        chosen = chosen if chosen is not None else self.chosen_keys()
        dialog = NewVpnDialog(self, routers, chosen, name, kind)
        if not dialog.exec_():
            return
        picks = dialog.chosen()
        unread = [key for key, _ in picks if key not in self.read or not self.read[key].read]
        if unread:
            self.pending_new = (dialog.name(), dialog.kind(), picks)
            self.start_read(unread)
            return
        self.make_new(dialog.name(), dialog.kind(), picks)

    def make_new(self, name, kind, picks, template=None):
        missing = [key for key, _ in picks if key not in self.read or not self.read[key].read]
        if missing:
            set_hint(self.status_label, f"Couldn't read {', '.join(self.title(key) for key in missing)}: the VPN "
                                        "needs its routers read.", "error")
            return
        design = template.copy() if template is not None else vpn.Vpn(name=name, kind=kind)
        if template is not None:
            design.id = vpn.Vpn().id
            design.name, design.kind, design.found = name, kind, False
            design.members = []
        if kind == vpn.CRYPTO_MAP:
            design.crypto = vpn.preset(vpn.COMPATIBLE) if template is None else design.crypto
        keys = {key for key, _ in picks}
        cloud = next((item for item in self.found if kind == vpn.DMVPN and item.kind == vpn.DMVPN and
                      keys & {member.key for member in item.members} and item.auth.psk), None)
        if cloud is not None and template is None:  # A second cloud: IOS needs the same key on a shared WAN link
            design.crypto, design.auth = copy.deepcopy(cloud.crypto), copy.deepcopy(cloud.auth)
            design.dmvpn.auth = cloud.dmvpn.auth
            design.routing = copy.deepcopy(cloud.routing)
        design.auth.psk = design.auth.psk or vpn.new_key()
        if kind == vpn.DMVPN and not design.dmvpn.auth:
            design.dmvpn.auth = vpn.new_key(8)
        hub_number = 1
        for key, role in sorted(picks, key=lambda pick: pick[1] != vpn.HUB):
            member = self.new_member(design, key, role, peers=keys)
            if role == vpn.HUB:
                member.hub_order = hub_number
                hub_number += 1
            design.members.append(member)
        number = vpn.suggest_tunnel([self.read[key] for key, _ in picks], 100 if kind == vpn.DMVPN else 10)
        for member in design.members:
            member.tunnel = number
        if kind != vpn.CRYPTO_MAP:
            taken = [item.subnet for item in self.found if item.subnet]
            design.subnet = vpn.suggest_subnet(design, [self.read[key] for key, _ in picks], taken)
            vpn.assign_addresses(design)
        if kind == vpn.CRYPTO_MAP:
            design.routing.kind = vpn.STATIC
        self.drafts[design.id] = design
        self.originals[design.id] = None
        self.current_id = design.id
        self.tabs.setCurrentIndex(0)
        self.fill_vpns()
        set_hint(self.status_label, f"{design.name}: add each router's LANs (Edit...), check the settings, then "
                                    f"Send.", "info")

    def take_away_vpn(self):
        vpn_id = self.current_id
        original = self.original(vpn_id)
        if not vpn_id:
            return
        if original is None:
            self.drafts.pop(vpn_id, None)
            self.originals.pop(vpn_id, None)
            self.current_id = ""
            self.fill_vpns()
            return
        if QMessageBox.question(self, "Take Away", f"Plan taking {original.name} off its routers? (Nothing is sent "
                                                   f"until Send.)") != QMessageBox.Yes:
            return
        self.drafts[vpn_id] = None
        self.originals[vpn_id] = original
        self.fill_vpns()

    def discard_changes(self):
        vpn_id = self.current_id
        if vpn_id in self.drafts:
            self.drafts.pop(vpn_id)
            if self.originals.get(vpn_id) is None:
                self.originals.pop(vpn_id, None)
                self.current_id = ""
        self.fill_vpns()

    # ----------------------------------------------------------------- Checks and changes

    def refresh_changes(self, *_):
        vpn_id = self.current_id
        self.findings_list.clear()
        design = self.design()
        original = self.original(vpn_id)
        devices = self.devices()
        findings = []
        if design is not None:
            others = [item for item in self.found if item.id != vpn_id]
            pc_ip = next((device.pc_ip for device in devices.values() if device.pc_ip), "")
            findings = vpncheck.check(design, devices, others, pc_ip)
        elif original is not None and vpn_id in self.drafts:
            findings = [vpnstatus.Finding(INFO, f"Taking {original.name} away from {len(original.members)} "
                                                f"router(s).")]
        for finding in findings:
            item = QListWidgetItem(finding.text)
            item.setForeground(QColor(COLORS[SEVERITY_COLOR.get(finding.severity, "muted")]))
            item.setToolTip(finding.text)
            self.findings_list.addItem(item)
        if not findings and design is not None:
            self.findings_list.addItem(QListWidgetItem("Nothing to say."))
        self.current_findings = findings
        changes = self.changes_for(vpn_id)
        self.preview_combo.blockSignals(True)
        current = self.preview_combo.currentData()
        self.preview_combo.clear()
        if len(changes) > 1:
            self.preview_combo.addItem("Every router", "")
        for key in changes:
            self.preview_combo.addItem(self.title(key), key)
        at = self.preview_combo.findData(current)
        self.preview_combo.setCurrentIndex(max(0, at))
        self.preview_combo.blockSignals(False)
        self.show_preview()
        self.show_waiting()
        self.update_buttons()

    def preview_text(self, undo=None, reveal=None):
        changes = self.changes_for(self.current_id)
        key = self.preview_combo.currentData()
        undo = self.undo_radio.isChecked() if undo is None else undo
        reveal = self.show_keys_check.isChecked() if reveal is None else reveal
        parts = []
        for item_key, change in changes.items():
            if key and item_key != key:
                continue
            text = change.undo_text() if undo else change.text(self.revert_minutes())
            parts.append((f"! {self.title(item_key)}\n" if not key else "") + text)
        text = "\n\n".join(parts)
        return text if reveal else vpn.mask(text)

    def show_preview(self, *_):
        self.preview.setPlainText(self.preview_text())
        self.update_buttons()

    def copy_preview(self):
        QApplication.clipboard().setText(self.preview.toPlainText())
        set_hint(self.status_label, "Copied" + (" (keys hidden: tick Show keys to copy them)."
                                                if not self.show_keys_check.isChecked() else "."), "success")

    def export_preview(self):
        design = self.design() or self.original(self.current_id)
        name = design.name if design is not None else "vpn"
        path, _ = QFileDialog.getSaveFileName(self, "Export the Changes", f"{name}.txt", "Text (*.txt)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(self.preview.toPlainText() + "\n")
        except OSError as error:
            set_hint(self.status_label, f"Couldn't save it: {error}", "error")
            return
        set_hint(self.status_label, f"Saved to {path}.", "success")

    def revert_minutes(self):
        return self.minutes_input.value() if self.revert_check.isChecked() else 0

    def blocked(self, vpn_id):
        """Why the VPN can't be sent now ("" if it can)."""
        changes = self.changes_for(vpn_id)
        if not changes:
            return "Nothing to send."
        errors = [finding for finding in getattr(self, "current_findings", []) if finding.severity == ERROR]
        if errors and vpn_id == self.current_id:
            return f"Fix this first: {errors[0].text}"
        missing = [key for key in changes if key not in self.targets or not self.targets[key].address]
        if missing:
            return f"NOMAD doesn't know how to reach {', '.join(missing)}."
        design = self.design(vpn_id)
        if design is not None and design.protected and design.auth.method == vpn.CERT:
            lacking = [member.title() for member in design.members if member.key in self.read and
                       not vpnpki.has_certificate(design, member, self.read[member.key])]
            if lacking:
                return f"Get certificates first: {', '.join(lacking)} {'has' if len(lacking) == 1 else 'have'} none " \
                       f"in the trustpoint yet."
        return ""

    # ----------------------------------------------------------------- Sending

    def jobs(self, vpn_id):
        design = self.design(vpn_id)
        checking = design if design is not None else None
        devices = self.devices()
        jobs = []
        changes = self.changes_for(vpn_id)
        order = list(changes)
        if checking is not None:  # Spokes and peers first, hubs last (a hub is often on the way to the rest)
            order.sort(key=lambda key: checking.member(key) is not None and checking.member(key).role == vpn.HUB)
        for key in order:
            change = changes[key]
            target = self.targets[key]
            member = checking.member(key) if checking is not None else None
            checks = vpn.verify_commands(checking, member, devices_after_with(checking, self.original(vpn_id),
                                                                              devices)) \
                if checking is not None and member is not None else []
            jobs.append(MemberJob(key, target.address, list(target.names), target.label, change.text(
                self.revert_minutes()), change.undo_text(), checks))
        return jobs

    def send(self):
        vpn_id = self.current_id
        if self.busy() or not vpn_id:
            return
        why = self.blocked(vpn_id)
        if why:
            set_hint(self.status_label, why, "error")
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        jobs = self.jobs(vpn_id)
        names = ", ".join(job.title for job in jobs)
        minutes = self.revert_minutes()
        how = (f"each with a {minutes}-minute revert timer, " if minutes else "without a revert timer, ") + \
            ("checked from each end, then confirmed" if self.verify_check.isChecked() else "then confirmed")
        design = self.design(vpn_id) or self.original(vpn_id)
        if QMessageBox.question(self, "Send", f"Send {design.name} to {names}, {how}?") != QMessageBox.Yes:
            return
        self.sending = (vpn_id, jobs, minutes)
        self.sender = SendThread(jobs, self.pusher_maker(logins), minutes,
                                 self.confirm_combo.currentData() != CONFIRM_MANUAL,
                                 self.verify_check.isChecked(), self)
        self.sender.progress.connect(lambda text: set_hint(self.status_label, text, "info"))
        self.sender.done.connect(self.on_sent)
        self.sender.start()
        self.set_busy("Sending a VPN")
        self.update_buttons()

    def on_sent(self, result):
        thread, self.sender = self.sender, None
        if thread is not None:
            thread.wait(2000)
            thread.deleteLater()
        self.clear_busy()
        vpn_id, jobs, minutes = self.sending
        design = self.design(vpn_id)
        original = self.original(vpn_id)
        name = (design or original).name if (design or original) else "VPN"
        entries = {}
        for job in jobs:
            outcome = result.outcomes.get(job.key)
            if outcome is None:
                continue
            if result.archive.get(job.key):
                outcome += f" (NOMAD set archive path {result.archive[job.key]} for the revert timer)"
            entry = self.store.record(name, job.title, job.address, job.text, job.undo, "SSH", outcome)
            entries[job.key] = entry.id
            self.notes[job.key] = outcome
        for key, command, passed, answer, meaning in result.checks:
            log.info("VPN %s check on %s: %s -> %s", name, key, command, "passed" if passed else "failed")
        if design is not None and design.auth.psk:
            self.store.remember(design)
        if result.ok and result.waiting:
            self.waiting[vpn_id] = Waiting(result.deadline, list(result.sent), entries)
            self.tick.start()
            set_hint(self.status_label, f"{name} is in and works from each end. Confirm All to keep it (the routers "
                                        f"put it back at {self.waiting[vpn_id].at} otherwise).", "warning")
        elif result.ok:
            set_hint(self.status_label, f"{name} is in, works from each end, and is confirmed. Reading the routers "
                                        f"again...", "success")
            self.offer_clear_after(vpn_id)
        else:
            text = f"Not done: {result.problem} " + " ".join(
                f"{self.title(key)}: {outcome}." for key, outcome in result.outcomes.items())
            set_hint(self.status_label, text, "error")
            failed = [check for check in result.checks if not check[2]]
            if failed:
                key, command, _, answer, meaning = failed[0]
                QMessageBox.warning(self, "The VPN Didn't Work", f"{self.title(key)}: {meaning}: no.\n\n{command}\n"
                                                                  f"{answer[-1200:]}\n\nEvery router was put back.")
        self.sent_message = (self.status_label.text(), "error" if not result.ok else
                             "warning" if result.waiting else "success")
        self.fill_history()
        keys = [job.key for job in jobs]
        self.start_read(keys, then=self.after_send_read, logins=self.saved_logins)

    def after_send_read(self):
        """Read again after a send: what was said about the send stays."""
        text, kind = getattr(self, "sent_message", ("", "info"))
        if text:
            set_hint(self.status_label, text.replace(" Reading the routers again...", ""), kind)
        self.show_waiting()
        self.update_buttons()

    def offer_clear_after(self, vpn_id):
        """A confirmed change to the crypto of a VPN that was up: offer clearing its sessions (they keep the old
        settings until they re-key)."""
        before = self.original(vpn_id)
        after = self.design(vpn_id)
        if before is None or after is None or not before.protected:
            return
        if (before.crypto, before.auth.psk) == (after.crypto, after.auth.psk):
            return
        offers = []
        for member in after.members:
            if member.key in self.targets:
                peers = after.hubs() if after.kind == vpn.DMVPN and member.role == vpn.SPOKE else \
                    after.others(member)
                offers += [(member.key, peer.reached_at) for peer in peers if peer.reached_at]
        if offers:
            self.clear_offer[vpn_id] = offers
        self.show_waiting()

    def offer_clear(self):
        offers = self.clear_offer.get(self.current_id, [])
        if offers:
            self.clear_sessions(offers, ticked=True)

    def dismiss_clear(self):
        self.clear_offer.pop(self.current_id, None)
        self.show_waiting()

    def clear_sessions(self, offers, ticked=False):
        items = [((key, peer), f"{self.title(key)}: clear crypto session remote {peer}") for key, peer in offers]
        dialog = ChoiceDialog(self, "Clear Sessions", "The IPsec sessions to clear (they renegotiate straight away; "
                                                      "traffic through them drops for a moment):", items, ticked)
        if not dialog.exec_() or not dialog.chosen():
            return
        by_key = {}
        for key, peer in dialog.chosen():
            by_key.setdefault(key, []).append(f"clear crypto session remote {peer}")
        actions = [Action("commands", key, self.targets[key].address, list(self.targets[key].names),
                          "\n".join(lines), f"Clearing sessions on {self.title(key)}...")
                   for key, lines in by_key.items() if key in self.targets]
        self.clear_offer.pop(self.current_id, None)
        self.start_actions(actions, then=self.refresh_status)

    # ----------------------------------------------------------------- Waiting to be confirmed

    def show_waiting(self):
        item = self.waiting.get(self.current_id)
        self.waiting_box.setVisible(item is not None)
        if item is not None:
            left = max(0, int((item.deadline - datetime.datetime.now()).total_seconds()))
            set_hint(self.waiting_label, f"In and working on {len(item.keys)} router(s), waiting to be confirmed: they "
                                         f"put their old configuration back at {item.at} ({left // 60}:"
                                         f"{left % 60:02d} left) unless confirmed.", "warning")
        self.clear_box.setVisible(bool(self.clear_offer.get(self.current_id)) and item is None)

    def on_tick(self):
        now = datetime.datetime.now()
        gone = [vpn_id for vpn_id, item in self.waiting.items()
                if now >= item.deadline + datetime.timedelta(seconds=EXPIRY_GRACE)]
        for vpn_id in gone:
            item = self.waiting.pop(vpn_id)
            for key, entry_id in item.entries.items():
                self.set_entry_outcome(entry_id, f"Not confirmed: put back at {item.at}")
            if self.saved_logins is not None and not self.busy():
                self.start_read(list(item.keys), then=self.update_buttons, logins=self.saved_logins)
        if not self.waiting:
            self.tick.stop()
        if gone:
            set_hint(self.status_label, "Not confirmed in time: the routers put their old configuration back.",
                     "warning")
            self.fill_vpns()
        self.show_waiting()

    def set_entry_outcome(self, entry_id, text):
        entry = next((entry for entry in self.store.history if entry.id == entry_id), None)
        if entry is not None:
            entry.outcome = text
            self.store.update(entry)
            self.fill_history()

    def confirm_waiting(self):
        self.end_waiting("confirm")

    def put_back_now(self):
        if QMessageBox.question(self, "Put All Back Now", "Have every router put its old configuration back "
                                                          "now?") != QMessageBox.Yes:
            return
        self.end_waiting("revert")

    def end_waiting(self, kind):
        vpn_id = self.current_id
        item = self.waiting.get(vpn_id)
        if item is None or self.busy():
            return
        line = "configure confirm" if kind == "confirm" else "configure revert now"
        typed = [key for key in item.keys if key in item.views]
        for key in typed:
            self.session_sender.send_to(item.views[key], line, what="keep the changes" if kind == "confirm" else
                                        "put the old configuration back")
        actions = [Action(kind, key, self.targets[key].address, list(self.targets[key].names),
                          title=f"{'Confirming on' if kind == 'confirm' else 'Putting back'} {self.title(key)}...")
                   for key in item.keys if key not in item.views and key in self.targets]
        self.ending = (vpn_id, kind)
        if not actions:
            self.waiting_done({key: True for key in typed})
            return
        self.start_actions(actions, then=lambda: self.waiting_done(
            {action.key: self.action_results.get(index, (False, ""))[0] for index, action in
             enumerate(self.actions)}))

    def waiting_done(self, results):
        vpn_id, kind = self.ending
        item = self.waiting.get(vpn_id)
        if item is None:
            return
        failed = [key for key, ok in results.items() if not ok]
        for key, ok in results.items():
            entry_id = item.entries.get(key)
            if entry_id:
                self.set_entry_outcome(entry_id, ("Confirmed" if kind == "confirm" else "Put back") if ok else
                                       f"{'Confirm' if kind == 'confirm' else 'Put back'} failed")
        if failed:
            set_hint(self.status_label, f"{'configure confirm' if kind == 'confirm' else 'configure revert now'} "
                                        f"didn't work on {', '.join(self.title(key) for key in failed)}: unless it "
                                        f"is, it puts itself back at {item.at}.", "error")
            item.keys = failed
        else:
            self.waiting.pop(vpn_id, None)
            set_hint(self.status_label, "Confirmed on every router." if kind == "confirm" else
                     "Every router put its old configuration back.", "success")
            if kind == "confirm":
                self.offer_clear_after(vpn_id)
        if not self.waiting:
            self.tick.stop()
        self.start_read(list(results), then=self.update_buttons, logins=self.saved_logins)

    # ----------------------------------------------------------------- Actions on routers

    def start_actions(self, actions, then=None, minutes=0):
        if self.busy() or not actions:
            return False
        logins = self.saved_logins or self.logins()
        if logins is None:
            return False
        self.saved_logins = logins
        self.actions, self.action_results = actions, {}
        self.after_actions = then
        self.actor = ActionThread(actions, self.pusher_maker(logins), minutes, self)
        self.actor.progress.connect(lambda text: set_hint(self.status_label, text, "info"))
        self.actor.action_done.connect(self.on_action_done)
        self.actor.finished.connect(self.on_actions_finished)
        self.actor.start()
        self.set_busy("Working on routers")
        self.update_buttons()
        return True

    def on_action_done(self, index, ok, said):
        self.action_results[index] = (ok, said)
        action = self.actions[index]
        if not ok:
            log.info("VPN action %s on %s failed: %s", action.kind, action.address, vpn.mask(said)[-500:])

    def on_actions_finished(self):
        thread, self.actor = self.actor, None
        if thread is not None:
            thread.deleteLater()
        self.clear_busy()
        then, self.after_actions = self.after_actions, None
        failed = [self.actions[index] for index, (ok, _) in self.action_results.items() if not ok]
        if failed and then is None:
            ok, said = self.action_results[self.actions.index(failed[0])]
            set_hint(self.status_label, f"{failed[0].title.rstrip('.')}: {vpn.mask(said)[-300:]}", "error")
        elif then is None:
            set_hint(self.status_label, "Done.", "success")
        self.update_buttons()
        if then is not None:
            then()

    # ----------------------------------------------------------------- Send to Session

    def fill_session_menu(self):
        self.session_menu.clear()
        changes = self.changes_for(self.current_id)
        if not changes:
            self.session_menu.addAction("No changes to send").setEnabled(False)
            return
        for key in changes:
            submenu = self.session_menu.addMenu(self.title(key))
            self.session_sender.fill_menu(submenu, lambda key=key: self.session_text(key),
                                          device=self.device_hints(key), tag=("changes", self.current_id, key))

    def session_text(self, key):
        change = self.changes_for(self.current_id).get(key)
        return change.text(self.revert_minutes()) if change is not None else ""

    def lines_sent(self, view, tag):
        """SessionSender: lines went to a session."""
        if not tag:
            return
        if tag[0] == "changes":
            _, vpn_id, key = tag
            change = self.changes_for(vpn_id).get(key)
            design = self.design(vpn_id) or self.original(vpn_id)
            if change is None or design is None:
                return
            minutes = self.revert_minutes()
            outcome = f"Typed into {view.title}" + (f" with a {minutes}-minute revert timer" if minutes else "")
            entry = self.store.record(design.name, self.title(key), self.targets[key].address,
                                      change.text(minutes), change.undo_text(), view.title, outcome)
            if self.design(vpn_id) is not None and self.design(vpn_id).auth.psk:
                self.store.remember(self.design(vpn_id))
            if minutes:
                item = self.waiting.get(vpn_id)
                if item is None:
                    item = Waiting(datetime.datetime.now() + datetime.timedelta(minutes=minutes), [])
                    self.waiting[vpn_id] = item
                if key not in item.keys:
                    item.keys.append(key)
                item.views[key] = view
                item.entries[key] = entry.id
                self.tick.start()
            self.notes[key] = outcome + ". Read it again to see what it has."
            self.fill_history()
            self.show_waiting()
            self.update_buttons()
        elif tag[0] == "undo":
            self.set_entry_outcome(tag[1], f"Undone in {view.title}")

    # ----------------------------------------------------------------- Certificates

    def certificate_targets(self, design):
        return {member.key: (self.targets[member.key].address, list(self.targets[member.key].names))
                for member in design.members if member.key in self.targets}

    def get_certificates(self):
        design = self.editable()
        if design is None or self.busy():
            return
        self.form_to_design(design)
        if design.auth.ca_kind == "paste":
            self.open_paste_dialog(design)
            return
        if not design.auth.ca_name:
            set_hint(self.status_label, "Give the CA a name first (its certificates' issuer).", "warning")
            return
        if design.auth.ca_kind == "scep" and (not design.auth.ca_url or not design.auth.ca_fingerprint):
            set_hint(self.status_label, "A CA's SCEP URL and its fingerprint are both needed.", "warning")
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        passphrase = ""
        if design.auth.ca_kind == "router":
            ca = design.member(design.auth.ca_device)
            if ca is None:
                set_hint(self.status_label, "Pick the router to be the CA.", "warning")
                return
            device = self.read.get(ca.key)
            if device is not None and not vpnpki.ca_running(device, vpnpki.ca_server_name(design)):
                passphrase, ok = QInputDialog.getText(self, "CA Passphrase", f"A passphrase protecting the CA's "
                                                                             f"key on {ca.title()} (keep it: it's "
                                                                             f"needed to move or restore the CA):",
                                                      QLineEdit.Password, vpnpki.new_secret())
                if not ok or len(passphrase) < 8:
                    set_hint(self.status_label, "The CA needs a passphrase of 8 characters or more.", "warning")
                    return
        steps = vpnpki.plan(design, self.devices(), passphrase, design.auth.ca_fingerprint)
        text = "\n".join(f"- {step.title}" for step in steps) or "- Check every router has its certificate"
        if QMessageBox.question(self, "Get Certificates", f"{text}\n\nNTP can take several minutes to set a clock. "
                                                           "Go ahead?") != QMessageBox.Yes:
            return
        self.pki = PkiThread(design.copy(), self.devices(), self.certificate_targets(design),
                             self.pusher_maker(logins), passphrase, design.auth.ca_fingerprint, self)
        self.pki.progress.connect(lambda text: set_hint(self.status_label, text, "info"))
        self.pki.step_done.connect(self.on_pki_step)
        self.pki.done.connect(self.on_pki_done)
        self.pki_design = design
        self.pki.start()
        self.set_busy("Getting certificates")
        self.update_buttons()

    def on_pki_step(self, step, ok, transcript, problem):
        name = self.pki_design.name if getattr(self, "pki_design", None) is not None else "VPN"
        target = self.targets.get(step.key)
        self.store.record(name, self.title(step.key), target.address if target else "", step.text(),
                          step.undo_text(), "SSH", f"{step.title}: {'done' if ok else problem}")
        log.info("Certificates, %s: %s\n%s", step.title, "done" if ok else problem, vpn.mask(transcript)[-2000:])

    def on_pki_done(self, ok, problem, fingerprint):
        thread, self.pki = self.pki, None
        if thread is not None:
            thread.wait(2000)
            thread.deleteLater()
        self.clear_busy()
        design = getattr(self, "pki_design", None)
        if design is not None and fingerprint:
            design.auth.ca_fingerprint = fingerprint
            self.fingerprint_input.setText(fingerprint)
        self.fill_history()
        if ok:
            set_hint(self.status_label, "Every router has its certificate. Reading them again...", "success")
        else:
            set_hint(self.status_label, f"Certificates: {problem}", "error")
        keys = [member.key for member in design.members if member.key in self.targets] if design else []
        self.start_read(keys, then=self.update_buttons, logins=self.saved_logins)

    def open_paste_dialog(self, design):
        self.paste_dialog = PasteEnrollDialog(self, design)
        self.paste_dialog.trust_requested.connect(self.paste_trust)
        self.paste_dialog.request_requested.connect(self.paste_request)
        self.paste_dialog.import_requested.connect(self.paste_import)
        self.paste_dialog.finished.connect(self.on_paste_closed)
        self.paste_dialog.show()

    def on_paste_closed(self, *_):
        design = self.design()
        if design is not None and self.paste_dialog is not None:
            design.auth.ca_fingerprint = self.paste_dialog.fingerprint_input.text().strip()
        self.paste_dialog = None
        keys = [member.key for member in design.members if member.key in self.targets] if design else []
        if keys and not self.busy():
            self.start_read(keys, then=self.update_buttons, logins=self.saved_logins)

    def start_paste(self, steps):
        if self.busy():
            return
        logins = self.saved_logins or self.logins()
        if logins is None:
            return
        self.saved_logins = logins
        design = self.design()
        self.pki_design = design
        self.paste_thread = PasteThread(steps, self.certificate_targets(design), self.pusher_maker(logins), self)
        self.paste_thread.step_done.connect(self.on_paste_step)
        self.paste_thread.finished.connect(self.on_paste_finished)
        self.pki = self.paste_thread
        self.pki.start()
        if self.paste_dialog is not None:
            self.paste_dialog.set_busy(True)
            self.paste_dialog.say("Working over SSH...", "info")
        self.set_busy("Certificates")

    def paste_trust(self, pem, fingerprint):
        design = self.design()
        steps = [vpnpki.paste_authenticate_steps(design, member, self.read.get(member.key), pem, fingerprint)
                 for member in design.members if member.key in self.targets]
        design.auth.ca_fingerprint = fingerprint
        self.start_paste(steps)

    def paste_request(self, key):
        design = self.design()
        member = design.member(key)
        self.start_paste([vpnpki.paste_request_steps(design, member)])

    def paste_import(self, key, pem):
        design = self.design()
        self.start_paste([vpnpki.import_steps(design, design.member(key), pem)])

    def on_paste_step(self, step, ok, transcript, problem):
        self.on_pki_step(step, ok, transcript, problem)
        if self.paste_dialog is None:
            return
        if ok and step.title.startswith("Make "):
            request = vpnpki.request_in(transcript)
            self.paste_dialog.set_request(step.key, request or transcript)
        self.paste_dialog.say(f"{step.title}: " + ("done." if ok else problem), "success" if ok else "error")

    def on_paste_finished(self):
        thread, self.pki = self.pki, None
        if thread is not None:
            thread.deleteLater()
        self.clear_busy()
        if self.paste_dialog is not None:
            self.paste_dialog.set_busy(False)
        self.fill_history()
        self.update_buttons()

    # ----------------------------------------------------------------- Status

    def fill_status(self):
        current = self.status_tree.currentItem()
        current_id = current.data(0, Qt.UserRole) if current is not None else ""
        self.status_tree.blockSignals(True)
        self.status_tree.clear()
        devices = self.devices()
        chosen = None
        for item_vpn in self.found:
            state = vpnstatus.vpn_state(item_vpn, devices)
            item = QTreeWidgetItem([item_vpn.name, vpn.kind_text(item_vpn), ", ".join(member.title() for member in
                                                                                      item_vpn.members),
                                    STATE_TEXT[state]])
            item.setData(0, Qt.UserRole, item_vpn.id)
            item.setForeground(3, QColor(COLORS[STATE_COLOR[state]]))
            self.status_tree.addTopLevelItem(item)
            if item_vpn.id == current_id:
                chosen = item
        for column in range(len(VPN_COLUMNS)):
            self.status_tree.resizeColumnToContents(column)
        self.status_tree.blockSignals(False)
        if chosen is not None:
            self.status_tree.setCurrentItem(chosen)
        elif self.status_tree.topLevelItemCount():
            self.status_tree.setCurrentItem(self.status_tree.topLevelItem(0))
        self.show_status()

    def status_vpn(self):
        item = self.status_tree.currentItem()
        vpn_id = item.data(0, Qt.UserRole) if item is not None else ""
        return next((found for found in self.found if found.id == vpn_id), None)

    def show_status(self, *_):
        self.diagnosis_list.clear()
        self.log_view.clear()
        found = self.status_vpn()
        if found is None:
            self.update_buttons()
            return
        devices = self.devices()
        for member in found.members:
            device = devices.get(member.key)
            if device is None:
                continue
            for finding in vpnstatus.diagnose(found, member, device, devices):
                item = QListWidgetItem(finding.text)
                item.setForeground(QColor(COLORS[SEVERITY_COLOR.get(finding.severity, "muted")]))
                self.diagnosis_list.addItem(item)
        for finding in vpncheck.check(found, devices, [item for item in self.found if item.id != found.id]):
            if finding.severity == ERROR:
                item = QListWidgetItem("Design: " + finding.text)
                item.setForeground(QColor(COLORS["error"]))
                self.diagnosis_list.addItem(item)
        lines = []
        for member in found.members:
            device = devices.get(member.key)
            if device is not None and device.status is not None and device.status.log:
                lines.append(f"! {member.title()}")
                lines += device.status.log[-15:]
        self.log_view.setPlainText("\n".join(lines))
        self.update_buttons()

    def refresh_status(self):
        keys = []
        for found in self.found:
            keys += [member.key for member in found.members if member.key in self.targets and member.key not in keys]
        if keys and not self.busy():
            self.start_read(keys, then=self.update_buttons)

    def on_auto_status(self, on):
        if on:
            self.status_timer.start()
        else:
            self.status_timer.stop()

    def clear_sessions_chosen(self):
        found = self.status_vpn()
        if found is None:
            return
        offers = []
        for member in found.members:
            if member.key in self.targets:
                peers = found.hubs() if found.kind == vpn.DMVPN and member.role == vpn.SPOKE else found.others(member)
                offers += [(member.key, peer.reached_at) for peer in peers if peer.reached_at]
        if offers:
            self.clear_sessions(offers)

    # ----------------------------------------------------------------- The library

    def save_to_library(self):
        design = self.design() or self.original(self.current_id)
        if design is None:
            return
        name, ok = QInputDialog.getText(self, "Save to Library", "Name in the library:", text=design.name)
        if not ok or not name.strip():
            return
        kept = design.copy()
        kept.name = name.strip()
        self.store.add_to_library(kept)
        self.fill_library()
        set_hint(self.status_label, f"Saved {kept.name} to the library (without its keys).", "success")

    def fill_library(self):
        table = self.library_table
        table.setRowCount(len(self.store.library))
        for row, entry in enumerate(self.store.library):
            design = vpn.Vpn.from_dict(entry.design)
            cells = [entry.name, vpn.kind_text(design), ", ".join(member.title() for member in design.members),
                     entry.saved[:16], entry.notes]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, entry.id)
                table.setItem(row, column, cell)
        table.resizeColumnsToContents()
        self.update_buttons()

    def library_entry(self):
        rows = sorted({index.row() for index in self.library_table.selectedIndexes()})
        if not rows:
            return None
        entry_id = self.library_table.item(rows[0], 0).data(Qt.UserRole)
        return next((entry for entry in self.store.library if entry.id == entry_id), None)

    def use_library(self):
        entry = self.library_entry()
        if entry is None:
            return
        template = vpn.Vpn.from_dict(entry.design)
        routers = [(key, self.title(key)) for key in sorted(self.targets, key=lambda key: self.title(key).lower())]
        chosen = [member.key for member in template.members if member.key in self.targets]
        dialog = NewVpnDialog(self, routers, chosen, f"{template.name}2", template.kind)
        if not dialog.exec_():
            return
        picks = dialog.chosen()
        unread = [key for key, _ in picks if key not in self.read or not self.read[key].read]
        template.auth.psk = ""
        if unread:
            self.start_read(unread, then=lambda: self.make_new(dialog.name(), dialog.kind(), picks, template))
            return
        self.make_new(dialog.name(), dialog.kind(), picks, template)

    def edit_library_notes(self):
        entry = self.library_entry()
        if entry is None:
            return
        notes, ok = QInputDialog.getMultiLineText(self, "Notes", f"Notes on {entry.name}:", entry.notes)
        if ok:
            entry.notes = notes
            self.store.save()
            self.fill_library()

    def delete_library(self):
        entry = self.library_entry()
        if entry is not None and QMessageBox.question(self, "Delete", f"Delete {entry.name} from the "
                                                                      "library?") == QMessageBox.Yes:
            self.store.remove_from_library(entry.id)
            self.fill_library()

    # ----------------------------------------------------------------- Changes sent

    def fill_history(self):
        table = self.history_table
        table.setRowCount(len(self.store.history))
        for row, entry in enumerate(self.store.history):
            cells = [entry.when[:16], entry.vpn, entry.device, entry.how, entry.outcome]
            for column, text in enumerate(cells):
                cell = QTableWidgetItem(text)
                cell.setData(Qt.UserRole, entry.id)
                cell.setToolTip(text)
                if column == 4:
                    good = text.startswith(("Confirmed", "Sent", "Typed", "Undone", "In and", "Set up", "Enroll",
                                            "Make", "Keep", "Trust", "Put "))
                    cell.setForeground(QColor(COLORS["success" if good and "fail" not in text.lower() else
                                                     "warning"]))
                table.setItem(row, column, cell)
        table.resizeColumnsToContents()
        self.on_history_selected()

    def history_entry(self):
        rows = sorted({index.row() for index in self.history_table.selectedIndexes()})
        if not rows:
            return None
        entry_id = self.history_table.item(rows[0], 0).data(Qt.UserRole)
        return next((entry for entry in self.store.history if entry.id == entry_id), None)

    def on_history_selected(self, *_):
        entry = self.history_entry()
        text = "" if entry is None else entry.lines if self.history_lines_radio.isChecked() else entry.undo
        self.history_view.setPlainText(text)
        self.update_buttons()

    def undo_over_ssh(self):
        entry = self.history_entry()
        if entry is None or self.busy():
            return
        if QMessageBox.question(self, "Undo over SSH", f"Send what undoes this {entry.vpn} change to {entry.device} "
                                                       f"({entry.address})?") != QMessageBox.Yes:
            return
        _, undo = self.store.unmasked(entry)
        key = next((key for key, target in self.targets.items() if target.address == entry.address),
                   f"address:{entry.address}")
        self.targets.setdefault(key, Target(key, entry.device, entry.address, [], "address"))
        target = self.targets[key]
        minutes = self.revert_minutes()
        self.undoing = entry
        self.start_actions([Action("undo", key, target.address, list(target.names), undo,
                                   f"Undoing on {target.label}...")], then=self.after_undo, minutes=minutes)

    def after_undo(self):
        entry = self.undoing
        ok, said = self.action_results.get(0, (False, ""))
        entry.outcome = "Undone over SSH" if ok else f"Undo failed: {vpn.mask(said)[-200:]}"
        self.store.update(entry)
        self.fill_history()
        set_hint(self.status_label, entry.outcome, "success" if ok else "error")

    def fill_undo_session_menu(self):
        entry = self.history_entry()
        self.undo_session_menu.clear()
        if entry is None:
            return
        key = next((key for key, target in self.targets.items() if target.address == entry.address), "")
        self.session_sender.fill_menu(self.undo_session_menu, lambda: self.store.unmasked(entry)[1],
                                      device=self.device_hints(key) if key else {"address": entry.address},
                                      tag=("undo", entry.id))

    def copy_undo(self):
        entry = self.history_entry()
        if entry is not None:
            QApplication.clipboard().setText(entry.undo)
            set_hint(self.status_label, "Copied what undoes it (keys hidden).", "success")

    def forget_history(self):
        entry = self.history_entry()
        if entry is None:
            return
        self.store.history = [item for item in self.store.history if item.id != entry.id]
        self.store.save()
        self.fill_history()

    # ----------------------------------------------------------------- From the map

    def prefill(self, map_keys=(), new=False):
        """From the Network Map: its routers (map device keys) chosen and read; new: then a new VPN between them."""
        keys = [f"map:{key}" for key in map_keys if f"map:{key}" in self.targets]
        if not keys:
            return
        self.router_list.blockSignals(True)
        for row in range(self.router_list.count()):
            item = self.router_list.item(row)
            item.setSelected(item.data(Qt.UserRole) in keys)
        self.router_list.blockSignals(False)
        self.tabs.setCurrentIndex(0)
        if new:
            kind = vpn.DMVPN if len(keys) > 2 else vpn.VTI
            unread = [key for key in keys if key not in self.read]
            if unread:
                self.start_read(unread, then=lambda: self.new_vpn(chosen=keys, kind=kind))
            else:
                self.new_vpn(chosen=keys, kind=kind)
            return
        unread = [key for key in keys if key not in self.read]
        if unread:
            self.start_read(unread, then=lambda: self.select_vpn_of(keys))
        else:
            self.select_vpn_of(keys)

    def select_vpn_of(self, keys):
        found = next((item for item in self.found if any(member.key in keys for member in item.members)), None)
        if found is not None:
            self.current_id = found.id
            self.fill_vpns()

    def map_tunnels(self):
        """[(map device key, map device key, state, text)] of the found VPNs between routers on the open map: for
        the map's VPN Tunnels overlay."""
        devices = self.devices()
        lines = []
        for found in self.found:
            state = vpnstatus.vpn_state(found, devices)
            keys = [(member, self.targets[member.key].map_key) for member in found.members
                    if member.key in self.targets and self.targets[member.key].map_key]
            pairs = []
            if found.kind == vpn.DMVPN:
                hubs = [(member, key) for member, key in keys if member.role == vpn.HUB]
                for hub, hub_key in hubs:
                    pairs += [((hub, hub_key), (member, key)) for member, key in keys if member.key != hub.key]
            elif len(keys) == 2:
                pairs.append((keys[0], keys[1]))
            for (a, a_key), (b, b_key) in pairs:
                text = f"{found.name}: {vpn.kind_text(found)}, {STATE_TEXT[state].lower()}"
                lines.append((a_key, b_key, state, text))
        return lines

    # ----------------------------------------------------------------- Busy

    def set_busy(self, text):
        busy = getattr(self.window, "set_busy", None)
        if busy is not None:
            busy("vpns", text)

    def clear_busy(self):
        clear = getattr(self.window, "clear_busy", None)
        if clear is not None:
            clear("vpns")

    def stop(self):
        for thread in (self.reader, self.sender, self.actor, self.pki):
            if thread is not None:
                thread.stop()
        set_hint(self.status_label, "Stopping...", "info")

    def update_buttons(self):
        if not hasattr(self, "history_table") or not hasattr(self, "status_tree"):
            return
        busy = self.busy()
        vpn_id = self.current_id
        design = self.design()
        changes = self.changes_for(vpn_id) if vpn_id else {}
        waiting = self.waiting.get(vpn_id)
        self.read_button.setEnabled(not busy and bool(self.chosen_keys()))
        self.stop_button.setEnabled(busy)
        self.new_button.setEnabled(not busy)
        self.delete_button.setEnabled(bool(vpn_id) and not busy)
        self.library_save_button.setEnabled(design is not None)
        member = self.selected_member() if design is not None else None
        self.edit_member_button.setEnabled(member is not None)
        self.remove_member_button.setEnabled(member is not None and len(design.members) > 2)
        self.add_member_button.setEnabled(design is not None)
        self.send_button.setEnabled(not busy and bool(changes) and waiting is None and not self.blocked(vpn_id))
        self.send_button.setToolTip(self.blocked(vpn_id) or "Every router's change in with the revert timer, the VPN "
                                                            "checked from each end, then confirmed on all (or all put "
                                                            "back)")
        self.session_button.setEnabled(bool(changes) and waiting is None)
        for button in (self.confirm_button, self.put_back_button):
            button.setEnabled(waiting is not None and not busy)
        self.confirm_combo.setEnabled(self.revert_check.isChecked())
        self.minutes_input.setEnabled(self.revert_check.isChecked())
        self.discard_button.setEnabled(vpn_id in self.drafts)
        text = self.preview.toPlainText()
        self.copy_button.setEnabled(bool(text))
        self.export_button.setEnabled(bool(text))
        self.certs_button.setEnabled(design is not None and design.auth.method == vpn.CERT and not busy)
        if design is not None and design.auth.method == vpn.CERT:
            have = [member.title() for member in design.members if member.key in self.read and
                    vpnpki.has_certificate(design, member, self.read[member.key])]
            lacking = [member.title() for member in design.members if member.key in self.read and
                       member.title() not in have]
            self.cert_state.setText(("Have certificates: " + ", ".join(have) + ". " if have else "") +
                                    ("Need them: " + ", ".join(lacking) + "." if lacking else ""))
        else:
            self.cert_state.setText("")
        found = self.status_vpn()
        self.status_read_button.setEnabled(not busy and bool(self.found))
        self.status_clear_button.setEnabled(not busy and found is not None and found.protected)
        self.clear_button.setEnabled(not busy)
        entry = self.library_entry()
        for button in (self.use_button, self.notes_button, self.library_delete_button):
            button.setEnabled(entry is not None)
        history = self.history_entry()
        self.undo_ssh_button.setEnabled(history is not None and not busy and bool(history.undo))
        self.undo_session_button.setEnabled(history is not None)
        self.copy_undo_button.setEnabled(history is not None)
        self.forget_button.setEnabled(history is not None)


def devices_after_with(design, original, devices):
    """The routers as they'd be once a VPN's change is in (for the checks to ping between its LANs)."""
    try:
        return vpn.devices_after(original, design, devices)
    except Exception:
        log.exception("Working out the routers after a VPN change failed")
        return devices
