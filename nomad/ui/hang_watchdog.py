"""Freeze reports: when the window stops answering for a couple of seconds, write what every thread is doing to the
log, with what NOMAD was doing (its version, the map open and how big it is, the tribe, sessions...), so a freeze
on someone else's computer can be tracked down from their nomad.log.

A timer on the UI thread beats a few times a second. A watcher thread notices when the beats stop and writes the
report; while the window stays frozen it notes where the UI thread is every tenth of a second, and once the window
answers again it logs how long the freeze lasted and where the time went. Should the UI thread hold Python's lock
the whole time (so the watcher can't run), Python's faulthandler writes the bare stacks to nomad-freezes.txt instead.
"""
import collections
import ctypes
import datetime
import faulthandler
import logging
import os
import platform
import sys
import threading
import time
import traceback

from PyQt5.QtCore import QEvent, QObject, Qt, QTimer

log = logging.getLogger(__name__)

THRESHOLD_SECONDS = 2.0  # A freeze this long is reported
BEAT_MS = 250  # How often the UI thread says it's alive
CONTEXT_SECONDS = 5.0  # How often what NOMAD is doing is noted (on the UI thread, ready for a report)
SAMPLE_SECONDS = 0.1  # How often the frozen UI thread's whereabouts are noted
REPEAT_AFTER = (10.0, 30.0, 60.0, 120.0)  # A freeze still going after this long: where the UI thread is now
FALLBACK_SECONDS = 5.0  # faulthandler's dump, for when the watcher itself can't run
FREEZES_FILE = "nomad-freezes.txt"
FREEZES_FILE_MAX = 1_000_000
MAIN_FRAMES = 40  # Frames of the UI thread's stack written out
OTHER_FRAMES = 8  # And of each other thread's


def short_frame(frame_summary):
    name = frame_summary.filename.replace("\\", "/")
    parts = name.split("/")
    if "nomad" in parts:  # nomad/ui/netmap_tab.py rather than the whole path
        name = "/".join(parts[len(parts) - 1 - parts[::-1].index("nomad"):])
    else:
        name = "/".join(parts[-2:])
    return f"{name}:{frame_summary.lineno} {frame_summary.name}"


def is_ours(frame_summary):
    name = frame_summary.filename.replace("\\", "/")
    return "/nomad/" in name and "/site-packages/" not in name


def frames_of(frame, limit=None, lines=False):
    """A thread's stack, outermost first, its innermost limit frames. Source lines only when asked for: looking them
    up while the UI thread is held up competes with it for Python's lock, and in the built NOMAD there's no source to
    show (PyInstaller's importer is asked for it each time, slowly)."""
    stack = traceback.StackSummary.extract(traceback.walk_stack(frame), limit=limit, lookup_lines=lines)
    stack.reverse()
    return stack


def where(frame, depth=4):
    """'file:line function <- caller...' for the innermost frames of NOMAD's own code (or the innermost frames at
    all, when none are NOMAD's)."""
    stack = frames_of(frame, limit=60)
    ours = [item for item in stack if is_ours(item)]
    chosen = ours[-depth:] if ours else stack[-depth:]
    text = " <- ".join(short_frame(item) for item in reversed(chosen))
    if ours and stack and stack[-1] is not ours[-1]:  # Inside a library call made from NOMAD's code
        text = f"[{short_frame(stack[-1])}] " + text
    return text


def thread_names():
    return {thread.ident: thread.name for thread in threading.enumerate()}


def format_threads(main_ident, skip_ident=None):
    """The UI thread's stack in full (with source lines), then each other thread's innermost frames, threads with
    the same frames listed together."""
    frames = sys._current_frames()
    names = thread_names()
    lines = []
    main = frames.get(main_ident)
    if main is not None:
        lines.append("  UI thread:")
        with_source = not getattr(sys, "frozen", False)
        for item in frames_of(main, limit=MAIN_FRAMES, lines=with_source):
            lines.append(f'    File "{item.filename}", line {item.lineno}, in {item.name}')
            source = item.line.strip() if with_source and item.line else ""
            if source:
                lines.append(f"      {source}")
    others = collections.OrderedDict()
    for ident, frame in frames.items():
        if ident in (main_ident, skip_ident):
            continue
        stack = frames_of(frame, limit=OTHER_FRAMES)
        key = " <- ".join(short_frame(item) for item in reversed(stack))
        others.setdefault(key, []).append(names.get(ident, f"thread {ident}"))
    lines.append(f"  Other threads ({sum(len(group) for group in others.values())}):")
    for key, group in others.items():
        label = ", ".join(sorted(set(group))[:4]) + (f" and {len(group) - 4} more" if len(group) > 4 else "")
        lines.append(f"    {len(group)} x {label}: {key}")
    return lines


def awake_seconds():
    """Seconds the computer has been awake (Windows' clock that stops while it sleeps or hibernates), or None off
    Windows."""
    if sys.platform != "win32":
        return None
    value = ctypes.c_ulonglong()
    if not ctypes.windll.kernel32.QueryUnbiasedInterruptTime(ctypes.byref(value)):
        return None
    return value.value / 10_000_000  # 100-nanosecond units


def process_memory_mb():
    """This process's working set, in MB (None off Windows, or if Windows won't say)."""
    if sys.platform != "win32":
        return None

    class Counters(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong), ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t)]
    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    kernel32 = ctypes.windll.kernel32
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi = ctypes.windll.psapi
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.POINTER(Counters), ctypes.c_ulong]
    if not psapi.GetProcessMemoryInfo(kernel32.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        return None
    return counters.WorkingSetSize // (1024 * 1024)


class HangWatchdog(QObject):
    """Start once the window is up (start()), stop when NOMAD closes (stop()).

    context: called on the UI thread every few seconds; returns the lines describing what NOMAD is doing, for the
    reports (window_context for the main window). freezes_path: where faulthandler writes when the watcher can't
    (None: no fallback, as in tests)."""

    def __init__(self, context=None, threshold=THRESHOLD_SECONDS, beat_ms=BEAT_MS, context_seconds=CONTEXT_SECONDS,
                 freezes_path=None, parent=None):
        super().__init__(parent)
        self.context = context
        self.threshold = threshold
        self.context_seconds = context_seconds
        self.freezes_path = freezes_path
        self.freezes_file = None
        self.started = time.monotonic()
        self.last_beat = self.started
        self.context_lines, self.context_when = [], 0.0
        self.last_input, self.last_input_when = "", 0.0
        self.main_ident = threading.main_thread().ident
        self.stopping = threading.Event()
        self.thread = None
        self.timer = QTimer(self)
        self.timer.setInterval(beat_ms)
        self.timer.timeout.connect(self.beat)
        self.freezes = 0  # Reported since starting
        self.held_up = 0.0  # How long the watcher itself was last held up (a thread kept Python's lock)

    # ----------------------------------------------------------------- On the UI thread

    def start(self):
        if self.thread is not None:
            return
        self.started = self.last_beat = time.monotonic()
        self.note_context()
        self.open_freezes_file()
        self.timer.start()
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            app.installEventFilter(self)
        self.thread = threading.Thread(target=self.watch, name="NOMAD freeze watchdog", daemon=True)
        self.thread.start()
        self.arm_fallback()
        log.debug("Freeze watchdog started: freezes of %.1f s or more are reported here", self.threshold)

    def stop(self):
        """Stop watching (closing NOMAD). A freeze still going is summed up first."""
        self.timer.stop()
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(1.0)
            self.thread = None
        if self.freezes_file is not None:
            faulthandler.cancel_dump_traceback_later()
            try:
                self.freezes_file.close()
            except OSError:
                pass
            self.freezes_file = None
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance()
        if app is not None:
            app.removeEventFilter(self)

    def beat(self):
        now = time.monotonic()
        self.last_beat = now
        self.arm_fallback()
        if now - self.context_when >= self.context_seconds:
            self.note_context()

    def note_context(self):
        started = time.monotonic()
        try:
            lines = list(self.context()) if self.context is not None else []
        except Exception as error:  # Never let describing NOMAD break it
            lines = [f"(Couldn't describe what NOMAD is doing: {error!r})"]
        took = time.monotonic() - started
        if took > 0.25:
            lines.append(f"(Noting this took {took:.2f} s)")
        self.context_lines, self.context_when = lines, time.monotonic()

    def eventFilter(self, obj, event):
        """Note the last click or command key (never typed text), to say what started a freeze."""
        kind = event.type()
        if kind != QEvent.MouseButtonRelease and kind != QEvent.KeyPress:
            return False
        try:
            self.note_input(obj, event, kind)
        except Exception:
            pass
        return False

    def note_input(self, obj, event, kind):
        if not obj.isWidgetType():
            return
        if kind == QEvent.KeyPress:
            key, modifiers = event.key(), event.modifiers()
            named = {Qt.Key_Return: "Enter", Qt.Key_Enter: "Enter", Qt.Key_Delete: "Delete", Qt.Key_Escape: "Esc",
                     Qt.Key_Tab: "Tab", Qt.Key_Backspace: "Backspace"}
            if key in named:
                text = named[key]
            elif Qt.Key_F1 <= key <= Qt.Key_F35:
                text = f"F{key - Qt.Key_F1 + 1}"
            elif modifiers & (Qt.ControlModifier | Qt.AltModifier) and 0x20 < key < 0x7f:
                text = ("Ctrl+" if modifiers & Qt.ControlModifier else "") + \
                       ("Alt+" if modifiers & Qt.AltModifier else "") + chr(key)
            else:
                return  # Typing: not noted (it could be a password)
            what = f"{text} key"
        else:
            button = {Qt.LeftButton: "click", Qt.RightButton: "right-click"}.get(event.button(), "click")
            what = button
            action = obj.activeAction() if hasattr(obj, "activeAction") and callable(obj.activeAction) else None
            if action is not None and action.text():
                what = f"menu {action.text().replace('&', '')!r}"
            elif hasattr(obj, "text") and callable(obj.text) and obj.metaObject().className() != "QLineEdit":
                label = obj.text()
                if isinstance(label, str) and label and len(label) < 60:
                    what += f" {label.replace('&', '')!r}"
        widget = obj
        while widget is not None and widget.metaObject().className() in ("QWidget", "QScrollBar") and \
                widget.parentWidget() is not None:  # A view's viewport: name the view
            widget = widget.parentWidget()
        page = obj.window().windowTitle() if obj.window() is not None else ""
        self.last_input = f"{what} on {widget.metaObject().className()}" + (f" in {page!r}" if page else "")
        self.last_input_when = time.monotonic()

    def open_freezes_file(self):
        if self.freezes_path is None:
            return
        try:
            from ..system import replace_file
            path = self.freezes_path
            if os.path.exists(path) and os.path.getsize(path) > FREEZES_FILE_MAX:
                replace_file(path, path + ".1")
            self.freezes_file = open(path, "a", encoding="utf-8")
            from .. import __version__
            self.freezes_file.write(f"\n=== NOMAD {__version__} started {datetime.datetime.now():%Y-%m-%d %H:%M:%S}"
                                    f" (pid {os.getpid()}): stacks below are from freezes of "
                                    f"{FALLBACK_SECONDS:.0f} s or more ===\n")
            self.freezes_file.flush()
        except OSError as error:
            log.info("Freeze watchdog: couldn't open %s: %s", self.freezes_path, error)
            self.freezes_file = None

    def arm_fallback(self):
        if self.freezes_file is None:
            return
        try:
            faulthandler.dump_traceback_later(FALLBACK_SECONDS, repeat=False, file=self.freezes_file)
        except (OSError, ValueError, RuntimeError):
            pass

    # ----------------------------------------------------------------- On the watcher thread

    def watch(self):
        frozen = False
        freeze_start = 0.0
        samples = collections.Counter()
        repeats = list(REPEAT_AFTER)
        last_tick, last_awake = time.monotonic(), awake_seconds()
        while not self.stopping.wait(SAMPLE_SECONDS):
            now, awake = time.monotonic(), awake_seconds()
            late = now - last_tick
            if late > 1.0:
                # The watcher itself was held up: the computer slept (its awake clock stood still meanwhile), or a
                # thread held Python's lock - only the second can be a freeze
                slept = late - (awake - last_awake) if awake is not None and last_awake is not None else 0.0
                if slept > late / 2:
                    log.debug("Freeze watchdog: the computer slept for %.0f s", slept)
                    self.last_beat = now
                    frozen = False
                else:
                    self.held_up = late
            last_tick, last_awake = now, awake
            beat = self.last_beat
            if frozen and beat > freeze_start:
                self.report_end(beat - freeze_start, samples)
                frozen = False
                continue
            gap = now - beat
            if not frozen:
                if gap >= self.threshold:
                    frozen, freeze_start = True, beat
                    samples.clear()
                    repeats = list(REPEAT_AFTER)
                    self.sample(samples)
                    self.report_start(gap, freeze_start)
                else:
                    self.held_up = 0.0  # A hold-up the window got through: nothing to report
                continue
            self.sample(samples)
            if repeats and gap >= repeats[0]:
                repeats.pop(0)
                self.report_still(gap, samples)
        if frozen:
            self.report_end(time.monotonic() - freeze_start, samples, ended=False)

    def sample(self, samples):
        frame = sys._current_frames().get(self.main_ident)
        if frame is not None:
            samples[where(frame)] += 1

    def report_start(self, gap, freeze_start):
        self.freezes += 1
        try:
            since = datetime.datetime.now() - datetime.timedelta(seconds=gap)
            lines = [f"UI freeze #{self.freezes}: the window hasn't answered for {gap:.1f} s (since "
                     f"{since:%H:%M:%S}.{since.microsecond // 1000:03d}). Details for tracking it down:"]
            lines += ["  " + line for line in self.context_lines]
            age = time.monotonic() - self.context_when
            lines.append(f"  (What NOMAD was doing, as of {age:.1f} s ago; up {self.uptime()})")
            if self.last_input:
                before = freeze_start - self.last_input_when
                lines.append(f"  Last input: {self.last_input}, " + (f"{before:.1f} s before the freeze" if before >= 0
                                                                    else "during it"))
            if self.held_up:
                lines.append(f"  This report itself was held up {self.held_up:.1f} s: a thread kept Python's lock "
                             "(the stacks below are from after that)")
                self.held_up = 0.0
            lines += format_threads(self.main_ident, threading.get_ident())
            log.warning("\n".join(lines))
        except Exception:
            log.exception("Freeze watchdog: couldn't write the report")

    def report_still(self, gap, samples):
        try:
            frame = sys._current_frames().get(self.main_ident)
            here = where(frame, depth=6) if frame is not None else "?"
            log.warning("UI freeze #%d still going after %.0f s. The UI thread is now at: %s\n%s", self.freezes, gap,
                        here, "\n".join(self.summary(samples)))
        except Exception:
            log.exception("Freeze watchdog: couldn't write the report")

    def report_end(self, length, samples, ended=True):
        try:
            head = (f"UI freeze #{self.freezes} over: the window didn't answer for {length:.1f} s." if ended else
                    f"UI freeze #{self.freezes} was still going when NOMAD closed, after {length:.1f} s.")
            log.warning("%s Where the UI thread spent it:\n%s", head, "\n".join(self.summary(samples)))
        except Exception:
            log.exception("Freeze watchdog: couldn't write the report")

    @staticmethod
    def summary(samples):
        total = sum(samples.values()) or 1
        return [f"  {100 * count // total:3d}%  {place}" for place, count in samples.most_common(6)]

    def uptime(self):
        seconds = int(time.monotonic() - self.started)
        return f"{seconds // 3600}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"


# --------------------------------------------------------------------- What the main window is doing

def _part(lines, label, describe):
    try:
        text = describe()
    except Exception as error:
        text = f"? ({type(error).__name__}: {error})"
    if text:
        lines.append(f"{label}: {text}")


def _yes(value):
    return "yes" if value else "no"


def window_context(window):
    """Lines saying what NOMAD is doing, for a freeze report: called on the UI thread every few seconds, so only
    cheap reads (no waiting on locks the sync threads hold)."""
    lines = []
    _part(lines, "NOMAD", lambda: _about(window))
    _part(lines, "Tribe", lambda: _tribe(window))
    _part(lines, "Page", lambda: _page(window))
    _part(lines, "Map", lambda: _map(window))
    _part(lines, "Map activity", lambda: _map_activity(window))
    _part(lines, "Tribe map sync", lambda: _tribe_maps(window))
    _part(lines, "IP Addresses", lambda: _ipam(window))
    _part(lines, "Terminal", lambda: _terminal(window))
    _part(lines, "Process", _process)
    return lines


def _about(window):
    from PyQt5.QtCore import PYQT_VERSION_STR, QT_VERSION_STR

    from .. import __version__
    return (f"{__version__}{' (built)' if getattr(sys, 'frozen', False) else ' (from source)'}, Python "
            f"{platform.python_version()}, Qt {QT_VERSION_STR}, PyQt {PYQT_VERSION_STR}, Windows "
            f"{platform.version()}, administrator: {_yes(getattr(window, 'admin', False))}, computer "
            f"{platform.node()}")


_server_here = {}


def _tribe(window):
    from ..ipam.client import is_tribe_server
    if "value" not in _server_here:  # Asks Windows about the service: once is enough
        _server_here["value"] = is_tribe_server()
    parts = [f"this computer is the tribe server: {_yes(_server_here['value'])}"]
    maps = getattr(getattr(getattr(window, "netmap_tab", None), "tribe", None), "maps", None)
    team = getattr(getattr(window, "ipam_tab", None), "team", None)
    client = getattr(maps, "client", None) or getattr(team, "client", None)
    key = getattr(client, "key", None)
    if key is None:
        parts.append("no tribe key in use")
    else:
        parts.append(f"key role {key.role}, server {', '.join(key.hosts)} port {key.port}")
        reached = [f"{name} last reached {getattr(item, 'last_host', None) or 'not yet'}"
                   for name, item in (("maps", getattr(maps, "client", None)), ("IPAM", getattr(team, "client", None)))
                   if item is not None]
        parts += reached
    banner = getattr(window, "tribe_banner", None)
    if banner is not None and getattr(banner, "update_needed", None) is not None:
        parts.append("server needs updating")
    return "; ".join(parts)


def _page(window):
    navigator = window.navigator
    page = navigator.currentWidget()
    text = navigator.title(page) if page is not None else "none"
    popped = getattr(navigator, "popped", {})
    if popped:
        text += f"; popped out: {', '.join(navigator.title(item) for item in popped)}"
    return text


def _map(window):
    page = window.netmap_tab
    network_map = page.network_map
    if network_map is None:
        return "none open"
    if page.tribe_map_id is not None:
        where_from = f"tribe map {page.map_name()!r} (id {page.tribe_map_id})"
    elif page.map_path:
        where_from = f"file {os.path.basename(str(page.map_path))!r}"
    else:
        where_from = "not saved yet"
    devices = network_map.devices.values()
    manual = sum(1 for device in devices if getattr(device, "manual", False))
    view = page.current_view()
    shown = "physical" if view is page.view else "L3" if view is getattr(page, "l3_view", None) else "a table"
    drawn = len(getattr(page.view, "items_by_key", {}))
    scene = page.view.scene()
    return (f"{where_from}: {len(network_map.devices)} devices ({manual} by hand), {len(network_map.links)} links, "
            f"{len(network_map.hosts)} hosts, {len(network_map.groups)} groups, "
            f"{len(getattr(network_map, 'tunnels', []) or [])} tunnels; showing {shown}; {drawn} devices drawn, "
            f"{len(scene.items()) if scene is not None else 0} items on the physical view; overlay "
            f"{page.overlay_shown[0] if page.overlay_shown else 'none'}, VLAN shown: "
            f"{_yes(page.vlan_shown)}; undo steps {len(page.undo_stack)}")


def _map_activity(window):
    page = window.netmap_tab
    watcher, monitor = page.watcher, page.monitor
    parts = [f"crawl running: {_yes(page.worker is not None)}",
             f"SNMP checks running: {len(page.check_threads)}",
             f"watch: {'on' if page.watch_check.isChecked() else 'off'}"
             + (" (watching)" if getattr(watcher, "running", False) else ""),
             f"monitor: {'on' if page.monitor_check.isChecked() else 'off'}"
             + (f" ({len(getattr(monitor, 'targets', {}) or {})} devices, every {monitor.interval} s)"
                if page.monitor_check.isChecked() else ""),
             f"save pending: {_yes(page.save_timer.isActive())}"]
    return ", ".join(parts)


def _tribe_maps(window):
    tribe = window.netmap_tab.tribe
    maps = tribe.maps
    if maps is None:
        return "not started"
    parts = [f"online: {_yes(maps.online)}"]
    if tribe.error:
        parts.append(f"last error: {tribe.error}")
    if tribe.last_sync:
        parts.append(f"last synced {datetime.datetime.fromtimestamp(tribe.last_sync):%H:%M:%S}")
    if maps.lock.acquire(blocking=False):  # Not if the sync thread has it: this mustn't wait
        try:
            parts.append(f"changes waiting to send: {maps.pending_count()}")
            parts.append(f"server API {maps.server_api}")
        finally:
            maps.lock.release()
    else:
        parts.append("(the sync thread is busy with the copy)")
    thread = tribe.thread
    parts.append(f"sync thread: {'running' if thread is not None and thread.isRunning() else 'not running'}")
    return ", ".join(parts)


def _ipam(window):
    page = window.ipam_tab
    team = page.team
    parts = [f"showing {'the tribe' if page.source != 'local' else 'this computer'}'s networks"]
    if team is None:
        parts.append("not connected to the tribe")
    else:
        parts.append(f"tribe online: {_yes(team.online)}")
        if team.last_error:
            parts.append(f"last error: {team.last_error}")
        parts.append(f"changes waiting to send: {team.pending_count()}")
    parts.append(f"syncing: {_yes(page.syncing)}")
    parts.append(f"sweeping: {_yes(page.sweep_worker is not None)}")
    return ", ".join(parts)


def _terminal(window):
    page = window.terminal_tab
    views = [view for tabs in page.all_tabs() for view in tabs.views()]
    connected = sum(1 for view in views if getattr(view, "state", None) == "connected")
    return f"{len(views)} sessions open ({connected} connected), {len(page.windows)} session windows"


def _process():
    memory = process_memory_mb()
    return (f"{threading.active_count()} Python threads" + (f", {memory} MB in use" if memory is not None else "") +
            f", pid {os.getpid()}")
