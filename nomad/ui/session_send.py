"""Typing configuration into a terminal session to a switch, for the pages that build it (SNMP Config, Carry VLAN):
choose a session that's connected, or open an SSH session (saved, to the device, or new) and send once it shows its
enable (#) prompt. Every send is asked about first, and lines go one at a time so slow consoles keep up."""
from PyQt5.QtCore import QObject, QTimer
from PyQt5.QtWidgets import QInputDialog, QMessageBox

from ..terminal.sessions import SSH, TELNET
from .common import set_hint

SEND_DELAY = 150  # ms between lines sent to a switch: older Catalysts drop characters from a fast paste
PROMPT_WAIT = 20000  # ms to wait for a session just opened to show its prompt


def prompt_of(view):
    """The text on the session's cursor line: its prompt, when it's waiting for a command."""
    model = view.model
    return model.line_text(model.cursor_position().line).strip()


class SessionSender(QObject):
    """Sends lines into terminal sessions for a page. status_label shows how it went; text() gives what to send
    when it's sent (for a session opened to send to, once it shows its prompt)."""

    def __init__(self, page, window, status_label):
        super().__init__(page)
        self.page, self.window, self.status_label = page, window, status_label
        self.waiting = None  # (view, QTimer, text, tag) for a session opened to send to, until it shows its prompt

    def terminal(self):
        return getattr(self.window, "terminal_tab", None)

    def connected_sessions(self):
        from .terminal_view import CONNECTED
        terminal = self.terminal()
        if terminal is None:
            return []
        return [view for view in terminal.all_views() if view.state == CONNECTED and hasattr(view, "send_block")]

    def fill_menu(self, menu, text, device=None, tag=None):
        """The connected sessions to send to, then Open SSH Session (and, for a device, Open SSH Session to it
        first). text: a callable giving the lines when they're sent. device: {"address", "aliases", "name",
        "folder"} for a device's own sessions (its connected ones are listed first). tag: handed to the page's
        lines_sent(view, tag) once they're sent, to say what was."""
        menu.clear()
        views = self.connected_sessions()
        if device:
            names = {name.lower() for name in [device.get("address", ""), device.get("name", ""),
                                               *device.get("aliases", ())] if name}
            views.sort(key=lambda view: view.title.lower() not in names)
        for view in views:
            prompt = prompt_of(view)
            label = f"{view.title}" + (f"  ({prompt})" if prompt else "")
            menu.addAction(label, lambda view=view: self.send_to(view, text(), tag=tag))
        if not views:
            menu.addAction("No terminal sessions connected").setEnabled(False)
        menu.addSeparator()
        if device and device.get("address"):
            label = f"Open Session to {device.get('name') or device['address']}"
            menu.addAction(label, lambda: self.open_device(device, text, tag))
        self.fill_open_menu(menu.addMenu("Open SSH Session"), text, tag)

    def fill_open_menu(self, menu, text, tag=None):
        """New Session, then the saved SSH sessions, in their folders as on the Terminal page."""
        menu.addAction("New Session...", lambda: self.open_new_session(text, tag))
        terminal = self.terminal()
        store = getattr(terminal, "store", None)
        sessions = sorted((session for session in (store.sessions if store is not None else [])
                           if session.protocol == SSH), key=lambda session: session.name.lower())
        menu.addSeparator()
        if not sessions:
            menu.addAction("No saved SSH sessions").setEnabled(False)
            return
        submenus = {"": menu}

        def folder_menu(path):
            if path not in submenus:
                parent, _, name = path.rpartition("/")
                submenus[path] = folder_menu(parent).addMenu(name)
            return submenus[path]
        for path in sorted({session.folder for session in sessions if session.folder}, key=str.lower):
            folder_menu(path)
        for session in sessions:
            action = folder_menu(session.folder).addAction(
                session.name, lambda session=session: self.open_saved(session, text, tag))
            action.setToolTip(session.target())

    def send_to(self, view, text, what="", tag=None):
        """Type the lines into view's session, after asking. Returns whether they're being sent."""
        lines = [line for line in text.splitlines() if line.strip()]
        if not lines:
            return False
        prompt = prompt_of(view)
        what = f" ({what})" if what else ""
        question = (f"Type these {len(lines)} lines{what} into {view.title}, one every {SEND_DELAY} ms?\n\n"
                    f"Its prompt is now: {prompt or '(nothing yet)'}")
        icon = QMessageBox.Question
        if not prompt.endswith("#"):
            question += ("\n\nThat doesn't look like the enable (#) prompt, so the configuration commands would be "
                         "refused. Type enable (and its password) in the session first.")
            icon = QMessageBox.Warning
        box = QMessageBox(icon, "Send to Session", question, QMessageBox.Yes | QMessageBox.No, self.page)
        if box.exec_() != QMessageBox.Yes:
            return False
        if not view.send_block(text, min_delay=SEND_DELAY):
            set_hint(self.status_label, f"{view.title} isn't connected any more.", "error")
            return False
        set_hint(self.status_label, f"Sending {len(lines)} lines to {view.title}. Watch its answers on the "
                                    "Terminal page.", "success")
        callback = getattr(self.page, "lines_sent", None)
        if callback is not None:
            callback(view, tag)
        self.show_session(view)
        return True

    def show_session(self, view):
        terminal = self.terminal()

        def reveal():
            for tabs in terminal.all_tabs():
                if tabs.pane_of(view) is not None:
                    tabs.show_view(view)
        if hasattr(self.window, "show_terminal"):
            self.window.show_terminal(reveal)

    def open_new_session(self, text, tag=None):
        """An SSH session to a switch that isn't saved, then send to it once it shows its prompt."""
        terminal = self.terminal()
        if terminal is None:
            return
        address, ok = QInputDialog.getText(self.page, "New SSH Session", "Switch to connect to (such as "
                                           "admin@10.0.0.1 or admin@switch:2222):")
        address = address.strip()
        if not ok or not address:
            return
        view = terminal.open_address(address, SSH, use_saved=False)
        if view is not None:
            self.wait_for_prompt(view, text, tag)

    def open_saved(self, session, text, tag=None):
        """A saved SSH session (its user name and saved password), then send to it once it shows its prompt."""
        terminal = self.terminal()
        if terminal is not None:
            self.wait_for_prompt(terminal.open_session(session), text, tag)

    def open_device(self, device, text, tag=None):
        """A session to a device: its saved SSH session if there is one (asking which if several), else its saved
        Telnet one (a switch without SSH), else a new SSH session named after it; then send to it once it shows its
        prompt."""
        terminal = self.terminal()
        if terminal is None:
            return
        address, aliases = device["address"], device.get("aliases", ())
        protocol = SSH
        matches = getattr(terminal, "saved_matches", None)
        if matches is not None and not matches(address, aliases, SSH) and matches(address, aliases, TELNET):
            protocol = TELNET
        view = terminal.open_address(address, protocol, aliases=aliases, name=device.get("name", ""),
                                     folder=device.get("folder", ""))
        if view is not None:
            self.wait_for_prompt(view, text, tag)

    def wait_for_prompt(self, view, text, tag=None):
        """Once the session just opened shows a prompt, offer to send to it."""
        from .terminal_view import CONNECTED, DISCONNECTED
        self.stop_waiting()
        if view is None:
            return
        timer = QTimer(self)
        timer.setInterval(500)
        waited = [0]

        def check():
            waited[0] += timer.interval()
            prompt = prompt_of(view) if view.state == CONNECTED else ""
            if view.state == DISCONNECTED or waited[0] > PROMPT_WAIT:
                self.stop_waiting()
                set_hint(self.status_label, f"{view.title} didn't connect, so nothing was sent.", "warning")
            elif prompt.endswith("#"):
                self.stop_waiting()
                QTimer.singleShot(0, lambda: self.send_to(view, text(), tag=tag))
            elif prompt.endswith(">"):
                self.stop_waiting()
                set_hint(self.status_label, f"{view.title} is at the > prompt: type enable (and its password) "
                                            "there, then Send to Session again.", "warning")
        timer.timeout.connect(check)
        timer.start()
        self.waiting = (view, timer, text, tag)
        set_hint(self.status_label, f"Connecting to {view.title}...", "info")

    def stop_waiting(self):
        if self.waiting is not None:
            self.waiting[1].stop()
            self.waiting[1].deleteLater()
            self.waiting = None
