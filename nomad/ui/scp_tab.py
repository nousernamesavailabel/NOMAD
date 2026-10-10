"""SCP page: browse and copy files on SSH servers, WinSCP-style, using the same saved sessions as the Terminal page.
Each tab is its own SSH connection; tabs can be popped out into windows."""
from PyQt5.QtWidgets import QMessageBox

from ..terminal.sessions import SSH
from .common import run_in_background
from .remote_editor import clean_old_edits
from .scp_view import FileSessionView
from .session_page import SessionPage


class ScpTab(SessionPage):
    protocols = {SSH}
    settings_prefix = "scp"
    window_title = "NOMAD SCP"
    kind = "SCP session"
    placeholder_text = ("Double-click a saved SSH session to browse its files, or type an address in Quick "
                        "connect.\n\nYour computer is on the left and the server on the right. Drag files between "
                        "them (or from Windows Explorer), or select them and press F5. F4 edits a remote file, F2 "
                        "renames, F7 makes a folder and F8 deletes.\n\nSFTP is used where the server offers it "
                        "(interrupted transfers resume); otherwise NOMAD falls back to SCP.")

    def __init__(self, window, store):
        super().__init__(window, store)
        run_in_background(clean_old_edits)  # Copies left by "Edit With" when NOMAD didn't close normally

    def make_view(self, session):
        return FileSessionView(session, self.store, self)

    def companion_actions(self, session):
        return [("Open in Terminal", lambda: self.window.terminal_tab.open_session(session))]

    def confirm_close(self):
        """Before the app closes: only transfers still to finish and unsaved edits are worth asking about."""
        problems = [view for view in self.all_views() if view.problems()]
        if not problems:
            return True
        lines = [f"{view.session.name}: {' and '.join(view.problems())}" for view in problems]
        reply = QMessageBox.question(self.window, "SCP", "\n".join(lines) + "\n\nClose NOMAD anyway?",
                                     QMessageBox.Yes | QMessageBox.No)
        return reply == QMessageBox.Yes
