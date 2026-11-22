"""How backups log in is set in one place, the Editor's Backups tab: Log in with (the usual login), Enable password,
Trust new SSH keys and Device Logins.... BackupLoginSync keeps those choices in configs/logins.py's file and gives the
Map Watcher service on this computer the same logins.

Whenever they change, the service's config is rewritten on the spot, asking for the master password if it's locked
(someone just changed them, so they're there to type it). Saved sessions and the archive's devices change too, so the
Editor also checks now and then (at start and while the Backups tab is shown). It compares a signature first, so it
reads no password while nothing has changed, and with the master password locked it leaves a link to update the
service instead of asking. Writing the service's config needs administrator rights; without them, nothing is read.

The Map Watcher's window shows what the service logs in with and links here; it no longer has logins of its own.
"""
import logging

from PyQt5.QtCore import QObject

from ..configs import logins as backup_logins
from ..terminal.vault import VaultLocked
from .common import set_hint
from .vault_dialog import ensure_unlocked

log = logging.getLogger(__name__)

UNLOCK_REASON = "The Map Watcher service needs the backup logins' passwords."
UPDATE_LINK = "update-service-logins"


def machine_protect(text):
    from ..terminal.credentials import protect
    return protect(text, machine=True)


class BackupLoginSync(QObject):
    """The Editor's backup logins, saved and copied to the Map Watcher service. editor: the EditorTab (its login_row,
    configs and backups_panel)."""

    def __init__(self, editor):
        super().__init__(editor)
        self.editor = editor
        self.enable_saved = ""  # The enable password as it's saved (plain), to know when it changed
        self.problem = ""  # Why the service's logins couldn't be updated, shown in the Backups tab

    # ----------------------------------------------------------------- The Editor's choices

    @property
    def store(self):
        return self.editor.login_row.sessions

    def usual_id(self):
        picker = self.editor.login_row.picker
        return picker.credential_id() if picker is not None else ""

    def trust_new(self):
        return self.editor.login_row.trust_check.isChecked()

    def enable_text(self):
        return self.editor.login_row.enable_input.text()

    def restore(self):
        """At start, after the Editor's settings: the file's usual login and enable password. When the Editor has no
        usual login yet, the Map Watcher's is taken (it used to be chosen in its window)."""
        data = backup_logins.read()
        row = self.editor.login_row
        if row.picker is None or self.store is None:
            return
        if data["usual"] is not None:
            row.picker.fill(data["usual"])
        service = self.service_backups_config()
        if not self.usual_id() and service:
            credential = self.store.credentials.get(service.get("credential_id", ""))
            if credential is None:  # From before the credential was noted: "credential NAME"
                name = (service.get("label") or "").removeprefix("credential ")
                credential = next((item for item in self.store.credentials.items if item.name == name), None)
            if credential is not None:
                row.picker.fill(credential.id)
        if data["usual"] != self.usual_id():
            self.save_usual()
        self.fill_enable(data["enable"], service)

    def fill_enable(self, stored=None, service=None):
        """Show the saved enable password (once the master password allows), or the Map Watcher's when none is
        saved here (it used to be typed there)."""
        row = self.editor.login_row
        if row.enable_input.text():
            return
        stored = backup_logins.read()["enable"] if stored is None else stored
        text = ""
        if stored:
            try:
                text = self.store.vault.reveal(stored)
            except VaultLocked:
                row.enable_input.setPlaceholderText("Saved: shown once the master password is unlocked")
                return
            except Exception as error:  # Saved by another Windows account, or another master password
                log.info("Couldn't read the saved enable password: %s", error)
        elif service and service.get("enable"):
            try:
                from ..terminal.credentials import unprotect
                text = unprotect(service["enable"])
            except Exception as error:
                log.info("Couldn't read the Map Watcher's enable password: %s", error)
        row.enable_input.blockSignals(True)
        row.enable_input.setText(text)
        row.enable_input.blockSignals(False)
        row.enable_input.setPlaceholderText("If they log in at >")
        self.enable_saved = text if stored else ""

    def save_usual(self):
        try:
            backup_logins.save_usual(self.usual_id())
        except OSError as error:
            log.warning("Couldn't save the usual backup login: %s", error)

    def save_enable(self, ask=True):
        """Save the enable password if it changed (encrypted with the vault). False if the master password was
        needed and not given (it's used until NOMAD closes all the same)."""
        text = self.enable_text()
        if text == self.enable_saved:
            return True
        if not text:
            protected = ""
        else:
            try:
                protected = self.store.vault.protect(text)
            except VaultLocked:
                if not ask or not ensure_unlocked(self.editor, self.store,
                                                  "The master password is needed to save the enable password."):
                    return False
                protected = self.store.vault.protect(text)
        try:
            backup_logins.save_enable(protected)
        except OSError as error:
            log.warning("Couldn't save the enable password: %s", error)
            return False
        self.enable_saved = text
        return True

    def changed(self):
        """Log in with, the enable password or Trust new SSH keys changed (by hand), or Device Logins: save them and
        give the service the same."""
        self.save_usual()
        self.save_enable()
        self.update_service(ask=True)

    # ----------------------------------------------------------------- The Map Watcher service

    def archive_devices(self):
        configs = self.editor.configs
        if configs is None:
            return []
        with configs.lock:
            return configs.store.devices()

    def plan(self):
        return backup_logins.service_plan(self.store, self.usual_id(), backup_logins.load(), self.archive_devices())

    def signature(self, plan):
        return backup_logins.signature(plan, backup_logins.read()["enable"], self.trust_new())

    @staticmethod
    def service_config():
        """The Map Watcher's config, or None (not installed here, or not readable without administrator rights)."""
        from ..netmap import watch_service
        try:
            return watch_service.load_config()
        except (OSError, ValueError):
            return None

    def service_backups_config(self):
        config = self.service_config()
        return (config or {}).get("backups") or None

    def backups_for_service(self, parent, old=None, ask=True):
        """make_config's backups for the service: {"keep": old} when nothing changed since old was written (no
        password read), else the logins with their passwords read (asking for the master password if ask). None
        if they couldn't be read (self.problem says why)."""
        self.problem = ""
        plan = self.plan()
        signed = self.signature(plan)
        if old and old.get("signature") == signed:
            return {"keep": old}
        if self.store.vault.enabled and not self.store.vault.unlocked and \
                (not ask or not ensure_unlocked(parent, self.store, UNLOCK_REASON)):
            self.problem = "locked"
            return None
        self.fill_enable()
        self.save_enable(ask=False)
        signed = self.signature(plan)  # The enable password may have just been saved
        try:
            return backup_logins.service_backups(plan, self.store.vault.reveal, self.enable_text(), self.trust_new(),
                                                 signed)
        except Exception as error:  # A password saved by another account or master password
            self.problem = f"Couldn't read a saved password: {error}"
            log.warning("Backup logins for the Map Watcher: %s", self.problem)
            return None

    def update_service(self, ask=False):
        """Give the Map Watcher service here the Editor's logins, if it runs backups and they've changed. ask: the
        master password may be asked for (else a locked one leaves a link in the Backups tab)."""
        config = self.service_config()
        old = (config or {}).get("backups")
        if not old:  # Not installed here, not running backups, or not readable (not administrator)
            self.show_note("")
            return
        backups = self.backups_for_service(self.editor, old, ask)
        if backups is None:
            self.show_note(self.problem)
            return
        if "keep" in backups:
            self.show_note("")
            return
        from ..netmap import watch_service
        config["backups"] = watch_service.protect_backups(backups, machine_protect)
        try:
            watch_service.save_config(config)
        except OSError as error:
            self.show_note(f"Couldn't update the Map Watcher service's logins: {error}")
            return
        log.info("Gave the Map Watcher service the backup logins (%d devices with their own or a saved session's)",
                 len(backups["devices"]))
        self.show_note("updated")

    def show_note(self, problem):
        label = self.editor.backups_panel.service_note
        if problem == "locked":
            set_hint(label, "The Map Watcher service on this computer still has the old backup logins: they need the "
                            f"master password. <a href=\"{UPDATE_LINK}\">Update the Service's Logins...</a>",
                     "warning")
        elif problem == "updated":
            set_hint(label, "The Map Watcher service on this computer now logs in the same way.", "success")
        elif problem:
            set_hint(label, problem, "error")
        else:
            label.setText("")

    def summary(self):
        """What the service logs in with, for the Map Watcher's window."""
        usual, mapped, _ = self.plan()
        chosen = backup_logins.load()
        own = sum(1 for device_id, key in mapped.items() if chosen.get(device_id) == key)
        sessions = len(mapped) - own
        parts = [f"the usual login is {usual[2]}" if usual else
                 "there's no usual login with a saved password, so devices without their own login or a saved "
                 "session can't be backed up"]
        if sessions:
            parts.append(f"{sessions} device{'s' if sessions != 1 else ''} use{'s' if sessions == 1 else ''} "
                         f"{'its' if sessions == 1 else 'their'} saved SSH session's login")
        if own:
            parts.append(f"{own} device{'s' if own != 1 else ''} use{'s' if own == 1 else ''} "
                         f"{'its' if own == 1 else 'their'} own login")
        return "; ".join(parts), usual is not None or bool(mapped)
