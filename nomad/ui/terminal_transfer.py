"""File-menu export and import dialogs for saved terminal configuration."""
from PyQt5.QtWidgets import QFileDialog, QInputDialog, QLineEdit, QMessageBox

from ..terminal.backup import BackupError, read_backup, restore_backup, write_backup
from ..terminal.credentials import CredentialError
from ..terminal.securecrt import SecureCrtError, write_securecrt_export
from ..terminal.sessions import SSH
from ..terminal.vault import VaultLocked
from .vault_dialog import ensure_unlocked


def export_securecrt(window):
    store = window.terminal_tab.store
    sessions = store.sessions
    if not any(session.protocol == SSH for session in sessions):
        QMessageBox.information(window, "Export to SecureCRT", "There are no saved SSH sessions to export.")
        return
    path, _ = QFileDialog.getSaveFileName(window, "Export SSH Sessions to SecureCRT", "nomad-securecrt.xml",
                                        "SecureCRT XML (*.xml)")
    if not path:
        return
    password_count = sum(1 for session in sessions if session.protocol == SSH and session.saved_password)
    passphrase = ""
    if password_count:
        passphrase = securecrt_passphrase(window)
        if passphrase is None or not ensure_unlocked(window, store, "Unlock NOMAD to export saved SSH passwords."):
            return
    try:
        count = write_securecrt_export(path, sessions, store.vault.reveal if password_count else None, passphrase)
    except (OSError, SecureCrtError, CredentialError, VaultLocked) as error:
        QMessageBox.critical(window, "Export to SecureCRT", f"Couldn't export the sessions:\n\n{error}")
        return
    password_message = (f"\n\nIncluded {password_count} saved password{'s' if password_count != 1 else ''}, encrypted "
                        "with the configuration passphrase you entered. The destination SecureCRT configuration "
                        "must use that same passphrase before importing."
                        if password_count else "\n\nThese sessions have no saved SSH passwords.")
    QMessageBox.information(window, "Export to SecureCRT",
                            f"Exported {count} SSH sessions.\n\nIn SecureCRT, use Tools > Import Settings from "
                            "XML File and select this file. Folders, hosts, ports, usernames, notes and key file "
                            "paths are included. Private key files and saved key passphrases are not included." +
                            password_message)


def securecrt_passphrase(window):
    title = "SecureCRT Configuration Passphrase"
    while True:
        passphrase, ok = QInputDialog.getText(
            window, title,
            "Enter the configuration passphrase used by the destination SecureCRT installation. "
            "If it has none, set one in SecureCRT before importing.\n\n"
            "NOMAD encrypts the exported SSH passwords with this passphrase. "
            "It is separate from your NOMAD master password.", QLineEdit.Password)
        if not ok:
            return None
        if not passphrase:
            QMessageBox.warning(window, title, "Enter a non-empty configuration passphrase.")
            continue
        repeated, ok = QInputDialog.getText(window, title, "Confirm the SecureCRT configuration passphrase.",
                                          QLineEdit.Password)
        if not ok:
            return None
        if repeated == passphrase:
            return passphrase
        QMessageBox.warning(window, title, "The configuration passphrases don't match. Try again.")


def backup_password(window, exporting):
    title = "Export NOMAD Terminal" if exporting else "Import NOMAD Terminal"
    prompt = ("Choose a backup password (at least 8 characters). This protects all settings and saved credentials. "
              "You will need it to import this file." if exporting else "Enter this file's backup password.")
    password, ok = QInputDialog.getText(window, title, prompt, QLineEdit.Password)
    if not ok:
        return None
    if exporting:
        if len(password) < 8:
            QMessageBox.warning(window, title, "Use at least 8 characters for the backup password.")
            return None
        repeated, ok = QInputDialog.getText(window, title, "Confirm the backup password.", QLineEdit.Password)
        if not ok:
            return None
        if repeated != password:
            QMessageBox.warning(window, title, "The backup passwords don't match.")
            return None
    return password


def export_terminal(window):
    tab = window.terminal_tab
    path, _ = QFileDialog.getSaveFileName(window, "Export NOMAD Terminal Settings and Sessions",
                                        "nomad-terminal.nomad", "NOMAD terminal backup (*.nomad)")
    if not path:
        return
    password = backup_password(window, True)
    if password is None or not ensure_unlocked(window, tab.store, "Unlock saved credentials to include them in the backup."):
        return
    try:
        window.save_settings()
        write_backup(path, password, tab.store, tab.commands, tab.highlights, window.settings)
    except (OSError, BackupError, CredentialError, VaultLocked, TypeError) as error:
        QMessageBox.critical(window, "Export NOMAD Terminal", f"Couldn't export the backup:\n\n{error}")
        return
    QMessageBox.information(window, "Export NOMAD Terminal",
                            "Exported terminal settings, all saved sessions and credentials, recent connections, "
                            "command buttons and highlighting.\n\nPrivate key files and terminal logs are not "
                            "embedded; their paths are preserved. Live connections are not restored.")


def import_terminal(window):
    tab = window.terminal_tab
    path, _ = QFileDialog.getOpenFileName(window, "Import NOMAD Terminal Settings and Sessions", "",
                                        "NOMAD terminal backup (*.nomad)")
    if not path:
        return
    password = backup_password(window, False)
    if password is None:
        return
    try:
        data = read_backup(path, password)
    except (OSError, BackupError) as error:
        QMessageBox.critical(window, "Import NOMAD Terminal", str(error))
        return
    answer = QMessageBox.question(window, "Import NOMAD Terminal",
                                  f"Restore {len(data['sessions'])} saved sessions and all terminal settings?\n\n"
                                  "This replaces your saved sessions, recent connections, command buttons, "
                                  "highlighting and Terminal/SCP/RDP preferences. Existing live connections stay open. "
                                  "Credentials will use this installation's master password protection.\n\n"
                                  "Export a backup first if you want to keep the current configuration.",
                                  QMessageBox.Yes | QMessageBox.No)
    if answer != QMessageBox.Yes:
        return
    if not ensure_unlocked(window, tab.store, "Unlock NOMAD to restore the saved credentials."):
        return
    try:
        restore_backup(data, tab.store, tab.commands, tab.highlights, window.settings)
        tab.restore_settings(window.settings)
        window.scp_tab.restore_settings(window.settings)
        if hasattr(window, "rdp_tab"):
            window.rdp_tab.restore_settings(window.settings)
        window.set_text_scale(window.settings.value("view/text_scale", 1.0, float))
    except (OSError, CredentialError, VaultLocked, ValueError, TypeError) as error:
        QMessageBox.critical(window, "Import NOMAD Terminal", f"Couldn't finish restoring the backup:\n\n{error}")
        return
    QMessageBox.information(window, "Import NOMAD Terminal", "Restored NOMAD terminal settings and sessions.")
