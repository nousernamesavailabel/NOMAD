"""Which login scheduled backups use for each device, when it isn't the usual one.

Set in the Editor's Backups tab (Device Logins...) and kept on this computer: backup_logins.json in NOMAD's app data
folder, {device id: saved credential id}. Device ids are the archive's (scope.device_id: the management address, else
the name). The Editor's backups use them as they are; the Map Watcher's window copies the chosen credentials into the
service's settings when it installs or updates the service (the service has no saved credentials of its own).

A device's own login comes first, then its saved SSH session, then the usual login.
"""
import json
import logging
import os

log = logging.getLogger(__name__)

FILE_NAME = "backup_logins.json"


def default_path():
    from ..system import app_data_dir
    return os.path.join(app_data_dir(), FILE_NAME)


def load(path=None):
    """{device id: credential id} ({} when there's none or it can't be read)."""
    try:
        with open(path or default_path(), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(device).strip().lower(): str(credential) for device, credential in data.items()
            if device and credential}


def save(chosen, path=None):
    path = path or default_path()
    from ..system import replace_file
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump({device: credential for device, credential in sorted(chosen.items()) if credential}, handle,
                  indent=1)
    replace_file(temporary, path)


class DeviceLogins:
    """Logins (macssh.SshLogins' way) that use a device's own login when it has one, else base's.

    own(device id) -> (Session with the user name and secrets, what it is such as "credential TACACS"), or None.
    It's asked at each login, so a credential changed since is used."""

    def __init__(self, base, own):
        self.base, self.own = base, own

    @property
    def password(self):  # Typed for a login with no saved password (configpush asks for it)
        return getattr(self.base, "password", None)

    def login_for(self, address, names=()):
        for host in (address, *names):
            found = self.own(str(host or "").strip().lower()) if host else None
            if found is not None:
                session, label = found
                return session.copy(host=address, port=22, name=names[0] if names else address), label
        return self.base.login_for(address, names)

    def for_device(self, address, names=()):
        return self.login_for(address, names)[0]
