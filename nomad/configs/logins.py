"""How scheduled backups log in to devices. It's set in one place, the Editor's Backups tab, and used by NOMAD's own
backups, Pull Config and the Map Watcher service on this computer.

Kept on this computer in backup_logins.json in NOMAD's app data folder: {"version": 2, "devices": {device id: saved
credential id} (Device Logins...), "usual": the usual login's saved credential id ("" for a user name and password
asked for; left out until it's first chosen), "enable": the enable password (encrypted with the session store's
vault, so the master password protects it)}. The file used to hold only the devices. Device ids are the archive's
(scope.device_id: the management address, else the name).

A device's own login comes first, then its saved SSH session, then the usual login. The Map Watcher service has no
saved sessions or credentials of its own, so NOMAD copies the logins it needs into its config (service_plan,
service_backups): the usual login, each device's own login, and the login of each archive device's saved SSH session,
with their passwords encrypted for this computer. signature says whether the service's copy is still current without
reading a password.
"""
import hashlib
import json
import logging
import os

log = logging.getLogger(__name__)

FILE_NAME = "backup_logins.json"
VERSION = 2


def default_path():
    from ..system import app_data_dir
    return os.path.join(app_data_dir(), FILE_NAME)


def read(path=None):
    """{"devices": {device id: credential id}, "usual": credential id, "" or None (never chosen), "enable": the
    encrypted enable password or ""} (all empty when there's no file or it can't be read)."""
    try:
        with open(path or default_path(), encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    if "version" not in data:  # The first version: only the devices
        data = {"devices": data}
    devices = data.get("devices") if isinstance(data.get("devices"), dict) else {}
    usual = data.get("usual")
    return {"devices": {str(device).strip().lower(): str(credential) for device, credential in devices.items()
                        if device and credential},
            "usual": str(usual) if usual is not None else None, "enable": str(data.get("enable") or "")}


def write(data, path=None):
    path = path or default_path()
    from ..system import replace_file
    out = {"version": VERSION,
           "devices": {device: credential for device, credential in sorted((data.get("devices") or {}).items())
                       if credential},
           "enable": data.get("enable") or ""}
    if data.get("usual") is not None:
        out["usual"] = data["usual"]
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=1)
    replace_file(temporary, path)


def load(path=None):
    """{device id: credential id} ({} when there's none or it can't be read)."""
    return read(path)["devices"]


def save(chosen, path=None):
    """Save the devices' own logins (the usual login and enable password are kept)."""
    data = read(path)
    data["devices"] = dict(chosen)
    write(data, path)


def move_devices(sources, target, path=None):
    """Devices merged into target (target None: forgotten): a source's own login goes to target when target has
    none, and the sources' are dropped. Returns whether the file changed."""
    data = read(path)
    devices = data["devices"]
    moved = False
    for source in sources:
        credential = devices.pop(source, None)
        if credential is None:
            continue
        moved = True
        if target is not None:
            devices.setdefault(target, credential)
    if moved:
        write(data, path)
    return moved


def save_usual(credential_id, path=None):
    data = read(path)
    data["usual"] = credential_id or ""
    write(data, path)


def save_enable(protected, path=None):
    """The enable password, already encrypted (vault.protect), or "" for none."""
    data = read(path)
    data["enable"] = protected or ""
    write(data, path)


# --------------------------------------------------------------------- What the Map Watcher service gets

def usable(item):
    """Whether a credential or session can log in with nobody there: a user name and a saved password."""
    from ..terminal.sessions import AUTH_PASSWORD
    return item.auth == AUTH_PASSWORD and bool(item.saved_password) and bool(item.username)


def service_plan(store, usual_id, chosen, devices):
    """The logins the service needs, with their passwords still encrypted: (the usual login (username, stored
    password, label) or None, {device id: login key}, {login key: (username, stored password, label)}).

    store: the session store. chosen: the devices' own logins ({device id: credential id}). devices: the archive's
    ({"id", "address", "names"}). Each device without its own login gets its saved SSH session's login (matched as
    NOMAD's backups match them), keyed by the session's credential when it has one so a credential is copied once."""
    usual = store.credentials.get(usual_id) if usual_id else None
    usual_login = (usual.username, usual.saved_password, f"credential {usual.name}") \
        if usual is not None and usable(usual) else None
    sessions = ssh_sessions(store)
    listed = {device["id"] for device in devices}
    rows = list(devices) + [{"id": device_id} for device_id in chosen if device_id not in listed]
    mapped, logins = {}, {}
    for device in rows:
        device_id = device["id"]
        credential = store.credentials.get(chosen[device_id]) if chosen.get(device_id) else None
        if credential is not None and usable(credential):
            key, login = credential.id, (credential.username, credential.saved_password,
                                         f"credential {credential.name}")
        else:
            session = session_for(sessions, device)
            if session is None or not usable(session):
                continue
            linked = store.credentials.get(session.credential_id) if session.credential_id else None
            if linked is not None:
                key, label = linked.id, f"credential {linked.name}"
            else:
                key, label = f"session:{session.id}", f"saved session {session.name}"
            login = (session.username, session.saved_password, label)
        mapped[device_id] = key
        logins[key] = login
    return usual_login, mapped, logins


def ssh_sessions(store):
    """The saved SSH sessions with their credentials filled in (copies keeping their ids)."""
    from ..terminal.sessions import SSH
    return [store.credentials.apply(session.copy(id=session.id)) for session in store.sessions
            if session.protocol == SSH]


def session_for(sessions, device):
    """The saved session for an archive device ({"id", "address", "names"}), matched by any of its addresses and
    names as NOMAD's backups match them, or None."""
    from ..terminal.sessions import same_host
    hosts = [host for host in (device.get("address") or device["id"], *(device.get("names") or ())) if host]
    return next((item for item in sessions if any(same_host(item.host, host) for host in hosts)), None)


def signature(plan, enable="", trust_new=True):
    """A hash of a service_plan and the encrypted enable password. It stays the same while nothing the service logs in
    with has changed, so the service's copy can be checked without the master password."""
    usual, mapped, logins = plan
    text = json.dumps([list(usual) if usual else None, sorted(mapped.items()),
                       sorted((key, list(login)) for key, login in logins.items()), enable or "", bool(trust_new)])
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def service_backups(plan, reveal, enable="", trust_new=True, signed=""):
    """watch_service.make_config's backups from a service_plan, the passwords read with reveal(stored) (which may
    raise VaultLocked or CredentialError). enable: as typed. signed: the plan's signature, kept in the config."""
    usual, mapped, logins = plan
    username, stored, label = usual if usual is not None else ("", "", "")
    return {"username": username, "password": reveal(stored) if stored else "", "label": label, "enable": enable,
            "trust_new": bool(trust_new), "credential_id": "", "devices": dict(mapped),
            "logins": {key: {"username": user, "password": reveal(secret), "label": text}
                       for key, (user, secret, text) in logins.items()},
            "signature": signed}


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
