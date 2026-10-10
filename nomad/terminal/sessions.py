"""Saved terminal sessions (SSH, Telnet, serial, raw TCP), organized in folders, plus importing PuTTY's sessions."""
import dataclasses
import ipaddress
import json
import logging
import os
import re
import time
import uuid
from dataclasses import dataclass, field
from urllib.parse import unquote

from ..system import app_data_dir, replace_file
from .vault import Vault

log = logging.getLogger(__name__)

SSH, TELNET, SERIAL, RAW = "SSH", "Telnet", "Serial", "Raw TCP"
RDP = "RDP"
TERMINAL_PROTOCOLS = [SSH, TELNET, SERIAL, RAW]
PROTOCOLS = [*TERMINAL_PROTOCOLS, RDP]
DEFAULT_PORTS = {SSH: 22, TELNET: 23, RAW: 23, RDP: 3389}
AUTH_PASSWORD, AUTH_KEY, AUTH_AGENT = "password", "key", "agent"
FILE_PROTOCOLS = ["Auto", "SFTP", "SCP"]
PARITIES = ["None", "Even", "Odd", "Mark", "Space"]
FLOW_CONTROLS = ["None", "XON/XOFF", "RTS/CTS", "DSR/DTR"]
BAUD_RATES = [1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600]
LINE_ENDINGS = {"CR": "\r", "LF": "\n", "CR+LF": "\r\n"}
ENCODINGS = ["utf-8", "cp437", "latin-1", "cp1252"]
FILE_NAME = "sessions.json"
FORMAT_VERSION = 1
RECENT_LIMIT = 10


@dataclass
class Session:
    name: str
    protocol: str = SSH
    host: str = ""
    port: int = 22
    folder: str = ""  # "Site A/Core"; "" for the top level
    # SSH
    username: str = ""
    auth: str = AUTH_PASSWORD
    saved_password: str = ""  # Encrypted with credentials.protect(); "" to ask each time
    key_file: str = ""
    saved_passphrase: str = ""  # For an encrypted key file, also encrypted
    keepalive: int = 30  # Seconds; 0 turns it off
    file_protocol: str = "Auto"  # The SCP page: "Auto" (SFTP if the server has it, else SCP), "SFTP" or "SCP"
    scp_sudo: bool = False  # The SCP page works as root, through sudo
    # Serial
    serial_port: str = "COM1"
    baud_rate: int = 9600
    data_bits: int = 8
    parity: str = "None"
    stop_bits: float = 1
    flow_control: str = "None"
    # Terminal
    terminal_type: str = "xterm-256color"
    encoding: str = "utf-8"
    backspace_sends_delete: bool = True  # DEL (^?) as most systems expect; off sends ^H
    local_echo: bool = False  # For raw TCP and serial devices that don't echo what you type
    line_ending: str = "CR"  # What Enter sends on raw TCP and serial
    scrollback: int = 10000
    log_to_file: bool = False
    log_folder: str = ""
    # Sending, and staying connected
    line_delay: int = 0  # Milliseconds between lines when pasting or sending several (slow consoles drop text)
    auto_reconnect: bool = False  # When the connection drops (such as a device reloading), until it's back
    anti_idle: int = 0  # Seconds without typing before sending anti_idle_text; 0 turns it off
    anti_idle_text: str = " \\b"  # Space, backspace: nothing to see at a prompt. See decode_escapes
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    rdp_fullscreen: bool = True
    rdp_multimon: bool = False
    rdp_width: int = 1280
    rdp_height: int = 800
    rdp_clipboard: bool = True
    rdp_audio: int = 0  # 0: this computer; 1: remote computer; 2: off
    rdp_admin: bool = False
    credential_id: str = ""  # A saved Credential whose user name and password (or key) this session logs in with

    @property
    def path(self):
        return f"{self.folder}/{self.name}" if self.folder else self.name

    def target(self):
        """Where it connects, for display: "admin@10.0.0.1", "COM3 9600 8N1", "10.0.0.5:9100"."""
        if self.protocol == SERIAL:
            parity = self.parity[0] if self.parity else "N"
            stop = int(self.stop_bits) if float(self.stop_bits).is_integer() else self.stop_bits
            return f"{self.serial_port} {self.baud_rate} {self.data_bits}{parity}{stop}"
        default = DEFAULT_PORTS.get(self.protocol)
        host = f"[{self.host}]" if ":" in self.host else self.host
        where = host if self.port == default else f"{host}:{self.port}"
        return f"{self.username}@{where}" if self.protocol in (SSH, RDP) and self.username else where

    def copy(self, **changes):
        """A copy with a new id (so it's a separate session), unless an id is given."""
        changes.setdefault("id", uuid.uuid4().hex)
        return dataclasses.replace(self, **changes)


def validate_session(session):
    """Returns an error message, or None."""
    if not session.name.strip():
        return "Give the session a name."
    if "/" in session.name:
        return "Session names can't contain \"/\" (it separates folders)."
    if session.protocol not in PROTOCOLS:
        return f"Unknown protocol {session.protocol}."
    if session.protocol == SERIAL:
        if not session.serial_port.strip():
            return "Choose a serial port, such as COM3."
        if session.baud_rate <= 0:
            return "Enter a baud rate, such as 9600."
        return None
    if not session.host.strip():
        return "Enter the host name or IP address to connect to."
    if session.protocol == RDP:
        from ..rdp import validate_rdp
        return validate_rdp(session)
    if not 1 <= int(session.port) <= 65535:
        return "The port must be between 1 and 65535."
    if session.protocol == SSH and session.auth == AUTH_KEY and not session.key_file.strip():
        return "Choose the private key file, or use password authentication."
    return None


ESCAPES = {"r": "\r", "n": "\n", "t": "\t", "b": "\b", "e": "\x1b", "\\": "\\", "0": "\x00"}


def decode_escapes(text):
    """Text typed with escapes, such as the anti-idle text: \\r \\n \\t \\b (backspace) \\e (Esc) \\0 \\\\
    and \\xNN. An unknown escape is kept as typed."""
    result = []
    index = 0
    while index < len(text):
        char = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if char == "\\" and following in ESCAPES:
            result.append(ESCAPES[following])
            index += 2
        elif char == "\\" and following == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", text[index + 2:index + 4]):
            result.append(chr(int(text[index + 2:index + 4], 16)))
            index += 4
        else:
            result.append(char)
            index += 1
    return "".join(result)


def normalize_folder(folder):
    return "/".join(part.strip() for part in folder.replace("\\", "/").split("/") if part.strip())


def session_from_dict(data):
    known = {item.name for item in dataclasses.fields(Session)}
    values = {key: value for key, value in data.items() if key in known}
    session = Session(**{"name": "Session", **values})
    session.folder = normalize_folder(session.folder)
    return session


def target_key(session):
    """What makes two connections "the same place", for the recent list."""
    if session.protocol == SERIAL:
        return SERIAL, session.serial_port.upper(), int(session.baud_rate)
    return session.protocol, session.host.lower(), int(session.port), session.username.lower()


def same_host(first, second):
    """Whether two host names or addresses are the same place: the same address (however it's written), the same
    name, or the same name with and without its domain ("core-sw1" and "core-sw1.corp.local")."""
    first, second = (text.strip().strip("[]").rstrip(".").lower() for text in (first or "", second or ""))
    if not first or not second:
        return False
    try:
        return ipaddress.ip_address(first) == ipaddress.ip_address(second)
    except ValueError:
        pass
    if first == second:
        return True
    if "." in first and "." in second:
        return False  # Two full names that differ
    if any(re.fullmatch(r"[\d.]+|.*:.*", text) for text in (first, second)):
        return False  # An address (or something like one) never matches a name by its first part
    return first.split(".")[0] == second.split(".")[0]


@dataclass
class Credential:
    """A named login (user name plus a saved password, or a key file) that many sessions can share, such as the same
    TACACS account on every switch. Sessions using it keep a copy of its user name and encrypted secrets, so every
    way of connecting works unchanged; changing the credential updates them all."""
    name: str
    username: str = ""
    auth: str = AUTH_PASSWORD
    saved_password: str = ""  # Encrypted like a session's; "" to ask each time
    key_file: str = ""
    saved_passphrase: str = ""
    notes: str = ""
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def summary(self):
        """How it logs in, for lists: "jsmith, saved password"."""
        how = {AUTH_KEY: "key file", AUTH_AGENT: "SSH agent"}.get(
            self.auth, "saved password" if self.saved_password else "password asked")
        return f"{self.username or 'user name asked'}, {how}"


def credential_from_dict(data):
    known = {item.name for item in dataclasses.fields(Credential)}
    return Credential(**{"name": "Credential", **{key: value for key, value in data.items() if key in known}})


CREDENTIAL_PROTOCOLS = {SSH, RDP}  # The ones that log in with a user name and password NOMAD supplies


class CredentialBook:
    """The saved credentials, kept in the sessions file. Only SSH and RDP sessions use them; RDP takes just the user
    name and password."""

    def __init__(self, store):
        self.store = store
        self.items = []
        self.default_id = ""  # Filled into new sessions

    def get(self, credential_id):
        return next((item for item in self.items if item.id == credential_id), None) if credential_id else None

    @property
    def default(self):
        return self.get(self.default_id)

    def sorted(self, protocol=None):
        """By name; for RDP only the ones with a password (RDP can't use a key)."""
        items = [item for item in self.items if protocol != RDP or item.auth == AUTH_PASSWORD]
        return sorted(items, key=lambda item: item.name.lower())

    def users(self, credential_id):
        """The saved sessions that log in with a credential."""
        return [session for session in self.store.source_sessions() if session.credential_id == credential_id]

    def apply(self, session):
        """Copy a session's credential into it (dropping the link if the credential is gone). Returns the session."""
        if not session.credential_id:
            return session
        credential = self.get(session.credential_id)
        if credential is None or session.protocol not in CREDENTIAL_PROTOCOLS:
            session.credential_id = ""
            return session
        session.username = credential.username
        if session.protocol == RDP:
            session.saved_password = credential.saved_password if credential.auth == AUTH_PASSWORD else ""
        else:
            session.auth, session.key_file = credential.auth, credential.key_file
            session.saved_password, session.saved_passphrase = credential.saved_password, credential.saved_passphrase
        return session

    def put(self, credential, default=None):
        """Add or replace a credential and update every session using it. default True/False makes it (or stops it
        being) the one new sessions start with."""
        for index, existing in enumerate(self.items):
            if existing.id == credential.id:
                self.items[index] = credential
                break
        else:
            self.items.append(credential)
        if default:
            self.default_id = credential.id
        elif default is False and self.default_id == credential.id:
            self.default_id = ""
        for session in self.users(credential.id):
            self.apply(session)
        self.store.save()

    def delete(self, credential_id):
        """Remove a credential. Sessions that used it keep its user name and password as their own."""
        self.items = [item for item in self.items if item.id != credential_id]
        if self.default_id == credential_id:
            self.default_id = ""
        for session in self.store.source_sessions():
            if session.credential_id == credential_id:
                session.credential_id = ""
        self.store.save()

    def assign(self, sessions, credential_id):
        """Make sessions log in with a credential ("" to stop, keeping its details as their own). Sessions that
        can't use it (Telnet, serial, raw TCP; RDP with a key credential) are skipped. Returns how many changed."""
        credential = self.get(credential_id)
        changed = 0
        for session in sessions:
            if session.protocol not in CREDENTIAL_PROTOCOLS:
                continue
            if credential is not None and session.protocol == RDP and credential.auth != AUTH_PASSWORD:
                continue
            if session.credential_id != credential_id:
                session.credential_id = credential_id
                self.apply(session)
                changed += 1
        if changed:
            self.store.save()
        return changed


def validate_credential(credential, book=None):
    """Returns an error message, or None."""
    if not credential.name.strip():
        return "Give the credential a name, such as TACACS or Domain Admin."
    if book is not None and any(item.name.lower() == credential.name.strip().lower() and item.id != credential.id
                                for item in book.items):
        return f"There's already a credential called {credential.name.strip()}."
    if not credential.username.strip():
        return "Enter the user name."
    if credential.auth == AUTH_KEY and not credential.key_file.strip():
        return "Choose the private key file, or use password authentication."
    return None


@dataclass
class RecentEntry:
    """A connection made recently. session is a copy without saved secrets; saved_id is the saved session it came
    from (or was later saved as), which is used instead while it still exists."""
    session: Session
    saved_id: str = ""
    last_used: float = 0.0
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def to_dict(self):
        return {"id": self.id, "saved_id": self.saved_id, "last_used": self.last_used,
                "session": dataclasses.asdict(self.session)}

    @classmethod
    def from_dict(cls, data):
        return cls(session_from_dict(data.get("session") or {}), str(data.get("saved_id") or ""),
                   float(data.get("last_used") or 0), str(data.get("id") or uuid.uuid4().hex))


class SessionStore:
    """Sessions and folders, saved as JSON in the roaming app data folder."""

    def __init__(self, path=None):
        self.path = path or os.path.join(app_data_dir(), FILE_NAME)
        self.sessions = []
        self.folders = set()  # Includes empty folders, which have no session to imply them
        self.rdp_folders = set()  # RDP has its own folder namespace.
        self.recent = []  # RecentEntry, newest first
        self.vault_settings = {}  # Master password salt and check value (no secrets), kept by the Vault
        self.vault = Vault(self.vault_settings, self.save)
        self.credentials = CredentialBook(self)
        self.listeners = []  # Called after every save, so each page showing the sessions can refresh
        self.load()

    def load(self):
        self.sessions, self.folders, self.recent = [], set(), []
        self.rdp_folders = set()
        self.vault_settings.clear()
        self.credentials.items, self.credentials.default_id = [], ""
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, ValueError) as error:
            log.error("Couldn't read %s: %s", self.path, error)
            return
        self.sessions = [session_from_dict(item) for item in data.get("sessions", []) if isinstance(item, dict)]
        self.folders = {normalize_folder(folder) for folder in data.get("folders", []) if isinstance(folder, str)}
        self.folders.discard("")
        self.rdp_folders = {normalize_folder(folder) for folder in data.get("rdp_folders", [])
                            if isinstance(folder, str)}
        self.rdp_folders.discard("")
        self.recent = [RecentEntry.from_dict(item) for item in data.get("recent", [])
                       if isinstance(item, dict)][:RECENT_LIMIT]
        if isinstance(data.get("vault"), dict):
            self.vault_settings.update(data["vault"])
        self.credentials.items = [credential_from_dict(item) for item in data.get("credentials", [])
                                  if isinstance(item, dict)]
        self.credentials.default_id = str(data.get("default_credential") or "")
        if self.credentials.default is None:
            self.credentials.default_id = ""
        for session in self.sessions:
            self.credentials.apply(session)

    def save(self):
        terminal_folders = SessionFolderStore(self, TERMINAL_PROTOCOLS).all_folders()
        rdp_folders = SessionFolderStore(self, {RDP}, "rdp_folders").all_folders()
        data = {"version": FORMAT_VERSION, "folders": sorted(terminal_folders), "rdp_folders": sorted(rdp_folders),
                "sessions": [dataclasses.asdict(session) for session in self.sessions],
                "recent": [entry.to_dict() for entry in self.recent]}
        if self.vault_settings:
            data["vault"] = dict(self.vault_settings)
        if self.credentials.items:
            data["credentials"] = [dataclasses.asdict(item) for item in self.credentials.items]
            data["default_credential"] = self.credentials.default_id
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        replace_file(temporary, self.path)  # Never leave a half-written file behind
        for listener in list(self.listeners):
            listener()

    def all_folders(self):
        """Every folder, including the parents of nested ones."""
        folders = set()
        for folder in self.folders | {session.folder for session in self.sessions}:
            parts = folder.split("/") if folder else []
            for depth in range(1, len(parts) + 1):
                folders.add("/".join(parts[:depth]))
        return folders

    def source_sessions(self):
        """Every saved session, whichever page's folder view this is."""
        return self.sessions

    @property
    def credential_sessions(self):
        """Everything holding secrets protected by this vault: every session across folder namespaces, and the
        saved credentials."""
        return [*self.source_sessions(), *self.credentials.items]

    def get(self, session_id):
        return next((session for session in self.sessions if session.id == session_id), None)

    def put(self, session):
        """Add a session, or replace the one with the same id."""
        session.folder = normalize_folder(session.folder)
        self.credentials.apply(session)
        for index, existing in enumerate(self.sessions):
            if existing.id == session.id:
                self.sessions[index] = session
                break
        else:
            self.sessions.append(session)
        self.save()

    def delete(self, session_id):
        self.sessions = [session for session in self.sessions if session.id != session_id]
        self.save()

    def add_folder(self, folder):
        folder = normalize_folder(folder)
        if folder:
            self.folders.add(folder)
            self.save()
        return folder

    def rename_folder(self, old, new):
        """Rename a folder, or give it a new path to move it (with everything under it). If the new path is already
        a folder, the two merge; a session whose name is taken there gets " (2)" added. The folder it came out of
        stays, even if that leaves it empty."""
        old, new = normalize_folder(old), normalize_folder(new)
        if not old or not new or old == new:
            return
        if new.startswith(old + "/"):
            raise ValueError("A folder can't be moved into itself.")

        def moved(folder):
            if folder == old:
                return new
            if folder.startswith(old + "/"):
                return new + folder[len(old):]
            return folder

        self.folders = self.all_folders()  # Keep folders that only existed because of the sessions moving out
        for session in self.sessions:
            folder = moved(session.folder)
            if folder != session.folder:
                session.folder = folder
                session.name = self.unique_name(session.name, folder, ignore_id=session.id)
        self.folders = {moved(folder) for folder in self.folders}
        self.folders.discard("")
        self.save()

    def move_folder(self, folder, parent):
        """Move a folder (and everything in it) into another folder, or to the top level with parent "". Returns
        its new path."""
        folder, parent = normalize_folder(folder), normalize_folder(parent)
        name = folder.rpartition("/")[2]
        new = f"{parent}/{name}" if parent else name
        if parent == folder or parent.startswith(folder + "/"):
            raise ValueError("A folder can't be moved into itself.")
        self.rename_folder(folder, new)
        return new

    def move_sessions(self, session_ids, folder):
        """Move sessions into a folder ("" for the top level). Names already taken there get " (2)" added.
        Returns how many moved."""
        folder = normalize_folder(folder)
        self.folders = self.all_folders()  # Folders emptied by the move stay
        if folder:
            self.folders.add(folder)
        moved = 0
        for session in self.sessions:
            if session.id in session_ids and session.folder != folder:
                session.folder = folder
                session.name = self.unique_name(session.name, folder, ignore_id=session.id)
                moved += 1
        self.save()
        return moved

    def delete_many(self, session_ids):
        self.sessions = [session for session in self.sessions if session.id not in session_ids]
        self.save()

    def delete_folder(self, folder):
        """Delete a folder and every session and folder in it."""
        folder = normalize_folder(folder)

        def inside(path):
            return path == folder or path.startswith(folder + "/")

        self.sessions = [session for session in self.sessions if not inside(session.folder)]
        self.folders = {path for path in self.folders if not inside(path)}
        self.save()

    def matching(self, hosts, protocol, username=""):
        """Saved sessions that connect to any of hosts (a device's addresses and names) with protocol, and as
        username if one is given; by folder and name."""
        hosts = [host for host in hosts if host]
        found = [session for session in self.sessions if session.protocol == protocol
                 and (not username or session.username.lower() == username.lower())
                 and any(same_host(session.host, host) for host in hosts)]
        return sorted(found, key=lambda session: session.path.lower())

    # ----------------------------------------------------------------- Recent connections

    def remember(self, session, when=None):
        """Put a connection at the top of the recent list (moving it up if it's already there)."""
        saved_id = session.id if self.get(session.id) is not None else ""
        key = target_key(session)

        def same(entry):
            if saved_id:
                return entry.saved_id == saved_id
            return not self.get(entry.saved_id) and target_key(entry.session) == key

        previous = next((entry for entry in self.recent if same(entry)), None)
        entry = RecentEntry(session.copy(saved_password="", saved_passphrase=""), saved_id,
                            time.time() if when is None else when, previous.id if previous else uuid.uuid4().hex)
        self.recent = [entry] + [other for other in self.recent if other is not previous][:RECENT_LIMIT - 1]
        self.save()
        return entry

    def recent_entry(self, entry_id):
        return next((entry for entry in self.recent if entry.id == entry_id), None)

    def recent_session(self, entry):
        """What to open for a recent entry: the saved session if it still exists, otherwise a fresh copy."""
        saved = self.get(entry.saved_id) if entry.saved_id else None
        return saved if saved is not None else self.credentials.apply(entry.session.copy())

    def link_recent(self, session):
        """A session was just saved: recent entries for the same place (not already tied to a saved session) now
        open it, with its name and saved password."""
        key = target_key(session)
        changed = False
        for entry in self.recent:
            if not self.get(entry.saved_id) and target_key(entry.session) == key:
                entry.saved_id = session.id
                entry.session = session.copy(saved_password="", saved_passphrase="")
                changed = True
        if changed:
            self.save()

    def forget_recent(self, entry_id=None):
        """Remove one recent entry, or all of them."""
        self.recent = [entry for entry in self.recent if entry_id is not None and entry.id != entry_id]
        self.save()

    def unique_name(self, name, folder, ignore_id=None):
        taken = {session.name.lower() for session in self.sessions
                 if session.folder == folder and session.id != ignore_id}
        if name.lower() not in taken:
            return name
        number = 2
        while f"{name} ({number})".lower() in taken:
            number += 1
        return f"{name} ({number})"


class SessionFolderStore(SessionStore):
    """A protocol-scoped folder view over one store, sharing its vault and persistence.

    All inherited mutations see only this view's sessions and folders, so identical
    folder paths can be renamed or deleted independently on RDP and Terminal/SCP.
    """

    def __init__(self, source, protocols, folder_key="folders"):
        self.source = getattr(source, "source", source)
        self.protocols = set(protocols)
        self.folder_key = folder_key

    def __getattr__(self, name):
        return getattr(self.source, name)

    @property
    def sessions(self):
        return [session for session in self.source.sessions if session.protocol in self.protocols]

    @sessions.setter
    def sessions(self, sessions):
        self.source.sessions = [session for session in self.source.sessions if session.protocol not in self.protocols] + \
            list(sessions)

    @property
    def folders(self):
        return getattr(self.source, self.folder_key)

    @folders.setter
    def folders(self, folders):
        setattr(self.source, self.folder_key, folders)

    @property
    def recent(self):
        return self.source.recent

    @recent.setter
    def recent(self, recent):
        self.source.recent = recent

    def source_sessions(self):
        return self.source.sessions

    @property
    def credential_sessions(self):
        return self.source.credential_sessions

    def put(self, session):
        if session.protocol not in self.protocols:
            raise ValueError("This session belongs to a different page.")
        session.folder = normalize_folder(session.folder)
        self.credentials.apply(session)
        sessions = self.sessions
        for index, existing in enumerate(sessions):
            if existing.id == session.id:
                sessions[index] = session
                break
        else:
            sessions.append(session)
        self.sessions = sessions
        self.save()

    def save(self):
        self.source.save()


# ----------------------------------------------------------------- Quick connect

QUICK_PATTERN = re.compile(r"^(?:(?P<scheme>ssh|telnet|raw|serial|rdp)(?:://|\s+))?(?:(?P<user>[^@\s]+)@)?"
                           r"(?P<host>\[[^\]]+\]|[^\s:]+)(?::(?P<port>\d+))?$", re.IGNORECASE)
SCHEMES = {"ssh": SSH, "telnet": TELNET, "raw": RAW, "serial": SERIAL, "rdp": RDP}


def parse_quick_connect(text, default_protocol=SSH):
    """Turn "admin@10.0.0.1", "telnet 10.0.0.5", "10.0.0.9:2222", "raw 10.0.0.5:9100" or "COM3:115200" into a
    Session (not saved). Raises ValueError with a message suitable for showing to the user."""
    text = text.strip()
    if not text:
        raise ValueError("Type a host to connect to, such as admin@10.0.0.1 or COM3.")
    serial = re.match(r"^(?:serial(?:://|\s+))?(COM\d+)(?:[:\s]+(\d+))?$", text, re.IGNORECASE)
    if serial:
        port = serial.group(1).upper()
        baud = int(serial.group(2)) if serial.group(2) else 9600
        return Session(name=port, protocol=SERIAL, serial_port=port, baud_rate=baud)
    match = QUICK_PATTERN.match(text)
    if not match:
        raise ValueError(f"'{text}' isn't something to connect to. Try admin@10.0.0.1, telnet 10.0.0.5 or COM3.")
    protocol = SCHEMES.get((match.group("scheme") or "").lower(), default_protocol)
    host = match.group("host").strip("[]")
    port = int(match.group("port")) if match.group("port") else DEFAULT_PORTS.get(protocol, 22)
    if not 1 <= port <= 65535:
        raise ValueError("The port must be between 1 and 65535.")
    user = match.group("user") or ""
    name = f"{user}@{host}" if user else host
    return Session(name=name, protocol=protocol, host=host, port=port, username=user,
                   line_ending="CR+LF" if protocol == RAW else "CR")


# ----------------------------------------------------------------- Importing from PuTTY

PUTTY_KEY = r"Software\SimonTatham\PuTTY\Sessions"
PUTTY_PROTOCOLS = {"ssh": SSH, "telnet": TELNET, "raw": RAW, "serial": SERIAL}
PUTTY_PARITY = {0: "None", 1: "Odd", 2: "Even", 3: "Mark", 4: "Space"}
PUTTY_FLOW = {0: "None", 1: "XON/XOFF", 2: "RTS/CTS", 3: "DSR/DTR"}


def session_from_putty(name, values, folder="Imported from PuTTY"):
    """Build a Session from one PuTTY session's registry values, or None if it can't be used."""
    protocol = PUTTY_PROTOCOLS.get(str(values.get("Protocol", "ssh")).lower())
    if protocol is None:
        return None
    session = Session(name=unquote(name).replace("/", "-"), protocol=protocol, folder=folder)
    session.host = str(values.get("HostName", "")).strip()
    if "@" in session.host:  # PuTTY lets people type user@host into the host box
        session.username, session.host = session.host.split("@", 1)
    session.port = int(values.get("PortNumber", DEFAULT_PORTS.get(protocol, 22)) or DEFAULT_PORTS.get(protocol, 22))
    session.username = str(values.get("UserName", "")) or session.username
    key_file = str(values.get("PublicKeyFile", "")).strip()
    if key_file:
        session.auth, session.key_file = AUTH_KEY, key_file
    ping = int(values.get("PingIntervalSecs", 0) or 0) or int(values.get("PingInterval", 0) or 0) * 60
    session.keepalive = ping
    if protocol == SERIAL:
        session.serial_port = str(values.get("SerialLine", "COM1"))
        session.baud_rate = int(values.get("SerialSpeed", 9600) or 9600)
        session.data_bits = int(values.get("SerialDataBits", 8) or 8)
        session.stop_bits = int(values.get("SerialStopHalfbits", 2) or 2) / 2
        session.parity = PUTTY_PARITY.get(int(values.get("SerialParity", 0) or 0), "None")
        session.flow_control = PUTTY_FLOW.get(int(values.get("SerialFlowControl", 0) or 0), "None")
    elif not session.host:
        return None
    return session


def read_putty_sessions():
    """[(name, {value: data})] for every session PuTTY has saved for this user (not its Default Settings)."""
    import winreg
    sessions = []
    try:
        root = winreg.OpenKey(winreg.HKEY_CURRENT_USER, PUTTY_KEY)
    except OSError:
        return sessions
    with root:
        index = 0
        while True:
            try:
                name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            if unquote(name) == "Default Settings":
                continue
            values = {}
            with winreg.OpenKey(root, name) as key:
                value_index = 0
                while True:
                    try:
                        value_name, data, _ = winreg.EnumValue(key, value_index)
                    except OSError:
                        break
                    values[value_name] = data
                    value_index += 1
            sessions.append((name, values))
    return sessions


def import_putty(store, putty_sessions=None):
    """Add PuTTY's sessions to the store, skipping ones already there. Returns how many were added."""
    putty_sessions = read_putty_sessions() if putty_sessions is None else putty_sessions
    existing = {(session.name.lower(), session.host.lower(), session.protocol) for session in store.sessions}
    added = 0
    for name, values in putty_sessions:
        session = session_from_putty(name, values)
        if session is None or (session.name.lower(), session.host.lower(), session.protocol) in existing:
            continue
        store.sessions = [*store.sessions, session]
        existing.add((session.name.lower(), session.host.lower(), session.protocol))
        added += 1
    if added:
        store.save()
    return added
