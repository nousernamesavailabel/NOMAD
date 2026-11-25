"""Sharing saved sessions with other people: a JSON file with no logins in it, and importing one with a saved
credential picked for all of its sessions, or for each by exception.

What goes in the file is an allowed list of fields (SHARE_FIELDS), so a field added to Session later stays out until
it's added here on purpose. Reading a file uses the same list, so a hand-edited file can't bring in a password, a key
file, a log folder or a credential link. User names are never written: a user name is half of a login."""
import dataclasses
import json
import os
import tempfile
import time
from dataclasses import dataclass, field

from .. import __version__
from ..system import replace_file
from .sessions import AUTH_AGENT, AUTH_KEY, AUTH_PASSWORD, CREDENTIAL_PROTOCOLS, ENCODINGS, FILE_PROTOCOLS, \
    FLOW_CONTROLS, LINE_ENDINGS, PARITIES, PROTOCOLS, RDP, Session, normalize_folder, validate_session

FORMAT = "nomad-session-share"
VERSION = 1
FILE_FILTER = "NOMAD shared sessions (*.json)"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_SESSIONS = 5000
MAX_TEXT = 1000  # Characters in a name, host, folder and the like
MAX_NOTES = 20000

# Everything about where and how a session connects, and nothing about who logs in
SHARE_FIELDS = (
    "name", "protocol", "host", "port", "folder", "auth", "keepalive", "file_protocol", "scp_sudo",
    "serial_port", "baud_rate", "data_bits", "parity", "stop_bits", "flow_control",
    "terminal_type", "encoding", "backspace_sends_delete", "local_echo", "line_ending", "scrollback",
    "line_delay", "auto_reconnect", "anti_idle", "anti_idle_text", "notes",
    "rdp_fullscreen", "rdp_multimon", "rdp_width", "rdp_height", "rdp_clipboard", "rdp_audio", "rdp_admin",
)
CHOICES = {"auth": (AUTH_PASSWORD, AUTH_KEY, AUTH_AGENT), "file_protocol": tuple(FILE_PROTOCOLS),
           "parity": tuple(PARITIES), "flow_control": tuple(FLOW_CONTROLS), "encoding": tuple(ENCODINGS),
           "line_ending": tuple(LINE_ENDINGS)}
MULTILINE = {"notes", "anti_idle_text"}  # Text that may hold line breaks (anti-idle text is typed with escapes)
NOT_NEGATIVE = {"keepalive", "scrollback", "line_delay", "anti_idle"}

# What to do with a shared session that's already saved here (same folder, name, host and protocol)
SKIP, REPLACE, KEEP_BOTH = "skip", "replace", "both"
DUPLICATE_ACTIONS = [(SKIP, "Skip"), (REPLACE, "Replace settings, keep my login"), (KEEP_BOTH, "Keep both")]
LOGIN_FIELDS = ("username", "auth", "saved_password", "key_file", "saved_passphrase", "credential_id")


class ShareError(Exception):
    pass


@dataclass
class SharedSession:
    session: Session  # With a new id and no login
    hint: str = ""  # The name of the credential it used where it was exported, such as "TACACS"


@dataclass
class SharedSessions:
    sessions: list = field(default_factory=list)  # SharedSession
    folders: list = field(default_factory=list)  # Terminal folders, empty ones included
    rdp_folders: list = field(default_factory=list)
    skipped: list = field(default_factory=list)  # "name: why" for sessions that couldn't be read
    nomad_version: str = ""
    exported: str = ""


DEFAULTS = dataclasses.asdict(Session(name=""))


def session_to_share(session, credentials=None, include_notes=True):
    """The dict written for a session: allowed fields only, plus the name of its credential as a hint."""
    data = {name: getattr(session, name) for name in SHARE_FIELDS}
    if not include_notes:
        data["notes"] = ""
    if data["auth"] == AUTH_KEY:
        data["auth"] = AUTH_PASSWORD  # The key file stays here; the importer picks how to log in
    credential = credentials.get(session.credential_id) if credentials is not None else None
    if credential is not None and session.protocol in CREDENTIAL_PROTOCOLS:
        data["credential_hint"] = credential.name
    return data


def share_data(sessions, folders=(), rdp_folders=(), credentials=None, include_notes=True):
    """The whole file's contents. credentials (a CredentialBook) adds each session's credential name as a hint."""
    return {"format": FORMAT, "version": VERSION, "nomad_version": __version__,
            "exported": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "folders": sorted({normalize_folder(folder) for folder in folders} - {""}, key=str.lower),
            "rdp_folders": sorted({normalize_folder(folder) for folder in rdp_folders} - {""}, key=str.lower),
            "sessions": [session_to_share(session, credentials, include_notes) for session in sessions]}


def write_share(path, sessions, folders=(), rdp_folders=(), credentials=None, include_notes=True):
    """Write a share file. Returns how many sessions went in."""
    data = share_data(sessions, folders, rdp_folders, credentials, include_notes)
    directory = os.path.dirname(os.path.abspath(path))
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=directory, suffix=".part",
                                         delete=False) as file:
            temporary = file.name
            json.dump(data, file, indent=2, ensure_ascii=False)
        replace_file(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return len(data["sessions"])


def _clean_text(value, name):
    """A string field's value, or None if it can't be used."""
    if not isinstance(value, str):
        return None
    limit = MAX_NOTES if name == "notes" else MAX_TEXT
    if len(value) > limit:
        return None
    allowed = "\r\n\t" if name in MULTILINE else ""
    if any(ord(char) < 32 and char not in allowed for char in value) or "\x7f" in value:
        return None
    return value


def _clean_value(name, value):
    """A field's value from a share file, or the default when it's the wrong type or out of range."""
    default = DEFAULTS[name]
    if name == "stop_bits":
        return value if type(value) in (int, float) and value in (1, 1.5, 2) else default
    if isinstance(default, bool):
        return value if type(value) is bool else default
    if isinstance(default, int):
        if type(value) is not int or (name in NOT_NEGATIVE and value < 0):
            return default
        return value
    if isinstance(default, float):
        if type(value) not in (int, float) or value <= 0:
            return default
        return float(value)
    cleaned = _clean_text(value, name)
    if cleaned is None:
        return default
    if name in CHOICES and cleaned not in CHOICES[name]:
        return default
    return cleaned


def session_from_share(data):
    """(SharedSession, None), or (None, why it can't be used)."""
    if not isinstance(data, dict):
        return None, "not a session"
    name = _clean_text(data.get("name"), "name")
    if not name or not name.strip():
        return None, "no name"
    protocol = data.get("protocol")
    if protocol not in PROTOCOLS:
        return None, f"unknown protocol {str(protocol)[:20]}"
    for text_field in ("host", "folder", "serial_port"):
        if text_field in data and _clean_text(data[text_field], text_field) is None:
            return None, f"unreadable {text_field.replace('_', ' ')}"
    values = {key: _clean_value(key, data[key]) for key in SHARE_FIELDS if key in data}
    values["name"] = name.strip()
    session = Session(**values)
    session.folder = normalize_folder(session.folder)
    if session.auth == AUTH_KEY:
        session.auth = AUTH_PASSWORD  # A share file never carries a key file
    error = validate_session(session)
    if error:
        return None, error
    hint = _clean_text(data.get("credential_hint", ""), "credential_hint") or ""
    return SharedSession(session, hint.strip() if session.protocol in CREDENTIAL_PROTOCOLS else ""), None


def _folders(data, key):
    items = data.get(key, [])
    if not isinstance(items, list):
        return []
    folders = {normalize_folder(item) for item in items[:MAX_SESSIONS]
               if _clean_text(item, "folder") is not None}
    return sorted(folders - {""}, key=str.lower)


def read_share(path):
    """Read a share file. Raises ShareError when it isn't one (or is from a newer NOMAD)."""
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            raise ShareError("The file is too large to be a NOMAD shared sessions file.")
        with open(path, encoding="utf-8-sig") as file:
            data = json.load(file)
    except (OSError, ValueError) as error:
        raise ShareError(f"Couldn't read the file: {error}") from None
    if not isinstance(data, dict) or data.get("format") != FORMAT:
        raise ShareError("This isn't a NOMAD shared sessions file. Make one with File > Export Sessions to Share.")
    version = data.get("version")
    if type(version) is not int or version < 1:
        raise ShareError("This shared sessions file has no version NOMAD can read.")
    if version > VERSION:
        raise ShareError(f"This file was made by a newer NOMAD ({str(data.get('nomad_version'))[:20]}). "
                         "Update NOMAD to import it.")
    items = data.get("sessions")
    if not isinstance(items, list):
        raise ShareError("This shared sessions file has no sessions in it.")
    if len(items) > MAX_SESSIONS:
        raise ShareError(f"This file has {len(items)} sessions; NOMAD imports up to {MAX_SESSIONS} at once.")
    shared = SharedSessions(folders=_folders(data, "folders"), rdp_folders=_folders(data, "rdp_folders"),
                            nomad_version=_clean_text(data.get("nomad_version", ""), "version") or "",
                            exported=_clean_text(data.get("exported", ""), "exported") or "")
    for index, item in enumerate(items, 1):
        session, why = session_from_share(item)
        if session is None:
            name = item.get("name") if isinstance(item, dict) else None
            label = _clean_text(name, "name") if isinstance(name, str) else None
            shared.skipped.append(f"{(label or f'session {index}')[:60]}: {why}")
        else:
            shared.sessions.append(session)
    return shared


# ----------------------------------------------------------------- Importing

def root_store(store):
    """The whole session store, from a page's folder view of it."""
    return getattr(store, "source", store)


def join_folder(prefix, folder):
    return normalize_folder(f"{prefix}/{folder}" if prefix else folder)


def existing_match(store, session, prefix=""):
    """The saved session a shared one would duplicate (same folder after the prefix, name, host and protocol)."""
    folder = join_folder(prefix, session.folder).lower()
    for existing in root_store(store).sessions:
        if (existing.protocol == session.protocol and existing.folder.lower() == folder
                and existing.name.lower() == session.name.lower() and existing.host.lower() == session.host.lower()):
            return existing
    return None


def usable_credential(book, credential_id, protocol):
    """The credential if this protocol can log in with it (RDP needs a password one), else None."""
    credential = book.get(credential_id)
    if credential is None or protocol not in CREDENTIAL_PROTOCOLS:
        return None
    if protocol == RDP and credential.auth != AUTH_PASSWORD:
        return None
    return credential


def match_hint(book, hint, protocol):
    """The id of a saved credential named like the hint (any case) that this protocol can use, or ""."""
    if not hint:
        return ""
    for credential in book.sorted(protocol):
        if credential.name.strip().lower() == hint.strip().lower() and usable_credential(book, credential.id,
                                                                                          protocol):
            return credential.id
    return ""


def _unique_name(sessions, name, folder, protocol):
    rdp = protocol == RDP
    taken = {session.name.lower() for session in sessions
             if session.folder.lower() == folder.lower() and (session.protocol == RDP) == rdp}
    if name.lower() not in taken:
        return name
    number = 2
    while f"{name} ({number})".lower() in taken:
        number += 1
    return f"{name} ({number})"


@dataclass
class ImportChoice:
    shared: SharedSession
    credential_id: str = ""  # "" to ask for a login when connecting
    duplicate: str = SKIP  # When it's already saved here: SKIP, REPLACE or KEEP_BOTH


@dataclass
class ImportResult:
    added: int = 0
    replaced: int = 0
    skipped: int = 0
    with_credential: int = 0
    asking: int = 0  # SSH and RDP sessions that will ask for a login


def import_shared(store, choices, prefix="", folders=(), rdp_folders=()):
    """Add the chosen shared sessions to the store under the prefix folder, each logging in with its credential.
    Sessions already saved are skipped, updated (keeping their own login) or added beside them, as chosen. folders
    and rdp_folders are the file's empty folders, made too."""
    root = root_store(store)
    book = root.credentials
    prefix = normalize_folder(prefix)
    result = ImportResult()
    sessions = list(root.sessions)
    for choice in choices:
        shared = choice.shared.session
        folder = join_folder(prefix, shared.folder)
        existing = existing_match(root, shared, prefix)
        if existing is not None and choice.duplicate == SKIP:
            result.skipped += 1
            continue
        if existing is not None and choice.duplicate == REPLACE:
            keep = {name: getattr(existing, name)
                    for name in (*LOGIN_FIELDS, "id", "name", "folder", "log_to_file", "log_folder")}
            updated = dataclasses.replace(shared, **keep)
            sessions = [updated if session.id == existing.id else session for session in sessions]
            result.replaced += 1
            continue
        session = shared.copy(folder=folder, username="", saved_password="", key_file="", saved_passphrase="",
                              credential_id="", log_to_file=False, log_folder="")  # A new id every import
        if existing is not None:
            session.name = _unique_name(sessions, session.name, folder, session.protocol)
        credential = usable_credential(book, choice.credential_id, session.protocol)
        if credential is not None:
            session.credential_id = credential.id
            book.apply(session)
            result.with_credential += 1
        elif session.protocol in CREDENTIAL_PROTOCOLS:
            if session.auth != AUTH_AGENT:
                session.auth = AUTH_PASSWORD
            result.asking += 1
        sessions.append(session)
        result.added += 1
    root.sessions = sessions
    rdp_chosen = any(choice.shared.session.protocol == RDP for choice in choices)
    terminal_chosen = any(choice.shared.session.protocol != RDP for choice in choices)
    for name, empty, chosen in (("folders", folders, terminal_chosen), ("rdp_folders", rdp_folders, rdp_chosen)):
        wanted = {join_folder(prefix, folder) for folder in empty}
        if prefix and (chosen or empty):
            wanted.add(prefix)
        setattr(root, name, set(getattr(root, name)) | (wanted - {""}))
    root.save()
    return result
