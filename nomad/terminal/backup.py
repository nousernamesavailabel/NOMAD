"""Portable terminal backups. The entire payload, including secrets, is authenticated and encrypted."""
import base64
import dataclasses
import json
import math
import os
import tempfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PyQt5.QtCore import QByteArray

from .commands import CommandButton
from .highlight import HighlightRule, Highlighter
from .sessions import RDP, TERMINAL_PROTOCOLS, Credential, Session, SessionFolderStore, RecentEntry, \
    validate_credential, validate_session
from ..system import replace_file
from .vault import derive_key

MAGIC = b"NOMAD-TERMINAL-BACKUP\x01"
SECRETS = ("saved_password", "saved_passphrase")


class BackupError(Exception):
    """A backup is invalid or cannot be decrypted."""


def terminal_key(key):
    return key.startswith(("terminal/", "scp/", "rdp/")) or key == "view/text_scale"


def write_backup(path, password, store, commands, highlights, settings):
    store = getattr(store, "source", store)
    if len(password) < 8:
        raise BackupError("Use at least 8 characters for the backup password.")
    sessions = []
    for session in store.sessions:
        item = dataclasses.asdict(session)
        for field in SECRETS:
            item[field] = store.vault.reveal(item[field]) if item[field] else ""
        sessions.append(item)
    credentials = []
    for credential in store.credentials.items:
        item = dataclasses.asdict(credential)
        for field in SECRETS:
            item[field] = store.vault.reveal(item[field]) if item[field] else ""
        credentials.append(item)
    preferences = {}
    for key in settings.allKeys():
        if terminal_key(key):
            value = settings.value(key)
            preferences[key] = ({"bytes": base64.b64encode(bytes(value)).decode("ascii")}
                                if isinstance(value, QByteArray) else value)
    data = {"sessions": sessions, "folders": sorted(SessionFolderStore(store, TERMINAL_PROTOCOLS).all_folders()),
            "rdp_folders": sorted(SessionFolderStore(store, {RDP}, "rdp_folders").all_folders()),
            "recent": [entry.to_dict() for entry in store.recent],
            "credentials": credentials, "default_credential": store.credentials.default_id,
            "commands": [dataclasses.asdict(button) for button in commands.buttons],
            "highlights": [dataclasses.asdict(rule) for rule in highlights.rules],
            "highlight_enabled": highlights.enabled, "settings": preferences,
            "lock_after": store.vault.lock_after}
    salt, nonce = os.urandom(16), os.urandom(12)
    payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
    encrypted = AESGCM(derive_key(password, salt)).encrypt(nonce, payload, MAGIC)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(path)), delete=False) as file:
            temporary = file.name
            file.write(MAGIC + salt + nonce + encrypted)
        replace_file(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)


def _record(cls, item):
    if not isinstance(item, dict):
        raise ValueError("Invalid record")
    record = cls(**item)
    defaults = cls(**({"name": "Session"} if cls in (Session, CommandButton, Credential) else {"pattern": ""}))
    for field in dataclasses.fields(cls):
        value, default = getattr(record, field.name), getattr(defaults, field.name)
        if isinstance(default, float) or field.name == "stop_bits":
            valid = type(value) in (float, int) and math.isfinite(value)
        else:
            valid = type(value) is type(default)
        if not valid:
            raise ValueError(f"Invalid {field.name}")
    if cls is Session:
        problem = validate_session(record)
        if problem:
            raise ValueError(problem)
    if cls is Credential:
        problem = validate_credential(record)
        if problem:
            raise ValueError(problem)
    return record


def read_backup(path, password):
    """Decrypt and validate everything before changing any local state."""
    with open(path, "rb") as file:
        raw = file.read()
    if not raw.startswith(MAGIC) or len(raw) < len(MAGIC) + 44:
        raise BackupError("This isn't a supported NOMAD terminal backup.")
    offset = len(MAGIC)
    try:
        payload = AESGCM(derive_key(password, raw[offset:offset + 16])).decrypt(
            raw[offset + 16:offset + 28], raw[offset + 28:], MAGIC)
    except InvalidTag:
        raise BackupError("The backup password is incorrect, or the file is damaged.") from None
    try:
        data = json.loads(payload)
        for key in ("sessions", "recent", "commands", "highlights"):
            if not isinstance(data[key], list):
                raise ValueError(f"Invalid {key}")
        data["sessions"] = [_record(Session, item) for item in data["sessions"]]
        if len({session.id for session in data["sessions"]}) != len(data["sessions"]):
            raise ValueError("Duplicate session IDs")
        data.setdefault("credentials", [])  # Backups from before credentials existed
        if not isinstance(data["credentials"], list):
            raise ValueError("Invalid credentials")
        data["credentials"] = [_record(Credential, item) for item in data["credentials"]]
        if len({credential.id for credential in data["credentials"]}) != len(data["credentials"]):
            raise ValueError("Duplicate credential IDs")
        data.setdefault("default_credential", "")
        if type(data["default_credential"]) is not str:
            raise ValueError("Invalid default credential")
        data["commands"] = [_record(CommandButton, item) for item in data["commands"]]
        data["highlights"] = [_record(HighlightRule, item) for item in data["highlights"]]
        for item in data["recent"]:
            _record(Session, item["session"])
            if any(item["session"][field] for field in SECRETS):
                raise ValueError("Recent connections cannot contain credentials")
        data["recent"] = [RecentEntry.from_dict(item) for item in data["recent"]][:10]
        if not isinstance(data["folders"], list) or any(type(x) is not str for x in data["folders"]):
            raise ValueError("Invalid folders")
        data.setdefault("rdp_folders", [])
        if not isinstance(data["rdp_folders"], list) or any(type(x) is not str for x in data["rdp_folders"]):
            raise ValueError("Invalid RDP folders")
        if type(data["highlight_enabled"]) is not bool or type(data["lock_after"]) is not int:
            raise ValueError("Invalid preferences")
        if data["lock_after"] < 0:
            raise ValueError("Invalid lock timeout")
        for key, value in data["settings"].items():
            if not terminal_key(key):
                raise ValueError("Unexpected setting")
            if isinstance(value, dict):
                data["settings"][key] = QByteArray(base64.b64decode(value["bytes"], validate=True))
            elif type(value) not in (str, bool, int, float):
                raise ValueError("Invalid setting")
            if key.endswith("/splitter") and not isinstance(data["settings"][key], QByteArray):
                raise ValueError("Invalid splitter state")
            if key == "view/text_scale" and (type(value) not in (float, int) or not math.isfinite(value) or value <= 0):
                raise ValueError("Invalid text scale")
        return data
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise BackupError(f"Invalid terminal backup: {error}") from None


def restore_backup(data, store, commands, highlights, settings):
    store = getattr(store, "source", store)
    # Prepare every credential before mutating stores: cancellation/unreadable credentials are never partial.
    sessions = []
    for original in data["sessions"]:
        session = dataclasses.replace(original)
        for field in SECRETS:
            secret = getattr(session, field)
            setattr(session, field, store.vault.protect(secret) if secret else "")
        sessions.append(session)
    credentials = []
    for original in data.get("credentials", []):
        credential = dataclasses.replace(original)
        for field in SECRETS:
            secret = getattr(credential, field)
            setattr(credential, field, store.vault.protect(secret) if secret else "")
        credentials.append(credential)
    originals = {}
    for owner in (store, commands, highlights):
        if os.path.exists(owner.path):
            with open(owner.path, "rb") as file:
                originals[owner.path] = file.read()
        else:
            originals[owner.path] = None
    previous = (store.sessions, store.folders, store.rdp_folders, store.recent, dict(store.vault_settings), commands.buttons,
                highlights.rules, highlights.enabled, highlights.highlighter)
    previous_credentials = (store.credentials.items, store.credentials.default_id)
    preferences = {key: settings.value(key) for key in settings.allKeys() if terminal_key(key)}
    try:
        store.sessions, store.folders, store.recent = sessions, set(data["folders"]), data["recent"]
        store.rdp_folders = set(data.get("rdp_folders", []))
        store.credentials.items = credentials
        store.credentials.default_id = data.get("default_credential", "")
        if store.credentials.default is None:
            store.credentials.default_id = ""
        for session in store.sessions:
            store.credentials.apply(session)  # Links to credentials the backup doesn't have are dropped
        store.vault_settings["lock_after"] = data["lock_after"]
        commands.buttons = data["commands"]
        highlights.rules, highlights.enabled = data["highlights"], data["highlight_enabled"]
        highlights.highlighter = Highlighter(highlights.rules)
        store.save()
        commands.save()
        highlights.save()
        for key in settings.allKeys():
            if terminal_key(key):
                settings.remove(key)
        for key, value in data["settings"].items():
            settings.setValue(key, value)
        settings.sync()
        if settings.status() != settings.NoError:
            raise OSError("Couldn't save terminal preferences.")
    except Exception:
        (store.sessions, store.folders, store.rdp_folders, store.recent, vault_settings, commands.buttons,
         highlights.rules, highlights.enabled, highlights.highlighter) = previous
        store.credentials.items, store.credentials.default_id = previous_credentials
        store.vault_settings.clear()
        store.vault_settings.update(vault_settings)
        for key in settings.allKeys():
            if terminal_key(key):
                settings.remove(key)
        for key, value in preferences.items():
            settings.setValue(key, value)
        settings.sync()
        for path, content in originals.items():
            if content is None:
                if os.path.exists(path):
                    os.unlink(path)
            else:
                with open(path + ".restore", "wb") as file:
                    file.write(content)
                replace_file(path + ".restore", path)
        for owner in (store, commands, highlights):
            for listener in list(owner.listeners):
                listener()
        raise
