"""Who may sign in to the NOMAD Dashboard, and who has.

users.json holds each login's name, its password's scrypt hash and salt, and whether it's a kiosk login (a wall screen,
signed in for a year). NOMAD's Dashboard Service dialog writes it; the service reads it again whenever it changes.

Sign-ins that fail are counted per login and per address: after MAX_FAILURES in a row, that login (or address) can't
sign in for LOCK_SECONDS. Sessions are random tokens in a cookie; only their SHA-256 is kept (sessions.json), so a
restart of the service doesn't sign the wall screens out, and the file alone signs nobody in.
"""
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from pathlib import Path

from ..system import replace_file

USERS_FILE = "users.json"
SESSIONS_FILE = "sessions.json"
MAX_FAILURES = 5
LOCK_SECONDS = 300
SESSION_HOURS = 12  # Idle time before an ordinary login is signed out
KIOSK_DAYS = 365
MIN_PASSWORD = 8
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}
NAME_PATTERN = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")


class AccountError(Exception):
    """Why a login can't be added or changed (shown as is)."""


def hash_password(password, salt=None):
    """(hash hex, salt hex) of a password."""
    salt = bytes.fromhex(salt) if isinstance(salt, str) else (salt or secrets.token_bytes(16))
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, dklen=32, maxmem=64 * 1024 * 1024, **SCRYPT)
    return digest.hex(), salt.hex()


def check_name(name):
    name = (name or "").strip()
    if not NAME_PATTERN.match(name):
        raise AccountError("Use 1 to 64 letters, digits and . _ @ - for the login name.")
    return name


def check_password(password):
    if len(password or "") < MIN_PASSWORD:
        raise AccountError(f"Use a password of at least {MIN_PASSWORD} characters.")
    return password


def _write_json(path, data):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(data, indent=2), encoding="utf-8")
    replace_file(temporary, path)  # (Tries again while a reader or the virus scanner has it open)


class UserFile:
    """users.json, for NOMAD's dialog: list, add, remove, set a password or the kiosk flag."""

    def __init__(self, directory):
        self.path = Path(directory) / USERS_FILE

    def load(self):
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {}
        except (OSError, ValueError):
            return {}
        return {name: entry for name, entry in (data.get("users") or {}).items() if isinstance(entry, dict)}

    def save(self, users):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        _write_json(self.path, {"users": users})

    def names(self):
        return sorted(self.load(), key=str.lower)

    def add(self, name, password, kiosk=False):
        name, users = check_name(name), self.load()
        if any(existing.lower() == name.lower() for existing in users):
            raise AccountError(f"There's already a login called {name}.")
        digest, salt = hash_password(check_password(password))
        users[name] = {"hash": digest, "salt": salt, "kiosk": bool(kiosk), "created": time.time(),
                       "changed": time.time(), "stamp": secrets.token_hex(8)}
        self.save(users)

    def set_password(self, name, password):
        users = self.load()
        if name not in users:
            raise AccountError(f"There's no login called {name}.")
        digest, salt = hash_password(check_password(password))
        users[name].update(hash=digest, salt=salt, changed=time.time(), stamp=secrets.token_hex(8))
        self.save(users)

    def set_kiosk(self, name, kiosk):
        users = self.load()
        if name in users:
            users[name].update(kiosk=bool(kiosk), changed=time.time(), stamp=secrets.token_hex(8))
            self.save(users)

    def remove(self, name):
        users = self.load()
        if users.pop(name, None) is not None:
            self.save(users)


class Session:
    def __init__(self, user, kiosk, created, used, stamp=""):
        self.user, self.kiosk, self.created, self.used = user, kiosk, created, used
        self.stamp = stamp  # The login's stamp when it signed in: a new password (or kiosk setting) changes it

    def expired(self, now, idle_hours=SESSION_HOURS):
        if self.kiosk:
            return now - self.created > KIOSK_DAYS * 86400
        return now - self.used > idle_hours * 3600


class Accounts:
    """The service's side: checking sign-ins, and the sessions they make. Thread-safe."""

    def __init__(self, directory, clock=time.time, idle_hours=SESSION_HOURS):
        self.directory = Path(directory)
        self.users_file = UserFile(directory)
        self.sessions_path = self.directory / SESSIONS_FILE
        self.clock, self.idle_hours = clock, idle_hours
        self.lock = threading.Lock()
        self.users, self.users_stamp = {}, None
        self.failures = {}  # "user:<name>" or "address:<ip>" -> (failures in a row, locked until)
        self.sessions = self._load_sessions()
        self.saved_used = {}  # Token hash -> when its use was last written (written at most every few minutes)

    # ----------------------------------------------------------------- Logins

    def _current_users(self):
        try:
            stamp = self.users_file.path.stat().st_mtime_ns
        except OSError:
            stamp = None
        if stamp != self.users_stamp:
            self.users, self.users_stamp = self.users_file.load(), stamp
            gone = [token for token, session in self.sessions.items() if session.user not in self.users or
                    self.users[session.user].get("stamp", "") != session.stamp]
            for token in gone:  # Removed, or its password changed: signed out everywhere
                del self.sessions[token]
            if gone:
                self._save_sessions()
        return self.users

    def has_users(self):
        with self.lock:
            return bool(self._current_users())

    def locked_for(self, name, address):
        """Seconds until this login (or address) may try again, or 0."""
        now = self.clock()
        with self.lock:
            return max([0] + [int(until - now) + 1 for count, until in
                              (self.failures.get(f"user:{name.lower()}", (0, 0)),
                               self.failures.get(f"address:{address}", (0, 0))) if until > now])

    def sign_in(self, name, password, address):
        """A new session token for a good login, or None. Raises AccountError while locked out."""
        name = (name or "").strip()
        wait = self.locked_for(name, address)
        if wait:
            raise AccountError(f"Too many failed sign-ins: try again in {max(1, wait // 60)} min.")
        with self.lock:
            users = self._current_users()
            entry = next((users[existing] for existing in users if existing.lower() == name.lower()), None)
            real = next((existing for existing in users if existing.lower() == name.lower()), name)
        if entry is None:
            hash_password(password or "", b"0" * 16)  # As long as a real check, so names can't be told apart
            self._failed(name, address)
            return None
        digest, _ = hash_password(password or "", entry.get("salt", ""))
        if not hmac.compare_digest(digest, entry.get("hash", "")):
            self._failed(name, address)
            return None
        token = secrets.token_urlsafe(32)
        now = self.clock()
        with self.lock:
            self.failures.pop(f"user:{name.lower()}", None)
            self.failures.pop(f"address:{address}", None)
            self.sessions[_token_hash(token)] = Session(real, bool(entry.get("kiosk")), now, now,
                                                        entry.get("stamp", ""))
            self._save_sessions()
        return token

    def _failed(self, name, address):
        now = self.clock()
        with self.lock:
            for key in (f"user:{name.lower()}", f"address:{address}"):
                count, until = self.failures.get(key, (0, 0))
                if until and until <= now:
                    count = 0
                count += 1
                self.failures[key] = (count, now + LOCK_SECONDS if count >= MAX_FAILURES else 0)

    # ----------------------------------------------------------------- Sessions

    def session(self, token):
        """The Session of a cookie's token (its use noted), or None."""
        if not token:
            return None
        hashed = _token_hash(token)
        now = self.clock()
        with self.lock:
            self._current_users()
            session = self.sessions.get(hashed)
            if session is None:
                return None
            if session.expired(now, self.idle_hours):
                del self.sessions[hashed]
                self._save_sessions()
                return None
            session.used = now
            if now - self.saved_used.get(hashed, 0) > 300:
                self.saved_used[hashed] = now
                self._save_sessions()
            return session

    def sign_out(self, token):
        if token:
            with self.lock:
                if self.sessions.pop(_token_hash(token), None) is not None:
                    self._save_sessions()

    def _load_sessions(self):
        try:
            data = json.loads(self.sessions_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        found = {}
        for hashed, entry in (data.get("sessions") or {}).items():
            try:
                found[hashed] = Session(str(entry["user"]), bool(entry.get("kiosk")), float(entry["created"]),
                                        float(entry["used"]), str(entry.get("stamp", "")))
            except (KeyError, TypeError, ValueError):
                continue
        return found

    def _save_sessions(self):
        now = self.clock()
        self.sessions = {hashed: session for hashed, session in self.sessions.items()
                         if not session.expired(now, self.idle_hours)}
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            _write_json(self.sessions_path, {"sessions": {
                hashed: {"user": session.user, "kiosk": session.kiosk, "created": session.created,
                         "used": session.used, "stamp": session.stamp} for hashed, session in self.sessions.items()}})
        except OSError:
            pass  # Kept in memory: a restart signs them out


def _token_hash(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
