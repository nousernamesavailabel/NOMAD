"""Moving the tribe server to another computer, keeping everything: its networks and history, the tribe maps and
their SNMP credentials, its certificate and the tribe key, so the laptops' saved keys, copies and pending changes all
carry on working.

On the old server, export_server writes a move file (.nomadmove) protected by a password: the server's databases,
certificate and secrets, zipped and encrypted with AES-256-GCM under a key made from the password by scrypt. The maps'
community strings are kept with Windows DPAPI for the old computer, which the new one can't read, so they travel
decrypted inside the encrypted file and are encrypted again for the new computer by import_server.

After the export the old server is "moved": it refuses every request with HTTP 410, naming the new server's address
when it was given, and laptops then switch to it by themselves (see TeamClient.request) and remember it. Left running
for a while, the old server points laptops that were away during the move to the new one. undo_move puts it back in
service, if the move is called off before anyone uses the new server.
"""
import datetime
import io
import json
import os
import secrets
import shutil
import socket
import sqlite3
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .. import __version__
from .server import _map_secret_protection, load_config, save_config, server_dir
from .store import IpamError

MOVE_FILE_SUFFIX = ".nomadmove"
MAGIC = b"NOMADMOVE1"
MOVE_FORMAT = 1
SALT_BYTES, NONCE_BYTES = 16, 12
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1
MIN_PASSWORD = 8
CONFIG_CARRIED = ("server_id", "port", "team_secret", "admin_secret", "backup_keep_days")
FILES = ("ipam.db", "maps.db", "cert.pem", "key.pem")


class MoveError(IpamError):
    pass


def _key(password, salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(password.encode("utf-8"))


def _encrypt(data, password):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = secrets.token_bytes(SALT_BYTES), secrets.token_bytes(NONCE_BYTES)
    return MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)


def _decrypt(blob, password):
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not blob.startswith(MAGIC):
        raise MoveError("That isn't a NOMAD tribe server move file.")
    salt = blob[len(MAGIC):len(MAGIC) + SALT_BYTES]
    nonce = blob[len(MAGIC) + SALT_BYTES:len(MAGIC) + SALT_BYTES + NONCE_BYTES]
    try:
        return AESGCM(_key(password, salt)).decrypt(nonce, blob[len(MAGIC) + SALT_BYTES + NONCE_BYTES:], MAGIC)
    except InvalidTag:
        raise MoveError("Wrong password (or the move file is damaged).") from None


def _snapshot(source, target):
    """A consistent copy of a SQLite database, even while the server has it open."""
    source_db, target_db = sqlite3.connect(source), sqlite3.connect(target)
    try:
        source_db.backup(target_db)
    finally:
        source_db.close()
        target_db.close()


def _recrypt_secrets(path, change):
    """Pass every map's community strings in maps.db at `path` through change(text); a map whose strings can't be
    read is left without them. Returns how many maps lost theirs."""
    db = sqlite3.connect(path)
    lost = 0
    try:
        db.execute("CREATE TABLE IF NOT EXISTS secrets (map_id INTEGER PRIMARY KEY, data TEXT NOT NULL, "
                   "revision INTEGER NOT NULL)")
        for map_id, data in db.execute("SELECT map_id, data FROM secrets").fetchall():
            try:
                db.execute("UPDATE secrets SET data = ? WHERE map_id = ?", (change(data), map_id))
            except Exception:  # Unreadable (damaged, or from yet another computer)
                db.execute("DELETE FROM secrets WHERE map_id = ?", (map_id,))
                lost += 1
        db.commit()
    finally:
        db.close()
    return lost


def _count(path, query):
    db = sqlite3.connect(path)
    try:
        return db.execute(query).fetchone()[0]
    except sqlite3.Error:
        return 0
    finally:
        db.close()


def parse_hosts(text_or_list):
    """Server names and addresses typed in one box (separated by commas, semicolons or spaces), or a list."""
    items = text_or_list.replace(";", ",").replace(" ", ",").split(",") if isinstance(text_or_list, str) \
        else text_or_list
    return [item.strip() for item in items if item and item.strip()]


@dataclass
class MoveSummary:
    server_id: str
    source: str  # The old server's computer name
    created: str
    version: str  # Of the NOMAD that exported it
    port: int
    networks: int
    maps: int
    lost_secrets: int = 0

    def describe(self):
        return (f"From {self.source}, exported {self.created[:16].replace('T', ' ')} by NOMAD {self.version}: "
                f"{self.networks} network(s), {self.maps} tribe map(s), port {self.port}.")


def export_server(path, password, new_hosts=(), new_port=None, directory=None):
    """Write the move file and mark this server moved (to new_hosts:new_port, when given). Stop the service first,
    so nothing changes after the export. Returns a MoveSummary."""
    if len(password) < MIN_PASSWORD:
        raise MoveError(f"Use a password of at least {MIN_PASSWORD} characters: the file holds the tribe key.")
    directory = Path(directory or server_dir())
    config = load_config(directory)
    for name in FILES:
        if not (directory / name).exists():
            raise MoveError(f"There's no {name} in {directory}: is the tribe server set up on this computer?")
    _, unprotect = _map_secret_protection()
    with tempfile.TemporaryDirectory() as work:
        work = Path(work)
        _snapshot(directory / "ipam.db", work / "ipam.db")
        _snapshot(directory / "maps.db", work / "maps.db")
        lost = _recrypt_secrets(work / "maps.db", unprotect) if unprotect else 0
        summary = MoveSummary(config["server_id"], socket.gethostname(),
                              datetime.datetime.now().isoformat(timespec="seconds"), __version__, int(config["port"]),
                              _count(work / "ipam.db", "SELECT COUNT(*) FROM networks WHERE deleted = 0"),
                              _count(work / "maps.db", "SELECT COUNT(*) FROM maps WHERE deleted = 0"), lost)
        manifest = {"format": MOVE_FORMAT, "summary": summary.__dict__,
                    "config": {name: config[name] for name in CONFIG_CARRIED if name in config}}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            for name in ("ipam.db", "maps.db"):
                archive.write(work / name, name)
            for name in ("cert.pem", "key.pem"):
                archive.write(directory / name, name)
    blob = _encrypt(buffer.getvalue(), password)
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(blob)
    os.replace(temporary, path)
    set_moved(new_hosts, new_port or config["port"], directory)
    return summary


def set_moved(new_hosts, new_port, directory=None):
    """Mark the server moved: it refuses every request, pointing laptops at new_hosts (when any) on new_port."""
    config = load_config(directory)
    config["moved"] = {"hosts": parse_hosts(new_hosts), "port": int(new_port),
                       "when": datetime.datetime.now().isoformat(timespec="seconds")}
    save_config(config, directory)
    return config


def undo_move(directory=None):
    """Put the old server back in service (only before anyone has used the new one: their changes there would be
    left behind)."""
    config = load_config(directory)
    config.pop("moved", None)
    save_config(config, directory)
    return config


def moved(directory=None):
    """The "moved" settings ({"hosts", "port", "when"}) if this server was moved, else None."""
    try:
        return load_config(directory).get("moved")
    except (OSError, ValueError):
        return None


class MoveFile:
    """An opened (decrypted) move file."""

    def __init__(self, path, password):
        try:
            blob = Path(path).read_bytes()
        except OSError as error:
            raise MoveError(f"Couldn't read {Path(path).name}: {error.strerror or error}") from None
        data = _decrypt(blob, password)
        try:
            self.archive = zipfile.ZipFile(io.BytesIO(data))
            self.manifest = json.loads(self.archive.read("manifest.json"))
            if self.manifest.get("format") != MOVE_FORMAT:
                raise ValueError
            self.summary = MoveSummary(**self.manifest["summary"])
            self.config = self.manifest["config"]
            missing = [name for name in FILES if name not in self.archive.namelist()]
            if missing or not all(name in self.config for name in ("server_id", "team_secret", "admin_secret")):
                raise ValueError
        except (zipfile.BadZipFile, KeyError, TypeError, ValueError):
            raise MoveError("That move file is incomplete, or from a newer version of NOMAD.") from None


def existing_server(directory=None):
    """The server_id of a tribe server already set up in `directory`, or None."""
    try:
        return load_config(directory).get("server_id")
    except (OSError, ValueError):
        return None


def import_server(move_file, directory=None, port=None):
    """Set this computer's tribe server up from a move file (the service must be stopped or not installed). A server
    already here is kept, renamed to server-before-move-<time> beside it. Returns the new config."""
    directory = Path(directory or server_dir())
    if directory.exists() and any(directory.iterdir()):
        aside = directory.with_name(f"{directory.name}-before-move-{datetime.datetime.now():%Y%m%d-%H%M%S}")
        shutil.move(str(directory), str(aside))
    directory.mkdir(parents=True, exist_ok=True)
    for name in FILES:
        (directory / name).write_bytes(move_file.archive.read(name))
    protect, _ = _map_secret_protection()
    if protect:
        _recrypt_secrets(directory / "maps.db", protect)
    config = dict(move_file.config)
    config["port"] = int(port or config.get("port") or move_file.summary.port)
    config["backup_dir"] = str(directory / "backups")  # The old computer's folder may not exist here
    save_config(config, directory)
    return config
