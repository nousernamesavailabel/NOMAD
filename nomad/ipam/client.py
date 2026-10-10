"""Talking to the NOMAD IPAM server: the tribe key, the HTTPS connection (pinned to the server's certificate), syncing
a local copy of the tribe's data, and TeamStore, which the IPAM page uses like a local IpamStore.

Reads come from the local copy, so they work offline. Edits go straight to the server, which checks them against
what the client last saw (raising ConflictError if someone else got there first) and replies with the changed rows,
which are applied to the copy at once; other changes arrive with the next sync.

Sweep results (when each address last answered) travel separately from changes: record_sightings keeps them in the
copy at once and in an outbox, sent with the next sync (send_sightings), and the server passes everyone's on
(fetch_sightings). They never go in the history.

While the server can't be reached, changes to addresses (not subnets or networks) are still made: they're applied to
the copy at once and queued as pending, several changes to one address becoming one. When the server is back they're
sent in the order they were made (send_pending on a worker thread, then apply_sent); any the server refuses, because
someone else changed that address first, are kept as refused for the user to resolve (use the next free address, or
discard), and the copy goes back to the server's version. VLAN changes made offline wait the same way (see
vlan_team.py), in a queue of their own.

When the tribe server has been moved to another computer (see migrate.py), the old one answers with the new one's
address: the client switches to it, repeats the request there, and remembers the address in the saved tribe key
(on_moved), so the laptop needs no new key file.
"""
import contextlib
import datetime
import http.client
import json
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..system import app_data_dir, log_dir
from .server import ADMIN, KEY_FILE_FORMAT, TEAM, ConflictError, fingerprint, fingerprint_of_file, load_config, \
    server_dir
from .store import TABLES, IpamError, IpamStore, current_user, ip_key, parse_address
from .vlans import VLAN_PENDING_SCHEMA, keep_pending_on_top as keep_vlan_pending_on_top

log = logging.getLogger(__name__)

SETTINGS_FILE = "ipam-team.json"
COPY_FILE = "ipam-team.db"
CONNECT_SECONDS = 4
READ_SECONDS = 60  # A first sync or an import can take a while to send
PENDING, REFUSED = "pending", "refused"
HISTORY_SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    seq INTEGER PRIMARY KEY, entity TEXT NOT NULL, entity_id TEXT NOT NULL, version INTEGER NOT NULL,
    op TEXT NOT NULL, data TEXT NOT NULL, modified TEXT NOT NULL, modified_by TEXT NOT NULL);
"""
PENDING_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, network_id TEXT NOT NULL, ip TEXT NOT NULL, sort_key TEXT NOT NULL,
    action TEXT NOT NULL, data TEXT NOT NULL DEFAULT '{}', expected_version INTEGER, original TEXT,
    made TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending', error TEXT NOT NULL DEFAULT '');
"""
SIGHTINGS_OUT_SCHEMA = """
CREATE TABLE IF NOT EXISTS sightings_out (
    seq INTEGER PRIMARY KEY AUTOINCREMENT, network_id TEXT NOT NULL, payload TEXT NOT NULL);
"""
SET, FREE = "set_address", "free_address"
VLAN_API = 7  # The server API level that keeps VLANs
PLACEMENT_API = 8  # And subnet placement
ROLES_API = 9  # And subnet roles
MOVE_API = 10  # And moving subnets between networks


class ServerUnreachable(IpamError):
    """No answer from the server (the laptop is offline, or the server is down)."""


class ServerMoved(ServerUnreachable):
    """The tribe server moved to another computer without saying where (a new tribe key file is needed); until
    then the laptop works as it does offline."""


class OldServerError(IpamError):
    """The server is an older NOMAD that doesn't know this request (it needs updating)."""


class TeamKeyError(IpamError):
    """The tribe key file is missing, damaged, or no longer accepted."""


@dataclass
class TeamKey:
    server_id: str
    hosts: list
    port: int
    fingerprint: str
    secret: str
    role: str = TEAM

    @classmethod
    def from_dict(cls, data):
        try:
            if data.get("format") != KEY_FILE_FORMAT:
                raise ValueError
            key = cls(str(data["server_id"]), [str(host) for host in data["hosts"]], int(data["port"]),
                      str(data["fingerprint"]).lower(), str(data["secret"]))
        except (KeyError, TypeError, ValueError, AttributeError):
            raise TeamKeyError("That isn't a NOMAD tribe key file (or it's from a newer version of NOMAD).") from None
        if not key.hosts or len(key.fingerprint) != 64:
            raise TeamKeyError("That tribe key file is incomplete.")
        return key


def read_key_file(path):
    try:
        return TeamKey.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))
    except (OSError, ValueError) as error:
        raise TeamKeyError(f"Couldn't read {Path(path).name}: {error}") from None


def admin_key(directory=None):
    """The key for managing the server from the server itself, or None if this isn't the server (or NOMAD isn't
    running as administrator, which reading the server's folder needs)."""
    directory = Path(directory or server_dir())
    try:
        config = load_config(directory)
        return TeamKey(config["server_id"], ["127.0.0.1"], int(config["port"]),
                       fingerprint_of_file(directory / "cert.pem"), config["admin_secret"], ADMIN)
    except (OSError, KeyError, ValueError):
        return None


def current_key(admin=False):
    """The tribe key NOMAD uses on this computer: on the tribe server itself (NOMAD running as administrator), the
    server's own admin key; otherwise the saved tribe key, or None."""
    return (admin_key() if admin else None) or load_saved_key()


def is_tribe_server():
    """Whether the IPAM server is installed on this computer (its folder is only readable as administrator, so
    this asks Windows about the service instead)."""
    try:
        from . import service
        return service.status() != service.NOT_INSTALLED
    except Exception:  # pywin32 missing, or not Windows
        return False


# --------------------------------------------------------------------- Saved connection (the secret encrypted)

def settings_path():
    return app_data_dir() / SETTINGS_FILE


def save_key(key, path=None):
    """Remember the tribe key for this Windows account (the secret encrypted with DPAPI)."""
    from ..terminal.credentials import protect
    data = {"format": KEY_FILE_FORMAT, "server_id": key.server_id, "hosts": key.hosts, "port": key.port,
            "fingerprint": key.fingerprint, "secret": protect(key.secret)}
    Path(path or settings_path()).write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_saved_key(path=None):
    """The remembered tribe key, or None."""
    from ..terminal.credentials import CredentialError, unprotect
    path = Path(path or settings_path())
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        data["secret"] = unprotect(data["secret"])
        return TeamKey.from_dict(data)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, CredentialError, TeamKeyError) as error:
        log.warning("Couldn't read the saved tribe key: %s", error)
        return None


def remember_moved_key(key, path=None):
    """The tribe server moved (see TeamClient.request): keep its new address in the saved tribe key, if that's the
    key that moved."""
    saved = load_saved_key(path)
    if saved is not None and saved.server_id == key.server_id and saved.secret == key.secret:
        saved.hosts, saved.port = list(key.hosts), key.port
        save_key(saved, path)


def forget_key(path=None):
    Path(path or settings_path()).unlink(missing_ok=True)


def copy_path():
    return log_dir() / COPY_FILE  # %LOCALAPPDATA%: a cache of the server's data, so it needn't roam


# --------------------------------------------------------------------- HTTPS, pinned to the server's certificate

class _Moved(Exception):
    def __init__(self, message, hosts, port):
        super().__init__(message)
        self.message, self.hosts, self.port = message, hosts, port


class TeamClient:
    def __init__(self, key, user=None, computer=None, on_moved=None, on_attempt=None):
        """on_moved(key): called (on whichever thread made the request) after the server said it moved to another
        computer and the key was pointed there; by default the saved tribe key is updated. on_attempt(event, host):
        told "trying" before each address is tried and "reached" once its certificate checks out (for showing
        progress, on the same thread)."""
        self.key = key
        self.user = user or current_user()
        self.computer = computer or socket.gethostname()
        self.last_host = None
        self.on_moved = on_moved or remember_moved_key
        self.on_attempt = on_attempt

    def _connect(self, host):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False  # Trust comes from the pinned fingerprint instead
        context.verify_mode = ssl.CERT_NONE
        connection = http.client.HTTPSConnection(host, self.key.port, timeout=CONNECT_SECONDS, context=context)
        connection.connect()
        presented = fingerprint(connection.sock.getpeercert(binary_form=True))
        if presented != self.key.fingerprint:
            connection.close()
            raise IpamError(f"The server at {host} isn't the one in the tribe key file (its certificate is "
                            "different). Ask for a new tribe key file if the server was rebuilt.")
        connection.sock.settimeout(READ_SECONDS)
        return connection

    def request(self, method, path, body=None):
        try:
            return self._request(method, path, body)
        except _Moved as moved:
            hosts, port = moved.hosts, moved.port
            if not hosts or self.key.role == ADMIN or (hosts == self.key.hosts and port == self.key.port):
                raise ServerMoved(moved.message) from None
            log.info("The tribe server moved to %s (port %s)", ", ".join(hosts), port)
            self.key.hosts, self.key.port, self.last_host = list(hosts), port, None
            try:
                self.on_moved(self.key)
            except Exception as error:  # Still works this time; it's asked again after a restart
                log.warning("Couldn't save the tribe server's new address: %s", error)
            try:
                return self._request(method, path, body)
            except _Moved as again:
                raise ServerMoved(again.message) from None

    def _request(self, method, path, body=None):
        hosts = [self.last_host] + [host for host in self.key.hosts if host != self.last_host] if self.last_host \
            else list(self.key.hosts)
        errors = []
        for host in hosts:
            if self.on_attempt:
                self.on_attempt("trying", host)
            try:
                connection = self._connect(host)
            except (OSError, ssl.SSLError) as error:
                errors.append(f"{host}: {getattr(error, 'strerror', None) or error}")
                continue
            if self.on_attempt:
                self.on_attempt("reached", host)
            try:
                data = None if body is None else json.dumps(body).encode("utf-8")
                headers = {"Authorization": f"Bearer {self.key.secret}", "X-NOMAD-User": self.user,
                           "X-NOMAD-Computer": self.computer, "Content-Type": "application/json"}
                connection.request(method, path, data, headers)
                response = connection.getresponse()
                payload = response.read()
            except (OSError, http.client.HTTPException) as error:
                errors.append(f"{host}: {error}")
                continue
            finally:
                connection.close()
            self.last_host = host
            try:
                reply = json.loads(payload or b"{}")
            except ValueError:
                raise IpamError(f"The server sent an unreadable reply (HTTP {response.status}).") from None
            if response.status == 409:
                raise ConflictError(reply.get("error", "Someone else changed it first."))
            if response.status == 401:  # The key itself was refused (whatever the server's wording)
                raise TeamKeyError(reply.get("error", "The tribe key isn't accepted."))
            if response.status == 410 and reply.get("moved"):
                raise _Moved(reply.get("error", "The tribe server has moved."), [str(host) for host in
                                                                                 reply.get("hosts") or []],
                             int(reply.get("port") or self.key.port))
            if response.status == 404:
                raise OldServerError(f"The IPAM server doesn't know {path.split('?')[0]}: it's running an older "
                                     "version of NOMAD.")
            if response.status >= 400:
                raise IpamError(reply.get("error", f"The server refused that (HTTP {response.status})."))
            return reply
        raise ServerUnreachable("Can't reach the IPAM server (" + "; ".join(errors) + ").")

    def status(self):
        return self.request("GET", "/api/status")

    def changes(self, since):
        return self.request("GET", f"/api/changes?since={int(since)}")

    def wait(self, since, timeout=25, sightings_since=None):
        """Wait (up to `timeout` seconds) for a revision after `since`, or sightings after `sightings_since`.
        Returns (latest revision, latest sightings or None from a server that doesn't have them)."""
        query = f"since={int(since)}&timeout={timeout}"
        if sightings_since is not None:
            query += f"&sightings_since={int(sightings_since)}"
        reply = self.request("GET", f"/api/wait?{query}")
        return reply["revision"], reply.get("sightings")

    def fetch_sightings(self, since):
        """Everyone's sweep results after `since` (safe on a worker thread). Returns (payload, seq), or None from a
        server too old to keep them."""
        payload, seq = {"hosts": [], "ranges": []}, since
        while True:
            try:
                reply = self.request("GET", f"/api/sightings?since={int(seq)}")
            except OldServerError:
                return None
            payload["hosts"] += reply["hosts"]
            payload["ranges"] += reply["ranges"]
            seq = reply["seq"]
            if not reply.get("more"):
                return payload, seq

    def fetch_log(self, since):
        """The server's change log after `since` (safe on a worker thread). Returns (entries, revision)."""
        entries, revision = [], since
        while True:
            reply = self.request("GET", f"/api/log?since={int(revision)}")
            entries.extend(reply["entries"])
            revision = reply["revision"]
            if not reply.get("more"):
                return entries, revision

    def fetch_all_changes(self, since):
        """Every change after `since`, following `more` (safe to call on a worker thread). Returns (status, items,
        revision)."""
        status = self.status()
        items, revision = [], since
        if status["server_id"] != self.key.server_id:
            raise TeamKeyError("The server has changed (it was set up again). Ask for the new tribe key file.")
        while True:
            reply = self.changes(revision)
            items.extend(reply["items"])
            revision = reply["revision"]
            if not reply.get("more"):
                return status, items, revision

    def edit(self, action, **arguments):
        return self.request("POST", "/api/edit", dict(arguments, action=action))

    # ----------------------------------------------------------------- Tribe maps (server API 6)

    def wait_for_maps(self, maps_since, timeout=25):
        """Wait (up to `timeout` seconds) for a map change after `maps_since`. Returns the latest map revision (None
        from a server without tribe maps)."""
        reply = self.request("GET", f"/api/wait?since={2 ** 62}&timeout={timeout}&maps_since={int(maps_since)}")
        return reply.get("maps")

    def map_changes(self, since):
        """Every map change after `since` (safe on a worker thread). Returns ({"maps", "items", "leases"},
        revision)."""
        payload, revision = {"maps": [], "items": [], "leases": {}}, since
        while True:
            reply = self.request("GET", f"/api/maps/changes?since={int(revision)}")
            payload["maps"] += reply["maps"]
            payload["items"] += reply["items"]
            payload["leases"] = reply.get("leases", {})
            revision = reply["revision"]
            if not reply.get("more"):
                return payload, revision

    def map_request(self, action, **body):
        """create, push, rename, delete, secrets or lease."""
        return self.request("POST", f"/api/maps/{action}", body)

    def map_secrets(self, map_id):
        return self.request("GET", f"/api/maps/secrets?map_id={int(map_id)}")["secrets"]

    def import_networks(self, plans):
        return self.request("POST", "/api/import", {"plans": plans})


# --------------------------------------------------------------------- The copy, and the store the UI uses

class TeamStore:
    """The tribe's IPAM data for the UI: IpamStore's reading methods from the local copy, and its changing methods
    sent to the server. Use on the UI thread (the copy's SQLite connection belongs to it)."""

    def __init__(self, key, path=None, client=None):
        self.key = key
        self.client = client or TeamClient(key)
        self.copy = IpamStore(str(path or copy_path()))
        self.online = False
        self.last_error = ""
        self.key_rejected = False  # The server refused the tribe key (a new key file is needed)
        self.copy.db.executescript(PENDING_SCHEMA)
        self.copy.db.executescript(HISTORY_SCHEMA)
        self.copy.db.executescript(SIGHTINGS_OUT_SCHEMA)
        self.copy.db.executescript(VLAN_PENDING_SCHEMA)
        if self.copy.get_meta("server_id") not in ("", key.server_id):
            self.reset_copy()
        if self.copy.get_meta("synced_tables") != ",".join(TABLES):
            # A copy synced by a NOMAD that kept fewer tables (from before VLANs, say) went past the server's rows
            # for the others without keeping them: fetch everything once more (rows here already are written again)
            with self.copy.transaction():
                self.copy.set_meta("revision", 0)
                self.copy.set_meta("synced_tables", ",".join(TABLES))

    @property
    def admin(self):
        return self.key.role == ADMIN

    @property
    def user(self):
        return self.client.user

    def close(self):
        self.copy.close()

    def reset_copy(self):
        """Empty the copy (for a different server), so the next sync fetches everything."""
        with self.copy.transaction():
            for table in ("networks", "subnets", "addresses", "changes", "pending", "history", "sightings", "sweeps",
                          "sightings_out", "vlan_domains", "vlans", "vlan_pending", "placements", "subnet_moves",
                          "subnet_roles"):
                self.copy.db.execute(f"DELETE FROM {table}")
            self.copy.set_meta("revision", 0)
            self.copy.set_meta("sighting_revision", 0)
            self.copy.set_meta("server_id", self.key.server_id)

    @property
    def revision(self):
        return int(self.copy.get_meta("revision", "0") or 0)

    @property
    def history_revision(self):
        """How far the copy of the server's change log (for history) reaches."""
        return int(self.copy.get_meta("history_revision", "0") or 0)

    def apply_log(self, entries, revision):
        """Keep the server's change log entries (on the UI thread), so history works offline."""
        with self.copy.transaction():
            self.copy.db.executemany("INSERT OR REPLACE INTO history VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                     [(entry["seq"], entry["entity"], entry["entity_id"], entry["version"],
                                       entry["op"], entry["data"], entry["modified"], entry["modified_by"])
                                      for entry in entries])
            self.copy.set_meta("history_revision", revision)

    def fetch_history(self):
        """Bring the history up to date now (blocking; the UI does the fetch on a worker thread)."""
        entries, revision = self.client.fetch_log(self.history_revision)
        self.apply_log(entries, revision)
        return len(entries)

    @property
    def last_sync(self):
        """When the copy last caught up with the server (seconds since the epoch), or 0."""
        return float(self.copy.get_meta("last_sync", "0") or 0)

    def apply_sync(self, items, revision, status=None):
        """Apply what fetch_all_changes brought (on the UI thread)."""
        self.copy.apply_rows(items)
        self._keep_pending_on_top(items)
        keep_vlan_pending_on_top(self.copy, items)
        with self.copy.transaction():
            self.copy.set_meta("revision", revision)
            self.copy.set_meta("server_id", self.key.server_id)
            self.copy.set_meta("last_sync", time.time())
            if status and status.get("name"):
                self.copy.set_meta("server_name", status["name"])
            if status and status.get("api"):
                self.copy.set_meta("server_api", status["api"])
        self.online, self.last_error, self.key_rejected = True, "", False

    @property
    def server_api(self):
        """The server's API level, as of the last sync (0 before one)."""
        return int(self.copy.get_meta("server_api", "0") or 0)

    @property
    def server_keeps_placement(self):
        """Whether the server is new enough to keep subnet placement (assumed so before the first sync)."""
        return self.server_api == 0 or self.server_api >= PLACEMENT_API

    @property
    def server_keeps_roles(self):
        """Whether the server is new enough to keep subnet roles (assumed so before the first sync)."""
        return self.server_api == 0 or self.server_api >= ROLES_API

    @property
    def server_moves_subnets(self):
        """Whether the server is new enough to move subnets between networks (assumed so before the first sync)."""
        return self.server_api == 0 or self.server_api >= MOVE_API

    @property
    def server_keeps_vlans(self):
        """Whether the server is new enough to keep VLANs (unknown until the first sync: assumed so)."""
        return self.server_api == 0 or self.server_api >= VLAN_API

    @property
    def server_name(self):
        """The server's computer name (from its last answer), or the first name in the tribe key."""
        return self.copy.get_meta("server_name") or self.key.hosts[0]

    @property
    def server_address(self):
        """"host:port" as last reached (or as first listed in the tribe key)."""
        return f"{self.client.last_host or self.key.hosts[0]}:{self.key.port}"

    def sync(self):
        """Fetch and apply every change now (blocking; the UI does the fetch on a worker thread instead)."""
        status, items, revision = self.client.fetch_all_changes(self.revision)
        self.apply_sync(items, revision, status)
        return len(items)

    def _send(self, action, **arguments):
        try:
            reply = self.client.edit(action, **arguments)
        except ServerUnreachable as error:
            self.online, self.last_error = False, str(error)
            raise ServerUnreachable("The IPAM server can't be reached, so subnets and networks can't be changed "
                                    "right now (addresses can: they're sent when it's back).") from None
        self.online = True
        self.copy.apply_rows(reply["items"])
        return reply

    # ----------------------------------------------------------------- Sweep results (last seen)

    @property
    def sighting_revision(self):
        """How far the copy has the server's sweep results."""
        return int(self.copy.get_meta("sighting_revision", "0") or 0)

    def record_sightings(self, network_id, hosts=(), ranges=()):
        """Keep a sweep's results in the copy now, and queue them for the server (sent with the next sync)."""
        hosts, ranges = list(hosts), list(ranges)
        if not hosts and not ranges:
            return 0
        by = f"{self.client.user} ({self.client.computer})"
        with self.copy.transaction():
            changed = self.copy.record_sightings(network_id, hosts, ranges, by=by)
            self.copy.db.execute("INSERT INTO sightings_out (network_id, payload) VALUES (?, ?)",
                                 (network_id, json.dumps({"hosts": hosts, "ranges": ranges})))
        return changed

    def outgoing_sightings(self):
        rows = self.copy.db.execute("SELECT * FROM sightings_out ORDER BY seq").fetchall()
        return [dict(seq=row["seq"], network_id=row["network_id"], **json.loads(row["payload"])) for row in rows]

    def send_sightings(self, entries):
        """Send queued sweep results (safe on a worker thread). Returns the seqs done with: sent, or refused for
        good (such as a network deleted since). Stops at the first that can't reach the server."""
        done = []
        for entry in entries:
            try:
                self.client.request("POST", "/api/sightings", {"network_id": entry["network_id"],
                                                               "hosts": entry["hosts"], "ranges": entry["ranges"]})
            except (ServerUnreachable, OldServerError, TeamKeyError):
                break  # Kept for later (an older server keeps them until it's updated)
            except IpamError as error:
                log.info("The IPAM server didn't take sweep results for network %s: %s", entry["network_id"], error)
            done.append(entry["seq"])
        return done

    def apply_sent_sightings(self, seqs):
        if seqs:
            with self.copy.transaction():
                self.copy.db.executemany("DELETE FROM sightings_out WHERE seq = ?", [(seq,) for seq in seqs])

    def apply_sightings(self, payload, seq):
        """Take in everyone's sweep results from fetch_sightings (on the UI thread)."""
        with self.copy.transaction():
            self.copy.apply_sightings(payload)
            self.copy.set_meta("sighting_revision", seq)

    # ----------------------------------------------------------------- Changes made offline

    def pending_count(self):
        return self.copy.db.execute("SELECT COUNT(*) FROM pending WHERE state = ?", (PENDING,)).fetchone()[0]

    def pending_ips(self, network_id):
        """Addresses in a network with a change waiting to be sent."""
        rows = self.copy.db.execute("SELECT ip FROM pending WHERE network_id = ? AND state = ?", (network_id, PENDING))
        return {row[0] for row in rows}

    def refused(self):
        """Changes made offline that the server refused: [dict] with network_id, ip, action, data, error, made."""
        rows = self.copy.db.execute("SELECT * FROM pending WHERE state = ? ORDER BY seq", (REFUSED,)).fetchall()
        return [dict(row, data=json.loads(row["data"])) for row in rows]

    def discard(self, seq):
        with self.copy.transaction():
            self.copy.db.execute("DELETE FROM pending WHERE seq = ?", (seq,))

    def _queue(self, network_id, ip, action, data):
        """Make an address change in the copy now and remember it for the server (merged with any earlier one)."""
        ip = str(parse_address(ip))
        key = ip_key(parse_address(ip))
        with self.copy.transaction():
            entry = self.copy.db.execute("SELECT * FROM pending WHERE network_id = ? AND sort_key = ? AND state = ?",
                                         (network_id, key, PENDING)).fetchone()
            if entry is None:
                current = self.copy.address(network_id, ip)
                if current is None and action == FREE:
                    return  # Already free
                original = self.copy.row_of("addresses", current.id)["row"] if current else None
                self.copy.db.execute("INSERT INTO pending (network_id, ip, sort_key, action, data, expected_version, "
                                     "original, made) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                     (network_id, ip, key, action, json.dumps(data),
                                      current.version if current else None,
                                      json.dumps(original) if original else None, now_text()))
            elif action == FREE and entry["original"] is None:
                # Recorded offline and freed again before the server heard about it: nothing to send
                self.copy.db.execute("DELETE FROM pending WHERE seq = ?", (entry["seq"],))
            else:
                self.copy.db.execute("UPDATE pending SET action = ?, data = ?, made = ? WHERE seq = ?",
                                     (action, json.dumps(data), now_text(), entry["seq"]))
            if action == SET:
                self.copy.set_address(network_id, ip, **data)
            else:
                self.copy.free_address(network_id, ip)

    def outgoing(self):
        """The pending changes to send, oldest first (plain data, for a worker thread)."""
        rows = self.copy.db.execute("SELECT * FROM pending WHERE state = ? ORDER BY seq", (PENDING,)).fetchall()
        return [dict(row, data=json.loads(row["data"])) for row in rows]

    def send_pending(self, entries):
        """Send pending changes in order (safe on a worker thread: it only talks to the server). Stops at the first
        one that can't reach the server. Returns [(seq, "sent", reply) or (seq, "refused", message)]."""
        results = []
        for entry in entries:
            arguments = dict(network_id=entry["network_id"], ip=entry["ip"],
                             expected_version=entry["expected_version"])
            if entry["action"] == SET:
                arguments.update(entry["data"])
            try:
                reply = self.client.edit(entry["action"], **arguments)
            except ServerUnreachable:
                break
            except TeamKeyError:
                raise
            except IpamError as error:  # Someone else changed it first, or the server couldn't make it
                results.append((entry["seq"], REFUSED, str(error)))
                continue
            results.append((entry["seq"], "sent", reply))
        return results

    def apply_sent(self, results):
        """Record what send_pending did (on the UI thread). Returns (sent, refused) counts."""
        sent = refused = 0
        for seq, outcome, detail in results:
            entry = self.copy.db.execute("SELECT * FROM pending WHERE seq = ?", (seq,)).fetchone()
            if entry is None:
                continue
            if outcome == "sent":
                self.copy.apply_rows(detail["items"])
                with self.copy.transaction():
                    self.copy.db.execute("DELETE FROM pending WHERE seq = ?", (seq,))
                sent += 1
                continue
            with self.copy.transaction():
                self.copy.db.execute("UPDATE pending SET state = ?, error = ? WHERE seq = ?", (REFUSED, detail, seq))
                self._restore(entry)
            refused += 1
        if results:
            self.online = True
        return sent, refused

    def _keep_pending_on_top(self, items):
        """The server's rows just replaced some addresses that have changes waiting. Remember the server's row as
        what to go back to if the change is refused, and show the waiting change on top of it again."""
        arrived = {(item["row"]["network_id"], item["row"]["sort_key"]): item["row"] for item in items
                   if item["entity"] == "addresses"}
        if not arrived:
            return
        entries = self.copy.db.execute("SELECT * FROM pending WHERE state = ?", (PENDING,)).fetchall()
        for entry in entries:
            row = arrived.get((entry["network_id"], entry["sort_key"]))
            if row is None:
                continue
            with self.copy.transaction():
                self.copy.db.execute("UPDATE pending SET original = ? WHERE seq = ?",
                                     (None if row["deleted"] else json.dumps(row), entry["seq"]))
                if entry["action"] == SET:
                    self.copy.set_address(entry["network_id"], entry["ip"], **json.loads(entry["data"]))
                else:
                    self.copy.free_address(entry["network_id"], entry["ip"])

    def _restore(self, entry):
        """Put the copy's address back to the server's latest version (as of the last sync) after a refusal."""
        self.copy.db.execute("UPDATE addresses SET deleted = 1 WHERE network_id = ? AND sort_key = ? AND deleted = 0",
                             (entry["network_id"], entry["sort_key"]))
        if entry["original"]:
            self.copy.apply_rows([{"entity": "addresses", "row": json.loads(entry["original"])}])

    def flush(self):
        """Send every pending change now (blocking). Returns (sent, refused)."""
        return self.apply_sent(self.send_pending(self.outgoing()))

    # ----------------------------------------------------------------- Reading, from the copy

    def __getattr__(self, name):
        if name in ("networks", "network", "network_named", "subnets", "subnet", "subnet_for", "addresses",
                    "address", "count_addresses", "next_free", "search", "detail_names", "free_blocks",
                    "deleted_since", "sightings"):
            return getattr(self.copy, name)
        raise AttributeError(name)

    @contextlib.contextmanager
    def transaction(self):
        yield  # Each change goes to the server on its own

    # ----------------------------------------------------------------- Changing, through the server

    def set_address(self, network_id, ip, status="used", name="", mac="", description="", fields=None):
        """Record an address: straight to the server when it can be reached (and nothing is waiting to be sent
        before it), otherwise queued as pending."""
        data = dict(status=status, name=name.strip(), mac=mac.strip(), description=description, fields=fields or {})
        if self.online and not self.pending_count():
            current = self.copy.address(network_id, ip)
            try:
                self._send(SET, network_id=network_id, ip=str(parse_address(ip)),
                           expected_version=current.version if current else None, **data)
                return self.copy.address(network_id, ip)
            except ServerUnreachable:
                pass  # Lost the server just now: keep the change for later
        self._queue(network_id, ip, SET, data)
        return self.copy.address(network_id, ip)

    def free_address(self, network_id, ip):
        current = self.copy.address(network_id, ip)
        if current is None:
            return
        if self.online and not self.pending_count():
            try:
                self._send(FREE, network_id=network_id, ip=str(parse_address(ip)), expected_version=current.version)
                return
            except ServerUnreachable:
                pass
        self._queue(network_id, ip, FREE, {})

    def add_subnet(self, network_id, cidr, name="", gateway="", description="", fields=None, loopbacks=False):
        reply = self._send("add_subnet", network_id=network_id, cidr=cidr, name=name, gateway=gateway,
                           description=description, fields=fields or {}, loopbacks=bool(loopbacks))
        created = [item["row"]["id"] for item in reply["items"] if item["entity"] == "subnets"]
        return self.copy.subnet(created[-1])

    def update_subnet(self, subnet_id, **changes):
        self._send("update_subnet", subnet_id=subnet_id, changes=changes,
                   expected_version=self.copy.subnet(subnet_id).version)
        return self.copy.subnet(subnet_id)

    def delete_subnet(self, subnet_id, with_addresses=False):
        self._send("delete_subnet", subnet_id=subnet_id, with_addresses=with_addresses,
                   expected_version=self.copy.subnet(subnet_id).version)

    def move_subnet(self, network_id, cidr, to_network_id, take_nested=True, link=None):
        """Move a subnet (and those inside it, with take_nested) to another tribe network, on the server."""
        self._needs_move_api()
        self._send("move_subnet", network_id=network_id, cidr=cidr, to_network_id=to_network_id,
                   take_nested=bool(take_nested), link=list(link) if link else None)

    def take_subnets(self, to_network_id, data, link=None):
        """Put subnets moved from this computer's own networks into a tribe network (network_move.payload)."""
        self._needs_move_api()
        self._send("take_subnets", to_network_id=to_network_id, data=data, link=list(link) if link else None)

    def _needs_move_api(self):
        if not self.server_moves_subnets:
            raise OldServerError("The IPAM server is running an older version of NOMAD that can't move subnets "
                                 "between networks: it needs updating (Tools > Tribe Management > Update Service, "
                                 "on the server).")

    def add_network(self, name, description="", fields=None):
        reply = self._send("add_network", name=name, description=description, fields=fields or {})
        created = [item["row"]["id"] for item in reply["items"] if item["entity"] == "networks"]
        return self.copy.network(created[-1])

    def update_network(self, network_id, **changes):
        self._send("update_network", network_id=network_id, changes=changes,
                   expected_version=self.copy.network(network_id).version)
        return self.copy.network(network_id)

    def delete_network(self, network_id):
        self._send("delete_network", network_id=network_id, expected_version=self.copy.network(network_id).version)

    def import_networks(self, plans):
        try:
            reply = self.client.import_networks(plans)
        except ServerUnreachable:
            self.online = False
            raise
        self.copy.apply_rows(reply["items"])
        return [self.copy.network(network_id) for network_id in reply["networks"]]


def now_text():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
