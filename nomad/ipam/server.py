"""The NOMAD IPAM server: the tribe's shared copy of the IPAM data, served over HTTPS to every NOMAD on the network.

It runs headless (normally as the "NOMAD IPAM Server" Windows service; see service.py) and keeps its files in
%ProgramData%\\NOMAD\\server: the database, its TLS certificate and key, config.json with the tribe and admin
secrets, the log and nightly backups. Only Administrators, SYSTEM and the service can read that folder.

Clients prove who they are with the tribe secret from the tribe key file (the key file also carries the server's
certificate fingerprint, which clients pin, so no certificate authority is needed). The admin secret is accepted
only from the server machine itself: it's what lets NOMAD's GUI there import spreadsheets and add or delete
networks. Every edit names the Windows user and computer it came from, for the change log.

API (JSON; "Authorization: Bearer <secret>"):
    GET  /api/status                  the server's id and name, latest revision, and the caller's role
    GET  /api/changes?since=N         rows changed after revision N (see IpamStore.changes_since)
    GET  /api/log?since=N             the change log after revision N (who changed what, when), for history
    GET  /api/wait?since=N            answers as soon as there's a revision after N (or after about 25 seconds
                                      without one): each laptop keeps one of these waiting, so it syncs the
                                      moment anyone changes anything
    POST /api/edit {"action": ...}    one change, checked against the version the client last saw
    POST /api/import {"plans": [...]} import prepared networks (admin only)

VLANs (API 7; see vlans.py) are rows like the rest, so they come with /api/changes and /api/log. Their edits are
add_vlan_domain, update_vlan_domain, delete_vlan_domain, set_vlan, delete_vlan and set_vlans (several at once).
Subnet placement (API 8; see placement.py): set_placement, plan_move, update_move and complete_move; set_role (API 9).
Moving subnets between networks (API 10; see network_move.py): move_subnet, and take_subnets (from a laptop's own).

A server moved to another computer (see migrate.py) answers every request with HTTP 410 and {"hosts", "port"}: the
new server's address, which laptops switch to by themselves.

Tribe maps (network maps shared by everyone; see nomad/netmap/shared.py), kept in maps.db:
    GET  /api/maps/changes?since=N    maps and map items changed after map revision N
    POST /api/maps/create             {"name", "changes": [...], "secrets": {...}}: a new shared map
    POST /api/maps/push               {"map_id", "changes": [...]}: items changed (the latest of each wins)
    POST /api/maps/rename             {"map_id", "name"}
    POST /api/maps/delete             {"map_id"}
    GET  /api/maps/secrets?map_id=N   its community strings; POST /api/maps/secrets {"map_id", "secrets"}
    POST /api/maps/lease              {"map_id", "holder", "kind", "release", "take"}: who's watching it for new
                                      devices (so two computers don't both poll the network)
    /api/wait also takes maps_since, and answers when a map changes.
"""
import datetime
import hashlib
import hmac
import http.server
import ipaddress
import json
import logging
import logging.handlers
import os
import secrets
import socket
import sqlite3
import ssl
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .. import __version__
from ..netmap.shared import MapError, MapStore
from .store import IpamError, IpamStore
from .placement import PlacementStore
from .vlans import VlanStore, check_number

log = logging.getLogger(__name__)

DEFAULT_PORT = 8443
KEY_FILE_SUFFIX = ".nomadkey"
KEY_FILE_FORMAT = 1
MAX_REQUEST_BYTES = 64 * 1024 * 1024  # An import of every page of a large workbook fits easily
BACKUP_KEEP_DAYS = 14
BACKUP_CHECK_SECONDS = 3600
TEAM, ADMIN = "team", "admin"
ADMIN_ONLY_ACTIONS = {"add_network", "delete_network"}
CERTIFICATE_YEARS = 20
MAX_WAIT_SECONDS = 55
API_LEVEL = 10  # 2 added /api/wait (instant sync), 3 /api/log (history), 4 loopback subnets, 5 sightings (last seen),
# 6 tribe maps, 7 VLANs, 8 subnet placement, 9 subnet roles, 10 moving subnets between networks.
# Clients cope with servers below this


class ConflictError(IpamError):
    """Someone else changed it first; the message says who and what, and the client should sync."""


def server_dir():
    """%ProgramData%\\NOMAD\\server, where the server keeps everything."""
    return Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "NOMAD" / "server"


def host_names():
    """This machine's names and IPv4 addresses, for the tribe key file (clients try each until one answers)."""
    names = []
    for name in (socket.getfqdn(), socket.gethostname()):
        if name and name.lower() not in (existing.lower() for existing in names):
            names.append(name)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = info[4][0]
            if not ipaddress.ip_address(address).is_loopback and address not in names:
                names.append(address)
    except OSError:
        pass
    return names


# --------------------------------------------------------------------- Setup: config, secrets, certificate

def load_config(directory=None):
    """The server's config.json (raises OSError if it's missing or can't be read, e.g. without admin rights)."""
    directory = Path(directory or server_dir())
    return json.loads((directory / "config.json").read_text(encoding="utf-8"))


def save_config(config, directory=None):
    directory = Path(directory or server_dir())
    temporary = directory / "config.json.tmp"
    temporary.write_text(json.dumps(config, indent=2), encoding="utf-8")
    os.replace(temporary, directory / "config.json")


def set_up(directory=None, port=DEFAULT_PORT):
    """Create the server's folder, secrets and certificate if they don't exist yet; returns the config.

    Running it again keeps what's there, so reinstalling the service doesn't lock out any laptops.
    """
    directory = Path(directory or server_dir())
    directory.mkdir(parents=True, exist_ok=True)
    try:
        config = load_config(directory)
    except FileNotFoundError:
        config = {"server_id": uuid.uuid4().hex, "port": port, "team_secret": secrets.token_urlsafe(32),
                  "admin_secret": secrets.token_urlsafe(32), "backup_dir": str(directory / "backups"),
                  "backup_keep_days": BACKUP_KEEP_DAYS}
        save_config(config, directory)
        log.info("Created the IPAM server's settings in %s", directory)
    if not (directory / "cert.pem").exists() or not (directory / "key.pem").exists():
        create_certificate(directory)
    return config


def create_certificate(directory):
    """A self-signed certificate for this machine's names. Clients pin its fingerprint (from the tribe key file),
    so it never needs to be trusted by Windows or renewed by a certificate authority."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname()),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NOMAD IPAM Server")])
    alternatives = []
    for host in host_names() + ["localhost", "127.0.0.1"]:
        try:
            alternatives.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            alternatives.append(x509.DNSName(host))
    today = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(today - datetime.timedelta(days=1))
                   .not_valid_after(today + datetime.timedelta(days=365 * CERTIFICATE_YEARS))
                   .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
                   .sign(key, hashes.SHA256()))
    directory = Path(directory)
    (directory / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                          serialization.PrivateFormat.PKCS8,
                                                          serialization.NoEncryption()))
    (directory / "cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    log.info("Created the IPAM server's certificate (fingerprint %s)", fingerprint_of_file(directory / "cert.pem"))


def fingerprint(der_bytes):
    """A certificate's SHA-256 fingerprint as hex, as the tribe key file holds it."""
    return hashlib.sha256(der_bytes).hexdigest()


def fingerprint_of_file(path):
    return fingerprint(ssl.PEM_cert_to_DER_cert(Path(path).read_text(encoding="ascii")))


def team_key(config, directory=None):
    """The contents of the tribe key file: where the server is, how to recognize it, and the tribe secret."""
    directory = Path(directory or server_dir())
    return {"format": KEY_FILE_FORMAT, "server_id": config["server_id"], "hosts": host_names(),
            "port": config["port"], "fingerprint": fingerprint_of_file(directory / "cert.pem"),
            "secret": config["team_secret"]}


def write_team_key(path, config, directory=None):
    Path(path).write_text(json.dumps(team_key(config, directory), indent=2), encoding="utf-8")


def change_team_secret(directory=None):
    """A new tribe secret: every laptop is locked out until it gets the new tribe key file."""
    config = load_config(directory)
    config["team_secret"] = secrets.token_urlsafe(32)
    save_config(config, directory)
    return config


# --------------------------------------------------------------------- Handling requests

class RequestError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _clean(text, limit=64):
    return "".join(character for character in str(text or "") if character.isprintable())[:limit].strip()


class IpamServer:
    """The server: its database and the HTTPS listener. serve() runs until stop()."""

    def __init__(self, directory=None, host="", port=None):
        self.directory = Path(directory or server_dir())
        self.config = set_up(self.directory, DEFAULT_PORT if port is None else port)
        self.port = self.config["port"] if port is None else port
        self.store = IpamStore(str(self.directory / "ipam.db"), user="server", shared=True)
        self.stop_event = threading.Event()
        self.changed = threading.Condition()  # Notified after every change, to answer waiting laptops
        self.latest = self.store.revision()
        self.latest_sightings = self.store.sighting_seq()  # Sweeps' news, which laptops also wait for
        self.maps = MapStore(self.directory / "maps.db", *_map_secret_protection())
        self.latest_maps = self.maps.revision()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.directory / "cert.pem", self.directory / "key.pem")
        handler = type("Handler", (_Handler,), {"server_app": self})
        try:
            self.httpd = http.server.ThreadingHTTPServer((host, self.port), handler)
        except OSError as error:
            self.store.close()
            self.maps.close()
            raise OSError(f"Couldn't listen on port {self.port}: {error.strerror or error}. Another program may be "
                          f"using it (see which with: netstat -ano | findstr :{self.port}).") from error
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]  # The actual port, when asked for any free one (0)
        self.httpd.socket = context.wrap_socket(self.httpd.socket, server_side=True)
        self.backup_thread = threading.Thread(target=self._backups, name="IPAM backups", daemon=True)
        self.backup_lock = threading.Lock()  # One backup at a time (the nightly one and any asked for)

    @property
    def address(self):
        return self.httpd.server_address

    def serve(self):
        log.info("NOMAD %s IPAM server listening on port %s (server %s)", __version__, self.port,
                 self.config["server_id"])
        self.backup_thread.start()
        try:
            self.httpd.serve_forever(poll_interval=0.5)
        finally:
            self.httpd.server_close()
            with self.store.lock:
                self.store.close()
            with self.maps.lock:
                self.maps.close()
            log.info("IPAM server stopped")

    def stop(self):
        self.stop_event.set()
        with self.changed:
            self.changed.notify_all()  # Let waiting requests finish
        self.httpd.shutdown()

    def announce(self, revision=None, sightings=None, maps=None):
        """Tell every waiting laptop there's a new revision (or new sightings, or a map changed)."""
        with self.changed:
            if revision is not None:
                self.latest = max(self.latest, revision)
            if sightings is not None:
                self.latest_sightings = max(self.latest_sightings, sightings)
            if maps is not None:
                self.latest_maps = max(self.latest_maps, maps)
            self.changed.notify_all()

    def wait(self, since, timeout, sightings_since=None, maps_since=None):
        """Block until there's a revision after `since` (or sightings after `sightings_since`, or a map revision
        after `maps_since`, when given), the timeout passes, or the server stops."""
        timeout = max(0.0, min(float(timeout), MAX_WAIT_SECONDS))
        with self.changed:
            self.changed.wait_for(lambda: self.latest > since or self.stop_event.is_set() or
                                  (sightings_since is not None and self.latest_sightings > sightings_since) or
                                  (maps_since is not None and self.latest_maps > maps_since), timeout)
            return {"revision": self.latest, "sightings": self.latest_sightings, "maps": self.latest_maps}

    # ----------------------------------------------------------------- Requests

    def role_for(self, authorization, client_address):
        secret = authorization[7:].strip() if authorization.startswith("Bearer ") else ""
        if secret and hmac.compare_digest(secret, self.config["admin_secret"]):
            if not ipaddress.ip_address(client_address).is_loopback:
                raise RequestError(403, "The admin key only works on the server itself.")
            return ADMIN
        if secret and hmac.compare_digest(secret, self.config["team_secret"]):
            return TEAM
        raise RequestError(401, "This tribe key isn't accepted. The tribe key may have been changed: ask for the "
                                "new tribe key file.")

    def moved_reply(self):
        """What a moved server answers every request with: where the tribe server is now (see migrate.py)."""
        moved = self.config["moved"]
        where = ", ".join(moved.get("hosts") or [])
        return {"error": f"The tribe server has moved to another computer{f' ({where})' if where else ''}."
                         + ("" if where else " Ask for the new tribe key file."),
                "moved": True, "hosts": moved.get("hosts") or [], "port": moved.get("port") or self.port}

    def status(self, role):
        with self.store.lock:
            revision = self.store.revision()
        return {"server_id": self.config["server_id"], "name": socket.gethostname(), "version": __version__,
                "api": API_LEVEL, "revision": revision, "sightings": self.latest_sightings, "maps": self.latest_maps,
                "role": role}

    def sightings(self, since):
        with self.store.lock:
            payload, seq, more = self.store.sightings_since(since)
        return dict(payload, seq=seq, more=more)

    def record_sightings(self, user, request):
        """A laptop's sweep results: kept (newest wins) and passed on to every laptop, but not in the history."""
        network_id = request["network_id"]
        # Who swept is who sent them, whatever the request says
        hosts = [{name: value for name, value in host.items() if name != "seen_by"} for host in request.get("hosts", [])]
        ranges = [{name: value for name, value in swept.items() if name != "swept_by"}
                  for swept in request.get("ranges", [])]
        with self.store.lock:
            self.store.network(network_id)  # Raises if it was deleted
            self.store.record_sightings(network_id, hosts, ranges, by=user)
            seq = self.store.sighting_seq()
        self.announce(sightings=seq)
        return {"seq": seq}

    def log(self, since):
        with self.store.lock:
            entries, revision, more = self.store.log_since(since)
        return {"entries": entries, "revision": revision, "more": more}

    def changes(self, since):
        with self.store.lock:
            items, revision, more = self.store.changes_since(since)
        return {"items": items, "revision": revision, "more": more}

    def edit(self, role, user, request):
        action = request.get("action")
        if action in ADMIN_ONLY_ACTIONS and role != ADMIN:
            raise RequestError(403, "Only the server can add or delete tribe networks.")
        method = getattr(self, f"_edit_{action}", None) if isinstance(action, str) else None
        if method is None:
            raise RequestError(400, f"Unknown change {action!r}.")
        with self.store.lock:
            self.store.user = user
            before = self.store.revision()
            with self.store.transaction():
                method(request)
            items, revision, _ = self.store.changes_since(before)
        log.info("%s by %s", action, user)
        self.announce(revision)
        return {"items": items, "revision": revision}

    def import_networks(self, role, user, plans):
        if role != ADMIN:
            raise RequestError(403, "Spreadsheets can only be imported on the server.")
        with self.store.lock:
            self.store.user = user
            before = self.store.revision()
            networks = self.store.import_networks(plans)
            items, revision, _ = self.store.changes_since(before, limit=10 ** 9)
        log.info("Import of %s by %s", ", ".join(network.name for network in networks), user)
        self.announce(revision)
        return {"items": items, "revision": revision, "networks": [network.id for network in networks]}

    # ----------------------------------------------------------------- Tribe maps

    def map_changes(self, since):
        with self.maps.lock:
            payload, revision, more = self.maps.changes_since(since)
            payload["leases"] = self.maps.leases(time.time())
        return dict(payload, revision=revision, more=more)

    def map_request(self, action, user, request):
        """A change to the tribe's maps. Returns the reply; announces the new map revision."""
        with self.maps.lock:
            if action == "create":
                map_id, revision = self.maps.create(request["name"], user, request.get("changes", []),
                                                    request.get("secrets"))
                reply = {"map_id": map_id}
            elif action == "push":
                revision = self.maps.push(request["map_id"], request.get("changes", []), user)
                reply = {}
            elif action == "rename":
                revision = self.maps.rename(request["map_id"], request["name"])
                reply = {}
            elif action == "delete":
                revision = self.maps.delete(request["map_id"])
                reply = {}
            elif action == "secrets":
                revision = self.maps.set_secrets(request["map_id"], request.get("secrets") or {})
                reply = {}
            elif action == "lease":
                computer = user.rpartition("(")[2].rstrip(")") if "(" in user else user
                lease = self.maps.lease(request["map_id"], _clean(request["holder"], 128), computer,
                                        _clean(request.get("kind", "gui")), time.time(),
                                        release=bool(request.get("release")), take=bool(request.get("take")))
                return {"lease": lease}  # Not a change anyone waits for
            else:
                raise RequestError(404, "No such request.")
        if action != "push" or request.get("changes"):
            log.info("Map %s by %s", action, user)
        self.announce(maps=revision)
        return dict(reply, revision=revision)

    def map_secrets(self, map_id):
        with self.maps.lock:
            return {"secrets": self.maps.secrets(map_id)}

    # ----------------------------------------------------------------- Edits, each checked for conflicts

    def _address_row(self, network_id, ip):
        """The address's current row, or its latest deleted one (to say who freed it), or None."""
        from .store import ip_key, parse_address
        return self.store.db.execute("SELECT * FROM addresses WHERE network_id = ? AND sort_key = ? "
                                     "ORDER BY deleted, version DESC LIMIT 1",
                                     (network_id, ip_key(parse_address(ip)))).fetchone()

    @staticmethod
    def _when(row):
        return f"{row['modified'][:16].replace('T', ' ')} UTC"

    def _check_address(self, request):
        row = self._address_row(request["network_id"], request["ip"])
        expected = request.get("expected_version")
        live = row is not None and not row["deleted"]
        if expected is None and live:
            status = "reserved" if row["status"] == "reserved" else "in use"
            named = f" for {row['name']}" if row["name"] else ""
            raise ConflictError(f"{request['ip']} was just recorded as {status}{named} by {row['modified_by']} "
                                f"({self._when(row)}). Pick another address.")
        if expected is not None and not live:
            who = f" by {row['modified_by']} ({self._when(row)})" if row is not None else ""
            raise ConflictError(f"{request['ip']} was marked free{who} since you last synced.")
        if expected is not None and row["version"] != expected:
            raise ConflictError(f"{request['ip']} was changed by {row['modified_by']} ({self._when(row)}) since you "
                                "last synced. Check it again, then make your change.")

    def _check_version(self, table, item_id, expected, what):
        row = self.store.db.execute(f"SELECT * FROM {table} WHERE id = ?", (item_id,)).fetchone()
        if row is None:
            raise IpamError(f"That {what} doesn't exist on the server.")
        if row["deleted"]:
            raise ConflictError(f"That {what} was deleted by {row['modified_by']} ({self._when(row)}).")
        if expected is not None and row["version"] != expected:
            raise ConflictError(f"That {what} was changed by {row['modified_by']} ({self._when(row)}) since you last "
                                "synced. Check it again, then make your change.")

    def _edit_set_address(self, request):
        self._check_address(request)
        self.store.set_address(request["network_id"], request["ip"], request.get("status", "used"),
                               request.get("name", ""), request.get("mac", ""), request.get("description", ""),
                               request.get("fields"))

    def _edit_free_address(self, request):
        self._check_address(dict(request, expected_version=request.get("expected_version", -1)))
        self.store.free_address(request["network_id"], request["ip"])

    def _edit_add_subnet(self, request):
        self.store.add_subnet(request["network_id"], request["cidr"], request.get("name", ""),
                              request.get("gateway", ""), request.get("description", ""), request.get("fields"),
                              bool(request.get("loopbacks")))

    def _edit_update_subnet(self, request):
        self._check_version("subnets", request["subnet_id"], request.get("expected_version"), "subnet")
        self.store.update_subnet(request["subnet_id"], **request["changes"])

    def _edit_delete_subnet(self, request):
        self._check_version("subnets", request["subnet_id"], request.get("expected_version"), "subnet")
        self.store.delete_subnet(request["subnet_id"], with_addresses=bool(request.get("with_addresses")))

    def _edit_move_subnet(self, request):
        from .network_move import move
        link = request.get("link")
        move(self.store, request["network_id"], request["cidr"], request["to_network_id"],
             bool(request.get("take_nested", True)), tuple(link) if link else None)

    def _edit_take_subnets(self, request):
        from .network_move import receive
        link = request.get("link")
        receive(self.store, request["to_network_id"], request["data"], tuple(link) if link else None)

    def _edit_add_network(self, request):
        self.store.add_network(request["name"], request.get("description", ""), request.get("fields"))

    def _edit_update_network(self, request):
        self._check_version("networks", request["network_id"], request.get("expected_version"), "network")
        self.store.update_network(request["network_id"], **request["changes"])

    def _edit_delete_network(self, request):
        self._check_version("networks", request["network_id"], request.get("expected_version"), "network")
        self.store.delete_network(request["network_id"])

    # ----------------------------------------------------------------- VLANs

    def _vlan_row(self, domain_id, number):
        """The VLAN's current row, or its latest deleted one (to say who deleted it), or None."""
        from .store import vlan_key
        return self.store.db.execute("SELECT * FROM vlans WHERE domain_id = ? AND sort_key = ? "
                                     "ORDER BY deleted, version DESC LIMIT 1",
                                     (domain_id, vlan_key(check_number(number)))).fetchone()

    def _check_vlan(self, request):
        """Like _check_address: a VLAN recorded since the client last synced, or changed or deleted, is a
        conflict."""
        number = check_number(request["vlan"])
        row = self._vlan_row(request["domain_id"], number)
        expected = request.get("expected_version")
        live = row is not None and not row["deleted"]
        if expected is None and live:
            named = f" ({row['name']})" if row["name"] else ""
            raise ConflictError(f"VLAN {number}{named} was just recorded by {row['modified_by']} ({self._when(row)}). "
                                "Pick another number.")
        if expected is not None and not live:
            who = f" by {row['modified_by']} ({self._when(row)})" if row is not None else ""
            raise ConflictError(f"VLAN {number} was deleted{who} since you last synced.")
        if expected is not None and row["version"] != expected:
            raise ConflictError(f"VLAN {number} was changed by {row['modified_by']} ({self._when(row)}) since you "
                                "last synced. Check it again, then make your change.")

    @staticmethod
    def _vlan_values(request):
        return dict(name=request.get("name", ""), status=request.get("status", "active"),
                    subnets=request.get("subnets") or [], description=request.get("description", ""),
                    fields=request.get("fields"))

    def _edit_add_vlan_domain(self, request):
        VlanStore(self.store).add_domain(request["name"], request.get("network_id", ""),
                                         request.get("vtp_domain", ""), request.get("description", ""),
                                         request.get("ranges"), request.get("fields"))

    def _edit_update_vlan_domain(self, request):
        self._check_version("vlan_domains", request["domain_id"], request.get("expected_version"), "VLAN domain")
        VlanStore(self.store).update_domain(request["domain_id"], **request["changes"])

    def _edit_delete_vlan_domain(self, request):
        self._check_version("vlan_domains", request["domain_id"], request.get("expected_version"), "VLAN domain")
        VlanStore(self.store).delete_domain(request["domain_id"])

    def _edit_set_vlan(self, request):
        self._check_vlan(request)
        VlanStore(self.store).set_vlan(request["domain_id"], request["vlan"], **self._vlan_values(request))

    def _edit_delete_vlan(self, request):
        self._check_vlan(dict(request, expected_version=request.get("expected_version", -1)))
        VlanStore(self.store).delete_vlan(request["domain_id"], request["vlan"])

    def _edit_set_vlans(self, request):
        """Several VLANs in one domain at once (bringing in a network map's): all, or none if any conflicts."""
        vlans = VlanStore(self.store)
        for item in request["vlans"]:
            self._check_vlan(dict(item, domain_id=request["domain_id"]))
            vlans.set_vlan(request["domain_id"], item["vlan"], **self._vlan_values(item))

    # ----------------------------------------------------------------- Subnet placement

    def _edit_set_placement(self, request):
        current = PlacementStore(self.store).placement(request["network_id"], request["cidr"])
        expected = request.get("expected_version")
        if current is not None and expected is not None and current.version != expected or \
                current is not None and expected is None:
            raise ConflictError(f"How {request['cidr']} is treated was changed by {current.modified_by} since you last "
                                "synced. Check it again, then make your change.")
        PlacementStore(self.store).set_placement(request["network_id"], request["cidr"], request.get("scope", "auto"),
                                                 bool(request.get("one_segment")), request.get("note", ""))

    def _edit_set_role(self, request):
        current = PlacementStore(self.store).role(request["network_id"], request["cidr"])
        expected = request.get("expected_version")
        if current is not None and expected is not None and current.version != expected or                 current is not None and expected is None:
            raise ConflictError(f"What {request['cidr']} is for was changed by {current.modified_by} since you last "
                                "synced. Check it again, then make your change.")
        PlacementStore(self.store).set_role(request["network_id"], request["cidr"], request.get("role", "auto"))

    def _edit_plan_move(self, request):
        PlacementStore(self.store).plan_move(request["network_id"], request["cidr"],
                                             **{name: request.get(name, default) for name, default in
                                                (("from_domain_id", ""), ("from_vlan", 0), ("from_device", ""),
                                                 ("to_domain_id", ""), ("to_vlan", 0), ("to_device", ""),
                                                 ("planned_for", ""), ("note", ""))})

    def _edit_update_move(self, request):
        self._check_version("subnet_moves", request["move_id"], request.get("expected_version"), "move")
        PlacementStore(self.store).update_move(request["move_id"], **request["changes"])

    def _edit_complete_move(self, request):
        self._check_version("subnet_moves", request["move_id"], request.get("expected_version"), "move")
        PlacementStore(self.store).complete_move(request["move_id"])

    # ----------------------------------------------------------------- Backups

    def backup_now(self):
        """Copy the database to the backup folder (one file a day), and remove backups past the keep limit."""
        with self.backup_lock:
            return self._backup()

    def _backup(self):
        folder = Path(self.config.get("backup_dir") or self.directory / "backups")
        folder.mkdir(parents=True, exist_ok=True)
        target = folder / f"ipam-{datetime.date.today().isoformat()}.db"
        temporary = target.with_name(f"{target.stem}.{uuid.uuid4().hex[:8]}.tmp")
        with self.store.lock:
            destination = sqlite3.connect(temporary)
            try:
                self.store.db.backup(destination)
            finally:
                destination.close()
        os.replace(temporary, target)
        maps_target = folder / f"maps-{datetime.date.today().isoformat()}.db"
        maps_temporary = maps_target.with_name(f"{maps_target.stem}.{uuid.uuid4().hex[:8]}.tmp")
        with self.maps.lock:
            self.maps.backup(maps_temporary)
        os.replace(maps_temporary, maps_target)
        keep = datetime.timedelta(days=int(self.config.get("backup_keep_days", BACKUP_KEEP_DAYS)))
        for old in list(folder.glob("ipam-*.db")) + list(folder.glob("maps-*.db")):
            try:
                day = datetime.date.fromisoformat(old.stem.partition("-")[2])
            except ValueError:
                continue
            if datetime.date.today() - day > keep:
                old.unlink(missing_ok=True)
        log.info("Backed up the IPAM database to %s", target)
        return target

    def _backups(self):
        while not self.stop_event.is_set():
            folder = Path(self.config.get("backup_dir") or self.directory / "backups")
            if not (folder / f"ipam-{datetime.date.today().isoformat()}.db").exists():
                try:
                    self.backup_now()
                except (OSError, sqlite3.Error) as error:
                    log.error("Backup failed: %s", error)
            self.stop_event.wait(BACKUP_CHECK_SECONDS)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_app = None  # Set per server by IpamServer
    server_version = "NOMAD-IPAM"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        log.debug("%s %s", self.client_address[0], format % args)

    def _reply(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _user(self):
        user = _clean(self.headers.get("X-NOMAD-User")) or "unknown"
        computer = _clean(self.headers.get("X-NOMAD-Computer"))
        return f"{user} ({computer})" if computer else user

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_REQUEST_BYTES:
            raise RequestError(413, "That request is too large.")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            raise RequestError(400, "The request isn't valid JSON.") from None

    def _handle(self, method):
        app = self.server_app
        try:
            role = app.role_for(self.headers.get("Authorization", ""), self.client_address[0])
            if app.config.get("moved"):
                return self._reply(410, app.moved_reply())
            url = urlparse(self.path)
            if method == "GET" and url.path == "/api/status":
                return self._reply(200, app.status(role))
            if method == "GET" and url.path == "/api/wait":
                query = parse_qs(url.query)
                sightings_since, maps_since = query.get("sightings_since"), query.get("maps_since")
                return self._reply(200, app.wait(int(query.get("since", ["0"])[0]),
                                                 float(query.get("timeout", ["25"])[0]),
                                                 int(sightings_since[0]) if sightings_since else None,
                                                 int(maps_since[0]) if maps_since else None))
            if method == "GET" and url.path == "/api/maps/changes":
                return self._reply(200, app.map_changes(int(parse_qs(url.query).get("since", ["0"])[0])))
            if method == "GET" and url.path == "/api/maps/secrets":
                return self._reply(200, app.map_secrets(int(parse_qs(url.query)["map_id"][0])))
            if method == "POST" and url.path.startswith("/api/maps/"):
                return self._reply(200, app.map_request(url.path[len("/api/maps/"):], self._user(), self._body()))
            if method == "GET" and url.path == "/api/sightings":
                return self._reply(200, app.sightings(int(parse_qs(url.query).get("since", ["0"])[0])))
            if method == "POST" and url.path == "/api/sightings":
                return self._reply(200, app.record_sightings(self._user(), self._body()))
            if method == "GET" and url.path == "/api/log":
                return self._reply(200, app.log(int(parse_qs(url.query).get("since", ["0"])[0])))
            if method == "GET" and url.path == "/api/changes":
                since = int(parse_qs(url.query).get("since", ["0"])[0])
                return self._reply(200, app.changes(since))
            if method == "POST" and url.path == "/api/edit":
                return self._reply(200, app.edit(role, self._user(), self._body()))
            if method == "POST" and url.path == "/api/import":
                return self._reply(200, app.import_networks(role, self._user(), self._body().get("plans", [])))
            raise RequestError(404, "No such request.")
        except RequestError as error:
            self._reply(error.status, {"error": str(error)})
        except ConflictError as error:
            self._reply(409, {"error": str(error), "conflict": True})
        except MapError as error:
            self._reply(422, {"error": str(error)})
        except IpamError as error:
            self._reply(422, {"error": str(error)})
        except (KeyError, TypeError, ValueError) as error:
            self._reply(400, {"error": f"The request is missing something or malformed ({error})."})
        except Exception:  # Report it to the client rather than dropping the connection
            log.exception("Request failed: %s %s", method, self.path)
            self._reply(500, {"error": "The server had a problem with that request; details are in its log."})

    def do_GET(self):
        self._handle("GET")

    def do_POST(self):
        self._handle("POST")


def _map_secret_protection():
    """How the server keeps maps' community strings: DPAPI for this computer, so the service can read them."""
    if sys.platform != "win32":
        return None, None
    from ..terminal.credentials import protect, unprotect
    return (lambda text: protect(text, machine=True)), unprotect


def log_to_file(directory=None):
    """Send the server's log to server.log in its folder (a few rotated files)."""
    directory = Path(directory or server_dir())
    directory.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(directory / "server.log", maxBytes=2_000_000, backupCount=3,
                                                   encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.INFO)


def run_in_foreground(directory=None, port=None):
    """Run the server in this console until Ctrl+C (NOMAD.exe --ipam-server), for trying it out or troubleshooting."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s")
    log_to_file(directory)
    server = IpamServer(directory, port=port)
    if sys.stdout is not None:  # The packaged exe has no console
        print(f"NOMAD IPAM server on port {server.port}; press Ctrl+C to stop.")
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    try:
        while thread.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        server.stop()
        thread.join(10)
