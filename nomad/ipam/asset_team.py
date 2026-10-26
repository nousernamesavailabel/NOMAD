"""The tribe's assets on a laptop: read from the copy of the server's data (so they work offline), changed through the
server.

Changes made while the server can't be reached are kept as pending, as VLAN changes are: made in the copy at once,
several changes to one asset becoming one, and sent in order when the server is back (the IP Addresses page's sync
does the sending). Any the server refuses (someone changed that asset first, or recorded its serial number as another
asset) are kept as refused for the user to resolve, and the copy goes back to the server's version.
"""
import json
import uuid

from .assets import DELETE_ASSET, SET_ASSET, AssetStore, clean_values
from .client import OldServerError, ServerUnreachable, TeamKeyError, now_text
from .store import IpamError

PENDING, REFUSED = "pending", "refused"
OLD_SERVER = "The IPAM server is running an older version of NOMAD that doesn't keep assets: it needs updating " \
             "(Tools > Tribe Management > Update Service, on the server)."


class TeamAssetStore:
    """AssetStore's reading methods from the copy, and its changing methods sent to the server (or queued). Use on
    the UI thread, except send_pending, which only talks to the server."""

    def __init__(self, team):
        self.team = team
        self.local = AssetStore(team.copy)

    @property
    def copy(self):
        return self.team.copy

    @property
    def online(self):
        return self.team.online

    def __getattr__(self, name):
        if name in ("assets", "asset", "find", "by_serial", "parts_of", "count", "deleted_serials", "search"):
            return getattr(self.local, name)
        raise AttributeError(name)

    def _require_assets(self):
        if not self.team.server_keeps_assets:
            raise OldServerError(OLD_SERVER)

    def _send(self, action, **arguments):
        self._require_assets()
        try:
            reply = self.team.client.edit(action, **arguments)
        except ServerUnreachable as error:
            self.team.online, self.team.last_error = False, str(error)
            raise
        self.team.online = True
        self.copy.apply_rows(reply["items"])
        return reply

    def _direct(self):
        """Whether a change can go straight to the server: it's reachable and nothing is waiting to go first."""
        return self.online and not self.pending_count()

    def set_asset(self, asset_id=None, **values):
        values = clean_values(values)
        asset_id = asset_id or uuid.uuid4().hex  # Made here, so a change made offline keeps its id on the server
        if self._direct():
            current = self.local.find(asset_id)
            try:
                self._send(SET_ASSET, asset_id=asset_id, values=values,
                           expected_version=current.version if current else None)
                return self.local.asset(asset_id)
            except ServerUnreachable:
                pass  # Lost the server just now: keep the change for later
        self._queue(asset_id, SET_ASSET, values)
        return self.local.asset(asset_id)

    def set_assets(self, items):
        """Record several ([{"id" (or None), **values}]): in one request when the server can be reached (all or none),
        otherwise each queued."""
        items = [dict(clean_values({name: value for name, value in item.items() if name not in ("id",)}),
                      id=item.get("id") or uuid.uuid4().hex) for item in items]
        if self._direct():
            sent = []
            for item in items:
                current = self.local.find(item["id"])
                sent.append({"asset_id": item["id"], "expected_version": current.version if current else None,
                             "values": {name: value for name, value in item.items() if name != "id"}})
            try:
                self._send("set_assets", assets=sent)
                return [self.local.asset(item["id"]) for item in items]
            except ServerUnreachable:
                pass
        for item in items:
            self._queue(item["id"], SET_ASSET, {name: value for name, value in item.items() if name != "id"})
        return [self.local.asset(item["id"]) for item in items]

    def delete_asset(self, asset_id):
        current = self.local.find(asset_id)
        if current is None:
            return
        if self._direct():
            try:
                self._send(DELETE_ASSET, asset_id=asset_id, expected_version=current.version)
                return
            except ServerUnreachable:
                pass
        self._queue(asset_id, DELETE_ASSET, {})

    # ----------------------------------------------------------------- Pending

    def pending_count(self):
        return self.copy.db.execute("SELECT COUNT(*) FROM asset_pending WHERE state = ?", (PENDING,)).fetchone()[0]

    def pending_ids(self):
        rows = self.copy.db.execute("SELECT asset_id FROM asset_pending WHERE state = ?", (PENDING,))
        return {row[0] for row in rows}

    def refused(self):
        """Asset changes made offline that the server refused: [dict] with asset_id, action, data, error."""
        rows = self.copy.db.execute("SELECT * FROM asset_pending WHERE state = ? ORDER BY seq", (REFUSED,)).fetchall()
        return [dict(row, data=json.loads(row["data"])) for row in rows]

    def discard(self, seq):
        with self.copy.transaction():
            self.copy.db.execute("DELETE FROM asset_pending WHERE seq = ?", (seq,))

    def _queue(self, asset_id, action, data):
        """Make a change in the copy now and remember it for the server (merged with any earlier one)."""
        self._require_assets()
        with self.copy.transaction():
            current = self.local.find(asset_id)
            if current is None and action == DELETE_ASSET:
                return
            original = self.copy.row_of("assets", asset_id)["row"] if current else None  # Before it changes
            # Made in the copy first: a change the copy can't take (a serial already recorded) isn't queued
            if action == SET_ASSET:
                self.local.set_asset(asset_id, **data)
            else:
                self.local.delete_asset(asset_id)
            entry = self.copy.db.execute("SELECT * FROM asset_pending WHERE asset_id = ? AND state = ?",
                                         (asset_id, PENDING)).fetchone()
            if entry is None:
                self.copy.db.execute("INSERT INTO asset_pending (asset_id, action, data, expected_version, original, "
                                     "made) VALUES (?, ?, ?, ?, ?, ?)",
                                     (asset_id, action, json.dumps(data), current.version if current else None,
                                      json.dumps(original) if original else None, now_text()))
            elif action == DELETE_ASSET and entry["expected_version"] is None:
                # Recorded offline and deleted again before the server heard about it: nothing to send
                self.copy.db.execute("DELETE FROM asset_pending WHERE seq = ?", (entry["seq"],))
            else:
                merged = dict(json.loads(entry["data"]), **data) if action == SET_ASSET else {}
                self.copy.db.execute("UPDATE asset_pending SET action = ?, data = ?, made = ? WHERE seq = ?",
                                     (action, json.dumps(merged), now_text(), entry["seq"]))

    def outgoing(self):
        """The pending changes to send, oldest first (plain data, for a worker thread). None of them while the
        server is too old to take them: they wait until it's updated."""
        if not self.team.server_keeps_assets:
            return []
        rows = self.copy.db.execute("SELECT * FROM asset_pending WHERE state = ? ORDER BY seq", (PENDING,)).fetchall()
        return [dict(row, data=json.loads(row["data"])) for row in rows]

    def send_pending(self, entries):
        """Send pending changes in order (safe on a worker thread: it only talks to the server). Stops at the first
        that can't reach the server. Returns [(seq, "sent", reply) or (seq, "refused", message)]."""
        results = []
        for entry in entries:
            arguments = dict(asset_id=entry["asset_id"], expected_version=entry["expected_version"])
            if entry["action"] == SET_ASSET:
                arguments["values"] = entry["data"]
            try:
                reply = self.team.client.edit(entry["action"], **arguments)
            except (ServerUnreachable, OldServerError):
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
            entry = self.copy.db.execute("SELECT * FROM asset_pending WHERE seq = ?", (seq,)).fetchone()
            if entry is None:
                continue
            if outcome == "sent":
                self.copy.apply_rows(detail["items"])
                with self.copy.transaction():
                    self.copy.db.execute("DELETE FROM asset_pending WHERE seq = ?", (seq,))
                sent += 1
                continue
            with self.copy.transaction():
                self.copy.db.execute("UPDATE asset_pending SET state = ?, error = ? WHERE seq = ?",
                                     (REFUSED, detail, seq))
                self._restore(entry)
            refused += 1
        if results:
            self.team.online = True
        return sent, refused

    def _restore(self, entry):
        """Put the copy's asset back to the server's latest version (as of the last sync) after a refusal."""
        self.copy.db.execute("UPDATE assets SET deleted = 1 WHERE id = ?", (entry["asset_id"],))
        if entry["original"]:
            self.copy.apply_rows([{"entity": "assets", "row": json.loads(entry["original"])}])

    def flush(self):
        """Send every pending change now (blocking). Returns (sent, refused)."""
        return self.apply_sent(self.send_pending(self.outgoing()))
