import threading

import pytest

from nomad.configs import archive, checks, local, runner, scope, tribe
from nomad.configs.archive import ArchiveError, ConfigStore
from nomad.ipam.client import OldServerError, TeamClient, TeamKey
from nomad.ipam.server import IpamServer, load_config, team_key
from nomad.netmap import model, shared

DAY = 24 * 3600
CONFIG = "hostname R1\n!\ninterface Gi0/1\n description A\n!\nntp server 10.0.0.1\n"
STANDARD = "! STANDARD: NTP\n! applies-to: kind=router\nntp server 10.0.0.1\nntp server 10.0.0.2\n"


def rows(*ids, kind="router"):
    return [{"id": item, "name": item.upper(), "address": item, "names": [], "platform": "ios", "kind": kind,
             "facts": {"hostname": item.upper(), "kind": kind}} for item in ids]


@pytest.fixture
def store(tmp_path):
    store = ConfigStore(tmp_path / "configs.db")
    yield store
    store.close()


# ----------------------------------------------------------------- Versions

def test_upload_keeps_changes_only(store):
    first = store.upload("10.0.0.1", "running", CONFIG, "alice", now=100)
    assert first["stored"] and first["first"]
    same = store.upload("10.0.0.1", "running", "Building configuration...\n" + CONFIG, "bob", now=200)
    assert not same["stored"] and same["version_id"] == first["version_id"]
    changed = store.upload("10.0.0.1", "running", CONFIG.replace("description A", "description B"), "bob",
                           changed_by="carol", now=300)
    assert changed["stored"] and not changed["first"]
    history = store.history("10.0.0.1")
    assert [item["id"] for item in history] == [changed["version_id"], first["version_id"]]
    latest = store.latest("10.0.0.1")
    assert latest["previous_id"] == first["version_id"] and (latest["added"], latest["removed"]) == (1, 1)
    assert latest["changed_by"] == "carol" and "description B" in latest["text"]
    assert store.device("10.0.0.1")["last_checked"] == 300
    with pytest.raises(ArchiveError):
        store.upload("10.0.0.1", "running", "  ", "x")


def test_review_clears_unreviewed(store):
    store.upload("d", "running", CONFIG, "a", now=1)
    version = store.upload("d", "running", CONFIG + "logging host 1.1.1.1\n", "a", now=2)
    assert store.unreviewed() == {"d": 1}
    assert [item["id"] for item in store.recent()] == [version["version_id"]]
    store.review(version["version_id"], "bob")
    assert store.unreviewed() == {}
    assert store.version(version["version_id"])["reviewed_by"] == "bob"


def test_startup_kept_apart_from_running(store):
    store.upload("d", "running", CONFIG, "a", now=1)
    store.upload("d", "startup", CONFIG.replace("A", "Z"), "a", now=1)
    assert "description Z" in store.latest("d", "startup")["text"]
    assert "description A" in store.latest("d", "running")["text"]


# ----------------------------------------------------------------- The queue

def test_scope_spreads_and_claims(store):
    assert store.sync_devices(rows("a", "b", "c"), now=0) == {"a", "b", "c"}
    assert store.sync_devices(rows("a", "b", "c"), now=0) == set()
    due = sorted(device["next_due"] for device in store.devices())
    assert all(0 <= value < DAY for value in due)
    assert store.claim("pc1", "PC1", now=0) == []  # Nothing due yet
    claimed = store.claim("pc1", "PC1", limit=2, now=DAY)
    assert len(claimed) == 2
    other = store.claim("pc2", "PC2", limit=5, now=DAY)
    assert {item["id"] for item in other}.isdisjoint({item["id"] for item in claimed})
    assert len(claimed) + len(other) == 3
    assert store.claim("pc3", "PC3", now=DAY + archive.CLAIM_SECONDS + 1) != []  # Claims run out


def test_failure_hands_device_to_another_computer(store):
    store.sync_devices(rows("a"), now=0)
    [device] = store.claim("pc1", "PC1", now=DAY)
    store.report_failure(device["id"], "PC1", "No route to host", now=DAY)
    assert store.claim("pc1", "PC1", now=DAY + 1) == []  # Not back to the one that failed
    assert [item["id"] for item in store.claim("pc2", "PC2", now=DAY + 1)] == ["a"]
    assert store.device("a")["failures"][0]["reason"] == "No route to host"
    store.upload("a", "running", CONFIG, "PC2", archive.SCHEDULED, now=DAY + 2)
    assert store.device("a")["failures"] == []
    assert store.device("a")["next_due"] > DAY + 2


def test_service_goes_first(store):
    store.sync_devices(rows("a", "b"), now=0)
    with store.db:
        store.db.execute("UPDATE devices SET next_due = ?", (DAY,))
    assert store.claim("svc", "SERVER", archive.SERVICE, limit=1, now=DAY) != []
    assert store.claim("pc", "PC", archive.GUI, now=DAY + 10) == []  # Only devices well overdue for a window
    assert store.claim("pc", "PC", archive.GUI, now=DAY + archive.SERVICE_SEEN_SECONDS + 1) != []


def test_overdue_and_excluded(store):
    store.sync_devices(rows("a", "b"), now=0)
    assert store.overdue(now=DAY) == []
    assert {item["id"] for item in store.overdue(now=3 * DAY)} == {"a", "b"}
    store.set_excluded("b", True)
    assert {item["id"] for item in store.overdue(now=3 * DAY)} == {"a"}
    assert [item["id"] for item in store.claim("pc", "PC", limit=5, now=3 * DAY)] == ["a"]


def test_devices_leave_scope_but_keep_copies(store):
    store.sync_devices(rows("a", "b"), now=0)
    store.upload("b", "running", CONFIG, "x", now=1)
    assert store.sync_devices(rows("a"), now=2) == {"b"}
    assert not store.device("b")["in_scope"] and store.latest("b") is not None


def test_interval_setting(store):
    store.set_settings({"interval_hours": 4})
    assert store.interval() == 4 * 3600
    with pytest.raises(ArchiveError):
        store.set_settings({"interval_hours": 0})


# ----------------------------------------------------------------- Standards, locally

def test_local_upload_checks_standards(tmp_path):
    configs = local.LocalConfigs(tmp_path / "local.db")
    configs.set_scope(rows("r1"))
    configs.save_standard("NTP", STANDARD, "alice")
    configs.upload("r1", "running", CONFIG, "alice")
    [row] = configs.store.compliance("r1")
    assert (row["standard"], row["failed"], row["total"]) == ("NTP", 1, 2)
    assert configs.store.failing() == {"r1": 1}
    configs.upload("r1", "running", CONFIG + "ntp server 10.0.0.2\n", "alice")
    assert configs.store.failing() == {}
    configs.set_scope(rows("r1", kind="switch"))  # No longer a router: the standard doesn't apply
    assert configs.store.compliance("r1") == []
    configs.close()


def test_results_round_trip():
    from nomad.configs import standards
    results = standards.check(standards.parse(STANDARD), CONFIG, {})
    again = checks.results_from(checks.result_dicts(results))
    assert [(item.status, item.rule, item.fix) for item in again] == [(item.status, item.rule, item.fix)
                                                                     for item in results]


# ----------------------------------------------------------------- The runner

class Shell:
    def __init__(self, config):
        self.config = config

    def run(self, command, timeout=30):
        return self.config if command == "show running-config" else "% Invalid input"


class Pusher:
    def __init__(self, configs):
        self.configs = configs
        self.problems, self.login_labels = {}, {}
        self.closed = False

    def shell(self, address, names=()):
        if address not in self.configs:
            self.problems[address] = "Connection timed out."
            return None
        return Shell(self.configs[address])

    def forget(self, address):
        pass

    def close(self):
        self.closed = True


def test_runner_backs_up_and_reports(tmp_path):
    clock = [DAY]
    configs = local.LocalConfigs(tmp_path / "local.db")
    configs.set_scope(rows("a", "b"), now=0)
    pushers = []

    def make_pusher():
        pushers.append(Pusher({"a": CONFIG}))
        return pushers[-1]

    backups = runner.BackupRunner(configs, make_pusher, "pc", "PC", "alice", clock=lambda: clock[0])
    done = backups.step()
    assert sorted((item.device_id, item.ok) for item in done) == [("a", True), ("b", False)]
    assert pushers[0].closed
    assert configs.store.latest("a")["source"] == archive.SCHEDULED
    assert "timed out" in configs.store.device("b")["failures"][0]["reason"]
    assert backups.step() == []  # a isn't due again yet; b was this computer's failure
    configs.close()


# ----------------------------------------------------------------- Scope from maps

def test_scope_rows_from_a_map():
    network_map = model.NetworkMap()
    network_map.devices["r"] = model.Device("r", name="R1", mgmt_ip="10.0.0.1", kind=model.ROUTER,
                                            addresses=["10.0.0.1", "10.9.9.9"])
    network_map.devices["h"] = model.Device("h", name="PC", mgmt_ip="10.0.0.50", kind=model.HOST)
    network_map.devices["s"] = model.Device("s", name="SW-nowhere", kind=model.SWITCH)
    found = scope.rows_for_map(network_map)
    assert list(found) == ["10.0.0.1"]
    assert found["10.0.0.1"]["names"] == ["R1", "10.9.9.9"]
    assert found["10.0.0.1"]["facts"]["kind"] == model.ROUTER


# ----------------------------------------------------------------- The Tribe server

@pytest.fixture
def server(tmp_path):
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def team(server, tmp_path, computer):
    config = load_config(server.directory)
    key = TeamKey.from_dict(dict(team_key(config, server.directory), hosts=["127.0.0.1"], port=server.port))
    client = TeamClient(key, user="alice", computer=computer)
    return tribe.TribeConfigs(key.server_id, client, tmp_path / f"{computer}.db"), client


def share_map(server):
    network_map = model.NetworkMap()
    network_map.devices["r"] = model.Device("r", name="R1", mgmt_ip="10.0.0.1", kind=model.ROUTER)
    network_map.devices["s"] = model.Device("s", name="SW1", mgmt_ip="10.0.0.2", kind=model.SWITCH)
    items = [{"section": section, "key": key, "data": data} for (section, key), data in shared.flatten(network_map).items()]
    with server.maps.lock:
        server.maps.create("Campus", "alice", items)


def test_server_archive_round_trip(server, tmp_path):
    share_map(server)
    laptop, client = team(server, tmp_path, "PC1")
    other, _ = team(server, tmp_path, "PC2")
    laptop.sync()
    assert {device["id"] for device in laptop.store.devices()} == {"10.0.0.1", "10.0.0.2"}
    laptop.save_standard("NTP", STANDARD, "alice")
    first = laptop.upload("10.0.0.1", "running", CONFIG, "alice", archive.MANUAL, "", "R1", "10.0.0.1", "ios")
    assert first["stored"] and first["first"]
    second = laptop.upload("10.0.0.1", "running", CONFIG + "ntp server 10.0.0.2\n", "alice", changed_by="bob")
    other.sync()
    [change] = other.store.recent()
    assert change["changed_by"] == "bob" and change["pulled_by"] == "alice (PC1)"
    assert other.text(change["id"]).endswith("ntp server 10.0.0.2\n")
    assert other.store.has_text(change["id"])
    [row] = other.store.compliance("10.0.0.1")
    assert row["failed"] == 0
    other.review(second["version_id"], "")
    laptop.sync()
    assert laptop.store.unreviewed() == {}
    assert client.wait_for_configs(0, timeout=1) >= laptop.store.revision()
    laptop.close()
    other.close()


def test_server_queue_between_two_computers(server, tmp_path):
    share_map(server)
    one, _ = team(server, tmp_path, "PC1")
    two, _ = team(server, tmp_path, "PC2")
    one.set_settings({"interval_hours": 1})
    with server.configs.lock:
        server._refresh_scope()
        server.configs.db.execute("UPDATE devices SET next_due = 0")
        server.configs.db.commit()
    claimed = one.claim("pc1", "PC1", limit=1)
    rest = two.claim("pc2", "PC2", limit=5)
    assert len(claimed) == 1 and len(rest) == 1 and claimed[0]["id"] != rest[0]["id"]
    one.report_failure(claimed[0]["id"], "PC1", "Authentication failed.")
    assert [item["id"] for item in two.claim("pc2", "PC2")] == [claimed[0]["id"]]
    two.sync()
    assert two.store.device(claimed[0]["id"])["failures"][0]["computer"] == "PC1"
    one.close()
    two.close()


def test_uploads_wait_when_server_unreachable(server, tmp_path):
    laptop, client = team(server, tmp_path, "PC1")
    client.key.port = 1  # Nothing listens there
    reply = laptop.upload("10.0.0.9", "running", CONFIG, "alice")
    assert reply["queued"] and laptop.waiting() == 1
    client.key.port = server.port
    laptop.sync()
    assert laptop.waiting() == 0
    assert laptop.store.latest("10.0.0.9", with_text=False) is not None
    laptop.close()


def test_old_server_is_told_apart(tmp_path):
    class OldClient:
        def config_request(self, *args, **kwargs):
            raise OldServerError("old")

        def config_changes(self, since):
            raise OldServerError("old")

    laptop = tribe.TribeConfigs("x", OldClient(), tmp_path / "old.db")
    with pytest.raises(OldServerError):
        laptop.sync()
    assert not laptop.online
    laptop.close()


def test_copy_of_another_tribe_starts_again(tmp_path):
    first = tribe.TribeConfigs("one", None, tmp_path / "copy.db")
    first.store.upload("d", "running", CONFIG, "x")
    first.close()
    again = tribe.TribeConfigs("two", None, tmp_path / "copy.db")
    assert again.store.devices() == []
    again.close()


# ----------------------------------------------------------------- The Map Watcher service's backups

def test_service_config_carries_the_backup_login(tmp_path):
    from nomad.netmap import watch_service
    key = TeamKey.from_dict({"server_id": "s", "hosts": ["127.0.0.1"], "port": 1, "fingerprint": "f" * 64,
                             "secret": "x", "format": 1})
    plain = watch_service.make_config(key, [1], protect=lambda text: f"<{text}>")
    assert "backups" not in plain
    config = watch_service.make_config(key, [1], protect=lambda text: f"<{text}>",
                                       backups={"username": "netops", "password": "pw", "enable": "en",
                                                "label": "credential NetOps"})
    assert config["backups"] == {"username": "netops", "label": "credential NetOps", "password": "<pw>",
                                 "enable": "<en>", "trust_new": True, "credential_id": "", "devices": {},
                                 "logins": {}, "signature": ""}
    made = watch_service.backup_runner(config, client=None, directory=tmp_path, unprotect=lambda text: text[1:-1])
    assert made.kind == archive.SERVICE and made.holder.endswith("-service")
    pusher = made.pusher_factory()
    session, label = pusher.logins.login_for("10.0.0.1")
    assert (session.username, session.saved_password, label) == ("netops", "<pw>", "credential NetOps")
    assert pusher.enable_secret == "en"
    assert watch_service.backup_runner(plain, None, tmp_path) is None
    made.configs.close()


def test_service_backups_use_each_devices_own_login(tmp_path):
    from nomad.netmap import watch_service
    key = TeamKey.from_dict({"server_id": "s", "hosts": ["127.0.0.1"], "port": 1, "fingerprint": "f" * 64,
                             "secret": "x", "format": 1})
    config = watch_service.make_config(key, [1], protect=lambda text: f"<{text}>", backups={
        "username": "netops", "password": "pw", "label": "credential NetOps", "credential_id": "c1",
        "devices": {"10.0.0.5": "c2", "10.0.0.6": "gone"},
        "logins": {"c2": {"username": "branch", "password": "bp", "label": "credential Branch"}}})
    assert config["backups"]["devices"] == {"10.0.0.5": "c2"}  # One whose login wasn't copied uses the usual one
    assert config["backups"]["logins"]["c2"]["password"] == "<bp>"
    made = watch_service.backup_runner(config, client=None, directory=tmp_path, unprotect=lambda text: text[1:-1])
    logins = made.pusher_factory().logins
    session, label = logins.login_for("10.0.0.5", ["BR1"])
    assert (session.username, session.saved_password, session.host, label) == \
        ("branch", "<bp>", "10.0.0.5", "credential Branch")
    assert logins.login_for("10.0.0.6")[1] == "credential NetOps"
    # Updating with the same logins and the master password locked keeps them as they are
    kept = watch_service.make_config(key, [1], protect=lambda text: f"<{text}>",
                                     backups={"keep": config["backups"], "enable": "new", "trust_new": True})
    assert kept["backups"] == dict(config["backups"], enable="<new>")
    made.configs.close()


def test_service_reads_its_logins_again_each_round(tmp_path):
    """NOMAD rewrites the service's logins when they change in the Editor: the next round uses them, no restart."""
    from nomad.netmap import watch_service
    key = TeamKey.from_dict({"server_id": "s", "hosts": ["127.0.0.1"], "port": 1, "fingerprint": "f" * 64,
                             "secret": "x", "format": 1})
    protect = lambda text: f"<{text}>"  # noqa: E731
    config = watch_service.make_config(key, [1], protect=protect, backups={
        "username": "netops", "password": "pw", "label": "credential NetOps"})
    watch_service.save_config(config, tmp_path)
    made = watch_service.backup_runner(config, client=None, directory=tmp_path, unprotect=lambda text: text[1:-1])
    assert made.pusher_factory().logins.login_for("10.0.0.1")[1] == "credential NetOps"
    # Changed to no usual login, with R2's saved session's login and a new enable password
    latest = watch_service.make_config(key, [1], protect=protect, backups={
        "username": "", "password": "", "label": "", "enable": "en2", "devices": {"10.100.2.1": "lab"},
        "logins": {"lab": {"username": "admin", "password": "lp", "label": "credential Lab Admin"}},
        "signature": "s2"})
    watch_service.save_config(latest, tmp_path)
    pusher = made.pusher_factory()
    session, label = pusher.logins.login_for("10.100.2.1", ["R2.home.lab"])
    assert (session.username, session.saved_password, label) == ("admin", "<lp>", "credential Lab Admin")
    assert pusher.logins.login_for("10.0.0.1") == (None, "")
    assert pusher.enable_secret == "en2"
    made.configs.close()
    # A service with only devices' logins (no usual one) still runs backups
    only = watch_service.backup_runner(latest, client=None, directory=tmp_path, unprotect=lambda text: text[1:-1])
    assert only is not None
    only.configs.close()


def test_watch_engine_steps_backups():
    from nomad.netmap import watch_service

    class Maps:
        def sync(self):
            pass

        def lease(self, *args, **kwargs):
            return {"yours": True}

    class Runner:
        steps = 0

        def step(self):
            Runner.steps += 1
            return [runner.Done("d", "R1", True, "changed", 0)]

    clock = [0.0]
    engine = watch_service.WatchEngine(Maps(), [], "pc-service", clock=lambda: clock[0], listen=False,
                                       backups=Runner())
    engine.step()
    engine.step()
    assert Runner.steps == 1  # Not again until BACKUP_SECONDS pass
    clock[0] += watch_service.BACKUP_SECONDS
    engine.step()
    assert Runner.steps == 2


# ----------------------------------------------------------------- Who's backing up, and backing up now

def test_runners_seen_with_status_and_claims(store):
    store.sync_devices(rows("a", "b"), now=0)
    with store.db:
        store.db.execute("UPDATE devices SET next_due = 0")
    store.claim("pc1-gui", "PC1", archive.GUI, limit=1, now=100, status="Nothing due", user="alice (PC1)")
    store.claim("svc", "SERVER", archive.SERVICE, limit=0, now=110, status="Backed up 2 of 2")
    found = store.runners(now=120)
    assert [(item["computer"], item["kind"]) for item in found] == [("SERVER", archive.SERVICE), ("PC1", archive.GUI)]
    pc = found[1]
    assert pc["status"] == "Nothing due" and pc["user"] == "alice (PC1)" and len(pc["working_on"]) == 1
    assert [item["computer"] for item in store.runners(now=110 + archive.RUNNER_SEEN_SECONDS + 1)] == []


def test_make_due_brings_backups_forward(store):
    store.sync_devices(rows("a", "b", "c"), now=0)
    store.set_excluded("c", True)
    store.report_failure("a", "PC1", "timeout", now=1)
    assert store.claim("pc", "PC1", now=2) == []  # Nothing due yet
    assert store.make_due(["a"], now=5) == 1
    assert [item["id"] for item in store.claim("pc", "PC1", now=6)] == ["a"]  # Its failure was forgotten
    assert store.make_due(None, now=10) == 2  # Not the excluded one
    assert store.make_due([], now=10) == 0
    store.upload("b", "running", CONFIG, "x", archive.SCHEDULED, now=20)
    assert store.device("b")["next_due"] == 10 + DAY  # Then its usual interval, from when it was due


def test_runner_status_told_with_next_claim(tmp_path):
    configs = local.LocalConfigs(tmp_path / "local.db")
    configs.set_scope(rows("a"), now=0)
    with configs.store.db:
        configs.store.db.execute("UPDATE devices SET next_due = 0")

    class Shell:
        def run(self, command, timeout=30):
            return CONFIG if command == "show running-config" else "% Invalid"

    class OnePusher(Pusher):
        def shell(self, address, names=()):
            return Shell()

    backups = runner.BackupRunner(configs, lambda: OnePusher({}), "pc", "PC", "alice")
    backups.step()
    assert backups.status.startswith("Backed up 1 of 1")
    backups.step()  # Nothing due: tells the archive how the last round went
    [seen] = configs.runners()
    assert seen["status"].startswith("Backed up 1 of 1") and seen["user"] == "alice"
    configs.close()


def test_server_runners_and_due(server, tmp_path):
    share_map(server)
    laptop, _ = team(server, tmp_path, "PC1")
    laptop.sync()
    assert laptop.claim("pc1-gui", "PC1", status="Starting") == []
    [seen] = laptop.runners()
    assert seen["computer"] == "PC1" and seen["status"] == "Starting" and seen["user"] == "alice (PC1)"
    assert laptop.make_due(["10.0.0.1"]) == 1
    assert [item["id"] for item in laptop.claim("pc1-gui", "PC1")] == ["10.0.0.1"]
    assert laptop.make_due(None) == 2  # Both (the claimed one is due again too)
    laptop.close()


def test_results_kept_for_scheduled_backups_only(store, monkeypatch):
    store.sync_devices(rows("a"), now=0)
    store.upload("a", "running", CONFIG, "Map Watcher service (CORE)", archive.SCHEDULED, now=1)
    store.upload("a", "running", CONFIG, "alice (PC1)", archive.MANUAL, now=2)  # By hand: not a backup
    store.upload("a", "running", CONFIG, "Map Watcher service (CORE)", archive.SCHEDULED, now=3)
    store.upload("a", "running", CONFIG + "logging host 1.1.1.1\n", "alice (PC1)", archive.SCHEDULED, now=4)
    store.report_failure("a", "PC2", "No route to host", now=5, by="bob (PC2)")
    found = [(item["by"], item["device_name"], item["ok"], item["note"]) for item in store.results()]
    assert found == [("bob (PC2)", "A", False, "No route to host"), ("alice (PC1)", "A", True, "changed"),
                     ("Map Watcher service (CORE)", "A", True, "no change"),
                     ("Map Watcher service (CORE)", "A", True, "first copy")]
    monkeypatch.setattr(archive, "RESULTS_KEPT", 2)
    store.report_failure("a", "PC2", "again", now=6)
    assert [item["note"] for item in store.results()] == ["again", "No route to host"]


def test_server_results_from_every_computer(server, tmp_path):
    share_map(server)
    one, _ = team(server, tmp_path, "PC1")
    two, _ = team(server, tmp_path, "PC2")
    one.upload("10.0.0.1", "running", CONFIG, "alice", archive.SCHEDULED)
    two.report_failure("10.0.0.2", "PC2", "Authentication failed.")
    found = [(item["by"], item["ok"], item["note"]) for item in one.results()]
    assert found == [("alice (PC2)", False, "Authentication failed."), ("alice (PC1)", True, "first copy")]
    one.close()
    two.close()


# ----------------------------------------------------------------- A device's old address: folded, merged, forgotten

def mapped(device_id, name, *addresses):
    return {"id": device_id, "name": name, "address": device_id, "names": [name, *addresses], "platform": "ios",
            "kind": "router", "facts": {"hostname": name, "kind": "router"}}


def test_new_address_folds_the_old_row_in(store):
    store.sync_devices([mapped("192.168.5.102", "EVE-PER")], now=0)
    old = store.upload("192.168.5.102", "running", CONFIG, "x", archive.SCHEDULED, now=10)
    store.set_excluded("192.168.5.102", True)
    changed = store.sync_devices([mapped("10.18.0.1", "EVE-PER", "172.18.0.1")], now=20)
    assert changed == {"192.168.5.102", "10.18.0.1"}
    assert [device["id"] for device in store.devices()] == ["10.18.0.1"]
    device = store.device("10.18.0.1")
    assert device["last_ok"] == 10 and device["created"] == 0 and device["in_scope"] and device["excluded"]
    assert [item["id"] for item in store.history("10.18.0.1")] == [old["version_id"]]
    assert [item["device_id"] for item in store.results()] == ["10.18.0.1"]
    # The next copy is compared with the old address's
    assert not store.upload("10.18.0.1", "running", CONFIG, "x", now=30)["stored"]


def test_old_rows_fold_by_name_or_address_only_when_unambiguous(store):
    store.upload("192.168.5.125", "running", CONFIG, "x", name="EVE-PER", now=1)  # Same name
    store.upload("192.168.5.103", "running", CONFIG, "x", name="eve-per.lab", now=2)  # Still one of its addresses
    store.upload("10.0.0.7", "running", CONFIG, "x", name="10.0.0.7", now=3)  # Only an address: left alone
    store.upload("10.0.0.8", "running", CONFIG, "x", name="SW", now=4)  # Two mapped devices called SW
    store.sync_devices([mapped("10.18.0.1", "EVE-PER", "192.168.5.103"), mapped("10.0.0.20", "SW"),
                        mapped("10.0.0.21", "SW")], now=5)
    assert sorted(device["id"] for device in store.devices()) == ["10.0.0.20", "10.0.0.21", "10.0.0.7", "10.0.0.8",
                                                                  "10.18.0.1"]
    assert len(store.history("10.18.0.1")) == 2


def test_merge_and_forget_by_hand(store):
    store.sync_devices(rows("a"), now=0)
    store.upload("old", "running", CONFIG, "x", name="Old name", now=1)
    store.upload("junk", "running", CONFIG, "x", name="Junk", now=2)
    with pytest.raises(ArchiveError, match="still on a map"):
        store.merge_devices(["a"], "old")
    with pytest.raises(ArchiveError, match="still on a map"):
        store.forget_devices(["a"])
    store.merge_devices(["old"], "a")
    assert store.device("old") is None and len(store.history("a")) == 1
    store.forget_devices(["junk"])
    assert store.device("junk") is None and store.history("junk") == []
    # A device made again under an id that went is back
    store.upload("junk", "running", CONFIG, "x", now=3)
    assert store.device("junk") is not None
    assert "junk" not in {item["device_id"] for item in store.changes_since(1)[0]["gone"]}


def test_copy_drops_devices_gone(store, tmp_path):
    copy = ConfigStore(tmp_path / "copy.db")
    store.sync_devices(rows("a"), now=0)
    first = store.upload("old", "running", CONFIG, "x", name="Old", now=1)
    store.upload("junk", "running", CONFIG, "x", now=2)
    copy.absorb(*store.changes_since(0))
    copy.store_text(first["version_id"], CONFIG)
    since = copy.revision()
    store.merge_devices(["old"], "a")
    store.forget_devices(["junk"])
    copy.absorb(*store.changes_since(since))
    assert [device["id"] for device in copy.devices()] == ["a"]
    [version] = copy.history("a")
    assert version["id"] == first["version_id"] and copy.has_text(version["id"])  # The text it had is kept
    assert copy.history("junk") == []
    copy.close()


def test_local_merge_checks_standards_again(tmp_path):
    configs = local.LocalConfigs(tmp_path / "local.db")
    configs.set_scope(rows("r1"))
    configs.save_standard("NTP", STANDARD, "alice")
    configs.upload("old", "running", CONFIG, "alice", name="Old")
    configs.merge_devices(["old"], "r1")
    [row] = configs.store.compliance("r1")
    assert row["failed"] == 1
    configs.close()


def test_server_merge_and_forget(server, tmp_path):
    share_map(server)
    laptop, _ = team(server, tmp_path, "PC1")
    laptop.upload("192.168.5.9", "running", CONFIG, "alice", name="Old R1")
    laptop.upload("192.168.5.10", "running", CONFIG, "alice", name="Junk")
    laptop.sync()
    assert {device["id"] for device in laptop.store.devices()} == {"10.0.0.1", "10.0.0.2", "192.168.5.9",
                                                                  "192.168.5.10"}
    with pytest.raises(Exception, match="still on a map"):
        laptop.forget_devices(["10.0.0.1"])
    laptop.merge_devices(["192.168.5.9"], "10.0.0.1")
    laptop.forget_devices(["192.168.5.10"])
    laptop.sync()
    assert {device["id"] for device in laptop.store.devices()} == {"10.0.0.1", "10.0.0.2"}
    assert len(laptop.store.history("10.0.0.1")) == 1
    laptop.close()


def test_merging_a_device_already_gone_tells_copies_again(store, tmp_path):
    # A copy that read past the gone notes (a NOMAD from before them) still shows the old row: merging or forgetting
    # it again works, and sends the note once more
    copy = ConfigStore(tmp_path / "copy.db")
    store.sync_devices(rows("a"), now=0)
    store.upload("old", "running", CONFIG, "x", name="Old", now=1)
    store.upload("junk", "running", CONFIG, "x", now=2)
    copy.absorb(*store.changes_since(0))
    store.merge_devices(["old"], "a")
    store.forget_devices(["junk"])
    changes, revision = store.changes_since(copy.revision())
    copy.absorb(dict(changes, gone=[]), revision)  # Missed them
    assert {device["id"] for device in copy.devices()} == {"a", "old", "junk"}
    since = copy.revision()
    store.merge_devices(["old"], "a")
    store.forget_devices(["junk"])
    copy.absorb(*store.changes_since(since))
    assert [device["id"] for device in copy.devices()] == ["a"]
    assert len(store.history("a")) == 1
    with pytest.raises(ArchiveError, match="isn't in the config archive"):
        store.merge_devices(["never"], "a")
    copy.close()


def test_whole_absorb_drops_devices_the_server_doesnt_keep(store, tmp_path):
    copy = ConfigStore(tmp_path / "copy.db")
    store.sync_devices(rows("a"), now=0)
    store.upload("old", "running", CONFIG, "x", name="Old", now=1)
    copy.absorb(*store.changes_since(0))
    store.merge_devices(["old"], "a")
    changes, revision = store.changes_since(copy.revision())
    copy.absorb(dict(changes, gone=[]), revision)
    assert {device["id"] for device in copy.devices()} == {"a", "old"}
    copy.absorb(*store.changes_since(0), whole=True)
    assert [device["id"] for device in copy.devices()] == ["a"]
    assert len(copy.history("a")) == 1
    copy.close()


def test_copy_from_before_gone_notes_reads_everything_again(tmp_path):
    path = tmp_path / "copy.db"
    first = tribe.TribeConfigs("one", None, path)
    with first.lock, first.store.db:
        first.store.set_meta("revision", 42)
        first.store.db.execute("DELETE FROM meta WHERE name = 'copy_format'")  # As an older NOMAD left it
    first.close()
    again = tribe.TribeConfigs("one", None, path)
    assert again.store.revision() == 0 and again.store.meta("copy_format") == tribe.COPY_FORMAT
    with again.lock, again.store.db:
        again.store.set_meta("revision", 42)
    again.close()
    later = tribe.TribeConfigs("one", None, path)
    assert later.store.revision() == 42  # Only once
    later.close()


def test_old_server_cant_merge(tmp_path):
    class OldClient:
        def config_request(self, *args, **kwargs):
            raise OldServerError("old")

    laptop = tribe.TribeConfigs("x", OldClient(), tmp_path / "old.db")
    with pytest.raises(OldServerError, match="update it first"):
        laptop.merge_devices(["a"], "b")
    laptop.close()


def test_moving_device_logins(tmp_path):
    from nomad.configs import logins
    path = str(tmp_path / "logins.json")
    logins.save({"old": "c1", "junk": "c2", "kept": "c3"}, path)
    assert logins.move_devices(["old"], "new", path)
    assert logins.move_devices(["junk"], None, path)
    assert not logins.move_devices(["none"], "new", path)
    assert logins.load(path) == {"new": "c1", "kept": "c3"}
    logins.save({"old": "c1", "new": "c9"}, path)
    logins.move_devices(["old"], "new", path)
    assert logins.load(path) == {"new": "c9"}  # Its own login wins
