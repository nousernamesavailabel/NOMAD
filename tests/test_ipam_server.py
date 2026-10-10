import datetime
import ipaddress
import json
import threading

import pytest

from nomad.ipam.client import ServerUnreachable, TeamClient, TeamKey, TeamKeyError, TeamStore, admin_key, \
    load_saved_key, read_key_file, save_key
from nomad.ipam.server import ADMIN, TEAM, ConflictError, IpamServer, RequestError, change_team_secret, load_config, \
    team_key, write_team_key
from nomad.ipam.store import IpamError, RESERVED, USED


@pytest.fixture
def server(tmp_path):
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def key_for(server, role=TEAM):
    if role == ADMIN:
        key = admin_key(server.directory)
        key.port = server.port
        return key
    config = load_config(server.directory)
    data = dict(team_key(config, server.directory), hosts=["127.0.0.1"], port=server.port)
    return TeamKey.from_dict(data)


def team_store(server, tmp_path, user, role=TEAM):
    key = key_for(server, role)
    store = TeamStore(key, tmp_path / f"{user}.db", TeamClient(key, user=user, computer="PC"))
    store.sync()
    return store


def plan(name="11AB SIPR"):
    return {"name": name, "replace": False, "fields": {"Unit": "11AB"},
            "subnets": [{"cidr": "10.0.0.0/24", "name": "LAN", "gateway": "10.0.0.1", "description": "",
                         "fields": {}}],
            "addresses": [{"ip": "10.0.0.5", "status": USED, "name": "sw1"}]}


def test_import_on_server_then_laptops_sync(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    assert network.fields["Unit"] == "11AB"

    laptop = team_store(server, tmp_path, "alice")
    assert [network.name for network in laptop.networks()] == ["11AB SIPR"]
    [subnet] = laptop.subnets(network.id)
    assert (subnet.cidr, subnet.gateway) == ("10.0.0.0/24", "10.0.0.1")
    assert laptop.address(network.id, "10.0.0.5").name == "sw1"
    assert laptop.online and laptop.last_sync > 0 and laptop.revision > 0

    # Only the server imports and adds or deletes networks
    with pytest.raises(IpamError, match="only be imported on the server"):
        laptop.import_networks([plan("Other")])
    with pytest.raises(IpamError, match="Only the server"):
        laptop.add_network("Other")
    with pytest.raises(IpamError, match="Only the server"):
        laptop.delete_network(network.id)


def test_laptop_edits_reach_everyone_and_record_who(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    alice = team_store(server, tmp_path, "alice")
    bob = team_store(server, tmp_path, "bob")

    address = alice.set_address(network.id, "10.0.0.9", RESERVED, "printer")
    assert address.modified_by == "alice (PC)"
    subnet = alice.subnets(network.id)[0]
    alice.update_subnet(subnet.id, name="LAN renamed")
    added = alice.add_subnet(network.id, "10.0.1.0/24", "New")
    assert alice.subnet(added.id).name == "New"
    loopbacks = alice.add_subnet(network.id, "10.0.2.0/29", "Loopbacks", loopbacks=True)
    assert alice.subnet(loopbacks.id).loopbacks

    bob.sync()
    assert bob.address(network.id, "10.0.0.9").name == "printer"
    assert {subnet.name for subnet in bob.subnets(network.id)} == {"LAN renamed", "New", "Loopbacks"}
    assert [subnet.loopbacks for subnet in bob.subnets(network.id) if subnet.name == "Loopbacks"] == [True]
    alice.delete_subnet(loopbacks.id)

    alice.delete_subnet(added.id)
    alice.free_address(network.id, "10.0.0.9")
    bob.sync()
    assert [subnet.name for subnet in bob.subnets(network.id)] == ["LAN renamed"]
    assert bob.address(network.id, "10.0.0.9") is None

    # Making an imported subnet a loopback subnet later drops its gateway, for everyone
    alice.update_subnet(subnet.id, loopbacks=True)
    bob.sync()
    assert bob.subnet(subnet.id).loopbacks and bob.subnet(subnet.id).gateway == ""
    assert bob.subnet(subnet.id).special_addresses() == {}


def test_conflicts_between_laptops(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    alice = team_store(server, tmp_path, "alice")
    bob = team_store(server, tmp_path, "bob")

    # Both see 10.0.0.20 free; Alice takes it first
    alice.set_address(network.id, "10.0.0.20", USED, "alice-pc")
    with pytest.raises(ConflictError, match=r"10\.0\.0\.20 was just recorded as in use for alice-pc by alice \(PC\)"):
        bob.set_address(network.id, "10.0.0.20", USED, "bob-pc")
    assert bob.address(network.id, "10.0.0.20") is None  # Bob's copy is unchanged until he syncs

    # Bob edits sw1 from an out-of-date copy
    alice.set_address(network.id, "10.0.0.5", USED, "sw1-renamed")
    with pytest.raises(ConflictError, match="was changed by alice"):
        bob.set_address(network.id, "10.0.0.5", USED, "sw1-bob")
    bob.sync()
    bob.set_address(network.id, "10.0.0.5", USED, "sw1-bob")  # Fine once he's seen Alice's change

    alice.free_address(network.id, "10.0.0.20")
    with pytest.raises(ConflictError, match="was marked free by alice"):
        bob.set_address(network.id, "10.0.0.20", RESERVED, "stale edit")

    subnet = alice.subnets(network.id)[0]
    alice.sync()
    alice.update_subnet(subnet.id, description="changed")
    with pytest.raises(ConflictError, match="That subnet was changed by alice"):
        bob.update_subnet(subnet.id, description="mine")


def test_keys_and_certificate_are_checked(server, tmp_path):
    key = key_for(server)
    wrong_fingerprint = TeamKey(key.server_id, key.hosts, key.port, "0" * 64, key.secret)
    with pytest.raises(IpamError, match="isn't the one in the tribe key file"):
        TeamClient(wrong_fingerprint).status()
    wrong_secret = TeamKey(key.server_id, key.hosts, key.port, key.fingerprint, "not-the-secret")
    with pytest.raises(TeamKeyError, match="tribe key"):
        TeamClient(wrong_secret).status()
    rebuilt = TeamKey("another-server", key.hosts, key.port, key.fingerprint, key.secret)
    with pytest.raises(TeamKeyError, match="set up again"):
        TeamClient(rebuilt).fetch_all_changes(0)

    # A new tribe secret locks out the old key file
    server.config = change_team_secret(server.directory)
    with pytest.raises(TeamKeyError):
        TeamClient(key).status()
    assert TeamClient(key_for(server)).status()["role"] == TEAM

    # The admin key only works from the server itself
    with pytest.raises(RequestError, match="only works on the server"):
        server.role_for(f"Bearer {server.config['admin_secret']}", "10.0.0.50")
    assert server.role_for(f"Bearer {server.config['admin_secret']}", "127.0.0.1") == ADMIN


def offline_store(server, tmp_path, user="alice"):
    """A laptop whose copy is `user`.db but which can't reach the server (nothing listens on port 1)."""
    key = key_for(server)
    unreachable = TeamKey(key.server_id, ["127.0.0.1"], 1, key.fingerprint, key.secret)
    return TeamStore(unreachable, tmp_path / f"{user}.db", TeamClient(unreachable, user=user, computer="PC"))


def online_again(server, tmp_path, user="alice"):
    key = key_for(server)
    return TeamStore(key, tmp_path / f"{user}.db", TeamClient(key, user=user, computer="PC"))


def test_offline_changes_wait_then_reach_the_server(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    team_store(server, tmp_path, "alice").close()  # Alice's copy is up to date, then she goes offline

    laptop = offline_store(server, tmp_path)
    assert laptop.address(network.id, "10.0.0.5").name == "sw1"  # Still readable
    laptop.set_address(network.id, "10.0.0.30", USED, "field-laptop")  # Assigned offline
    laptop.set_address(network.id, "10.0.0.5", USED, "sw1-renamed")
    laptop.set_address(network.id, "10.0.0.5", RESERVED, "sw1-final")  # Merged with the change before
    laptop.free_address(network.id, "10.0.0.31")  # Free already: nothing to do
    laptop.set_address(network.id, "10.0.0.32", USED, "temporary")
    laptop.free_address(network.id, "10.0.0.32")  # Recorded and freed offline: nothing to send
    assert laptop.address(network.id, "10.0.0.30").name == "field-laptop"  # Usable straight away
    assert laptop.pending_count() == 2 and laptop.pending_ips(network.id) == {"10.0.0.30", "10.0.0.5"}
    with pytest.raises(ServerUnreachable, match="subnets and networks can't be changed"):
        laptop.add_subnet(network.id, "10.0.9.0/24")  # Only addresses change offline
    laptop.close()

    laptop = online_again(server, tmp_path)  # Pending changes survive a restart
    assert laptop.pending_count() == 2
    assert laptop.flush() == (2, 0)
    assert laptop.pending_count() == 0
    bob = team_store(server, tmp_path, "bob")
    assert bob.address(network.id, "10.0.0.30").name == "field-laptop"
    assert (bob.address(network.id, "10.0.0.5").status, bob.address(network.id, "10.0.0.5").name) ==            (RESERVED, "sw1-final")
    assert bob.address(network.id, "10.0.0.30").modified_by == "alice (PC)"


def test_offline_changes_someone_beat_are_refused(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    team_store(server, tmp_path, "alice").close()
    laptop = offline_store(server, tmp_path)
    laptop.set_address(network.id, "10.0.0.40", USED, "alice-offline")
    laptop.set_address(network.id, "10.0.0.5", USED, "alice-edit")
    laptop.set_address(network.id, "10.0.0.41", USED, "no-conflict")
    laptop.close()

    bob = team_store(server, tmp_path, "bob")  # Meanwhile, online
    bob.set_address(network.id, "10.0.0.40", USED, "bob-online")
    bob.set_address(network.id, "10.0.0.5", USED, "bob-edit")

    laptop = online_again(server, tmp_path)
    assert laptop.flush() == (1, 2)
    refused = {entry["ip"]: entry for entry in laptop.refused()}
    assert set(refused) == {"10.0.0.40", "10.0.0.5"}
    assert "was just recorded as in use for bob-online by bob" in refused["10.0.0.40"]["error"]
    assert "was changed by bob" in refused["10.0.0.5"]["error"]
    assert refused["10.0.0.40"]["data"]["name"] == "alice-offline"  # Kept, to use another address instead
    assert laptop.address(network.id, "10.0.0.40") is None  # Back to what the server had when she went offline
    assert laptop.address(network.id, "10.0.0.5").name == "sw1"
    laptop.sync()
    assert laptop.address(network.id, "10.0.0.40").name == "bob-online"
    laptop.discard(refused["10.0.0.5"]["seq"])
    assert [entry["ip"] for entry in laptop.refused()] == ["10.0.0.40"]


def test_copy_from_another_server_is_emptied(server, tmp_path):
    admin = team_store(server, tmp_path, "admin", ADMIN)
    admin.import_networks([plan()])
    laptop = team_store(server, tmp_path, "alice")
    assert laptop.networks()
    laptop.close()
    key = key_for(server)
    other = TeamKey("different-server", key.hosts, key.port, key.fingerprint, key.secret)
    assert TeamStore(other, tmp_path / "alice.db").networks() == []


def test_key_files(server, tmp_path):
    path = tmp_path / "tribe.nomadkey"
    write_team_key(path, server.config, server.directory)
    key = read_key_file(path)
    assert key.secret == server.config["team_secret"] and len(key.fingerprint) == 64 and key.hosts
    with pytest.raises(TeamKeyError, match="isn't a NOMAD tribe key file"):
        path.write_text(json.dumps({"format": 1, "hosts": []}))
        read_key_file(path)

    saved = tmp_path / "ipam-team.json"
    save_key(key, saved)
    assert key.secret not in saved.read_text()  # Encrypted for this Windows account
    assert load_saved_key(saved) == key
    assert load_saved_key(tmp_path / "missing.json") is None


def test_backups(server, tmp_path):
    folder = tmp_path / "server" / "backups"
    folder.mkdir(parents=True, exist_ok=True)
    old = folder / f"ipam-{(datetime.date.today() - datetime.timedelta(days=30)).isoformat()}.db"
    old.write_bytes(b"")
    target = server.backup_now()
    assert target.exists() and target.stat().st_size > 0
    assert not old.exists()  # Past the 14 days kept


def test_secure_folder_leaves_files_readable(tmp_path):
    """The server's folder is locked down, but its files (old and new) must stay readable by those granted it."""
    import getpass
    import subprocess
    from nomad.ipam.service import secure_folder
    folder = tmp_path / "server"
    folder.mkdir()
    (folder / "config.json").write_text("{}")
    (folder / "backups").mkdir()
    (folder / "backups" / "old.db").write_bytes(b"x")
    me = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True).stdout
    sid = me.strip().split(",")[-1].strip('"')
    secure_folder(folder, [f"*{sid}:(OI)(CI)M", "*S-1-5-18:(OI)(CI)F"])
    assert (folder / "config.json").read_text() == "{}"
    assert (folder / "backups" / "old.db").read_bytes() == b"x"
    (folder / "new.db").write_bytes(b"y")  # Files created later inherit the folder's permissions
    assert (folder / "new.db").read_bytes() == b"y"
    assert getpass.getuser()


def test_waiting_laptops_hear_about_changes_at_once(server, tmp_path):
    import time
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    laptop = team_store(server, tmp_path, "alice")
    watcher = TeamClient(key_for(server), user="bob")
    since = watcher.status()["revision"]

    started = time.monotonic()
    assert watcher.wait(since, timeout=1)[0] == since  # Nothing changed: answers after the timeout
    assert 0.8 < time.monotonic() - started < 5

    result = {}
    thread = threading.Thread(target=lambda: result.update(revision=watcher.wait(since, timeout=20)[0]))
    started = time.monotonic()
    thread.start()
    time.sleep(0.3)
    laptop.set_address(network.id, "10.0.0.40", USED, "new")
    thread.join(10)
    assert result["revision"] > since and time.monotonic() - started < 3  # Woken by the change, not the timeout
    assert laptop.server_name and laptop.server_address.endswith(f":{server.port}")


def test_older_server_is_recognized_not_offline(server, monkeypatch):
    from nomad.ipam.client import OldServerError
    monkeypatch.setattr(IpamServer, "wait", lambda self, *arguments: (_ for _ in ()).throw(
        RequestError(404, "No such request.")))  # A server from before instant sync
    client = TeamClient(key_for(server))
    with pytest.raises(OldServerError, match="older version"):
        client.wait(0, 1)
    assert not issubclass(OldServerError, ServerUnreachable)  # So the laptop doesn't show it as offline
    assert client.status()["api"] >= 2  # This server reports what it supports


def test_refusal_keeps_the_newer_server_version(server, tmp_path):
    """A sync brings someone else's change to an address while this laptop's own change to it is still waiting:
    when that waiting change is refused, the copy must show the other person's change, not the old state."""
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    team_store(server, tmp_path, "alice").close()
    laptop = offline_store(server, tmp_path)
    laptop.set_address(network.id, "10.0.0.50", USED, "alice-offline")
    laptop.close()
    team_store(server, tmp_path, "bob").set_address(network.id, "10.0.0.50", USED, "bob-online")

    laptop = online_again(server, tmp_path)
    laptop.sync()  # Brings Bob's row while Alice's change is still waiting...
    assert laptop.address(network.id, "10.0.0.50").name == "alice-offline"  # ...which still shows, as pending
    assert laptop.pending_ips(network.id) == {"10.0.0.50"}
    assert laptop.flush() == (0, 1)
    assert laptop.address(network.id, "10.0.0.50").name == "bob-online"


def test_laptops_keep_the_servers_history(server, tmp_path):
    from nomad.ipam.history import address_history
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    alice = team_store(server, tmp_path, "alice")
    alice.set_address(network.id, "10.0.0.5", RESERVED, "sw1-core")
    bob = team_store(server, tmp_path, "bob")
    assert bob.fetch_history() > 0
    events = address_history(bob, network.id, "10.0.0.5")
    assert [(event.action, event.who) for event in events] == [("Changed", "alice (PC)"), ("Recorded", "admin (PC)")]
    assert bob.fetch_history() == 0  # Only new entries after that
    bob.close()
    offline = offline_store(server, tmp_path, "bob")  # Still there offline
    assert len(address_history(offline, network.id, "10.0.0.5")) == 2


def sync_sightings(laptop):
    """What the IP Addresses page does with sweep results when it syncs."""
    laptop.apply_sent_sightings(laptop.send_sightings(laptop.outgoing_sightings()))
    fetched = laptop.client.fetch_sightings(laptop.sighting_revision)
    if fetched is not None:
        laptop.apply_sightings(*fetched)


def test_sweep_results_are_shared_but_not_history(server, tmp_path):
    import time
    admin = team_store(server, tmp_path, "admin", ADMIN)
    [network] = admin.import_networks([plan()])
    alice = team_store(server, tmp_path, "alice")
    bob = team_store(server, tmp_path, "bob")
    revision = alice.revision
    swept = time.time()
    alice.record_sightings(network.id, [{"ip": "10.0.0.5", "seen": swept, "rtt": 2, "mac": "aa-bb", "name": "sw1"}],
                           [{"cidr": "10.0.0.0/24", "started": swept - 5, "finished": swept + 1}])
    assert alice.sightings(network.id)[0]  # Shown on Alice's laptop at once
    watcher = TeamClient(key_for(server), user="carol")
    before = watcher.status()["sightings"]
    sync_sightings(alice)
    assert watcher.wait(watcher.status()["revision"], 1, before)[1] > before  # Waiting laptops hear of it

    sync_sightings(bob)
    hosts, ranges = bob.sightings(network.id)
    [(address, row)] = hosts.items()
    assert str(address) == "10.0.0.5" and row["mac"] == "aa-bb" and row["seen_by"] == "alice (PC)"
    assert [str(block) for block, *_ in ranges] == ["10.0.0.0/24"]
    alice.sync()
    assert alice.revision == revision  # Sweeps aren't changes: nothing in the history
    assert alice.outgoing_sightings() == []

    # Swept offline (in an air-gapped network): kept, and sent once the server is back
    alice.close()
    offline = offline_store(server, tmp_path)
    offline.record_sightings(network.id, [{"ip": "10.0.0.6", "seen": swept + 60, "rtt": None, "mac": "", "name": ""}])
    assert offline.send_sightings(offline.outgoing_sightings()) == []  # Can't reach the server: kept
    offline.close()
    alice = online_again(server, tmp_path)
    sync_sightings(alice)
    sync_sightings(bob)
    assert {str(address) for address in bob.sightings(network.id)[0]} == {"10.0.0.5", "10.0.0.6"}

    # An older sighting doesn't replace a newer one
    bob.record_sightings(network.id, [{"ip": "10.0.0.5", "seen": swept - 3600, "rtt": 9, "mac": "cc", "name": ""}])
    sync_sightings(bob)
    sync_sightings(alice)
    assert alice.sightings(network.id)[0][ipaddress.ip_address("10.0.0.5")]["mac"] == "aa-bb"


# --------------------------------------------------------------------- Tribe maps

def tribe_maps(server, tmp_path, user):
    from nomad.netmap.tribe import TribeMaps
    key = key_for(server)
    return TribeMaps(key.server_id, TeamClient(key, user=user, computer=user.upper()), tmp_path / f"{user}-maps.db")


def small_map():
    from nomad.netmap.model import Device, Link, NetworkMap
    network_map = NetworkMap(seeds=["10.0.0.1"])
    network_map.devices = {"core": Device("core", "core", "10.0.0.1", source="snmp"),
                           "acc1": Device("acc1", "acc1", "10.0.0.11", source="snmp")}
    network_map.links = [Link("core", "Gi1/0/1", "acc1", "Gi1/0/49", ["cdp"])]
    network_map.positions = {"core": (0.0, 0.0), "acc1": (0.0, 100.0)}
    return network_map


def test_tribe_map_shared_edited_and_merged(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {"scope": ["10.0.0.0/8"]}, {"communities": ["s3cret"]})
    bob.sync()
    assert [item["name"] for item in bob.maps()] == ["HQ"]
    assert bob.fetch_secrets(map_id) == {"communities": ["s3cret"]}
    bobs, settings = bob.load(map_id)
    assert set(bobs.devices) == {"core", "acc1"} and settings == {"scope": ["10.0.0.0/8"]}

    # Both move a different device; alice is offline when she does
    alices, _ = alice.load(map_id)
    alices.positions["core"] = (50.0, 50.0)
    alice.save(map_id, alices)
    bobs.positions["acc1"] = (70.0, 70.0)
    assert bob.save(map_id, bobs) == 1
    bob.sync()
    assert bob.pending_count() == 0
    alice.sync()
    merged, _ = alice.load(map_id)
    assert merged.positions == {"core": (50.0, 50.0), "acc1": (70.0, 70.0)}
    bob.sync()
    assert bob.load(map_id)[0].positions == merged.positions


def test_tribe_map_offline_changes_kept_until_sent(server, tmp_path):
    alice = tribe_maps(server, tmp_path, "alice")
    map_id = alice.create("HQ", small_map(), {}, {})
    edited, _ = alice.load(map_id)
    edited.devices["acc1"].note = "closet 2"
    server.stop()
    alice.save(map_id, edited)
    with pytest.raises(ServerUnreachable):
        alice.sync()
    assert alice.pending_count(map_id) == 1 and not alice.online
    assert alice.load(map_id)[0].devices["acc1"].note == "closet 2"  # Offline, still there



class FlakyClient:
    """A TeamClient that can be cut off from the server (down = True)."""

    def __init__(self, client):
        self.client, self.down = client, False

    def __getattr__(self, name):
        attribute = getattr(self.client, name)
        if self.down and callable(attribute):
            def unreachable(*args, **kwargs):
                raise ServerUnreachable("The tribe server can't be reached.")
            return unreachable
        return attribute


def test_tribe_map_credentials_changed_reach_everyone(server, tmp_path):
    from nomad.netmap.tribe import SECRETS
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {}, {"communities": ["public"]})
    bob.sync()
    assert bob.secrets(map_id) == {"communities": ["public"]}  # Fetched with the map, before it's opened

    assert alice.set_secrets(map_id, {"communities": ["s3cret"], "v3_users": [{"user": "nomad"}]})
    touched = bob.sync()
    assert SECRETS in touched[map_id]
    assert bob.secrets(map_id) == {"communities": ["s3cret"], "v3_users": [{"user": "nomad"}]}
    assert SECRETS not in alice.sync().get(map_id, set())  # Her own change coming back isn't news
    assert bob.sync() == {}  # Only fetched again when they change

    alice.rename(map_id, "Head Office")  # Fetched again, but the same
    assert SECRETS not in bob.sync()[map_id]


def test_tribe_map_credentials_changed_offline_sent_later(server, tmp_path):
    from nomad.netmap.tribe import SECRETS, TribeMaps
    key = key_for(server)
    flaky = FlakyClient(TeamClient(key, user="alice", computer="ALICE"))
    alice = TribeMaps(key.server_id, flaky, tmp_path / "alice-maps.db")
    bob = tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {}, {"communities": ["public"]})
    bob.sync()

    flaky.down = True
    assert not alice.set_secrets(map_id, {"communities": ["offline"]})
    assert alice.secrets(map_id) == {"communities": ["offline"]} and alice.pending_count(map_id) == 1
    assert bob.set_secrets(map_id, {"communities": ["bobs"]})  # Someone else changes them meanwhile

    flaky.down = False
    touched = alice.sync()  # Hers are sent, then fetched back: the last change made wins
    assert alice.pending_count() == 0 and SECRETS not in touched.get(map_id, set())
    assert alice.secrets(map_id) == {"communities": ["offline"]}
    assert SECRETS in bob.sync()[map_id] and bob.secrets(map_id) == {"communities": ["offline"]}


def test_tribe_copy_from_older_nomad_fetches_credentials_again(server, tmp_path):
    import sqlite3
    from nomad.netmap.tribe import SECRETS, TribeMaps
    alice, key = tribe_maps(server, tmp_path, "alice"), key_for(server)
    map_id = alice.create("HQ", small_map(), {}, {"communities": ["new"]})
    path = tmp_path / "old-maps.db"
    old = sqlite3.connect(path)  # As 1.21 left it: credentials fetched once, never again
    old.executescript("CREATE TABLE maps (id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_by TEXT, created TEXT, "
                      "deleted INTEGER NOT NULL DEFAULT 0, revision INTEGER NOT NULL DEFAULT 0);"
                      "CREATE TABLE secrets (map_id INTEGER PRIMARY KEY, data TEXT NOT NULL);"
                      "CREATE TABLE meta (name TEXT PRIMARY KEY, value TEXT);")
    old.execute("INSERT INTO maps (id, name) VALUES (?, 'HQ')", (map_id,))
    old.execute("INSERT INTO secrets VALUES (?, ?)", (map_id, json.dumps({"communities": ["stale"]})))
    old.execute("INSERT INTO meta VALUES ('server_id', ?), ('revision', '999999')", (key.server_id,))
    old.commit()
    old.close()
    bob = TribeMaps(key.server_id, TeamClient(key, user="bob"), path)
    assert bob.secrets(map_id) == {"communities": ["stale"]}
    assert SECRETS in bob.sync()[map_id]
    assert bob.secrets(map_id) == {"communities": ["new"]}


def test_tribe_map_groups_collapsed_by_each_person(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    network_map = small_map()
    hq = network_map.new_group("HQ")
    network_map.set_group(["core"], hq.key)
    lab = network_map.new_group("Lab")
    network_map.set_group(["acc1"], lab.key)
    hq.collapsed = True
    map_id = alice.create("HQ", network_map, {}, {})
    bob.sync()
    bobs, _ = bob.load(map_id)
    assert not any(group.collapsed for group in bobs.groups)  # Alice's collapsing stays hers

    for group in bobs.groups:
        group.collapsed = group.key == lab.key
    assert bob.save(map_id, bobs) == 0 and bob.pending_count() == 0  # Nothing to send
    alices, _ = alice.load(map_id)
    alices.devices["acc1"].note = "closet 2"
    alices.groups[[group.key for group in alices.groups].index(hq.key)].collapsed = False
    assert alice.save(map_id, alices) == 1  # Just the note
    alice.sync()
    bob.sync()
    bobs, _ = bob.load(map_id)
    assert bobs.devices["acc1"].note == "closet 2"
    assert {group.key for group in bobs.groups if group.collapsed} == {lab.key}  # Bob's own, kept
    assert not any(group.collapsed for group in alice.load(map_id)[0].groups)


def test_tribe_map_collapsed_groups_shared_by_older_nomads(server, tmp_path):
    alice = tribe_maps(server, tmp_path, "alice")
    network_map = small_map()
    hq = network_map.new_group("HQ")
    network_map.set_group(["core"], hq.key)
    map_id = alice.create("HQ", network_map, {}, {})
    TeamClient(key_for(server), user="old").map_request(  # An older NOMAD collapses it, for everyone
        "push", map_id=map_id, changes=[{"section": "group", "key": hq.key,
                                         "data": {"key": hq.key, "name": "HQ", "kind": hq.kind, "parent": "",
                                                  "collapsed": True}}])
    alice.sync()
    assert not alice.load(map_id)[0].groups[0].collapsed  # Alice keeps her own
    newcomer = tribe_maps(server, tmp_path, "bob")
    newcomer.sync()
    opened, _ = newcomer.load(map_id)
    assert opened.groups[0].collapsed  # First opened here: as it was shared
    assert newcomer.save(map_id, opened) == 0  # And nothing to send back


def test_tribe_map_saved_while_others_changes_arrive(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {}, {})
    alices, settings, seen = alice.snapshot(map_id)  # Open on Alice's page
    bob.sync()
    bobs, _ = bob.load(map_id)
    bobs.positions["acc1"] = (70.0, 70.0)
    bobs.devices["acc1"].note = "closet 2"
    bob.save(map_id, bobs)
    bob.sync()
    alice.sync()  # Bob's changes reach Alice's copy, but her page hasn't redrawn yet

    alices.positions["core"] = (50.0, 50.0)
    assert alice.save(map_id, alices, settings, seen) == 1  # Just her move
    alice.sync()
    bob.sync()
    merged, _ = bob.load(map_id)
    assert merged.positions == {"core": (50.0, 50.0), "acc1": (70.0, 70.0)}
    assert merged.devices["acc1"].note == "closet 2"
    assert seen[("position", "core")] == [50.0, 50.0]
    assert alice.save(map_id, alices, settings, seen) == 0  # Nothing new on her page

def test_tribe_map_lease_and_wait(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {}, {})
    assert alice.lease(map_id, "alice-gui")["yours"]
    lease = bob.lease(map_id, "bob-gui")
    assert not lease["yours"] and lease["computer"] == "ALICE"
    bob.sync()
    assert bob.leases[map_id]["holder"] == "alice-gui"
    revision = bob.revision
    waiter = TeamClient(key_for(server), user="bob")
    result = []
    thread = threading.Thread(target=lambda: result.append(waiter.wait_for_maps(revision, timeout=10)))
    thread.start()
    alice.rename(map_id, "Head office")
    thread.join(10)
    assert result and result[0] > revision
    bob.sync()
    assert bob.maps()[0]["name"] == "Head office"
    alice.delete(map_id)
    bob.sync()
    assert bob.maps() == []
