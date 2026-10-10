import json
import threading

import pytest

from nomad.ipam.client import ServerMoved, TeamClient, load_saved_key, remember_moved_key, save_key
from nomad.ipam.migrate import MoveError, MoveFile, export_server, import_server, moved, undo_move
from nomad.ipam.server import IpamServer, load_config
from nomad.ipam.store import USED
from test_ipam_server import key_for, plan, small_map, team_store


def start(directory, port=0):
    server = IpamServer(directory, host="127.0.0.1", port=port)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    return server, thread


def stop(server, thread):
    server.stop()
    thread.join(10)


@pytest.fixture
def old(tmp_path):
    server, thread = start(tmp_path / "old")
    yield server
    stop(server, thread)


def test_move_carries_everything_and_laptops_follow(old, tmp_path):
    from nomad.netmap.tribe import TribeMaps
    admin = team_store(old, tmp_path, "admin", "admin")
    [network] = admin.import_networks([plan()])
    alice = team_store(old, tmp_path, "alice")
    saved = tmp_path / "alice-key.json"
    save_key(alice.key, saved)
    alice.client.on_moved = lambda key: remember_moved_key(key, saved)
    maps = TribeMaps(alice.key.server_id, TeamClient(key_for(old), user="alice", on_moved=lambda key: None), tmp_path / "alice-maps.db")
    map_id = maps.create("HQ", small_map(), {}, {"communities": ["s3cret"]})
    old_config = load_config(old.directory)

    # The old server is stopped for the export, then answers only to point laptops at the new one
    old.stop()
    move_path = tmp_path / "tribe.nomadmove"
    summary = export_server(move_path, "correct horse", ["127.0.0.1"], 0, old.directory)
    assert (summary.networks, summary.maps, summary.lost_secrets) == (1, 1, 0)
    assert b"s3cret" not in move_path.read_bytes() and old_config["team_secret"].encode() not in move_path.read_bytes()
    with pytest.raises(MoveError, match="Wrong password"):
        MoveFile(move_path, "wrong password")

    new_dir = tmp_path / "new"
    (new_dir / "something-old.txt").parent.mkdir()
    (new_dir / "something-old.txt").write_text("kept aside")
    config = import_server(MoveFile(move_path, "correct horse"), new_dir)
    assert {name: config[name] for name in ("server_id", "team_secret", "admin_secret")} == \
        {name: old_config[name] for name in ("server_id", "team_secret", "admin_secret")}
    assert config["backup_dir"] == str(new_dir / "backups") and "moved" not in config
    assert [path.name for path in tmp_path.glob("new-before-move-*/something-old.txt")] == ["something-old.txt"]

    new, new_thread = start(new_dir)
    signpost, signpost_thread = start(old.directory, port=old.port)
    try:
        signpost.config["moved"]["port"] = new.port  # The test's new server is on a port of its own
        assert moved(old.directory)["hosts"] == ["127.0.0.1"]

        # Alice's laptop still has the old address: it's pointed to the new server, and remembers it
        alice.set_address(network.id, "10.0.0.20", USED, "printer")
        assert alice.key.port == new.port and load_saved_key(saved).port == new.port
        assert new.store.address(network.id, "10.0.0.20").name == "printer"
        alice.sync()
        assert alice.online and alice.address(network.id, "10.0.0.5").name == "sw1"  # Same copy, carried on

        # Same certificate, so the pinned fingerprint still matches; the maps and their credentials came too
        maps.sync()  # Its own connection also follows the old server's pointer
        assert maps.client.key.port == new.port
        assert maps.secrets(map_id) == {"communities": ["s3cret"]}
        assert TeamClient(key_for(new)).map_secrets(map_id) == {"communities": ["s3cret"]}
    finally:
        stop(signpost, signpost_thread)
        stop(new, new_thread)


def test_moved_without_an_address_works_as_offline(old, tmp_path):
    admin = team_store(old, tmp_path, "admin", "admin")
    [network] = admin.import_networks([plan()])
    alice = team_store(old, tmp_path, "alice")
    old.stop()
    export_server(tmp_path / "tribe.nomadmove", "correct horse", [], None, old.directory)
    signpost, thread = start(old.directory, port=old.port)
    try:
        with pytest.raises(ServerMoved, match="Ask for the new tribe key file"):
            alice.client.status()
        alice.set_address(network.id, "10.0.0.21", USED, "kept until the new key file")
        assert alice.pending_count() == 1  # Waits, as when the server is down

        undo_move(old.directory)
        assert moved(old.directory) is None
    finally:
        stop(signpost, thread)


def test_move_password_and_file_checks(old, tmp_path):
    old.stop()
    with pytest.raises(MoveError, match="at least"):
        export_server(tmp_path / "x.nomadmove", "short", [], None, old.directory)
    other = tmp_path / "other.nomadmove"
    other.write_bytes(b"not a move file")
    with pytest.raises(MoveError, match="isn't a NOMAD"):
        MoveFile(other, "correct horse")
    json.loads((old.directory / "config.json").read_text())  # Untouched by a refused export
    assert moved(old.directory) is None
