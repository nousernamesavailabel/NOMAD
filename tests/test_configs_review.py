"""Reviewing config changes: blocks, verdicts checked by the archive, Approve / Raise / close, Acknowledge (off unless
allowed), Seen from an older NOMAD, self-review labeled, a raised change closed by a later copy putting it back,
NOMAD's pushes suggesting blocks, and the same through the tribe server."""
import threading

import pytest

from nomad.configs import review, tribe
from nomad.configs.archive import ArchiveError, ConfigStore
from nomad.ipam.client import TeamClient, TeamKey
from nomad.ipam.server import IpamServer, load_config, team_key
from nomad.netmap import configpush

BEFORE = ("hostname R1\n!\ninterface Gi0/1\n description A\n!\ninterface Gi0/2\n shutdown\n!\n"
          "ntp server 10.0.0.1\n!\nline vty 0 4\n transport input ssh\n!\n")
AFTER = BEFORE.replace("description A", "description B").replace(
    "ntp server 10.0.0.1\n", "ntp server 10.0.0.1\nusername eve privilege 15 secret 0 x\n")


@pytest.fixture
def store(tmp_path):
    store = ConfigStore(tmp_path / "configs.db")
    yield store
    store.close()


def change(store, before=BEFORE, after=AFTER, device="10.0.0.1", now=(100, 200), changed_by=""):
    store.upload(device, "running", before, "alice", name="R1", now=now[0])
    return store.upload(device, "running", after, "alice", changed_by=changed_by, now=now[1])["version_id"]


def verdicts(blocks, verdict=review.EXPECTED, notes=None, unexpected=()):
    notes = notes or {}
    return [{"index": block.index, "fingerprint": block.fingerprint,
             "verdict": review.UNEXPECTED if block.index in unexpected else verdict,
             "note": notes.get(block.index, "checked it" if block.sensitive else ""), "seconds": 3, "seen": True}
            for block in blocks]


# ----------------------------------------------------------------- Blocks

def test_blocks_and_sensitive_lines():
    blocks = review.blocks(BEFORE, AFTER)
    assert [(block.kind, block.path, block.added) for block in blocks] == [
        ("changed", "interface Gi0/1", ["description B"]),
        ("added", "", ["username eve privilege 15 secret 0 x"])]
    assert [block.sensitive for block in blocks] == [False, True]
    assert len({block.fingerprint for block in blocks}) == 2
    assert review.blocks(BEFORE, "Building configuration...\n" + BEFORE) == []  # Noise isn't a block
    assert not review.blocks(BEFORE, AFTER, patterns=[])[1].sensitive  # The tribe's own list (empty: none)


def test_check_needs_a_verdict_a_note_and_a_reason():
    blocks = review.blocks(BEFORE, AFTER)
    with pytest.raises(review.ReviewError, match="no verdict"):
        review.check(blocks, verdicts(blocks)[:1], "CHG-1")
    with pytest.raises(review.ReviewError, match="sensitive"):
        review.check(blocks, verdicts(blocks, notes={1: ""}), "CHG-1")
    with pytest.raises(review.ReviewError, match="why"):
        review.check(blocks, verdicts(blocks), "")
    bad = verdicts(blocks)
    bad[0]["verdict"] = "looked"
    with pytest.raises(review.ReviewError, match="Expected or Unexpected"):
        review.check(blocks, bad, "CHG-1")
    checked = review.check(blocks, verdicts(blocks), "CHG-1", seconds=20)
    assert (checked.outcome, checked.unexpected, checked.seen, checked.quick) == ("approved", 0, 2, False)
    assert review.check(blocks, verdicts(blocks, unexpected={1}), "Who is eve?").outcome == "raised"


def test_a_quick_review_is_marked_not_refused():
    before = "\n".join(f"interface Gi0/{n}\n description A" for n in range(5)) + "\n"
    after = before.replace("description A", "description B")
    blocks = review.blocks(before, after)
    assert len(blocks) == 5
    assert review.check(blocks, verdicts(blocks), "CHG-2", seconds=2).quick
    assert not review.check(blocks, verdicts(blocks), "CHG-2", seconds=30).quick


def test_pushes_suggest_the_blocks_they_typed():
    blocks = review.blocks(BEFORE, AFTER)
    push = {"at": 150, "user": "alice (PC1)", "source": "The ACLs page",
            "lines": ["interface Gi0/1", " description B"]}
    assert review.explained_by(blocks[0], [push]) is push
    assert review.explained_by(blocks[1], [push]) is None
    removal = review.blocks(BEFORE, BEFORE.replace("ntp server 10.0.0.1\n", ""))[0]
    assert review.explained_by(removal, [dict(push, lines=["no ntp server 10.0.0.1"])]) is not None
    assert review.explained_by(removal, [push]) is None
    assert review.push_label(push) == "alice (PC1) from The ACLs page"


# ----------------------------------------------------------------- The archive

def test_approve(store):
    version_id = change(store)
    assert store.unreviewed() == {"10.0.0.1": 1}
    blocks = store.review_blocks(version_id)
    with pytest.raises(ArchiveError, match="sensitive"):
        store.finish_review(version_id, "bob", verdicts(blocks, notes={1: ""}), "CHG-1")
    result = store.finish_review(version_id, "bob", verdicts(blocks), "CHG-1", seconds=12, started=190, now=210)
    assert result["outcome"] == "approved" and not result["self_review"]
    assert store.unreviewed() == {} and store.raised() == {}
    version = store.version(version_id, False)
    assert (version["review_state"], version["reviewed_by"], version["reviewed_at"]) == ("approved", "bob", 210)
    [row] = store.reviews_of(version_id)
    assert (row["kind"], row["outcome"], row["reason"], row["total"], row["seen"]) == ("review", "approved", "CHG-1",
                                                                                      2, 2)
    assert row["blocks"][1]["note"] == "checked it" and "lines" not in row["blocks"][1]
    with pytest.raises(ArchiveError, match="Approved already"):
        store.finish_review(version_id, "carol", verdicts(blocks), "again")
    [logged] = store.review_log()
    assert logged["device_name"] == "R1" and logged["pulled_at"] == 200


def test_raise_then_close(store):
    version_id = change(store)
    blocks = store.review_blocks(version_id)
    result = store.finish_review(version_id, "bob", verdicts(blocks, unexpected={1}), "Who is eve?")
    assert result["outcome"] == "raised"
    assert store.unreviewed() == {} and store.raised() == {"10.0.0.1": 1}
    with pytest.raises(ArchiveError, match="Say why"):
        store.close_raised(version_id, "carol", review.EXPLAINED, "")
    store.close_raised(version_id, "carol", review.EXPLAINED, "Eve is the new contractor (CHG-9)")
    assert store.raised() == {}
    rows = store.reviews_of(version_id)
    assert [(row["kind"], row["outcome"], row["self_review"]) for row in rows] == [
        ("review", "raised", False), ("close", "explained", False)]
    with pytest.raises(ArchiveError, match="Only a raised change"):
        store.close_raised(version_id, "carol", review.REVERTED, "again")


def test_closing_your_own_raised_change_is_labeled(store):
    version_id = change(store)
    store.finish_review(version_id, "bob", verdicts(store.review_blocks(version_id), unexpected={0}), "Odd")
    store.close_raised(version_id, "bob", review.REVERTED, "Put it back by hand")
    assert store.reviews_of(version_id)[-1]["self_review"]


def test_a_later_copy_putting_it_back_closes_it(store):
    version_id = change(store)
    store.finish_review(version_id, "bob", verdicts(store.review_blocks(version_id), unexpected={1}), "Who is eve?")
    still = AFTER.replace("description B", "description C")  # Eve's still there
    store.upload("10.0.0.1", "running", still, "alice", now=300)
    assert store.raised() == {"10.0.0.1": 1}
    gone = still.replace("username eve privilege 15 secret 0 x\n", "")
    store.upload("10.0.0.1", "running", gone, "alice", now=400)
    assert store.raised() == {}
    version = store.version(version_id, False)
    assert (version["review_state"], version["reviewed_by"]) == ("reverted", review.REVERTED_BY)


def test_oldest_first(store):
    store.upload("d", "running", BEFORE, "a", now=1)
    first = store.upload("d", "running", AFTER, "a", now=2)["version_id"]
    second = store.upload("d", "running", AFTER + "logging host 1.1.1.1\n", "a", now=3)["version_id"]
    with pytest.raises(ArchiveError, match="oldest first"):
        store.finish_review(second, "bob", verdicts(store.review_blocks(second)), "CHG")
    store.finish_review(first, "bob", verdicts(store.review_blocks(first)), "CHG")
    store.finish_review(second, "bob", verdicts(store.review_blocks(second)), "CHG")
    assert store.unreviewed() == {}


def test_acknowledge_is_off_unless_allowed(store):
    version_id = change(store)
    with pytest.raises(ArchiveError, match="turned off"):
        store.acknowledge([version_id], "bob", "Maintenance window")
    store.set_settings({"allow_acknowledge": True})
    with pytest.raises(ArchiveError, match="Say why"):
        store.acknowledge([version_id], "bob", "")
    assert store.acknowledge([version_id], "bob", "Maintenance window") == 1
    assert store.unreviewed() == {}
    assert store.version(version_id, False)["review_state"] == "acknowledged"
    assert review.state_text(store.version(version_id, False)) == "Acknowledged"
    assert store.acknowledge([version_id], "bob", "Again") == 0


def test_seen_rows_from_before_reviews_can_still_be_reviewed(store):
    version_id = change(store)
    store.db.execute("UPDATE versions SET reviewed_by = 'old', reviewed_at = 1 WHERE id = ?", (version_id,))
    store.db.commit()
    assert review.state_text(store.version(version_id, False)) == "Seen" and store.unreviewed() == {}
    store.finish_review(version_id, "bob", verdicts(store.review_blocks(version_id)), "Looked properly now")
    assert store.version(version_id, False)["review_state"] == "approved"


def test_self_review_is_labeled_not_refused(store):
    store.upload("10.0.0.1", "running", BEFORE, "alice", name="R1", now=100)
    store.record_push("bob (PC2)", "The ACLs page", "10.0.0.1", [], ["interface Gi0/1", " description B"], now=150)
    store.record_push("carol (PC3)", "Carry VLAN", "10.9.9.9", [], ["vlan 10"], now=150)  # Another device
    version_id = store.upload("10.0.0.1", "running", AFTER, "alice", now=200)["version_id"]
    assert [push["user"] for push in store.pushes_for_version(version_id)] == ["bob (PC2)"]
    blocks = store.review_blocks(version_id)
    assert store.finish_review(version_id, "bob (PC2)", verdicts(blocks), "CHG-3")["self_review"]
    other = change(store, AFTER, AFTER + "logging host 1.1.1.1\n", now=(300, 400))
    result = store.finish_review(other, "dave", verdicts(store.review_blocks(other)), "CHG-4", self_review=True)
    assert result["self_review"]


def test_settings_validate_the_patterns(store):
    assert store.settings()["allow_acknowledge"] is False
    assert store.settings()["sensitive_patterns"] == list(review.SENSITIVE_PATTERNS)
    with pytest.raises(ArchiveError, match="regular expression"):
        store.set_settings({"sensitive_patterns": ["(unclosed"]})
    store.set_settings({"sensitive_patterns": ["^description"]})
    version_id = change(store)
    assert [block.sensitive for block in store.review_blocks(version_id)] == [True, False]


def test_an_old_archive_gets_the_new_column(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE versions (id INTEGER PRIMARY KEY, device_id TEXT NOT NULL, which TEXT NOT NULL, text BLOB, "
               "hash TEXT, pulled_at REAL, pulled_by TEXT, source TEXT, changed_by TEXT, previous_id INTEGER, "
               "added INTEGER, removed INTEGER, first INTEGER NOT NULL DEFAULT 0, reviewed_by TEXT, reviewed_at REAL, "
               "revision INTEGER NOT NULL DEFAULT 0)")
    db.commit()
    db.close()
    store = ConfigStore(path)
    version_id = change(store)
    assert store.version(version_id, False)["review_state"] is None
    store.close()


def test_pushes_are_told_to_the_listeners():
    heard = []

    def listener(target, names, lines, source):
        heard.append((target, names, lines, source))

    class Shell(configpush.ConfigShell):
        def __init__(self):
            self.answers = {"bad line": "% Invalid input detected at '^' marker."}

        def line(self, line, timeout=0):
            return self.answers.get(line.strip(), "")

    shell = Shell()
    shell.push_target, shell.push_names, shell.push_source = "10.0.0.1", ("R1",), "The ACLs page"
    configpush.add_push_listener(listener)
    try:
        shell.configure("configure terminal\ninterface Gi0/1\n description B\nbad line\nend\n", stop_on_error=False)
    finally:
        configpush.remove_push_listener(listener)
    assert heard == [("10.0.0.1", ["R1"], ["interface Gi0/1", " description B"], "The ACLs page")]


# ----------------------------------------------------------------- Through the tribe server

@pytest.fixture
def server(tmp_path):
    server = IpamServer(tmp_path / "server", host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve, daemon=True)
    thread.start()
    yield server
    server.stop()
    thread.join(10)


def team(server, tmp_path, computer, user="alice"):
    config = load_config(server.directory)
    key = TeamKey.from_dict(dict(team_key(config, server.directory), hosts=["127.0.0.1"], port=server.port))
    client = TeamClient(key, user=user, computer=computer)
    return tribe.TribeConfigs(key.server_id, client, tmp_path / f"{computer}.db"), client


def test_reviews_through_the_server(server, tmp_path):
    laptop, client = team(server, tmp_path, "PC1")
    other, _ = team(server, tmp_path, "PC2", user="bob")
    laptop.upload("10.0.0.1", "running", BEFORE, "alice", name="R1")
    laptop.record_push("", "The ACLs page", "10.0.0.1", [], ["interface Gi0/1", " description B"])
    version_id = laptop.upload("10.0.0.1", "running", AFTER, "alice")["version_id"]
    other.sync()
    [push] = other.pushes_for_version(version_id)
    assert push["user"] == "alice (PC1)" and push["source"] == "The ACLs page"
    with other.lock:
        blocks = review.blocks(other.text(other.store.version(version_id, False)["previous_id"]),
                               other.text(version_id), other.store.sensitive_patterns())
    result = other.finish_review(version_id, "", verdicts(blocks, unexpected={1}), "Who is eve?", 9.5, 1.0)
    assert result["outcome"] == "raised" and not result["self_review"]
    with pytest.raises(Exception, match="turned off"):
        laptop.acknowledge([version_id], "", "x")
    laptop.close_raised(version_id, "", review.EXPLAINED, "Contractor (CHG-9)")
    laptop.sync()
    rows = laptop.store.reviews_of(version_id)
    assert [(row["outcome"], row["user"]) for row in rows] == [("raised", "bob (PC2)"), ("explained", "alice (PC1)")]
    assert laptop.store.version(version_id, False)["review_state"] == "explained"
    reply = client.config_reviews(50)
    assert reply["to_review"] == 0 and reply["raised"] == 0 and len(reply["reviews"]) == 2
    assert "text" not in reply["changes"][0]
    laptop.close()
    other.close()
