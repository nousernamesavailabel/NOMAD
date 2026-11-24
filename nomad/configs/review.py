"""Reviewing a change to a device's configuration: proof someone went through it, not just that it was opened.

A change is cut into blocks: the section-aware comparison's changes (diff.SECTION), each a run of lines removed,
added or changed in one place. The reviewer gives every block a verdict, Expected or Unexpected, while it's on the
screen. A block touching a sensitive line (users, AAA, SNMP communities, crypto, the VTY lines, the default route:
SENSITIVE_PATTERNS, or the tribe's own list) needs a note too. Then the review is finished:

- Approved: every block was expected, with a reason (a ticket number or a sentence).
- Raised: a block was unexpected. The change stays flagged until someone closes it as Explained (with a note) or
  Reverted (by hand, or on its own when a later backup shows the unexpected lines gone: reverted()).

A change can also be Acknowledged without a review (a planned maintenance window, say), only when the tribe allows
it (off unless turned on), and never counts as reviewed. One opened by an older NOMAD (which marked a change reviewed
as it was opened) is Seen.

The archive checks a finished review against the blocks it works out itself from the two copies (check()), so a
review can only cover the change as it is. Blocks are matched by fingerprint (their kind, place and lines).

NOMAD's own pushes (the ACLs, VPNs, Carry VLAN, Port Mirroring, NetFlow Config and Editor pages) are kept, so a block
that a push typed is suggested as Expected, with who sent it from where (explained_by()). The reviewer still decides.
"""
import hashlib
import re
from dataclasses import dataclass, field

from . import diff

EXPECTED, UNEXPECTED = "expected", "unexpected"
VERDICTS = (EXPECTED, UNEXPECTED)

# A change's review state (versions.review_state). None, with nobody's name on it: to review
SEEN, APPROVED, RAISED, EXPLAINED, REVERTED, ACKNOWLEDGED = ("seen", "approved", "raised", "explained", "reverted",
                                                             "acknowledged")
STATE_NAMES = {None: "To review", "": "To review", SEEN: "Seen", APPROVED: "Approved", RAISED: "Raised",
               EXPLAINED: "Explained", REVERTED: "Reverted", ACKNOWLEDGED: "Acknowledged"}
CLOSED = (EXPLAINED, REVERTED)

# What a review row records (reviews.kind)
KIND_REVIEW, KIND_CLOSE, KIND_ACKNOWLEDGE, KIND_SEEN = "review", "close", "acknowledge", "seen"

MIN_REASON = 3  # Characters in a reason or a note
QUICK_SECONDS = 1.0  # A review with less time than this on each block (on average) is marked quick in the log
QUICK_MIN_BLOCKS = 3  # ...when it has at least this many blocks (one or two can be read at a glance)
REVERTED_BY = "NOMAD (a later backup)"

SENSITIVE_PATTERNS = (
    r"^username\s",
    r"^aaa\s",
    r"^enable\s+(secret|password)",
    r"^snmp-server\s+(community|user|group|host)",
    r"^crypto\s",
    r"pre-shared-key",
    r"^(tacacs|radius)",
    r"^line\s+(vty|con)",
    r"access-class",
    r"^ip\s+route\s+(vrf\s+\S+\s+)?0\.0\.0\.0\s+0\.0\.0\.0",
    r"^ip\s+(ssh|http)",
    r"^key\s",
    r"^password\s",
)


class ReviewError(Exception):
    pass


@dataclass
class Block:
    """One change in a review: where it is in each copy (0-based, half-open), what it removed and added."""
    index: int
    kind: str  # diff.ADDED, REMOVED or CHANGED
    path: str
    a_start: int
    a_end: int
    b_start: int
    b_end: int
    removed: list = field(default_factory=list)
    added: list = field(default_factory=list)
    fingerprint: str = ""
    sensitive: bool = False

    def as_dict(self):
        """What the review keeps of it (no lines: those stay in the archive's copies)."""
        return {"index": self.index, "kind": self.kind, "path": self.path, "fingerprint": self.fingerprint,
                "sensitive": self.sensitive, "removed": len(self.removed), "added": len(self.added)}

    @property
    def where(self):
        return self.path or "(top level)"


def meaningful(lines):
    """Lines that say something (not blank, not a ! separator), stripped."""
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("!")]


def fingerprint(kind, path, removed, added):
    text = "\x1f".join([kind, path, "\x1e".join(removed), "\x1e".join(added)])
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def compiled(patterns):
    """The sensitive patterns as regular expressions (ones that don't compile are left out)."""
    result = []
    for pattern in patterns if patterns is not None else SENSITIVE_PATTERNS:
        try:
            result.append(re.compile(pattern, re.IGNORECASE))
        except re.error:
            continue
    return result


def bad_patterns(patterns):
    """[(pattern, why)] of the patterns that aren't regular expressions."""
    bad = []
    for pattern in patterns:
        try:
            re.compile(pattern)
        except re.error as error:
            bad.append((pattern, str(error)))
    return bad


def is_sensitive(lines, path, patterns):
    candidates = list(lines) + [part.strip() for part in path.split(" > ") if part.strip()]
    return any(pattern.search(line) for pattern in patterns for line in candidates)


def blocks(before, after, patterns=None):
    """[Block] of the change from before to after (texts), as section-aware Compare shows it."""
    result = diff.compare(before or "", after or "", diff.SECTION)
    expressions = compiled(patterns)
    found = []
    for index, hunk in enumerate(result.changes):
        removed = meaningful(result.a_lines[hunk.a_start:hunk.a_end])
        added = meaningful(result.b_lines[hunk.b_start:hunk.b_end])
        block = Block(index, hunk.kind, hunk.path, hunk.a_start, hunk.a_end, hunk.b_start, hunk.b_end, removed, added)
        block.fingerprint = fingerprint(hunk.kind, hunk.path, removed, added)
        block.sensitive = is_sensitive(removed + added, hunk.path, expressions)
        found.append(block)
    return found


# ----------------------------------------------------------------- NOMAD's own pushes

def normal(line):
    return " ".join(line.split()).lower()


def explained_by(block, pushes):
    """The push (newest first) whose lines account for every line of the block, or None. A line added must have been
    typed; a line removed must have been typed with "no", or replaced by a line typed in the same block."""
    for push in sorted(pushes, key=lambda item: -(item.get("at") or 0)):
        typed = {normal(line) for line in push.get("lines") or []}
        if not typed:
            continue
        added_ok = all(normal(line) in typed for line in block.added)
        if not added_ok:
            continue
        removed_ok = all(f"no {normal(line)}" in typed or (normal(line).startswith("no ") and
                                                             normal(line)[3:] in typed) or block.added
                         for line in block.removed)
        if removed_ok and (block.added or block.removed):
            return push
    return None


def push_label(push):
    """"jared (PC1) from the ACLs page"."""
    if not push:
        return ""
    source = push.get("source") or "NOMAD"
    return f"{push.get('user') or 'someone'} from {source}"


# ----------------------------------------------------------------- Checking a finished review

@dataclass
class Checked:
    outcome: str  # APPROVED or RAISED
    blocks: list  # [dict]: Block.as_dict() with the verdict, note, seconds and push
    seconds: float
    seen: int
    quick: bool
    unexpected: int


def check(found, verdicts, reason, seconds=0.0):
    """A review's verdicts checked against the blocks: every block has a verdict, every sensitive block a note, and
    the review a reason. verdicts: [{"index", "fingerprint", "verdict", "note", "seconds", "seen", "push"}]. Returns
    Checked; raises ReviewError saying what's missing."""
    if not found:
        raise ReviewError("There's nothing to review: the two copies differ only in noise.")
    by_print = {}
    for item in verdicts or []:
        by_print.setdefault(str(item.get("fingerprint") or ""), []).append(item)
    rows, unexpected, seen = [], 0, 0
    for block in found:
        matches = by_print.get(block.fingerprint) or []
        if not matches:
            raise ReviewError(f"Block {block.index + 1} ({block.where}) has no verdict: the change may have been "
                              f"looked at from another copy. Open it again and go through it.")
        item = matches.pop(0)
        verdict = item.get("verdict")
        if verdict not in VERDICTS:
            raise ReviewError(f"Block {block.index + 1} ({block.where}) needs Expected or Unexpected.")
        note = str(item.get("note") or "").strip()[:1000]
        if block.sensitive and len(note) < MIN_REASON:
            raise ReviewError(f"Block {block.index + 1} ({block.where}) touches a sensitive line, so it needs a note.")
        if verdict == UNEXPECTED:
            unexpected += 1
        if item.get("seen"):
            seen += 1
        rows.append(dict(block.as_dict(), verdict=verdict, note=note,
                         seconds=round(max(float(item.get("seconds") or 0), 0.0), 1),
                         push=str(item.get("push") or "")[:200]))
    if len((reason or "").strip()) < MIN_REASON:
        raise ReviewError("Say why the change was made (a ticket number or a sentence)." if not unexpected else
                          "Say what's wrong with the change.")
    seconds = max(float(seconds or 0), 0.0)
    quick = len(found) >= QUICK_MIN_BLOCKS and seconds / len(found) < QUICK_SECONDS
    return Checked(RAISED if unexpected else APPROVED, rows, round(seconds, 1), seen, quick, unexpected)


# ----------------------------------------------------------------- Put back by a later copy

def placed(found):
    """{(path, line)} added and {(path, line)} removed by a set of blocks."""
    added = {(block.path, normal(line)) for block in found for line in block.added}
    removed = {(block.path, normal(line)) for block in found for line in block.removed}
    return added, removed


def reverted(before, raised_text, newest, unexpected_prints, patterns=None):
    """Whether the newest copy has put back every block of a raised change that was unexpected: none of their lines
    added is still there, and none of their lines removed is still missing (both against the copy before the
    change)."""
    wrong = [block for block in blocks(before, raised_text, patterns) if block.fingerprint in set(unexpected_prints)]
    if not wrong:
        return False
    still_added, still_removed = placed(blocks(before, newest, patterns))
    for block in wrong:
        for line in block.added:
            if (block.path, normal(line)) in still_added:
                return False
        for line in block.removed:
            if (block.path, normal(line)) in still_removed:
                return False
    return True


def needs_attention(version):
    """To review, or raised and not closed."""
    if version.get("first"):
        return False
    state = version.get("review_state")
    return state == RAISED or (not state and not version.get("reviewed_by"))


def state_of(version):
    """A version's state: its review_state, Seen for one an older NOMAD marked reviewed, or None (to review)."""
    state = version.get("review_state")
    if state:
        return state
    return SEEN if version.get("reviewed_by") and not version.get("first") else None


def state_text(version):
    return STATE_NAMES.get(state_of(version), "To review")


def time_text(seconds):
    seconds = int(round(seconds or 0))
    if seconds < 60:
        return f"{seconds} s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes} min {seconds} s" if seconds else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"
