"""Comparing two configurations, three ways:

- Plain text: line by line, like Notepad++'s Compare.
- Hide noise: the same, with noise lines (timestamps, byte counts, certificate data...) left out of the comparison.
- Section-aware: by mode, so a block that only moved isn't removed and added, and each change says which mode it's
  in (interface Gi0/1 > ...). The panes still line up by the plain comparison (the files keep their own order).

Whatever the mode, a Comparison has rows (which line of each side goes beside which, for lining the panes up),
hunks (the changes, as line ranges on each side) and each line's kind (for coloring)."""
import difflib
from dataclasses import dataclass, field
from itertools import zip_longest

from . import noise, text

PLAIN, NOISE, SECTION = "plain", "noise", "section"
MODES = [(PLAIN, "Plain text"), (NOISE, "Hide noise"), (SECTION, "Section-aware")]
EQUAL, DELETE, INSERT, REPLACE, HIDDEN = "equal", "delete", "insert", "replace", "hidden"  # Row tags
ADDED, REMOVED, CHANGED, MOVED = "added", "removed", "changed", "moved"  # Hunk kinds
QUICK_LIMIT = 4_000_000  # Past this many line pairs, popular lines (! and exit) don't anchor the comparison


@dataclass
class Row:
    a: object  # Line number on the left (0-based), or None (a gap)
    b: object
    tag: str


@dataclass
class Hunk:
    kind: str
    a_start: int
    a_end: int  # Half-open: a_start == a_end is a place on that side (where the other side's lines would go)
    b_start: int
    b_end: int
    path: str = ""

    @property
    def a_count(self):
        return self.a_end - self.a_start

    @property
    def b_count(self):
        return self.b_end - self.b_start


@dataclass
class Comparison:
    mode: str
    a_lines: list
    b_lines: list
    rows: list = field(default_factory=list)
    hunks: list = field(default_factory=list)
    a_hidden: set = field(default_factory=set)
    b_hidden: set = field(default_factory=set)
    a_kinds: dict = field(default_factory=dict)  # {line: hunk kind}
    b_kinds: dict = field(default_factory=dict)

    @property
    def changes(self):
        """The hunks that are changes (not blocks that only moved)."""
        return [hunk for hunk in self.hunks if hunk.kind != MOVED]

    @property
    def same(self):
        return not self.changes

    def counts(self):
        """(lines added, lines removed)."""
        added = sum(hunk.b_count for hunk in self.changes if hunk.kind in (ADDED, CHANGED))
        removed = sum(hunk.a_count for hunk in self.changes if hunk.kind in (REMOVED, CHANGED))
        return added, removed

    def summary(self):
        if self.same:
            moved = len(self.hunks)
            return "No differences" + (f" ({moved} moved)" if moved else "")
        added, removed = self.counts()
        count = len(self.changes)
        return f"{count} change{'s' if count != 1 else ''}: +{added} -{removed}"

    def inline(self):
        """[(tag, a line number, b line number, text)] for one pane showing both sides: equal, delete (only on the
        left), insert (only on the right) or hidden."""
        result = []
        for row in self.rows:
            if row.tag == REPLACE or (row.a is not None and row.b is not None and
                                      (row.a in self.a_kinds or row.b in self.b_kinds) and
                                      self.a_lines[row.a] != self.b_lines[row.b]):
                result.append((DELETE, row.a, None, self.a_lines[row.a]))
                result.append((INSERT, None, row.b, self.b_lines[row.b]))
            elif row.a is not None and row.b is not None:
                result.append((HIDDEN if row.tag == HIDDEN else EQUAL, row.a, row.b, self.b_lines[row.b]))
            elif row.a is not None:
                result.append((HIDDEN if row.tag == HIDDEN else DELETE, row.a, None, self.a_lines[row.a]))
            else:
                result.append((HIDDEN if row.tag == HIDDEN else INSERT, None, row.b, self.b_lines[row.b]))
        return result


def lines_of(value):
    if isinstance(value, (list, tuple)):
        return list(value)
    return (value or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")


def compare(a, b, mode=PLAIN):
    """Comparison of two configurations (text, or lists of lines)."""
    a_lines, b_lines = lines_of(a), lines_of(b)
    result = Comparison(mode, a_lines, b_lines)
    a_noise = noise.noise_lines(a_lines) if mode != PLAIN else set()
    b_noise = noise.noise_lines(b_lines) if mode != PLAIN else set()
    if mode == NOISE:
        result.a_hidden, result.b_hidden = a_noise, b_noise
    a_keep = [number for number in range(len(a_lines)) if number not in result.a_hidden]
    b_keep = [number for number in range(len(b_lines)) if number not in result.b_hidden]
    a_keys = [a_lines[number].rstrip() for number in a_keep]
    b_keys = [b_lines[number].rstrip() for number in b_keep]
    result.rows = rows_from(opcodes(a_keys, b_keys), a_keep, b_keep, len(a_lines), len(b_lines))
    a_tree, b_tree = text.parse(a_lines, skip=a_noise), text.parse(b_lines, skip=b_noise)
    if mode == SECTION:
        result.hunks = section_hunks(a_tree, b_tree)
    else:
        result.hunks = hunks_from(result.rows)
    a_paths, b_paths = text.paths_by_line(a_tree), text.paths_by_line(b_tree)
    for hunk in result.hunks:
        if not hunk.path:
            hunk.path = b_paths.get(hunk.b_start, "") if hunk.b_count else a_paths.get(hunk.a_start, "")
        for number in range(hunk.a_start, hunk.a_end):
            result.a_kinds.setdefault(number, hunk.kind)
        for number in range(hunk.b_start, hunk.b_end):
            result.b_kinds.setdefault(number, hunk.kind)
    return result


def opcodes(a_keys, b_keys):
    """difflib opcodes, quick for long files that differ a little: the lines the same at the start and the end aren't
    given to SequenceMatcher."""
    n, m = len(a_keys), len(b_keys)
    start = 0
    while start < n and start < m and a_keys[start] == b_keys[start]:
        start += 1
    end = 0
    while end < n - start and end < m - start and a_keys[n - 1 - end] == b_keys[m - 1 - end]:
        end += 1
    codes = [("equal", 0, start, 0, start)] if start else []
    middle_a, middle_b = a_keys[start:n - end], b_keys[start:m - end]
    if middle_a or middle_b:
        quick = len(middle_a) * len(middle_b) > QUICK_LIMIT
        matcher = difflib.SequenceMatcher(None, middle_a, middle_b, autojunk=quick)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            codes.append((tag, i1 + start, i2 + start, j1 + start, j2 + start))
    if end:
        codes.append(("equal", n - end, n, m - end, m))
    return codes


def rows_from(codes, a_keep, b_keep, a_count, b_count):
    """Rows for opcodes over the lines kept (a_keep/b_keep: their line numbers); the lines left out (noise) go in as
    hidden rows where they fall, beside each other when both sides have some there."""
    rows = []
    at = [0, 0]  # The next line not yet in a row, on each side

    def flush(a_to, b_to):
        hidden_a, hidden_b = range(at[0], a_to), range(at[1], b_to)
        for left, right in zip_longest(hidden_a, hidden_b):
            rows.append(Row(left, right, HIDDEN))
        at[0], at[1] = max(at[0], a_to), max(at[1], b_to)

    for tag, i1, i2, j1, j2 in codes:
        if tag == "equal":
            for offset in range(i2 - i1):
                left, right = a_keep[i1 + offset], b_keep[j1 + offset]
                flush(left, right)
                rows.append(Row(left, right, EQUAL))
                at[0], at[1] = left + 1, right + 1
            continue
        for left, right in zip_longest(a_keep[i1:i2], b_keep[j1:j2]):
            flush(left if left is not None else at[0], right if right is not None else at[1])
            rows.append(Row(left, right, REPLACE if left is not None and right is not None else
                            DELETE if left is not None else INSERT))
            if left is not None:
                at[0] = left + 1
            if right is not None:
                at[1] = right + 1
    flush(a_count, b_count)
    return rows


def hunks_from(rows):
    """Hunks from the runs of changed rows (hidden rows inside a run don't break it)."""
    hunks = []
    run = []
    next_a = next_b = 0

    def close():
        if not run:
            return
        a_numbers = [row.a for row in run if row.a is not None and row.tag != HIDDEN]
        b_numbers = [row.b for row in run if row.b is not None and row.tag != HIDDEN]
        a_start = a_numbers[0] if a_numbers else run_start[0]
        b_start = b_numbers[0] if b_numbers else run_start[1]
        a_end = a_numbers[-1] + 1 if a_numbers else a_start
        b_end = b_numbers[-1] + 1 if b_numbers else b_start
        kind = CHANGED if a_numbers and b_numbers else REMOVED if a_numbers else ADDED
        hunks.append(Hunk(kind, a_start, a_end, b_start, b_end))
        run.clear()

    run_start = (0, 0)
    for row in rows:
        if row.tag in (DELETE, INSERT, REPLACE):
            if not run:
                run_start = (next_a, next_b)
            run.append(row)
        elif row.tag == EQUAL:
            close()
        if row.a is not None:
            next_a = row.a + 1
        if row.b is not None:
            next_b = row.b + 1
    close()
    return hunks


# ----------------------------------------------------------------- Section-aware

def keyed(nodes, parent_line):
    """[(key, node)] of siblings, keys made unique (a second line the same gets #2)."""
    seen = {}
    result = []
    for node in nodes:
        key = text.key_of(node.line, parent_line)
        seen[key] = seen.get(key, 0) + 1
        result.append((key if seen[key] == 1 else f"{key}#{seen[key]}", node))
    return result


def stem(line):
    """A line without its last word (switchport access vlan 10 -> switchport access vlan), or "" for one word."""
    words = line.split()
    return " ".join(words[:-1]) if len(words) >= 2 else ""


def paired(a_keyed, b_keyed):
    """a_keyed with the lines only on the left that one line only on the right replaces (the same but for the last
    word: a new VLAN, a new next hop) given that line's key, so they show as changed rather than removed and added."""
    b_keys = {key for key, _ in b_keyed}
    a_keys = {key for key, _ in a_keyed}
    a_only = [(key, node) for key, node in a_keyed if key not in b_keys]
    b_only = [(key, node) for key, node in b_keyed if key not in a_keys]
    if not a_only or not b_only:
        return a_keyed

    def stems(items):
        found = {}
        for key, node in items:
            found.setdefault(stem(node.line), []).append(key)
        return {value: keys[0] for value, keys in found.items() if value and len(keys) == 1}

    left, right = stems(a_only), stems(b_only)
    renamed = {left[value]: right[value] for value in left.keys() & right.keys()}
    return [(renamed.get(key, key), node) for key, node in a_keyed]


def section_hunks(a_nodes, b_nodes):
    hunks = []
    compare_siblings(a_nodes, b_nodes, None, None, hunks)
    hunks.sort(key=lambda hunk: (hunk.b_start, hunk.a_start, hunk.kind != REMOVED))
    return merged(hunks)


def compare_siblings(a_list, b_list, a_parent, b_parent, hunks):
    parent_line = (b_parent or a_parent).line if (b_parent or a_parent) is not None else ""
    a_keyed, b_keyed = keyed(a_list, parent_line), keyed(b_list, parent_line)
    a_keyed = paired(a_keyed, b_keyed)
    a_map, b_map = dict(a_keyed), dict(b_keyed)
    path = " > ".join((b_parent or a_parent).path + [parent_line]) if parent_line else ""
    common_a = [key for key, _ in a_keyed if key in b_map]
    common_b = [key for key, _ in b_keyed if key in a_map]
    in_order = set()
    for block in difflib.SequenceMatcher(None, common_a, common_b, autojunk=False).get_matching_blocks():
        in_order.update(common_a[block.a:block.a + block.size])
    a_place = a_parent.number + 1 if a_parent is not None else 0
    for key, b_node in b_keyed:
        a_node = a_map.get(key)
        if a_node is None:
            hunks.append(Hunk(ADDED, a_place, a_place, b_node.number, b_node.end + 1, path))
            continue
        a_place = a_node.end + 1
        if a_node.line != b_node.line:
            hunks.append(Hunk(CHANGED, a_node.number, a_node.number + 1, b_node.number, b_node.number + 1, path))
        elif key not in in_order:
            hunks.append(Hunk(MOVED, a_node.number, a_node.end + 1, b_node.number, b_node.end + 1, path))
        if not same_leaves(a_node, b_node):
            compare_siblings(a_node.children, b_node.children, a_node, b_node, hunks)
    b_place = b_parent.number + 1 if b_parent is not None else 0
    for key, a_node in a_keyed:
        b_node = b_map.get(key)
        if b_node is None:
            hunks.append(Hunk(REMOVED, a_node.number, a_node.end + 1, b_place, b_place, path))
        else:
            b_place = b_node.end + 1


def same_leaves(a_node, b_node):
    """Whether two blocks have the same lines under them, none of them a mode (most interfaces): nothing to look
    into."""
    if len(a_node.children) != len(b_node.children):
        return False
    for left, right in zip(a_node.children, b_node.children):
        if left.line != right.line or left.children or right.children:
            return False
    return True


def merged(hunks):
    """Runs of lines added (or removed) one after another in the same place made one hunk."""
    result = []
    for hunk in hunks:
        last = result[-1] if result else None
        if last is not None and last.kind == hunk.kind and last.path == hunk.path and (
                (hunk.kind == ADDED and last.a_start == hunk.a_start and last.b_end == hunk.b_start) or
                (hunk.kind == REMOVED and last.b_start == hunk.b_start and last.a_end == hunk.a_start)):
            last.a_end, last.b_end = hunk.a_end, hunk.b_end
            continue
        result.append(hunk)
    return result


# ----------------------------------------------------------------- Taking a change across

def take(hunk, a_lines, b_lines, to_b=True):
    """The lines of the side a hunk is taken to, with the other side's lines in its place (the copy arrows)."""
    if to_b:
        return b_lines[:hunk.b_start] + a_lines[hunk.a_start:hunk.a_end] + b_lines[hunk.b_end:]
    return a_lines[:hunk.a_start] + b_lines[hunk.b_start:hunk.b_end] + a_lines[hunk.a_end:]
