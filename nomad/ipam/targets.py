"""Software targets: the software each model of hardware should run, kept in the IPAM database beside the assets, so
the Assets page (and the Network Map's Software overlay) can say which devices are on it, behind it or ahead of it.

A target is for a model ("C9300-48P"), or for models matching a wildcard ("C9300-*", "CP-88??"): the most exact one
for an asset's model counts. Besides its target version, other versions can be allowed (an older one still
supported, a newer one being tried out).

Versions are compared the way their numbers read: 17.9.4a is ahead of 17.9.4 and behind 17.12.1; 15.2(7)E4 is behind
15.2(7)E10; a phone's sip8845_65.14-1-1-0001-136 is behind sip8845_65.14-2-1-0001-11. Versions of different trains
(15.2(7)E against 15.2(7)M) can't be compared: they're "other software".

TargetStore works on an IpamStore (this computer's, the server's, or a laptop's copy of the server's); on a laptop
TeamTargetStore (target_team.py) changes them through the server.
"""
import fnmatch
import re
import uuid

from .store import IpamError, SoftwareTarget, _from_row, model_key

ON_TARGET, BEHIND, AHEAD, OTHER, NO_TARGET, NO_SOFTWARE = "on target", "behind", "ahead", "other", "no target", \
    "no software"
STATE_NAMES = {ON_TARGET: "On target", BEHIND: "Behind target", AHEAD: "Ahead of target", OTHER: "Other software",
               NO_TARGET: "No target", NO_SOFTWARE: "Software not known"}
OFF_TARGET = (BEHIND, AHEAD, OTHER)
TOKEN = re.compile(r"\d+|[A-Za-z]+")
LIST_SEPARATORS = re.compile(r"[,;\s]+")
WILDCARDS = set("*?[")


def version_parts(text):
    """A version's numbers and words, in order: "17.9.4a" -> [(0, 17), (0, 9), (0, 4), (1, "a")]. A leading v (as
    FortiOS writes "v7.2.5") isn't one."""
    text = (text or "").strip()
    if len(text) > 1 and text[0] in "vV" and text[1].isdigit():
        text = text[1:]
    return [(0, int(token)) if token.isdigit() else (1, token.lower()) for token in TOKEN.findall(text)]


def compare_versions(first, second):
    """-1 when first is behind second, 0 the same, 1 ahead, or None when they can't be compared (other trains, or
    names rather than numbers)."""
    one, two = version_parts(first), version_parts(second)
    if not one or not two:
        return None
    for at, (mine, theirs) in enumerate(zip(one, two)):
        if mine == theirs:
            continue
        if mine[0] != theirs[0]:
            return None  # A number against a word: another kind of version
        if mine[0] == 1:
            last = at == len(one) - 1 and at == len(two) - 1
            if not (last and len(mine[1]) == 1 and len(theirs[1]) == 1):
                return None  # Another train (15.2(7)E against 15.2(7)M); a last letter is a rebuild (17.9.4a, 17.9.4b)
        return -1 if mine[1] < theirs[1] else 1
    if len(one) == len(two):
        return 0
    return -1 if len(one) < len(two) else 1  # 17.9.4 is behind 17.9.4a


def same_version(first, second):
    return compare_versions(first, second) == 0 or (first or "").strip().lower() == (second or "").strip().lower()


def allowed_versions(target):
    return [version for version in LIST_SEPARATORS.split(target.allowed or "") if version]


def is_pattern(model):
    return bool(WILDCARDS & set(model))


def matches(target_model, model):
    """Whether a target's model (perhaps with wildcards) is this model, without case."""
    if not model:
        return False
    if not is_pattern(target_model):
        return model_key(target_model) == model_key(model)
    return fnmatch.fnmatchcase(model_key(model), model_key(target_model))


def target_for(targets, model):
    """The target that counts for a model: one for it exactly, else the matching pattern with the most said
    (C9300-48* over C9300-*), or None."""
    found = [target for target in targets if matches(target.model, model)]
    if not found:
        return None
    return max(found, key=lambda target: (not is_pattern(target.model),
                                          len([char for char in target.model if char not in WILDCARDS])))


def state_of(software, target):
    """Where software stands against a target (or None): ON_TARGET, BEHIND, AHEAD, OTHER, NO_TARGET or NO_SOFTWARE."""
    if target is None:
        return NO_TARGET
    if not software:
        return NO_SOFTWARE
    if any(same_version(software, version) for version in [target.target] + allowed_versions(target)):
        return ON_TARGET
    order = compare_versions(software, target.target)
    return {-1: BEHIND, 1: AHEAD}.get(order, OTHER)


def compliance(asset, targets):
    """(state, target) for an asset: STATE_NAMES' states, and the target that counts (None without one). Only whole
    devices have targets: a part runs its chassis' software."""
    from .assets import is_part
    if is_part(asset.kind):
        return NO_TARGET, None
    target = target_for(targets, asset.model)
    return state_of(asset.software, target), target


def describe(state, software, target):
    """A Problems column line for an asset off target, or ""."""
    if state == BEHIND:
        return f"Behind target: runs {software}, the target for {target.model} is {target.target}"
    if state == AHEAD:
        return f"Ahead of target: runs {software}, the target for {target.model} is {target.target}"
    if state == OTHER:
        return f"Runs {software}, not the target for {target.model} ({target.target})"
    return ""


def clean_target_values(model, target, allowed="", note=""):
    model = " ".join(str(model or "").split())
    target = str(target or "").strip()
    if not model:
        raise IpamError("Say which model the target is for (wildcards like C9300-* are fine).")
    if not target:
        raise IpamError(f"Say which software {model} should run.")
    allowed = ", ".join(version for version in LIST_SEPARATORS.split(str(allowed or "")) if version)
    return dict(model=model, target=target, allowed=allowed, note=str(note or "").strip())


class TargetStore:
    """Software targets in an IpamStore."""

    def __init__(self, store):
        self.store = store

    @property
    def db(self):
        return self.store.db

    def targets(self):
        rows = self.db.execute("SELECT * FROM software_targets WHERE deleted = 0 ORDER BY sort_key")
        return [_from_row(SoftwareTarget, row) for row in rows]

    def target(self, target_id):
        row = self.db.execute("SELECT * FROM software_targets WHERE id = ? AND deleted = 0",
                              (str(target_id),)).fetchone()
        return _from_row(SoftwareTarget, row) if row is not None else None

    def by_model(self, model):
        """The target written for exactly this model (or pattern), or None."""
        row = self.db.execute("SELECT * FROM software_targets WHERE sort_key = ? AND deleted = 0",
                              (model_key(model),)).fetchone()
        return _from_row(SoftwareTarget, row) if row is not None else None

    def set_target(self, target_id=None, model="", target="", allowed="", note=""):
        """Add a target (target_id None, or one not recorded yet) or change one. Returns it."""
        values = clean_target_values(model, target, allowed, note)
        with self.store.transaction():
            same = self.by_model(values["model"])
            if same is not None and same.id != target_id:
                raise IpamError(f"There's a target for {same.model} already ({same.target}): change that one.")
            existing = self.target(target_id) if target_id else None
            if existing is None:
                item = SoftwareTarget(str(target_id or uuid.uuid4().hex), **values)
                return self.store._insert("software_targets", item)
            return self.store._update("software_targets", existing, values)

    def delete_target(self, target_id):
        with self.store.transaction():
            existing = self.target(target_id)
            if existing is None:
                raise IpamError("That target was deleted (perhaps by someone else).")
            self.store._delete("software_targets", existing)

    @property
    def can_change(self):
        return True


def counts(assets, targets):
    """{target id: {state: how many in-service devices}} for the Targets list."""
    from .assets import IN_SERVICE
    found = {target.id: {} for target in targets}
    for asset in assets:
        if asset.status != IN_SERVICE:
            continue
        state, target = compliance(asset, targets)
        if target is not None:
            found[target.id][state] = found[target.id].get(state, 0) + 1
    return found


def suggestions(assets, targets):
    """[(model, its most run version, {version: how many})] for the models in service that no target covers: what to
    start the targets from."""
    from .assets import IN_SERVICE, is_part
    found = {}
    for asset in assets:
        if asset.status != IN_SERVICE or is_part(asset.kind) or not asset.model or not asset.software:
            continue
        if target_for(targets, asset.model) is not None:
            continue
        versions = found.setdefault(asset.model, {})
        versions[asset.software] = versions.get(asset.software, 0) + 1
    listed = []
    for model, versions in sorted(found.items(), key=lambda item: item[0].lower()):
        common = max(versions, key=lambda version: (versions[version], version_parts(version)))
        listed.append((model, common, versions))
    return listed


def newest_first(versions):
    """Versions sorted newest first, as far as they compare (others by name)."""
    return sorted(versions, key=lambda version: version_parts(version), reverse=True)
