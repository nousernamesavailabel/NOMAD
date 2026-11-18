"""Standards: the lines every device of a sort must have (and mustn't), checked against its configuration.

A standard is written like a configuration:

    ! STANDARD: Access switch baseline
    ! applies-to: kind=switch group=Main Campus name=^SW-
    hostname {{hostname}}
    ntp server 10.1.0.10
    no ip http server
    ~ ^snmp-server community \\S+ RO \\S+$
    line vty 0 4
     transport input ssh
    ~ ^interface GigabitEthernet1/0/
     spanning-tree portfast

- A plain line must be there, in its mode (the lines indented under a mode line are checked inside it).
- A no line must not be there the other way: no ip http server passes when the device shows no ip http server, or
  doesn't have ip http server.
- A ~ line is a regular expression: some line there must match it. As a mode line, the lines under it are checked in
  every mode it matches (each GigabitEthernet1/0/ port). ~ lines are only reported: there's no one right line to type.
- {{name}} is filled in for each device: hostname, mgmt_ip, kind, platform, site, building, room.
- applies-to picks the devices it's for (all when there's none): kind= and platform= take lists (switch,router),
  group= a site, building or room the device is in, name= a regular expression for its name.
"""
import re
from dataclasses import dataclass, field

from ..netmap import routepolicy, vpn
from . import noise, text

PASS, MISSING, DIFFERENT, FORBIDDEN, PROBLEM = "pass", "missing", "different", "forbidden", "problem"
STATUS_NAMES = {PASS: "Passed", MISSING: "Missing", DIFFERENT: "Different", FORBIDDEN: "Not allowed",
                PROBLEM: "Problem"}
REQUIRED, NEGATED, PATTERN = "required", "negated", "pattern"
VARIABLE = re.compile(r"\{\{\s*([A-Za-z_][\w.]*)\s*\}\}")
HEADER = re.compile(r"^!\s*STANDARD\s*:\s*(.*)$", re.IGNORECASE)
APPLIES = re.compile(r"^!\s*applies-to\s*:\s*(.*)$", re.IGNORECASE)
FILTER_WORD = re.compile(r"(kind|platform|group|name)\s*=\s*", re.IGNORECASE)


@dataclass
class Rule:
    line: str
    kind: str
    number: int  # Its line in the standard
    children: list = field(default_factory=list)


@dataclass
class Standard:
    name: str
    text: str
    rules: list = field(default_factory=list)
    applies_to: dict = field(default_factory=dict)  # {"kind": [...], "platform": [...], "group": "", "name": ""}
    problems: list = field(default_factory=list)  # Lines that couldn't be read (a bad regular expression)

    @property
    def applies_text(self):
        parts = [f"{key}={','.join(value) if isinstance(value, list) else value}"
                 for key, value in self.applies_to.items() if value]
        return " ".join(parts) or "every device"


@dataclass
class Result:
    status: str
    rule: str  # The standard's line (variables filled in)
    path: list  # The modes it's in, as the device has them
    detail: str = ""
    line_number: object = None  # Where the device's configuration has what it's about (0-based), or None
    fix: list = field(default_factory=list)  # Lines to type in path's mode, [] when there's nothing to type

    @property
    def passed(self):
        return self.status == PASS

    @property
    def where(self):
        return " > ".join(self.path)


def is_standard(source):
    """Whether text is a standard (has the ! STANDARD: line) rather than a whole configuration."""
    return any(HEADER.match(line.strip()) for line in (source or "").splitlines()[:20])


def parse(source, name=""):
    """Standard from its text."""
    standard = Standard(name, source or "")
    stack = []  # (indent, rule)
    for number, raw in enumerate((source or "").splitlines()):
        stripped = raw.strip()
        header = HEADER.match(stripped)
        if header:
            standard.name = header.group(1).strip() or standard.name
            continue
        applies = APPLIES.match(stripped)
        if applies:
            standard.applies_to = parse_applies(applies.group(1))
            continue
        if not stripped or stripped.startswith("!"):
            continue
        indent = len(raw.replace("\t", " ")) - len(raw.replace("\t", " ").lstrip(" "))
        if stripped.startswith("~"):
            kind, line = PATTERN, stripped[1:].strip()
            try:
                re.compile(VARIABLE.sub("x", line))
            except re.error as error:
                standard.problems.append(f"Line {number + 1}: {error}")
                continue
        elif stripped.startswith("no "):
            kind, line = NEGATED, vpn.collapse(stripped)
        else:
            kind, line = REQUIRED, vpn.collapse(stripped)
        rule = Rule(line, kind, number)
        while stack and stack[-1][0] >= indent:
            stack.pop()
        (stack[-1][1].children if stack else standard.rules).append(rule)
        stack.append((indent, rule))
    return standard


def parse_applies(value):
    """{"kind": [...], "platform": [...], "group": "...", "name": "..."} from "kind=switch,router group=Main"."""
    result = {}
    found = list(FILTER_WORD.finditer(value))
    for index, match in enumerate(found):
        end = found[index + 1].start() if index + 1 < len(found) else len(value)
        key, words = match.group(1).lower(), value[match.end():end].strip()
        if key in ("kind", "platform"):
            result[key] = [word.strip().lower() for word in words.split(",") if word.strip()]
        else:
            result[key] = words
    return result


# ----------------------------------------------------------------- Which devices, and what's filled in

def device_facts(network_map, device):
    """What a standard can ask about a map device: {"hostname", "mgmt_ip", "kind", "platform", "site", "building",
    "room", "groups": [names]}."""
    from ..netmap import model
    facts = {"hostname": device.name or device.mgmt_ip or device.key, "mgmt_ip": device.mgmt_ip or "",
             "kind": device.kind, "platform": text.platform_for_device(device), "site": "", "building": "",
             "room": "", "groups": []}
    if network_map is not None:
        for group in network_map.group_path(device.key):
            facts["groups"].append(group.name)
            if group.kind in (model.SITE, model.BUILDING, model.ROOM):
                facts[group.kind] = group.name
    return facts


def applies(standard, facts):
    """Whether a standard is for a device (facts: device_facts, or as much of it as is known)."""
    rules = standard.applies_to
    if rules.get("kind") and (facts.get("kind") or "").lower() not in rules["kind"]:
        return False
    if rules.get("platform") and (facts.get("platform") or "").lower() not in rules["platform"]:
        return False
    if rules.get("group"):
        wanted = rules["group"].lower()
        if not any(name.lower() == wanted for name in facts.get("groups", ())):
            return False
    if rules.get("name"):
        try:
            if not re.search(rules["name"], facts.get("hostname") or "", re.IGNORECASE):
                return False
        except re.error:
            return False
    return True


def fill(line, facts, pattern=False):
    """line with its {{variables}} filled in (escaped in a pattern). KeyError for one that isn't known."""
    def value(match):
        name = match.group(1).lower()
        if name not in facts or isinstance(facts[name], list):
            raise KeyError(match.group(1))
        found = str(facts[name] or "")
        return re.escape(found) if pattern else found
    return VARIABLE.sub(value, line)


# ----------------------------------------------------------------- Checking

def check(standard, config, facts=None):
    """[Result] of a standard against a configuration (text or lines), one per rule (and per mode a ~ mode line
    matches)."""
    lines = config.splitlines() if isinstance(config, str) else list(config)
    tree = text.parse(lines, skip=noise.noise_lines(lines))
    results = [Result(PROBLEM, problem, [], problem) for problem in standard.problems]
    check_rules(standard.rules, tree, [], facts or {}, results)
    return results


def stem_of(line):
    """A line without its last word, when that leaves at least two (transport input ssh -> transport input)."""
    words = line.split()
    return " ".join(words[:-1]) if len(words) >= 3 else ""


def check_rules(rules, nodes, path, facts, results):
    parent_line = path[-1] if path else ""
    stems = {}  # How many of these rules start each way: a line like one only it starts like is "different"
    for rule in rules:
        if rule.kind == REQUIRED and stem_of(rule.line):
            stems[stem_of(rule.line)] = stems.get(stem_of(rule.line), 0) + 1
    for rule in rules:
        try:
            line = fill(rule.line, facts, pattern=rule.kind == PATTERN)
        except KeyError as error:
            results.append(Result(PROBLEM, rule.line, path, f"Nothing to fill in for {{{{{error.args[0]}}}}}"))
            continue
        if rule.kind == PATTERN:
            matched = [node for node in nodes if re.search(line, node.line)]
            if not matched:
                results.append(Result(MISSING, "~ " + line, path, "No line matches it"))
            elif not rule.children:
                results.append(Result(PASS, "~ " + line, path, matched[0].line, matched[0].number))
            for node in matched if rule.children else ():
                check_rules(rule.children, node.children, path + [node.line], facts, results)
            continue
        if rule.kind == NEGATED:
            target = line[3:]
            present = [node for node in nodes if node.line == target or node.line.startswith(target + " ")]
            if present and not any(node.line == line for node in nodes):
                results.append(Result(FORBIDDEN, line, path, f"Has: {present[0].line}", present[0].number,
                                      [line]))
            else:
                results.append(Result(PASS, line, path))
            continue
        found = next((node for node in nodes if node.line == line), None)
        if found is not None:
            if rule.children:
                check_rules(rule.children, found.children, path + [found.line], facts, results)
            else:
                results.append(Result(PASS, line, path, "", found.number))
            continue
        key = vpn.key_of(line, parent_line)
        instead = next((node for node in nodes if key != line and vpn.key_of(node.line, parent_line) == key), None)
        if instead is None and stems.get(stem_of(rule.line)) == 1:
            alike = [node for node in nodes if node.line.startswith(stem_of(line) + " ")]
            instead = alike[0] if len(alike) == 1 else None
        block = rendered(rule, facts)
        if instead is not None and not rule.children:
            results.append(Result(DIFFERENT, line, path, f"Has: {instead.line}", instead.number, [line]))
        else:
            results.append(Result(MISSING, line, path, "", None, block))


def rendered(rule, facts, depth=0):
    """A required rule and the required lines under it (filled in), for typing; ~ lines left out."""
    try:
        line = fill(rule.line, facts)
    except KeyError:
        return []
    if rule.kind == PATTERN:
        return []
    lines = [" " * depth + line]
    for child in rule.children:
        lines += rendered(child, facts, depth + 1)
    return lines


def failed(results):
    return [result for result in results if not result.passed]


def fix_lines(results):
    """The configuration lines (in their modes) that fix the results that failed and can be fixed."""
    groups = {}
    for result in failed(results):
        if result.fix:
            groups.setdefault(tuple(result.path), []).extend(result.fix)
    lines = []
    for path, fixes in groups.items():
        depth = len(path)
        lines += routepolicy.enter(list(path))
        lines += [" " * depth + line for line in dict.fromkeys(fixes)]
        if path:
            lines += routepolicy.leave(list(path))
    return lines
