"""Keyword highlighting for terminal output (as in SecureCRT): words like "down", "err-disabled" or "% Invalid" in
color, so problems stand out in long show output. Rules are saved as JSON in the roaming app data folder."""
import dataclasses
import json
import logging
import os
import re
from dataclasses import dataclass

from ..system import app_data_dir

log = logging.getLogger(__name__)

FILE_NAME = "highlights.json"
# Color names a rule can use, and how they're drawn (bright enough to read on the terminal's dark background)
COLORS = {"Red": "#ff7a85", "Amber": "#ffd68a", "Green": "#b5e890", "Blue": "#7cc4ff", "Purple": "#de9df0",
          "Cyan": "#6fd3df"}
IPV4 = r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:/\d{1,2})?\b"
MAC = r"\b(?:[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})\b"
CACHE_LIMIT = 4000


@dataclass
class HighlightRule:
    pattern: str
    color: str = "Red"
    regex: bool = False  # Otherwise the pattern is plain text
    match_case: bool = False
    whole_word: bool = True  # Plain text only: "up" doesn't light up "backup"

    def compile(self):
        """The rule as a regular expression. Raises re.error for a bad one."""
        body = self.pattern if self.regex else re.escape(self.pattern)
        if not self.regex and self.whole_word:
            # \b only works next to a word character; "% Invalid" starts with one that isn't
            start = r"(?<![\w-])" if re.match(r"[\w]", self.pattern) else ""
            end = r"(?![\w-])" if re.search(r"[\w]$", self.pattern) else ""
            body = start + body + end
        return re.compile(body, 0 if self.match_case else re.IGNORECASE)


# First match wins where rules overlap, so "administratively down" (amber) comes before "down" (red)
DEFAULT_RULES = [
    HighlightRule("administratively down", "Amber"),
    HighlightRule("notconnect", "Amber"),
    HighlightRule("disabled", "Amber"),
    HighlightRule("shutdown", "Amber"),
    HighlightRule("warning", "Amber"),
    HighlightRule("inactive", "Amber"),
    HighlightRule("blocking", "Amber"),
    HighlightRule("err-disabled", "Red"),
    HighlightRule("errdisable", "Red"),
    HighlightRule("% Invalid", "Red"),
    HighlightRule("% Incomplete", "Red"),
    HighlightRule("% Ambiguous", "Red"),
    HighlightRule("down", "Red"),
    HighlightRule("error", "Red"),
    HighlightRule("failed", "Red"),
    HighlightRule("failure", "Red"),
    HighlightRule("denied", "Red"),
    HighlightRule("unreachable", "Red"),
    HighlightRule("timed out", "Red"),
    HighlightRule("critical", "Red"),
    HighlightRule("up", "Green"),
    HighlightRule("connected", "Green"),
    HighlightRule("established", "Green"),
    HighlightRule("full", "Green"),
    HighlightRule("forwarding", "Green"),
    HighlightRule(IPV4, "Blue", regex=True),
    HighlightRule(MAC, "Purple", regex=True),
]


class Highlighter:
    """Finds where the rules match in a line of text."""

    def __init__(self, rules):
        self.rules = []
        for rule in rules:
            if rule.color not in COLORS or not rule.pattern:
                continue
            try:
                self.rules.append((rule.compile(), rule.color))
            except re.error as error:
                log.warning("Skipping highlight rule %r: %s", rule.pattern, error)
        self.cache = {}

    def spans(self, text):
        """[(start, end, color name)], not overlapping, in order. Earlier rules win where matches overlap."""
        cached = self.cache.get(text)
        if cached is not None:
            return cached
        taken = [False] * len(text)
        spans = []
        for pattern, color in self.rules:
            for match in pattern.finditer(text):
                start, end = match.span()
                if start == end or any(taken[start:end]):
                    continue
                taken[start:end] = [True] * (end - start)
                spans.append((start, end, color))
        spans.sort()
        if len(self.cache) >= CACHE_LIMIT:
            self.cache.clear()
        self.cache[text] = spans
        return spans


def rule_from_dict(data):
    known = {item.name for item in dataclasses.fields(HighlightRule)}
    return HighlightRule(**{"pattern": "", **{key: value for key, value in data.items() if key in known}})


class HighlightStore:
    """The rules and whether highlighting is on. Listeners are called after every change."""

    def __init__(self, path=None):
        self.path = path or os.path.join(app_data_dir(), FILE_NAME)
        self.enabled = True
        self.rules = [dataclasses.replace(rule) for rule in DEFAULT_RULES]
        self.listeners = []
        self.highlighter = Highlighter(self.rules)
        self.load()

    def load(self):
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, encoding="utf-8") as file:
                data = json.load(file)
        except (OSError, ValueError) as error:
            log.error("Couldn't read %s: %s", self.path, error)
            return
        self.enabled = bool(data.get("enabled", True))
        if isinstance(data.get("rules"), list):
            self.rules = [rule_from_dict(item) for item in data["rules"] if isinstance(item, dict)]
        self.highlighter = Highlighter(self.rules)

    def save(self):
        data = {"enabled": self.enabled, "rules": [dataclasses.asdict(rule) for rule in self.rules]}
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        temporary = self.path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
        os.replace(temporary, self.path)
        self.changed()

    def set_rules(self, rules):
        self.rules = list(rules)
        self.highlighter = Highlighter(self.rules)
        self.save()

    def set_enabled(self, enabled):
        self.enabled = bool(enabled)
        self.save()

    def changed(self):
        for listener in list(self.listeners):
            listener()
