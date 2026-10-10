"""Capture command output independently of the terminal's bounded scrollback."""
import os
import re
import tempfile

from ..system import replace_file
from .model import LogCleaner


CONFIG_PROFILES = {
    "Cisco IOS / IOS XE / NX-OS / Arista EOS": ("terminal length 0", "show running-config"),
    "Cisco ASA": ("terminal pager 0", "show running-config"),
    "Juniper Junos": ("show configuration | no-more",),
    "Custom command (disable paging first)": (),
}

ERROR_LINE = re.compile(
    r"^\s*(?:%\s*(?:Invalid|Error|Incomplete|Ambiguous|Unknown|Authorization|Access denied)|"
    r"(?:syntax error|error:|unknown command|invalid input|permission denied|command not found))", re.I)


class ConfigCapture:
    def __init__(self, prompt, command):
        self.prompt = prompt.strip()
        self.command = command
        self.cleaner = LogCleaner()
        self.parts = []
        self.tail = ""

    def feed(self, text):
        cleaned = self.cleaner.clean(text)
        self.parts.append(cleaned)
        # Only the current line is needed to recognize the returning prompt.
        self.tail = (self.tail + cleaned).rsplit("\n", 1)[-1]

    @property
    def complete(self):
        return self.tail.strip() == self.prompt and bool(self.parts)

    def output(self):
        if not self.complete:
            raise ValueError("The device prompt has not returned; the configuration may be incomplete.")
        lines = "".join(self.parts).splitlines()
        while lines and not lines[0].strip():
            lines.pop(0)
        if lines and lines[0].strip() in (self.command, self.prompt + self.command,
                                        self.prompt + " " + self.command):
            lines.pop(0)
        lines.pop()  # Returning prompt
        for line in lines:
            if ERROR_LINE.match(line):
                raise ValueError("The device rejected the command: " + line.strip())
        return "\n".join(lines).strip("\n") + "\n" if any(line.strip() for line in lines) else ""


def write_config(path, text):
    """Replace the destination only after the complete capture has been written."""
    folder = os.path.dirname(os.path.abspath(path))
    descriptor, temporary = tempfile.mkstemp(prefix=".nomad-config-", dir=folder)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as file:
            file.write(text)
        replace_file(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
