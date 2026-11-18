"""Lines that change without anyone changing the configuration (timestamps, byte counts, checksums, certificate
data, NTP's clock drift): left out of the Hide noise comparison and of the archive's "has it changed?" check."""
import hashlib
import re

# One line each
NOISE_PATTERNS = [
    ("Building configuration", re.compile(r"^\s*Building configuration\.\.\.\s*$")),
    ("Current configuration size", re.compile(r"^\s*Current configuration\s*:\s*\d+ bytes\s*$")),
    ("Last configuration change", re.compile(r"^\s*!\s*Last configuration change at\b")),
    ("NVRAM last updated", re.compile(r"^\s*!\s*NVRAM config last updated at\b")),
    ("No configuration change since reload", re.compile(r"^\s*!\s*No configuration change since last restart")),
    ("NTP clock period", re.compile(r"^\s*ntp clock-period\s+\d+\s*$")),
    ("NX-OS command header", re.compile(r"^\s*!Command:\s*show\s")),
    ("NX-OS time header", re.compile(r"^\s*!Time:\s")),
    ("NX-OS last done", re.compile(r"^\s*!(?:Running|Startup) configuration last done at:")),
    ("ASA saved header", re.compile(r"^\s*:\s*Saved\s*$")),
    ("ASA written by", re.compile(r"^\s*:\s*Written by\b")),
    ("ASA serial and hardware", re.compile(r"^\s*:\s*(?:Serial Number|Hardware)\s*:")),
    ("ASA checksum", re.compile(r"^\s*Cryptochecksum:")),
    ("Aruba last modified", re.compile(r"^\s*!\s*Configuration (?:last )?(?:modified|saved)\b", re.IGNORECASE)),
]
NOISE = re.compile("|".join(f"(?:{pattern.pattern})" for _, pattern in NOISE_PATTERNS), re.IGNORECASE)
HEX_DIGITS = set("0123456789abcdefABCDEF")
HEX_ROW = re.compile(r"^\s+(?:[0-9A-Fa-f]{2,8}\s+)*[0-9A-Fa-f]{2,8}\s*$")  # A row of a certificate's data
HEX_WORD = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}(?![0-9A-Fa-f])")  # Certificate rows start with 8-digit words
QUIT = re.compile(r"^\s+quit\s*$")
REVISION_START = re.compile(r"^\s*<revision>\s*$")  # pfSense: who saved it last, and when
REVISION_END = re.compile(r"^\s*</revision>\s*$")


def noise_lines(lines):
    """The line numbers (0-based) of lines that are noise."""
    lines = lines.splitlines() if isinstance(lines, str) else lines
    found = set()
    in_revision = False
    hex_before = False
    for number, line in enumerate(lines):
        if in_revision:
            found.add(number)
            in_revision = not REVISION_END.match(line)
            continue
        if REVISION_START.match(line):
            found.add(number)
            in_revision = True
            continue
        stripped = line.lstrip()
        if stripped and stripped[0] in HEX_DIGITS and line[:1].isspace() and HEX_ROW.match(line) and \
                (hex_before or HEX_WORD.search(line)):
            found.add(number)
            hex_before = True
            continue
        if hex_before and QUIT.match(line):
            found.add(number)  # The end of the certificate's data
            hex_before = False
            continue
        hex_before = False
        if NOISE.match(line):
            found.add(number)
    return found


def normalized(text):
    """The configuration without its noise, comment-only lines, blank lines and trailing spaces: what's compared to
    tell whether it changed."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    hidden = noise_lines(lines)
    kept = []
    for number, line in enumerate(lines):
        stripped = line.rstrip()
        if number in hidden or not stripped.strip() or stripped.strip() == "!":
            continue
        kept.append(stripped)
    return "\n".join(kept)


def fingerprint(text):
    """A hash of normalized(text): the same for two pulls only noise tells apart."""
    return hashlib.sha256(normalized(text).encode("utf-8", "replace")).hexdigest()
