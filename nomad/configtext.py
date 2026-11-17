"""Cisco-style "!" lines between the blocks of configuration text, the way a running-config shows them, so NOMAD's
config previews read the same. IOS takes "!" as a comment when it's pasted or typed; NOMAD's own SSH sender skips them
(configpush.ConfigShell.configure)."""

SEPARATOR = "!"
FINISHING = ("end", "write memory", "write mem", "wr", "copy running-config startup-config")


def is_comment(line):
    return line.strip().startswith("!")


def is_exit(line):
    word = line.strip()
    return word == "exit" or word.startswith("exit-")


def is_indented(line):
    return line[:1].isspace()


BROAD_WORDS = {"ip", "ipv6", "crypto", "do"}  # Too broad alone: ip route and ip access-list are different sorts


def family(line):
    """What sort of top-level command a line is (its first word, without no; two for ip, crypto...): runs of one
    sort stay together, the way a running-config lists its snmp-server and ip route lines."""
    words = line.split()
    if words[:1] == ["no"]:
        words = words[1:]
    return tuple(words[:2]) if words[:1] and words[0] in BROAD_WORDS else tuple(words[:1])


def opens_block(lines, at):
    """Whether lines[at] has indented lines under it."""
    following = lines[at + 1] if at + 1 < len(lines) else ""
    return bool(following.strip()) and is_indented(following) and not is_comment(following)


def separated(lines):
    """lines (a list) with "!" before each block (a line with lines indented under it), after each one, and between
    runs of different sorts of single lines. Nothing goes right after configure terminal or a comment, nor before
    end unless a block comes just before it. Lines already separated come back unchanged."""
    lines = list(lines)
    result = []
    before = None  # What came last: None (the start, configure terminal, a comment), "block", or a family

    def separate():
        if result and result[-1].strip() != SEPARATOR:
            result.append(SEPARATOR)

    for at, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            result.append(line)
            before = None
        elif stripped == SEPARATOR:
            if not result or result[-1].strip() != SEPARATOR:
                result.append(line)
            before = None
        elif is_comment(line):
            if before is not None:
                separate()
            result.append(line)
            before = None
        elif is_indented(line) or is_exit(line):
            result.append(line)
            before = "block"
        elif stripped.startswith("conf"):
            result.append(line)
            before = None
        elif stripped in FINISHING:
            if before == "block":
                separate()
            result.append(line)
            before = None
        else:
            kind = "block" if opens_block(lines, at) else family(stripped)
            if before is not None and (before == "block" or kind == "block" or before != kind):
                separate()
            result.append(line)
            before = kind
    return result


def separated_text(text):
    """separated() for text."""
    return "\n".join(separated((text or "").splitlines()))
