"""Remote files over SSH, for the SCP page: browsing, transfers with resume, checksums, and comparing folders.

SFTP is used when the server offers it. Without it, listing runs `ls` over an exec channel and files move with the
scp protocol (as WinSCP's SCP mode does); that mode can't resume. No Qt here, so it can be tested on its own.
Everything blocks: run it off the UI thread.
"""
import errno
import hashlib
import io
import logging
import os
import posixpath
import re
import shlex
import stat
import time
from dataclasses import dataclass, field

import paramiko

from ..system import replace_file
from .transports import Cancelled, ConnectionFailed, SshTransport

log = logging.getLogger(__name__)

SFTP, SCP = "SFTP", "SCP"
PART_SUFFIX = ".filepart"  # Unfinished transfers, as WinSCP names them, so either can resume the other's
CHUNK = 32768
PREFETCH_WINDOW = 16 * 1024 * 1024  # Bytes of a download requested ahead at a time
HASHES = {"SHA-256": ("sha256", "sha256sum", "shasum -a 256"), "MD5": ("md5", "md5sum", "md5 -q"),
          "SHA-1": ("sha1", "sha1sum", "shasum -a 1")}
EXEC_TIMEOUT = 30
BROWSE_TIMEOUT = 30  # Seconds a browsing request (listing, rename...) may wait for the server before giving up
# Finds the server's sftp-server program, for running it through sudo: where sshd_config says, else the usual places
SFTP_SERVER_SEARCH = (
    "p=$(awk 'tolower($1)==\"subsystem\" && $2==\"sftp\" {print $3; exit}' /etc/ssh/sshd_config 2>/dev/null); "
    "[ -x \"$p\" ] && { echo \"$p\"; exit 0; }; "
    "for p in /usr/lib/openssh/sftp-server /usr/libexec/openssh/sftp-server /usr/lib/ssh/sftp-server "
    "/usr/libexec/sftp-server /usr/lib/sftp-server /usr/local/libexec/sftp-server; do "
    "[ -x \"$p\" ] && { echo \"$p\"; exit 0; }; done; exit 1")
SUDO_TRIES = 3
TIME_TOLERANCE = 2  # Seconds: FAT and some servers keep modification times to 2 s


class RemoteError(Exception):
    """A remote operation failed; the message is suitable for showing to the user."""


class TransferCancelled(Exception):
    pass


@dataclass
class Entry:
    name: str
    path: str
    is_dir: bool = False
    size: int = 0
    mtime: float = 0.0  # Seconds since the epoch; 0 if unknown
    mode: int = 0  # Permission bits (and type bits when known)
    owner: str = ""
    group: str = ""
    is_link: bool = False
    link_target: str = ""
    uid: int = None  # Numeric owner and group, when the server says (SFTP does)
    gid: int = None

    @property
    def permissions(self):
        """"rwxr-xr-x" style, with the type letter first: "drwxr-xr-x"."""
        kind = "l" if self.is_link else "d" if self.is_dir else "-"
        return kind + permission_text(self.mode)


def permission_text(mode):
    text = ""
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 7
        text += ("r" if bits & 4 else "-") + ("w" if bits & 2 else "-") + ("x" if bits & 1 else "-")
    special = list(text)
    if mode & stat.S_ISUID:
        special[2] = "s" if special[2] == "x" else "S"
    if mode & stat.S_ISGID:
        special[5] = "s" if special[5] == "x" else "S"
    if mode & stat.S_ISVTX:
        special[8] = "t" if special[8] == "x" else "T"
    return "".join(special)


def parse_permissions(text):
    """"rwxr-xr-x" (with or without a type letter) to mode bits."""
    text = text[-9:]
    if len(text) != 9:
        raise ValueError(f"Not a permission string: {text}")
    mode = 0
    for index, char in enumerate(text):
        shift = 8 - index
        if char in "rwxst":
            mode |= 1 << shift
    if text[2] in "sS":
        mode |= stat.S_ISUID
    if text[5] in "sS":
        mode |= stat.S_ISGID
    if text[8] in "tT":
        mode |= stat.S_ISVTX
    return mode


def join(folder, name):
    return posixpath.join(folder or "/", name)


def parent(path):
    return posixpath.dirname(path.rstrip("/")) or "/"


def quote(path):
    return shlex.quote(path)


# ----------------------------------------------------------------- Parsing `ls -la`

MONTHS = {name: index for index, name in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
LS_LINE = re.compile(
    r"^(?P<perm>[-dlcbps][-rwxsStTl]{9})[.+@]?\s+\d+\s+(?P<owner>\S+)\s+(?P<group>\S+)\s+(?P<size>\d+|\d+,\s*\d+)\s+"
    r"(?:(?P<iso>\d{4}-\d\d-\d\d \d\d:\d\d(?::\d\d(?:\.\d+)?)?)(?: [+-]\d{4})?|"
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<year_or_time>\d{4}|\d{1,2}:\d\d))\s(?P<name>.+)$")


def parse_ls_time(match, now=None):
    if match.group("iso"):
        text = match.group("iso")
        seconds = 0.0
        if text.count(":") == 2:
            text, _, fraction = text.rpartition(":")
            seconds = float(fraction)
        return time.mktime(time.strptime(text, "%Y-%m-%d %H:%M")) + seconds
    month, day = MONTHS.get(match.group("month"), 1), int(match.group("day"))
    value = match.group("year_or_time")
    if ":" in value:  # Within the last six months: no year shown
        now = time.localtime(now if now is not None else time.time())
        hour, minute = (int(part) for part in value.split(":"))
        year = now.tm_year
        stamp = time.mktime((year, month, day, hour, minute, 0, 0, 0, -1))
        if stamp > time.mktime(now) + 86400:
            stamp = time.mktime((year - 1, month, day, hour, minute, 0, 0, 0, -1))
        return stamp
    return time.mktime((int(value), month, day, 0, 0, 0, 0, 0, -1))


def parse_ls(text, folder, now=None):
    """Entries from `ls -la` output (GNU with --time-style=full-iso, BusyBox or BSD), leaving out . and .."""
    entries = []
    for line in text.splitlines():
        match = LS_LINE.match(line.rstrip("\r"))
        if not match:
            continue
        name = match.group("name")
        perm = match.group("perm")
        link_target = ""
        if perm[0] == "l" and " -> " in name:
            name, _, link_target = name.partition(" -> ")
        if name in (".", ".."):
            continue
        size = match.group("size")
        entries.append(Entry(name=name, path=join(folder, name), is_dir=perm[0] == "d",
                             size=int(size) if size.isdigit() else 0, mtime=parse_ls_time(match, now),
                             mode=parse_permissions(perm[1:]), owner=match.group("owner"),
                             group=match.group("group"), is_link=perm[0] == "l", link_target=link_target))
    return entries


# ----------------------------------------------------------------- The scp protocol

def _read_line(channel):
    data = b""
    while not data.endswith(b"\n"):
        byte = channel.recv(1)
        if not byte:
            raise RemoteError("The scp connection closed unexpectedly.")
        data += byte
    return data[:-1].decode("utf-8", "replace")


def _expect_ok(channel):
    code = channel.recv(1)
    if code == b"\x00":
        return
    if not code:
        raise RemoteError("The scp connection closed unexpectedly (is scp installed on the server?).")
    message = _read_line(channel) if code in (b"\x01", b"\x02") else (code + channel.recv(1024)).decode("utf-8",
                                                                                                      "replace")
    raise RemoteError(f"scp: {message.strip()}")


def scp_receive(channel, write, progress=None, cancelled=lambda: False):
    """Receive one file over a channel running `scp -p -f path`. write(bytes) stores it. Returns (size, mtime)."""
    channel.sendall(b"\x00")
    mtime = 0.0
    while True:
        code = channel.recv(1)
        if not code:
            raise RemoteError("The scp connection closed before sending the file.")
        if code in (b"\x01", b"\x02"):
            raise RemoteError(f"scp: {_read_line(channel).strip()}")
        line = _read_line(channel)
        if code == b"T":
            mtime = float(line.split()[0])
            channel.sendall(b"\x00")
            continue
        if code == b"C":
            _, size, _name = line.split(" ", 2)
            size = int(size)
            break
        raise RemoteError(f"scp sent something unexpected: {(code.decode('latin-1') + line)[:80]}")
    channel.sendall(b"\x00")
    remaining = size
    while remaining:
        if cancelled():
            raise TransferCancelled()
        data = channel.recv(min(CHUNK * 2, remaining))
        if not data:
            raise RemoteError("The connection closed part way through the file.")
        write(data)
        remaining -= len(data)
        if progress is not None:
            progress(len(data))
    _expect_ok(channel)
    channel.sendall(b"\x00")
    return size, mtime


def scp_send(channel, read, size, name, mode=0o644, mtime=None, progress=None, cancelled=lambda: False):
    """Send one file over a channel running `scp -t [-p] path`. read(n) gives the file's bytes."""
    _expect_ok(channel)
    if mtime is not None:
        channel.sendall(f"T{int(mtime)} 0 {int(mtime)} 0\n".encode())
        _expect_ok(channel)
    channel.sendall(f"C{mode & 0o7777:04o} {size} {name}\n".encode("utf-8"))
    _expect_ok(channel)
    remaining = size
    while remaining:
        if cancelled():
            raise TransferCancelled()
        data = read(min(CHUNK * 2, remaining))
        if not data:
            raise RemoteError("The local file got shorter while it was being sent.")
        channel.sendall(data)
        remaining -= len(data)
        if progress is not None:
            progress(len(data))
    channel.sendall(b"\x00")
    _expect_ok(channel)


# ----------------------------------------------------------------- Remote file systems

class RemoteFS:
    """The operations the SCP page needs. Paths are absolute POSIX paths."""
    kind = ""
    can_resume = False
    aborted = False  # abort() was called: this one can't be used again
    as_root = False  # Running through sudo

    def abort(self):
        """Stop whatever is running right now, from any thread, without waiting for the server (Cancel and Pause,
        even while the network is stalled). Afterwards this file system is finished with."""

    def __init__(self, connection):
        self.connection = connection

    def home(self):
        raise NotImplementedError

    def listdir(self, path):
        raise NotImplementedError

    def stat(self, path):
        """The Entry for a path, or None if it doesn't exist."""
        raise NotImplementedError

    def mkdir(self, path):
        raise NotImplementedError

    def rename(self, old, new):
        raise NotImplementedError

    def remove(self, path):
        raise NotImplementedError

    def rmdir(self, path):
        raise NotImplementedError

    def chmod(self, path, mode):
        raise NotImplementedError

    def chown(self, path, owner=None, group=None):
        """Change a file's owner and/or group (names or numbers; None leaves one as it is)."""
        raise NotImplementedError

    def set_mtime(self, path, mtime):
        raise NotImplementedError

    def read_bytes(self, path):
        buffer = io.BytesIO()
        self.download(path, buffer)
        return buffer.getvalue()

    def accounts(self):
        """({user name: uid}, {group name: gid}) from the server's /etc/passwd and /etc/group ({} if unreadable)."""
        found = []
        for path in ("/etc/passwd", "/etc/group"):
            try:
                found.append(parse_ids(self.read_bytes(path).decode("utf-8", "replace")))
            except (RemoteError, OSError):
                found.append({})
        return found[0], found[1]

    def download(self, remote, local_file, offset=0, progress=None, cancelled=lambda: False):
        """Copy a remote file into an open local file, starting at offset. Returns the remote mtime (or 0)."""
        raise NotImplementedError

    def upload(self, local_file, size, remote, offset=0, mode=None, mtime=None, progress=None,
               cancelled=lambda: False):
        """Copy an open local file (already at offset) to remote. offset > 0 appends to what's there."""
        raise NotImplementedError

    def checksum(self, path, algorithm="SHA-256", cancelled=lambda: False):
        """The file's hash as lowercase hex: worked out on the server when it can, otherwise by reading it."""
        python_name, *commands = HASHES[algorithm]
        for command in commands:
            try:
                status, out, _ = self.connection.run(f"{command} {quote(path)}")
            except RemoteError:
                break  # No exec channel (an SFTP-only account): read it instead
            match = re.match(rb"^\\?([0-9a-fA-F]{32,128})\b", out.strip())
            if status == 0 and match:
                return match.group(1).decode().lower()
        return self.read_hash(path, python_name, cancelled)

    def read_hash(self, path, python_name, cancelled):
        digest = hashlib.new(python_name)

        class Sink:
            write = digest.update

        self.download(path, Sink(), cancelled=cancelled)
        return digest.hexdigest()

    def realpath(self, path):
        """Where a path really is, with links resolved (for noticing a link that loops back)."""
        return path

    def walk_files(self, path, cancelled=lambda: False, follow_links=False):
        """(relative path, Entry) for every file under a folder, and each folder as it's entered. follow_links goes
        into links to folders too (for copying), skipping any that lead back to a folder already being walked."""
        stack = [("", path, frozenset({self.realpath(path)} if follow_links else ()))]
        while stack:
            relative, folder, ancestors = stack.pop()
            if cancelled():
                raise TransferCancelled()
            for entry in sorted(self.listdir(folder), key=lambda item: item.name):
                child = f"{relative}/{entry.name}" if relative else entry.name
                if entry.is_dir and entry.is_link:
                    if not follow_links:
                        yield child, entry
                        continue
                    real = self.realpath(entry.path)
                    if real in ancestors:
                        continue  # A link back up the tree: copying it would never end
                    yield child, entry
                    stack.append((child, entry.path, ancestors | {real}))
                    continue
                yield child, entry
                if entry.is_dir:
                    stack.append((child, entry.path, ancestors | ({self.realpath(entry.path)} if follow_links
                                                                   else frozenset())))

    def close(self):
        pass


def _sftp_error(error, path):
    if isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == errno.ENOENT:
        return RemoteError(f"{path} doesn't exist.")
    if isinstance(error, PermissionError) or getattr(error, "errno", None) == errno.EACCES:
        return RemoteError(f"Permission denied: {path}")
    return RemoteError(f"{path}: {getattr(error, 'strerror', None) or error}")


class SftpFS(RemoteFS):
    kind = SFTP
    can_resume = True

    def __init__(self, connection, client):
        super().__init__(connection)
        self.client = client

    def abort(self):
        self.aborted = True
        try:
            self.client.get_channel().close()  # A blocked read or write fails straight away
        except (OSError, EOFError, paramiko.SSHException):
            pass

    def set_timeout(self, seconds):
        """Give up on any request the server takes longer than this to answer (None waits for ever)."""
        self.client.get_channel().settimeout(seconds)

    def entry(self, attributes, folder, name=None):
        name = name if name is not None else attributes.filename
        mode = attributes.st_mode or 0
        owner = group = ""
        longname = getattr(attributes, "longname", "") or ""
        parts = longname.split()
        if len(parts) >= 4:
            owner, group = parts[2], parts[3]
        entry = Entry(name=name, path=join(folder, name), is_dir=stat.S_ISDIR(mode), size=attributes.st_size or 0,
                      mtime=float(attributes.st_mtime or 0), mode=stat.S_IMODE(mode), owner=owner or
                      str(attributes.st_uid if attributes.st_uid is not None else ""),
                      group=group or str(attributes.st_gid if attributes.st_gid is not None else ""),
                      is_link=stat.S_ISLNK(mode), uid=attributes.st_uid, gid=attributes.st_gid)
        return entry

    def home(self):
        try:
            return self.client.normalize(".")
        except (OSError, paramiko.SSHException):
            return "/"

    def realpath(self, path):
        try:
            return self.client.normalize(path)
        except (OSError, paramiko.SSHException):
            return path

    def listdir(self, path):
        try:
            items = self.client.listdir_attr(path)
        except (OSError, paramiko.SSHException) as error:
            raise _sftp_error(error, path) from None
        entries = []
        for attributes in items:
            if attributes.filename in (".", ".."):
                continue
            entry = self.entry(attributes, path)
            if entry.is_link:  # Show where it points, and treat links to folders as folders
                try:
                    entry.link_target = self.client.readlink(entry.path) or ""
                    target = self.client.stat(entry.path)
                    entry.is_dir = stat.S_ISDIR(target.st_mode or 0)
                    if not entry.is_dir:
                        entry.size = target.st_size or 0
                except (OSError, paramiko.SSHException):
                    pass  # A broken link
            entries.append(entry)
        return entries

    def stat(self, path):
        try:
            attributes = self.client.stat(path)
        except FileNotFoundError:
            return None
        except (OSError, paramiko.SSHException) as error:
            if getattr(error, "errno", None) == errno.ENOENT:
                return None
            raise _sftp_error(error, path) from None
        return self.entry(attributes, parent(path), posixpath.basename(path.rstrip("/")) or "/")

    def _do(self, action, path, *arguments):
        try:
            return action(*arguments)
        except (OSError, paramiko.SSHException) as error:
            raise _sftp_error(error, path) from None

    def mkdir(self, path):
        self._do(self.client.mkdir, path, path)

    def rename(self, old, new):
        if self.stat(new) is not None:
            raise RemoteError(f"{posixpath.basename(new)} already exists.")
        self._do(self.client.rename, old, old, new)

    def replace(self, old, new):
        """Rename over an existing file (posix-rename@openssh.com if offered, otherwise remove then rename)."""
        try:
            self.client.posix_rename(old, new)
            return
        except (OSError, paramiko.SSHException):
            pass
        if self.stat(new) is not None:
            self.remove(new)
        self._do(self.client.rename, old, old, new)

    def remove(self, path):
        self._do(self.client.remove, path, path)

    def rmdir(self, path):
        self._do(self.client.rmdir, path, path)

    def chmod(self, path, mode):
        self._do(self.client.chmod, path, path, mode)

    def chown(self, path, owner=None, group=None):
        # SFTP only takes numbers, and both at once
        users, groups = self.accounts() if not all(str(value).isdigit() for value in (owner, group)
                                                   if value is not None) else ({}, {})
        current = None
        if owner is None or group is None:
            try:
                current = self.client.stat(path)
            except (OSError, paramiko.SSHException) as error:
                raise _sftp_error(error, path) from None
        uid = current.st_uid if owner is None else resolve_id(owner, users, "user")
        gid = current.st_gid if group is None else resolve_id(group, groups, "group")
        self._do(self.client.chown, path, path, uid, gid)

    def set_mtime(self, path, mtime):
        try:
            self.client.utime(path, (mtime, mtime))
        except (OSError, paramiko.SSHException):
            pass  # Not every server allows it; the file itself arrived fine

    def download(self, remote, local_file, offset=0, progress=None, cancelled=lambda: False):
        try:
            size = self.client.stat(remote).st_size or 0
            with self.client.open(remote, "rb") as source:
                # Pipelined reads, a window at a time: fast over slow links, but never more than one window
                # requested ahead (prefetching the whole file made a cancel wait for all of it to arrive)
                position = offset
                while position < size:
                    end = min(size, position + PREFETCH_WINDOW)
                    chunks = [(start, min(CHUNK, end - start)) for start in range(position, end, CHUNK)]
                    for data in source.readv(chunks):
                        if cancelled():
                            raise TransferCancelled()
                        local_file.write(data)
                        if progress is not None:
                            progress(len(data))
                    position = end
            return float(self.client.stat(remote).st_mtime or 0)
        except (OSError, paramiko.SSHException, EOFError) as error:
            raise _sftp_error(error, remote) from None

    def upload(self, local_file, size, remote, offset=0, mode=None, mtime=None, progress=None,
               cancelled=lambda: False):
        try:
            with self.client.open(remote, "r+b" if offset else "wb") as target:
                target.set_pipelined(True)
                if offset:
                    target.seek(offset)
                while True:
                    if cancelled():
                        raise TransferCancelled()
                    data = local_file.read(CHUNK)
                    if not data:
                        break
                    target.write(data)
                    if progress is not None:
                        progress(len(data))
            if mode is not None:
                self.client.chmod(remote, mode)
        except (OSError, paramiko.SSHException, EOFError) as error:
            raise _sftp_error(error, remote) from None
        if mtime is not None:
            self.set_mtime(remote, mtime)

    def close(self):
        try:
            self.client.close()
        except (OSError, paramiko.SSHException):
            pass


class ShellFS(RemoteFS):
    """For servers without SFTP: shell commands to browse, and scp to move files."""
    kind = SCP

    def __init__(self, connection):
        super().__init__(connection)
        self.gnu_ls = None  # Whether ls understands --time-style (GNU); found on first use
        self.channel = None  # The scp channel of the file being copied

    def abort(self):
        self.aborted = True
        channel = self.channel
        if channel is not None:
            channel.close()

    def run(self, command, path):
        status, out, err = self.connection.run(command)
        if status != 0:
            message = (err or out).decode("utf-8", "replace").strip().splitlines()
            raise RemoteError(message[-1] if message else f"{path}: the command failed (status {status}).")
        return out.decode("utf-8", "replace")

    def ls(self, arguments, path):
        if self.gnu_ls is not False:
            status, out, err = self.connection.run(f"LC_ALL=C ls {arguments} --time-style=full-iso {quote(path)}")
            if status == 0 or self.gnu_ls:
                self.gnu_ls = True
                if status != 0:
                    raise RemoteError((err or out).decode("utf-8", "replace").strip() or f"Can't list {path}.")
                return out.decode("utf-8", "replace")
            if b"time-style" not in err and b"unrecognized" not in err and b"illegal" not in err \
                    and b"invalid" not in err:
                raise RemoteError(err.decode("utf-8", "replace").strip() or f"Can't list {path}.")
            self.gnu_ls = False
        return self.run(f"LC_ALL=C ls {arguments} {quote(path)}", path)

    def home(self):
        try:
            return self.run("pwd", "~").strip() or "/"
        except RemoteError:
            return "/"

    def realpath(self, path):
        try:
            return self.run(f"cd {quote(path)} && pwd -P", path).strip() or path
        except RemoteError:
            return path

    def listdir(self, path):
        entries = parse_ls(self.ls("-la", path.rstrip("/") + "/" if path != "/" else "/"), path)
        for entry in entries:
            if entry.is_link:
                status, _, _ = self.connection.run(f"test -d {quote(entry.path)}")
                entry.is_dir = status == 0
        return entries

    def stat(self, path):
        status, out, _ = self.connection.run(f"LC_ALL=C ls -lad {'--time-style=full-iso ' if self.gnu_ls else ''}"
                                             f"{quote(path)}")
        if status != 0:
            return None
        entries = parse_ls(out.decode("utf-8", "replace"), parent(path))
        if not entries:
            return None
        entry = entries[0]
        entry.name, entry.path = posixpath.basename(path.rstrip("/")) or "/", path
        return entry

    def mkdir(self, path):
        self.run(f"mkdir {quote(path)}", path)

    def rename(self, old, new):
        if self.stat(new) is not None:
            raise RemoteError(f"{posixpath.basename(new)} already exists.")
        self.run(f"mv {quote(old)} {quote(new)}", old)

    def replace(self, old, new):
        self.run(f"mv -f {quote(old)} {quote(new)}", old)

    def remove(self, path):
        self.run(f"rm -f {quote(path)}", path)

    def rmdir(self, path):
        self.run(f"rmdir {quote(path)}", path)

    def chmod(self, path, mode):
        self.run(f"chmod {mode & 0o7777:o} {quote(path)}", path)

    def chown(self, path, owner=None, group=None):
        if owner is not None:
            self.run(f"chown {quote(str(owner) + (':' + str(group) if group is not None else ''))} {quote(path)}",
                     path)
        elif group is not None:
            self.run(f"chgrp {quote(str(group))} {quote(path)}", path)

    def set_mtime(self, path, mtime):
        stamp = time.strftime("%Y%m%d%H%M.%S", time.localtime(mtime))
        self.connection.run(f"touch -t {stamp} {quote(path)}")

    def download(self, remote, local_file, offset=0, progress=None, cancelled=lambda: False):
        if offset:
            raise RemoteError("SCP can't resume a transfer.")
        channel = self.channel = self.connection.exec_channel(f"scp -p -f {quote(remote)}")
        try:
            _, mtime = scp_receive(channel, local_file.write, progress, cancelled)
            return mtime
        except (OSError, EOFError, paramiko.SSHException) as error:
            raise RemoteError(f"The transfer stopped: {error}") from None
        finally:
            self.channel = None
            channel.close()

    def upload(self, local_file, size, remote, offset=0, mode=None, mtime=None, progress=None,
               cancelled=lambda: False):
        if offset:
            raise RemoteError("SCP can't resume a transfer.")
        channel = self.channel = self.connection.exec_channel(f"scp -p -t {quote(remote)}")
        try:
            scp_send(channel, local_file.read, size, posixpath.basename(remote), 0o644 if mode is None else mode,
                     mtime, progress, cancelled)
        except (OSError, EOFError, paramiko.SSHException) as error:
            raise RemoteError(f"The transfer stopped: {error}") from None
        finally:
            self.channel = None
            channel.close()


def make_remote_folders(fs, folder):
    """Create a remote folder and any missing parents (mkdir -p)."""
    missing = []
    while folder not in ("", "/") and fs.stat(folder) is None:
        missing.append(folder)
        folder = parent(folder)
    for path in reversed(missing):
        fs.mkdir(path)


def parse_ids(text):
    """{name: id} from /etc/passwd or /etc/group text."""
    found = {}
    for line in text.splitlines():
        parts = line.split(":")
        if len(parts) >= 3 and parts[0] and not parts[0].startswith("#") and parts[2].isdigit():
            found[parts[0]] = int(parts[2])
    return found


def resolve_id(value, names, kind):
    """A uid or gid from a name or number."""
    text = str(value).strip()
    if text.isdigit():
        return int(text)
    if text in names:
        return names[text]
    raise RemoteError(f"There's no {kind} called {text} on the server (or its /etc/{'passwd' if kind == 'user' else 'group'} "
                      "couldn't be read; the number works too).")


def chown_tree(fs, entry, owner=None, group=None, recursive=False, cancelled=lambda: False):
    """Change the owner and/or group of a file or folder, and optionally everything inside. Links are left alone
    (changing one over SFTP would change what it leads to)."""
    if not entry.is_link:
        fs.chown(entry.path, owner, group)
    if recursive and entry.is_dir and not entry.is_link:
        for _, child in fs.walk_files(entry.path, cancelled):
            if not child.is_link:
                fs.chown(child.path, owner, group)


def remove_tree(fs, entry, cancelled=lambda: False):
    """Delete a remote file, link or folder (with everything in it). Links are removed, not followed."""
    if not entry.is_dir or entry.is_link:
        fs.remove(entry.path)
        return
    for child in fs.listdir(entry.path):
        if cancelled():
            raise TransferCancelled()
        remove_tree(fs, child, cancelled)
    fs.rmdir(entry.path)


def folder_mode(mode):
    """A file mode for a folder: execute (enter) wherever read is allowed, as WinSCP's "Add X to directories"."""
    return mode | ((mode & 0o444) >> 2)


def chmod_tree(fs, entry, mode, recursive=False, cancelled=lambda: False):
    """Set permissions on a file or folder, and optionally everything inside (folders get X added)."""
    fs.chmod(entry.path, folder_mode(mode) if entry.is_dir and recursive else mode)
    if recursive and entry.is_dir and not entry.is_link:
        for _, child in fs.walk_files(entry.path, cancelled):
            if not child.is_link:
                fs.chmod(child.path, folder_mode(mode) if child.is_dir else mode)


# ----------------------------------------------------------------- A connection

class FileConnection:
    """One SSH login, with any number of file system channels on it (one to browse, one for the transfer queue)."""

    def __init__(self, session, prompter=None, vault=None, known_hosts=None, mode=None, sudo=None):
        self.session = session
        self.ssh = SshTransport(session, prompter, known_hosts=known_hosts)
        if vault is not None:
            self.ssh.vault = vault
        # SFTP, SCP, or None to use SFTP when the server has it; the session's File transfer setting by default
        self.mode = mode or {"SFTP": SFTP, "SCP": SCP}.get(getattr(session, "file_protocol", "Auto"))
        self.sudo = getattr(session, "scp_sudo", False) if sudo is None else sudo  # Work as root
        self.sudo_ready = False  # sudo has been checked (and its password found, if it needs one)
        self.sudo_password = None  # In memory only; None when sudo doesn't ask for one
        self.sftp_server = None
        self.kind = None
        self.description = ""
        self.notice = ""

    @property
    def transport(self):
        return self.ssh.transport

    def connect(self):
        """Log in (asking through the prompter as needed) and find out whether SFTP works. Returns the first file
        system, for browsing."""
        username = self.ssh.login()
        self.notice = self.ssh.notice
        try:
            fs = self.open_fs()
        except ConnectionFailed:
            self.close()
            raise
        if isinstance(fs, SftpFS):
            fs.set_timeout(BROWSE_TIMEOUT)  # A quiet network mustn't leave the pane waiting for ever
        self.description = f"{fs.kind}{' as root (sudo)' if self.sudo else ''} to {username}@" \
                           f"{self.session.host.strip()}"
        if fs.kind == SCP and self.mode != SCP:
            self.notice = ("This server doesn't offer SFTP, so NOMAD is using SCP: browsing uses ls, and interrupted "
                           "transfers start again rather than resuming.")
        return fs

    def open_fs(self):
        if self.sudo:
            return self.open_sudo_fs()
        if self.mode != SCP and self.kind != SCP:
            try:
                client = paramiko.SFTPClient.from_transport(self.transport)
                self.kind = SFTP
                return SftpFS(self, client)
            except (paramiko.SSHException, EOFError, OSError) as error:
                if self.mode == SFTP or not self.transport.is_active():
                    raise ConnectionFailed(f"The server wouldn't start SFTP: {error}") from None
                log.info("No SFTP on %s (%s); using SCP", self.session.host, error)
        self.kind = SCP
        return ShellFS(self)

    # ----------------------------------------------------------------- Sudo

    def open_sudo_fs(self):
        """SFTP as root: the server's sftp-server run through sudo, on an exec channel (as WinSCP does)."""
        if self.mode == SCP:
            raise ConnectionFailed("Sudo on the SCP page needs SFTP. Set the session's File transfer to Auto or SFTP.")
        if not self.sudo_ready:
            self.prepare_sudo()
        server = quote(self.sftp_server)
        if self.sudo_password is None:
            channel = self.exec_channel(f"sudo -n {server}")
        else:
            channel = self.exec_channel(f"sudo -S -p '' {server}")
            channel.sendall((self.sudo_password + "\n").encode())  # sudo reads one line; the rest is SFTP
        try:
            client = paramiko.SFTPClient(channel)
        except (paramiko.SSHException, EOFError, OSError) as error:
            detail = ""
            if channel.recv_stderr_ready():
                detail = channel.recv_stderr(4096).decode("utf-8", "replace").strip()
            channel.close()
            raise ConnectionFailed(f"sudo wouldn't start SFTP as root: {detail or error}") from None
        self.kind = SFTP
        fs = SftpFS(self, client)
        fs.as_root = True
        return fs

    def prepare_sudo(self):
        """Check sudo can be used, find sftp-server, and find the sudo password if it needs one (the login password
        first, then asking)."""
        host = self.session.host.strip()
        status, _, err = self.run("sudo -n true")
        if status == 127:
            raise ConnectionFailed(f"sudo isn't installed on {host}.")
        self.check_sudo_refusal(err)
        if status == 0:
            self.sudo_password = None  # Allowed without a password
        else:
            # The login password first (usually the sudo one too), then ask
            passwords = ([self.ssh.password] if self.ssh.password else []) + [None] * SUDO_TRIES
            prompt = f"Password for sudo on {host}:"
            for password in passwords:
                if password is None:
                    answer = self.ssh.prompter.secret("Sudo Password", prompt, False)
                    if answer is None:
                        raise Cancelled()
                    password = answer[0]
                status, _, err = self.run("sudo -S -p '' -v", stdin=(password + "\n").encode())
                self.check_sudo_refusal(err)
                if status == 0:
                    self.sudo_password = password
                    break
                prompt = "sudo didn't accept that password. Try again:" if password is not self.ssh.password else \
                    f"sudo didn't accept your login password. Password for sudo on {host}:"
            else:
                raise ConnectionFailed("sudo didn't accept the password.")
        status, out, _ = self.run(SFTP_SERVER_SEARCH)
        if status != 0 or not out.strip():
            raise ConnectionFailed(f"Couldn't find the sftp-server program on {host}, which sudo needs (usually "
                                   "/usr/lib/openssh/sftp-server or /usr/libexec/openssh/sftp-server).")
        self.sftp_server = out.decode("utf-8", "replace").strip().splitlines()[0]
        self.sudo_ready = True

    def check_sudo_refusal(self, err):
        """Raise with a clear message if sudo said no for a reason a password won't fix."""
        text = err.decode("utf-8", "replace")
        lower = text.lower()
        user = self.ssh.session.username or "This user"
        if "not in the sudoers" in lower or "may not run sudo" in lower or "not allowed to" in lower:
            raise ConnectionFailed(f"{user} isn't allowed to use sudo on {self.session.host.strip()}.")
        if "must have a tty" in lower or "no tty present" in lower:
            raise ConnectionFailed("sudo on this server needs a terminal (requiretty in sudoers), so it can't be used "
                                   "for file transfer. Ask for requiretty to be turned off for your user.")

    def exec_channel(self, command):
        try:
            channel = self.transport.open_session()
            channel.exec_command(command)
            return channel
        except (paramiko.SSHException, EOFError, OSError) as error:
            raise RemoteError(f"The server wouldn't run a command: {error}") from None

    def run(self, command, timeout=EXEC_TIMEOUT, stdin=None):
        """Run a command, with stdin bytes if given. Returns (exit status, stdout bytes, stderr bytes)."""
        channel = self.exec_channel(command)
        if stdin is not None:
            try:
                channel.sendall(stdin)
                channel.shutdown_write()
            except (OSError, paramiko.SSHException, EOFError) as error:
                channel.close()
                raise RemoteError(f"The command failed: {error}") from None
        out, err = bytearray(), bytearray()
        deadline = time.monotonic() + timeout
        try:
            while True:
                busy = False
                while channel.recv_ready():
                    out += channel.recv(65536)
                    busy = True
                while channel.recv_stderr_ready():
                    err += channel.recv_stderr(65536)
                    busy = True
                if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() > deadline:
                    raise RemoteError(f"The server took more than {timeout} s to answer.")
                if not busy:
                    if channel.closed or not self.active:
                        raise RemoteError("The connection closed.")
                    time.sleep(0.005)
            return channel.recv_exit_status(), bytes(out), bytes(err)
        except (OSError, paramiko.SSHException, EOFError) as error:
            raise RemoteError(f"The command failed: {error}") from None
        finally:
            channel.close()

    @property
    def active(self):
        return self.transport is not None and self.transport.is_active()

    def close(self):
        self.ssh.close()


# ----------------------------------------------------------------- Transfers

UPLOAD, DOWNLOAD = "upload", "download"
QUEUED, RUNNING, DONE, FAILED, SKIPPED, CANCELLED, PAUSED = \
    "Queued", "Transferring", "Done", "Failed", "Skipped", "Cancelled", "Paused"
OVERWRITE, SKIP, RENAME, NEWER, ASK = "overwrite", "skip", "rename", "newer", "ask"


@dataclass
class Transfer:
    """One file (or folder, expanded when it runs) to copy."""
    direction: str
    local: str
    remote: str
    size: int = 0
    is_dir: bool = False
    verify: str = ""  # A HASHES name to check afterwards, or ""
    conflict: str = ""  # What to do if the target exists (OVERWRITE...), or "" for the queue's setting
    source_mtime: float = 0.0  # Filled in when it runs, for the "already exists" question
    state: str = QUEUED
    done: int = 0
    message: str = ""
    resumed_from: int = 0
    id: int = field(default_factory=lambda: next(_ids))

    @property
    def name(self):
        return os.path.basename(self.local) if self.direction == UPLOAD else posixpath.basename(self.remote)

    @property
    def source(self):
        return self.local if self.direction == UPLOAD else self.remote

    @property
    def target(self):
        return self.remote if self.direction == UPLOAD else self.local


def _counter():
    number = 0
    while True:
        number += 1
        yield number


_ids = _counter()


def unique_local_name(path):
    stem, extension = os.path.splitext(path)
    number = 2
    while os.path.exists(f"{stem} ({number}){extension}"):
        number += 1
    return f"{stem} ({number}){extension}"


def unique_remote_name(fs, path):
    stem, extension = posixpath.splitext(path)
    number = 2
    while fs.stat(f"{stem} ({number}){extension}") is not None:
        number += 1
    return f"{stem} ({number}){extension}"


def local_hash(path, algorithm="SHA-256", cancelled=lambda: False):
    digest = hashlib.new(HASHES[algorithm][0])
    with open(path, "rb") as file:
        while True:
            if cancelled():
                raise TransferCancelled()
            data = file.read(1 << 20)
            if not data:
                break
            digest.update(data)
    return digest.hexdigest()


def expand(fs, transfer, cancelled=lambda: False):
    """A folder transfer as the folders to create and the file transfers inside it: ([(kind, path)], [Transfer])."""
    folders, files = [], []
    if transfer.direction == UPLOAD:
        folders.append(transfer.remote)
        for folder, names, file_names in os.walk(transfer.local):
            names.sort()
            relative = os.path.relpath(folder, transfer.local)
            remote_folder = transfer.remote if relative == "." else join(transfer.remote,
                                                                          relative.replace(os.sep, "/"))
            for name in names:
                folders.append(join(remote_folder, name))
            for name in sorted(file_names):
                local = os.path.join(folder, name)
                files.append(Transfer(UPLOAD, local, join(remote_folder, name), os.path.getsize(local),
                                      verify=transfer.verify))
    else:
        folders.append(transfer.local)
        for relative, entry in fs.walk_files(transfer.remote, cancelled, follow_links=True):
            local = os.path.join(transfer.local, *relative.split("/"))
            if entry.is_dir:
                folders.append(local)
            else:
                files.append(Transfer(DOWNLOAD, local, entry.path, entry.size, verify=transfer.verify))
    return folders, files


class TransferRunner:
    """Copies one file at a time with a file system of its own. ask(transfer, existing) answers conflicts:
    returns (OVERWRITE / SKIP / RENAME / NEWER, apply to the rest). progress(transfer) reports as it goes."""

    def __init__(self, fs, conflict=ASK, ask=None, progress=None, preserve_times=True):
        self.fs = fs
        self.conflict = conflict
        self.ask = ask
        self.progress = progress or (lambda transfer: None)
        self.preserve_times = preserve_times
        self.cancel_current = False  # Set from another thread: stop this file (Cancel, or Pause)

    def cancelled(self):
        return self.cancel_current

    def cancel(self):
        """Stop the file being copied now (from another thread). The file system is aborted, so the caller opens a
        new one for the next file."""
        self.cancel_current = True
        self.fs.abort()

    def decide(self, transfer, existing):
        """What to do when the target exists: (OVERWRITE / SKIP / RENAME)."""
        choice = transfer.conflict or self.conflict
        if choice == ASK:
            choice, remember = self.ask(transfer, existing) if self.ask is not None else (OVERWRITE, False)
            if remember:
                self.conflict = choice
        if choice == NEWER:
            choice = OVERWRITE if transfer.source_mtime > existing.mtime + TIME_TOLERANCE else SKIP
        return choice

    def run(self, transfer):
        """Copy one file. Sets transfer.state (DONE, SKIPPED, FAILED, CANCELLED) and returns it."""
        self.cancel_current = False
        transfer.state, transfer.message, transfer.done = RUNNING, "", 0
        self.progress(transfer)
        try:
            if transfer.direction == UPLOAD:
                self.upload(transfer)
            else:
                self.download(transfer)
            if transfer.state == RUNNING and transfer.verify:
                self.verify(transfer)
            if transfer.state == RUNNING:
                transfer.state = DONE
        except TransferCancelled:
            transfer.state = CANCELLED
        except (RemoteError, OSError, EOFError, paramiko.SSHException) as error:
            if self.cancel_current:  # Aborting the channel broke whatever was running: that's the cancel
                transfer.state = CANCELLED
            elif isinstance(error, RemoteError):
                transfer.state, transfer.message = FAILED, str(error)
            elif isinstance(error, OSError):
                transfer.state, transfer.message = FAILED, f"{error.filename or transfer.local}: " \
                                                           f"{error.strerror or error}"
            else:
                transfer.state, transfer.message = FAILED, f"The transfer stopped: {error or 'connection closed'}"
        self.progress(transfer)
        return transfer

    def count(self, transfer):
        def add(amount):
            transfer.done += amount
            self.progress(transfer)
        return add

    def download(self, transfer):
        remote = self.fs.stat(transfer.remote)
        if remote is None:
            raise RemoteError(f"{transfer.remote} doesn't exist any more.")
        transfer.size, transfer.source_mtime = remote.size, remote.mtime
        if os.path.exists(transfer.local):
            info = os.stat(transfer.local)
            choice = self.decide(transfer, Entry(os.path.basename(transfer.local), transfer.local,
                                                 size=info.st_size, mtime=info.st_mtime))
            if choice == SKIP:
                transfer.state, transfer.message = SKIPPED, "Already exists"
                return
            if choice == RENAME:
                transfer.local = unique_local_name(transfer.local)
        os.makedirs(os.path.dirname(transfer.local) or ".", exist_ok=True)
        part = transfer.local + PART_SUFFIX
        offset = 0
        if self.fs.can_resume and os.path.exists(part):
            offset = os.path.getsize(part)
            if offset > remote.size:
                offset = 0
        transfer.resumed_from = transfer.done = offset
        try:
            with open(part, "ab" if offset else "wb") as file:
                mtime = self.fs.download(transfer.remote, file, offset, self.count(transfer), self.cancelled)
        except BaseException:
            if not self.fs.can_resume and os.path.exists(part):
                os.remove(part)  # Can't be resumed, so it's no use
            raise
        if os.path.getsize(part) != remote.size:
            raise RemoteError(f"Got {os.path.getsize(part):,} of {remote.size:,} bytes; try again to resume.")
        replace_file(part, transfer.local)
        if self.preserve_times and (mtime or remote.mtime):
            stamp = mtime or remote.mtime
            os.utime(transfer.local, (stamp, stamp))

    def upload(self, transfer):
        info = os.stat(transfer.local)
        transfer.size, transfer.source_mtime = info.st_size, info.st_mtime
        existing = self.fs.stat(transfer.remote)
        mode = None
        if existing is None:
            make_remote_folders(self.fs, parent(transfer.remote))
        else:
            if existing.is_dir:
                raise RemoteError(f"{transfer.remote} is a folder.")
            choice = self.decide(transfer, existing)
            if choice == SKIP:
                transfer.state, transfer.message = SKIPPED, "Already exists"
                return
            if choice == RENAME:
                transfer.remote = unique_remote_name(self.fs, transfer.remote)
            else:
                mode = existing.mode & 0o7777  # Replacing a file keeps its permissions
        mtime = info.st_mtime if self.preserve_times else None
        if not self.fs.can_resume:
            with open(transfer.local, "rb") as file:
                self.fs.upload(file, info.st_size, transfer.remote, 0, 0o644 if mode is None else mode, mtime,
                               self.count(transfer), self.cancelled)
            return
        part = transfer.remote + PART_SUFFIX
        partial = self.fs.stat(part)
        offset = partial.size if partial is not None and partial.size <= info.st_size else 0
        transfer.resumed_from = transfer.done = offset
        with open(transfer.local, "rb") as file:
            file.seek(offset)
            self.fs.upload(file, info.st_size, part, offset, None, None, self.count(transfer), self.cancelled)
        uploaded = self.fs.stat(part)
        if uploaded is None or uploaded.size != info.st_size:
            raise RemoteError(f"Sent {uploaded.size if uploaded else 0:,} of {info.st_size:,} bytes; try again to "
                              "resume.")
        self.fs.replace(part, transfer.remote)
        if mode is not None:
            self.fs.chmod(transfer.remote, mode)
        if mtime is not None:
            self.fs.set_mtime(transfer.remote, mtime)

    def verify(self, transfer):
        transfer.message = f"Checking {transfer.verify}..."
        self.progress(transfer)
        mine = local_hash(transfer.local, transfer.verify, self.cancelled)
        theirs = self.fs.checksum(transfer.remote, transfer.verify, self.cancelled)
        if mine != theirs:
            transfer.state = FAILED
            transfer.message = f"{transfer.verify} doesn't match: local {mine[:16]}..., remote {theirs[:16]}..."
        else:
            transfer.message = f"{transfer.verify} verified"


# ----------------------------------------------------------------- Comparing folders (Synchronize)

LOCAL_ONLY, REMOTE_ONLY, LOCAL_NEWER, REMOTE_NEWER, DIFFERENT, SAME = \
    "Only here (local)", "Only on the server", "Newer here (local)", "Newer on the server", "Different", "Same"
TO_REMOTE, TO_LOCAL, BOTH_WAYS = "remote", "local", "both"


@dataclass
class Difference:
    relative: str  # "sub/file.conf"
    status: str
    local: object = None  # os.stat_result-like: (size, mtime) tuple
    remote: Entry = None
    action: str = ""  # UPLOAD, DOWNLOAD or "" (nothing)

    @property
    def local_size(self):
        return self.local[0] if self.local else None

    @property
    def local_mtime(self):
        return self.local[1] if self.local else None


def local_files(root, cancelled=lambda: False):
    """{relative path: (size, mtime)} of the files under a local folder."""
    found = {}
    for folder, names, file_names in os.walk(root):
        if cancelled():
            raise TransferCancelled()
        names[:] = sorted(name for name in names if not os.path.islink(os.path.join(folder, name)))
        relative = os.path.relpath(folder, root)
        for name in file_names:
            if name.endswith(PART_SUFFIX):
                continue
            path = os.path.join(folder, name)
            try:
                info = os.stat(path)
            except OSError:
                continue
            key = name if relative == "." else f"{relative.replace(os.sep, '/')}/{name}"
            found[key] = (info.st_size, info.st_mtime)
    return found


def remote_files(fs, root, cancelled=lambda: False):
    return {relative: entry for relative, entry in fs.walk_files(root, cancelled, follow_links=True)
            if not entry.is_dir and not entry.name.endswith(PART_SUFFIX)}


def compare(local, remote, direction, by_checksum=None):
    """Differences between {relative: (size, mtime)} and {relative: Entry}, with what Synchronize would do in a
    direction (TO_REMOTE, TO_LOCAL or BOTH_WAYS). by_checksum(relative) -> True if the contents match, for files of
    equal size (None compares by size and time only). Same files are included, with no action."""
    differences = []
    for relative in sorted(set(local) | set(remote), key=str.lower):
        mine, theirs = local.get(relative), remote.get(relative)
        if theirs is None:
            status = LOCAL_ONLY
        elif mine is None:
            status = REMOTE_ONLY
        else:
            size, mtime = mine
            newer_here = mtime > theirs.mtime + TIME_TOLERANCE
            newer_there = theirs.mtime > mtime + TIME_TOLERANCE
            if size != theirs.size:
                status = LOCAL_NEWER if newer_here else REMOTE_NEWER if newer_there else DIFFERENT
            elif by_checksum is not None:
                status = SAME if by_checksum(relative) else (LOCAL_NEWER if newer_here else
                                                            REMOTE_NEWER if newer_there else DIFFERENT)
            else:
                status = LOCAL_NEWER if newer_here else REMOTE_NEWER if newer_there else SAME
        differences.append(Difference(relative, status, mine, theirs, suggested_action(status, direction)))
    return differences


def suggested_action(status, direction):
    if status == SAME:
        return ""
    if direction == TO_REMOTE:  # Make the server match this computer, except where the server's copy is newer
        return UPLOAD if status in (LOCAL_ONLY, LOCAL_NEWER, DIFFERENT) else ""
    if direction == TO_LOCAL:
        return DOWNLOAD if status in (REMOTE_ONLY, REMOTE_NEWER, DIFFERENT) else ""
    return {LOCAL_ONLY: UPLOAD, LOCAL_NEWER: UPLOAD, REMOTE_ONLY: DOWNLOAD, REMOTE_NEWER: DOWNLOAD}.get(status, "")
