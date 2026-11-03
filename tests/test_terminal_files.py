import hashlib
import os
import shlex
import socket
import stat
import threading
import time

import paramiko
import pytest

from nomad.terminal.files import BOTH_WAYS, CANCELLED, DIFFERENT, DONE, DOWNLOAD, FAILED, LOCAL_NEWER, LOCAL_ONLY, \
    NEWER, OVERWRITE, PART_SUFFIX, QUEUED, REMOTE_NEWER, REMOTE_ONLY, RENAME, SAME, SCP, SFTP, SKIP, SKIPPED, TO_LOCAL, \
    TO_REMOTE, UPLOAD, Entry, FileConnection, RemoteError, RemoteFS, ShellFS, Transfer, TransferRunner, chmod_tree, compare, \
    SFTP_SERVER_SEARCH, chown_tree, download_transfer, expand, folder_mode, local_files, local_name_problem, local_path, parse_ids, parse_ls, parse_permissions, permission_text, remote_files, remove_tree, \
    scp_receive, scp_send
from nomad.terminal.hostkeys import KnownHosts
from nomad.terminal.sessions import SSH, Session
from nomad.terminal.transports import Cancelled, ConnectionFailed, Prompter


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


# ----------------------------------------------------------------- A small SSH server with SFTP over a folder

class SlowHandle(paramiko.SFTPHandle):
    """Answers reads and writes slowly, like a server over a slow link."""
    delay = 0.0

    def read(self, offset, length):
        time.sleep(self.delay)
        return super().read(offset, length)

    def write(self, offset, data):
        time.sleep(self.delay)
        return super().write(offset, data)


class FolderSFTP(paramiko.SFTPServerInterface):
    root = ""

    def __init__(self, server, *args, **kwargs):
        super().__init__(server, *args, **kwargs)

    def real(self, path):
        return os.path.join(self.root, self.canonicalize(path).lstrip("/"))

    def canonicalize(self, path):
        path = path if path.startswith("/") else "/home/admin/" + path
        return os.path.normpath(path).replace("\\", "/") or "/"

    def list_folder(self, path):
        folder = self.real(path)
        try:
            items = []
            for name in os.listdir(folder):
                attributes = paramiko.SFTPAttributes.from_stat(os.lstat(os.path.join(folder, name)))
                attributes.filename = name
                items.append(attributes)
            return items
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    def stat(self, path):
        try:
            return paramiko.SFTPAttributes.from_stat(os.stat(self.real(path)))
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)

    lstat = stat

    def open(self, path, flags, attr):
        real = self.real(path)
        try:
            binary = getattr(os, "O_BINARY", 0)
            descriptor = os.open(real, flags | binary, 0o666)
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)
        if flags & os.O_WRONLY:
            mode = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            mode = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            mode = "rb"
        handle = SlowHandle(flags)
        handle.filename = real
        handle.readfile = handle.writefile = os.fdopen(descriptor, mode)
        return handle

    def remove(self, path):
        try:
            os.remove(self.real(path))
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)
        return paramiko.SFTP_OK

    def rename(self, old, new):
        if os.path.exists(self.real(new)):
            return paramiko.SFTP_FAILURE
        os.rename(self.real(old), self.real(new))
        return paramiko.SFTP_OK

    def posix_rename(self, old, new):
        os.replace(self.real(old), self.real(new))
        return paramiko.SFTP_OK

    def mkdir(self, path, attr):
        try:
            os.mkdir(self.real(path))
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)
        return paramiko.SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(self.real(path))
        except OSError as error:
            return paramiko.SFTPServer.convert_errno(error.errno)
        return paramiko.SFTP_OK

    def chattr(self, path, attr):
        real = self.real(path)
        if attr.st_mode is not None:
            FileServer.modes[self.canonicalize(path)] = attr.st_mode
        if attr.st_uid is not None:
            FileServer.owners[self.canonicalize(path)] = (attr.st_uid, attr.st_gid)
        if attr.st_mtime is not None:
            os.utime(real, (attr.st_atime or attr.st_mtime, attr.st_mtime))
        return paramiko.SFTP_OK


class FileServer(paramiko.ServerInterface):
    modes = {}  # chmod calls seen (Windows can't store Unix modes)
    owners = {}  # chown calls seen: path: (uid, gid)

    def __init__(self, root, sftp=True, exec_commands=True, sudo="secret", sudoers=True):
        self.root, self.sftp, self.exec_commands = root, sftp, exec_commands
        self.sudo = sudo  # sudo's password for admin, or None if sudo doesn't ask (NOPASSWD)
        self.sudoers = sudoers  # admin may use sudo at all
        self.commands = []

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("admin", "secret") else paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_subsystem_request(self, channel, name):
        if not self.sftp:
            return False
        return super().check_channel_subsystem_request(channel, name)

    def check_channel_exec_request(self, channel, command):
        if not self.exec_commands:
            return False
        command = command.decode()
        self.commands.append(command)
        # A moment later, as a real server does: answering and closing before this returns (and paramiko confirms
        # the request) would look to the client like a channel that closed at once
        timer = threading.Timer(0.05, self.execute, args=(channel, command))
        timer.daemon = True
        timer.start()
        return True

    @staticmethod
    def read_line(channel):
        line = b""
        while not line.endswith(b"\n"):
            byte = channel.recv(1)
            if not byte:
                break
            line += byte
        return line.rstrip(b"\n").decode()

    def fake_sudo(self, channel, command):
        """Like sudo: -n (no password), -S (password on stdin), -v (just check it), and running sftp-server.
        Returns True if it handled the command."""
        refused = b"Sorry, user admin may not run sudo on test.\n"
        if command == SFTP_SERVER_SEARCH:
            channel.sendall(b"/usr/lib/openssh/sftp-server\n")
            channel.send_exit_status(0)
        elif command == "sudo -n true":
            if not self.sudoers:
                channel.sendall_stderr(refused)
            elif self.sudo is not None:
                channel.sendall_stderr(b"sudo: a password is required\n")
            channel.send_exit_status(0 if self.sudoers and self.sudo is None else 1)
        elif command.startswith("sudo -S -p '' -v"):
            ok = self.read_line(channel) == self.sudo
            if not ok:
                channel.sendall_stderr(b"Sorry, try again.\nsudo: 1 incorrect password attempt\n")
            channel.send_exit_status(0 if ok else 1)
        elif command.endswith("/usr/lib/openssh/sftp-server") and command.startswith("sudo "):
            if command.startswith("sudo -S") and self.read_line(channel) != self.sudo:
                channel.sendall_stderr(b"sudo: 1 incorrect password attempt\n")
                channel.send_exit_status(1)
            else:
                # sftp-server as root: serve SFTP on this exec channel, as the real one does
                handler = paramiko.SFTPServer(channel, "sftp", self, FolderSFTP)
                handler.start()
                return True
        else:
            return False
        channel.close()
        return True

    def execute(self, channel, command):
        if self.fake_sudo(channel, command):
            return
        words = shlex.split(command)
        path = os.path.join(self.root, words[-1].lstrip("/")) if words else ""
        if words[:1] == ["sha256sum"] and os.path.isfile(path):
            with open(path, "rb") as file:
                digest = hashlib.sha256(file.read()).hexdigest()
            channel.sendall(f"{digest}  {words[-1]}\n".encode())
            channel.send_exit_status(0)
        else:
            channel.sendall_stderr(f"sh: {words[0] if words else ''}: not found\n".encode())
            channel.send_exit_status(127)
        channel.close()


def run_file_server(host_key, root, **options):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    server = FileServer(root, **options)
    FolderSFTP.root = root

    def serve(connection):
        transport = paramiko.Transport(connection)
        transport.add_server_key(host_key)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, FolderSFTP)
        try:
            transport.start_server(server=server)
            while transport.is_active():
                time.sleep(0.05)
        except (EOFError, OSError, paramiko.SSHException):
            pass
        finally:
            transport.close()

    def accept():
        """Every connection (reconnecting makes a new one), until the test ends."""
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(connection,), daemon=True).start()

    threading.Thread(target=accept, daemon=True).start()
    return port, server


class PasswordPrompter(Prompter):
    def host_key(self, *args):
        return "once"

    def secret(self, title, prompt, can_save):
        return "secret", False


@pytest.fixture
def remote(tmp_path, host_key):
    """(connection, fs, server root, server) logged in over SFTP."""
    root = tmp_path / "server"
    (root / "home" / "admin").mkdir(parents=True)
    port, server = run_file_server(host_key, str(root))
    session = Session("files", SSH, "127.0.0.1", port, username="admin")
    connection = FileConnection(session, PasswordPrompter(), known_hosts=KnownHosts(str(tmp_path / "known")))
    fs = connection.connect()
    yield connection, fs, root, server
    connection.close()


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


# ----------------------------------------------------------------- Browsing over SFTP

def test_sftp_browse_and_change_things(remote):
    connection, fs, root, _ = remote
    assert fs.kind == SFTP and fs.can_resume
    assert connection.description.startswith("SFTP to admin@127.0.0.1")
    assert fs.home() == "/home/admin"
    write(root / "etc" / "nginx.conf", b"worker_processes 1;\n")
    fs.mkdir("/etc/sites")
    names = {entry.name: entry for entry in fs.listdir("/etc")}
    assert set(names) == {"nginx.conf", "sites"}
    assert names["sites"].is_dir and names["nginx.conf"].size == 20
    assert fs.stat("/etc/nginx.conf").size == 20 and fs.stat("/etc/missing") is None
    fs.rename("/etc/nginx.conf", "/etc/nginx.old")
    with pytest.raises(RemoteError, match="already exists"):
        fs.rename("/etc/nginx.old", "/etc/sites")
    fs.chmod("/etc/nginx.old", 0o600)
    assert FileServer.modes["/etc/nginx.old"] == 0o600
    fs.remove("/etc/nginx.old")
    fs.rmdir("/etc/sites")
    assert fs.listdir("/etc") == []
    with pytest.raises(RemoteError, match="doesn't exist"):
        fs.listdir("/nowhere")


def test_delete_and_chmod_folders(remote):
    _, fs, root, _ = remote
    write(root / "site" / "index.html", b"x")
    write(root / "site" / "css" / "a.css", b"y")
    FileServer.modes.clear()
    chmod_tree(fs, fs.stat("/site"), 0o640, recursive=True)
    assert FileServer.modes == {"/site": 0o750, "/site/css": 0o750, "/site/index.html": 0o640,
                                "/site/css/a.css": 0o640}
    assert folder_mode(0o644) == 0o755 and folder_mode(0o600) == 0o700
    remove_tree(fs, fs.stat("/site"))
    assert not (root / "site").exists()


def test_checksum_on_the_server_or_by_reading(remote):
    connection, fs, root, server = remote
    data = os.urandom(100_000)
    write(root / "fw.bin", data)
    assert fs.checksum("/fw.bin") == hashlib.sha256(data).hexdigest()
    assert any(command.startswith("sha256sum") for command in server.commands)
    # md5sum isn't on this server: NOMAD reads the file and works it out itself
    assert fs.checksum("/fw.bin", "MD5") == hashlib.md5(data).hexdigest()


# ----------------------------------------------------------------- Transfers

def test_upload_and_download_with_verify(remote, tmp_path):
    _, fs, root, _ = remote
    data = os.urandom(300_000)
    local = write(tmp_path / "local" / "image.bin", data)
    os.utime(local, (1_700_000_000, 1_700_000_000))
    seen = []
    runner = TransferRunner(fs, progress=lambda transfer: seen.append(transfer.done))
    up = runner.run(Transfer(UPLOAD, str(local), "/image.bin", verify="SHA-256"))
    assert up.state == DONE, up.message
    assert up.message == "SHA-256 verified"
    assert (root / "image.bin").read_bytes() == data
    assert int(os.path.getmtime(root / "image.bin")) == 1_700_000_000  # Times kept
    assert not (root / ("image.bin" + PART_SUFFIX)).exists()
    assert seen[-1] == len(data)

    down = runner.run(Transfer(DOWNLOAD, str(tmp_path / "back" / "image.bin"), "/image.bin", verify="SHA-256"))
    assert down.state == DONE, down.message
    assert (tmp_path / "back" / "image.bin").read_bytes() == data
    assert int(os.path.getmtime(tmp_path / "back" / "image.bin")) == 1_700_000_000


def test_download_resumes_from_a_filepart(remote, tmp_path):
    _, fs, root, _ = remote
    data = os.urandom(200_000)
    write(root / "big.iso", data)
    target = tmp_path / "big.iso"
    write(tmp_path / ("big.iso" + PART_SUFFIX), data[:75_000])
    transfer = TransferRunner(fs).run(Transfer(DOWNLOAD, str(target), "/big.iso"))
    assert transfer.state == DONE and transfer.resumed_from == 75_000
    assert target.read_bytes() == data
    assert not (tmp_path / ("big.iso" + PART_SUFFIX)).exists()


def test_upload_resumes_from_a_remote_filepart(remote, tmp_path):
    _, fs, root, _ = remote
    data = os.urandom(200_000)
    local = write(tmp_path / "big.iso", data)
    write(root / ("big.iso" + PART_SUFFIX), data[:120_000])
    transfer = TransferRunner(fs).run(Transfer(UPLOAD, str(local), "/big.iso"))
    assert transfer.state == DONE and transfer.resumed_from == 120_000
    assert (root / "big.iso").read_bytes() == data


def test_cancel_leaves_a_part_to_resume(remote, tmp_path):
    _, fs, root, _ = remote
    write(root / "big.iso", os.urandom(400_000))
    runner = TransferRunner(fs)

    def progress(transfer):
        if transfer.done > 100_000:
            runner.cancel_current = True
    runner.progress = progress
    transfer = runner.run(Transfer(DOWNLOAD, str(tmp_path / "big.iso"), "/big.iso"))
    assert transfer.state == CANCELLED
    assert (tmp_path / ("big.iso" + PART_SUFFIX)).exists() and not (tmp_path / "big.iso").exists()
    runner.progress = lambda transfer: None
    again = runner.run(Transfer(DOWNLOAD, str(tmp_path / "big.iso"), "/big.iso"))
    assert again.state == DONE and again.resumed_from > 100_000
    assert (tmp_path / "big.iso").read_bytes() == (root / "big.iso").read_bytes()


@pytest.fixture
def slow_server():
    SlowHandle.delay = 0.004  # About 8 MB/s: the file below takes seconds to finish
    yield
    SlowHandle.delay = 0.0


def cancel_part_way(runner, transfer, threshold):
    """Run a transfer on a thread, cancel it once threshold bytes are done, and time how long the cancel takes."""
    started = threading.Event()

    def progress(item):
        if item.done > threshold:
            started.set()
    runner.progress = progress
    thread = threading.Thread(target=runner.run, args=(transfer,))
    thread.start()
    assert started.wait(10)
    begun = time.monotonic()
    runner.cancel()
    thread.join(10)
    return time.monotonic() - begun


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")  # paramiko's read-ahead thread dies
def test_cancel_stops_a_big_download_straight_away(remote, tmp_path, slow_server):
    connection, _, root, _ = remote
    data = os.urandom(24_000_000)
    write(root / "big.iso", data)
    fs = connection.open_fs()
    runner = TransferRunner(fs)
    transfer = Transfer(DOWNLOAD, str(tmp_path / "big.iso"), "/big.iso")
    took = cancel_part_way(runner, transfer, 500_000)
    assert transfer.state == CANCELLED and took < 1.5, (transfer.state, took)  # Not after the rest arrives
    assert fs.aborted and not (tmp_path / "big.iso").exists()
    part_size = (tmp_path / ("big.iso" + PART_SUFFIX)).stat().st_size
    assert 0 < part_size < len(data)
    # The login is still good: a new channel resumes from the part
    SlowHandle.delay = 0.0
    again = TransferRunner(connection.open_fs()).run(Transfer(DOWNLOAD, str(tmp_path / "big.iso"), "/big.iso"))
    assert again.state == DONE and again.resumed_from == part_size
    assert (tmp_path / "big.iso").read_bytes() == data


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")  # paramiko's read-ahead thread dies
def test_cancel_stops_a_big_upload_straight_away(remote, tmp_path, slow_server):
    connection, _, root, _ = remote
    local = write(tmp_path / "big.iso", os.urandom(24_000_000))
    runner = TransferRunner(connection.open_fs())
    transfer = Transfer(UPLOAD, str(local), "/big.iso")
    took = cancel_part_way(runner, transfer, 500_000)
    assert transfer.state == CANCELLED and took < 1.5, (transfer.state, took)
    assert not (root / "big.iso").exists()


def test_conflicts_skip_rename_newer_and_ask(remote, tmp_path):
    _, fs, root, _ = remote
    write(root / "a.conf", b"server")
    local = write(tmp_path / "a.conf", b"local copy")
    os.utime(local, (1_000_000, 1_000_000))  # Much older than the server's

    assert TransferRunner(fs, SKIP).run(Transfer(UPLOAD, str(local), "/a.conf")).state == SKIPPED
    renamed = TransferRunner(fs, RENAME).run(Transfer(UPLOAD, str(local), "/a.conf"))
    assert renamed.state == DONE and renamed.remote == "/a (2).conf"
    assert TransferRunner(fs, NEWER).run(Transfer(UPLOAD, str(local), "/a.conf")).state == SKIPPED
    assert (root / "a.conf").read_bytes() == b"server"

    asked = []

    def ask(transfer, existing):
        asked.append(existing.size)
        return OVERWRITE, True
    runner = TransferRunner(fs, ask=ask)
    assert runner.run(Transfer(UPLOAD, str(local), "/a.conf")).state == DONE
    assert runner.run(Transfer(UPLOAD, str(local), "/a (2).conf")).state == DONE
    assert asked == [6]  # "Apply to all" answered the second
    assert (root / "a.conf").read_bytes() == b"local copy"


def test_upload_makes_missing_folders_and_per_transfer_conflict(remote, tmp_path):
    _, fs, root, _ = remote
    local = write(tmp_path / "b.conf", b"new")
    assert TransferRunner(fs).run(Transfer(UPLOAD, str(local), "/deep/er/b.conf")).state == DONE
    assert (root / "deep" / "er" / "b.conf").read_bytes() == b"new"
    write(tmp_path / "b.conf", b"newer")
    runner = TransferRunner(fs, SKIP)
    assert runner.run(Transfer(UPLOAD, str(local), "/deep/er/b.conf", conflict=OVERWRITE)).state == DONE
    assert (root / "deep" / "er" / "b.conf").read_bytes() == b"newer"


def test_missing_source_fails_cleanly(remote, tmp_path):
    _, fs, _, _ = remote
    transfer = TransferRunner(fs).run(Transfer(DOWNLOAD, str(tmp_path / "x"), "/nope"))
    assert transfer.state == FAILED and "doesn't exist" in transfer.message


def test_expand_folders_both_ways(remote, tmp_path):
    _, fs, root, _ = remote
    write(tmp_path / "site" / "index.html", b"hi")
    write(tmp_path / "site" / "css" / "main.css", b"body{}")
    (tmp_path / "site" / "empty").mkdir()
    folders, files = expand(fs, Transfer(UPLOAD, str(tmp_path / "site"), "/var/www", is_dir=True))
    assert folders == ["/var/www", "/var/www/css", "/var/www/empty"]
    assert sorted(item.remote for item in files) == ["/var/www/css/main.css", "/var/www/index.html"]

    write(root / "logs" / "a.log", b"1")
    write(root / "logs" / "old" / "b.log", b"22")
    folders, files = expand(fs, Transfer(DOWNLOAD, str(tmp_path / "logs"), "/logs", is_dir=True))
    assert folders == [str(tmp_path / "logs"), str(tmp_path / "logs" / "old")]
    assert sorted((item.remote, item.size) for item in files) == [("/logs/a.log", 1), ("/logs/old/b.log", 2)]


@pytest.mark.parametrize("name", ["..", ".", "", r"..\..\Startup\x.bat", "C:evil.bat", r"C:\x.bat",
                                  "file.txt:hidden", "bad\x01name", "trailing.", "trailing ", "CON", "nul.txt",
                                  "com1", "LPT9.log", 'quote".txt', "pipe|x", "star*"])
def test_names_windows_cant_use_are_refused(name, tmp_path):
    assert local_name_problem(name)
    with pytest.raises(RemoteError):
        local_path(str(tmp_path), name)
    with pytest.raises(RemoteError):
        local_path(str(tmp_path), f"ok/{name}/deeper")


@pytest.mark.parametrize("name", ["running-config", "a.b.c", ".bashrc", "...x", "with space.txt", "CONSOLE.txt",
                                  "com10", "ünïcode.txt"])
def test_ordinary_names_are_kept(name, tmp_path):
    assert local_name_problem(name) == "" and local_name_problem("a/b")
    assert local_path(str(tmp_path), f"sub/{name}") == os.path.join(str(tmp_path), "sub", name)


class HostileFS(RemoteFS):
    """A server whose listing names files so as to land outside the download folder on Windows."""

    def __init__(self, listing):
        super().__init__(None)
        self.listing = listing

    def listdir(self, path):
        return self.listing.get(path, [])

    def stat(self, path):
        return next((entry for entries in self.listing.values() for entry in entries if entry.path == path), None)

    def download(self, remote, local_file, offset=0, progress=None, cancelled=lambda: False):
        local_file.write(b"payload")
        return 0


def test_hostile_names_in_a_folder_download_save_nothing_outside_it(tmp_path):
    target = tmp_path / "into"
    fs = HostileFS({"/logs": [Entry("ok.log", "/logs/ok.log", size=7),
                              Entry(r"..\..\escaped.bat", r"/logs/..\..\escaped.bat", size=7),
                              Entry("C:evil.bat", "/logs/C:evil.bat", size=7),
                              Entry("bad..", "/logs/bad..", is_dir=True)],
                    "/logs/bad..": [Entry("inside.log", "/logs/bad../inside.log", size=7)]})
    folders, files = expand(fs, Transfer(DOWNLOAD, str(target), "/logs", is_dir=True))
    assert folders == [str(target)]
    by_remote = {item.remote: item for item in files}
    assert by_remote["/logs/ok.log"].state != FAILED and by_remote["/logs/ok.log"].local == str(target / "ok.log")
    refused = [by_remote[path] for path in (r"/logs/..\..\escaped.bat", "/logs/C:evil.bat", "/logs/bad../inside.log")]
    assert all(item.state == FAILED and item.local == "" and "Not copied" in item.message for item in refused)

    runner = TransferRunner(fs)
    for item in files:  # Even run (or retried) they save nothing
        item.state = QUEUED
        runner.run(item)
    assert (target / "ok.log").read_bytes() == b"payload"
    assert [item.state for item in refused] == [FAILED] * 3
    assert sorted(path.name for path in tmp_path.rglob("*")) == ["into", "ok.log"]
    assert not list(tmp_path.parent.glob("escaped.bat")) and not os.path.exists(PART_SUFFIX)


def test_a_folder_download_with_nowhere_to_go_is_refused(tmp_path):
    with pytest.raises(RemoteError):
        expand(HostileFS({}), Transfer(DOWNLOAD, "", "/logs", is_dir=True))


def test_download_transfer_marks_unusable_names_failed(tmp_path):
    good = download_transfer(str(tmp_path), "sub/a.conf", "/x/sub/a.conf", 5, conflict=OVERWRITE)
    assert good.local == str(tmp_path / "sub" / "a.conf") and good.state == QUEUED and good.conflict == OVERWRITE
    bad = download_transfer(str(tmp_path), r"sub\..\..\a.conf", "/x/a.conf", 5, is_dir=True)
    assert bad.state == FAILED and bad.local == "" and bad.is_dir and "Windows" in bad.message


# ----------------------------------------------------------------- Without SFTP

def test_falls_back_to_scp_without_the_sftp_subsystem(tmp_path, host_key):
    port, _ = run_file_server(host_key, str(tmp_path), sftp=False)
    connection = FileConnection(Session("x", SSH, "127.0.0.1", port, username="admin"), PasswordPrompter(),
                                known_hosts=KnownHosts(str(tmp_path / "known")))
    try:
        fs = connection.connect()
        assert fs.kind == SCP and not fs.can_resume
        assert "doesn't offer SFTP" in connection.notice
    finally:
        connection.close()


class FakeConnection:
    """Answers ShellFS's commands from a script."""

    def __init__(self, answers):
        self.answers, self.commands = answers, []

    def run(self, command):
        self.commands.append(command)
        for start, answer in self.answers:
            if command.startswith(start):
                return answer
        return 127, b"", b"not found"


def test_shell_listing_falls_back_from_gnu_ls():
    busybox = (b"drwxr-xr-x    2 root     root          4096 Jan  5  2024 .\n"
               b"-rw-r--r--    1 root     root           512 Mar  3 10:15 startup config\n")
    connection = FakeConnection([("LC_ALL=C ls -la --time-style", (1, b"", b"ls: unrecognized option")),
                                 ("LC_ALL=C ls -la ", (0, busybox, b""))])
    fs = ShellFS(connection)
    entries = fs.listdir("/flash")
    assert [(entry.name, entry.path, entry.size) for entry in entries] == \
        [("startup config", "/flash/startup config", 512)]
    assert fs.gnu_ls is False
    fs.listdir("/flash")
    assert sum("time-style" in command for command in connection.commands) == 1  # Not tried again


# ----------------------------------------------------------------- Parsing and the scp protocol

def test_parse_ls_formats():
    gnu = """total 12
drwxr-xr-x  3 root root 4096 2026-09-01 10:20:30.123456789 +0000 .
drwxr-xr-x 20 root root 4096 2026-09-01 10:20:30.000000000 +0000 ..
-rw-r-----  1 www  adm   123 2026-08-02 04:05:06.500000000 +0000 access log.1
lrwxrwxrwx  1 root root    7 2026-01-01 00:00:00.000000000 +0000 current -> /var/x
drwsr-sr-t  2 root root 4096 2026-01-01 00:00:00.000000000 +0000 sticky
crw-rw-rw-  1 root root 1, 3 2026-01-01 00:00:00.000000000 +0000 null
"""
    entries = {entry.name: entry for entry in parse_ls(gnu, "/var/log")}
    assert set(entries) == {"access log.1", "current", "sticky", "null"}
    log_file = entries["access log.1"]
    assert (log_file.path, log_file.size, log_file.owner, log_file.group) == ("/var/log/access log.1", 123, "www", "adm")
    assert log_file.mode == 0o640 and log_file.permissions == "-rw-r-----"
    assert time.localtime(log_file.mtime)[:6] == (2026, 8, 2, 4, 5, 6)
    assert entries["current"].is_link and entries["current"].link_target == "/var/x"
    assert entries["sticky"].is_dir and entries["sticky"].permissions == "drwsr-sr-t"
    assert entries["null"].size == 0

    now = time.mktime((2026, 3, 10, 12, 0, 0, 0, 0, -1))
    bsd = "-rw-r--r--  1 admin  staff  42 Dec 24 18:30 notes.txt\n-rw-r--r--  1 admin  staff  1 Jan  2  2019 old\n"
    notes, old = parse_ls(bsd, "/Users/admin", now)
    assert time.localtime(notes.mtime)[:5] == (2025, 12, 24, 18, 30)  # December: last year
    assert time.localtime(old.mtime)[:3] == (2019, 1, 2)


def test_permission_text_round_trip():
    for mode in (0o755, 0o644, 0o4755, 0o2750, 0o1777, 0o4644, 0o000):
        assert parse_permissions(permission_text(mode)) == mode
    assert Entry("x", "/x", is_dir=True, mode=0o750).permissions == "drwxr-x---"


class ScriptedChannel:
    def __init__(self, incoming):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()

    def recv(self, size):
        data = bytes(self.incoming[:size])
        del self.incoming[:size]
        return data

    def sendall(self, data):
        self.sent += data


def test_scp_receive_and_send():
    body = b"hostname core-sw1\n" * 100
    channel = ScriptedChannel(b"T1700000000 0 1700000000 0\n" + f"C0644 {len(body)} running.cfg\n".encode() + body +
                              b"\x00")
    received = bytearray()
    size, mtime = scp_receive(channel, received.extend)
    assert (bytes(received), size, mtime) == (body, len(body), 1_700_000_000)
    assert bytes(channel.sent) == b"\x00" * 4

    channel = ScriptedChannel(b"\x00" * 4)
    source = iter([body[:1000], body[1000:]])
    scp_send(channel, lambda size: next(source), len(body), "new.cfg", 0o640, 1_700_000_000)
    assert bytes(channel.sent) == (b"T1700000000 0 1700000000 0\n" + f"C0640 {len(body)} new.cfg\n".encode() + body +
                                   b"\x00")

    with pytest.raises(RemoteError, match="Permission denied"):
        scp_receive(ScriptedChannel(b"\x01scp: /root/x: Permission denied\n"), received.extend)


# ----------------------------------------------------------------- Comparing folders

def test_compare_and_suggested_actions():
    old, new = 1_000_000.0, 2_000_000.0
    local = {"same.conf": (5, old), "mine.conf": (1, old), "edited.conf": (9, new), "stale.conf": (3, old),
             "tweaked.conf": (4, old)}
    remote = {"same.conf": Entry("same.conf", "/r/same.conf", size=5, mtime=old + 1),
              "theirs.conf": Entry("theirs.conf", "/r/theirs.conf", size=2, mtime=old),
              "edited.conf": Entry("edited.conf", "/r/edited.conf", size=8, mtime=old),
              "stale.conf": Entry("stale.conf", "/r/stale.conf", size=4, mtime=new),
              "tweaked.conf": Entry("tweaked.conf", "/r/tweaked.conf", size=4, mtime=old)}
    status = {item.relative: item.status for item in compare(local, remote, TO_REMOTE)}
    assert status == {"same.conf": SAME, "mine.conf": LOCAL_ONLY, "theirs.conf": REMOTE_ONLY,
                      "edited.conf": LOCAL_NEWER, "stale.conf": REMOTE_NEWER, "tweaked.conf": SAME}

    def actions(direction, **options):
        return {item.relative: item.action for item in compare(local, remote, direction, **options) if item.action}
    assert actions(TO_REMOTE) == {"mine.conf": UPLOAD, "edited.conf": UPLOAD}
    assert actions(TO_LOCAL) == {"theirs.conf": DOWNLOAD, "stale.conf": DOWNLOAD}
    assert actions(BOTH_WAYS) == {"mine.conf": UPLOAD, "edited.conf": UPLOAD, "theirs.conf": DOWNLOAD,
                                  "stale.conf": DOWNLOAD}
    # By checksum, a same-size same-time file with other contents is found
    by_hash = {item.relative: item.status for item in
               compare(local, remote, TO_REMOTE, by_checksum=lambda relative: relative != "tweaked.conf")}
    assert by_hash["tweaked.conf"] == DIFFERENT and by_hash["same.conf"] == SAME
    assert actions(TO_REMOTE, by_checksum=lambda relative: relative != "tweaked.conf")["tweaked.conf"] == UPLOAD


def test_compare_real_folders(remote, tmp_path):
    _, fs, root, _ = remote
    write(tmp_path / "cfg" / "a.conf", b"1")
    write(tmp_path / "cfg" / "sub" / "b.conf", b"22")
    write(tmp_path / "cfg" / ("partial" + PART_SUFFIX), b"x")
    write(root / "cfg" / "a.conf", b"1")
    os.utime(root / "cfg" / "a.conf", (os.path.getmtime(tmp_path / "cfg" / "a.conf"),) * 2)
    write(root / "cfg" / "c.conf", b"333")
    local = local_files(str(tmp_path / "cfg"))
    assert set(local) == {"a.conf", "sub/b.conf"}
    remote_side = remote_files(fs, "/cfg")
    assert set(remote_side) == {"a.conf", "c.conf"}
    result = {item.relative: item.status for item in compare(local, remote_side, BOTH_WAYS)}
    assert result == {"a.conf": SAME, "sub/b.conf": LOCAL_ONLY, "c.conf": REMOTE_ONLY}
    assert stat.S_ISREG(os.stat(tmp_path / "cfg" / "a.conf").st_mode)


# ----------------------------------------------------------------- Links to folders, protocol choice, old edit copies

class TreeFS(RemoteFS):
    """An in-memory tree with links: {path: [Entry]}, and where each link really goes."""

    def __init__(self, tree, links):
        super().__init__(None)
        self.tree, self.links = tree, links

    def listdir(self, path):
        return self.tree[self.links.get(path, path)]

    def realpath(self, path):
        return self.links.get(path, path)


def test_copying_follows_links_to_folders_but_not_loops():
    tree = {
        "/site": [Entry("index.html", "/site/index.html", size=1),
                  Entry("shared", "/site/shared", is_dir=True, is_link=True),
                  Entry("again", "/site/again", is_dir=True, is_link=True)],
        "/srv/shared": [Entry("logo.png", "/site/shared/logo.png", size=2)],
    }
    fs = TreeFS(tree, {"/site/shared": "/srv/shared", "/site/again": "/site"})  # "again" loops back to /site
    followed = sorted(relative for relative, _ in fs.walk_files("/site", follow_links=True))
    assert followed == ["index.html", "shared", "shared/logo.png"]  # The loop ("again") is left out entirely
    # Without following (delete and chmod), links are listed but never entered
    assert sorted(relative for relative, _ in fs.walk_files("/site")) == ["again", "index.html", "shared"]


def test_session_can_force_scp(tmp_path, host_key):
    root = tmp_path / "server"
    (root / "home" / "admin").mkdir(parents=True)
    port, _ = run_file_server(host_key, str(root))
    session = Session("x", SSH, "127.0.0.1", port, username="admin", file_protocol="SCP")
    connection = FileConnection(session, PasswordPrompter(), known_hosts=KnownHosts(str(tmp_path / "known")))
    try:
        assert connection.connect().kind == SCP  # SFTP is there, but the session asked for SCP
        assert "doesn't offer SFTP" not in connection.notice
    finally:
        connection.close()
    assert FileConnection(Session("y", SSH, file_protocol="SFTP")).mode == SFTP
    assert FileConnection(Session("z", SSH)).mode is None


def test_old_edit_copies_are_cleaned(tmp_path, monkeypatch):
    from nomad.ui import remote_editor
    monkeypatch.setattr(remote_editor, "EDIT_FOLDER", str(tmp_path))
    old, recent = tmp_path / "old1", tmp_path / "new1"
    write(old / "nginx.conf", b"x")
    write(recent / "motd", b"y")
    week_ago = time.time() - 7 * 86400
    for path in (old / "nginx.conf", old):
        os.utime(path, (week_ago, week_ago))
    assert remote_editor.clean_old_edits() == 1
    assert not old.exists() and recent.exists()


@pytest.mark.parametrize("name", ["setup.exe", "RUN.BAT", "fix.cmd", "script.ps1", "notes.txt.exe", "go.lnk",
                                  "site.url", "app.hta", "a.js", "a.vbs", "install.msi", "image.iso", "keys.reg",
                                  "help.chm", "bundle.pfx"])
def test_types_that_run_when_opened(name):
    from nomad.ui.remote_editor import runs_when_opened
    assert runs_when_opened(name)


@pytest.mark.parametrize("name", ["running-config", "router.cfg", "nginx.conf", "notes.txt", "syslog.log",
                                  "c2960-lanbasek9-mz.bin", "trace.pcapng", "data.json", "inventory.csv", "Makefile"])
def test_types_that_just_open(name):
    from nomad.ui.remote_editor import runs_when_opened
    assert not runs_when_opened(name)


@pytest.fixture
def startfile_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(os, "startfile", lambda path, *verb: calls.append((path, *verb)), raising=False)
    return calls


def test_default_program_opens_for_editing_and_never_runs(tmp_path, startfile_calls, monkeypatch):
    from nomad.ui.remote_editor import open_in_program
    program = write(tmp_path / "evil.exe", b"MZ")
    assert "wasn't opened" in open_in_program(str(program))
    assert startfile_calls == []

    text = write(tmp_path / "router.cfg", b"hostname r1")
    assert open_in_program(str(text)) == ""
    assert startfile_calls == [(str(text), "edit")]

    def no_edit_verb(path, *verb):
        if verb:
            raise OSError("No application is associated with the specified file for this operation")
        startfile_calls.append((path,))
    monkeypatch.setattr(os, "startfile", no_edit_verb)
    assert open_in_program(str(text)) == ""
    assert startfile_calls[-1] == (str(text),)  # Types without an edit verb are opened as usual

    startfile_calls.clear()
    monkeypatch.setattr(os, "startfile", lambda path, *verb: startfile_calls.append((path, *verb)))
    assert open_in_program(str(tmp_path)) == ""  # Show in Explorer
    assert startfile_calls == [(str(tmp_path),)]


class FakeScpView:
    """Just enough of an SCP tab for its edit methods."""

    def __init__(self, program="", choice=""):
        self.program, self.choice = program, choice
        self.failures, self.submitted, self.calls, self.editors = [], [], [], []

    def settings(self):
        return self

    def value(self, key, default="", kind=str):
        return self.program

    def fail(self, title, message):
        self.failures.append(message)

    def set_status(self, *arguments):
        pass

    def submit(self, work, done, failed):
        self.submitted.append(work)

    def instead_of_running(self, entry):
        self.calls.append(("instead", entry.name))
        return self.choice

    def choose_editor(self, entry):
        self.calls.append(("choose", entry.name))

    def edit_external(self, entry, program):
        self.calls.append(("edit", entry.name, program))


def test_a_file_windows_would_run_is_never_given_to_its_default_program(tmp_path, monkeypatch):
    from nomad.ui import remote_editor
    from nomad.ui.scp_view import FileSessionView as ScpView
    monkeypatch.setattr(remote_editor, "EDIT_FOLDER", str(tmp_path))
    view = FakeScpView(choice="")
    ScpView.edit_external(view, Entry("update.exe", "/tmp/update.exe"), "")
    assert view.calls == [("instead", "update.exe")] and view.submitted == []  # Cancelled: nothing downloaded

    view = FakeScpView(choice=remote_editor.notepad())
    ScpView.edit_external(view, Entry("fix.ps1", "/tmp/fix.ps1"), "")
    assert view.calls == [("instead", "fix.ps1")] and len(view.submitted) == 1

    view = FakeScpView()
    ScpView.edit_external(view, Entry("router.cfg", "/etc/router.cfg"), "")
    assert view.calls == [] and len(view.submitted) == 1  # Not a type that runs: Windows' editor for it


def test_a_big_file_never_goes_to_windows_default_program(monkeypatch):
    from nomad.ui import scp_view
    monkeypatch.setattr(scp_view.QMessageBox, "question", lambda *arguments: scp_view.QMessageBox.Yes)
    big = Entry("c9300-universalk9.SPA.exe", "/flash/c9300.exe", size=scp_view.EDITOR_LIMIT + 1)
    view = FakeScpView()
    scp_view.FileSessionView.open_remote_file(view, big)
    assert view.calls == [("choose", big.name)]  # No editor chosen yet: ask for one
    view = FakeScpView(program=r"C:\Tools\editor.exe")
    scp_view.FileSessionView.open_remote_file(view, big)
    assert view.calls == [("edit", big.name, r"C:\Tools\editor.exe")]


# ----------------------------------------------------------------- Sudo and owners

class SudoPrompter(PasswordPrompter):
    """Logs in with "secret"; answers sudo's question with sudo_answers, in turn."""

    def __init__(self, sudo_answers=()):
        self.sudo_answers, self.asked = list(sudo_answers), []

    def secret(self, title, prompt, can_save):
        if title == "Sudo Password":
            self.asked.append(prompt)
            return (self.sudo_answers.pop(0), False) if self.sudo_answers else None
        return "secret", False


def sudo_connection(tmp_path, host_key, prompter, **server_options):
    root = tmp_path / "server"
    (root / "home" / "admin").mkdir(parents=True, exist_ok=True)
    port, server = run_file_server(host_key, str(root), **server_options)
    connection = FileConnection(Session("x", SSH, "127.0.0.1", port, username="admin"), prompter,
                                known_hosts=KnownHosts(str(tmp_path / "known")), sudo=True)
    return connection, server, root


def test_sudo_with_the_login_password(tmp_path, host_key):
    prompter = SudoPrompter()
    connection, server, root = sudo_connection(tmp_path, host_key, prompter)
    try:
        fs = connection.connect()
        assert fs.as_root and connection.description.startswith("SFTP as root (sudo) to admin@")
        assert prompter.asked == []  # The login password worked for sudo
        write(root / "etc" / "shadow", b"x")
        assert [entry.name for entry in fs.listdir("/etc")] == ["shadow"]
        transfers = connection.open_fs()  # The queue's channel: root too, without checking the password again
        assert transfers.as_root and transfers.listdir("/etc")
        assert sum(command.startswith("sudo -S -p '' -v") for command in server.commands) == 1
        assert sum(command == "sudo -S -p '' /usr/lib/openssh/sftp-server" for command in server.commands) == 2
    finally:
        connection.close()


def test_sudo_asks_when_the_login_password_is_not_it(tmp_path, host_key):
    prompter = SudoPrompter(["wrong", "rootpw"])
    connection, _, _ = sudo_connection(tmp_path, host_key, prompter, sudo="rootpw")
    try:
        assert connection.connect().as_root
        assert "didn't accept your login password" in prompter.asked[0]
        assert "Try again" in prompter.asked[1]
    finally:
        connection.close()


def test_sudo_without_a_password_and_refusals(tmp_path, host_key):
    connection, server, _ = sudo_connection(tmp_path / "a", host_key, SudoPrompter(), sudo=None)
    try:
        assert connection.connect().as_root
        assert "sudo -n /usr/lib/openssh/sftp-server" in server.commands
    finally:
        connection.close()
    connection, _, _ = sudo_connection(tmp_path / "b", host_key, SudoPrompter(), sudoers=False)
    with pytest.raises(ConnectionFailed, match="isn't allowed to use sudo"):
        connection.connect()
    connection, _, _ = sudo_connection(tmp_path / "c", host_key, SudoPrompter(), sudo="other")
    with pytest.raises(Cancelled):  # The login password didn't work and the user cancelled the question
        connection.connect()


def test_chown_by_name_and_number(remote):
    _, fs, root, _ = remote
    write(root / "etc" / "passwd", b"root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n")
    write(root / "etc" / "group", b"root:x:0:\nadm:x:4:syslog\nwww-data:x:33:\n")
    assert parse_ids((root / "etc" / "group").read_text()) == {"root": 0, "adm": 4, "www-data": 33}
    write(root / "site" / "index.html", b"x")
    write(root / "site" / "css" / "a.css", b"y")
    FileServer.owners.clear()
    chown_tree(fs, fs.stat("/site"), "www-data", "adm", recursive=True)
    assert FileServer.owners == {"/site": (33, 4), "/site/css": (33, 4), "/site/index.html": (33, 4),
                                 "/site/css/a.css": (33, 4)}
    fs.chown("/site/index.html", "1001")  # A number; the group stays as it was
    assert FileServer.owners["/site/index.html"][0] == 1001
    with pytest.raises(RemoteError, match="no user called nobody-here"):
        fs.chown("/site/index.html", "nobody-here")
