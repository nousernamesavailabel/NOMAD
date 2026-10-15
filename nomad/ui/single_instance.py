"""One NOMAD per Windows account: opening it again brings the open copy to the front instead of starting another.

The open copy listens on a local (named pipe) server named for the account. A new copy says hello and is told the
open one's version and whether it runs as administrator; if it's the same NOMAD, it asks it to come to the front and
stops. Another version, or this copy running as administrator when the open one isn't, is asked about first.
"""
import ctypes
import logging
import os
import re

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtNetwork import QLocalServer, QLocalSocket

from ..system import APP_NAME

log = logging.getLogger(__name__)

CONNECT_MILLISECONDS = 500
REPLY_MILLISECONDS = 2000  # A copy still building its window answers once it's built; it shows itself then anyway
ASFW_ANY = -1


def server_name():
    """The local server's name: one per Windows account, the same whether running as administrator or not."""
    account = f"{os.environ.get('USERDOMAIN', '')}-{os.environ.get('USERNAME', '')}"
    return f"{APP_NAME}-" + re.sub(r"[^A-Za-z0-9_.-]", "_", account)


class RunningCopy:
    """The copy of NOMAD already open, as it said hello: its version and whether it runs as administrator (None
    when it didn't answer in time, still starting up)."""

    def __init__(self, version=None, admin=None):
        self.version = version
        self.admin = admin

    @property
    def answered(self):
        return self.version is not None


def find_running_copy(name=None):
    """Say hello to the copy of NOMAD already open, if there is one. Returns a RunningCopy and the connected socket
    (to ask it to come to the front, or close), or (None, None)."""
    socket = QLocalSocket()
    socket.connectToServer(name or server_name())
    if not socket.waitForConnected(CONNECT_MILLISECONDS):
        return None, None
    socket.write(b"hello\n")
    socket.waitForBytesWritten(CONNECT_MILLISECONDS)
    reply = b""
    while b"\n" not in reply and socket.waitForReadyRead(REPLY_MILLISECONDS):
        reply += bytes(socket.readAll())
    version, _, admin = reply.decode("utf-8", "replace").strip().partition(" ")
    if not version:
        log.info("A copy of %s is open but didn't answer: still starting", APP_NAME)
        return RunningCopy(), socket
    return RunningCopy(version, admin == "admin"), socket


def bring_to_front(socket):
    """Ask the open copy to show its window, letting it take the foreground (Windows only lets the program the user
    just started do that), and hang up."""
    try:
        ctypes.windll.user32.AllowSetForegroundWindow(ASFW_ANY)
    except (AttributeError, OSError):
        pass
    socket.write(b"show\n")
    socket.waitForBytesWritten(CONNECT_MILLISECONDS)
    socket.disconnectFromServer()


def hang_up(socket):
    socket.abort()


def needs_asking(running, version, admin):
    """Whether to ask before handing over to the open copy instead of just doing it: it's another version, or this
    copy has administrator rights it doesn't. A copy that didn't answer is still starting: it's handed over to."""
    if not running.answered:
        return False
    return running.version != version or (admin and not running.admin)


class InstanceServer(QObject):
    """What later copies say hello to: answers with this copy's version and rights, and emits show_requested when
    one asks this copy to come to the front."""
    show_requested = pyqtSignal()

    def __init__(self, version, admin, parent=None):
        super().__init__(parent)
        self.version = version
        self.admin = admin
        self.server = QLocalServer(self)
        # The account's own access: an administrator copy and a copy without the rights both reach it
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        self.server.newConnection.connect(self.on_new_connection)
        self.sockets = set()  # Kept here: Qt owning them doesn't keep their Python side (and slots) alive

    def listen(self, name=None):
        if self.server.listen(name or server_name()):
            return True
        log.warning("Couldn't listen for other copies of %s: %s", APP_NAME, self.server.errorString())
        return False

    def close(self):
        """Stop listening (before this copy goes, so a copy opened then doesn't hand over to it) and hang up on any
        copy still connected, letting go of the sockets before Qt frees them."""
        self.server.close()
        for socket in list(self.sockets):
            self.sockets.discard(socket)
            socket.abort()
            socket.deleteLater()

    def on_new_connection(self):
        while self.server.hasPendingConnections():
            socket = self.server.nextPendingConnection()
            socket.buffer = b""
            self.sockets.add(socket)
            socket.readyRead.connect(self.on_ready_read)
            socket.disconnected.connect(self.on_disconnected)
            self.read(socket)  # A copy that wrote while this one was busy has its lines waiting already

    def on_ready_read(self):
        self.read(self.sender())

    def on_disconnected(self):
        socket = self.sender()
        if socket not in self.sockets:  # Hung up by close()
            return
        self.read(socket)
        self.sockets.discard(socket)
        socket.deleteLater()

    def read(self, socket):
        if socket not in self.sockets:
            return
        socket.buffer += bytes(socket.readAll())
        while b"\n" in socket.buffer:
            line, socket.buffer = socket.buffer.split(b"\n", 1)
            command = line.strip().decode("ascii", "replace")
            if command == "hello":
                socket.write(f"{self.version} {'admin' if self.admin else 'user'}\n".encode("ascii"))
                socket.flush()
            elif command == "show":
                log.info("Another copy of %s was opened: showing this one", APP_NAME)
                self.show_requested.emit()
