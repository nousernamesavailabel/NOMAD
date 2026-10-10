"""TFTP server and client (RFC 1350, with the blksize, tsize and timeout options of RFCs 2347-2349).

Used to give switches, phones and access points firmware and to receive their config backups.
Transfers are in binary ("octet"); "netascii" requests are served byte for byte, as most TFTP servers do.
"""
import itertools
import logging
import os
import socket
import struct
import tempfile
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .system import replace_file

log = logging.getLogger(__name__)

TFTP_PORT = 69
RRQ, WRQ, DATA, ACK, ERROR, OACK = 1, 2, 3, 4, 5, 6
DEFAULT_BLOCK_SIZE = 512
CLIENT_BLOCK_SIZE = 1468  # Fills an Ethernet frame without fragmenting
MIN_BLOCK_SIZE, MAX_BLOCK_SIZE = 8, 65464
DEFAULT_TIMEOUT = 3
MAX_RETRIES = 5
ERR_UNDEFINED, ERR_NOT_FOUND, ERR_ACCESS, ERR_DISK_FULL, ERR_ILLEGAL, ERR_UNKNOWN_TID, ERR_EXISTS, \
    ERR_NO_USER, ERR_OPTIONS = range(9)
ERROR_TEXT = {ERR_UNDEFINED: "Error", ERR_NOT_FOUND: "File not found", ERR_ACCESS: "Access violation",
              ERR_DISK_FULL: "Disk full", ERR_ILLEGAL: "Illegal TFTP operation", ERR_UNKNOWN_TID: "Unknown transfer ID",
              ERR_EXISTS: "File already exists", ERR_NO_USER: "No such user", ERR_OPTIONS: "Option negotiation failed"}
MODES = {"octet", "netascii"}


class TftpError(Exception):
    def __init__(self, code, message="", from_peer=False):
        self.code = code
        self.from_peer = from_peer  # The other side sent this error, so it mustn't be answered with another
        super().__init__(message or ERROR_TEXT.get(code, "Error"))


# ----------------------------------------------------------------- Packets

def request_packet(opcode, filename, mode="octet", options=None):
    packet = struct.pack("!H", opcode) + filename.encode("ascii", "replace") + b"\0" + mode.encode("ascii") + b"\0"
    for name, value in (options or {}).items():
        packet += name.encode("ascii") + b"\0" + str(value).encode("ascii") + b"\0"
    return packet


def data_packet(block, data):
    return struct.pack("!HH", DATA, block) + data


def ack_packet(block):
    return struct.pack("!HH", ACK, block)


def error_packet(code, message=""):
    return struct.pack("!HH", ERROR, code) + (message or ERROR_TEXT.get(code, "Error")).encode("ascii", "replace") + \
        b"\0"


def oack_packet(options):
    return struct.pack("!H", OACK) + b"".join(name.encode("ascii") + b"\0" + str(value).encode("ascii") + b"\0"
                                              for name, value in options.items())


def _strings(raw):
    parts = raw.split(b"\0")
    if parts and parts[-1] == b"":
        parts.pop()
    return [part.decode("ascii", "replace") for part in parts]


def parse_packet(packet):
    """Returns (opcode, fields). Raises TftpError(ERR_ILLEGAL) for anything malformed.

    RRQ/WRQ: (filename, mode, {option: value}); DATA: (block, data); ACK: (block,); ERROR: (code, message);
    OACK: ({option: value},)
    """
    if len(packet) < 4:
        raise TftpError(ERR_ILLEGAL, "Packet too short.")
    opcode, = struct.unpack_from("!H", packet)
    body = packet[2:]
    if opcode in (RRQ, WRQ):
        strings = _strings(body)
        if len(strings) < 2 or len(strings) % 2:
            raise TftpError(ERR_ILLEGAL, "Malformed request.")
        options = {strings[i].lower(): strings[i + 1] for i in range(2, len(strings) - 1, 2)}
        return opcode, (strings[0], strings[1].lower(), options)
    if opcode == DATA:
        return opcode, (struct.unpack_from("!H", body)[0], body[2:])
    if opcode == ACK:
        return opcode, (struct.unpack_from("!H", body)[0],)
    if opcode == ERROR:
        code, = struct.unpack_from("!H", body)
        return opcode, (code, _strings(body[2:])[0] if len(body) > 2 and _strings(body[2:]) else "")
    if opcode == OACK:
        strings = _strings(body)
        return opcode, ({strings[i].lower(): strings[i + 1] for i in range(0, len(strings) - 1, 2)},)
    raise TftpError(ERR_ILLEGAL, f"Unknown opcode {opcode}.")


def negotiate(requested, file_size=None):
    """The options a server agrees to: (accepted {name: value}, block size, timeout). Unknown ones are ignored."""
    accepted = {}
    block_size, timeout = DEFAULT_BLOCK_SIZE, DEFAULT_TIMEOUT
    if "blksize" in requested:
        try:
            block_size = max(MIN_BLOCK_SIZE, min(MAX_BLOCK_SIZE, int(requested["blksize"])))
            accepted["blksize"] = block_size
        except ValueError:
            pass
    if "timeout" in requested:
        try:
            value = int(requested["timeout"])
            if 1 <= value <= 255:
                timeout = value
                accepted["timeout"] = value
        except ValueError:
            pass
    if "tsize" in requested:
        if file_size is not None:
            accepted["tsize"] = file_size  # Reading: tell the client the size
        else:
            accepted["tsize"] = requested["tsize"]  # Writing: echo what the client said
    return accepted, block_size, timeout


def safe_path(root, filename):
    """The file a request refers to, which must be inside root. Raises TftpError(ERR_ACCESS) otherwise."""
    name = filename.replace("\\", "/").lstrip("/")
    parts = [part for part in name.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." or ":" in part for part in parts):
        raise TftpError(ERR_ACCESS, "Access violation: the file must be inside the served folder.")
    root_real = os.path.realpath(root)
    path = os.path.realpath(os.path.join(root_real, *parts))
    if os.path.commonpath([path, root_real]) != root_real:
        raise TftpError(ERR_ACCESS, "Access violation: the file must be inside the served folder.")
    return path


# ----------------------------------------------------------------- Transfers

@dataclass
class Transfer:
    id: int
    peer: str
    filename: str
    direction: str  # "Sent" (to the peer) or "Received"
    size: Optional[int] = None  # Total bytes, if known
    done: int = 0
    status: str = "Starting"
    finished: bool = False
    ok: bool = False
    started: float = 0.0
    ended: float = 0.0

    @property
    def rate(self):
        elapsed = (self.ended or time.monotonic()) - self.started
        return self.done / elapsed if elapsed > 0 else 0.0


class _Channel:
    """One transfer's socket, talking to one peer address (its transfer ID)."""

    def __init__(self, sock, peer, timeout, should_stop):
        self.sock, self.peer, self.timeout, self.should_stop = sock, peer, timeout, should_stop

    def send(self, packet):
        self.sock.sendto(packet, self.peer)

    def receive(self, deadline):
        """The next packet from the peer before deadline, or None. Strays from other ports get an error."""
        while not self.should_stop():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            self.sock.settimeout(min(remaining, 0.5))
            try:
                packet, sender = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            except ConnectionResetError:  # The peer's port closed
                raise TftpError(ERR_UNDEFINED, "The other side stopped responding (port closed).") from None
            if sender[:2] != self.peer[:2]:
                self.sock.sendto(error_packet(ERR_UNKNOWN_TID), sender)
                continue
            return packet
        raise TftpError(ERR_UNDEFINED, "Stopped.")

    def exchange(self, packet, accept):
        """Send packet (if any) and wait for a reply accept(opcode, fields) likes, resending on timeouts.

        Returns (opcode, fields). Raises TftpError for an ERROR from the peer or after too many timeouts.
        """
        for _ in range(MAX_RETRIES + 1):
            if packet is not None:
                self.send(packet)
            deadline = time.monotonic() + self.timeout
            while True:
                raw = self.receive(deadline)
                if raw is None:
                    break
                try:
                    opcode, fields = parse_packet(raw)
                except TftpError:
                    continue
                if opcode == ERROR:
                    code, message = fields
                    raise TftpError(code, f"The other side reported: {message or ERROR_TEXT.get(code, 'Error')}",
                                    from_peer=True)
                if accept(opcode, fields):
                    return opcode, fields
        raise TftpError(ERR_UNDEFINED, f"Timed out: no answer after {MAX_RETRIES + 1} tries.")


def send_file(channel, source, block_size, progress, first_block=1):
    """Send a file's blocks, each waiting for its ACK. Block numbers wrap around after 65535."""
    sent = 0
    for block in itertools.count(first_block):
        data = source.read(block_size)
        number = block % 65536
        channel.exchange(data_packet(number, data), lambda op, fields, n=number: op == ACK and fields[0] == n)
        sent += len(data)
        progress(sent)
        if len(data) < block_size:
            return sent


def receive_file(channel, target, block_size, progress, first_packet=None, first_block=1,
                 before_final_ack=lambda: None):
    """Receive DATA blocks into target, acknowledging each. first_packet is the ACK or OACK reply to send first.

    before_final_ack() runs once all the data is in, before the last ACK tells the sender it's done, so the
    file can be saved first (and an error sent instead if that fails).
    """
    received = 0
    expected = first_block
    reply = first_packet
    while True:
        wanted, previous = expected % 65536, (expected - 1) % 65536

        def accept(opcode, fields):
            if opcode != DATA:
                return False
            if fields[0] == previous and expected > first_block:
                channel.send(ack_packet(previous))  # Our ACK was lost: say it again rather than wait
            return fields[0] == wanted

        opcode, (number, data) = channel.exchange(reply, accept)
        target.write(data)
        received += len(data)
        progress(received)
        reply = ack_packet(number)
        if len(data) < block_size:
            before_final_ack()
            channel.send(reply)  # Final ACK; a lost one makes the sender resend, which we don't wait for
            return received
        expected += 1


# ----------------------------------------------------------------- Server

class TftpServer:
    """Serves files from a folder and (optionally) accepts uploads into it.

    on_event(transfer) is called from worker threads whenever a transfer starts, progresses or finishes.
    """

    def __init__(self, root, address="0.0.0.0", port=TFTP_PORT, allow_upload=True, allow_overwrite=False,
                 on_event=lambda transfer: None):
        self.root, self.address, self.port = root, address, port
        self.allow_upload, self.allow_overwrite = allow_upload, allow_overwrite
        self.on_event = on_event
        self.sock = None
        self.stopping = threading.Event()
        self.thread = None
        self.ids = itertools.count(1)
        self.progress_interval = 0.2

    def start(self):
        """Raises OSError if the port can't be used (for example, another TFTP server has it)."""
        if not os.path.isdir(self.root):
            raise OSError(f"The folder {self.root} doesn't exist.")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.address, self.port))
        except OSError:
            self.sock.close()
            raise
        self.sock.settimeout(0.5)
        self.stopping.clear()
        self.thread = threading.Thread(target=self.serve, name="tftp-server", daemon=True)
        self.thread.start()

    def stop(self):
        self.stopping.set()
        if self.thread is not None:
            self.thread.join(2)
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def serve(self):
        while not self.stopping.is_set():
            try:
                packet, peer = self.sock.recvfrom(65536)
            except socket.timeout:
                continue
            except OSError:  # Includes ConnectionResetError from an earlier reply's port being closed
                if self.stopping.is_set() or self.sock is None:
                    return
                continue
            threading.Thread(target=self.handle, args=(packet, peer), name="tftp-transfer", daemon=True).start()

    def handle(self, packet, peer):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((self.address, 0))  # Each transfer gets its own port (transfer ID)
            try:
                opcode, fields = parse_packet(packet)
            except TftpError as error:
                sock.sendto(error_packet(error.code, str(error)), peer)
                return
            if opcode not in (RRQ, WRQ):
                sock.sendto(error_packet(ERR_ILLEGAL), peer)
                return
            filename, mode, requested = fields
            transfer = Transfer(next(self.ids), peer[0], filename, "Sent" if opcode == RRQ else "Received",
                                started=time.monotonic())
            last_report = [0.0]

            def progress(done):
                transfer.done = done
                transfer.status = "Transferring"
                now = time.monotonic()
                if now - last_report[0] >= self.progress_interval:
                    last_report[0] = now
                    self.on_event(transfer)

            try:
                if mode not in MODES:
                    raise TftpError(ERR_ILLEGAL, f"Mode '{mode}' isn't supported; use octet.")
                path = safe_path(self.root, filename)
                self.on_event(transfer)
                if opcode == RRQ:
                    self.serve_read(sock, peer, path, requested, transfer, progress)
                else:
                    self.serve_write(sock, peer, path, requested, transfer, progress)
                transfer.ok = True
                transfer.status = "Done"
            except TftpError as error:
                transfer.status = str(error)
                if not error.from_peer:
                    try:
                        sock.sendto(error_packet(error.code, str(error)), peer)
                    except OSError:
                        pass
            except OSError as error:
                transfer.status = f"Error: {error.strerror or error}"
                try:
                    sock.sendto(error_packet(ERR_UNDEFINED, transfer.status), peer)
                except OSError:
                    pass
            transfer.finished = True
            transfer.ended = time.monotonic()
            if transfer.ok:
                log.info("TFTP %s %s %s %s (%d bytes)", transfer.direction.lower(), filename,
                         "to" if opcode == RRQ else "from", peer[0], transfer.done)
            else:
                log.warning("TFTP transfer of %s with %s failed: %s", filename, peer[0], transfer.status)
            self.on_event(transfer)

    def serve_read(self, sock, peer, path, requested, transfer, progress):
        if not os.path.isfile(path):
            raise TftpError(ERR_NOT_FOUND, f"File not found: {transfer.filename}")
        size = os.path.getsize(path)
        transfer.size = size
        accepted, block_size, timeout = negotiate(requested, size)
        channel = _Channel(sock, peer, timeout, self.stopping.is_set)
        with open(path, "rb") as source:
            if accepted:
                channel.exchange(oack_packet(accepted), lambda op, fields: op == ACK and fields[0] == 0)
            send_file(channel, source, block_size, progress)

    def serve_write(self, sock, peer, path, requested, transfer, progress):
        if not self.allow_upload:
            raise TftpError(ERR_ACCESS, "Uploads are turned off on this server.")
        if os.path.exists(path) and not self.allow_overwrite:
            raise TftpError(ERR_EXISTS, f"File already exists: {transfer.filename}")
        accepted, block_size, timeout = negotiate(requested)
        if "tsize" in accepted:
            try:
                transfer.size = int(accepted["tsize"])
            except ValueError:
                pass
        os.makedirs(os.path.dirname(path), exist_ok=True)
        channel = _Channel(sock, peer, timeout, self.stopping.is_set)
        # Write to a temporary file and only then put it in place, so a failed upload leaves nothing half-done
        handle, temporary = tempfile.mkstemp(prefix=".nomad-tftp-", dir=os.path.dirname(path))
        target = os.fdopen(handle, "wb")

        def commit():
            target.close()
            replace_file(temporary, path)

        try:
            receive_file(channel, target, block_size, progress, oack_packet(accepted) if accepted else ack_packet(0),
                         before_final_ack=commit)
        except BaseException:
            target.close()
            try:
                os.remove(temporary)
            except OSError:
                pass
            raise


# ----------------------------------------------------------------- Client

def _client_socket(host, port):
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    family, address = infos[0][0], infos[0][4]
    sock = socket.socket(family, socket.SOCK_DGRAM)
    return sock, address


def _first_reply(sock, server, request, timeout, should_stop):
    """Send a request to the server's port and wait for its reply from the transfer's own port.

    Returns (opcode, fields, transfer address).
    """
    for _ in range(MAX_RETRIES + 1):
        sock.sendto(request, server)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if should_stop():
                raise TftpError(ERR_UNDEFINED, "Stopped.")
            sock.settimeout(max(0.05, min(0.5, deadline - time.monotonic())))
            try:
                packet, sender = sock.recvfrom(65536)
            except socket.timeout:
                continue
            except ConnectionResetError:
                raise TftpError(ERR_UNDEFINED, f"{server[0]} isn't running a TFTP server (UDP port {server[1]} is "
                                               "closed).") from None
            if sender[0] != server[0]:
                continue
            try:
                opcode, fields = parse_packet(packet)
            except TftpError:
                continue
            if opcode == ERROR:
                raise TftpError(fields[0], f"The server said: {fields[1] or ERROR_TEXT.get(fields[0], 'Error')}")
            return opcode, fields, sender
    raise TftpError(ERR_UNDEFINED, f"No answer from {server[0]}. Check the address, that its TFTP server is running, "
                                   "and that a firewall isn't blocking UDP port 69.")


def download(host, remote_name, local_path, port=TFTP_PORT, block_size=CLIENT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT,
             progress=lambda done, total: None, should_stop=lambda: False):
    """Fetch remote_name from a TFTP server into local_path. Returns the number of bytes received."""
    sock, server = _client_socket(host, port)
    folder = os.path.dirname(os.path.abspath(local_path))
    handle, temporary = tempfile.mkstemp(prefix=".nomad-tftp-", dir=folder)
    try:
        with sock, os.fdopen(handle, "wb") as target:
            options = {"blksize": block_size, "tsize": 0, "timeout": timeout}
            opcode, fields, peer = _first_reply(sock, server, request_packet(RRQ, remote_name, options=options),
                                                timeout, should_stop)
            channel = _Channel(sock, peer, timeout, should_stop)
            total = None
            if opcode == OACK:
                accepted = fields[0]
                size = int(accepted.get("blksize", DEFAULT_BLOCK_SIZE))
                total = int(accepted["tsize"]) if accepted.get("tsize", "").isdigit() else None
                received = receive_file(channel, target, size, lambda done: progress(done, total), ack_packet(0))
            elif opcode == DATA and fields[0] == 1:  # The server ignored our options
                data = fields[1]
                target.write(data)
                progress(len(data), None)
                if len(data) < DEFAULT_BLOCK_SIZE:
                    channel.send(ack_packet(1))
                    received = len(data)
                else:
                    received = len(data) + receive_file(channel, target, DEFAULT_BLOCK_SIZE,
                                                        lambda done: progress(len(data) + done, None),
                                                        ack_packet(1), first_block=2)
            else:
                raise TftpError(ERR_ILLEGAL, "The server's reply didn't make sense.")
        replace_file(temporary, local_path)
        return received
    except BaseException:
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise


def upload(host, local_path, remote_name, port=TFTP_PORT, block_size=CLIENT_BLOCK_SIZE, timeout=DEFAULT_TIMEOUT,
           progress=lambda done, total: None, should_stop=lambda: False):
    """Send local_path to a TFTP server as remote_name. Returns the number of bytes sent."""
    total = os.path.getsize(local_path)
    sock, server = _client_socket(host, port)
    with sock, open(local_path, "rb") as source:
        options = {"blksize": block_size, "tsize": total, "timeout": timeout}
        opcode, fields, peer = _first_reply(sock, server, request_packet(WRQ, remote_name, options=options),
                                            timeout, should_stop)
        channel = _Channel(sock, peer, timeout, should_stop)
        if opcode == OACK:
            size = int(fields[0].get("blksize", DEFAULT_BLOCK_SIZE))
        elif opcode == ACK and fields[0] == 0:  # The server ignored our options
            size = DEFAULT_BLOCK_SIZE
        else:
            raise TftpError(ERR_ILLEGAL, "The server's reply didn't make sense.")
        return send_file(channel, source, size, lambda done: progress(done, total))
