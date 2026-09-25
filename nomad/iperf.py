"""iperf3-compatible bandwidth testing in pure Python (no iperf3 binary needed).

Speaks the iperf3 control protocol, so the client can test against any iperf3 server
(iperf3 -s) and the server accepts tests from any iperf3 client (iperf3 -c ...).

Supported: TCP and UDP, upload and reverse (download, -R), parallel streams (-P), duration (-t),
UDP bitrate (-b) and block size (-l). Not supported: SCTP, bidirectional mode (--bidir) and
authentication. Python is slower than C iperf3, so very fast links (10 Gbit/s and up) may need
several parallel streams to fill.

Protocol summary: the client opens a TCP control connection and sends a 37-byte cookie. The server
then drives the test by sending one-byte states; parameters and results are exchanged as JSON
preceded by a 4-byte big-endian length. Data streams connect to the same port and identify
themselves with the cookie (TCP) or a 4-byte hello datagram (UDP).
"""
import json
import logging
import random
import select
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import Optional

from .system import CommandError, run_command

log = logging.getLogger(__name__)

DEFAULT_PORT = 5201
COOKIE_SIZE = 37
COOKIE_CHARS = "abcdefghijklmnopqrstuvwxyz234567"
TCP_BLOCK_SIZE = 128 * 1024
UDP_BLOCK_SIZE = 1460
DEFAULT_UDP_BITRATE = 1_000_000  # iperf3's default for UDP
CLIENT_VERSION = "3.17"
MAX_JSON_SIZE = 10 * 1024 * 1024

# Control states (signed bytes)
TEST_START = 1
TEST_RUNNING = 2
TEST_END = 4
PARAM_EXCHANGE = 9
CREATE_STREAMS = 10
SERVER_TERMINATE = 11
CLIENT_TERMINATE = 12
EXCHANGE_RESULTS = 13
DISPLAY_RESULTS = 14
IPERF_START = 15
IPERF_DONE = 16
ACCESS_DENIED = -1
SERVER_ERROR = -2

# UDP stream hello messages, sent as 32-bit integers in the sender's byte order
UDP_CONNECT_MSG = 0x36373839
UDP_CONNECT_REPLY = 0x39383736
LEGACY_UDP_CONNECT_MSG = 123456789
LEGACY_UDP_CONNECT_REPLY = 987654321

UDP_HEADER = struct.Struct("!IIi")  # seconds, microseconds, packet number
POLL_SECONDS = 0.2


class IperfError(Exception):
    """A test failed; str() is a message for the user."""


# ---------------------------------------------------------------------------- Formatting

def format_bytes(count):
    """Byte counts in iperf's style (1024-based)."""
    for unit, size in (("GBytes", 1024 ** 3), ("MBytes", 1024 ** 2), ("KBytes", 1024)):
        if count >= size:
            return f"{count / size:.2f} {unit}" if count / size < 10 else f"{count / size:.1f} {unit}"
    return f"{count} Bytes"


def format_bitrate(bits_per_second):
    """Bitrates in iperf's style (1000-based)."""
    for unit, size in (("Gbits/sec", 1e9), ("Mbits/sec", 1e6), ("Kbits/sec", 1e3)):
        if bits_per_second >= size:
            return f"{bits_per_second / size:.2f} {unit}" if bits_per_second / size < 100 \
                else f"{bits_per_second / size:.0f} {unit}"
    return f"{bits_per_second:.0f} bits/sec"


# ---------------------------------------------------------------------------- Parameters and results

@dataclass
class IperfParams:
    protocol: str = "tcp"  # "tcp" or "udp"
    duration: int = 10  # Seconds
    parallel: int = 1
    reverse: bool = False  # Server sends, client receives (download)
    bitrate: int = 0  # Bits per second per stream; 0 = unlimited (UDP defaults to 1 Mbit/s like iperf3)
    length: int = 0  # Block/datagram size; 0 = protocol default

    @property
    def udp(self):
        return self.protocol == "udp"

    @property
    def block_size(self):
        return self.length or (UDP_BLOCK_SIZE if self.udp else TCP_BLOCK_SIZE)

    def to_json(self):
        data = {self.protocol: True, "omit": 0, "time": self.duration, "num": 0, "blockcount": 0,
                "parallel": self.parallel, "len": self.block_size, "bandwidth": self.bitrate,
                "pacing_timer": 1000, "client_version": CLIENT_VERSION}
        if self.reverse:
            data["reverse"] = True
        return data

    @classmethod
    def from_json(cls, data):
        if data.get("sctp"):
            raise IperfError("SCTP tests aren't supported.")
        if data.get("bidirectional"):
            raise IperfError("Bidirectional (--bidir) tests aren't supported.")
        udp = bool(data.get("udp"))
        return cls(protocol="udp" if udp else "tcp", duration=int(data.get("time") or 10),
                   parallel=max(1, int(data.get("parallel") or 1)), reverse=bool(data.get("reverse")),
                   bitrate=int(data.get("bandwidth") or 0), length=int(data.get("len") or 0))


@dataclass
class StreamStats:
    id: int
    bytes: int = 0
    packets: int = 0  # UDP: sent, or the highest packet number received
    lost: int = 0  # UDP receiver
    out_of_order: int = 0
    jitter: float = 0.0  # Seconds (UDP receiver)
    prev_transit: Optional[float] = None
    error: Optional[str] = None

    def record_udp_packet(self, packet_number, sent_seconds, arrival_seconds, size):
        """Update loss and jitter the way iperf3 does (RFC 1889 jitter)."""
        self.bytes += size
        if packet_number >= self.packets + 1:
            if packet_number > self.packets + 1:
                self.lost += packet_number - 1 - self.packets
            self.packets = packet_number
        else:
            self.out_of_order += 1
            if self.lost > 0:
                self.lost -= 1
        transit = arrival_seconds - sent_seconds
        if self.prev_transit is not None:
            self.jitter += (abs(transit - self.prev_transit) - self.jitter) / 16.0
        self.prev_transit = transit


def stream_ids(count):
    """iperf3 numbers streams 1, 3, 4, 5, ... and both sides must agree."""
    return [1] + list(range(3, count + 2))


def cpu_percent(cpu_started, elapsed):
    """This process's CPU use since cpu_started (from time.process_time()), as a percentage of one core."""
    return min(100.0, 100 * (time.process_time() - cpu_started) / max(elapsed, 0.001))


def results_json(streams, elapsed, cpu):
    return {
        "cpu_util_total": cpu, "cpu_util_user": cpu, "cpu_util_system": 0,
        "sender_has_retransmits": 0,
        "streams": [{"id": stream.id, "bytes": stream.bytes, "retransmits": -1, "jitter": stream.jitter,
                     "errors": stream.lost, "omitted_errors": 0, "packets": stream.packets, "omitted_packets": 0,
                     "start_time": 0, "end_time": elapsed} for stream in streams],
    }


@dataclass
class IperfResult:
    params: IperfParams
    server: str
    sender_bytes: int
    sender_seconds: float
    receiver_bytes: int
    receiver_seconds: float
    packets: int = 0
    lost: int = 0
    jitter_ms: float = 0.0

    @property
    def sender_bps(self):
        return self.sender_bytes * 8 / self.sender_seconds if self.sender_seconds else 0

    @property
    def receiver_bps(self):
        return self.receiver_bytes * 8 / self.receiver_seconds if self.receiver_seconds else 0

    @property
    def loss_percent(self):
        return 100 * self.lost / self.packets if self.packets else 0.0

    def summary_lines(self):
        direction = "Download (server → this computer)" if self.params.reverse else "Upload (this computer → server)"
        lines = [f"{direction}, {self.params.protocol.upper()}, {self.params.parallel} stream(s):",
                 f"  Sender:   {format_bytes(self.sender_bytes):>12}  {format_bitrate(self.sender_bps):>16}  "
                 f"in {self.sender_seconds:.2f} s",
                 f"  Receiver: {format_bytes(self.receiver_bytes):>12}  {format_bitrate(self.receiver_bps):>16}  "
                 f"in {self.receiver_seconds:.2f} s"]
        if self.params.udp:
            lines.append(f"  Jitter {self.jitter_ms:.3f} ms, lost {self.lost}/{self.packets} datagrams "
                         f"({self.loss_percent:.2g}%)")
        return lines


# ---------------------------------------------------------------------------- Socket helpers

def make_cookie():
    return "".join(random.choice(COOKIE_CHARS) for _ in range(COOKIE_SIZE - 1)).encode("ascii") + b"\0"


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise IperfError("The other side closed the connection unexpectedly.")
        data += chunk
    return bytes(data)


def send_state(sock, state):
    sock.sendall(struct.pack("b", state))


def recv_state(sock):
    return struct.unpack("b", recv_exact(sock, 1))[0]


def send_json(sock, data):
    payload = json.dumps(data, separators=(",", ":")).encode("utf-8")
    sock.sendall(struct.pack("!I", len(payload)) + payload)


def recv_json(sock):
    size = struct.unpack("!I", recv_exact(sock, 4))[0]
    if size > MAX_JSON_SIZE:
        raise IperfError("Received an oversized message; the other side may not be iperf3.")
    return json.loads(recv_exact(sock, size).decode("utf-8"))


def clean_address(address):
    """Show IPv4-mapped IPv6 addresses (from dual-stack sockets) as plain IPv4."""
    return address[7:] if address.startswith("::ffff:") else address


def _udp_hello_reply(message):
    """Reply to a UDP stream hello in the same byte order it arrived in. None if it isn't a hello."""
    for order in ("<", ">"):
        value = struct.unpack(order + "I", message)[0]
        if value == UDP_CONNECT_MSG:
            return struct.pack(order + "I", UDP_CONNECT_REPLY)
        if value == LEGACY_UDP_CONNECT_MSG:
            return struct.pack(order + "I", LEGACY_UDP_CONNECT_REPLY)
    return None


def _is_udp_hello_reply(message):
    return any(struct.unpack(order + "I", message)[0] in (UDP_CONNECT_REPLY, LEGACY_UDP_CONNECT_REPLY)
               for order in ("<", ">"))


# ---------------------------------------------------------------------------- Stream workers

def tcp_sender(sock, stats, block_size, stop):
    block = memoryview(bytes(random.getrandbits(8) for _ in range(256)) * (block_size // 256 + 1))[:block_size]
    sock.settimeout(POLL_SECONDS)
    while not stop.is_set():
        try:
            stats.bytes += sock.send(block)
        except socket.timeout:
            continue
        except OSError as error:
            if not stop.is_set():
                stats.error = str(error)
            return


def tcp_receiver(sock, stats, stop):
    buffer = bytearray(256 * 1024)
    sock.settimeout(POLL_SECONDS)
    while not stop.is_set():
        try:
            count = sock.recv_into(buffer)
        except socket.timeout:
            continue
        except OSError as error:
            if not stop.is_set():
                stats.error = str(error)
            return
        if count == 0:
            return
        stats.bytes += count


def udp_sender(sock, stats, block_size, bitrate, peer, stop):
    """Send numbered, timestamped datagrams, paced to the bitrate (0 = as fast as possible)."""
    padding = bytes(max(0, block_size - UDP_HEADER.size))
    interval = block_size * 8 / bitrate if bitrate else 0.0
    next_send = time.perf_counter()
    packet_number = 0
    while not stop.is_set():
        if interval:
            delay = next_send - time.perf_counter()
            if delay > 0:
                time.sleep(min(delay, POLL_SECONDS))
                continue
            next_send += interval
        now = time.time()
        packet_number += 1
        datagram = UDP_HEADER.pack(int(now), int((now % 1) * 1_000_000), packet_number) + padding
        try:
            sent = sock.sendto(datagram, peer) if peer else sock.send(datagram)
        except (BlockingIOError, ConnectionResetError, socket.timeout):
            packet_number -= 1
            continue
        except OSError as error:
            if not stop.is_set():
                stats.error = str(error)
            return
        stats.bytes += sent
        stats.packets = packet_number


def parse_udp_datagram(data):
    seconds, microseconds, packet_number = UDP_HEADER.unpack_from(data)
    return packet_number, seconds + microseconds / 1_000_000


def udp_receiver(sock, stats, stop):
    buffer = bytearray(65536)
    sock.settimeout(POLL_SECONDS)
    while not stop.is_set():
        try:
            count = sock.recv_into(buffer)
        except (socket.timeout, ConnectionResetError):
            continue
        except OSError as error:
            if not stop.is_set():
                stats.error = str(error)
            return
        if count >= UDP_HEADER.size:
            packet_number, sent = parse_udp_datagram(buffer)
            stats.record_udp_packet(packet_number, sent, time.time(), count)


def udp_demux_receiver(sock, streams_by_peer, stop):
    """Server side: one UDP socket receives every stream; route datagrams by sender address."""
    buffer = bytearray(65536)
    sock.settimeout(POLL_SECONDS)
    while not stop.is_set():
        try:
            count, peer = sock.recvfrom_into(buffer)
        except (socket.timeout, ConnectionResetError):
            continue
        except OSError:
            return
        stats = streams_by_peer.get(peer)
        if stats is None:
            if count == 4 and (reply := _udp_hello_reply(bytes(buffer[:4]))):
                sock.sendto(reply, peer)  # A repeated hello whose first reply was lost
            continue
        if count >= UDP_HEADER.size:
            packet_number, sent = parse_udp_datagram(buffer)
            stats.record_udp_packet(packet_number, sent, time.time(), count)


class _StreamRunner:
    """Runs stream workers on threads and samples their byte counts for interval reports."""

    def __init__(self):
        self.stop = threading.Event()
        self.threads = []

    def start(self, target, *args):
        """Start target(*args, stop) on a thread; every worker takes the stop event last."""
        thread = threading.Thread(target=target, args=(*args, self.stop), daemon=True)
        thread.start()
        self.threads.append(thread)

    def finish(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=5)


# ---------------------------------------------------------------------------- Interval reporting

@dataclass
class Interval:
    start: float
    end: float
    bytes: int
    lost: int = 0
    packets: int = 0
    jitter_ms: Optional[float] = None  # Set when this side receives UDP

    @property
    def bits_per_second(self):
        return self.bytes * 8 / (self.end - self.start) if self.end > self.start else 0

    def format(self):
        line = f"{self.start:6.2f}-{self.end:<6.2f} sec  {format_bytes(self.bytes):>12}  " \
               f"{format_bitrate(self.bits_per_second):>16}"
        if self.jitter_ms is not None:
            loss = 100 * self.lost / self.packets if self.packets else 0
            line += f"  {self.jitter_ms:7.3f} ms  {self.lost}/{self.packets} ({loss:.2g}%)"
        return line


class _IntervalTracker:
    def __init__(self, streams, udp_receiver_side):
        self.streams = streams
        self.udp_receiver_side = udp_receiver_side
        self.last_time = 0.0
        self.last_bytes = self.last_lost = self.last_packets = 0

    def sample(self, now):
        total = sum(stream.bytes for stream in self.streams)
        lost = sum(stream.lost for stream in self.streams)
        packets = sum(stream.packets for stream in self.streams)
        interval = Interval(self.last_time, now, total - self.last_bytes)
        if self.udp_receiver_side:
            interval.lost = lost - self.last_lost
            interval.packets = packets - self.last_packets
            interval.jitter_ms = max((stream.jitter for stream in self.streams), default=0) * 1000
        self.last_time, self.last_bytes, self.last_lost, self.last_packets = now, total, lost, packets
        return interval


# ---------------------------------------------------------------------------- Client

class IperfClient:
    """Runs one test against an iperf3 server."""

    def __init__(self, host, port=DEFAULT_PORT, params=None, on_interval=lambda interval: None,
                 on_log=lambda message: None, should_stop=lambda: False, timeout=10):
        self.host, self.port = host, port
        self.params = params or IperfParams()
        self.on_interval, self.on_log, self.should_stop = on_interval, on_log, should_stop
        self.timeout = timeout
        self.cookie = make_cookie()
        self.sockets = []
        self.cpu_percent = 0.0

    def run(self):
        try:
            return self._run()
        except (ConnectionResetError, ConnectionAbortedError):
            raise IperfError("The server closed the connection. It may be busy with another test (public iperf3 "
                             "servers allow one at a time), so try again shortly or use another port.") from None
        except socket.timeout:
            raise IperfError("The server stopped responding.") from None
        except OSError as error:
            raise IperfError(f"Network error: {error}") from None
        finally:
            for sock in self.sockets:
                try:
                    sock.close()
                except OSError:
                    pass

    def _connect(self, sock_type):
        infos = socket.getaddrinfo(self.host, self.port, type=sock_type)
        family, _, _, _, address = infos[0]
        sock = socket.socket(family, sock_type)
        self.sockets.append(sock)
        sock.settimeout(self.timeout)
        sock.connect(address)
        return sock, address

    def _run(self):
        params = self.params
        try:
            control, address = self._connect(socket.SOCK_STREAM)
        except socket.gaierror:
            raise IperfError(f"Could not resolve '{self.host}'.") from None
        except (ConnectionRefusedError, socket.timeout, OSError) as error:
            raise IperfError(f"Couldn't connect to {self.host} port {self.port}: {error}. Check that an iperf3 "
                             "server is running there and the firewall allows it.") from None
        server = clean_address(address[0])
        self.on_log(f"Connected to {self.host} [{server}] port {self.port}")
        control.sendall(self.cookie)
        streams = []
        test_seconds = 0.0
        server_results = None

        while True:
            state = recv_state(control)
            if state == PARAM_EXCHANGE:
                send_json(control, params.to_json())
            elif state == CREATE_STREAMS:
                streams = self._create_streams()
            elif state == TEST_START:
                pass
            elif state == TEST_RUNNING:
                test_seconds = self._run_streams(control, streams)
            elif state == EXCHANGE_RESULTS:
                send_json(control, results_json([stats for stats, _ in streams], test_seconds, self.cpu_percent))
                server_results = recv_json(control)
            elif state == DISPLAY_RESULTS:
                send_state(control, IPERF_DONE)
                break
            elif state == ACCESS_DENIED:
                raise IperfError("The server is busy running another test. Try again in a moment.")
            elif state == SERVER_ERROR:
                code, errno_value = struct.unpack("!ii", recv_exact(control, 8))
                raise IperfError(f"The server reported an error (iperf error {code}, errno {errno_value}).")
            elif state in (SERVER_TERMINATE, CLIENT_TERMINATE):
                raise IperfError("The server ended the test early.")
            elif state == IPERF_START:
                pass
            else:
                raise IperfError(f"Unexpected message from the server (state {state}).")

        return self._build_result(server, [stats for stats, _ in streams], test_seconds, server_results)

    def _create_streams(self):
        params = self.params
        streams = []
        for stream_id in stream_ids(params.parallel):
            stats = StreamStats(stream_id)
            if params.udp:
                sock, _ = self._connect(socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
                self._udp_hello(sock)
            else:
                sock, _ = self._connect(socket.SOCK_STREAM)
                sock.sendall(self.cookie)
            streams.append((stats, sock))
        self.on_log(f"Opened {len(streams)} {params.protocol.upper()} stream(s)")
        return streams

    def _udp_hello(self, sock):
        sock.settimeout(2)
        for _ in range(3):
            sock.send(struct.pack("<I", UDP_CONNECT_MSG))
            try:
                reply = sock.recv(4)
            except (socket.timeout, ConnectionResetError):
                continue
            if len(reply) == 4 and _is_udp_hello_reply(reply):
                return
        raise IperfError("The server didn't answer on UDP. A firewall may be blocking UDP on this port.")

    def _run_streams(self, control, streams):
        params = self.params
        runner = _StreamRunner()
        for stats, sock in streams:
            if params.reverse:
                runner.start(udp_receiver if params.udp else tcp_receiver, sock, stats)
            elif params.udp:
                runner.start(udp_sender, sock, stats, params.block_size, params.bitrate or DEFAULT_UDP_BITRATE, None)
            else:
                runner.start(tcp_sender, sock, stats, params.block_size)

        all_stats = [stats for stats, _ in streams]
        tracker = _IntervalTracker(all_stats, udp_receiver_side=params.udp and params.reverse)
        started = time.perf_counter()
        cpu_started = time.process_time()
        next_report = 1.0
        try:
            while True:
                elapsed = time.perf_counter() - started
                if elapsed >= params.duration or self.should_stop():
                    break
                if elapsed >= next_report:
                    self.on_interval(tracker.sample(next_report))
                    next_report += 1.0
                readable, _, _ = select.select([control], [], [], POLL_SECONDS / 2)
                if readable:
                    state = recv_state(control)
                    if state == SERVER_ERROR:
                        code, errno_value = struct.unpack("!ii", recv_exact(control, 8))
                        raise IperfError(f"The server reported an error (iperf error {code}, errno {errno_value}).")
                    raise IperfError("The server ended the test early.")
                errors = [stats.error for stats in all_stats if stats.error]
                if errors:
                    raise IperfError(f"A data stream failed: {errors[0]}")
            elapsed = time.perf_counter() - started
            if elapsed - tracker.last_time > 0.05:
                self.on_interval(tracker.sample(elapsed))
            send_state(control, TEST_END)
            self.cpu_percent = cpu_percent(cpu_started, elapsed)
        finally:
            runner.finish()
        return elapsed

    def _build_result(self, server, streams, test_seconds, server_results):
        params = self.params
        local_bytes = sum(stats.bytes for stats in streams)
        remote_streams = (server_results or {}).get("streams") or []
        remote_bytes = sum(int(stream.get("bytes", 0)) for stream in remote_streams)
        remote_seconds = max((float(stream.get("end_time") or 0) for stream in remote_streams), default=0) \
            or test_seconds
        if params.reverse:
            result = IperfResult(params, server, remote_bytes, remote_seconds, local_bytes, test_seconds)
            receiving = streams
            result.packets = sum(stats.packets for stats in receiving)
            result.lost = sum(stats.lost for stats in receiving)
            result.jitter_ms = max((stats.jitter for stats in receiving), default=0) * 1000
        else:
            result = IperfResult(params, server, local_bytes, test_seconds, remote_bytes, remote_seconds)
            result.packets = sum(int(stream.get("packets", 0)) for stream in remote_streams)
            result.lost = sum(int(stream.get("errors", 0)) for stream in remote_streams)
            result.jitter_ms = max((float(stream.get("jitter", 0)) for stream in remote_streams), default=0) * 1000
        return result


# ---------------------------------------------------------------------------- Server

FIREWALL_RULE_NAME = "NOMAD-iperf-server"
LEGACY_FIREWALL_RULE_NAME = "NICManager-iperf-server"  # From before the rename


def open_firewall_port(port):
    """Allow inbound iperf tests (TCP and UDP) through Windows Firewall. Needs administrator rights."""
    for name in (FIREWALL_RULE_NAME, LEGACY_FIREWALL_RULE_NAME):  # Replace any rule from an earlier port
        try:
            run_command(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
        except CommandError:
            pass  # No existing rule
    for protocol in ("TCP", "UDP"):
        run_command(["netsh", "advfirewall", "firewall", "add", "rule", f"name={FIREWALL_RULE_NAME}", "dir=in",
                     "action=allow", f"protocol={protocol}", f"localport={int(port)}"])


class IperfServer:
    """Accepts tests from iperf3 clients (or NOMAD), one at a time."""

    def __init__(self, port=DEFAULT_PORT, on_log=lambda message: None, on_interval=lambda interval: None,
                 should_stop=lambda: False):
        self.port = port
        self.on_log, self.on_interval, self.should_stop = on_log, on_interval, should_stop
        self.listener = None

    def _bind(self, sock_type):
        """Bind a dual-stack (IPv4 + IPv6) socket, falling back to IPv4 only."""
        try:
            sock = socket.socket(socket.AF_INET6, sock_type)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            sock.bind(("::", self.port))
        except OSError:
            sock = socket.socket(socket.AF_INET, sock_type)
            sock.bind(("0.0.0.0", self.port))
        return sock

    def serve(self):
        """Serve tests until should_stop() returns True."""
        try:
            self.listener = self._bind(socket.SOCK_STREAM)
        except OSError as error:
            raise IperfError(f"Couldn't listen on port {self.port}: {error}. Is another server using it?") from None
        self.listener.listen(16)
        self.listener.settimeout(POLL_SECONDS)
        self.on_log(f"Server listening on port {self.port}")
        try:
            while not self.should_stop():
                try:
                    control, peer = self.listener.accept()
                except socket.timeout:
                    continue
                with control:
                    try:
                        self._handle_test(control, clean_address(peer[0]))
                    except (IperfError, OSError, ValueError) as error:
                        self.on_log(f"Test from {clean_address(peer[0])} failed: {error}")
        finally:
            self.listener.close()
            self.on_log("Server stopped")

    def _handle_test(self, control, peer):
        control.settimeout(15)
        cookie = recv_exact(control, COOKIE_SIZE)
        send_state(control, PARAM_EXCHANGE)
        params = IperfParams.from_json(recv_json(control))
        direction = "download (we send)" if params.reverse else "upload (we receive)"
        self.on_log(f"Test from {peer}: {params.protocol.upper()} {direction}, {params.parallel} stream(s), "
                    f"{params.duration} s")

        udp_socket = self._bind(socket.SOCK_DGRAM) if params.udp else None
        data_sockets = []
        try:
            if udp_socket is not None:
                udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            send_state(control, CREATE_STREAMS)
            ids = stream_ids(params.parallel)
            if params.udp:
                peers = self._accept_udp_streams(udp_socket, len(ids))
                streams = [(StreamStats(stream_id), peer_address) for stream_id, peer_address in zip(ids, peers)]
            else:
                data_sockets = self._accept_tcp_streams(cookie, len(ids))
                streams = [(StreamStats(stream_id), sock) for stream_id, sock in zip(ids, data_sockets)]
            send_state(control, TEST_START)
            send_state(control, TEST_RUNNING)
            cpu_started = time.process_time()
            elapsed = self._run_streams(control, params, streams, udp_socket)

            send_state(control, EXCHANGE_RESULTS)
            client_results = recv_json(control)
            send_json(control, results_json([stats for stats, _ in streams], elapsed,
                                            cpu_percent(cpu_started, elapsed)))
            send_state(control, DISPLAY_RESULTS)
            try:
                recv_state(control)  # IPERF_DONE
            except (IperfError, OSError):
                pass
            self._log_summary(peer, params, streams, elapsed, client_results)
        finally:
            for sock in data_sockets:
                sock.close()
            if udp_socket is not None:
                udp_socket.close()

    def _accept_tcp_streams(self, cookie, count):
        sockets = []
        deadline = time.monotonic() + 15
        while len(sockets) < count:
            if time.monotonic() > deadline:
                raise IperfError("The client didn't open its data streams.")
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            sock.settimeout(5)
            try:
                if recv_exact(sock, COOKIE_SIZE) == cookie:
                    sockets.append(sock)
                    continue
                send_state(sock, ACCESS_DENIED)  # Another client arrived mid-test
            except (IperfError, OSError):
                pass
            sock.close()
        return sockets

    def _accept_udp_streams(self, udp_socket, count):
        peers = []
        udp_socket.settimeout(POLL_SECONDS)
        deadline = time.monotonic() + 15
        while len(peers) < count:
            if time.monotonic() > deadline:
                raise IperfError("The client's UDP streams never arrived. A firewall may be blocking UDP.")
            try:
                message, peer = udp_socket.recvfrom(64)
            except (socket.timeout, ConnectionResetError):
                continue
            reply = _udp_hello_reply(message[:4]) if len(message) >= 4 else None
            if reply is None:
                continue
            udp_socket.sendto(reply, peer)
            if peer not in peers:
                peers.append(peer)
        return peers

    def _run_streams(self, control, params, streams, udp_socket):
        runner = _StreamRunner()
        all_stats = [stats for stats, _ in streams]
        if params.udp and not params.reverse:
            runner.start(udp_demux_receiver, udp_socket, {peer: stats for stats, peer in streams})
        else:
            for stats, target in streams:
                if params.udp:
                    runner.start(udp_sender, udp_socket, stats, params.block_size,
                                 params.bitrate or DEFAULT_UDP_BITRATE, target)
                elif params.reverse:
                    runner.start(tcp_sender, target, stats, params.block_size)
                else:
                    runner.start(tcp_receiver, target, stats)

        tracker = _IntervalTracker(all_stats, udp_receiver_side=params.udp and not params.reverse)
        started = time.perf_counter()
        next_report = 1.0
        limit = params.duration + 30  # The client normally ends the test well before this
        control.settimeout(POLL_SECONDS / 2)
        try:
            while True:
                elapsed = time.perf_counter() - started
                if self.should_stop():
                    send_state(control, SERVER_TERMINATE)
                    raise IperfError("Server stopped during the test.")
                if elapsed > limit:
                    raise IperfError("The client never ended the test.")
                if elapsed >= next_report:
                    self.on_interval(tracker.sample(next_report))
                    next_report += 1.0
                try:
                    state = recv_state(control)
                except socket.timeout:
                    continue
                if state == TEST_END:
                    break
                if state in (CLIENT_TERMINATE, IPERF_DONE):
                    raise IperfError("The client ended the test early.")
            elapsed = time.perf_counter() - started
            if elapsed - tracker.last_time > 0.05:
                self.on_interval(tracker.sample(elapsed))
        finally:
            runner.finish()
            control.settimeout(15)
        return elapsed

    def _log_summary(self, peer, params, streams, elapsed, client_results):
        local_bytes = sum(stats.bytes for stats, _ in streams)
        bits = local_bytes * 8 / elapsed if elapsed else 0
        verb = "Sent" if params.reverse else "Received"
        line = f"{verb} {format_bytes(local_bytes)} in {elapsed:.2f} s from/to {peer}: {format_bitrate(bits)}"
        if params.udp and not params.reverse:
            packets = sum(stats.packets for stats, _ in streams)
            lost = sum(stats.lost for stats, _ in streams)
            jitter = max(stats.jitter for stats, _ in streams) * 1000
            line += f", jitter {jitter:.3f} ms, lost {lost}/{packets}"
        self.on_log(line)
