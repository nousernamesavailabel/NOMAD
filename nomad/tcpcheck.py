"""TCP round trip times for hosts that don't answer ping: the time a TCP connection takes to open (SYN out, SYN/ACK
back) is one round trip, as an echo is. Nothing is sent over the connection, so a web server doesn't log a request.

Qt-free: the Network Map's monitoring, the Map Watcher and the Latency page use it on worker threads."""
import os
import re
import socket
import struct
import time
from dataclasses import dataclass
from typing import Optional

OK, REFUSED, TIMEOUT, FAILED = "ok", "refused", "timeout", "failed"
DEFAULT_TIMEOUT = 3.0  # Seconds: Windows takes 2 s to say a port is refused (it tries twice more after a reset)
# SO_LINGER on with 0 s: close() resets, leaving no TIME_WAIT socket behind (Windows' linger is two u_shorts)
LINGER_RESET = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)


@dataclass
class TcpResult:
    outcome: str  # OK, REFUSED (it answered: a reset, nothing listening), TIMEOUT (no answer) or FAILED
    rtt: Optional[float] = None  # ms: the connection's time to open, or the reset's time to come back
    error: str = ""  # For FAILED: why (no route, the address can't be used...)

    @property
    def ok(self):
        return self.outcome == OK


def connect_time(address, port, timeout=DEFAULT_TIMEOUT, clock=time.perf_counter):
    """Open a TCP connection to address port and close it at once, timing the handshake. Never raises."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
    except OSError as error:
        return TcpResult(FAILED, error=error.strerror or str(error))
    try:
        sock.settimeout(timeout)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, LINGER_RESET)
        except OSError:
            pass
        started = clock()
        try:
            sock.connect((address.split("%")[0] if family == socket.AF_INET else address, port))
        except (socket.timeout, TimeoutError):
            return TcpResult(TIMEOUT)
        except ConnectionRefusedError:
            return TcpResult(REFUSED, (clock() - started) * 1000)
        except OSError as error:
            if getattr(error, "winerror", None) == 10060:  # WSAETIMEDOUT
                return TcpResult(TIMEOUT)
            return TcpResult(FAILED, error=error.strerror or str(error))
        return TcpResult(OK, (clock() - started) * 1000)
    finally:
        sock.close()


TARGET_PORT = re.compile(r"^(?:\[(?P<v6>[^\]]+)\]|(?P<host>[^:\s]+)):(?P<port>\d{1,5})$")
URL_TARGET = re.compile(r"^(?P<scheme>https?)://(?:\[(?P<v6>[^\]]+)\]|(?P<host>[^:/\s]+))(?::(?P<port>\d{1,5}))?",
                        re.IGNORECASE)


def split_target(text):
    """(host, port) of a TCP target written as host:port, [v6]:port or an http(s):// address (its port, else 80 or
    443), or None when it's a plain host (to ping)."""
    text = (text or "").strip()
    match = URL_TARGET.match(text)
    if match:
        port = int(match["port"]) if match["port"] else (443 if match["scheme"].lower() == "https" else 80)
        return match["v6"] or match["host"], port
    match = TARGET_PORT.match(text)  # (A bare IPv6 address has more than one colon, so it isn't host:port)
    if match:
        return match["v6"] or match["host"], int(match["port"])
    return None


def port_problem(port):
    """Why a port number can't be used, or ""."""
    return "" if 1 <= int(port) <= 65535 else f"Port {port} isn't between 1 and 65535."
