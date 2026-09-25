"""ICMP echo (ping), traceroute probes and path MTU discovery.

Uses the Windows IP Helper API directly instead of parsing ping.exe output, so results
don't depend on the Windows display language.
"""
import ctypes
import ipaddress
import math
import socket
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Optional

IP_SUCCESS = 0
IP_BUF_TOO_SMALL = 11001
IP_DEST_NET_UNREACHABLE = 11002
IP_DEST_HOST_UNREACHABLE = 11003
IP_DEST_PROT_UNREACHABLE = 11004
IP_DEST_PORT_UNREACHABLE = 11005
IP_NO_RESOURCES = 11006
IP_BAD_OPTION = 11007
IP_HW_ERROR = 11008
IP_PACKET_TOO_BIG = 11009
IP_REQ_TIMED_OUT = 11010
IP_BAD_REQ = 11011
IP_BAD_ROUTE = 11012
IP_TTL_EXPIRED_TRANSIT = 11013  # Also IP_HOP_LIMIT_EXCEEDED for IPv6
IP_TTL_EXPIRED_REASSEM = 11014
IP_PARAM_PROBLEM = 11015
IP_SOURCE_QUENCH = 11016
IP_BAD_DESTINATION = 11018
IP_DEST_UNREACHABLE = 11040
IP_TIME_EXCEEDED = 11041
IP_GENERAL_FAILURE = 11050
ERROR_NETWORK_UNREACHABLE = 1231
ERROR_HOST_UNREACHABLE = 1232

STATUS_MESSAGES = {
    IP_DEST_NET_UNREACHABLE: "Destination network unreachable.",
    IP_DEST_HOST_UNREACHABLE: "Destination host unreachable.",
    IP_DEST_PROT_UNREACHABLE: "Destination protocol unreachable.",
    IP_DEST_PORT_UNREACHABLE: "Destination port unreachable.",
    IP_NO_RESOURCES: "Insufficient IP resources.",
    IP_BAD_OPTION: "Bad IP option.",
    IP_HW_ERROR: "Hardware error.",
    IP_PACKET_TOO_BIG: "Packet needs to be fragmented but DF set.",
    IP_REQ_TIMED_OUT: "Request timed out.",
    IP_BAD_REQ: "Bad request.",
    IP_BAD_ROUTE: "Bad route.",
    IP_TTL_EXPIRED_TRANSIT: "TTL expired in transit.",
    IP_TTL_EXPIRED_REASSEM: "TTL expired during reassembly.",
    IP_PARAM_PROBLEM: "Parameter problem.",
    IP_SOURCE_QUENCH: "Source quench received.",
    IP_BAD_DESTINATION: "Bad destination.",
    IP_DEST_UNREACHABLE: "Destination unreachable.",
    IP_TIME_EXCEEDED: "Time exceeded.",
    IP_GENERAL_FAILURE: "General failure.",
    ERROR_NETWORK_UNREACHABLE: "Network unreachable.",
    ERROR_HOST_UNREACHABLE: "Host unreachable.",
}

TTL_EXPIRED_STATUSES = {IP_TTL_EXPIRED_TRANSIT, IP_TIME_EXCEEDED}
IP_FLAG_DF = 0x2
IPV4_ICMP_HEADER_BYTES = 28  # 20-byte IPv4 header + 8-byte ICMP header
PAYLOAD_PATTERN = b"abcdefghijklmnopqrstuvwabcdefghi"  # Same payload ping.exe sends


class IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_uint32), ("Status", ctypes.c_uint32), ("RoundTripTime", ctypes.c_uint32),
                ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", IP_OPTION_INFORMATION)]


class SOCKADDR_IN6(ctypes.Structure):
    _fields_ = [("sin6_family", ctypes.c_short), ("sin6_port", ctypes.c_ushort), ("sin6_flowinfo", ctypes.c_uint32),
                ("sin6_addr", ctypes.c_ubyte * 16), ("sin6_scope_id", ctypes.c_uint32)]


class IPV6_ADDRESS_EX(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("sin6_port", ctypes.c_ushort), ("sin6_flowinfo", ctypes.c_uint32),
                ("sin6_addr", ctypes.c_ubyte * 16), ("sin6_scope_id", ctypes.c_uint32)]


class ICMPV6_ECHO_REPLY(ctypes.Structure):
    _fields_ = [("Address", IPV6_ADDRESS_EX), ("Status", ctypes.c_uint32), ("RoundTripTime", ctypes.c_uint)]


_iphlpapi = None


def _api():
    """Load iphlpapi.dll lazily so this module can be imported (and tested) anywhere."""
    global _iphlpapi
    if _iphlpapi is None:
        dll = ctypes.WinDLL("iphlpapi", use_last_error=True)
        dll.IcmpCreateFile.restype = wintypes.HANDLE
        dll.Icmp6CreateFile.restype = wintypes.HANDLE
        dll.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        dll.IcmpSendEcho2Ex.restype = wintypes.DWORD
        dll.IcmpSendEcho2Ex.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, wintypes.WORD, ctypes.POINTER(IP_OPTION_INFORMATION), ctypes.c_void_p,
            wintypes.DWORD, wintypes.DWORD]
        dll.Icmp6SendEcho2.restype = wintypes.DWORD
        dll.Icmp6SendEcho2.argtypes = [
            wintypes.HANDLE, wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(SOCKADDR_IN6),
            ctypes.POINTER(SOCKADDR_IN6), ctypes.c_void_p, wintypes.WORD, ctypes.POINTER(IP_OPTION_INFORMATION),
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        _iphlpapi = dll
    return _iphlpapi


@dataclass
class EchoReply:
    status: int
    address: str = ""  # Who answered (the target, or a router for errors/TTL expiry)
    rtt: Optional[int] = None  # Milliseconds
    ttl: Optional[int] = None

    @property
    def ok(self):
        return self.status == IP_SUCCESS

    @property
    def message(self):
        if self.ok:
            return "Reply"
        return STATUS_MESSAGES.get(self.status, f"Error {self.status}.")


def resolve_host(host, family=None):
    """Resolve a host name or address. Returns (address, family) with family 4 or 6."""
    host = host.strip()
    if not host:
        raise ValueError("Enter a host name or IP address.")
    socket_family = {4: socket.AF_INET, 6: socket.AF_INET6}.get(family, socket.AF_UNSPEC)
    try:
        results = socket.getaddrinfo(host, None, socket_family, socket.SOCK_RAW)
    except socket.gaierror:
        kind = f" to an IPv{family} address" if family else ""
        raise ValueError(f"Could not resolve '{host}'{kind}.") from None
    result_family, _, _, _, sockaddr = results[0]
    if result_family == socket.AF_INET6:
        address = sockaddr[0]
        if sockaddr[3] and "%" not in address:
            address = f"{address}%{sockaddr[3]}"
        return address, 6
    return sockaddr[0], 4


class IcmpClient:
    """Sends ICMP echo requests for one address family. Use as a context manager."""

    def __init__(self, family):
        self.family = family
        api = _api()
        self.handle = api.IcmpCreateFile() if family == 4 else api.Icmp6CreateFile()
        if not self.handle or self.handle == wintypes.HANDLE(-1).value:
            raise OSError(ctypes.get_last_error(), "Could not open an ICMP handle.")

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        if self.handle:
            _api().IcmpCloseHandle(self.handle)
            self.handle = None

    def echo(self, destination, size=32, timeout=1000, ttl=128, dont_fragment=False, source=None):
        """Send one echo request and wait for the reply (or timeout)."""
        payload = (PAYLOAD_PATTERN * (size // len(PAYLOAD_PATTERN) + 1))[:size]
        request = ctypes.create_string_buffer(payload, size) if size else None
        options = IP_OPTION_INFORMATION(Ttl=ttl, Flags=IP_FLAG_DF if dont_fragment else 0)
        reply_size = max(ctypes.sizeof(ICMP_ECHO_REPLY), ctypes.sizeof(ICMPV6_ECHO_REPLY)) + size + 8 + 256
        reply_buffer = ctypes.create_string_buffer(reply_size)
        api = _api()

        if self.family == 4:
            destination_value = int.from_bytes(socket.inet_aton(destination), "little")
            source_value = int.from_bytes(socket.inet_aton(source), "little") if source else 0
            count = api.IcmpSendEcho2Ex(self.handle, None, None, None, source_value, destination_value, request,
                                        size, ctypes.byref(options), reply_buffer, reply_size, timeout)
            if count == 0:
                return EchoReply(ctypes.get_last_error() or IP_GENERAL_FAILURE)
            reply = ICMP_ECHO_REPLY.from_buffer(reply_buffer)
            address = socket.inet_ntoa(reply.Address.to_bytes(4, "little"))
            return EchoReply(reply.Status, address, reply.RoundTripTime,
                             reply.Options.Ttl if reply.Status == IP_SUCCESS else None)

        address_text, _, scope = destination.partition("%")
        destination_sockaddr = SOCKADDR_IN6(sin6_family=socket.AF_INET6, sin6_scope_id=int(scope) if scope else 0)
        destination_sockaddr.sin6_addr[:] = ipaddress.IPv6Address(address_text).packed
        source_sockaddr = SOCKADDR_IN6(sin6_family=socket.AF_INET6)
        if source:
            source_sockaddr.sin6_addr[:] = ipaddress.IPv6Address(source.partition("%")[0]).packed
        count = api.Icmp6SendEcho2(self.handle, None, None, None, ctypes.byref(source_sockaddr),
                                   ctypes.byref(destination_sockaddr), request, size, ctypes.byref(options),
                                   reply_buffer, reply_size, timeout)
        if count == 0:
            return EchoReply(ctypes.get_last_error() or IP_GENERAL_FAILURE)
        reply = ICMPV6_ECHO_REPLY.from_buffer(reply_buffer)
        address = str(ipaddress.IPv6Address(bytes(reply.Address.sin6_addr)))
        return EchoReply(reply.Status, address, reply.RoundTripTime)


def format_reply(reply, size):
    """Format a reply the way ping.exe does."""
    if reply.ok:
        time = "time<1ms" if reply.rtt < 1 else f"time={reply.rtt}ms"
        ttl = f" TTL={reply.ttl}" if reply.ttl is not None else ""
        return f"Reply from {reply.address}: bytes={size} {time}{ttl}"
    if reply.address and reply.address not in ("0.0.0.0", "::"):
        return f"Reply from {reply.address}: {reply.message}"
    return reply.message


@dataclass
class PingStats:
    sent: int = 0
    received: int = 0
    rtts: list = field(default_factory=list)

    def add(self, reply):
        self.sent += 1
        if reply.ok:
            self.received += 1
            self.rtts.append(reply.rtt)

    @property
    def lost(self):
        return self.sent - self.received

    @property
    def loss_percent(self):
        return 0 if not self.sent else round(100 * self.lost / self.sent)

    def summary(self):
        text = f"Sent {self.sent}, received {self.received}, lost {self.lost} ({self.loss_percent}% loss)"
        if self.rtts:
            average = round(sum(self.rtts) / len(self.rtts))
            text += f"  ·  min {min(self.rtts)} ms, avg {average} ms, max {max(self.rtts)} ms"
        return text


# Probe outcomes for path MTU discovery
PROBE_OK = "ok"
PROBE_TOO_BIG = "too_big"
PROBE_TIMEOUT = "timeout"
PROBE_ERROR = "error"


def path_mtu_steps(minimum, maximum):
    """Upper bound on probes find_path_mtu makes (ignoring retries), for progress bars."""
    return 2 + max(0, math.ceil(math.log2(max(maximum - minimum, 1))))


def find_path_mtu(probe, minimum, maximum, retries=2, should_stop=lambda: False, log=lambda message: None,
                  progress=lambda step: None):
    """Binary search for the largest MTU that reaches the target without fragmenting.

    probe(mtu) returns (outcome, message) where outcome is one of the PROBE_* constants.
    A probe that times out is retried; if it keeps timing out it is treated as too big, since
    some routers silently drop oversized packets instead of reporting them.
    Returns (mtu, message). mtu is None when no working MTU was found or the search was stopped.
    """
    step = 0

    def attempt(mtu):
        nonlocal step
        for attempt_number in range(retries + 1):
            if should_stop():
                return None, "Stopped."
            outcome, message = probe(mtu)
            log(f"MTU {mtu}: {message}")
            if outcome != PROBE_TIMEOUT:
                break
            if attempt_number < retries:
                log(f"MTU {mtu}: retrying ({attempt_number + 1} of {retries})")
        step += 1
        progress(step)
        return outcome, message

    outcome, message = attempt(maximum)
    if outcome is None:
        return None, message
    if outcome == PROBE_OK:
        return maximum, f"The maximum MTU of {maximum} works."
    if outcome == PROBE_ERROR:
        return None, message

    outcome, message = attempt(minimum)
    if outcome is None:
        return None, message
    if outcome == PROBE_TIMEOUT:
        return None, f"No reply even at the minimum MTU of {minimum}. Check that the host is reachable and answers ping."
    if outcome != PROBE_OK:
        return None, f"The minimum MTU of {minimum} failed: {message}"

    low, high = minimum, maximum  # low always works, high never does
    while high - low > 1:
        middle = (low + high) // 2
        outcome, message = attempt(middle)
        if outcome is None:
            return None, message
        if outcome == PROBE_OK:
            low = middle
        elif outcome in (PROBE_TOO_BIG, PROBE_TIMEOUT):
            high = middle
        else:
            return None, message
    return low, f"Largest MTU that gets through without fragmenting: {low}."


def make_mtu_probe(client, destination, timeout, source=None):
    """Build a find_path_mtu probe that sends DF pings sized to fill the given MTU."""
    def probe(mtu):
        reply = client.echo(destination, size=mtu - IPV4_ICMP_HEADER_BYTES, timeout=timeout,
                            dont_fragment=True, source=source)
        if reply.ok:
            return PROBE_OK, f"OK ({reply.rtt} ms)"
        if reply.status == IP_PACKET_TOO_BIG:
            return PROBE_TOO_BIG, "too big (needs fragmenting)"
        if reply.status == IP_REQ_TIMED_OUT:
            return PROBE_TIMEOUT, "timed out"
        return PROBE_ERROR, reply.message
    return probe
