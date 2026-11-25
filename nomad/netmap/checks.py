"""How monitoring checks a map device: ping (the usual), a TCP port, or a web address (HTTP or HTTPS). A web server
that drops ping is checked on its web port: the time its TCP connection takes to open is the round trip time, as an
echo's is (netmap/../tcpcheck.py).

A device's Device.check says which ("" for its kind's way: TCP 443 for a web server, ping for the rest). A check by
web address fetches it once from the device's address and counts as up whatever the server answers; a 5xx answer is
noted as a warning (the server is there, the site has trouble). The time shown is the connection's, not the page's,
so it stays a measure of the network.

Qt-free: NOMAD's monitoring and the Map Watcher run these on worker threads."""
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

from .. import tcpcheck
from .model import WEB

PING, TCP, HTTP = "ping", "tcp", "http"
METHOD_NAMES = {PING: "Ping", TCP: "TCP port", HTTP: "Web address (HTTP or HTTPS)"}
WEB_PORT = 443
TCP_TRIES = 2  # Tries per poll when there's no answer at all (as pings): one answer is enough
TCP_TIMEOUT = 3.0  # Seconds: Windows takes 2 s to say refused (it tries again after a reset), so more than that
HTTP_TIMEOUT = 5.0


@dataclass(frozen=True)
class CheckSpec:
    method: str = PING
    port: int = 0  # TCP's port
    url: str = ""  # HTTP's address ("" for https://<the device's address>/)

    @property
    def pings(self):
        return self.method == PING

    @property
    def tcp_port(self):
        """The TCP port the check connects to (0 for ping): what a router's IP SLA tcp-connect probe checks."""
        if self.method == TCP:
            return self.port
        if self.method == HTTP:
            return url_port(self.url or "https://x/")
        return 0


@dataclass
class Outcome:
    rtt: Optional[int]  # ms, or None: no answer (down)
    note: str = ""  # Why there was no answer, or a warning while it answers ("HTTP 503 Service Unavailable")


def url_port(url):
    parts = urlsplit(url)
    try:
        return parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        return 0


def default_for(kind):
    return CheckSpec(TCP, WEB_PORT) if kind == WEB else CheckSpec(PING)


def parse(text):
    """A CheckSpec from Device.check's text, or None when it's "" (the kind's way) or can't be read."""
    method, _, rest = (text or "").strip().partition(":")
    if method == PING:
        return CheckSpec(PING)
    if method == TCP and rest.isdigit() and not tcpcheck.port_problem(int(rest)):
        return CheckSpec(TCP, int(rest))
    if method == HTTP and not rest:
        return CheckSpec(HTTP)  # https://<the device's address>/
    if method == HTTP:
        try:
            return CheckSpec(HTTP, url=normalize_url(rest))
        except ValueError:
            return None
    return None


def text_of(spec):
    if spec.method == TCP:
        return f"{TCP}:{spec.port}"
    if spec.method == HTTP:
        return f"{HTTP}:{spec.url}"
    return PING


def spec_of(device):
    """How monitoring checks the device."""
    return parse(device.check) or default_for(device.kind)


def stored(spec, kind):
    """Device.check's text for a spec: "" when it's the kind's own way, so a later change of kind changes it too."""
    return "" if spec == default_for(kind) else text_of(spec)


def normalize_url(text):
    """An http(s) address as checked: https:// added when there's no scheme, / when there's no path. Raises
    ValueError for one that can't be used."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Enter a web address, such as https://intranet/health.")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// addresses can be checked.")
    if not parts.hostname:
        raise ValueError(f"'{text}' has no host name.")
    try:
        parts.port
    except ValueError:
        raise ValueError(f"'{text}' has a port that can't be used.") from None
    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def describe(spec):
    """"Ping", "TCP 443" or "HTTPS https://intranet/health": for the details, the Monitor log and the dashboard."""
    if spec.method == TCP:
        return f"TCP {spec.port}"
    if spec.method == HTTP:
        url = spec.url or "https://(its address)/"
        return f"{urlsplit(url).scheme.upper()} {url}"
    return "Ping"


def short_text(spec):
    """"TCP 443", "HTTPS 443", or "" for ping: what's shown beside a device's response time."""
    if spec.method == TCP:
        return f"TCP {spec.port}"
    if spec.method == HTTP:
        return f"{urlsplit(spec.url or 'https://x/').scheme.upper()} {spec.tcp_port}"
    return ""


def url_for(spec, address):
    """The address an HTTP check fetches: its own, or https://<the device's address>/."""
    if spec.url:
        return spec.url
    host = f"[{address}]" if ":" in address else address
    return f"https://{host}/"


def tcp_note(result, port):
    if result.outcome == tcpcheck.REFUSED:
        return f"TCP {port} refused (nothing listening)"
    if result.outcome == tcpcheck.TIMEOUT:
        return f"no answer on TCP {port}"
    return f"TCP {port}: {result.error or 'failed'}"


def whole_ms(value):
    return None if value is None else max(0, int(round(value)))


def run(spec, address, connect=tcpcheck.connect_time, fetch=None):
    """Check a device at address the spec's way (not ping: that's monitor.ping's). Returns an Outcome."""
    if spec.method == TCP:
        result = None
        for _ in range(TCP_TRIES):
            result = connect(address, spec.port, TCP_TIMEOUT)
            if result.outcome != tcpcheck.TIMEOUT:
                break
        if result.ok:
            return Outcome(whole_ms(result.rtt))
        return Outcome(None, tcp_note(result, spec.port))
    if spec.method == HTTP:
        if fetch is None:
            from ..httpcheck import check_url as fetch
        url = url_for(spec, address)
        port = url_port(url)
        result = fetch(url, HTTP_TIMEOUT, address=address)
        if result.connect_ms is None:  # Never connected
            if "refused" in result.error:
                return Outcome(None, f"TCP {port} refused (nothing listening)")
            if result.error.startswith("No answer"):
                return Outcome(None, f"no answer on TCP {port}")
            return Outcome(None, result.error.rstrip(".") or f"couldn't connect on TCP {port}")
        if result.status is None:  # Connected, but no web server answered
            return Outcome(None, (result.error or "no HTTP reply").rstrip("."))
        rtt = whole_ms(result.connect_ms)
        if result.status >= 500:
            return Outcome(rtt, f"HTTP {result.status} {result.reason}".strip())
        return Outcome(rtt)
    raise ValueError(f"run() doesn't ping: {spec.method}")


class Answers:
    """A pinger for crawl.check_device that checks the spec's way: callable(address) -> whether it answered."""

    def __init__(self, spec):
        self.spec = spec

    def __call__(self, address):
        return run(self.spec, address).rtt is not None
