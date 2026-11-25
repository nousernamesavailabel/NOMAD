"""Check a web server: how long each step takes (DNS, connect, TLS, first byte), its certificate, and its reply."""
import http.client
import ipaddress
import os
import socket
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlsplit

MAX_REDIRECTS = 5
USER_AGENT = "NOMAD"
EXPIRY_WARNING_DAYS = 30


@dataclass
class Certificate:
    subject: str = ""
    issuer: str = ""
    names: list = field(default_factory=list)  # Subject alternative names
    not_before: str = ""
    not_after: str = ""
    days_left: Optional[int] = None
    serial: str = ""
    self_signed: bool = False


@dataclass
class HttpResult:
    url: str
    address: str = ""
    dns_ms: Optional[float] = None
    connect_ms: Optional[float] = None
    tls_ms: Optional[float] = None
    first_byte_ms: Optional[float] = None  # From sending the request to the start of the reply
    total_ms: Optional[float] = None
    tls_version: str = ""
    cipher: str = ""
    certificate: Optional[Certificate] = None
    verified: Optional[bool] = None  # None for plain HTTP
    verify_error: str = ""
    status: Optional[int] = None
    reason: str = ""
    server: str = ""
    location: str = ""  # Absolute redirect target
    error: str = ""

    @property
    def redirect(self):
        return self.status in (301, 302, 303, 307, 308) and bool(self.location)


def normalize_url(text):
    """Accept "example.com", "example.com:8443/path" or a full http(s) URL. Raises ValueError if unusable."""
    text = text.strip()
    if not text:
        raise ValueError("Enter a web address, such as https://example.com.")
    if "://" not in text:
        text = "https://" + text
    parts = urlsplit(text)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only http:// and https:// addresses can be checked.")
    if not parts.hostname:
        raise ValueError(f"'{text}' doesn't include a host name.")
    try:
        parts.port
    except ValueError:
        raise ValueError(f"'{text}' has an invalid port.") from None
    return parts.geturl() if parts.path else parts._replace(path="/").geturl()


def _name(entries):
    """Turn getpeercert()'s ((('commonName', 'x'),), ...) into "CN=x, O=y"."""
    short = {"commonName": "CN", "organizationName": "O", "organizationalUnitName": "OU", "countryName": "C",
             "domainComponent": "DC", "localityName": "L", "stateOrProvinceName": "ST"}
    return ", ".join(f"{short.get(key, key)}={value}" for entry in entries for key, value in entry)


def certificate_from_dict(info, now=None):
    now = time.time() if now is None else now
    certificate = Certificate(subject=_name(info.get("subject", ())), issuer=_name(info.get("issuer", ())),
                              names=[f"{kind}:{value}" if kind != "DNS" else value
                                     for kind, value in info.get("subjectAltName", ())],
                              not_before=info.get("notBefore", ""), not_after=info.get("notAfter", ""),
                              serial=info.get("serialNumber", ""))
    certificate.self_signed = bool(certificate.subject) and certificate.subject == certificate.issuer
    if certificate.not_after:
        try:
            certificate.days_left = int((ssl.cert_time_to_seconds(certificate.not_after) - now) // 86400)
        except ValueError:
            pass
    return certificate


def decode_certificate(der):
    """Decode a certificate we couldn't verify, so its details can still be shown."""
    path = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as file:
            file.write(ssl.DER_cert_to_PEM_cert(der))
            path = file.name
        return certificate_from_dict(ssl._ssl._test_decode_cert(path))  # CPython's own decoder
    except (AttributeError, OSError, ssl.SSLError, ValueError):
        return Certificate(subject="(couldn't decode the certificate)")
    finally:
        if path:
            os.remove(path)


def _connect(address, port, timeout):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except BaseException:
        sock.close()
        raise
    return sock


def check_url(url, timeout=10.0, address=None):
    """Fetch url once, timing each step. Never raises: problems end up in result.error. address: connect there
    instead of looking the URL's host up (a map device's own address), still asking for the URL's host."""
    result = HttpResult(url)
    parts = urlsplit(url)
    host, secure = parts.hostname, parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    total_started = time.perf_counter()
    try:
        started = time.perf_counter()
        try:
            if address:
                result.address = address
            else:
                ipaddress.ip_address(host)
                result.address = host
        except ValueError:
            try:
                infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            except socket.gaierror:
                result.error = f"Couldn't find {host} in DNS."
                return result
            result.address = infos[0][4][0]
            result.dns_ms = (time.perf_counter() - started) * 1000

        started = time.perf_counter()
        try:
            sock = _connect(result.address, port, timeout)
        except (socket.timeout, TimeoutError):
            result.error = f"No answer from {result.address} port {port} (a firewall may be dropping it)."
            return result
        except ConnectionRefusedError:
            result.error = f"{result.address} refused the connection: nothing is listening on port {port}."
            return result
        except OSError as error:
            result.error = f"Couldn't connect to {result.address} port {port}: {error.strerror or error}"
            return result
        result.connect_ms = (time.perf_counter() - started) * 1000

        if secure:
            server_name = None if _is_address(host) else host
            started = time.perf_counter()
            try:
                tls = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
                result.verified = True
            except ssl.SSLCertVerificationError as error:
                # Say why, then look again without checking so the certificate can still be shown
                result.verified = False
                result.verify_error = error.verify_message or error.reason or str(error)
                sock = _connect(result.address, port, timeout)
                started = time.perf_counter()
                unverified = ssl._create_unverified_context()
                tls = unverified.wrap_socket(sock, server_hostname=server_name)
            except ssl.SSLError as error:
                sock.close()
                result.error = f"The TLS handshake failed: {error.reason or error}"
                return result
            except OSError as error:
                sock.close()
                result.error = f"The connection dropped during the TLS handshake: {error.strerror or error}"
                return result
            result.tls_ms = (time.perf_counter() - started) * 1000
            result.tls_version = tls.version() or ""
            result.cipher = (tls.cipher() or ("",))[0]
            info = tls.getpeercert() if result.verified else None
            result.certificate = certificate_from_dict(info) if info else decode_certificate(tls.getpeercert(True))
            sock = tls

        connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.sock = sock  # Already connected (and encrypted)
        try:
            started = time.perf_counter()
            path = parts.path or "/"
            connection.request("GET", path + (f"?{parts.query}" if parts.query else ""),
                               headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
            response = connection.getresponse()
            result.first_byte_ms = (time.perf_counter() - started) * 1000
            result.status, result.reason = response.status, response.reason
            result.server = response.getheader("Server", "")
            location = response.getheader("Location", "")
            result.location = urljoin(url, location) if location else ""
            response.read(64 * 1024)  # Enough to see the start of the page, without downloading it all
        except (http.client.HTTPException, OSError) as error:
            result.error = f"The server didn't send a valid HTTP reply: {error}"
        finally:
            connection.close()
    finally:
        result.total_ms = (time.perf_counter() - total_started) * 1000
    return result


def _is_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def check_with_redirects(url, timeout=10.0, max_redirects=MAX_REDIRECTS, check=None, should_stop=lambda: False):
    """Check url and follow any redirects. Returns the list of HttpResults, one per hop."""
    check = check or check_url
    results = []
    seen = set()
    while len(results) <= max_redirects and not should_stop():
        seen.add(url)
        result = check(url, timeout)
        results.append(result)
        if not result.redirect or result.location in seen:
            break
        url = result.location
    return results
