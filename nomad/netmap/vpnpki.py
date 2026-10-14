"""Certificates for VPNs: the steps that give each router a certificate before a certificate-authenticated VPN goes in.

Where they come from (vpn.Auth.ca_kind):
- "router": an IOS certificate server NOMAD sets up on one of the routers (crypto pki server, SCEP over HTTP, granting
  automatically to the VPN's routers only), and the routers enroll with it over SCEP;
- "scep": an existing CA's SCEP URL (the routers enroll with it; its fingerprint, typed in, is checked first);
- "paste": no SCEP: the CA certificate is pasted in, each router's request is shown to take to the CA, and the
  certificate it signs is pasted back.

IOS only uses certificates once its clock is authoritative (set by NTP): without NTP, the steps keep the clocks in
step from the CA router (ntp master there, ntp server to it on the others) and wait for them.

Each step is lines with the questions they ask answered (configpush.VpnShell.dialog), and what undoes it. They aren't
sent with the revert timer: a configuration rollback and certificate chains don't mix (and a key once made stays).

Qt-free.
"""
import re
import secrets
import string
from dataclasses import dataclass, field

from . import vpn as V

YES_NO = r"\[yes/no\]"
CERT_DIR = "nomad-ca"


@dataclass
class PkiStep:
    """One router's part of setting up certificates."""
    key: str  # Member key
    title: str
    steps: list = field(default_factory=list)  # [(line, [(question regex, answer or callable)])]
    undo: list = field(default_factory=list)
    wait: str = ""  # What to wait for afterwards: "ntp", "certificate", "ca"
    trustpoint: str = ""

    def text(self):
        return "\n".join(line for line, _ in self.steps)

    def undo_text(self):
        return "\n".join(line for line, _ in self.undo)


def new_secret(length=20):
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def normal_fingerprint(text):
    """A fingerprint's hex digits, upper case, no spaces or colons."""
    return re.sub(r"[^0-9A-Fa-f]", "", text or "").upper()


def fingerprints_in(text):
    """The fingerprints shown in a router's answer (crypto pki authenticate, show crypto pki server)."""
    found = []
    for match in re.finditer(r"(?:Fingerprint(?: MD5| SHA1| SHA256)?|CA cert fingerprint)\s*:?\s*((?:[0-9A-Fa-f]{2,8}"
                             r"[ :]?){4,})", text or ""):
        found.append(normal_fingerprint(match.group(1)))
    return found


def accepts(wanted):
    """An answer to "Do you accept this certificate?" that's yes only if the router showed the wanted fingerprint."""
    wanted = normal_fingerprint(wanted)

    def answer(said):
        shown = fingerprints_in(said)
        if wanted and any(item == wanted or item.startswith(wanted) or wanted.startswith(item) and len(item) >= 32
                          for item in shown):
            return "yes"
        return None
    return answer


def ca_address(vpn, members):
    """The address the routers reach the CA router at."""
    ca = vpn.member(vpn.auth.ca_device)
    return ca.reached_at if ca is not None else ""


def scep_url(vpn):
    if vpn.auth.ca_kind == "router":
        ca = vpn.member(vpn.auth.ca_device)
        return f"http://{ca.reached_at}:80" if ca is not None and ca.reached_at else ""
    return vpn.auth.ca_url


def explain(problem, vpn):
    """Plain words for what a certificate step's failure usually means, or ""."""
    if re.search(r"Error in receiving Certificate Authority certificate|cert length = 0", problem or "", re.I):
        url = scep_url(vpn) or "the CA"
        return (f"it couldn't fetch the CA's certificate from {url}: check it has a route to that address and "
                f"that the CA lets it in over HTTP")
    return ""


def has_ntp(device):
    return bool(device.blocks("ntp server") or device.blocks("ntp master") or device.blocks("ntp peer"))


def clock_ok(device):
    status = device.status if device is not None else None
    return status is not None and status.clock_set


def ca_server_name(vpn):
    return V.safe_name(vpn.auth.ca_name or "NOMAD-CA", 24)


def ca_running(device, name):
    status = device.status if device is not None else None
    return device.block(f"crypto pki server {name}") is not None and status is not None and \
        status.pki_server == "enabled"


def ca_steps(vpn, device, passphrase):
    """Setting up the certificate server on the CA router (and HTTP for SCEP, open only to the VPN's routers)."""
    member = vpn.member(vpn.auth.ca_device)
    name = ca_server_name(vpn)
    step = PkiStep(member.key, f"Set up certificate server {name} on {member.title()}", wait="ca")
    answers = [(r"Create directory filename", ""), (r"Password:|passphrase", passphrase),
               (r"Re-enter password", passphrase), (YES_NO, "yes"), (r"\[confirm\]", "")]
    http_on = device.block("ip http server") is not None
    access = device.block("ip http access-class") is not None
    acl_name = f"{name}-SCEP"
    step.steps.append((f"mkdir bootflash:{CERT_DIR}", answers))
    config = ["configure terminal"]
    if not http_on:
        config.append("ip http server")
    if not access and not http_on:
        config.append(f"ip access-list standard {acl_name}")
        for other in vpn.members:
            for address in {other.local_ip, other.public_ip} - {""}:
                config.append(f" permit host {address}")
        config.append(" exit")
        config.append(f"ip http access-class ipv4 {acl_name}")
    config += [f"crypto pki server {name}", " database level complete", f" database url bootflash:{CERT_DIR}/",
               f" issuer-name CN={vpn.auth.ca_name or name}", " hash sha256", " grant auto",
               " lifetime certificate 730", " lifetime ca-certificate 3650", " no shutdown", "end"]
    step.steps += [(line, answers) for line in config]
    undo = ["configure terminal", f"no crypto pki server {name}", f"no crypto pki trustpoint {name}",
            f"crypto key zeroize rsa {name}"]
    if not http_on:
        undo.append("no ip http server")
    if not access and not http_on:
        undo += ["no ip http access-class ipv4", f"no ip access-list standard {acl_name}"]
    undo.append("end")
    undo.append(f"delete /force /recursive bootflash:{CERT_DIR}")
    step.undo = [(line, answers) for line in undo]
    return step


def ntp_steps(vpn, devices):
    """Clocks kept in step from the CA router for routers whose clocks aren't authoritative (IOS won't use
    certificates otherwise)."""
    steps = []
    ca = vpn.member(vpn.auth.ca_device) if vpn.auth.ca_kind == "router" else None
    if ca is None:
        return steps
    ca_device = devices.get(ca.key)
    if ca_device is not None and not has_ntp(ca_device) and not clock_ok(ca_device):
        step = PkiStep(ca.key, f"Make {ca.title()}'s clock the VPN's time source (ntp master)", wait="ntp")
        step.steps = [(line, []) for line in ["configure terminal", "ntp master 3", "end"]]
        step.undo = [(line, []) for line in ["configure terminal", "no ntp master 3", "end"]]
        steps.append(step)
    for member in vpn.members:
        device = devices.get(member.key)
        if member.key == ca.key or device is None or has_ntp(device) or clock_ok(device):
            continue
        step = PkiStep(member.key, f"Keep {member.title()}'s clock in step with {ca.title()} (NTP)", wait="ntp")
        step.steps = [(line, []) for line in ["configure terminal", f"ntp server {ca.reached_at}", "end"]]
        step.undo = [(line, []) for line in ["configure terminal", f"no ntp server {ca.reached_at}", "end"]]
        steps.append(step)
    return steps


def trustpoint_lines(vpn, member, device, url):
    trustpoint = V.names(vpn, member)["trustpoint"]
    hostname = device.hostname if device is not None and device.hostname else member.title()
    lines = [f"crypto pki trustpoint {trustpoint}"]
    lines.append(f" enrollment url {url}" if url else " enrollment terminal")
    lines += [f" subject-name CN={hostname}", " serial-number none", " ip-address none", " fqdn none",
              f" revocation-check {vpn.auth.revocation or 'none'}", f" rsakeypair {trustpoint} 2048", " exit"]
    return trustpoint, lines


def enroll_steps(vpn, member, device, fingerprint):
    """A router's trustpoint, its CA trusted (only when it shows the expected fingerprint), and its certificate
    requested over SCEP."""
    url = scep_url(vpn)
    trustpoint, lines = trustpoint_lines(vpn, member, device, url)
    challenge = new_secret(16)
    answers = [(r"Do you accept this certificate", accepts(fingerprint)), (r"Password:", challenge),
               (r"Re-enter password", challenge), (r"Include the router serial number", "no"),
               (r"Include an IP address", "no"), (r"Request certificate from CA", "yes"),
               (r"You already have RSA keys", "no"), (YES_NO, "no"), (r"\[confirm\]", "")]
    step = PkiStep(member.key, f"Enroll {member.title()} ({trustpoint})", wait="certificate", trustpoint=trustpoint)
    step.steps = [(line, answers) for line in ["configure terminal"] + lines +
                  [f"crypto pki authenticate {trustpoint}", f"crypto pki enroll {trustpoint}", "end"]]
    step.undo = untrust_steps(trustpoint)
    return step


def untrust_steps(trustpoint):
    answers = [(YES_NO, "yes"), (r"\[confirm\]", "")]
    return [(line, answers) for line in ["configure terminal", f"no crypto pki trustpoint {trustpoint}",
                                         f"crypto key zeroize rsa {trustpoint}", "end"]]


def paste_authenticate_steps(vpn, member, device, ca_pem, fingerprint):
    """Manual enrollment, first part: the trustpoint, and the CA certificate pasted in (accepted only with the
    expected fingerprint)."""
    trustpoint, lines = trustpoint_lines(vpn, member, device, "")
    pem = [line.strip() for line in ca_pem.strip().splitlines() if line.strip()]
    pasting = [(r"Do you accept this certificate", accepts(fingerprint)), (r"\[confirm\]", "")]
    step = PkiStep(member.key, f"Trust the CA on {member.title()} ({trustpoint})", trustpoint=trustpoint)
    step.steps = [(line, []) for line in ["configure terminal"] + lines]
    step.steps.append((f"crypto pki authenticate {trustpoint}", [(r"End with a blank line|quit", "\n".join(pem) +
                                                                  "\nquit")] + pasting))
    step.steps.append(("end", []))
    step.undo = untrust_steps(trustpoint)
    return step


def paste_request_steps(vpn, member):
    """Manual enrollment, second part: the router's certificate request, shown in the transcript (request_in())."""
    trustpoint = V.names(vpn, member)["trustpoint"]
    challenge = new_secret(16)
    answers = [(r"Password:", challenge), (r"Re-enter password", challenge),
               (r"Include the router serial number", "no"), (r"Include an IP address", "no"),
               (r"Display Certificate Request to terminal", "yes"), (r"Redisplay enrollment request", "no"),
               (r"You already have RSA keys", "no"), (YES_NO, "no"), (r"\[confirm\]", "")]
    step = PkiStep(member.key, f"Make {member.title()}'s certificate request", trustpoint=trustpoint)
    step.steps = [(line, answers) for line in ["configure terminal", f"crypto pki enroll {trustpoint}", "end"]]
    return step


def request_in(transcript):
    """The base64 certificate request a router showed (with BEGIN/END lines), or ""."""
    lines = (transcript or "").splitlines()
    found, inside = [], False
    for line in lines:
        text = line.strip()
        if "BEGIN" in text and "REQUEST" in text:
            inside = True
            found = [text]
            continue
        if inside:
            found.append(text)
            if "END" in text and "REQUEST" in text:
                return "\n".join(found)
    body = [line.strip() for line in lines if re.fullmatch(r"[A-Za-z0-9+/=]{40,}", line.strip())]
    if body:
        return "-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(body) + "\n-----END CERTIFICATE REQUEST-----"
    return ""


def import_steps(vpn, member, certificate_pem):
    """Manual enrollment, last part: the certificate the CA signed, pasted in."""
    trustpoint = V.names(vpn, member)["trustpoint"]
    pem = [line.strip() for line in certificate_pem.strip().splitlines() if line.strip()]
    step = PkiStep(member.key, f"Put {member.title()}'s certificate in", trustpoint=trustpoint)
    step.steps = [("configure terminal", []),
                  (f"crypto pki import {trustpoint} certificate", [(r"End with a blank line|quit",
                                                                    "\n".join(pem) + "\nquit"),
                                                                   (r"\[confirm\]", "")]),
                  ("end", [])]
    return step


def plan(vpn, devices, passphrase="", fingerprint=""):
    """[PkiStep] still needed before a certificate VPN can go in (nothing for one with keys): the CA server, NTP, and
    enrolling each router that hasn't a certificate in the trustpoint yet (SCEP; manual enrollment is driven step by
    step from the page)."""
    if not vpn.protected or vpn.auth.method != V.CERT:
        return []
    steps = []
    if vpn.auth.ca_kind == "router":
        ca = vpn.member(vpn.auth.ca_device)
        device = devices.get(ca.key) if ca is not None else None
        if device is not None and not ca_running(device, ca_server_name(vpn)):
            steps.append(ca_steps(vpn, device, passphrase or new_secret()))
    steps += ntp_steps(vpn, devices)
    if vpn.auth.ca_kind in ("router", "scep"):
        for member in vpn.members:
            device = devices.get(member.key)
            if device is None or not device.read or has_certificate(vpn, member, device):
                continue
            steps.append(enroll_steps(vpn, member, device, fingerprint))
    return steps


def has_certificate(vpn, member, device):
    trustpoint = V.names(vpn, member)["trustpoint"]
    status = device.status
    return status is not None and any(trustpoint in item.trustpoints and item.kind == "identity" and
                                      (item.status or "available").lower() == "available"
                                      for item in status.certificates)


def ca_fingerprint(show_server):
    """The CA certificate's fingerprint from show crypto pki server ("" until it has one)."""
    found = re.search(r"CA cert fingerprint:\s*([0-9A-Fa-f ]{16,})", show_server or "")
    return normal_fingerprint(found.group(1)) if found else ""
