"""The NOMAD Dashboard's HTTPS certificate: a self-signed one made for this computer's names on install, or one
imported from the company's certificate authority (a PFX/P12 file, or PEM files) so browsers trust it without a
warning. Either way it's kept as cert.pem and key.pem in the dashboard's folder (readable by administrators and the
service only)."""
import datetime
import hashlib
import ipaddress
import socket
import ssl
from pathlib import Path

CERT_FILE, KEY_FILE = "cert.pem", "key.pem"
CERTIFICATE_YEARS = 10


class CertificateError(Exception):
    """Why a certificate couldn't be imported (shown as is)."""


def host_names():
    from ..ipam.server import host_names as names
    return names()


def make_self_signed(directory):
    """A self-signed certificate for this computer's names and addresses (and localhost)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, socket.gethostname()),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NOMAD Dashboard")])
    alternatives = []
    for host in host_names() + ["localhost", "127.0.0.1"]:
        try:
            alternatives.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            alternatives.append(x509.DNSName(host))
    today = datetime.datetime.now(datetime.timezone.utc)
    certificate = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(today - datetime.timedelta(days=1))
                   .not_valid_after(today + datetime.timedelta(days=365 * CERTIFICATE_YEARS))
                   .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
                   .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .sign(key, hashes.SHA256()))
    write_pair(directory, certificate.public_bytes(serialization.Encoding.PEM),
               key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption()))


def write_pair(directory, certificate_pem, key_pem):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / KEY_FILE).write_bytes(key_pem)
    (directory / CERT_FILE).write_bytes(certificate_pem)


def ensure_certificate(directory):
    directory = Path(directory)
    if not (directory / CERT_FILE).exists() or not (directory / KEY_FILE).exists():
        make_self_signed(directory)


def load_import(path, password="", key_path=None):
    """(certificate chain PEM, key PEM) from a PFX/P12 file, or a PEM file holding the certificate (and the key, or
    the key in key_path). Raises CertificateError."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12

    path = Path(path)
    try:
        data = path.read_bytes()
    except OSError as error:
        raise CertificateError(f"Couldn't read {path.name}: {error.strerror or error}") from None
    secret = password.encode("utf-8") if password else None
    if path.suffix.lower() in (".pfx", ".p12"):
        try:
            key, certificate, extra = pkcs12.load_key_and_certificates(data, secret)
        except ValueError:
            raise CertificateError(f"Couldn't open {path.name}: the password may be wrong.") from None
        if key is None or certificate is None:
            raise CertificateError(f"{path.name} doesn't hold both a certificate and its private key.")
        chain = [certificate] + list(extra or [])
    else:
        try:
            chain = x509.load_pem_x509_certificates(data)
        except ValueError:
            raise CertificateError(f"{path.name} doesn't hold a PEM certificate.") from None
        key_data = Path(key_path).read_bytes() if key_path else data
        try:
            key = serialization.load_pem_private_key(key_data, secret)
        except (ValueError, TypeError):
            raise CertificateError("Couldn't read the private key (is it in the file, and is the password "
                                   "right?).") from None
        certificate = chain[0]
    public = certificate.public_key().public_bytes(serialization.Encoding.DER,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(serialization.Encoding.DER,
                                     serialization.PublicFormat.SubjectPublicKeyInfo) != public:
        raise CertificateError("The private key isn't the certificate's.")
    if certificate.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc):
        raise CertificateError("That certificate has expired.")
    chain_pem = b"".join(item.public_bytes(serialization.Encoding.PEM) for item in chain)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return chain_pem, key_pem


def check_pair(certificate_pem, key_pem):
    """Raise CertificateError unless Python's TLS can serve with them."""
    import tempfile
    with tempfile.TemporaryDirectory() as folder:
        write_pair(folder, certificate_pem, key_pem)
        try:
            server_context(folder)
        except (ssl.SSLError, OSError) as error:
            raise CertificateError(f"That certificate can't be used: {error}") from None


def server_context(directory):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(Path(directory) / CERT_FILE, Path(directory) / KEY_FILE)
    return context


def describe(directory):
    """{"subject", "issuer", "expires", "fingerprint", "self_signed"} of the certificate in use, or {}."""
    from cryptography import x509
    try:
        data = (Path(directory) / CERT_FILE).read_bytes()
        certificate = x509.load_pem_x509_certificates(data)[0]
    except (OSError, ValueError, IndexError):
        return {}
    from cryptography.hazmat.primitives import serialization
    der = certificate.public_bytes(serialization.Encoding.DER)
    digest = hashlib.sha256(der).hexdigest().upper()
    return {"subject": certificate.subject.rfc4514_string(), "issuer": certificate.issuer.rfc4514_string(),
            "expires": certificate.not_valid_after_utc.strftime("%Y-%m-%d"),
            "fingerprint": ":".join(digest[index:index + 2] for index in range(0, len(digest), 2)),
            "self_signed": certificate.subject == certificate.issuer}
