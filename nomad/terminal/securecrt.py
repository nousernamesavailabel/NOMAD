"""Importing sessions from a SecureCRT XML export (File > Export Settings in SecureCRT).

The export holds SecureCRT's whole configuration; only the "Sessions" key matters here. Its sub-keys are folders, and
a key with a "Protocol Name" value is a session. Saved passwords ("Password V2") are encrypted with SecureCRT's
configuration passphrase ("" if none was set):

  "02:<hex>"  AES-256-CBC, key SHA-256(passphrase), zero IV (SecureCRT 7.3.3 to 9.x)
  "03:<hex>"  16-byte salt, then AES-256-CBC with key and IV from bcrypt_pbkdf(passphrase, salt, 48 bytes, 16 rounds)

Both decrypt to: 4-byte little-endian length, the password, SHA-256 of the password, padding. The hash tells a wrong
passphrase apart from a right one.
"""
import hashlib
import os
import tempfile
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from ..system import replace_file
from .sessions import AUTH_KEY, DEFAULT_PORTS, RAW, SERIAL, SSH, TELNET, Session, normalize_folder

IMPORT_FOLDER = "Imported from SecureCRT"
PROTOCOLS = {"ssh2": SSH, "ssh1": SSH, "telnet": TELNET, "raw": RAW, "serial": SERIAL}
PORT_VALUES = {"ssh2": "[SSH2] Port", "ssh1": "[SSH1] Port"}  # Telnet and raw use "Port"
PARITY = {0: "None", 1: "Odd", 2: "Even", 3: "Mark", 4: "Space"}
STOP_BITS = {0: 1, 1: 1.5, 2: 2}
DIGEST_BYTES = 32


class SecureCrtError(Exception):
    """The file isn't a SecureCRT export NOMAD can read."""


class WrongPassphrase(Exception):
    """A saved password didn't decrypt with the passphrase given."""


# ----------------------------------------------------------------- Passwords

def _unpad(plain):
    length = int.from_bytes(plain[:4], "little")
    password = plain[4:4 + length]
    digest = plain[4 + length:4 + length + DIGEST_BYTES]
    if len(password) != length or len(digest) != DIGEST_BYTES or hashlib.sha256(password).digest() != digest:
        raise WrongPassphrase()
    try:
        return password.decode("utf-8")
    except UnicodeDecodeError:
        raise WrongPassphrase() from None


def _aes_decrypt(key, iv, data):
    if not data or len(data) % 16:
        raise WrongPassphrase()
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


def decrypt_password(stored, passphrase=""):
    """The plain password from a "Password V2" value. Raises WrongPassphrase if it doesn't decrypt."""
    prefix, _, text = stored.strip().rpartition(":")
    try:
        data = bytes.fromhex(text)
    except ValueError:
        raise WrongPassphrase() from None
    secret = passphrase.encode("utf-8")
    if prefix in ("", "02"):
        return _unpad(_aes_decrypt(hashlib.sha256(secret).digest(), bytes(16), data))
    if prefix == "03":
        import bcrypt  # paramiko's own dependency
        if len(data) <= 16 or not secret:  # bcrypt_pbkdf needs a passphrase
            raise WrongPassphrase()
        derived = bcrypt.kdf(secret, data[:16], 48, 16, ignore_few_rounds=True)
        return _unpad(_aes_decrypt(derived[:32], derived[32:], data[16:]))
    raise WrongPassphrase()


def encrypt_password(password, passphrase="", salt=None):
    """SecureCRT's "03:" format (or "02:" without a salt)."""
    plain = password.encode("utf-8")
    plain = len(plain).to_bytes(4, "little") + plain + hashlib.sha256(plain).digest()
    plain += os.urandom(-len(plain) % 16)
    secret = passphrase.encode("utf-8")
    if salt is None:
        key, iv, prefix = hashlib.sha256(secret).digest(), bytes(16), "02:"
    else:
        import bcrypt
        derived = bcrypt.kdf(secret, salt, 48, 16, ignore_few_rounds=True)
        key, iv, prefix = derived[:32], derived[32:], "03:" + salt.hex()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return prefix + (encryptor.update(plain) + encryptor.finalize()).hex()


# ----------------------------------------------------------------- Sessions

@dataclass
class ImportedSession:
    session: Session
    encrypted_password: str = ""  # "Password V2" as SecureCRT stored it
    password: str = ""  # Filled in by SecureCrtExport.decrypt()


@dataclass
class SecureCrtExport:
    sessions: list = field(default_factory=list)
    skipped: list = field(default_factory=list)  # Names of sessions NOMAD can't use (RLogin, TAPI, no host)

    @property
    def encrypted_count(self):
        return sum(1 for item in self.sessions if item.encrypted_password)

    def decrypt(self, passphrase=""):
        """Decrypt every saved password with a passphrase. Returns how many decrypted; raises WrongPassphrase if
        there were some and none did."""
        decrypted = 0
        for item in self.sessions:
            if not item.encrypted_password:
                continue
            try:
                item.password = decrypt_password(item.encrypted_password, passphrase)
                decrypted += 1
            except WrongPassphrase:
                item.password = ""
        if self.encrypted_count and not decrypted:
            raise WrongPassphrase()
        return decrypted


def _values(key):
    """{name: value} of a key's own values: dwords as ints, strings as text, arrays as lists of text."""
    values = {}
    for child in key:
        name = child.get("name")
        if child.tag == "dword":
            try:
                values[name] = int((child.text or "0").strip())
            except ValueError:
                values[name] = 0
        elif child.tag == "string":
            values[name] = child.text or ""
        elif child.tag == "array":
            values[name] = [item.text or "" for item in child]
    return values


def session_from_securecrt(name, values, folder=IMPORT_FOLDER):
    """Build an ImportedSession from one SecureCRT session's values, or None if NOMAD can't use it."""
    protocol_name = str(values.get("Protocol Name", "")).strip().lower()
    protocol = PROTOCOLS.get(protocol_name)
    if protocol is None:
        return None
    session = Session(name=name.strip().replace("/", "-") or "Session", protocol=protocol,
                      folder=normalize_folder(folder))
    session.host = str(values.get("Hostname", "")).strip()
    port = values.get(PORT_VALUES.get(protocol_name, "Port"))
    session.port = port if isinstance(port, int) and 1 <= port <= 65535 else DEFAULT_PORTS.get(protocol, 22)
    session.username = str(values.get("Username", "")).strip()
    description = values.get("Description")
    if isinstance(description, list):
        session.notes = "\n".join(line for line in description if line).strip()
    if protocol == SSH and values.get("Use Global Public Key", 1) == 0:
        key_file = str(values.get("Identity Filename V2", "")).strip()
        if key_file and "${" not in key_file:  # SecureCRT's own path variables can't be resolved here
            session.auth, session.key_file = AUTH_KEY, key_file
    if protocol == SERIAL:
        session.serial_port = str(values.get("Com Port", "")).strip().upper() or "COM1"
        session.baud_rate = values.get("Baud Rate", 9600) or 9600
        session.data_bits = values.get("Data Bits", 8) or 8
        session.parity = PARITY.get(values.get("Parity", 0), "None")
        session.stop_bits = STOP_BITS.get(values.get("Stop Bits", 0), 1)
        session.flow_control = ("RTS/CTS" if values.get("CTS Flow") else "DSR/DTR" if values.get("DSR Flow") else
                                "XON/XOFF" if values.get("XON Flow") else "None")
    elif not session.host:
        return None
    if protocol == RAW:
        session.line_ending = "CR+LF"
    encrypted = str(values.get("Password V2", "")).strip() if protocol == SSH else ""
    if values.get("Session Password Saved", 1) == 0:
        encrypted = ""
    return ImportedSession(session, encrypted)


def read_securecrt_export(path):
    """Read a SecureCRT XML export. Raises SecureCrtError if it isn't one (or has no sessions)."""
    try:
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as error:
        raise SecureCrtError(f"Couldn't read the file: {error}") from None
    sessions_key = root.find("key[@name='Sessions']") if root.tag == "VanDyke" else None
    if sessions_key is None:
        raise SecureCrtError("This isn't a SecureCRT export with sessions in it. In SecureCRT, use Tools > Export "
                             "Settings and include the sessions.")
    export = SecureCrtExport()

    def walk(key, folder):
        for child in key.findall("key"):
            name = child.get("name") or ""
            values = _values(child)
            if "Protocol Name" in values:
                if not folder and name == "Default":  # SecureCRT's template for new sessions, not a real one
                    continue
                item = session_from_securecrt(name, values, f"{IMPORT_FOLDER}/{folder}" if folder else IMPORT_FOLDER)
                if item is None:
                    export.skipped.append(f"{folder}/{name}" if folder else name)
                else:
                    export.sessions.append(item)
            else:
                walk(child, f"{folder}/{name}" if folder else name)

    walk(sessions_key, "")
    return export


def import_securecrt(store, export, protect=None):
    """Add an export's sessions to the store, skipping ones already there (same folder, name, host and protocol).
    protect(password) encrypts decrypted passwords for saving; without it they aren't saved. Returns
    (added, passwords saved)."""
    existing = {(session.folder.lower(), session.name.lower(), session.host.lower(), session.protocol)
                for session in store.sessions}
    added = saved = 0
    for item in export.sessions:
        session = item.session
        key = (session.folder.lower(), session.name.lower(), session.host.lower(), session.protocol)
        if key in existing:
            continue
        if item.password and protect is not None:
            session.saved_password = protect(item.password)
            saved += 1
        store.sessions = [*store.sessions, session]
        existing.add(key)
        added += 1
    if added:
        store.save()
    return added, saved


def write_securecrt_export(path, sessions, reveal=None, passphrase=""):
    """Write SSH import XML. With reveal, encrypt saved passwords using the destination config passphrase.

    No configuration-wide security settings are changed by the XML. The destination must use this passphrase.
    Private key contents and saved private key passphrases are not exported.
    """
    if reveal is not None and not passphrase:
        raise SecureCrtError("Enter the destination SecureCRT configuration passphrase to encrypt saved passwords.")
    root = ElementTree.Element("VanDyke", version="3.0")
    sessions_key = ElementTree.SubElement(root, "key", name="Sessions")
    folders = {"": sessions_key}
    used = {}
    count = 0
    sessions = [session for session in sessions if session.protocol == SSH]
    # Create folders first so session names cannot shadow a later folder.
    for session in sessions:
        folder = normalize_folder(session.folder)
        parent = sessions_key
        parts = folder.split("/") if folder else []
        for index, part in enumerate(parts):
            prefix = "/".join(parts[:index + 1])
            if prefix not in folders:
                folders[prefix] = ElementTree.SubElement(parent, "key", name=part)
            parent = folders[prefix]
    for session in sessions:
        folder = normalize_folder(session.folder)
        parent = folders[folder]
        # SecureCRT stores folders and sessions in the same namespace.
        taken = used.setdefault(folder, {child.get("name", "").lower() for child in parent})
        name = session.name
        suffix = 2
        while name.lower() in taken or (not folder and name.lower() == "default"):
            name = f"{session.name} ({suffix})"
            suffix += 1
        taken.add(name.lower())
        key = ElementTree.SubElement(parent, "key", name=name)
        password = (encrypt_password(reveal(session.saved_password), passphrase, salt=os.urandom(16))
                    if reveal is not None and session.saved_password else "")
        values = [("string", "Protocol Name", "SSH2"), ("dword", "Is Session", 1),
                  ("string", "Hostname", session.host), ("dword", "[SSH2] Port", session.port),
                  ("string", "Username", session.username), ("dword", "Session Password Saved", int(bool(password)))]
        if password:
            values.append(("string", "Password V2", password))
        if session.auth == AUTH_KEY:
            values.extend([("dword", "Use Global Public Key", 0),
                           ("string", "Identity Filename V2", session.key_file)])
        for tag, name, value in values:
            ElementTree.SubElement(key, tag, name=name).text = str(value)
        description = ElementTree.SubElement(key, "array", name="Description")
        for line in session.notes.splitlines():
            ElementTree.SubElement(description, "string").text = line
        count += 1
    ElementTree.indent(root)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=os.path.dirname(os.path.abspath(path)), delete=False) as file:
            temporary = file.name
            ElementTree.ElementTree(root).write(file, encoding="utf-8", xml_declaration=True)
        replace_file(temporary, path)
    finally:
        if temporary and os.path.exists(temporary):
            os.unlink(temporary)
    return count
