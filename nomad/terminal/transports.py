"""The connections behind a terminal: SSH, Telnet, serial and raw TCP, all with the same small interface.

connect() blocks (run it off the UI thread) and asks the user things (host keys, passwords) through a Prompter.
read() blocks until data arrives and returns b"" once the connection has closed.
"""
import logging
import os
import socket

import paramiko
import serial

from . import telnet
from .credentials import CredentialError
from .hostkeys import CHANGED, MATCH, KnownHosts, fingerprint
from .legacy_ssh import CompatibleTransport, describe_algorithms, uses_legacy
from .sessions import AUTH_AGENT, AUTH_KEY, LINE_ENDINGS, RAW, SERIAL, SSH, TELNET
from .vault import Vault, VaultLocked

log = logging.getLogger(__name__)

CONNECT_TIMEOUT = 10
PASSWORD_TRIES = 3
READ_SIZE = 65536
SERIAL_PARITY = {"None": serial.PARITY_NONE, "Even": serial.PARITY_EVEN, "Odd": serial.PARITY_ODD,
                 "Mark": serial.PARITY_MARK, "Space": serial.PARITY_SPACE}
SERIAL_STOP_BITS = {1: serial.STOPBITS_ONE, 1.5: serial.STOPBITS_ONE_POINT_FIVE, 2: serial.STOPBITS_TWO}


class ConnectionFailed(Exception):
    """Connecting didn't work; the message is suitable for showing to the user."""


class Cancelled(ConnectionFailed):
    def __init__(self):
        super().__init__("Cancelled.")


class Prompter:
    """How a connection asks the user things. The UI implements these (they block until answered)."""

    def host_key(self, host, port, key_type, fingerprint, changed, old_fingerprint):
        """"trust" (and remember), "once", or "cancel"."""
        return "cancel"

    def secret(self, title, prompt, can_save):
        """(value, save) or None if cancelled. For passwords and key passphrases."""
        return None

    def text(self, title, prompt):
        """A line of text (such as a user name), or None if cancelled."""
        return None

    def username(self, host):
        """The user name to log in to host as, or None if cancelled. The UI may have the session log in with a saved
        credential instead, filling in its user name and password or key."""
        return self.text("User Name", f"User name for {host}:")

    def unlock_vault(self):
        """Ask for the master password so saved secrets can be used. True once unlocked, False if declined."""
        return False

    def save_secret(self, kind, value):
        """Remember a password ("password") or key passphrase ("passphrase") the user asked us to save."""


def friendly_socket_error(error, host, port):
    if isinstance(error, socket.gaierror):
        return f"Couldn't find {host} (not in DNS, or no network)."
    if isinstance(error, (socket.timeout, TimeoutError)):
        return f"No answer from {host} port {port} (a firewall may be dropping it, or the device is off)."
    if isinstance(error, ConnectionRefusedError):
        return f"{host} refused the connection: nothing is listening on port {port}."
    return f"Couldn't connect to {host} port {port}: {getattr(error, 'strerror', None) or error}"


class Transport:
    """Base class. `enter` is what the Enter key sends; `local_echo` shows typed text locally."""
    enter = "\r"
    local_echo = False
    description = ""  # Shown in the status bar once connected
    notice = ""  # A warning worth showing once connected

    def __init__(self, session, prompter=None, size=(80, 24)):
        self.session, self.prompter, self.size = session, prompter or Prompter(), size
        self.vault = Vault()  # Replaced with the session store's vault, which knows the master password settings
        self.closed = False
        self.close_reason = ""

    def reveal(self, stored):
        """A saved secret, or None to ask the user for it instead (none saved, unreadable, or left locked)."""
        if not stored:
            return None
        try:
            return self.vault.reveal(stored)
        except VaultLocked:
            if not self.prompter.unlock_vault():
                return None
            try:
                return self.vault.reveal(stored)
            except (VaultLocked, CredentialError):
                return None
        except CredentialError as error:
            log.warning("A saved secret for %s couldn't be read: %s", self.session.name, error)
            return None

    def connect(self):
        raise NotImplementedError

    def read(self):
        raise NotImplementedError

    def send(self, data):
        raise NotImplementedError

    def resize(self, columns, rows):
        self.size = (columns, rows)

    def close(self):
        self.closed = True


class RawTransport(Transport):
    """A plain TCP connection, such as a terminal server port or a printer's port 9100."""

    def __init__(self, session, prompter=None, size=(80, 24)):
        super().__init__(session, prompter, size)
        self.sock = None
        self.enter = LINE_ENDINGS.get(session.line_ending, "\r\n")
        self.local_echo = session.local_echo

    def connect(self):
        host, port = self.session.host.strip(), int(self.session.port)
        try:
            self.sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as error:
            raise ConnectionFailed(friendly_socket_error(error, host, port)) from None
        self.sock.settimeout(None)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Keystrokes go out straight away
        self.description = f"Connected to {host} port {port}"

    def read(self):
        try:
            data = self.sock.recv(READ_SIZE)
        except OSError as error:
            if not self.closed:
                self.close_reason = f"Connection lost: {error.strerror or error}"
            return b""
        if not data and not self.close_reason:
            self.close_reason = "The other end closed the connection."
        return data

    def send(self, data):
        try:
            self.sock.sendall(data)
        except OSError:
            pass  # read() notices the connection has gone and reports it

    def close(self):
        super().close()
        if self.sock is not None:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()


class TelnetTransport(RawTransport):
    def __init__(self, session, prompter=None, size=(80, 24)):
        super().__init__(session, prompter, size)
        self.protocol = telnet.TelnetProtocol(session.terminal_type, size)
        self.enter = "\r\n"
        self.local_echo = session.local_echo

    def connect(self):
        super().connect()
        self.description = f"Telnet to {self.session.host} port {self.session.port}"

    def read(self):
        while True:
            data = super().read()
            if not data:
                return b""
            shown, replies = self.protocol.feed(data)
            if replies:
                self.send_raw(replies)
            if shown:
                return shown  # Otherwise it was all negotiation: keep reading

    def send_raw(self, data):
        super().send(data)

    def send(self, data):
        super().send(telnet.escape(data))

    def resize(self, columns, rows):
        super().resize(columns, rows)
        update = self.protocol.resize(columns, rows)
        if update and self.sock is not None:
            self.send_raw(update)


class SerialTransport(Transport):
    """A COM port, such as a USB console cable to a switch."""

    def __init__(self, session, prompter=None, size=(80, 24)):
        super().__init__(session, prompter, size)
        self.port = None
        self.enter = LINE_ENDINGS.get(session.line_ending, "\r")
        self.local_echo = session.local_echo

    def connect(self):
        session = self.session
        flow = session.flow_control
        try:
            self.port = serial.serial_for_url(
                session.serial_port.strip(), baudrate=int(session.baud_rate), bytesize=int(session.data_bits),
                parity=SERIAL_PARITY.get(session.parity, serial.PARITY_NONE),
                stopbits=SERIAL_STOP_BITS.get(float(session.stop_bits), serial.STOPBITS_ONE),
                xonxoff=flow == "XON/XOFF", rtscts=flow == "RTS/CTS", dsrdtr=flow == "DSR/DTR", timeout=0.2)
        except (serial.SerialException, ValueError) as error:
            message = str(error)
            if "FileNotFoundError" in message or "could not open port" in message.lower():
                if "PermissionError" in message or "Access is denied" in message:
                    message = f"{session.serial_port} is in use by another program (close PuTTY or any other " \
                              "terminal using it)."
                else:
                    message = f"{session.serial_port} doesn't exist. Check the cable is plugged in and which COM " \
                              "port it was given (Device Manager, or the list in the session settings)."
            raise ConnectionFailed(message) from None
        self.description = f"{session.target()}"

    def read(self):
        while not self.closed:
            try:
                data = self.port.read(self.port.in_waiting or 1)
            except (serial.SerialException, OSError, TypeError, AttributeError) as error:
                if not self.closed:
                    self.close_reason = f"The serial port stopped working (unplugged?): {error}"
                return b""
            if data:
                return data
        return b""

    def send(self, data):
        try:
            self.port.write(data)
        except (serial.SerialException, OSError):
            pass

    def send_break(self, seconds=0.5):
        """A serial break: what Cisco devices watch for to enter ROMMON (password recovery)."""
        self.port.send_break(seconds)

    def close(self):
        super().close()
        if self.port is not None:
            try:
                self.port.close()
            except (serial.SerialException, OSError):
                pass


class SshTransport(Transport):
    def __init__(self, session, prompter=None, size=(80, 24), known_hosts=None):
        super().__init__(session, prompter, size)
        self.known_hosts = known_hosts or KnownHosts()
        self.transport = None
        self.channel = None
        self.password = None  # The password that logged in (kept in memory only, for sudo on the SCP page)

    def connect(self):
        session = self.session
        username = self.login()
        try:
            self.channel = self.transport.open_session()
            columns, rows = self.size
            self.channel.get_pty(term=session.terminal_type, width=columns, height=rows)
            self.channel.invoke_shell()
        except paramiko.SSHException as error:
            self.close()
            raise ConnectionFailed(f"Logged in, but the device wouldn't open a terminal: {error}") from None
        self.description = f"SSH to {username}@{session.host.strip()} ({describe_algorithms(self.transport)})"

    def login(self):
        """Connect, check the host key and log in, leaving self.transport ready for channels. Returns the user name.
        Shared by the terminal and the SCP page."""
        session = self.session
        host, port = session.host.strip(), int(session.port)
        try:
            sock = socket.create_connection((host, port), timeout=CONNECT_TIMEOUT)
        except OSError as error:
            raise ConnectionFailed(friendly_socket_error(error, host, port)) from None
        if self.closed:  # Closed while the connection was being made (nothing to close then)
            sock.close()
            raise Cancelled()
        try:
            self.transport = CompatibleTransport(sock)
            self.transport.banner_timeout = 15
            self.transport.start_client(timeout=20)
        except paramiko.SSHException as error:
            sock.close()
            message = str(error)
            if "banner" in message.lower():
                raise ConnectionFailed(f"{host} port {port} isn't answering as an SSH server (or closed the "
                                       "connection straight away). Is it Telnet, or is SSH turned off?") from None
            if "incompatible" in message.lower() or "no acceptable" in message.lower():
                raise ConnectionFailed(f"{host} and NOMAD have no SSH algorithms in common: {message}") from None
            raise ConnectionFailed(f"SSH failed: {message}") from None
        except (EOFError, OSError) as error:
            sock.close()
            raise ConnectionFailed(f"{host} closed the connection during setup: {error or 'no reason given'}") \
                from None

        self.check_host_key(host, port)
        username = session.username.strip() or self.prompter.username(host)
        if not username:
            self.close()
            raise Cancelled()
        self.authenticate(username)
        if session.keepalive:
            self.transport.set_keepalive(int(session.keepalive))
        if uses_legacy(self.transport):
            self.notice = ("This device only supports older SHA-1 SSH algorithms. The connection works, but "
                           "consider updating its firmware.")
        return username

    def check_host_key(self, host, port):
        key = self.transport.get_remote_server_key()
        status, old = self.known_hosts.check(host, port, key)
        if status == MATCH:
            return
        decision = self.prompter.host_key(host, port, key.get_name(), fingerprint(key), status == CHANGED,
                                          fingerprint(old) if old is not None else "")
        if decision == "trust":
            self.known_hosts.remember(host, port, key)
        elif decision != "once":
            self.close()
            raise Cancelled()

    def authenticate(self, username):
        session, transport = self.session, self.transport
        try:
            transport.auth_none(username)
            return  # Some devices let anyone in (a login prompt follows in the terminal)
        except paramiko.BadAuthenticationType as error:
            allowed = set(error.allowed_types)
        except paramiko.SSHException:
            allowed = {"publickey", "password", "keyboard-interactive"}

        if "publickey" in allowed and session.auth == AUTH_KEY and session.key_file:
            if self.try_key_file(username):
                return
        if "publickey" in allowed and session.auth == AUTH_AGENT:
            if self.try_agent(username):
                return
        if not allowed & {"password", "keyboard-interactive"}:
            self.close()
            raise ConnectionFailed(f"{session.host} only accepts: {', '.join(sorted(allowed))}.")

        failed = False
        saved = self.reveal(session.saved_password)
        if saved is not None:
            if self.try_password(username, saved, allowed):
                return
            failed = True  # The saved password no longer works: ask for the new one
        for attempt in range(PASSWORD_TRIES):
            prompt = "That didn't work. Try the password again:" if failed or attempt else \
                f"Password for {username}@{session.host}:"
            answer = self.prompter.secret("Password", prompt, True)
            if answer is None:
                self.close()
                raise Cancelled()
            password, save = answer
            if self.try_password(username, password, allowed):
                if save:
                    self.prompter.save_secret("password", password)
                return
        self.close()
        raise ConnectionFailed("Login failed: the user name or password wasn't accepted.")

    def try_password(self, username, password, allowed):
        try:
            if "password" in allowed:
                self.transport.auth_password(username, password)  # Falls back to keyboard-interactive
            else:
                self.transport.auth_interactive(username, lambda title, instructions, prompts: [
                    password if not echo else (self.prompter.text(title or "Login", prompt) or "")
                    for prompt, echo in prompts])
            if self.transport.is_authenticated():
                self.password = password
                return True
            return False
        except paramiko.AuthenticationException:
            if not self.transport.is_active():
                self.disconnected_during_login()
            return False
        except (paramiko.SSHException, EOFError, OSError) as error:
            if not self.transport.is_active():
                self.disconnected_during_login()
            self.close()
            raise ConnectionFailed(f"Login failed: {error}") from None

    def disconnected_during_login(self):
        """A dropped connection isn't a wrong password: say what actually happened."""
        self.close()
        raise ConnectionFailed(f"{self.session.host} closed the connection during login, so the password wasn't "
                               "checked. It may have hit its limit of login attempts, or be refusing logins from this "
                               "computer. Details are in the log (View Log).")

    def load_key(self):
        path = os.path.expandvars(os.path.expanduser(self.session.key_file.strip()))
        if path.lower().endswith(".ppk"):
            raise ConnectionFailed("PuTTY .ppk keys can't be read directly. In PuTTYgen, load the key and use "
                                   "Conversions > Export OpenSSH key, then choose that file.")
        if not os.path.isfile(path):
            raise ConnectionFailed(f"The key file {path} doesn't exist.")
        saved = self.reveal(self.session.saved_passphrase)
        try:
            return paramiko.PKey.from_path(path, password=saved.encode() if saved is not None else None)
        except paramiko.PasswordRequiredException:
            pass  # Encrypted, and no saved passphrase: ask
        except TypeError as error:  # Older PEM keys say "Password was not given but private key is encrypted"
            if "encrypted" not in str(error):
                raise ConnectionFailed(f"Couldn't read the key file {path}: {error}") from None
        except (paramiko.SSHException, ValueError) as error:
            if saved is None:  # Not a passphrase problem: the file itself is the trouble
                raise ConnectionFailed(f"Couldn't read the key file {path}: {error}") from None
        except OSError as error:
            raise ConnectionFailed(f"Couldn't read the key file {path}: {error.strerror or error}") from None
        for attempt in range(PASSWORD_TRIES):
            prompt = f"Passphrase for {os.path.basename(path)}:" if not attempt else \
                "That passphrase didn't work. Try again:"
            answer = self.prompter.secret("Key Passphrase", prompt, True)
            if answer is None:
                raise Cancelled()
            passphrase, save = answer
            try:
                key = paramiko.PKey.from_path(path, password=passphrase.encode())
            except (paramiko.SSHException, ValueError):
                continue
            if save:
                self.prompter.save_secret("passphrase", passphrase)
            return key
        raise ConnectionFailed("The key's passphrase wasn't right.")

    def try_key_file(self, username):
        try:
            key = self.load_key()
        except ConnectionFailed:
            self.close()
            raise
        try:
            self.transport.auth_publickey(username, key)
            return self.transport.is_authenticated()
        except paramiko.AuthenticationException:
            return False

    def try_agent(self, username):
        try:
            keys = paramiko.Agent().get_keys()
        except (paramiko.SSHException, OSError):
            keys = ()
        for key in keys:
            try:
                self.transport.auth_publickey(username, key)
                if self.transport.is_authenticated():
                    return True
            except paramiko.SSHException:
                continue
        return False

    def read(self):
        try:
            data = self.channel.recv(READ_SIZE)
        except (OSError, EOFError, paramiko.SSHException) as error:
            if not self.closed:
                self.close_reason = f"Connection lost: {error}"
            return b""
        if not data and not self.close_reason:
            if self.channel.exit_status_ready():
                status = self.channel.recv_exit_status()
                self.close_reason = "Logged out." if status in (0, -1) else f"Session ended (exit status {status})."
            elif not self.transport.is_active():
                self.close_reason = "Connection lost."
            else:
                self.close_reason = "The device closed the session."
        return data

    def send(self, data):
        try:
            self.channel.sendall(data)
        except (OSError, EOFError, paramiko.SSHException):
            pass

    def resize(self, columns, rows):
        super().resize(columns, rows)
        if self.channel is not None and not self.closed:
            try:
                self.channel.resize_pty(width=columns, height=rows)
            except (OSError, paramiko.SSHException):
                pass

    def close(self):
        super().close()
        for thing in (self.channel, self.transport):
            if thing is not None:
                try:
                    thing.close()
                except (OSError, EOFError, paramiko.SSHException):
                    pass


TRANSPORTS = {SSH: SshTransport, TELNET: TelnetTransport, SERIAL: SerialTransport, RAW: RawTransport}


def make_transport(session, prompter=None, size=(80, 24), vault=None):
    transport = TRANSPORTS[session.protocol](session, prompter, size)
    if vault is not None:
        transport.vault = vault
    return transport


def serial_ports():
    """[(device, description)] for the COM ports on this computer."""
    from serial.tools import list_ports
    return sorted(((port.device, port.description) for port in list_ports.comports()),
                  key=lambda item: (len(item[0]), item[0]))
