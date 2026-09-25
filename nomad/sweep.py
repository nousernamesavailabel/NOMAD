"""Network sweep: find which hosts on an IPv4 subnet answer ping (formerly the RADAR tool).

Also finds PuTTY and adds it to the user's PATH so discovered hosts can be opened over SSH.
"""
import ctypes
import ipaddress
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

from .icmp import IcmpClient

SWEEP_PASSES = 3  # A host that misses a pass is retried on the next; missing every pass means it's down
LARGE_SWEEP_HOSTS = 65536  # Ask before sweeping more addresses than this


def sweep_hosts(subnet):
    """Parse an IPv4 subnet like 192.168.1.0/24 (or a single address) and return (network, hosts).

    Raises ValueError with a message suitable for showing to the user.
    """
    subnet = subnet.strip()
    if not subnet:
        raise ValueError("Enter a subnet, such as 192.168.1.0/24.")
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError:
        raise ValueError(f"'{subnet}' is not a valid subnet. Use CIDR notation, such as 192.168.1.0/24.") from None
    if network.version != 4:
        raise ValueError("Only IPv4 subnets can be swept; IPv6 subnets are far too large.")
    hosts = list(network.hosts())
    if not hosts:
        raise ValueError("The subnet contains no usable host addresses.")
    return network, hosts


def ping_once(address, timeout):
    """Ping an IPv4 address once. Returns the round trip time in ms, or None if the host didn't answer."""
    with IcmpClient(4) as client:
        reply = client.echo(str(address), timeout=timeout)
    # Only a success status counts: a router can answer with "unreachable" on the host's behalf
    return reply.rtt if reply.ok else None


def run_sweep(hosts, probe, workers, passes=SWEEP_PASSES, should_stop=lambda: False,
              found=lambda address, rtt: None, progress=lambda done, total, pass_number, remaining: None):
    """Probe every host, retrying the ones that didn't answer on later passes.

    probe(address) returns a round trip time in ms, or None for no reply.
    found(address, rtt) is called for each host as soon as it answers.
    progress(done, total, pass_number, remaining) reports work done out of hosts * passes; a host
    that answers early is credited for the passes it skips. remaining is the number of hosts in this pass.
    Returns the list of (address, rtt) for hosts that answered, in the order they answered.
    """
    total = len(hosts) * passes
    done = 0
    alive = []
    pending = list(hosts)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        for pass_number in range(1, passes + 1):
            if should_stop() or not pending:
                break
            progress(done, total, pass_number, len(pending))
            futures = {executor.submit(lambda address=address: None if should_stop() else probe(address)): address
                       for address in pending}
            next_pending = []
            for future in as_completed(futures):
                if should_stop():
                    for waiting in futures:
                        waiting.cancel()
                    break
                address = futures[future]
                try:
                    rtt = future.result()
                except OSError:
                    rtt = None
                done += 1
                if rtt is None:
                    next_pending.append(address)
                else:
                    done += passes - pass_number  # Not probed again on the remaining passes
                    alive.append((address, rtt))
                    found(address, rtt)
                progress(done, total, pass_number, len(pending))
            pending = next_pending
    return alive


# ----------------------------------------------------------------- PuTTY

def putty_locations():
    return [
        r"C:\Program Files\PuTTY\putty.exe",
        r"C:\Program Files (x86)\PuTTY\putty.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\PuTTY\putty.exe"),
        os.path.expandvars(r"%LOCALAPPDATA%\PuTTY\putty.exe"),
    ]


def find_putty():
    """Return the path to putty.exe from PATH or a common install location, or None."""
    return shutil.which("putty.exe") or next((path for path in putty_locations() if os.path.isfile(path)), None)


def _normalize(path):
    return os.path.normcase(os.path.normpath(os.path.expandvars(path)))


def add_to_user_path(directory):
    """Add a directory to the user's PATH (and this process's). Returns False if it was already there."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
        try:
            current, value_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            current, value_type = "", winreg.REG_EXPAND_SZ
        entries = [entry.strip() for entry in current.split(";") if entry.strip()]
        added = _normalize(directory) not in {_normalize(entry) for entry in entries}
        if added:
            winreg.SetValueEx(key, "Path", 0, value_type, ";".join(entries + [directory]))

    process_entries = os.environ.get("PATH", "").split(os.pathsep)
    if _normalize(directory) not in {_normalize(entry) for entry in process_entries if entry}:
        os.environ["PATH"] = directory + os.pathsep + os.environ.get("PATH", "")

    if added:
        # Tell running programs (Explorer, new consoles) that the environment changed
        HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG = 0xFFFF, 0x001A, 0x0002
        ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
                                                 SMTO_ABORTIFHUNG, 5000, None)
    return added
