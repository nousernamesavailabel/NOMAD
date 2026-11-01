"""pfSense: how full a firewall's disks are, from the Host Resources MIB (the Host Resources module of its SNMP
service, Services > SNMP).

What pfSense 2.8.1 (FreeBSD's bsnmpd) does, as walked from a firewall on ZFS:
- hrStorageTable has 700+ rows, nearly all the kernel's memory zones ("UMA: mbuf"): so only its type column is walked,
  and the disks' rows are then asked for by GET.
- File systems aren't typed hrStorageFixedDisk: their type is one of hrFSTypes instead (hrFSOther for zfs and devfs,
  hrFSUnknown for tmpfs).
- A file system's description is "<mount>, type: <file system>, dev: <device>": "/var/log, type: zfs, dev:
  pfSense/var/log". The pool is the first part of a ZFS device.
- Each ZFS dataset's size is its own used space plus the free space of the pool: they all show the same free space,
  and adding their sizes up would count that once per dataset. So a pool is the sum of its datasets' used space plus
  that free space once. (What only the pool sees, such as snapshots, isn't in any dataset: free space is exact, but
  the total can be a little under the pool's real size.)
- Past 2^31 blocks the allocation unit doubles, rather than the size being cut off, so big pools still add up.

The parsers take the (oid, Value) pairs a walk returns, like collect's, so they can be tested without a network.
"""
import re

from ..snmp import OBJECT_ID, oid_text, parse_oid
from .collect import column, columns, text

STORAGE_ENTRY = "1.3.6.1.2.1.25.2.3.1"  # hrStorageTable (index: hrStorageIndex)
STORAGE_TYPE, STORAGE_DESCR, STORAGE_UNITS, STORAGE_SIZE, STORAGE_USED = 2, 3, 4, 5, 6
DETAIL_COLUMNS = (STORAGE_DESCR, STORAGE_UNITS, STORAGE_SIZE, STORAGE_USED)
FIXED_DISK = "1.3.6.1.2.1.25.2.1.4"  # hrStorageFixedDisk
FILE_SYSTEM_TYPES = "1.3.6.1.2.1.25.3.9"  # hrFSTypes: hrFSOther and the rest are under it
DESCRIPTION = re.compile(r"^(?P<mount>.*), type: (?P<kind>\S+), dev: (?P<device>.*)$")
ZFS = "zfs"
NOT_DISKS = {"devfs", "fdescfs", "nullfs", "procfs", "tmpfs"}  # Mounted, but not on a drive


def disk_indexes(type_rows):
    """The rows of hrStorageTable that are disks, from its walked type column."""
    found = []
    for index, value in column(type_rows, f"{STORAGE_ENTRY}.{STORAGE_TYPE}").items():
        if len(index) == 1 and value.tag == OBJECT_ID:
            kind = oid_text(value.value)
            if kind == FIXED_DISK or kind.startswith(FILE_SYSTEM_TYPES + "."):
                found.append(index[0])
    return found


def detail_oids(indexes):
    """The OIDs to GET for those rows."""
    entry = parse_oid(STORAGE_ENTRY)
    return [entry + (number, index) for index in indexes for number in DETAIL_COLUMNS]


def disks(rows):
    """The disks in those rows, in table order: [{"name", "total", "used", "free"}] in bytes. A ZFS pool is one disk,
    named for the pool; any other file system is its own, named for where it's mounted."""
    found = {}
    for _, row in sorted(columns(rows, STORAGE_ENTRY).items()):
        if any(number not in row for number in DETAIL_COLUMNS):
            continue
        descr = text(row[STORAGE_DESCR])
        match = DESCRIPTION.match(descr)
        kind, device = (match["kind"], match["device"]) if match else ("", "")
        units, size, used = (row[number].value for number in (STORAGE_UNITS, STORAGE_SIZE, STORAGE_USED))
        if kind in NOT_DISKS or units <= 0 or size <= 0:
            continue
        mount = match["mount"] if match else descr
        name = device.split("/")[0] if kind == ZFS and device else mount
        disk = found.setdefault(name, {"name": name, "total": 0, "used": 0, "free": 0})
        disk["used"] += used * units
        disk["free"] = max(disk["free"], (size - used) * units)  # The same on each of a pool's datasets
        disk["total"] = disk["used"] + disk["free"]
    return list(found.values())
