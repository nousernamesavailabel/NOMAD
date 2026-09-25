"""DNS lookups with Resolve-DnsName, which returns structured records instead of nslookup's text."""
import ipaddress
import re
from dataclasses import dataclass

from .system import ps_quote, run_powershell_json

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "PTR", "SOA", "SRV", "ANY"]
HOSTNAME_PATTERN = re.compile(r"^[A-Za-z0-9_*]([A-Za-z0-9_\-]*)(\.[A-Za-z0-9_\-]+)*\.?$")

LOOKUP_SCRIPT = r"""
$parameters = @{ Name = %(name)s; Type = %(type)s; DnsOnly = $true; ErrorAction = 'Stop' }
if (%(server)s) { $parameters.Server = %(server)s }
$records = @(Resolve-DnsName @parameters | ForEach-Object {
    $data = if ($_.IPAddress) { $_.IPAddress }
        elseif ($_.NameExchange) { "$($_.Preference) $($_.NameExchange)" }
        elseif ($_.NameTarget) { "$($_.Priority) $($_.Weight) $($_.Port) $($_.NameTarget)" }
        elseif ($_.Strings) { $_.Strings -join ' ' }
        elseif ($_.PrimaryServer) { "$($_.PrimaryServer) $($_.NameAdministrator) serial $($_.SerialNumber)" }
        elseif ($_.NameHost) { $_.NameHost }
        else { '' }
    [ordered]@{ Name = $_.Name; Type = "$($_.Type)"; TTL = $_.TTL; Section = "$($_.Section)"; Data = "$data" }
})
ConvertTo-Json -InputObject $records -Depth 3 -Compress
"""


@dataclass
class DnsRecord:
    name: str
    type: str
    ttl: int
    section: str
    data: str


def validate_lookup_input(name, server):
    """Returns an error message, or None if the inputs are usable."""
    name, server = name.strip(), server.strip()
    if not name:
        return "Enter a name or IP address to look up."
    for value, label in ((name, "Name"), (server, "DNS server")):
        if not value:
            continue
        try:
            ipaddress.ip_address(value)
        except ValueError:
            if len(value) > 253 or not HOSTNAME_PATTERN.match(value):
                return f"{label}: '{value}' is not a valid host name or IP address."
    return None


def resolve(name, record_type="A", server=""):
    """Look up DNS records. Raises CommandError with the resolver's message on failure."""
    if record_type not in RECORD_TYPES:
        raise ValueError(f"Unsupported record type {record_type}.")
    name, server = name.strip(), server.strip()
    try:
        ipaddress.ip_address(name)
        record_type = "PTR" if record_type in ("A", "AAAA") else record_type  # Reverse lookup for addresses
    except ValueError:
        pass
    script = LOOKUP_SCRIPT % {
        "name": ps_quote(name),
        "type": ps_quote(record_type),
        "server": ps_quote(server),
    }
    rows = run_powershell_json(script) or []
    if isinstance(rows, dict):
        rows = [rows]
    return [DnsRecord(row.get("Name") or "", row.get("Type") or "", row.get("TTL") or 0, row.get("Section") or "",
                      row.get("Data") or "") for row in rows]
