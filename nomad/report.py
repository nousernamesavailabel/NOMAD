"""Diagnostics report: run a standard set of checks on an adapter and write the findings up as HTML.

Every check copes with having no internet access: an isolated network is reported as such, not as a fault.
"""
import html
import platform
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import __version__
from .dnsclient import benchmark_server
from .icmp import IcmpClient, PingStats, find_path_mtu, make_mtu_probe
from .mtr import MtrTrace, hop_losses, report_text
from .neighbors import arp_lookup, load_neighbors, shared_macs
from .ports import OPEN, check_port
from .system import APP_FULL_NAME, APP_NAME

OK, INFO, WARNING, PROBLEM = "ok", "info", "warning", "problem"
STATUS_LABELS = {OK: "OK", INFO: "Info", WARNING: "Warning", PROBLEM: "Problem"}
SEVERITY = {OK: 0, INFO: 1, WARNING: 2, PROBLEM: 3}

INTERNET_PING_TARGETS = ["8.8.8.8", "1.1.1.1"]
INTERNET_TCP_TARGETS = [("1.1.1.1", 443), ("8.8.8.8", 443)]
DNS_TEST_NAMES = ["example.com", "microsoft.com"]
TRACE_TARGET = "8.8.8.8"
GATEWAY_PINGS = 10
SLOW_DNS_MS = 150
HIGH_GATEWAY_MS = 20
MTU_RANGE = (576, 1500)


@dataclass
class Finding:
    section: str
    status: str
    summary: str
    details: list = field(default_factory=list)
    preformatted: str = ""  # A text table to show as-is (the traceroute)


@dataclass
class Report:
    adapter: str
    computer: str = ""
    created: str = ""
    findings: list = field(default_factory=list)

    @property
    def status(self):
        return max((finding.status for finding in self.findings), key=SEVERITY.get, default=OK)

    def counts(self):
        counts = {}
        for finding in self.findings:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        return counts


# ----------------------------------------------------------------- Evaluating results

def evaluate_adapter(adapter):
    details = [f"Description: {adapter.description}" if adapter.description else "",
               f"Status: {adapter.status}", f"MAC address: {adapter.mac}" if adapter.mac else "",
               f"Link speed: {adapter.speed_text}" if adapter.speed_text else "",
               "IPv4 addresses: " + (", ".join(str(address) for address in adapter.ipv4) or "none"),
               "Addressing: " + ("DHCP" if adapter.dhcp else "static") if adapter.dhcp is not None else "",
               "Gateway: " + (", ".join(adapter.gateways4) or "none"),
               "DNS servers: " + (", ".join(adapter.dns4 + adapter.dns6) or "none"),
               f"MTU: {adapter.mtu4}" if adapter.mtu4 else ""]
    details = [line for line in details if line]
    if adapter.status == "Disabled":
        return Finding("Adapter", PROBLEM, f"{adapter.name} is disabled.", details)
    if adapter.status != "Up":
        return Finding("Adapter", PROBLEM, f"{adapter.name} isn't connected (no cable or no Wi-Fi network).",
                       details)
    usable = [address for address in adapter.ipv4 if not address.ip.is_link_local]
    if not usable:
        if adapter.dhcp:
            return Finding("Adapter", PROBLEM, "No address from DHCP: the adapter only has an automatic 169.254.x.x "
                                               "address, so no DHCP server answered.", details)
        return Finding("Adapter", PROBLEM, "The adapter has no usable IPv4 address.", details)
    problems = []
    if not adapter.gateways4:
        problems.append("there's no default gateway, so only the local subnet can be reached")
    if not (adapter.dns4 or adapter.dns6):
        problems.append("there are no DNS servers, so names won't resolve")
    if problems:
        return Finding("Adapter", WARNING, f"{adapter.name} is connected, but " + " and ".join(problems) + ".",
                       details)
    return Finding("Adapter", OK, f"{adapter.name} is connected with address {usable[0]}"
                                  + (f" at {adapter.speed_text}." if adapter.speed_text else "."), details)


def evaluate_gateway(gateway, stats, gateway_mac):
    if gateway is None:
        return Finding("Gateway", WARNING, "There's no default gateway to test.")
    details = [stats.summary()]
    if gateway_mac:
        details.append(f"Gateway MAC address: {gateway_mac}")
    if not stats.received:
        if gateway_mac:
            return Finding("Gateway", WARNING, f"The gateway {gateway} is there (it answered ARP) but doesn't answer "
                                               "ping. Some routers and firewalls block ping on purpose.", details)
        return Finding("Gateway", PROBLEM, f"The gateway {gateway} can't be reached: no reply to ping or ARP.",
                       details)
    average = sum(stats.rtts) / len(stats.rtts)
    if stats.loss_percent >= 50:
        return Finding("Gateway", PROBLEM, f"{stats.loss_percent}% of pings to the gateway {gateway} were lost. "
                                           "Check the cable, Wi-Fi signal or switch port.", details)
    if stats.lost:
        return Finding("Gateway", WARNING, f"{stats.loss_percent}% of pings to the gateway {gateway} were lost; "
                                           "a healthy local link loses none.", details)
    if average > HIGH_GATEWAY_MS:
        return Finding("Gateway", WARNING, f"The gateway {gateway} answers, but slowly for a local device "
                                           f"(average {average:.0f} ms).", details)
    return Finding("Gateway", OK, f"The gateway {gateway} answers with no loss (average {average:.0f} ms).",
                   details)


def evaluate_dns(results):
    if not results:
        return Finding("DNS", WARNING, "There are no DNS servers to test.")
    details = []
    working, servfail_only = [], []
    for result in results:
        average = f"{result.average:.0f} ms average" if result.average is not None else "no answers"
        details.append(f"{result.server}: {average}, {result.answered} of {result.sent} answered ({result.status})")
        if result.answered:
            working.append(result)
        elif set(result.failures) == {"SERVFAIL"}:
            servfail_only.append(result)
    if not working and servfail_only:
        return Finding("DNS", WARNING, "The DNS servers answer but can't look up internet names (SERVFAIL). That's "
                                       "expected on a network without internet access; otherwise check the DNS "
                                       "server's forwarders.", details)
    if not working:
        return Finding("DNS", PROBLEM, "None of the DNS servers answered, so names won't resolve.", details)
    if len(working) < len(results):
        return Finding("DNS", WARNING, f"{len(results) - len(working)} of {len(results)} DNS servers didn't "
                                       "answer. Windows falls back to the others, but lookups can stall.", details)
    slowest = max(result.average for result in working)
    if slowest > SLOW_DNS_MS:
        return Finding("DNS", WARNING, f"DNS works but is slow (up to {slowest:.0f} ms per lookup).", details)
    return Finding("DNS", OK, f"All {len(results)} DNS server{'' if len(results) == 1 else 's'} answered "
                              f"(average {sum(result.average for result in working) / len(working):.0f} ms).",
                   details)


def evaluate_internet(ping_results, tcp_results, resolved):
    """ping_results {target: PingStats}; tcp_results {"host:port": True/False}; resolved: name lookup worked."""
    details = [f"Ping {target}: {stats.summary()}" for target, stats in ping_results.items()]
    details += [f"TCP {target}: {'connected' if connected else 'no connection'}"
                for target, connected in tcp_results.items()]
    details.append(f"Looking up {DNS_TEST_NAMES[0]}: {'worked' if resolved else 'failed'}")
    reachable = any(stats.received for stats in ping_results.values()) or any(tcp_results.values())
    if not reachable:
        return Finding("Internet", INFO, "No internet access. That's expected on an isolated network; otherwise "
                                         "the problem is past the gateway.", details)
    if not resolved:
        return Finding("Internet", WARNING, "The internet can be reached by address, but names don't resolve: a DNS "
                                            "problem.", details)
    lossy = [target for target, stats in ping_results.items() if stats.received and stats.lost]
    if lossy:
        return Finding("Internet", WARNING, f"Internet access works, with some packet loss to {', '.join(lossy)}.",
                       details)
    return Finding("Internet", OK, "Internet access works.", details)


def loss_start(rows):
    """The hop where loss begins and carries on to the destination, or None.

    Loss at one router that later hops don't share is just that router ignoring probes.
    """
    losses = hop_losses(rows)
    if not rows or not losses[-1].path:
        return None
    return next((row.ttl for row, loss in zip(rows, losses) if loss.added >= 0.5), None)


def evaluate_trace(target, rows, reached, text):
    if not rows:
        return Finding("Traceroute", INFO, "Skipped: no internet access to trace to.")
    hops = len(rows)
    if not reached:
        last = next((row for row in reversed(rows) if row.address), None)
        where = f"hop {last.ttl} ({last.address})" if last else "the first hop"
        return Finding("Traceroute", WARNING, f"The trace to {target} didn't finish; the last router to answer was at "
                                              f"{where}. {target} may block ping, or the path breaks there.",
                       preformatted=text)
    start = loss_start(rows)
    if start is not None:
        return Finding("Traceroute", WARNING, f"{rows[-1].loss_percent:.0f}% loss to {target}, starting at hop "
                                              f"{start}. That's where to look.", preformatted=text)
    return Finding("Traceroute", OK, f"{target} is {hops} hop{'' if hops == 1 else 's'} away with no loss "
                                     f"(average {rows[-1].average:.0f} ms).", preformatted=text)


def evaluate_mtu(target, mtu, message):
    if mtu is None:
        return Finding("MTU", INFO, f"Couldn't measure the path MTU to {target}: {message}")
    if mtu >= MTU_RANGE[1]:
        return Finding("MTU", OK, f"Full-size {mtu}-byte packets reach {target} without fragmenting.")
    return Finding("MTU", WARNING, f"The largest packet that reaches {target} unfragmented is {mtu} bytes, less "
                                   "than the usual 1500. Common with VPNs and PPPoE; if large transfers stall, "
                                   f"set the adapter's MTU to {mtu} on the MTU tab.")


def evaluate_arp(table, gateways, networks=None):
    """networks: the adapter's subnets; only addresses inside them count towards spoofing warnings."""
    details = []
    status = OK
    for (interface, mac), addresses in shared_macs(table.neighbors, networks).items():
        gateway = next((address for address in addresses if address in gateways), None)
        if gateway:
            others = [address for address in addresses if address != gateway]
            status = WARNING
            details.append(f"The gateway {gateway}'s MAC {mac} also answers for {', '.join(others)}: normal for "
                           "proxy ARP, but it can mean another device is impersonating the gateway (ARP spoofing).")
    for interface_name, address in table.duplicate_addresses:
        status = PROBLEM
        details.append(f"Windows found another device using this computer's address {address} on "
                       f"{interface_name}.")
    if status == PROBLEM:
        return Finding("ARP", PROBLEM, "Another device is using this computer's IP address.", details)
    if status == WARNING:
        return Finding("ARP", WARNING, "The gateway's MAC address answers for other addresses too.", details)
    entries = sum(1 for neighbor in table.neighbors if neighbor.family == 4 and neighbor.mac
                  and not neighbor.is_multicast)
    return Finding("ARP", OK, f"No duplicate addresses or signs of ARP spoofing ({entries} devices in the ARP "
                              "table).")


# ----------------------------------------------------------------- Running the checks

def ping(address, count, interval=0.2, timeout=1000, should_stop=lambda: False):
    stats = PingStats()
    with IcmpClient(4) as client:
        for number in range(count):
            if should_stop():
                break
            stats.add(client.echo(address, timeout=timeout))
            if number < count - 1:
                time.sleep(interval)
    return stats


def trace(target, rounds=5, max_hops=20, timeout=1000, should_stop=lambda: False):
    """A short MTR-style trace. Returns (rows, reached)."""
    clients = [IcmpClient(4) for _ in range(max_hops)]
    trace_state = MtrTrace(max_hops)
    try:
        with ThreadPoolExecutor(max_workers=max_hops) as pool:
            for _ in range(rounds):
                if should_stop():
                    break
                futures = {ttl: pool.submit(clients[ttl - 1].echo, target, timeout=timeout, ttl=ttl)
                           for ttl in trace_state.probe_ttls()}
                trace_state.add_round({ttl: future.result() for ttl, future in futures.items()})
    finally:
        for client in clients:
            client.close()
    return trace_state.rows(), trace_state.reached


def run_diagnostics(adapter, should_stop=lambda: False, progress=lambda step, total, text: None,
                    finding=lambda finding: None):
    """Run every check on an adapter (a snapshot.Adapter). Returns a Report."""
    report = Report(adapter.name, socket.gethostname(), time.strftime("%Y-%m-%d %H:%M:%S"))
    steps = ["Checking the adapter", "Pinging the gateway", "Testing DNS servers", "Checking internet access",
             "Tracing the route", "Measuring the path MTU", "Checking the ARP table"]

    def add(result):
        report.findings.append(result)
        finding(result)

    def step(index):
        if should_stop():
            return False
        progress(index, len(steps), steps[index])
        return True

    if not step(0):
        return report
    add(evaluate_adapter(adapter))
    connected = adapter.status == "Up" and any(not address.ip.is_link_local for address in adapter.ipv4)
    if not connected:
        progress(len(steps), len(steps), "Done")
        return report  # Nothing past the adapter can work

    gateway = adapter.gateways4[0] if adapter.gateways4 else None
    if not step(1):
        return report
    if gateway:
        stats = ping(gateway, GATEWAY_PINGS, should_stop=should_stop)
        add(evaluate_gateway(gateway, stats, None if stats.received == stats.sent else arp_lookup(gateway)))
    else:
        add(evaluate_gateway(None, None, None))

    if not step(2):
        return report
    servers = [server for server in adapter.dns4 + adapter.dns6 if server]
    add(evaluate_dns([benchmark_server(server, DNS_TEST_NAMES, rounds=2, should_stop=should_stop)
                      for server in servers]))

    if not step(3):
        return report
    ping_results = {target: ping(target, 4, should_stop=should_stop) for target in INTERNET_PING_TARGETS}
    tcp_results = {f"{host}:{port}": check_port(host, 4, port, 2000).state == OPEN
                   for host, port in INTERNET_TCP_TARGETS}
    try:
        socket.getaddrinfo(DNS_TEST_NAMES[0], 443)
        resolved = True
    except OSError:
        resolved = False
    internet = evaluate_internet(ping_results, tcp_results, resolved)
    add(internet)
    online = any(stats.received for stats in ping_results.values())

    if not step(4):
        return report
    if online:
        rows, reached = trace(TRACE_TARGET, should_stop=should_stop)
        add(evaluate_trace(TRACE_TARGET, rows, reached,
                           report_text(f"Traceroute to {TRACE_TARGET}", rows)))
    else:
        add(evaluate_trace(TRACE_TARGET, [], False, ""))

    if not step(5):
        return report
    mtu_target = TRACE_TARGET if online else gateway
    if mtu_target:
        with IcmpClient(4) as client:
            mtu, message = find_path_mtu(make_mtu_probe(client, mtu_target, 1000), *MTU_RANGE,
                                         should_stop=should_stop)
        add(evaluate_mtu(mtu_target, mtu, message))

    if not step(6):
        return report
    try:
        add(evaluate_arp(load_neighbors(), set(adapter.gateways4 + adapter.gateways6),
                         [address.network for address in adapter.ipv4]))
    except OSError as error:
        add(Finding("ARP", INFO, f"Couldn't read the ARP table: {error}"))
    progress(len(steps), len(steps), "Done")
    return report


# ----------------------------------------------------------------- Writing it up

REPORT_CSS = """
body { font-family: "Segoe UI", Arial, sans-serif; margin: 2em auto; max-width: 900px; color: #1d252c;
       padding: 0 16px; background: #fff; }
h1 { margin-bottom: 0; } .meta { color: #5b6770; margin-top: 4px; }
.overall { padding: 10px 14px; border-radius: 6px; margin: 1.2em 0; font-weight: 600; }
.finding { border: 1px solid #d8dee4; border-left-width: 6px; border-radius: 6px; padding: 10px 14px;
           margin: 10px 0; }
.finding h2 { font-size: 1.05em; margin: 0 0 4px; } .finding p { margin: 4px 0; }
.finding ul { margin: 6px 0 0; padding-left: 20px; color: #3b4650; }
.badge { display: inline-block; font-size: 0.8em; padding: 1px 8px; border-radius: 10px; margin-left: 6px;
         vertical-align: middle; color: #fff; }
pre { background: #f4f6f8; padding: 8px; overflow-x: auto; font-size: 0.85em; }
.ok { border-left-color: #1f9d55; } .ok .badge, .overall.ok { background: #1f9d55; color: #fff; }
.info { border-left-color: #3b82c4; } .info .badge, .overall.info { background: #3b82c4; color: #fff; }
.warning { border-left-color: #d69e2e; } .warning .badge, .overall.warning { background: #d69e2e; color: #fff; }
.problem { border-left-color: #d64545; } .problem .badge, .overall.problem { background: #d64545; color: #fff; }
footer { color: #5b6770; font-size: 0.85em; margin-top: 2em; }
"""

OVERALL = {OK: "No problems found.", INFO: "No problems found.",
           WARNING: "Some things need a look.", PROBLEM: "Problems found."}


def render_html(report):
    escape = html.escape
    parts = [f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
             f"<meta name='viewport' content='width=device-width, initial-scale=1'>"
             f"<title>Network report: {escape(report.computer)}</title><style>{REPORT_CSS}</style></head><body>",
             "<h1>Network diagnostics report</h1>",
             f"<p class='meta'>{escape(report.computer)} · adapter {escape(report.adapter)} · "
             f"{escape(report.created)}</p>",
             f"<div class='overall {report.status}'>{escape(OVERALL[report.status])}</div>"]
    for finding in report.findings:
        parts.append(f"<div class='finding {finding.status}'><h2>{escape(finding.section)}"
                     f"<span class='badge'>{STATUS_LABELS[finding.status]}</span></h2>"
                     f"<p>{escape(finding.summary)}</p>")
        if finding.details:
            parts.append("<ul>" + "".join(f"<li>{escape(line)}</li>" for line in finding.details) + "</ul>")
        if finding.preformatted:
            parts.append(f"<pre>{escape(finding.preformatted)}</pre>")
        parts.append("</div>")
    parts.append(f"<footer>Made by {APP_NAME} {escape(__version__)} ({APP_FULL_NAME}) on "
                 f"{escape(platform.platform())}.</footer></body></html>")
    return "\n".join(parts)


def render_text(report):
    lines = [f"Network diagnostics report: {report.computer}, adapter {report.adapter}, {report.created}",
             OVERALL[report.status], ""]
    for finding in report.findings:
        lines.append(f"[{STATUS_LABELS[finding.status]}] {finding.section}: {finding.summary}")
        lines += [f"    {line}" for line in finding.details]
        if finding.preformatted:
            lines += [f"    {line}" for line in finding.preformatted.rstrip().splitlines()]
    return "\n".join(lines) + "\n"
