# Changelog

Notable changes to NOMAD. Versions follow [semantic versioning](https://semver.org/): MAJOR for big or breaking changes, MINOR for new features, PATCH for fixes.

Add changes under Unreleased as you go; `python -m nomad.version bump <part>` dates them when you release.

## [Unreleased]

- New Switch Port tab: find the switch, port and VLAN an adapter is plugged into from LLDP/CDP announcements, using Windows' built-in pktmon (needs administrator rights).
- New Services tab: compare DNS servers' response times (add your own, or remove any from the list) and check forward/reverse DNS; check a web server's timings, certificate and reply, following redirects.
- New Utilities tab: subnet calculator with subnet splitting, and Wake-on-LAN with saved devices (also on the Sweep and ARP tabs' right-click menus).
- New diagnostics report (Tools > Run Diagnostics Report, Ctrl+R): checks the adapter, gateway, DNS, internet access, route, path MTU and ARP table and saves the findings as a web page.
- Open web ports on the Ports tab can be checked on the Services tab straight from the right-click menu.
- The ARP spoofing warning now only counts addresses on the local subnets, so proxy ARP for other addresses doesn't set it off.
- New Ports tab: check whether TCP ports on a host are open, closed or filtered, with presets from common ports up to all 65535; open web, Remote Desktop and SSH ports straight from the results. Scan Ports is also on the Sweep and ARP tabs.
- New ARP tab: the ARP and IPv6 neighbor tables with MAC vendors, warnings about possible ARP spoofing and duplicate IP addresses, and delete entry / clear cache.
- New Connections tab: TCP connections and listening TCP/UDP ports with the owning program (like netstat -ano), with filtering and optional auto refresh.
- Traceroute now shows loss, latency and jitter per hop like MTR, probes every hop at once, can keep running until stopped, and copies a text report.
- Sweep now shows each host's MAC address, vendor and host name (DNS, or NetBIOS without a DNS server), finds hosts that block ping by using ARP on local subnets, and includes them in the CSV export.
- The MAC vendor list is built in, so vendor lookups work offline.
- View > Text Size makes all text larger or smaller (90% to 200%), with Ctrl+= / Ctrl+- / Ctrl+0 shortcuts. The choice is remembered.
- The version now shows in the title bar and the exe's file name (NOMAD-X.Y.Z.exe), and Help > About is a proper About window with build and runtime details that can be copied.

## [1.0.0] - 2026-09-24

- First versioned release: NIC Manager renamed to NOMAD, with Interfaces, Routing Table, MTU, Ping, Latency, Traceroute, iperf, DNS Lookup and Sweep tabs.
