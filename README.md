# NOMAD

**Network Operations, Monitoring And Diagnostics**: a one stop shop to manage Network Interface Cards (NICs) and troubleshoot networks in Windows. (Formerly NIC Manager, now with the RADAR subnet sweep built in.)

Pick an adapter at the top of the window; the Interfaces, MTU, Ping and Sweep tabs all work with it. NOMAD always opens on the Interfaces tab.

Everything works without internet access: the tests only talk to the hosts you give them, and the MAC vendor list is built in (to update it, download https://standards-oui.ieee.org/oui/oui.csv and run python -m nomad.oui build oui.csv).

Tabs:
  Interfaces - shows the adapter's status, addresses, gateway, DNS servers, link speed and MAC address. Lets you switch between DHCP and a static IP (CIDR notation like 192.168.1.10/24 works), set DNS servers and MTU, and enable/disable, reset, release or renew the adapter. After changing IP settings you get 15 seconds to confirm; if you don't (say the change cut off your remote session), the previous settings come back automatically. Save settings as named profiles to switch networks in one click, and import/export profiles to share them.
  Routing Table - view, filter, sort, add, edit and delete IPv4 and IPv6 routes, including persistent routes that survive a reboot. System routes are hidden by default.
  ARP - the ARP (IPv4) and neighbor (IPv6) tables: which MAC address answers for each IP, with the vendor of each device. Warns when one MAC answers for the gateway and other addresses (possible ARP spoofing), when an address starts answering from a different MAC (two devices sharing an IP), and when Windows reports that another device is using this computer's address. Delete an entry or clear the whole cache (like arp -d *).
  Connections - every TCP connection and listening TCP/UDP port with the program that owns it, like netstat -ano. Filter by port, address or program to see what's using a port; optionally refresh every 2 seconds.
  Switch Port - shows which switch, port and VLAN (and voice VLAN) the computer is plugged into, from the LLDP and CDP announcements managed switches send every 30-60 seconds, along with the switch's model, management address and software. Uses Windows' built-in packet monitor (pktmon), so nothing needs installing, but it needs administrator rights.
  MTU - finds the largest MTU that reaches a remote host without fragmenting, from the selected adapter, and applies it with one click.
  Ping - ping a host with a running summary (loss, min/avg/max). Quick buttons ping the adapter's gateway or DNS server.
  Latency - monitors several hosts at once (Google and Cloudflare DNS to start; add your gateway with one click), with a gauge per host, a graph of latency over time with lost pings marked in red, and last/average/min/max/loss for each. Switch hosts on and off while it runs, view the last minute up to the last 8 hours, and optionally log every ping to CSV. Compact shows just the gauges and graph. (This replaces the separate Latenct tool.)
  Traceroute - shows each router on the way to a host, with loss, last/average/best/worst latency and jitter (standard deviation) for each hop, like MTR / WinMTR. Every hop is probed at once, so a trace takes seconds. Run a set number of probes per hop, or keep it running to watch a problem develop; Copy Report gives a text table to send to an ISP.
  Ports - checks whether TCP ports on a host are open, closed (refused) or filtered (no answer, usually a firewall), with presets for common, web, remote access and file sharing ports, or any list and ranges up to all 65535. Open ports can be opened in the browser, Remote Desktop or PuTTY from the results.
  Services - two checks. DNS Servers times how fast each DNS server answers (the adapter's, the gateway, well-known public servers and any you add; remove any you don't want with Remove Selected or the Delete key, and Restore Removed brings them back), asking each directly so Windows' cache doesn't skew the result, and checks that a name's addresses have PTR records pointing back to it. Web Check fetches a page and shows how long DNS, connecting, the TLS handshake and the first byte took, the certificate (who issued it, the names it covers, days until it expires, and why it isn't trusted if it isn't) and the reply, following redirects.
  iperf - measures bandwidth (TCP or UDP, upload or download, parallel streams) with a built-in iperf3-compatible client and server, so no iperf3 download is needed. Test against any iperf3 server, or switch to server mode and run iperf3 -c <this computer> (or another copy of NOMAD) elsewhere. Open Firewall Port adds the Windows Firewall rule server mode needs.
  DNS Lookup - look up A, AAAA, MX, TXT and other records, optionally against a specific DNS server.
  Sweep - finds every host on an IPv4 subnet that answers ping (hosts that miss are retried, 3 tries in all). On subnets this computer is directly connected to it also uses ARP, which finds devices whose firewall drops ping, and shows each host's MAC address and vendor. Host names come from DNS, or from NetBIOS on networks without a DNS server. One click fills in the selected adapter's subnet. From the results, open an SSH session in PuTTY, open the host's web page, ping, trace, scan ports or monitor its latency; copy the addresses or export them (with names, MACs and vendors) to CSV. Tools > Add PuTTY to PATH and Tools > Default Browser Settings help set up those actions. (This replaces the separate RADAR tool.)
  Utilities - a subnet calculator (network, netmask, broadcast, host range and counts for IPv4 and IPv6, and splitting a network into smaller subnets by prefix or by hosts needed) and Wake-on-LAN (wake a computer by its MAC address, save devices you wake often, or pick one from the Sweep or ARP tab).

The program starts without administrator rights, so viewing, ping, latency monitoring, traceroute, port scans, sweeps and lookups work straight away. Changing settings needs administrator rights; NOMAD offers to restart itself as administrator when you first try (or use File > Restart as Administrator).

Diagnostics report: Tools > Run Diagnostics Report (Ctrl+R) checks the selected adapter's settings, the gateway, DNS, internet access, the route to the internet, the path MTU and the ARP table in about half a minute, then saves the findings as a web page to email or attach to a ticket. On a network without internet access it says so rather than reporting a fault.

Text size: View > Text Size makes all text from 90% to 200% of normal, and NOMAD remembers the choice. Ctrl+= and Ctrl+- also change it, and Ctrl+0 goes back to the default.

Shortcuts: F5 refreshes, Ctrl+R runs a diagnostics report, Ctrl+F filters the routing table, Delete removes the selected route, Ctrl+= / Ctrl+- / Ctrl+0 change the text size.

Logs are written to %LOCALAPPDATA%\NOMAD\nomad.log (Tools > View Log). Profiles are saved in %APPDATA%\NOMAD\profiles.json. The first time NOMAD runs it moves over the folders and settings from NIC Manager.

Running from source:

    pip install -r requirements.txt
    pythonw Main.py

Running the tests and building a standalone exe (dist\NOMAD-<version>.exe, e.g. dist\NOMAD-1.0.0.exe):

    pip install -r requirements-dev.txt
    python -m pytest
    .\build.ps1

Versions and releases: the version is set in nomad\__init__.py and shows in the title bar, Help > About, the log, the exe's file name and its Properties > Details. Note changes under Unreleased in CHANGELOG.md as you go, then release with:

    python -m nomad.version bump patch     (or minor / major)
    git commit -am "Release X.Y.Z"
    git tag vX.Y.Z
    .\build.ps1

Screenshots below are from the previous version.

NIC Tab:

![image](https://github.com/user-attachments/assets/e37cd314-97d2-4cba-8dd0-3faa197ae232)

Routing Table Tab:

![image](https://github.com/user-attachments/assets/ce43098e-7e4b-420a-afb9-679cb0687f4b)

MTU Tab:

![image](https://github.com/user-attachments/assets/d9809bb0-f1e3-4d29-86b7-0aec12695b8b)


Happy troubleshooting!
