# NOMAD

**Network Operations, Monitoring And Diagnostics**: a one stop shop to manage Network Interface Cards (NICs) and troubleshoot networks in Windows. (Formerly NIC Manager, now with the RADAR subnet sweep built in.)

Pick an adapter at the top of the window; the Interfaces, MTU, Ping and Sweep tabs all work with it. NOMAD always opens on the Interfaces tab.

Tabs:
  Interfaces - shows the adapter's status, addresses, gateway, DNS servers, link speed and MAC address. Lets you switch between DHCP and a static IP (CIDR notation like 192.168.1.10/24 works), set DNS servers and MTU, and enable/disable, reset, release or renew the adapter. After changing IP settings you get 15 seconds to confirm; if you don't (say the change cut off your remote session), the previous settings come back automatically. Save settings as named profiles to switch networks in one click, and import/export profiles to share them.
  Routing Table - view, filter, sort, add, edit and delete IPv4 and IPv6 routes, including persistent routes that survive a reboot. System routes are hidden by default.
  MTU - finds the largest MTU that reaches a remote host without fragmenting, from the selected adapter, and applies it with one click.
  Ping - ping a host with a running summary (loss, min/avg/max). Quick buttons ping the adapter's gateway or DNS server.
  Latency - monitors several hosts at once (Google and Cloudflare DNS to start; add your gateway with one click), with a gauge per host, a graph of latency over time with lost pings marked in red, and last/average/min/max/loss for each. Switch hosts on and off while it runs, view the last minute up to the last 8 hours, and optionally log every ping to CSV. Compact shows just the gauges and graph. (This replaces the separate Latenct tool.)
  Traceroute - shows each router on the way to a host.
  iperf - measures bandwidth (TCP or UDP, upload or download, parallel streams) with a built-in iperf3-compatible client and server, so no iperf3 download is needed. Test against any iperf3 server, or switch to server mode and run iperf3 -c <this computer> (or another copy of NOMAD) elsewhere. Open Firewall Port adds the Windows Firewall rule server mode needs.
  DNS Lookup - look up A, AAAA, MX, TXT and other records, optionally against a specific DNS server.
  Sweep - finds every host on an IPv4 subnet that answers ping (hosts that miss are retried, 3 tries in all). One click fills in the selected adapter's subnet. From the results, open an SSH session in PuTTY, open the host's web page, or ping, trace or monitor its latency; copy the addresses or export them to CSV. Tools > Add PuTTY to PATH and Tools > Default Browser Settings help set up those actions. (This replaces the separate RADAR tool.)

The program starts without administrator rights, so viewing, ping, latency monitoring, traceroute and lookups work straight away. Changing settings needs administrator rights; NOMAD offers to restart itself as administrator when you first try (or use File > Restart as Administrator).

Shortcuts: F5 refreshes, Ctrl+F filters the routing table, Delete removes the selected route.

Logs are written to %LOCALAPPDATA%\NOMAD\nomad.log (Tools > View Log). Profiles are saved in %APPDATA%\NOMAD\profiles.json. The first time NOMAD runs it moves over the folders and settings from NIC Manager.

Running from source:

    pip install -r requirements.txt
    pythonw Main.py

Running the tests and building a standalone exe (dist\NOMAD.exe):

    pip install -r requirements-dev.txt
    python -m pytest
    .\build.ps1

Versions and releases: the version is set in nomad\__init__.py and shows in Help > About, the log and the exe's Properties > Details. Note changes under Unreleased in CHANGELOG.md as you go, then release with:

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
