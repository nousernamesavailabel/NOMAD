# NOMAD

**Network Operations, Monitoring And Diagnostics**: one Windows app to set up network adapters, troubleshoot networks, talk to devices and keep track of IP addresses. (Formerly NIC Manager, with the RADAR subnet sweep and the Latenct latency monitor built in.)

**Version 1.21.0** adds **MAC Finder**: type a MAC address in any format (or part of one, an IP address or a name) to find the switch and port it's plugged into, from the Network Map's last crawl or live over SNMP, with lists and a history of where each MAC has been. It also adds Ctrl+S / Ctrl+Shift+S for terminal logging and config saving, Add Device to Map and Create Terminal/RDP Session on address menus, and a Key for the Network Map. See the [changelog](CHANGELOG.md#1210---2026-10-06) and [keyboard guide](docs/keyboard-shortcuts.md).

![The Interfaces page](docs/screenshots/interfaces.png)

- **Works offline.** Tests only talk to the hosts you give them, and the MAC vendor list is built in.
- **One exe, nothing to install.** `NOMAD-<version>.exe` runs on its own ([build it](#running-from-source-and-building) with `build.ps1`).
- **Safe changes.** New IP settings, and disabling an adapter, revert on their own unless you confirm within 15 seconds, so a change that cuts off your remote session undoes itself.

Screenshots use made-up demo data; some show the earlier navigation layout.

## Contents

- [Getting around](#getting-around)
- [Pages](#pages)
- [Network map](#network-map)
- [Setting switches up for NOMAD](#setting-switches-up-for-nomad)
- [ACLs](#acls)
  - [Prefix lists and route maps](#prefix-lists-and-route-maps)
- [VPNs](#vpns)
- [Port mirroring](#port-mirroring)
- [Packet capture](#packet-capture)
- [Terminal and SCP](#terminal-and-scp)
- [IP address management (IPAM)](#ip-address-management-ipam)
- [Sharing IPAM with the tribe](#sharing-ipam-with-the-tribe)
- [VLANs](#vlans)
- [Subnet placement](#subnet-placement)
- [Assets](#assets)
- [Good to know](#good-to-know)
- [Running from source and building](#running-from-source-and-building)

## Getting around

- Switch tools with the **favorites rail** on the left, or open the **Tools drawer** for the full list. **Ctrl+K** opens tool search (try “bandwidth” or “file transfer”). Right-click a tool to pin or unpin it; drag favorites in the rail to reorder them. Favorites and their order are saved. Tools you used lately that aren't favorites sit on the rail below a thin line, like the Windows taskbar, until other tools push them off; right-click one to pin it or remove it, or drag it up among the favorites to pin it there (right-click the rail > **Show Recent Tools Here** turns this off).
- Each tool has its own outline icon, used in both the rail and drawer. Hover over a rail icon to see its full name; the selected tool is highlighted in green.
- The drawer lists favorites, recent tools and collapsible categories. It closes when you choose a tool, click outside it or press Escape. Choose **Keep drawer open** (also View > Keep Tool Drawer Open or Ctrl+B) for persistent navigation; this preference is saved. Ctrl+Tab and Ctrl+Shift+Tab move between all tools.
- Pick an **adapter** at the top of the window. Interfaces, MTU, Ping, Sweep, DHCP Servers and other pages work with it.
- **F11** (focus mode) hides everything but the current page.
- **View > Text Size** scales all text from 90% to 200% (Ctrl+= and Ctrl+- too, and Ctrl+0 to reset).

## Pages

### This Computer

| Page | Function |
| --- | --- |
| **Interfaces** | The adapter's status, addresses, gateway, DNS, speed and MAC. Switch between DHCP and a static IP (CIDR like `192.168.1.10/24` works), set DNS and MTU, and enable, disable, reset, release or renew. **Free Address from IPAM** fills in the next free address in a subnet you pick. Save settings as **profiles** to switch networks in one click. |
| **Routing Table** | View, filter, add, edit and delete IPv4 and IPv6 routes, persistent ones included. Type an address in the filter to see which route Windows would use for it. |
| **ARP** | Which MAC answers for each IP, with vendors. Warns about possible ARP spoofing and address conflicts. |
| **Connections** | Every TCP connection and listening port with the program that owns it, like `netstat -ano`. |
| **Network Reset** | Flush DNS, clear ARP, renew DHCP, reset Winsock and TCP/IP, and turn off a leftover proxy. |

![The Routing Table page](docs/screenshots/routing.png)

### Connect & Transfer

| Page | What it does |
| --- | --- |
| **Terminal** | SSH, Telnet, serial and raw TCP sessions in tabs, tiles and pop-out windows. [More below.](#terminal-and-scp) |
| **SCP** | A WinSCP-style file manager for SSH servers. [More below.](#terminal-and-scp) |
| **RDP** | Saved Remote Desktop sessions in folders, with remembered credentials and display settings. Launches Windows' built-in Remote Desktop Connection. |
| **TFTP** | A TFTP server and client for firmware and config transfers. **Cisco TFTP Tips** shows how to make switches copy faster (a bigger block size, or SCP instead). |
| **Wake-on-LAN** | Wake a computer by its MAC, and save the ones you wake often. |

The **RDP** page has its own session folders, separate from Terminal and SCP, and uses NOMAD's shared password vault.
Create a session with a
computer name or IP address, port and username (`DOMAIN\user` or `user@domain`), and optionally remember its password.
The full-width session list shows addresses, usernames, password status, display mode and last launch. Search and
Quick connect are above the list, with launch/edit actions in the toolbar and a compact summary below it.
Double-click a session or click **Launch** to open Windows Remote Desktop Connection. Quick connect accepts
`host`, `host:3390` or `[IPv6]:3389`; with saved credentials, it asks which one to log in with (the default
credential first). Recent launches can be saved as sessions. Display options include full screen,
window size and all monitors, plus clipboard, audio and administrative sessions. Windows policies may still require
interactive sign-in. NOMAD hands passwords to the client in an encrypted temporary `.rdp` file, normally deleted
after one minute; files left by an interrupted launch expire after 24 hours and are cleaned up next time the RDP
page starts or launches a connection. Closing NOMAD leaves Remote Desktop windows running. Encrypted NOMAD session
backups include RDP sessions, credentials and page preferences.

### Discover

| Page | Functions |
| --- | --- |
| **Sweep** | Finds every host on a subnet (ping, plus ARP on local subnets), with names, MACs and vendors. **Compare with IPAM** shows which hosts IPAM has, is missing or records with a different MAC. |
| **Switch Port** | Which switch, port and VLAN you're plugged into, from LLDP and CDP. |
| **MAC Finder** | Which switch and port a device is plugged into: type its MAC address in any format (or part of one), its IP address or its name. **Find** searches the Network Map's last crawl at once; **Locate Now** asks the map's switches over SNMP where it is now, following uplinks to the edge port. Tick **Also over SSH** to ask the switches that don't answer SNMP at their command line too (Cisco IOS, IOS XE and NX-OS show commands), following the MAC through CDP and LLDP onto switches the map doesn't have, or with no map at all from a switch you name. Paste or load a list to find many at once, and see where each MAC has been. |
| **DHCP Servers** | Every DHCP server that answers, with each option it offers decoded, and warns about rogue servers. Nothing is leased. |
| **SNMP Walk** | Walk or get over SNMP v1, v2c or v3 (a user with authentication and privacy), with presets and a per-port interface summary. |

### Diagnostics: Connectivity & Performance

| Page | Functions |
| --- | --- |
| **Ping** | Ping with a running summary; quick buttons for the gateway and DNS server. |
| **Latency** | Watches several hosts at once, with gauges, a graph over time (lost pings in red) and optional CSV logging. |
| **Traceroute** | Loss, latency and jitter for every hop, like MTR/WinMTR. Every hop is probed at once, so a trace takes seconds. |
| **MTU** | Finds the largest MTU that reaches a host without fragmenting, and applies it. |
| **Ports** | Open, closed or filtered, for common port presets or any list and range. |
| **iperf** | Bandwidth tests with a built-in iperf3-compatible client and server. |

### Diagnostics: DNS & Web

| Page | Functions |
| --- | --- |
| **DNS Lookup** | A, AAAA, MX, TXT and other records, from any DNS server. |
| **DNS Servers** | Times how fast each DNS server answers, and checks reverse (PTR) records. |
| **Web Check** | DNS, connect, TLS and first-byte timings, the certificate, and redirects. |

### Network Management

| Page | Functions |
| --- | --- |
| **IP Addresses** | IP address management for several separate networks, shared with the tribe through an IPAM server and usable offline. [More below.](#ip-address-management-ipam) |
| **VLANs** | Each VLAN domain's VLANs and the subnets they carry, brought in from what the network map finds, shared with the tribe. [More below.](#vlans) |
| **Subnet Placement** | Where each subnet is planned to be and where the network map finds it, whether it's advertised, what's wrong, and moving subnets between VLANs and devices. [More below.](#subnet-placement) |
| **Assets** | Every piece of hardware on the network (chassis and stack members, access points, phones, servers, and their modules, power supplies, fans and transceivers) with hostname, model, serial number and software version kept together, from the network map's crawls, shared with the tribe. [More below.](#assets) |
| **Network Map** | Crawls switches, routers and firewalls over SNMP from a starting device and draws what's plugged into what (CDP/LLDP), with the hosts on each switch port, and the subnets and routes between them. See [Network map](#network-map). |
| **SNMP Config** | Builds the Cisco IOS / IOS-XE configuration that sets a switch up for NOMAD, and types it into a terminal session to the switch. See [Setting switches up for NOMAD](#setting-switches-up-for-nomad). |
| **ACLs & Route Maps** | Reads, builds and edits ACLs, prefix lists and route maps on Cisco IOS / IOS-XE devices, finds entries that never match and changes that would lock you out, tests packets and routes, and sends the changes entry by entry with a revert timer. See [ACLs](#acls). |
| **VPNs** | Builds and edits IPsec VTI, GRE over IPsec, GRE, crypto map and DMVPN VPNs between Cisco routers (keys or certificates), checks the design, sends it to every router with a revert timer and confirms it once the VPN works from each end, and says why one is down. See [VPNs](#vpns). |

### Capture & Logs

| Page | Functions |
| --- | --- |
| **Packet Capture** | Captures with Windows' built-in pktmon (nothing to install) to a pcapng file, shows the packets as they come, and looks through it (or any pcap/pcapng file) right there: Wireshark-style filters, each packet decoded, conversations and top talkers, problems found, and following a stream. Takes SPAN copies on a wired adapter, and unwraps ERSPAN sent to this PC. |
| **Port Mirroring** | Sets up SPAN, RSPAN or ERSPAN on Cisco IOS / IOS-XE switches in a click, checks the ports first, and takes it away again (or the switches do, when the time's up). See [Port mirroring](#port-mirroring). |
| **Syslog** | Receives syslog from network devices, colored by severity and filterable. |

### Utilities

| Page | Functions |
| --- | --- |
| **Subnet Calculator** | Network, mask, host range and counts for IPv4 and IPv6, and splitting a network into smaller subnets. |

![The Subnet Calculator](docs/screenshots/subnet-calculator.png)

## Network map

![The Network Map page](docs/screenshots/network-map.png)

Enter a core switch or your gateway (or use **Adapter's Gateway**) and click **Start**. NOMAD reads the device's CDP and LLDP neighbors over SNMP, then asks each neighbor for its neighbors, and so on. Nothing needs installing on the devices, and nothing is changed on them.

- **While it maps:** the map is drawn as devices are found, with the ones being read ringed in green (you can drag things around meanwhile). A progress bar shows how many devices have been read, are being read and are queued, the time taken and roughly how long is left. The **Crawl** tab shows what each device being read is doing (which table, which VLAN, which community string it's trying) and a log of everything found, skipped and why (outside the scope, too many hops, no answer), which you can copy or save. Community strings are never written to the log.
- **Credentials:** **SNMP Credentials...** holds the community strings and SNMPv3 users to try, in order, plus ones for particular subnets (tried first there; type `v3:name` for a user). They're saved encrypted for your Windows account; a tribe map's are shared with the tribe (see Tribe maps below). SNMPv3 users have MD5, SHA-1 or SHA-2 authentication and DES or AES-128/192/256 privacy; they're tried before the community strings unless you untick that, since a switch without the user says so at once while a wrong community string waits for the timeout. On Catalyst switches, the per-VLAN MAC tables are read with `community@vlan`, or over v3 in the `vlan-` contexts.
- **Scope:** **Scope...** limits the crawl to subnets (by default any private address), a number of hops and a number of devices, and sets how many devices are read at once (16; up to 64 for a big network). Devices outside it still appear as neighbors, just without their own neighbors.
- **Hosts:** each switch's MAC table (per VLAN on Catalyst IOS, using `community@vlan`, only for the VLANs its access, voice and native trunk ports use, several at once) and the routers' and firewalls' ARP tables put hosts on the edge ports they're plugged into. MACs learned on uplinks are left out, and phones get their names from CDP/LLDP. Hosts are hidden until you double-click a switch (or tick **Show Hosts** for every switch): then there's a box per port listing each host with its VLAN. A port with many hosts and no neighbor is marked as a likely unmanaged switch or hypervisor.
- **Tunnels:** the crawl reads each router's tunnel interfaces (TUNNEL-MIB: each one's two ends) and, on Cisco, its IKE sessions that are up (CISCO-IPSEC-FLOW-MONITOR-MIB), and **Show Tunnels** (ticked) draws the tunnels between the map's routers as thin dashed lines: green up, amber up but IPsec isn't, red down, gray not known. A point-to-point tunnel (GRE, IPsec VTI) goes to the router with its far end's address; a DMVPN router is joined to the routers it has IKE sessions with (a hub's spokes, a spoke's hubs and shortcuts), and a router in the cloud's tunnel subnet with no session to its hub is drawn to it as down or not encrypted (when the hub, the one with the most sessions, can be told). A far end that isn't on the map isn't drawn. A router's details list its tunnels. While **Monitor** is on, each poll reads the routers' tunnel interfaces and IKE sessions again, so the lines (and Overlay > VPN Tunnels) show the tunnels as they are now, and a tunnel that goes down, comes back or loses its IPsec is noted in the Monitor log; turning Monitor off puts them back as the crawl found them. Read-only SNMP, no SSH; tested on IOS XE 17.4 (C8000V).
- **Aruba wireless:** an ArubaOS 8 Mobility Controller the crawl reaches (start from it, or let a switch's LLDP lead there) is a **Wireless controller** (WLC). NOMAD reads its access points from it (name, address, AP group, model, serial number, software, up or down) and puts each on the map: an AP a switch's LLDP already found gets the controller's details, and one on no switch the map has sits beside its controller. An AP its controller has down is drawn in red. Its Wi-Fi clients (MAC, IP address, the computer's or user's name, SSID and VLAN) are hosts on their AP, a box per SSID. **Overlay** > **Wireless** shows each AP's controller and whether it's up. Read-only SNMP: give the controller a read community or SNMPv3 user as for the switches.
- **Reading the map:** colors show the kind of device (switch, router, firewall, wireless controller, access point). A dashed outline is a device NOMAD didn't read itself: one only seen as a neighbor, or one that **pings but doesn't answer SNMP** (usually the community string or an SNMP ACL). Red means it answered neither. Palo Alto firewalls are found through LLDP, so turn on an LLDP profile on the interfaces facing the switches.
- **Adding and removing hosts:** a device that's turned off or unplugged while you map won't be found, so add it by hand: right-click a switch (or a port's box, or the Hosts tab) > **Add Host...** and give its port and a name, IP or MAC. Hand-added hosts are drawn dashed and kept when you map again; if one is later found for real, the crawl's entry takes over and keeps your name and note. Right-click hosts (or select them on the Hosts tab and press Delete) to edit or delete them. A deleted host that's still plugged in comes back the next time you map.
- **Adding devices and drawing links:** for a device the crawl can't find (an unmanaged switch, or one SNMP can't reach), right-click the map's background > **Add Device Here...**, or a device > **Edit** > **Add Device Linked to This...**, and give it a name, an IP address, its kind and model. To link two devices yourself (a port with CDP and LLDP turned off, say), right-click one > **Edit** > **Draw Link from Here** and click the other, then give the ports (or use **Add Link...**). Devices added by hand have their names in italics and links drawn by hand are dotted. A device with an address is checked over SNMP with your community strings, like the crawl's devices: it's dashed with *Pings, no SNMP* when the community or an SNMP ACL is wrong, and red when it doesn't answer at all (right-click > **Edit** > **Check SNMP Again**). It's pinged while monitoring, like the others. They're kept and checked again when you map again; once the crawl finds the device (by its address or name), the crawl's entry takes over its links, hosts, group and note, and a link drawn by hand goes once the crawl finds a link between the same two devices. Right-click them to edit or delete them. **Check SNMP Again** (right-click > **Edit**) also asks a device the crawl found that doesn't answer SNMP, with the credentials as they are now: one that answers is read (Crawl from Here), and one that doesn't says why when it can (an SNMPv3 user it doesn't know, a wrong password).
- **Logical (L3) view:** the routers, L3 switches and firewalls joined through the subnets they have addresses in, with the next hops their routes point to. After the crawl, NOMAD traceroutes from this computer to what SNMP couldn't show (devices that didn't answer, next hops that aren't on the map, and static routes' destinations) and draws the paths it found, dashed, with `*` where a hop didn't answer. Select a router to see its IP interfaces and routes, or a subnet to see what's on it (right-click it to sweep it). Traceroute can be turned off under **Scope...**.

![The Logical (L3) view](docs/screenshots/network-map-l3.png)

- **The top bar:** one row of buttons. **Map** holds New Map, Open, Recent, Save As, Export, Compare, the tribe's maps and the **Key** (what the map's colors, outlines and line styles mean); **Crawl** shows where to start from, to map again or crawl from another switch (it shows anyway while there's no map, or a crawl's running). The status line keeps to one line: hover over it to read all of it. To have the buttons spread over two rows as before, with the start row always showing, choose **View** > **Network Map Top Bar** > **Classic**.
- **Working with it:** scroll to zoom and drag the background to move around. Drag devices where you want them (NOMAD remembers, even after mapping again); to move several at once, hold **Shift** and drag a box round them (Ctrl+click adds or removes one, Ctrl+A selects everything), then drag any of them. **Ctrl+F** goes to the find box, which works on the tab showing: it finds a device on either map, filters the rows of the Devices, Links or Hosts tab as you type, or finds text in the crawl log. **Find** jumps to a device or host by name, IP, MAC or vendor. Right-click a device for SSH and the other sessions (**Connect**), ping, SNMP and the rest (**Tools**), **Crawl from Here** (which adds what it finds to this map, reading only devices that weren't read yet), **Put at the Top**, or **Show In** the physical or logical view, the Devices tab or the Links tab (all its links). The Devices, Links and Hosts tabs list everything, with Excel-style filters: click the funnel at the left of a column's header (or right-click the header) to tick the values to show, search them, or sort (such as a Kind, a Switch or a VLAN); filters on several columns combine, and the tab shows how many rows are left (Hosts (12 of 340)). Double-click a row to see it on the map, or right-click it (on the Links tab, to show both ends of a link).
- **Sites and buildings:** select devices, right-click > **Group** > **New Site or Building...** to draw a labeled box round them (a building can sit inside a site). Drag a device into a box to add it, or out of one to take it out; drag a box's title to move everything in it. Double-click the title to collapse the group into one box that keeps its links to the rest of the map, which is handy for a big campus; finding a device inside opens it again. Select a group to see its devices, how many are down and its links out. Groups are saved with the map, carried over when you map again, shown in the Devices tab's Group column (to filter on), and exported to draw.io as boxes.
- **Arranging:** **Re-arrange** lays the map out again, ordering each layer so links cross as little as it can find (and a link between two devices in the same layer doesn't run over the ones between), with each device near the ones it links to. Devices with a single link (access points, say) sit in a grid under the device they hang off, or, when it has links down to other devices too, off to the side those links don't go, so they don't run through the grid. Its arrow chooses **Top to Bottom**, **Bottom to Top**, **Left to Right**, **Right to Left**, **Grid** or **Circle** (rings round the core) and the **Spacing** (**Compact**, **Normal**, **Roomy** or **Spacious**: draws the map's devices closer together or spreads them out, leaving each where it is among the rest, so nothing is laid out again; Re-arrange uses it from then on), and with **Keep Sites and Buildings Together** each group is laid out inside its own box, with the device that links out of it on top, and the boxes are laid out as the links between them go (each under the one it hangs off), or tiled when nothing links them. Select several devices and right-click (or use the arrow) to arrange just them where they are, or draw just them closer or spread them out (**Spacing of the 5 Selected**, which leaves them as they're arranged), or **Align** them (right-click > **Layout**) by their left, center, right, top, middle or bottom edges and **Distribute** them evenly. Right-click a group's title to arrange or space out just that group. Ctrl+click (or Shift-drag round) the titles of several sites, buildings or rooms, with devices too if you like, to drag them together, arrange them, or align and distribute them; each group moves as one box with everything in it.
- **Saving and exporting:** each map is saved automatically (reopen it with **Recent** or **Open**), and the map open when NOMAD closes (a file or a tribe map) is opened again when it starts. **New Map** puts the map open away, as it is, so **Start** makes a new one; pressing **Start** with a tribe map open asks whether to start a new map or map the tribe map again for everyone. **Export** saves the view showing as a picture (PNG or SVG) or a draw.io file (which Visio can import), or the devices, links or hosts as CSV.
- **Overlays:** **Overlay** (on the top bar) shows one thing at a time over the physical view; the rest fades (except Color By), and a bar over the map says what it found and what each color means (**Show All** or Esc puts the map back). **Highlight VLAN**, **VRF** or **Subnet** (a subnet's gateways, the switches and links carrying its VLAN, and the switches with hosts in it); **Single Points of Failure** (every device and connection that's the only way to part of the network) and, from a device's or link's right-click menu, **What If It Fails?** (what would be cut off, and how many hosts, measured from the device put at the top); **Trunk and Port Problems** (the VLANs tab's checks, on the links); **Link Speed and Status** (speed as color and thickness; links down at an end, with speeds that differ, or a duplex mismatch); **Utilization and Errors** (while Monitor is on, each poll reads the linked ports' counters: green, amber over 30% busy, red over 70% or with errors; rates in each link's tooltip); **Spanning Tree** > a VLAN (reads its switches, then shows the root bridge and the links blocking); **Software Targets** (each device on, behind or ahead of its model's software target, set on the Assets page); **Wireless** (the wireless controllers and their access points: green up, red down, a dashed line from each AP to its controller); and **Color By** kind, model, software version, site, VTP domain or mode, spanning tree mode, or AP group.
- **Monitoring:** tick **Monitor** (and choose how often, every 10 s to 10 min) to ping every device on the map and see which are up: a green dot and the response time, or a red tint and how long it's been down. A device counts as down after missing two checks in a row, so one lost ping doesn't make it flap. The Devices tab gets a Status column to filter on, and the **Monitor** tab logs each device going down or coming back (with how long it was down); the history is saved with the map. Monitoring carries on while you use other pages, and starts again with NOMAD if it was on (even if NOMAD was closed by Windows restarting). **Devices this computer can't reach** (behind a VRF, or with no route back here) are checked from a router on the map that can: right-click them > **Tools** > **Monitor from a Router...** (or **Router Probes...** on the Monitor tab) picks the router and VRF (an interface in the device's subnet first, then the most specific route), and **Add Probes over SSH** puts an IP SLA ICMP echo probe tagged NOMAD on the router (after a test ping from it; one already there for the same address and VRF is used instead). Monitor then reads each probe's latest result over SNMP (read-only), showing the device as up or down "via R5 (vrf X)"; a router not answering SNMP makes its devices **Can't check**, not down. The probes live on the routers, so everyone monitoring the map uses the same ones (found again when monitoring starts and every 10 minutes); the probes list shows them all and takes them away. Cisco IOS / IOS XE routers and L3 switches only; nothing is saved to startup unless you tick write memory.
- **Watching for new devices:** tick **Watch** to have what's plugged into the network added to the map as it appears. Every few minutes each switch NOMAD read is asked for its CDP and LLDP neighbors (two short tables, not a whole crawl); a switch with a new neighbor is read again at once, the way **Crawl from Here** does, so a new switch, router, firewall or access point goes on the map beside the port it was seen on, with its links and hosts. Every hour every switch's MAC table is read again for new hosts. Devices on the map that don't answer SNMP (they only ping, or were only seen as a neighbor) are asked again every hour too, and at once when you change the map's credentials: one that answers now (say, once SNMPv3 is set up on it) is read and turns solid, and the Watch tab's log says what it answered to. All the timers are set on the **Watch** tab: how often neighbors, hosts and devices that don't answer SNMP are checked, and how long after a trap or syslog message a switch is read. What's found is tagged **NEW** (a green tag on a device, a dot beside a host, and a New column on the Devices and Hosts tabs to filter on) until you right-click it > **Mark as Seen**, or **Mark All as Seen** on the Watch tab, which also logs what was found and where. A host that was on the map in the last 30 days isn't new, and devices you deleted stay off. For news the moment it happens, set the switches to send syslog and SNMP traps to the computer watching (the Watch tab's **Generate SNMP Config** builds the configuration; see [Setting switches up for NOMAD](#setting-switches-up-for-nomad)): a port coming up, a CDP or LLDP change or a MAC address learned has that switch read 45 seconds later. Watching shares UDP 514 with the Syslog page, carries on while you use other pages, and starts again with NOMAD if it was on.
- **Tribe maps:** connect to the tribe with **Tribe** > **Connect to the Tribe with a Key File...** (the same key file as for [sharing IPAM](#sharing-ipam-with-the-tribe); connecting on either page connects both). To leave the tribe, use **Tools** > **Tribe Management** > **Disconnect from the Tribe...**. On the tribe server itself, run NOMAD as administrator and it uses the server's own key, as the IP Addresses page does. Then **Tribe** > **Share This Map with the Tribe...** keeps the map on the tribe's IPAM server, with its SNMP credentials and scope, and everyone with the tribe key can open it from **Tribe**. The credentials are kept encrypted on the server (and on each computer, for when the server can't be reached), so nobody else has to type them in: changing them with **SNMP Credentials...** while a tribe map is open changes them for everyone who opens or watches it, including the Map Watcher service, within seconds (or once the server can be reached again). Changes anyone makes (moving devices, groups, hosts and devices added by hand, mapping again, what watching finds) reach the others within seconds. Changes are merged item by item, so two people moving different devices both keep theirs; when two change the same thing, the later change wins. Which groups are collapsed is each person's own, so expanding or collapsing one doesn't change anyone else's view. A tribe map opens and can be changed without the server, and the changes are sent when it's back. Only one computer watches a tribe map at a time (the others show who, and stand by), so the network isn't read twice; if it stops, another takes over. **Tribe** also renames or deletes a tribe map, or keeps a copy on this computer only.
- **Map Watcher service:** the tribe server may not be able to reach the switches, so watching runs where they can be reached. To watch while nobody has NOMAD open, install **Tools** > **Map Watcher Service...** on a computer that's usually on (as administrator), tick the tribe maps for it to watch, and set its timers. It takes over from NOMAD left open elsewhere, listens for the switches' syslog and traps (opening UDP 514 and 162 in Windows Firewall), and adds what it finds to the tribe maps. Its settings and log are in `%ProgramData%\NOMAD\watcher`.
- **Adding addresses from other pages:** right-click an address anywhere in NOMAD (a table, a log, a label, a map item) and choose **Add Device to Map...**, or use **Add to Map...** under Sweep's results. Pick the map (the one open, a saved one, a tribe map or a new one), then name the device and optionally link it. A map that isn't open is updated where it's kept; tick **Show it on the Network Map page afterwards** to go and see it.
- **What changed:** **Compare** lists the differences from an earlier map: devices and links that appeared or went away, devices that changed (such as one that stopped answering SNMP), and hosts that moved to another port. New devices are ringed in green and changed ones in amber; double-click a difference to see it on the map.

## Setting switches up for NOMAD

The **SNMP Config** page (under SNMP) builds the Cisco IOS / IOS-XE configuration a Catalyst switch needs for the Network Map and watching, and can type it in for you.

- **Read access:** a read-only community string, an SNMPv3 user, or both, limited by a standard access list to the computers running NOMAD. **Use the Map's Credentials...** sets the switches up with the community strings and SNMPv3 users saved for the open Network Map: tick which (public and private, and those for particular subnets, are left unticked to begin with); traps go with the first community string or user, and the rest are allowed to read too. **Generate SNMP Config** in the map's **SNMP Credentials...** dialog and on its Watch tab opens the page this way. **From the Map** (beside each) fills in a single community string or SNMPv3 user the Network Map already tries, the user with its protocols and passwords; **Generate** makes up a community string or passwords; **Add to Network Map** has the map try them. A v3 user goes in a group that can also read the per-VLAN contexts (`context vlan- match prefix`), so the hosts on every VLAN are found.
- **Where traps and syslog go:** this computer (**Add This Computer**) and the Map Watcher service's, with the interface they're sent from. Traps can be sent with v2c or as the v3 user; the ones the Map Watcher acts on (ports coming up, restarts, MAC address notifications) are ticked, and others can be added for the log.
- **Access ports:** an interface range to turn link-status logging and MAC address notifications on for. Configurations often turn link-status logging off on access ports, which hides a device being plugged in.
- **Sending it:** **Send to Session** lists the connected terminal sessions (with the prompt each one shows), or **Open SSH Session** opens one to a switch, from your saved SSH sessions (in their folders) or a **New Session**, and waits for its prompt. NOMAD asks first, warns if the session isn't at the enable (#) prompt, then types the configuration a line at a time (150 ms apart, so older switches don't drop characters) and shows the session so you can watch the switch's answers. **Copy** and **Save As...** are there to paste it yourself. Choose **Show: Commands to take it out again** for the lines that undo it.
- Check the result on the switch with `show snmp community`, `show snmp user`, `show snmp host` and `show logging`. The form is remembered, with its passwords encrypted for your Windows account.

## ACLs

The **ACLs & Route Maps** page (under Network Management) reads the ACLs (and [prefix lists and route maps](#prefix-lists-and-route-maps)) of Cisco IOS / IOS-XE switches and routers, lets you edit them, and sends back only what changed, in a way that can't leave a device without its ACL or lock you out of it.

- **Read:** pick devices on the left (the open Network Map's switches and routers, saved SSH sessions, or **Add Address...**) and **Read**: NOMAD logs in over SSH (each device's saved session, or the login chosen; the enable password when it logs in at >) and reads its running-config and `show ip access-lists` / `show ipv6 access-list`. You get every ACL (IPv4 standard and extended, named and numbered; IPv6), the object groups and time ranges, where each ACL is applied (interfaces in and out, VTY lines, and anything else naming one, such as an SNMP community or a route-map), and how many packets each rule has matched. On the map, right-click a switch or router > **Tools** > **ACLs & Route Maps...**, or a port's box > **ACLs on This Port...**.
- **Edit:** **Add Rule...** (protocol, source and destination typed as `10.1.0.0/16`, a host, `any` or an object group, or picked from IP Addresses, the map's devices and subnets; ports by number or name, ICMP messages, established, time range, logging and a remark), **Edit**, **Duplicate**, **Delete**, and drag rules (or **Move Up** / **Move Down**) to reorder them. The **Seq** column shows the number each rule will have once sent (`30 (was 10)` for one renumbered); double-click it (or F2), or use **Number** in the rule box, to type a number yourself: the rule moves to its place by that number (a number another rule keeps is refused; nothing typed means an automatic one). IOS can't renumber a single rule, so a rule given a new number is taken out and put back at it. A subnet mask typed where a wildcard goes is turned into the wildcard. **New ACL...**, **Apply To...** (beside where the ACL is applied, above its rules) an interface or VTY lines (in or out), **Take Off**, **Delete ACL**, and network and service object groups and time ranges (**New**) are edited the same way. New and changed rules are shown in green. Nothing goes to the device until you send it.
- **Checks** as you edit: rules that never match because an earlier rule takes everything they would, rules that aren't needed, duplicates, a subnet mask written as a wildcard (`255.255.255.0` where `0.0.0.255` was meant), host bits IOS will quietly clear, object groups and time ranges that aren't on the device, ports on a protocol without them, an IPv6 deny that drops neighbor discovery, and rules that haven't matched anything since the counters were cleared. Click a finding to see its rule.
- **Packet Tester:** a source, destination, protocol, ports (or ICMP message), TCP flags and a time: it says which rule matches and whether it's permitted, and what the device does with it now if that's different.
- **Changes** shows exactly the lines that will be sent, and the lines that undo them. Rules are changed by sequence number: one added goes in at a free number between its neighbors, one changed goes in at a new number before the old one is taken out (so there's never a moment without it), one moved is taken out and put straight back at its new place (IOS quietly drops a rule it has already, so it can't be added first). New rules get round numbers where they fit. When there's no free number, `ip access-list resequence` makes room first, with a step leaving round numbers for the new rules. The ACL is never deleted and typed in again. In a standard ACL IOS lists (and renumbers) the single addresses first, in an order of its own; NOMAD plans with that order, and doesn't move single addresses about when the order makes no difference (IOS won't take a single address after a rule that covers it, which Checks shows as an error).
- **Lockout check:** before sending, NOMAD checks that this PC could still log in: the VTY lines' access-class, and the inbound ACL on the interface this PC's packets come in on (read with `show ip cef`) and on the one holding the device's address. If it couldn't, **Send** stays off until you tick that you can reach the device another way (the console). A refusal the device as it is now gives too is only a warning, since NOMAD did log in to it. ACLs on routers in between aren't checked.
- **Send over SSH** goes in with a revert timer (**Put it back after**, on to begin with, 5 minutes): `configure terminal revert timer`, so the device puts its old configuration back by itself unless it's told `configure confirm`. Once the lines are in, NOMAD logs in again, and only if that works does it send `configure confirm`; or, with **unless I click Confirm**, it leaves that to you, so you can check more than logging in first: the device waits, with a countdown, for **Confirm** (`configure confirm`, from a new login) or **Put Back Now** (`configure revert now`), and nothing more goes to it until then. If a line is refused or the new login fails, NOMAD sends `configure revert now` straight away. If it can't even do that, the device puts its old configuration back when the time's up. The revert timer needs an archive path; if the device has none, NOMAD sets `archive` / `path` on its flash (and says so). Afterwards the device is read again, so the numbers and counts shown are its own. **Save to Startup Config** (`write memory`) is offered once a change is confirmed. Nothing is saved otherwise. **Send All Devices** sends every device with changes waiting, one after the other, and stops at the first that doesn't take them.
- **Send to Session** types the same lines into a terminal session instead (to watch, or for a device with Telnet only). With the revert timer on, log in again from another session to check you still can, then **Confirm** (or **Put Back Now**), which types it into that session. **Copy** and **Export...** give you the lines.
- **Library:** **Save to Library...** keeps an ACL on this PC with the object groups and time ranges it names. **Use on This Device** merges it rule by rule into the ACL of the same name (rules that already match are left alone) or makes it; **Put on Devices...** does that for several devices, read first, ready for **Send All Devices**. **Import Text...** takes ACLs pasted from a configuration. The **Scratch Pad** at the top of the device list is a device that isn't one, for building an ACL from nothing. **Compare...** shows how an ACL differs from the ACL of the same name on the other devices read.
- **Changes Sent** lists every change sent from this PC, with the lines and what undoes them: **Undo over SSH** (with the revert timer, when it's on), **Undo in Session** or **Copy Undo**.

### Prefix lists and route maps

The same page reads, edits and sends a device's IPv4 and IPv6 **prefix lists** and its **route maps**, listed under the ACLs, with the same device list, Changes box, revert timer, Library and Changes Sent. A change that touches an ACL, the prefix list a route map matches and the route map goes out together, in the right order.

- **Read:** every prefix list (with its description and how many routes each entry has matched, from `show ip prefix-list detail`), every route map (each entry's description, match and set lines and continue, and policy routing counts from `show route-map`), and where each is used: BGP neighbors and peer groups (in or out, per address family), redistribution and `default-information originate`, policy routing (`ip policy route-map` on interfaces, `ip local policy`), distribute lists and OSPF area filter lists, and anything else naming one. The BGP neighbors, routing processes, AS-path lists and community lists are read too.
- **Edit:** **Add Entry...** / **Edit** / **Duplicate** / **Delete**, drag entries or type numbers into the **Seq** column, the same as ACL rules. A prefix list entry is a prefix with `ge` / `le` (it says in words what it matches, and clears host bits as IOS does). A route-map entry is permit or deny, a description, match lines (all of them have to match; the values on one line are any of them) and set lines picked from what IOS has (prefix lists, ACLs, AS-path and community lists on the device are offered), and **continue** (BGP). **New** > **Prefix List...** / **Route Map...** (empty, a copy, or from the Library). **Apply To...** puts it on a BGP neighbor or peer group, a redistribution (one there already, or a new one, which starts redistributing), policy routing, or a distribute list / OSPF area filter; **Take Off** takes it off (a redistribution stays, without the route map).
- **Checks:** prefix list entries that never match (an earlier one takes every prefix they would) or aren't needed, `ge` / `le` IOS won't take, a list with no permit; route-map entries after one that matches everything, prefix lists, ACLs and AS-path lists that aren't on the device, an ACL and a prefix list in one entry (IOS refuses that), continue going backwards, set lines on a deny, and match lines IOS doesn't support where the map is used (AS-path or community matches on an OSPF redistribution, a tag match on BGP in): IOS warns about those and acts as if there were no match lines, so NOMAD's send takes the warning as a refusal and puts the change back.
- **Route Tester:** a prefix (and for a route map, a next hop, AS path, communities, tag, metric and local preference): it says which entry takes it, permit or deny, following continue, and what the route map sets, against the list or map as it will be once sent, and what the device does now if that's different. AS-path and community lists are matched the way IOS does (`_` and all).
- **How changes go:** IOS won't change a prefix list entry at its number or hold the same entry twice, so a changed entry goes in at a new number before the old one is taken out, and a moved one is taken out just before its new place goes in; there's no resequence for prefix lists, so with no number free the entries are renumbered one by one. A route-map entry is changed where it is: match values are added before the old ones are taken out (IOS adds match values up), set lines are taken out before the new ones go in (`set community` adds to what's there), descriptions are cleared and typed again (each description line adds one), and an entry that moves is made at its new number before the old one goes (a continue pointing at it follows it). `no route-map NAME` alone would delete the whole map, so an entry is always named with its number. Deleting a prefix list deletes its description too (IOS keeps it otherwise).
- **BGP soft clear:** BGP only puts routes it has already learned through a changed policy after a soft clear. Once a change touching a BGP neighbor's policy is confirmed (put on, taken off, or the route map, prefix list or ACL it uses changed), the neighbors it affects are listed with the command for each (`clear ip bgp 10.1.1.1 soft in`, `clear bgp ipv6 unicast ... soft out`, `clear ip bgp vrf RED ...`, peer groups too), none ticked: **Soft Clear Ticked** sends the ticked ones over SSH (or types them into the session the change went to), **Copy Commands**, or **Not Now**. The sessions stay up.
- **Library:** a prefix list, or a route map with the prefix lists and ACLs it matches, saved and merged into devices the same way as ACLs (entries already there are left alone).

## VPNs

The **VPNs** page (under Network Management) builds and edits VPNs between Cisco IOS / IOS-XE routers, writing every router's side from one design, and says why one that isn't up isn't.

- **Kinds:** **IPsec VTI** (a routed IPsec tunnel interface: the usual choice for site to site), **GRE over IPsec** (carries multicast and other protocols; IPsec in transport mode), plain **GRE** (not encrypted), **Crypto Map** (policy-based IPsec on the WAN interface between the two routers' LANs, for a far end that only does that; IKEv1 or IKEv2), and **DMVPN** (hubs and spokes on one multipoint GRE tunnel with NHRP and IPsec): phase 1 (hub and spoke), phase 2 and phase 3 (spokes build tunnels to each other as they need them; phase 3 with NHRP redirect and shortcut), one hub or two. A second cloud (two hubs' WAN links, or a dual-homed hub) is a second DMVPN: spokes with two multipoint tunnels on one WAN interface get tunnel keys.
- **Read:** pick routers on the left (the open Network Map's routers and switches, saved SSH sessions, or **Add Address...**) and **Read**: NOMAD reads each one's running-config, routes, and what `show crypto session detail`, `show crypto ikev2 sa` / `isakmp sa`, `show dmvpn`, `show crypto pki certificates` and the log say. It finds the VPNs on them, built by NOMAD or by hand: tunnels paired by their addresses, DMVPN clouds by NHRP network ID and tunnel subnet (hubs are the routers the others register with), crypto map entries by peer address. One whose far end wasn't read is shown with its far end as an address; its own side can still be changed. On the map, right-click a router > **Tools** > **VPNs...**, or select two routers (or more, for a DMVPN) > **Tools** > **Build VPN Between...**.
- **Build:** **New VPN...**: a name, the kind and the routers (with each one's role in a DMVPN). NOMAD fills in each router's WAN interface (the one toward the others), a tunnel number free on all of them, a tunnel subnet in 172.31.0.0/16 that none of them uses (**Suggest**, or **From IP Addresses...** to take a free block from a subnet there and record it), the tunnel addresses, and a random 24-character key. Add each router's **LANs** (Edit..., or picked from its interfaces), and set **Reached At** for a router behind NAT (the others use that address; its own stays its IKE identity). **Authentication:** a pre-shared key (**Generate**, **Show**), or **certificates** (below). **Crypto:** **Modern IKEv2** (AES-GCM-256, DH 20/19), **Compatible IKEv2** (AES-256 with SHA-256, DH 14), **IKEv1**, or your own (encryption, integrity or PRF, DH groups, the IPsec transform, PFS, DPD, NAT keepalives). **Routing across it:** static routes, EIGRP (classic or named), OSPF or BGP, set up the way each kind needs (on a DMVPN hub: no split horizon, and no next-hop-self for phase 2; OSPF point-to-multipoint, or broadcast with spokes at priority 0 for phase 2; a BGP listen range and peer group on the hub). With BGP, **Keep the VPN's LANs from the routers' other BGP neighbors** (on to begin with) adds the VPN's LANs as denies to their outbound prefix list (or puts NOMAD's guard list on them), so an ISP is never told them. IP MTU 1400 and TCP MSS 1360 on the tunnels.
- **One side only:** tick just one router in **New VPN...** and type the far end's WAN address (for a DMVPN, tick only spokes and type the hub's address, or tick only a hub), or **Add Far End...** in the editor. The far end is set up by hand: give it its tunnel address, LANs and BGP AS (Edit...) so the other routers' lines are right. NOMAD sends nothing to it; its lines are under Changes as "(by hand)" to copy, export or type into a terminal session, with placeholders such as `<WAN-INTERFACE>` for what isn't known. **Check it works first** only passes once its side is in (untick it to send your side alone).
- **Templates:** **New VPN...** > **Template: no routers** (with **Hubs** for a DMVPN) makes a VPN with no routers: sides A and B, or the hub(s) and a spoke that stands for every spoke. Choose its settings as for any VPN; each side's lines have placeholders (`<A-WAN-INTERFACE>`, `<SPOKE-WAN-IP>`, `<SPOKE-TUNNEL-IP>`, `<HUB-LAN-NETWORK>`, `<B-AS>`...) with a legend of what each one stands for, and a side's details can be typed in place of a placeholder (Edit...). The lines suit classic IOS as well as IOS XE (they keep the NHRP lines XE takes as defaults). **Save to Library** keeps a template; **Use** builds it on routers, or makes another template from it.
- **Edit** a VPN found on the routers the same way: only what changed is sent, in an order IOS takes (what something uses goes in first, and anything still in use is taken off what uses it before it's removed: a crypto map comes off its interface before its entry goes, the far ends' sessions are cleared before an IKE profile goes). The names each router uses (its proposal, keyring, profiles, crypto map...) are kept, lines NOMAD doesn't know are left as they are, and objects other VPNs use too are shared. A crypto map VPN on a WAN interface that already has a crypto map gets an entry in that map. **Take Away** removes a VPN from its routers (what other VPNs may share, such as NAT keepalives and an IKEv1 policy, stays).
- **Checks:** what would stop it working or make it unsafe: recursive routing (a far end's address inside what goes over the VPN), a LAN covering the WAN network, a far LAN the router already reaches with a better route (it would keep going that way, in the clear), LANs a routing protocol won't advertise, other eBGP neighbors a VPN's routes would leak to, a router's NAT catching the traffic before its crypto map, an ACL on a WAN interface dropping IKE, NAT-T, ESP or GRE from the far end, overlapping addresses and tunnel numbers taken, keys that are short or have characters IOS chokes on, weak crypto, MTU and MSS, certificates missing or a clock not kept by NTP, and this PC being inside a LAN the VPN carries.
- **Changes** shows each router's lines (or **Every router**) and what undoes them, keys hidden unless **Show keys** is ticked.
- **Send over SSH** puts the change on every router with the revert timer (**Put it back after**, 10 minutes to begin with; NOMAD sets an archive path where there's none), spokes before hubs. Then, with **Check it works first**, it checks the VPN from each end: the far tunnel addresses answer, the LANs reach each other (so the routing works), the crypto sessions are up. Only then does it confirm the change on every router from new logins (or, **unless I click Confirm All**, leaves it waiting with a countdown for **Confirm All** or **Put All Back Now**). If any router refuses a line, or any check fails, every router is put back (`configure revert now`), and NOMAD says why. After a confirmed change to the crypto of a VPN that was up, **Clear Sessions Now...** offers `clear crypto session remote ...` so the new settings take effect straight away. **Send to Session** types a router's lines into a terminal session instead.
- **Certificates:** from a **CA NOMAD sets up on one of the routers** (an IOS certificate server granting automatically, reached over SCEP, with HTTP open only to the VPN's routers), a **CA's SCEP URL**, or **by hand** (paste the CA's certificate, have each router make its request to take to the CA, paste back what it signs). **Get Certificates** does what's needed before Send: if a router's clock isn't kept by NTP (IOS won't use certificates then), it makes the CA router the VPN's time source (`ntp master`) and points the others at it, and waits for the clocks (a few minutes); it sets up the CA; and it enrolls each router that hasn't a certificate in the trustpoint, trusting the CA only if it shows the expected fingerprint. The routers then authenticate with RSA signatures, matching each other's certificates by issuer.
- **Status:** each VPN found, up, partly up or down, and why: a tunnel down, no IKE answer from a peer (UDP 500/4500 blocked, wrong address, no profile for it), IKEv1 stuck at MM_NO_STATE or MM_KEY_EXCH (most often a key mismatch), IKEv2 stuck negotiating, IKE up but no IPsec (transform sets or crypto ACLs that don't match), packets sent but none back, a spoke not registered with its hub, spoke-to-spoke tunnels up now, certificates expired or not yet valid, and what the routers logged about it in words. **Read Again** (or **Every minute**), and **Clear Sessions...**.
- **On the map:** **Overlay** > **VPN Tunnels** draws the tunnels between the map's routers as dashed lines, green when up, amber when partly up, red when down: the ones the crawl found (see **Tunnels** under Network Map), and the VPNs read here, which update the map as soon as they're read.
- **Library** keeps designs (without their keys) to build again on other routers. **Changes Sent** keeps every change, with the keys protected for this Windows account: **Undo over SSH**, **Undo in Session**, **Copy Undo**.

## Port mirroring

The **Port Mirroring** page (under Capture & Logs) copies a port's traffic, or a VLAN's, to where it can be captured, on Cisco IOS / IOS-XE switches and routers from the open Network Map, and takes it away again.

- **What and where:** choose the switch or router and its ports (**Add Ports...**, **Add VLAN...**, or **Add Host...** by MAC, IP address or name, as the map has it), and for each whether to copy what it receives, sends, or both. Then where the copies go: **A switch port**, **This PC**, or **An address** (a capture box, over ERSPAN). On the map, right-click a port's box > **Mirror This Port...** or **Mirror to This Port...**, a switch or router > **Tools** > **Mirror Ports...**, or a host on the Hosts tab > **Mirror This Host's Port...**.
- **The kind is picked for you** (or choose it under **Kind**): **SPAN** when the destination is on the same device; **RSPAN** when the map joins the two switches by switched links: a VLAN no switch on the map has (from 999 down) is made `remote-span` on each switch along the way and added to the trunks that don't allow it (`allowed vlan add`, never replacing the list); **ERSPAN** when only routers join them, or to an address (IOS XE: Catalyst 9000, 3650/3850, ISR/ASR, CSR), from the source device's management address (**More Options** picks a loopback or VLAN interface instead, a VRF, the ERSPAN ID and the session number).
- **Plan checks first:** it logs in to the devices over SSH (each device's saved session, or the login chosen; the enable password when they log in at >) and reads their sessions, so a free session number is used and a port already in one isn't. A destination port stops passing normal traffic, so a link to another network device, a trunk or a port-channel is never used as one; devices on the destination port that would lose the network, and sources adding up to more than it takes, are warned about. Plan changes nothing.
- **Set Up** sends each device its lines over SSH (the destination first and the source last, so copies start once there's somewhere for them), then reads the devices to check they show it. If a device refuses a line, NOMAD offers to take back what it already set up. **Send** on each device's row types its lines into a terminal session instead (to watch, or for a device with Telnet only); **Copy All** and **Export...** give you the lines and what undoes them. Nothing is saved to the startup configuration.
- **Remove after** (on to begin with, 60 minutes) adds an EEM applet with a countdown to each device: when the time's up the device takes its part away itself, logs a syslog message and deletes the applet, even if this PC has gone. A device that refuses the applet has NOMAD take its part away when the time's up, while NOMAD is open.
- **Mirrors** lists every mirror set up from this PC with exactly what takes it away: **Take Away** sends it over SSH (or **Take Away in a Session** types it into a terminal session); **Check Now** reads the devices to see whether each is still there and lists every session they have, NOMAD's or not (right-click one to take it away); **Read All Devices** does that for every switch and router on the map.
- **This PC:** NOMAD looks for the adapter chosen on the map. Plugged into a free port of its own (a second adapter), the copies go out of that port: **Capture Here** opens Packet Capture with **SPAN copies on** that adapter, so it takes them in. On the adapter this PC reaches the network devices through, on Wi-Fi, or on a port the map doesn't have, they go to its address over ERSPAN (so a wired port keeps working): **Capture Here** opens Packet Capture ready to capture what the source device sends and, with **Unwrap ERSPAN**, saves the mirrored frames as their own capture, as if this PC were plugged into the mirrored port.

## Packet capture

**Packet Capture** (under Capture & Logs) records with Windows' own packet monitor, pktmon (administrator rights needed; nothing to install), shows the packets in the viewer below it as they're captured, and opens what it saved there after **Stop and Save**. **Open Capture...** opens any pcapng or pcap file, from Wireshark or tcpdump too.

- **Capturing:** a filter (an address or subnet, a port, a protocol) keeps a capture small. **Capture whole packets** keeps all of each one (needed to follow streams); untick it to keep only the headers of long captures. **Stop after** stops and saves on its own. The settings fold away (the **Settings** button, which says what a capture would take) to give the packets the room; they fold away by themselves once a capture starts.
- **Show packets live** (on to begin with): the packets appear in the viewer about a second after they're captured, with the filter, summaries and problems kept up to date (the summaries and problems every few seconds). **Follow newest** keeps the newest in sight; scrolling up stops it and scrolling back to the bottom starts it again. NOMAD listens to the events pktmon logs for each packet while pktmon writes its file as usual, so the saved file is always the whole capture: on a very busy link (more than about 15,000 packets a second) the live view falls behind or misses some and says so, and after Stop and Save the viewer opens the saved file with everything.
- **SPAN copies on:** a switch mirroring (SPAN or RSPAN) to this PC's wired port sends copies addressed to other machines, which an adapter normally throws away. Tick it and choose the adapter: it's held in promiscuous mode while capturing (Windows' own SIO_RCVALL; no Npcap needed). The adapter needs an IPv4 address; on a SPAN destination port it usually gets a 169.254 one. Some adapters drop 802.1Q-tagged frames (with `encapsulation replicate`) before anything sees them.
- **Unwrap ERSPAN:** for a switch mirroring here over ERSPAN, Stop and Save also saves the mirrored frames as their own capture. The viewer unwraps them by itself too: a capture that's mostly ERSPAN opens showing the frames mirrored (**Show as Captured** shows the GRE packets).
- **Packets:** the list (with each packet's source and destination ports in their own columns; colored as Wireshark colors them: resent and reset in red, ARP, spanning tree and CDP/LLDP, names, routing protocols), the selected packet decoded line by line, and its bytes, with the part a line is about highlighted. Right-click a packet to follow its stream, show only its conversation or address, or hide its protocol. A packet captured twice (pktmon sees some at more than one point) is hidden; untick **Hide duplicates** to see them.
- **Filters** are written as in Wireshark: `ip.addr == 10.0.0.5 && tcp.port == 443`, `dns`, `!arp`, `ip.src == 10.1.0.0/16`, `eth.addr == 00:11:22:33:44:55`, `tcp.port in {80 443}`, `dns.qry.name contains "corp"`, `tcp.analysis.retransmission`, `frame contains "password"`. Just an address, a subnet, a MAC address or a port number works too. To build one by clicking, right-click a packet > **Add to Filter**, **Add to Filter with Or** or **Exclude from Filter** and pick its address, port, VLAN, protocol or conversation (the one in the column you right-clicked is first, in bold), or right-click any line of the decoded packet (a source address, a TTL, a flag, a DNS name) for that field, or the protocol it's under; **Show Only This** replaces the filter instead. They work while capturing live too. Field names complete as you type, and the box turns red with the reason while a filter doesn't make sense. **Open in Wireshark** opens the file there with the same filter.
- **Decoded:** Ethernet, 802.1Q, ARP, IPv4/IPv6, ICMP, TCP (with Wireshark's analysis: relative sequence numbers, retransmissions, duplicate ACKs, zero windows, gaps), UDP, DNS, DHCP, TLS (the server name asked for), HTTP, SMB2, SNMP, syslog, NTP, TFTP, RADIUS, 802.1X, CDP, LLDP, STP/RSTP/PVST+, LACP, DTP, VTP, HSRP, VRRP, OSPF, EIGRP, IGMP, PIM, BGP, GRE, ERSPAN and VXLAN; anything else is named by its port.
- **Summaries:** conversations (IP, TCP, UDP, Ethernet) and top talkers, with names learned from DNS answers and DHCP; the protocols; traffic over time (click a bar for its packets); and the devices heard announcing themselves (CDP/LLDP: which switch and port this is). Double-click a row to see its packets.
- **Problems:** what's worth a look, worst first: TCP resends, connections refused or unanswered, slow handshakes, zero windows, packets missing from the capture (on a mirror, usually the mirror dropping copies: the ports mirrored carry more than the destination takes), only one direction captured (a mirror of rx or tx only, or replies taking another path), DNS failures and slow answers, DHCP with no offer or from two servers (a rogue one?), duplicate IP addresses, ARP nobody answers, spanning tree topology changes and root changes, broadcast storms, ICMP unreachables, two HSRP or VRRP routers active, half duplex, 802.1X and RADIUS rejections, SMB, TLS and HTTP errors, SNMP with no answer. Double-click one (or **Show These Packets**) to see its packets.
- **Follow Stream** (double-click a TCP or UDP packet) shows what each side sent, in order and once, as text or a hex dump, with gaps marked; **Save As...** saves it.
- A big capture file (hundreds of thousands of packets) takes some seconds to open.

## Terminal and SCP

![Two sessions side by side on the Terminal page](docs/screenshots/terminal.png)

**Sessions**

- Save sessions in folders, and import them from PuTTY or a SecureCRT export.
- **File > Export SSH Sessions to SecureCRT...** writes an XML file for SecureCRT's **Tools > Import Settings from XML File**. Includes folders, hosts, ports, usernames, notes, private key paths and saved SSH passwords. When passwords are present, unlock NOMAD if needed and enter/confirm the destination SecureCRT configuration passphrase. Passwords are encrypted in SecureCRT's salted `03:` format; the destination must use the same configuration passphrase before importing (set one in SecureCRT first if needed). The export does not change SecureCRT's global security settings. Private key contents and saved key passphrases are excluded.
- **File > Export / Import NOMAD Terminal Settings and Sessions...** saves or restores a password-protected `.nomad` backup: all saved sessions and credentials, empty folders, recent connections, command buttons, highlighting, Terminal/SCP preferences and text scale. Import replaces these settings after confirmation and protects credentials with the destination installation's Windows account and current NOMAD master password. Keep the backup password to restore on another computer. Private keys and logs remain external files; live connections are not part of the backup.
- **Quick connect** takes `admin@10.0.0.1`, `telnet 10.0.0.5`, `raw 10.0.0.9:9100` or `COM3:115200`. An SSH connection with no user name (quick connect, or Connect > SSH on a host with no saved session) asks which saved credential to log in with, starting on the default one, or takes a user name typed instead; Recent reopens it the same way.
- **Recent** at the top of the list keeps your last 10 connections.
- **Layout** tiles sessions side by side, stacked, or in a 2 × 2 or 3 × 2 grid. Drag tabs between panes and windows.
- Pop any tab out into its own window (right-click the tab).
- **Copy and paste** as in PuTTY: dragging over text copies it, double-click copies a word, triple-click (or a click straight after a double-click) copies the whole line, and right-click pastes.

**Working with many devices**

- **Send to All** sends a command (or Ctrl+C, Ctrl+Z, Ctrl+Shift+6...) to every session, and **Type in All** mirrors your typing.
- **Command buttons** send saved commands or blocks of configuration with one click, or with Ctrl+1 to Ctrl+9 (even with the Buttons bar hidden). Drag a button, or right-click it > Move to Position, to change the order and so its hotkey.
- **Keyword highlighting** colors down, err-disabled, % Invalid, up, and IP and MAC addresses. Change the rules in View > Terminal Keyword Highlighting.
- **Save Config…** in each terminal session saves the complete running configuration to your workstation as a timestamped `.cfg` file (or a filename you choose). Start at the device's operational / exec prompt with permission to read the full config, select Cisco IOS / IOS XE / NX-OS / Arista EOS, Cisco ASA, Juniper Junos, or a custom command, then choose where to save. Cisco profiles disable paging for the current terminal session; Junos uses `no-more`. Disable paging yourself before using a custom command. Capture is independent of scrollback and finishes when the device prompt returns. **Cancel Save** (or **Ctrl+Shift+S** again) interrupts the command; **Ctrl+Shift+S** also starts a save, like the button; a disconnect, command error, or five-minute timeout leaves the destination unchanged. The same action is available by right-clicking the session tab. Config capture stays in that session even with Send to All enabled.

**Staying connected**

- A per-session **line delay** keeps slow consoles from dropping pasted text.
- **Reconnect automatically** when a device reloads.
- **Anti-idle** keystrokes keep exec-timeout from logging you out.
- **Log Session…**, beside Save Config…, asks where to save a plain-text session log on your workstation. The button changes to **Stop Logging** while recording; **Ctrl+S** starts or stops logging too. The saved-session **Logging** option still starts logging automatically in its configured folder when you connect.

**Security**

- SSH logs in with a password, an OpenSSH private key, or Pageant/SSH agent.
- Saved passwords are encrypted for your Windows account (DPAPI). Add a **master password** (AES-256) for more protection.
- Host keys are remembered, and NOMAD warns if one changes.
- Older switches that only speak SHA-1 SSH algorithms still connect.

**Serial**

- Serial sessions list the COM ports present, and can send a break (for Cisco ROMMON).

**Keys**

- Ctrl+Shift+F finds text, Shift+PgUp scrolls back, and Ctrl+mouse wheel zooms.
- Keys like Ctrl+B and F5 go to the device, not to NOMAD.

**SCP** is a WinSCP-style file manager using the same saved sessions:

- Drag files between your computer and the server, or press F5.
- F4 edits a remote file in place; F2 renames, F7 makes a folder, F8 deletes.
- Change permissions and owners (chmod and chown).
- **Work as Root** (sudo) browses, copies and edits as root.
- Transfers queue with progress, can be paused and resumed, and can be checked with SHA-256.
- **Synchronize** compares a local and a remote folder and copies the differences.

## IP address management (IPAM)

The **IP Addresses** page keeps track of addresses for several separate networks, such as air-gapped ones that reuse the same ranges.

![The IP Addresses page](docs/screenshots/ip-addresses.png)

**Everyday use**

- **Subnets as a tree** (blocks hold the subnets inside them), each with how much is used.
- **Every address** in a subnet as used, reserved or free, or as its network, broadcast or gateway address.
- **Use Next Free** records the lowest free address.
- **Loopback subnets:** every address is its own /32, with no network, broadcast or gateway address.
- **Select several** addresses or subnets to change them together.
- **Find Free Blocks** (right-click a subnet) shows the unused space in it, ready to add new subnets in.
- **Move to Another Network** (right-click a subnet, or **Move...** under the subnet list) moves it, with its recorded addresses, to another network: when a plan changes after the import and a block belongs to another enclave's page. You choose whether the subnets inside it go too; its role and Subnet Placement settings go with it; its VLAN links (the old network's) are dropped and a VLAN of the new network can be linked instead (the same number, if it has one). Anything in the way there (an overlapping subnet, an address recorded in it) or a placement move under way stops it. Tribe networks move on the server (it needs this version); this computer's networks can move into the tribe's, never the other way. The old network's history keeps what it had; the new one shows it added.
- **Add Subnet** can say what the new subnet is for and link it to a VLAN of the network's domains (the next free number, or one there is) as it's added. **Delete** takes its VLAN links and role and placement settings with it (and won't while it's being moved on Subnet Placement), and Subnet Placement flags links or settings left behind for a subnet that's no longer in IPAM.

**Sweeps and Last Seen**

- **Sweep Subnet** pings every address in place. **Last Seen** shows when each address last answered:
  - red where IPAM says used but nothing answered;
  - amber where something answered that IPAM doesn't have.
- **Record Answering Devices** and **Update MACs** save what a sweep found.
- Sweep results are kept, and shared through the IPAM server with who swept, including sweeps made offline.

**Search**

Search every network, or narrow it to subnets, addresses, one network, or one field (such as a name, a MAC, or a detail column from your workbook).

![Searching one detail column](docs/screenshots/ipam-search.png)

**Workbooks**

- **Import Spreadsheet** reads your addressing workbook (`.xlsx`, a network per page, or a `.csv` of one page).
  - Where a page's summary and its detailed listing disagree, you choose which to keep.
  - Impossible gateways get a suggested fix.
  - Unusable rows are listed by row number.
  - SNMP strings are never imported.
- **Export to Workbook** writes networks back in the same layout, and it imports back unchanged. **Export to CSV** is there too.
- **Compare with Workbook** lists every difference from a newer copy of the workbook to tick and apply, instead of importing it again. Edits made in NOMAD since the import are left unticked.

![Compare with Workbook](docs/screenshots/compare-workbook.png)

**Checking and history**

- **Check Data** lists likely mistakes, most serious first. Double-click one to go to it. It looks for:
  - a device on a network or broadcast address;
  - addresses outside every subnet;
  - names that look like a stray note;
  - "Loopback" subnets not marked as loopbacks;
  - duplicate MACs, and more.
- **History** shows every change with who made it and when: an address, a subnet, or the whole network.
- **View As Of** shows a network as it was at any moment.

![Check Data](docs/screenshots/check-data.png)

**On the Interfaces page**, **Free Address from IPAM** fills in the next free address, mask and gateway. It records the address in IPAM once you keep the new settings.

## Sharing IPAM with the tribe

Networks are either **Local** (on this computer) or **Tribe** (shared by an IPAM server on one always-on Windows machine).

**Setting up the server**

1. On the server machine, run NOMAD as administrator and open **Tools > Tribe Management**.
2. Click **Install Service**. It sets up the database, a certificate and nightly backups (kept 14 days) in `%ProgramData%\NOMAD\server`, installs the NOMAD IPAM Server service, and opens TCP port 8443.
3. **Save Tribe Key File** and give it only to the tribe: anyone with it can change the tribe's IPAM. **Change Tribe Key** locks out every old copy.
4. After updating NOMAD, click **Update Service** in the same window.

Spreadsheets are imported, and tribe networks added or deleted, only in NOMAD on the server itself (running as administrator).

**On each laptop**

1. **Tribe > Connect with Tribe Key File** here, or **Tribe > Connect to the Tribe with a Key File** on the Network Map page (either connects both), or **Connect with Key File** in **Tools > Tribe Management**. **Disconnect from the Tribe** there (the only place to leave) forgets the key and the copies of the tribe's networks and maps.
2. The laptop keeps a copy of the tribe's networks and history, so lookups work offline.
3. It syncs the moment anyone changes anything.

**Offline and conflicts**

- **Offline**, you can still assign, edit and free addresses. Changes wait as *pending* and are sent in order when the server is back.
- If someone else changed the same address first, **Review Refused Changes** lets you take the next free address instead, or discard yours.
- Subnets and networks can only be changed online.

**Moving the server to another computer**

1. On the old server (NOMAD as administrator), **Tools > Tribe Management > Move to Another Computer...**: give the new server's name and/or IP address (if known) and a password, and save the move file. It holds everything: networks and history, tribe maps and their SNMP credentials, the certificate and the tribe key.
2. On the new computer (NOMAD as administrator), **Set Up from Move File...** in the same window. It installs the service with the same data, certificate and tribe key.
3. The old server now only points laptops (and the Map Watcher service) to the new address: they switch over by themselves the next time they reach it, keeping their copies and pending changes. Leave it running until every laptop has switched, then **Uninstall** it. If no address was given, give the laptops the new server's tribe key file instead; they still keep their copies and pending changes.
4. **Undo Move...** on the old server puts it back in service, if the move is called off before anyone uses the new one. Delete the move file when you're done.

**Troubleshooting:** stop the service and run `NOMAD.exe --ipam-server` to run the server in a console. Its log is `%ProgramData%\NOMAD\server\server.log`.

## VLANs

The **VLANs** page (Network Management > VLANs) keeps each VLAN domain's VLANs: number, name, status (active, reserved or planned), description and the subnets each carries.

- **Domains:** a domain is where VLAN numbers are unique: a VTP domain, or a site's switches. **New Domain** makes a Tribe one (shared through the IPAM server, like tribe networks) or a Local one. A domain can belong to one IPAM network, whose subnets its VLANs carry, and can have ranges set aside (100-199 for users, say), which **Next Free** picks from.
- **IPAM stays as it is:** a VLAN names its subnets by CIDR, in its domain's network. Nothing is written to the subnets, so the IP Addresses page and its export to the workbook don't change. **Domain > Link Subnets Named for VLANs** links subnets whose names (Vlan 6) or details (a Vlan 10 column) say which VLAN they're in, without touching them.
- **From the network map:** **Domain > Bring in VLANs from a Network Map** (or **Add to VLAN Database** on the map's VLANs tab) compares what the crawl found on the switches with a domain, or a new one named after the VTP domain, and you tick what to add, rename or link. Each VLAN interface (an SVI, or a router's subinterface such as Gi0/0.100) links the IPAM subnet holding its address; the network holding most of them is suggested for a domain that has none. VLANs deleted from the domain, and names it already has, aren't ticked: the database may have the intended answer, and the switches may be what needs changing.
- **On the page:** **Gateways (IPAM)** comes from the linked subnets, **VLAN Interfaces (Map)** from the map open, and **On the Map** says how many switches have each VLAN, warning when a switch names it differently. In a VLAN's window, the subnets holding its interfaces on the map are marked and listed first. **Highlight on Map** shows a VLAN on the map, **Show Subnet in IPAM** goes to its subnet, and **History** shows who changed it and when.
- **Offline:** tribe VLANs can be changed offline: changes wait as pending and are sent when the server is back. **Review Refused VLAN Changes** offers the next free number (in the same range) or discarding, for a VLAN someone else changed first. Domains can only be changed online. The server needs NOMAD 1.16 or later (Update Service).

On the **Network Map**, the crawl reads every switch's VLANs, VTP domain and port VLANs (access, voice, trunk native and allowed). The **VLANs** tab lists each VLAN by VTP domain with its switches, ports, gateways and hosts, and **checks** for mistakes: a trunk facing an access port, native VLANs that differ, VLANs allowed at one end of a trunk only, access ports in VLANs the switch doesn't have, and a VLAN named differently on two switches. **Highlight on Map** (or right-click a device > **VLANs** > **Highlight VLAN**, or a port > **Highlight VLAN**) fades everything that doesn't carry the VLAN; the links that do are colored by how they carry it, with a trunk allowing it at one end only dashed orange. **Stop Highlighting VLAN** is at the top of every right-click menu while one is highlighted.

VLANs stay up to date as the map does: mapping again, **Crawl from Here** and watching (which reads each switch again every hour, and when a trap, a syslog message or a new neighbor says something changed) read them again, and watching notes in its log VLANs added, gone or renamed and ports moved to another VLAN. **Read VLANs Again** on the VLANs tab reads just the VLANs, quickly: it's how a map made before NOMAD read VLANs gets them.

**Carry VLAN** gets a VLAN to a switch over the map's links, on Cisco IOS / IOS-XE switches. Right-click a switch > **VLANs** > **Carry a VLAN Here...** (or a port's hosts > **Carry a VLAN Here...**), select two devices > **VLANs** > **Carry a VLAN Between These...**, or right-click a VLAN on the VLANs tab > **Carry It to a Switch...**.

- **The way:** NOMAD starts from the nearest switch already carrying the VLAN (the part of it with its gateway first), or from A if you choose one, and takes the way needing the fewest changes. Or choose **Through these switches** and set the whole route yourself: **Add Switch...**, or **Pick on Map** and click them in order; where two switches have several links, choose the one to use. **Fill In Between** adds the switches between two that aren't linked, and **Edit This Route** turns the way NOMAD chose into one you can change. Routers and firewalls can only be where it starts (a router-on-a-stick's subinterface counts), and a link with an access port in another VLAN is never used or changed.
- **Plan** reads the switches involved again first (their VLANs, port-channels, and how spanning tree has their ports for the VLAN), then lists each switch's changes: the VLAN created where it's missing (on a VTP client, on its domain's VTP server, which goes first), `switchport trunk allowed vlan add` on each trunk end that doesn't allow it (always with `add`, so nothing else on the trunk is touched; port-channels are changed, never their members), and any of B's edge ports you tick. Problems (no VTP server on the map, an extended VLAN on VTP version 1 or 2, a port spanning tree blocks in an MST instance, a switch that wasn't read) are listed above.
- **Redundant links:** links that would close a loop once the VLAN is on the way are listed with what spanning tree does there (Rapid-PVST+ keeps one blocked for the VLAN; MST blocks by instance, so you're warned; an unknown spanning tree could loop). They're only changed when you tick them, and go last.
- **Gateway:** whether B will reach the VLAN's gateway (an SVI or a subinterface on the map) is checked, never set up.
- **Sending:** each switch's row has **Send**: to a connected terminal session, or **Open Session to** the switch (its saved SSH session if there is one, else its saved Telnet one), typed in a line at a time after you say yes, at the enable prompt. **Send Undo** takes it back out. **Copy** and **Export All...** (every switch's configuration and undo) are there too, and **write memory** is only added if you tick it.
- **Verify** reads the switches again and marks each one done, or says what isn't yet (a VTP client still waiting for the VLAN, say), along with any VLAN mistakes now on the route's links. While the window is open, the map highlights the VLAN, rings the route's switches (amber for the ones to change, green for the rest) and draws the route on the links: thick green dashed where the VLAN will be added, thick green where it's carried already (or once verified), thick amber dashed for redundant links ticked, amber dotted for ones not ticked, and red dashed for a link that can't carry it. Hover over a link for what changes there.

## Subnet placement

An advertised subnet (one other routers have a route to) can be in only one place at a time; a local one (that nobody routes to, such as a printer subnet reused at every site) can be in several. The **Subnet Placement** page (Network Management > Subnet Placement) checks this for an IPAM network against the network map open on the Network Map page.

- **Each subnet** (per VRF) shows where it's planned to be (the VLANs it's linked to on the VLANs page), where the map finds it (each device's address in it, with places that are one L2 segment counted as one: HSRP/VRRP SVIs on a trunked VLAN, a link's two ends, a router subinterface and the switch it's on, two linked devices whose link can carry it, such as OSPF neighbors on a transit subnet), and whether it's advertised: the protocols and how many routers have a route to it, each route followed to where it leads, so each place says whether that device advertises it or only has an address in it. Routers on it the map couldn't read (a next hop in it no device on the map has, or a linked device that didn't answer SNMP) are noted. A subnet only covered by a summary counts as local, with the summary noted.
- **What's wrong:** an advertised subnet in two places; routers reaching it in different places; an advertised subnet linked to two VLANs; a subnet in another VLAN on the map than it's linked to; a local-only subnet that's leaking into the routing tables; an advertised subnet inside another one advertised elsewhere. **Show** picks problems, advertised, local, moving, or subnets on the map that aren't in the network.
- **Roles:** not every subnet is in a VLAN, so each one has a role saying what it's for: **VLAN**, **Point-to-point**, **Loopbacks**, **Tunnel**, **Routed port**, **Container** (a block holding other subnets) or **Other** (not known yet: nothing is expected of it). It's worked out from the map (tunnel and loopback interfaces, SVIs and subinterfaces, a router port plugged into a switch's access VLAN, the two ends of a link), then IPAM (a loopback subnet, a /32, a /30 or /31, subnets inside it, a name such as Vlan 6) and the VLANs page, and shown in the **Role** column, with a **Role** filter. A tunnel's ends, or a point-to-point link's, count as one place however far apart they are (so a DMVPN subnet advertised from the hub and every spoke isn't "in several places"); router loopbacks inside IPAM's loopback subnet belong to it, and one loopback address on two devices is a problem. Only VLAN subnets are expected to be linked to a VLAN, and the VLANs page's subnet list and name-based link suggestions leave the others out (a tick box lists them too).
- **Role and Scope** sets what a subnet is for, and advertised or local when the routing tables don't say it right (with a note), or marks its places one L2 segment the map can't see. A role set that doesn't fit the map (a tunnel set as point-to-point, say) is pointed out. It's kept beside the VLANs (shared with the tribe), never on the IPAM subnet, so the IP Addresses page's exports are unchanged.
- **Moving a subnet:** **Plan Move** (from its VLAN, and device, to another; when; why), **Start Move** when the work begins, **Read Routes Again** once it's done on the switches, **Check Move** (it's only at the new place, and every route leads there), then **Complete Move**, which relinks it on the VLANs page. While it's in progress, the page expects it at the old place or the new one, and flags it if it's advertised from both.
- **VRFs:** each VRF is checked on its own (the same subnet in two VRFs is two subnets). Interfaces' VRFs come from CISCO-VRF-MIB or MPLS-L3VPN-STD-MIB, and VRF routing tables from MPLS-L3VPN-STD-MIB; when a device doesn't offer those, the crawl log says so and the page notes it.
- Watching notes subnets that appear, go or move between switches in the Watch log, and **Read Routes Again** brings the map's routing tables up to date without mapping again.

## Assets

The **Assets** page (Network Management > Assets) is the inventory of the hardware on the network. Each asset is its **serial number**: its hostname, address and software version are what it has now, and its history says what they were.

- **From the network map:** every crawl now reads each device's hardware over SNMP (ENTITY-MIB): one chassis per stack member, each with its model and serial number, and the modules, power supplies, fans and transceivers that have a serial number; and the **software version** it runs (from its system description, or PAN-OS's and FortiOS's own MIB). An Aruba wireless controller gives its own serial number and model, and those of all its access points (up or down). Phones tell their switch their model and firmware (CDP) and serial number (LLDP-MED). The map's device details and Devices table show the serial and software too.
- **Kept in step by itself:** with **Bring in after each crawl** ticked (the default), each crawl, Crawl from Here and Read Hardware Again brings what it found into the list: new hardware is added, a device found under another hostname or running other software is changed (renames and upgrades go in its history), and where a hostname, stack member or slot now has a **different serial number**, the old hardware is marked **Replaced**, pointing at the new one (which keeps its location and owner, not its asset tag). Changes that might undo what was said by hand (a location typed in, hardware marked spare or retired but seen on the network) wait for **Review the Crawl's Hardware**, and a serial number found on two devices (lab images often share one) is pointed out, never brought in. **Bring In from Map...** does the same with a review first, for the open map or a map file.
- **Parts:** **Track parts** (ticked by default) brings in modules, power supplies, fans and transceivers as assets of their own, in the chassis they're in; untick it to keep just chassis, phones and servers.
- **MAC addresses:** a phone's or server's MAC is recorded with it, and so is each switch's and router's **base MAC**: the first of the block of MACs burned into its chassis, which its ports and VLAN interfaces take theirs from, so it stays with the hardware like its serial number. A stack's members each have their own (CISCO-STACKWISE-MIB); a device on its own gives it as its LLDP chassis ID or bridge address; a firewall that gives neither, the MAC of its management interface (said so in its details). A stack's own MAC isn't put on any member: it's the active member's, so it moves. Type a whole MAC in the filter box, written any usual way (`00-1B-17-00-01-00`, `00:1b:17:00:01:00`, `001b.1700.0100`), and the assets it belongs to are shown: a phone's or server's own, a chassis' base MAC, or (by the open map) one of its ports' or VLAN interfaces' MACs, so a MAC from MAC Finder or an ARP table leads to the switch.
- **Without a serial number:** a phone (or a chassis that gives no serial) is known by its MAC address until its serial number is known, and a device NOMAD can't read (seen only in a neighbor's CDP) by the map device it is; a Nexus switch's CDP name carries its serial number, which is used.
- **Servers, phones, and devices SNMP says nothing of:** **Read Details over SSH/WMI...** asks Windows servers over WMI (WinRM, or DCOM; as your Windows login, or a user name and password, which goes to PowerShell on its input, never its command line), Linux servers over SSH (a saved session, a saved credential or a typed login; the serial number needs root, so passwordless sudo is tried), Cisco IP phones through their web page, and Cisco switches, routers and firewalls (IOS, IOS XE, NX-OS, ASA) over SSH for **show inventory** and **show version** (each chassis and stack member, its modules, power supplies, fans and transceivers, the software, and each member's base MAC; nothing is changed on them), then shows what that changes before recording it. A network device on the open map gets the hardware on the map too, and keeps it when a later crawl's SNMP says nothing of it. On the map, right-click devices > **Tools** > **Read Hardware over SSH...** asks them (it works for ones that don't answer SNMP at all), and **Read Hardware Again** names the devices whose SNMP gave no serial numbers.
- **By hand:** **Add...** records hardware the map can't see (a spare on the shelf), and **Edit...** has every field: asset tag, owner, location, status (In service, Spare, In repair (RMA), Replaced, Retired), purchase, warranty and end-of-life dates, notes. Right-click several to set their status, location or owner at once.
- **Software targets:** **Software Targets...** keeps the software each model should run: a target version, and other versions that are fine too (an older one still supported, a newer one being tried). A target can be for one model (`C9300-48P`) or a family (`C9300-*`, `CP-88??`); the most exact one counts. **Add from the Asset List...** starts one for each model from the version most of it runs, and right-click a device > **Make 17.9.4a the Target for C9300-48P...** sets one from it. Each device is then on target, **behind** (an older version), **ahead** (a newer one) or running **other software** (another train, such as 15.2(7)M against 15.2(7)E): versions compare the way their numbers read (17.9.4a is ahead of 17.9.4 and behind 17.12.1). The Software column is colored by it, **Show** > Not on target software lists the ones off it, the summary counts them, and the export has each one's target. On the map, **Overlay** > **Software Targets** colors the devices the same way. The tribe's targets are shared through the IPAM server and are changed only while it can be reached (they matter to everyone); the server needs this version of NOMAD.
- **Problems:** the **Problems** column (and **Show** > With problems) points out assets with no serial number, hardware in service not on a map for 30 days, a device off its model's software target (or, for a model without one, running other software than most of its model), and an ended warranty or end of life.
- **History and export:** **History...** shows one asset's changes, **All Changes...** every asset's, and **Export...** writes the list to Excel or CSV. **Show on Map** (and the map's right-click **Show In** > **Assets**) goes between an asset and its device.
- **Shared and offline:** like VLANs, the tribe's asset list is shared through the IPAM server, and can be changed offline: changes wait until the server is back, and **Review Refused Asset Changes** lists any someone else beat (they changed that asset first, or recorded its serial number). The server needs this version of NOMAD (Update Service); Local is this computer's own list.

**Read Hardware Again** (on the Assets page, or right-click devices on the map > **Tools**) reads just the hardware and software of the map's devices: it's how a map made before NOMAD read serial numbers gets them, and how a swapped part shows up without mapping again.

## The Manage pages and the map together

- **One network at a time:** choosing a network on IP Addresses, VLANs (a domain of it) or Subnet Placement chooses it on the others, and opening a map of a network chooses that network.
- **A map is of one IPAM network:** **IPAM Network...** (on the map's bar, or its Map menu) says which, suggesting the one holding most of the map's subnets. It's saved with the map (and shared with a tribe map). The VLANs and Subnet Placement pages only check a network against a map of it, so a map of another network isn't mixed in.
- **When a network has no map, or no VLAN domain:** the Network Map page says so in a bar: a map that isn't tied to an IPAM network (with IPAM Network... to say which), or a map of another network than the pages are on, with **Open** for that network's map (a tribe map, or a recent map file, of it) and **Back to** the map's network. A tribe map no one has tied to a network asks once, when opened. The VLANs page shows nothing (not another network's domain) for a network with no VLAN domain, with **New Domain for** it.
- **IPAM on the map:** the Hosts tab has an **IPAM** column (in IPAM with its name, not in IPAM, or IPAM has another MAC address); the logical view's subnets show their IPAM name and role, outlined orange or red when Subnet Placement finds something wrong, and say "not in IPAM" when the network doesn't have them. Watching notes new hosts and subnets the network doesn't have in the Watch log.
- **Recording what the map found:** **Record in IPAM...** (on the map's bar and Map menu, a device's right-click for its own addresses, or the Hosts tab's right-click for the hosts chosen) lists the map's addresses IPAM lacks, or has with another MAC: a device's management address named after it (R1S1), an interface's after the device and port (R1S1 Vl100), a host by its name. Tick what to record, rename any first, then Record Ticked; nothing is written before that. Tribe networks take them offline too (sent when the server is back). The map must be tied to its IPAM network first (it asks).
- **IP Addresses shows what the other pages know** about the selected subnet, on its line above the addresses: its role, the VLANs it's linked to, whether Subnet Placement finds anything wrong with it, and how many places the map has it in, each a link to that page. None of it is written to IPAM, so the exports are unchanged.
- **Links everywhere:** a subnet's right-click menu (IP Addresses) shows its VLANs, its placement and it on the map; an address's shows the device that has it (or the switch a host with it is on). The VLANs page shows each subnet's role and placement with links, and Show Subnet in Subnet Placement. Subnet Placement links to IP Addresses, the VLANs page and the map, and right-click shows its VLANs. On the map, a subnet on the logical view, a device (its addresses in IP Addresses, its subnets in Subnet Placement), a port (its VLANs on the VLANs page, its host's address in IP Addresses), a host, and the VLANs tab (**Show on VLANs Page**) all reach the other pages.

## Good to know

- **Administrator rights:** NOMAD starts without them, so viewing and testing work straight away. When a change needs them, it offers to restart as administrator (or use File > Restart as Administrator). To always have them, tick **File > Always Start as Administrator** (or the box on the yellow banner): Windows then asks for them each time NOMAD starts. Hold Shift while it starts (or answer No to Windows) to start without them for once.
- **Opening NOMAD again** while it's open brings the open one to the front rather than starting a second copy (it asks first if the open one is another version, or hasn't administrator rights this one has). A splash says what NOMAD is loading while it starts.
- **What's new:** Help > What's New... lists what each version added and fixed, newest first, with the version running marked.
- **Diagnostics report:** Tools > Run Diagnostics Report (Ctrl+R) checks the adapter, gateway, DNS, internet access, route, path MTU and ARP table in about half a minute. It saves the findings as a web page to attach to a ticket.
- **Updating the MAC vendor list:** download https://standards-oui.ieee.org/oui/oui.csv and run `python -m nomad.oui build oui.csv`.

**Shortcuts**

Press **F1** for the searchable, grouped keyboard guide, or read the [full keyboard guide](docs/keyboard-shortcuts.md).

| Goal | Shortcut |
| --- | --- |
| Choose a tool | Ctrl+K |
| Choose an adapter | Alt+A |
| Focus the tool's main input or filter | Ctrl+F |
| Start a diagnostic/discovery tool | Shift+Enter |
| Stop the current tool | Shift+Esc |
| Next / previous tool | Ctrl+Tab / Ctrl+Shift+Tab |
| New saved session / saved-session folder | Ctrl+N / Ctrl+Shift+N |
| Previous / next Terminal or SCP session | Alt+Left / Alt+Right |
| Close the current Terminal or SCP session | Ctrl+W (Enter confirms Yes) |
| Pop out a session / move it back | Ctrl+Shift+Enter |
| Focus the current SCP pane's folder path | Ctrl+L |
| See command-button numbers (and S / Shift+S over Log Session / Save Config) | Hold Ctrl in the terminal window |
| Start / stop a terminal session log | Ctrl+S |
| Save a terminal session's running config | Ctrl+Shift+S |

SCP folder-back is now **Alt+Up**; **Alt+Left** switches sessions. Terminal **Ctrl+W** now closes the session, while **Ctrl+L**, **Ctrl+C** and **Ctrl+R** retain their shell behavior.

**Where things are kept**

| What | Where |
| --- | --- |
| Terminal sessions and SSH host keys | `%APPDATA%\NOMAD\sessions.json`, `known_hosts` |
| Profiles | `%APPDATA%\NOMAD\profiles.json` |
| Local IPAM networks | `%APPDATA%\NOMAD\ipam.db` |
| Network maps | `%APPDATA%\NOMAD\maps` |
| Log (Tools > View Log) | `%LOCALAPPDATA%\NOMAD\nomad.log` |
| IPAM server | `%ProgramData%\NOMAD\server` |

The first time NOMAD runs, it moves over the folders and settings from NIC Manager.

## Running from source and building

    pip install -r requirements.txt
    pythonw Main.py

Tests, and a standalone exe (`dist\NOMAD-<version>.exe`):

    pip install -r requirements-dev.txt
    python -m pytest
    .\build.ps1

The exe's startup splash is drawn by PyInstaller with Python's Tcl/Tk, so the Python that builds needs tkinter (the python.org installer's "tcl/tk and IDLE" option, on by default).

**Releases:** the version lives in `nomad\__init__.py`. Note changes under Unreleased in `CHANGELOG.md` as you go, and a line or two for users in `nomad\data\whats_new.md` (shown under Help > What's New; the tests check every version has an entry), then:

    python -m nomad.version bump patch     (or minor / major)
    git add -A
    git commit -m "Release X.Y.Z"
    git tag vX.Y.Z
    .\build.ps1

## Third-party software

NOMAD bundles PyQt5 (GPL), paramiko (LGPL 2.1) for SSH, pyte (LGPL 3) for terminal emulation, pyserial (BSD) for serial ports, openpyxl (MIT) for workbooks, and pywin32 (PSF) for the IPAM server service.

Happy troubleshooting!
