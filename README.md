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
- [Terminal and SCP](#terminal-and-scp)
- [IP address management (IPAM)](#ip-address-management-ipam)
- [Sharing IPAM with the tribe](#sharing-ipam-with-the-tribe)
- [VLANs](#vlans)
- [Subnet placement](#subnet-placement)
- [Good to know](#good-to-know)
- [Running from source and building](#running-from-source-and-building)

## Getting around

- Switch tools with the **favorites rail** on the left, or open the **Tools drawer** for the full list. **Ctrl+K** opens tool search (try “bandwidth” or “file transfer”). Right-click a tool to pin or unpin it; drag favorites in the rail to reorder them. Favorites and their order are saved.
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
| **TFTP** | A TFTP server and client for firmware and config transfers. |
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
| **Network Map** | Crawls switches, routers and firewalls over SNMP from a starting device and draws what's plugged into what (CDP/LLDP), with the hosts on each switch port, and the subnets and routes between them. See [Network map](#network-map). |
| **SNMP Config** | Builds the Cisco IOS / IOS-XE configuration that sets a switch up for NOMAD, and types it into a terminal session to the switch. See [Setting switches up for NOMAD](#setting-switches-up-for-nomad). |

### Capture & Logs

| Page | Functions |
| --- | --- |
| **Packet Capture** | Captures to a pcapng file for Wireshark with Windows' built-in pktmon. Nothing to install. |
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
- **Reading the map:** colors show the kind of device (switch, router, firewall, access point). A dashed outline is a device NOMAD didn't read itself: one only seen as a neighbor, or one that **pings but doesn't answer SNMP** (usually the community string or an SNMP ACL). Red means it answered neither. Palo Alto firewalls are found through LLDP, so turn on an LLDP profile on the interfaces facing the switches.
- **Adding and removing hosts:** a device that's turned off or unplugged while you map won't be found, so add it by hand: right-click a switch (or a port's box, or the Hosts tab) > **Add Host...** and give its port and a name, IP or MAC. Hand-added hosts are drawn dashed and kept when you map again; if one is later found for real, the crawl's entry takes over and keeps your name and note. Right-click hosts (or select them on the Hosts tab and press Delete) to edit or delete them. A deleted host that's still plugged in comes back the next time you map.
- **Adding devices and drawing links:** for a device the crawl can't find (an unmanaged switch, or one SNMP can't reach), right-click the map's background > **Add Device Here...**, or a device > **Edit** > **Add Device Linked to This...**, and give it a name, an IP address, its kind and model. To link two devices yourself (a port with CDP and LLDP turned off, say), right-click one > **Edit** > **Draw Link from Here** and click the other, then give the ports (or use **Add Link...**). Devices added by hand have their names in italics and links drawn by hand are dotted. A device with an address is checked over SNMP with your community strings, like the crawl's devices: it's dashed with *Pings, no SNMP* when the community or an SNMP ACL is wrong, and red when it doesn't answer at all (right-click > **Edit** > **Check SNMP Again**). It's pinged while monitoring, like the others. They're kept and checked again when you map again; once the crawl finds the device (by its address or name), the crawl's entry takes over its links, hosts, group and note, and a link drawn by hand goes once the crawl finds a link between the same two devices. Right-click them to edit or delete them. **Check SNMP Again** (right-click > **Edit**) also asks a device the crawl found that doesn't answer SNMP, with the credentials as they are now: one that answers is read (Crawl from Here), and one that doesn't says why when it can (an SNMPv3 user it doesn't know, a wrong password).
- **Logical (L3) view:** the routers, L3 switches and firewalls joined through the subnets they have addresses in, with the next hops their routes point to. After the crawl, NOMAD traceroutes from this computer to what SNMP couldn't show (devices that didn't answer, next hops that aren't on the map, and static routes' destinations) and draws the paths it found, dashed, with `*` where a hop didn't answer. Select a router to see its IP interfaces and routes, or a subnet to see what's on it (right-click it to sweep it). Traceroute can be turned off under **Scope...**.

![The Logical (L3) view](docs/screenshots/network-map-l3.png)

- **The top bar:** one row of buttons. **Map** holds New Map, Open, Recent, Save As, Export, Compare, the tribe's maps and the **Key** (what the map's colors, outlines and line styles mean); **Crawl** shows where to start from, to map again or crawl from another switch (it shows anyway while there's no map, or a crawl's running). The status line keeps to one line: hover over it to read all of it. To have the buttons spread over two rows as before, with the start row always showing, choose **View** > **Network Map Top Bar** > **Classic**.
- **Working with it:** scroll to zoom and drag the background to move around. Drag devices where you want them (NOMAD remembers, even after mapping again); to move several at once, hold **Shift** and drag a box round them (Ctrl+click adds or removes one, Ctrl+A selects everything), then drag any of them. **Ctrl+F** goes to the find box, which works on the tab showing: it finds a device on either map, filters the rows of the Devices, Links or Hosts tab as you type, or finds text in the crawl log. **Find** jumps to a device or host by name, IP, MAC or vendor. Right-click a device for SSH and the other sessions (**Connect**), ping, SNMP and the rest (**Tools**), **Crawl from Here** (which adds what it finds to this map, reading only devices that weren't read yet), **Put at the Top**, or **Show In** the physical or logical view, the Devices tab or the Links tab (all its links). The Devices, Links and Hosts tabs list everything, with Excel-style filters: click the funnel at the left of a column's header (or right-click the header) to tick the values to show, search them, or sort (such as a Kind, a Switch or a VLAN); filters on several columns combine, and the tab shows how many rows are left (Hosts (12 of 340)). Double-click a row to see it on the map, or right-click it (on the Links tab, to show both ends of a link).
- **Sites and buildings:** select devices, right-click > **Group** > **New Site or Building...** to draw a labeled box round them (a building can sit inside a site). Drag a device into a box to add it, or out of one to take it out; drag a box's title to move everything in it. Double-click the title to collapse the group into one box that keeps its links to the rest of the map, which is handy for a big campus; finding a device inside opens it again. Select a group to see its devices, how many are down and its links out. Groups are saved with the map, carried over when you map again, shown in the Devices tab's Group column (to filter on), and exported to draw.io as boxes.
- **Arranging:** **Re-arrange** lays the map out again, ordering each layer so links cross as little as it can find (and a link between two devices in the same layer doesn't run over the ones between), with each device near the ones it links to. Devices with a single link (access points, say) sit in a grid under the device they hang off, or, when it has links down to other devices too, off to the side those links don't go, so they don't run through the grid. Its arrow chooses **Top to Bottom**, **Bottom to Top**, **Left to Right**, **Right to Left**, **Grid** or **Circle** (rings round the core) and the **Spacing** (**Compact**, **Normal**, **Roomy** or **Spacious**: draws the map's devices closer together or spreads them out, leaving each where it is among the rest, so nothing is laid out again; Re-arrange uses it from then on), and with **Keep Sites and Buildings Together** each group is laid out inside its own box, with the device that links out of it on top, and the boxes are laid out as the links between them go (each under the one it hangs off), or tiled when nothing links them. Select several devices and right-click (or use the arrow) to arrange just them where they are, or draw just them closer or spread them out (**Spacing of the 5 Selected**, which leaves them as they're arranged), or **Align** them (right-click > **Layout**) by their left, center, right, top, middle or bottom edges and **Distribute** them evenly. Right-click a group's title to arrange or space out just that group. Ctrl+click (or Shift-drag round) the titles of several sites, buildings or rooms, with devices too if you like, to drag them together, arrange them, or align and distribute them; each group moves as one box with everything in it.
- **Saving and exporting:** each map is saved automatically (reopen it with **Recent** or **Open**), and the map open when NOMAD closes (a file or a tribe map) is opened again when it starts. **New Map** puts the map open away, as it is, so **Start** makes a new one; pressing **Start** with a tribe map open asks whether to start a new map or map the tribe map again for everyone. **Export** saves the view showing as a picture (PNG or SVG) or a draw.io file (which Visio can import), or the devices, links or hosts as CSV.
- **Overlays:** **Overlay** (on the top bar) shows one thing at a time over the physical view; the rest fades (except Color By), and a bar over the map says what it found and what each color means (**Show All** or Esc puts the map back). **Highlight VLAN**, **VRF** or **Subnet** (a subnet's gateways, the switches and links carrying its VLAN, and the switches with hosts in it); **Single Points of Failure** (every device and connection that's the only way to part of the network) and, from a device's or link's right-click menu, **What If It Fails?** (what would be cut off, and how many hosts, measured from the device put at the top); **Trunk and Port Problems** (the VLANs tab's checks, on the links); **Link Speed and Status** (speed as color and thickness; links down at an end, with speeds that differ, or a duplex mismatch); **Utilization and Errors** (while Monitor is on, each poll reads the linked ports' counters: green, amber over 30% busy, red over 70% or with errors; rates in each link's tooltip); **Spanning Tree** > a VLAN (reads its switches, then shows the root bridge and the links blocking); and **Color By** kind, model, software version, site, VTP domain or mode, or spanning tree mode.
- **Monitoring:** tick **Monitor** (and choose how often, every 10 s to 10 min) to ping every device on the map and see which are up: a green dot and the response time, or a red tint and how long it's been down. A device counts as down after missing two checks in a row, so one lost ping doesn't make it flap. The Devices tab gets a Status column to filter on, and the **Monitor** tab logs each device going down or coming back (with how long it was down); the history is saved with the map. Monitoring carries on while you use other pages, and starts again with NOMAD if it was on (even if NOMAD was closed by Windows restarting).
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

## The Manage pages and the map together

- **One network at a time:** choosing a network on IP Addresses, VLANs (a domain of it) or Subnet Placement chooses it on the others, and opening a map of a network chooses that network.
- **A map is of one IPAM network:** **IPAM Network...** (on the map's bar, or its Map menu) says which, suggesting the one holding most of the map's subnets. It's saved with the map (and shared with a tribe map). The VLANs and Subnet Placement pages only check a network against a map of it, so a map of another network isn't mixed in.
- **When a network has no map, or no VLAN domain:** the Network Map page says so in a bar: a map that isn't tied to an IPAM network (with IPAM Network... to say which), or a map of another network than the pages are on, with **Open** for that network's map (a tribe map, or a recent map file, of it) and **Back to** the map's network. A tribe map no one has tied to a network asks once, when opened. The VLANs page shows nothing (not another network's domain) for a network with no VLAN domain, with **New Domain for** it.
- **IPAM on the map:** the Hosts tab has an **IPAM** column (in IPAM with its name, not in IPAM, or IPAM has another MAC address); the logical view's subnets show their IPAM name and role, outlined orange or red when Subnet Placement finds something wrong, and say "not in IPAM" when the network doesn't have them. Watching notes new hosts and subnets the network doesn't have in the Watch log.
- **Recording what the map found:** **Record in IPAM...** (on the map's bar and Map menu, a device's right-click for its own addresses, or the Hosts tab's right-click for the hosts chosen) lists the map's addresses IPAM lacks, or has with another MAC: a device's management address named after it (R1S1), an interface's after the device and port (R1S1 Vl100), a host by its name. Tick what to record, rename any first, then Record Ticked; nothing is written before that. Tribe networks take them offline too (sent when the server is back). The map must be tied to its IPAM network first (it asks).
- **IP Addresses shows what the other pages know** about the selected subnet, on its line above the addresses: its role, the VLANs it's linked to, whether Subnet Placement finds anything wrong with it, and how many places the map has it in, each a link to that page. None of it is written to IPAM, so the exports are unchanged.
- **Links everywhere:** a subnet's right-click menu (IP Addresses) shows its VLANs, its placement and it on the map; an address's shows the device that has it (or the switch a host with it is on). The VLANs page shows each subnet's role and placement with links, and Show Subnet in Subnet Placement. Subnet Placement links to IP Addresses, the VLANs page and the map, and right-click shows its VLANs. On the map, a subnet on the logical view, a device (its addresses in IP Addresses, its subnets in Subnet Placement), a port (its VLANs on the VLANs page, its host's address in IP Addresses), a host, and the VLANs tab (**Show on VLANs Page**) all reach the other pages.

## Good to know

- **Administrator rights:** NOMAD starts without them, so viewing and testing work straight away. When a change needs them, it offers to restart as administrator (or use File > Restart as Administrator).
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

**Releases:** the version lives in `nomad\__init__.py`. Note changes under Unreleased in `CHANGELOG.md` as you go, then:

    python -m nomad.version bump patch     (or minor / major)
    git add -A
    git commit -m "Release X.Y.Z"
    git tag vX.Y.Z
    .\build.ps1

## Third-party software

NOMAD bundles PyQt5 (GPL), paramiko (LGPL 2.1) for SSH, pyte (LGPL 3) for terminal emulation, pyserial (BSD) for serial ports, openpyxl (MIT) for workbooks, and pywin32 (PSF) for the IPAM server service.

Happy troubleshooting!
