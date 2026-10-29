# What's New

The short version of CHANGELOG.md, shown in NOMAD under Help > What's New. Keep each version to a few lines: what a user will notice, not how it works. Add lines under Unreleased as you go; `python -m nomad.version bump <part>` dates them with CHANGELOG.md.

## [Unreleased]

## [1.35.0] - 2026-10-28

- **New:** links that are gone leave the map when Crawl from Here or Watch reads a device again. One the other end may still have is drawn faint until that end is read (right-click to remove it now).
- **New:** Monitor from a Router can ping from an interface you pick (Source Interface): a loopback, say, so the device's answers come back to an address it can reach.
- **New:** Traceroute tells loss that matters from a router just not answering pings (Path loss column, and the Note says where loss starts), the way pathping does.
- **New:** the Subnet Calculator's split subnets show each one's network address, wildcard mask and address count.
- **Changed:** Ctrl+W in a terminal goes to the device again (Where Is in nano); it no longer closes the session (it still does on SCP).
- **Fixed:** Traceroute's Stop works straight away; it no longer waits for slow router name lookups (DNS).
- **Fixed:** with no map open, right-click > Add Device Here shows the device on the map (it was drawn out of sight).
- **Fixed:** an Aruba access point found through a switch by its MAC and listed by its controller by name is one device on the map, not two (and no longer a serial-number conflict in Assets).
- **Fixed:** Interfaces > Apply Settings failed when a default gateway had to be removed or given a new metric, and putting the previous settings back after that failed too.

## [1.34.0] - 2026-10-27

- **New:** Aruba wireless controllers (ArubaOS 8) on the Network Map: the access points each one has (down ones in red), and its Wi-Fi clients on their APs. Overlay > Wireless shows which AP belongs to which controller.
- **New:** access points and wireless controllers are Assets too, with their serial numbers and software.
- **New:** MAC Finder finds Wi-Fi clients on their access point, asking the controller first.

## [1.33.0] - 2026-10-26

- **Fixed:** the tribe server could stop answering anyone (laptops: "actively refused") after one connection was cut off part way.
- **Fixed:** setting the tribe server up from a move file, or updating its service, on a computer where a NOMAD service was still running.

- **New:** Software targets on the Assets page: say which software each model should run, and see which devices are behind it (on the page, and on the map with Overlay > Software Targets).
- **New:** read a switch's, router's or firewall's hardware over SSH (show inventory) when its SNMP doesn't say: Assets > Read Details over SSH/WMI, or right-click it on the map > Tools > Read Hardware over SSH.
- **New:** the Map Watcher's log notes upgrades and swapped hardware (an RMA'd stack member, a power supply added, a transceiver taken out).

## [1.32.0] - 2026-10-26

- **New:** Assets (Network Management): every switch, stack member, router, firewall, access point, phone and server with its hostname, model, serial number and software version, brought in from each Network Map crawl by itself. Renames and upgrades go in its history; hardware swapped for other hardware (an RMA) is marked Replaced. Parts (modules, power supplies, fans, transceivers) too, if you want them. Shared with the tribe.
- **New:** Read Server/Phone Details asks Windows servers (WMI), Linux servers (SSH) and Cisco phones (their web page) for their serial numbers.
- **New:** assets keep MAC addresses: phones' and servers', and each switch's and stack member's base MAC. Paste any MAC into the Assets filter box, even one of a switch's ports', and it finds the hardware.
- **Better:** the Network Map shows each device's serial number, MAC and software version, and can read just the hardware again (right-click > Tools).
- **New:** Interfaces can give an adapter secondary IPs and more default gateways, each gateway with a metric.
- **Better:** Latency says what's wrong with a target that isn't an address or host name.
- **Better:** after the tribe server moves to another computer, the old one carries on in the tribe by itself.

## [1.31.1] - 2026-10-15

- **Better:** a Network Map device checked from a router says "Via R5" instead of a red "Unreachable" when it's up. Monitor from a Router is also in the Map menu now.
- **New:** IP Addresses > right-click a subnet > Add Windows Route opens the Routing Table with a route to it filled in; pick the gateway, typed or from the new ▾ list of the gateways this computer uses.
- **Better:** new routes on the Routing Table are persistent (survive a restart) unless you untick it.
- **Better:** Carry VLAN lists the switches NOMAD chose in the Through these switches table after Plan, ready to change by hand.

## [1.31.0] - 2026-10-14

- **New:** the Network Map can monitor devices this computer can't reach (behind a VRF, or with no route back) from a router that can: right-click > Tools > Monitor from a Router adds an IP SLA ping on the router, and Monitor reads its result over SNMP. Everyone monitoring the map uses the same probes.
- **New:** the Network Map shows tunnels (GRE, IPsec VTI, DMVPN) between routers, found by the crawl over SNMP: dashed lines, green up, amber not encrypted, red down. With Monitor on, they stay up to date and the Monitor log says when one goes down or comes back. Untick Show Tunnels to hide them; Overlay > VPN Tunnels shows just them.
- **New:** VPNs can build just one side: tick one router (or only spokes, or only a hub) and type the far end's address. NOMAD sends only to your router and shows the far end's lines to copy.
- **New:** VPN templates: New VPN > Template makes any kind of VPN with no routers, each side's lines with placeholders such as `<SPOKE-WAN-IP>` to fill in, and a legend saying what each one is.
- **New:** NOMAD starts about 3.5 seconds faster, shows a splash saying what it's loading as soon as it's opened, and opening it again brings the open one to the front instead of starting another.
- **New:** File > Always Start as Administrator: NOMAD asks for administrator rights as it starts, instead of starting twice. Hold Shift while it starts to start without them for once.
- **Fixed:** VPNs reads IKEv2 keys written as `pre-shared-key local` and `remote` (the word "local" was taken as part of the key, and the remote key was missed), and keeps each router's keys when you edit.
- **Fixed:** VPNs no longer treats every Tunnel1 as one VPN: tunnels are paired by their addresses and DMVPN routers by the hub they register with. Checks say where a router's settings, as read, differ from the others'.

## [1.30.0] - 2026-10-14

- **New:** VPNs builds and edits VPNs between Cisco routers: IPsec VTI, GRE over IPsec, GRE, crypto maps and DMVPN (phases 1-3, one or two hubs), with keys or certificates (it can set up a CA on one of the routers). It writes every router's side, checks the design, sends it with a revert timer and keeps it only once the VPN works from each end. Status says why a VPN is down. On the map: Build VPN Between, and a VPN Tunnels overlay.
- **New:** tools you used lately sit on the favorites rail below your favorites, like the Windows taskbar. Right-click one to pin it, or drag it up among the favorites.

## [1.29.0] - 2026-10-13

- **New:** the ACLs page is now ACLs & Route Maps: it reads, edits and tests prefix lists and route maps, puts them on BGP neighbors, redistributions, policy routing and distribute lists, and sends the changes entry by entry with the revert timer. After a change to a BGP neighbor's policy, it offers a soft clear.

## [1.28.0] - 2026-10-12

- **New:** ACLs reads, builds and edits ACLs on Cisco IOS / IOS-XE devices (IPv4 and IPv6, object groups, time ranges), finds rules that never match, tests packets against them, and checks a change won't lock you out. Changes go rule by rule with a revert timer, confirmed only once NOMAD can still log in. A library keeps ACLs to put on other devices.
- **New:** Carry VLAN sends over SSH too (Send All over SSH, Undo Sent over SSH), and numbers the route you pick on the map.
- **New:** in the Packet Capture viewer, right-click a packet > Add to Filter (or Exclude from Filter, Show Only This).

## [1.27.1] - 2026-10-11

- **Changed:** Port Mirroring works with routers as well as switches, and says so; a router's ports can be mirrored from the map too. Copies still go to a switch port (or an address).
- **Fixed:** Port Mirroring sends the right line for a service instance (source service instance N ...), and warns that some routers copy nothing from one.
- **Fixed:** a terminal whose connection closed no longer shows the device's prompt again after the note.

## [1.27.0] - 2026-10-11

- **New:** Help > What's New lists what each version added and fixed.
- **New:** TFTP: Cisco TFTP Tips shows how to make switches copy faster, with a bigger block size or SCP.
- **New:** Port Mirroring sets up SPAN, RSPAN or ERSPAN on Cisco switches in a click (from the page or the map's right-click menus), checks the ports first, and takes it away again; the switches can take it away themselves after a while.
- **New:** Packet Capture can unwrap ERSPAN sent to this PC into an ordinary capture.
- **New:** Packet Capture has a viewer: Wireshark-style filters, each packet decoded, conversations and top talkers, problems found (resends, DNS and DHCP failures, duplicate IPs, spanning tree changes and more) and Follow Stream. It opens any pcap/pcapng file too.
- **New:** Packet Capture takes SPAN copies on a wired adapter (promiscuous mode, no Npcap needed).
- **New:** Packet Capture shows packets live while capturing, with the filter, summaries and problems kept up to date.

## [1.26.0] - 2026-10-10

- **New:** MAC Finder can ask switches over SSH when SNMP isn't available, following a MAC through switches the map doesn't have. A Switches Asked tab shows each switch that was asked and how.
- **New:** quick SSH and RDP connections with no user name ask which saved credential to use.
- **Fixed:** saving files no longer fails now and then with "Access is denied" while the virus scanner is checking them. Fixed a possible cause of rare crashes from menus.

## [1.25.1] - 2026-10-10

- **New:** Network Map: Add Link opens filled in for two selected devices, and one device can be linked to all the others selected.
- **Changed:** Yes (or OK) is the default answer in yes/no questions, so Enter answers Yes.
- **Fixed:** finishing a link drawn by hand could miss the device clicked.

## [1.25.0] - 2026-10-09

- **New:** Network Map overlays: what fails if a device or link goes down, single points of failure, trunk problems, link speed, utilization, spanning tree, and color by model, software, site and more.
- **New:** move the tribe server to another computer; laptops and the Map Watcher follow it there by themselves.
- **New:** IP Addresses has an On Map column showing where the open map has each address.
- **New:** SNMP Config can build a switch's configuration from a map's saved SNMP credentials.
- **Changed:** right-click menus are shorter, with entries grouped under Connect, Tools, Show In, Layout and more. Connecting to and disconnecting from the tribe show each step, and changes not yet sent are sent before disconnecting.
- **Fixed:** Esc on the Network Map works again.

## [1.24.2] - 2026-10-08

- **New:** triple-click in a terminal selects and copies the whole line, as in PuTTY.

## [1.24.1] - 2026-10-08

- **New:** Carry VLAN draws its planned route on the map.

## [1.24.0] - 2026-10-08

- **New:** Carry VLAN: get a VLAN to a switch over the map's links, with each switch's configuration and undo, spanning tree checks, sending to sessions and verifying afterward.
- **Fixed:** lab switches and routers that don't name their model are no longer mixed up.

## [1.23.0] - 2026-10-08

- **New:** Ansible Inventory page: build a YAML or INI inventory from the map's devices and your saved SSH sessions, grouped by site, kind and OS. No passwords are written to it.

## [1.22.0] - 2026-10-07

- **New:** saved credentials: save a login once under a name and use it for any SSH or Remote Desktop session. Changing it updates every session using it.
- **Fixed:** changes to a tribe map's SNMP credentials now reach everyone in the tribe.

## [1.21.1] - 2026-10-07

- **Fixed:** Windows computers announcing themselves over LLDP are shown as hosts, not network devices.

## [1.21.0] - 2026-10-06

- **New:** MAC Finder page: find the switch and port a device is plugged into from its MAC, IP address or name, with history of where each MAC has been.
- **New:** Add Device to Map, Create Terminal Session and Create RDP Session on any address's right-click menu.
- **New:** Ctrl+S logs a terminal session and Ctrl+Shift+S saves the running config.
- **New:** a Key window explains the Network Map's colors, lines and marks.

## [1.20.0] - 2026-10-05

- **New:** Remote Desktop page with saved sessions, encrypted logins, folders and quick connect.
- **New:** Save Config and Log Session buttons on each terminal session.
- **New:** a searchable Keyboard Guide (F1) and many new shortcuts.

## [1.19.0] - 2026-10-05

- **New:** export SSH sessions to SecureCRT, with their saved passwords.
- **New:** password-protected backups of all terminal sessions, credentials and settings, to move them to another computer.
- **New:** right-click any IP address, almost anywhere, to connect to it, test it or find it in IPAM or on the map.
- **Fixed:** workbook import, map discovery and VLAN highlighting fixes.

## [1.18.0] - 2026-10-05

- **New:** a slim favorites rail and a searchable tool drawer (Ctrl+K) replace the sidebar, with an icon for every tool.
- **Changed:** tools are grouped by task.

## [1.17.0] - 2026-10-05

- **New:** move a subnet to another IPAM network.
- **New:** subnet roles (VLAN, point-to-point, loopbacks, tunnel and more), worked out from the map.
- **New:** IP Addresses, VLANs, Subnet Placement and the Network Map work as one: choosing a network on one chooses it on the others, with links between them.
- **New:** Record in IPAM adds the map's addresses that IPAM doesn't have yet.

## [1.16.0] - 2026-10-04

- **New:** VLANs page: each domain's VLANs, names and subnets, shared with the tribe, with VLANs brought in from a network map.
- **New:** Subnet Placement page: where each subnet is planned to be and where the map finds it, with checks and a guided way to move a subnet.
- **New:** the Network Map reads VLANs, VRFs and routing tables, and can highlight a VLAN.
- **Changed:** every table's columns can be resized.

## [1.15.0] - 2026-10-03

- **New:** Network Map: a compact one-row top bar, spacing settings, more arrangements, New Map, and the last map reopens when NOMAD starts.
- **Changed:** Re-arrange crosses fewer links.
- **Fixed:** a crash when closing a page while it was still working in the background.

## [1.14.0] - 2026-10-03

- **New:** SNMP Config page: build the configuration that sets a Cisco switch up for NOMAD and send it to a session.
- **New:** SNMPv3 for the Network Map, the Map Watcher service and SNMP Walk.
- **Fixed:** several Network Map fixes for duplicate devices, devices with the same name and management addresses.

## [1.13.1] - 2026-10-02

- **New:** join or leave the tribe from the Network Map page.
- **Fixed:** the tribe server itself can use tribe maps.

## [1.13.0] - 2026-10-02

- **New:** Network Map watching: new devices and hosts are found and added by themselves, and switches can report changes by syslog and traps.
- **New:** tribe maps: share a network map with the tribe, merged as people change it, offline included.
- **New:** Map Watcher Windows service watches tribe maps with nobody signed in.
- **New:** correct or delete devices the crawl found.

## [1.12.0] - 2026-10-01

- **New:** add devices and draw links by hand on the Network Map.
- **New:** sessions opened from the map, IP Addresses or Sweep use the host's saved session.
- **New:** rooms inside buildings, and Undo / Redo on the map.

## [1.11.0] - 2026-10-01

- **New:** Network Map sites and buildings, more arrangements, and align and distribute.
- **Changed:** faster crawls, and Crawl from Here adds to the open map.

## [1.10.1] - 2026-09-30

- **New:** Network Map: a Logical (L3) view, comparing with an earlier map, monitoring, hosts added by hand, column filters, and the map drawn live while it crawls.

## [1.10.0] - 2026-09-30

- **New:** Network Map page: crawl the network over SNMP from a core switch and draw its devices, links and hosts. Export to PNG, SVG, draw.io and CSV.

## [1.9.1] - 2026-09-30

- **New:** Ctrl+1 to Ctrl+9 press terminal command buttons, and buttons can be rearranged.
- **Fixed:** the Buttons bar was far too tall, and terminal text jumped when the window got shorter.

## [1.9.0] - 2026-09-29

- **New:** IP Addresses: Check Data, Compare with Workbook, Export to Workbook, Find Free Blocks, editing many at once and narrower searches.
- **New:** Interfaces can take a free address from IPAM.
- **Changed:** sweep results are kept and shared as Last Seen.

## [1.8.2] - 2026-09-29

- **Fixed:** selecting a loopback subnet on the IP Addresses page showed an error.

## [1.8.1] - 2026-09-29

- **New:** loopback subnets in IPAM.
- **Changed:** disabling an adapter asks whether to keep it disabled, and turns it back on if nobody answers.

## [1.8.0] - 2026-09-29

- **New:** Terminal: command buttons, Send to All, tiled sessions, keyword highlighting, line delay, reconnect automatically and anti-idle.
- **New:** route lookup on the Routing Table page.
- **Fixed:** adding a persistent route failed.

## [1.7.0] - 2026-09-29

- **New:** SCP: work as root (sudo) and change file owners.
- **Fixed:** selecting text in a busy terminal could fail.

## [1.6.2] - 2026-09-29

- **New:** Upload and Download buttons on the SCP page, and a choice of SFTP or SCP per session.
- **Fixed:** many SCP fixes: cancelling straight away, stalled transfers shown, slow drives no longer freeze NOMAD.

## [1.6.1] - 2026-09-28

- **New:** open SCP wherever SSH is offered.

## [1.6.0] - 2026-09-28

- **New:** SCP page: a WinSCP-style file manager with a transfer queue, resume, editing remote files and Synchronize.
- **New:** import sessions from SecureCRT, drag sessions into folders, and Recent connections.

## [1.5.0] - 2026-09-28

- **New:** IPAM history: who changed what and when, and the network as it was at any moment.
- **Changed:** Sweep Subnet runs right on the IP Addresses page.

## [1.4.0] - 2026-09-28

- **New:** change tribe networks offline; changes are sent when the server is back.
- **New:** Sweep and ARP compare what answers with IPAM.

## [1.3.0] - 2026-09-28

- **New:** IPAM server: the tribe's shared IPAM, run as a Windows service, with offline copies on each laptop.

## [1.2.0] - 2026-09-27

- **New:** IP Addresses (IPAM), Terminal, SNMP, DHCP Servers, Packet Capture, TFTP, Syslog and Network Reset pages.
- **Changed:** a sidebar of pages, and Focus Mode (F11).

## [1.0.1] - 2026-09-24

- **New:** Ports, ARP, Connections, Switch Port, Services and Utilities pages, the Diagnostics Report and Text Size.
- **Changed:** Traceroute works like MTR, and Sweep shows MACs, vendors and names.

## [1.0.0] - 2026-09-24

- First release as NOMAD (formerly NIC Manager).
