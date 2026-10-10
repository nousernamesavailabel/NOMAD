# Changelog

Notable changes to NOMAD. Versions follow [semantic versioning](https://semver.org/): MAJOR for big or breaking changes, MINOR for new features, PATCH for fixes.

Add changes under Unreleased as you go; `python -m nomad.version bump <part>` dates them when you release.

## [Unreleased]

## [1.25.0] - 2026-10-09

### Added

- **Tribe server:** move it to another computer. **Tools > Tribe Management > Move to Another Computer...** on the old server saves a password-protected move file with everything it keeps (networks and history, tribe maps and their SNMP credentials, certificate and tribe key); **Set Up from Move File...** on the new computer installs the server from it. The old server then points laptops and the Map Watcher service to the new address, and they switch over by themselves, keeping their copies and pending changes (no new key file needed). **Undo Move...** calls it off.
- **IP Addresses:** an **On Map** column says where the open Network Map has each address: the device and port with it (such as "sw1 Vlan50"), or the switch port a host with it is seen on ("Host on sw1 Gi1/0/5"). Recorded addresses the map doesn't have say **Not on the map**, and addresses on the map that IPAM has no record of are shown in amber (listed even with Hide free addresses ticked). The column shows only while a map of the network is open, updates as the map changes (watching, mapping again), and is on screen only: exports are unchanged.

- **Network Map overlays:** an **Overlay** button on the map bar (classic and compact) shows one thing at a time over the physical view, with a bar saying what it found and what each color means (Esc or Show All puts the map back; the key explains them too):
  - **Highlight VLAN**, **Highlight VRF** (devices and links with ports in it, amber where only one end is) and **Highlight Subnet** (its gateways, the switches and links carrying its VLAN, devices managed from it, switches with hosts in it; or type any subnet or address).
  - **What If It Fails?** (right-click a device or a link, or a port-channel's line for all its links): what would be cut off from the rest of the network, with the hosts that lose it, measured from the device put at the top (else the one the map started from). **Single Points of Failure** marks every device and connection that's the only way to part of the network.
  - **Trunk and Port Problems**: links whose ends are set up differently (trunk and access, native VLANs, VLANs allowed at one end) and ports in VLANs their switch doesn't have, with what's wrong in the tooltip.
  - **Link Speed and Status**: each link's speed as color and thickness, and links down at an end, whose ends' speeds differ, or with a duplex mismatch or half duplex. Ports' status, speed and duplex are now read when mapping and by Read VLANs Again, and saved with the map.
  - **Utilization and Errors**: while Monitor is on, each poll also reads the traffic and error counters of the linked ports on switches, routers and firewalls that answer SNMP; links are green, amber (over 30% busy or discarding) or red (over 70%, or errors), with the rates in the tooltip. Not saved with the map.
  - **Spanning Tree > VLAN N**: reads the VLAN's spanning tree from its switches and shows the root bridge, the links blocking (the redundant ones STP keeps shut) and those forwarding.
  - **Color By** kind, model, software version (from the description), site, VTP domain or mode, spanning tree mode, or how each device was found, with a legend of each value and how many have it.
  - A device's right-click menu has **Overlay** (What If It Fails?, its VRFs and subnets); a link's has **What If It Fails?**.

- **SNMP Config:** build the switch configuration from a Network Map's saved SNMP credentials. **Use the Map's Credentials...** on the page (or **Generate SNMP Config** in the map's **SNMP Credentials...** dialog and on its Watch tab, which was Switch SNMP Config...) sets the switches up with all of the map's community strings and SNMPv3 users, ticking which to include: public and private, and those for particular subnets, are left out unless ticked. Traps go with the first community string or user; the others are allowed to read too, and SNMPv3 users with different security levels each get their group.

### Changed

- **Right-click menus** are shorter: an address's sessions and browsing (SSH, SCP, Telnet, RDP, PuTTY, http/https) are under **Connect**, and Ping, Traceroute, Monitor Latency, Scan Ports, SNMP Details and Capture Traffic under **Tools**, on the Network Map, IP Addresses, Sweep and anywhere else they're offered. A map device's menu groups the rest too: **Show In** (the other views and tabs), **Layout** (arranging, spacing and aligning the selection), **Edit** (drawing links, adding, correcting and deleting devices), **VLANs** (Highlight VLAN, Carry a VLAN) and **IPAM**; it went from over 40 entries to about 15. Entries that appeared twice (Copy Address and Copy IP Address, Show on Map, and Show in IPAM on the IP Addresses page) are shown once.
- Spelling is American throughout (color, utilization, gray, neighbor...).
- **Connecting to the tribe** shows each step as it happens, from Tools > Tribe Management, the IP Addresses page and the Network Map page alike: reading the key file, reaching the tribe server (each address tried in turn, its certificate checked), checking the key with it, saving it, and the first download of the tribe's networks and maps, with a moving bar, a spinner and the seconds a slow step has taken. A key the server refuses, or a server that isn't the one in the key file, is no longer saved; a server that can't be reached right now can still be joined with **Save Key Anyway** (NOMAD connects when it can be reached). **Continue in Background** closes the window while the download carries on.
- **Disconnecting from the tribe** (Tools > Tribe Management) is shown step by step the same way, in one window that asks first: changes made offline that haven't reached the tribe server are sent before anything is removed (if they can't be, it says why and offers **Disconnect Anyway** or Cancel, where they used to be lost), then syncing stops, the key is forgotten, the copies of the tribe's networks and maps are removed (with how many) and the pages go back to this computer's own. NOMAD no longer freezes for a few seconds while the map sync's last request to the server ends.

### Fixed

- **IP Addresses:** a sync still running when another tribe's key file was connected could put the old tribe's data in the new tribe's copy.
- **Esc** on the Network Map does Show All again (stopping a VLAN highlight or overlay), and closes the Network Reset find bar: the tool drawer's own Esc shortcut made both ambiguous, so neither fired. Esc still closes the drawer while it's open.

## [1.24.2] - 2026-10-08

### Added

- **Terminal:** triple-click (or a click straight after a double-click) selects and copies the whole line, as in PuTTY; double-click still copies a word.

## [1.24.1] - 2026-10-08

### Added

- **Carry VLAN:** the route planned is drawn on the map while its window is open: thick green dashed on links the VLAN will be added to, thick green on links of the route that already carry it (or do once sent and verified), thick amber dashed on redundant links ticked to carry it too, amber dotted on redundant links left as they are, and red dashed on a link of a route set by hand that can't carry it. A link's tooltip says what's changed there (such as "allowed vlan add 300 on sw1 Gi0/2"). The map's key explains each.

### Changed

- **Network Map:** rings round devices (Carry VLAN's route, Compare's added and changed devices, devices being read) are drawn solid and a little thicker. Carry VLAN's switches stay at full strength while the VLAN is highlighted, even those that don't have it yet.

## [1.24.0] - 2026-10-08

### Added

- **Carry VLAN** (Network Map): get a VLAN to a switch over the map's links on Cisco IOS / IOS-XE switches, with the configuration for each switch on the way. Right-click a switch or a port's hosts > **Carry a VLAN Here...**, two selected devices > **Carry a VLAN Between These...**, or a VLAN on the VLANs tab > **Carry It to a Switch...**.
  - **The way:** from the nearest switch already carrying the VLAN (its gateway's part first), or from A, over the links needing the fewest changes. Or set the route by hand, switch by switch: **Add Switch...**, **Pick on Map**, the link to use where there are several, **Fill In Between** for gaps, and **Edit This Route** to start from the way NOMAD chose. Routers and firewalls are only ever where it starts; access ports in another VLAN are never crossed or turned into trunks.
  - **Plan** reads the switches involved again first, then lists each switch's changes: the VLAN created where it's missing (on a VTP client, on its domain's VTP server, sent first), `switchport trunk allowed vlan add` on trunk ends that don't allow it (never without `add`), on port-channels rather than their members, and B's edge ports you tick. Each switch's undo is made too.
  - **Spanning tree:** the mode is read on every crawl and Read VLANs Again, and for the VLAN being carried, which ports forward or block (Rapid-PVST+ and MST port roles, PVST+ port states). Redundant links that would close a loop are listed with what spanning tree does there and changed only when ticked, last. On MST, ports blocking the VLAN's instance are avoided, or warned about on a route set by hand.
  - **Gateway check:** says whether B will reach the VLAN's gateway on the map (never sets one up).
  - **Send** each switch's step (or its undo) to a terminal session, or open an SSH session to the switch (its saved session if there is one) and send once it's at the enable prompt; **Copy**, **Export All...**, and `write memory` only if ticked. **Verify** reads the switches again and marks each done, or says what's still missing.

### Changed

- **Network Map:** crawls and Read VLANs Again now also note each switch's port-channel members and spanning tree mode (port-channels are read even when hosts aren't collected).

### Fixed

- **Network Map:** switches that don't name their model (such as IOL and vIOS lab images) are no longer taken for routers, or routers for switches, depending on which neighbor's CDP the crawl used ("Router Switch" for both). The image names say which is which, and a Cisco device whose own tables have access or trunk ports is a switch unless its model is a router's. **Read VLANs Again** corrects maps made before (a kind set by hand is kept).

## [1.23.0] - 2026-10-08

### Added

- **Ansible Inventory** (Network Management): make an Ansible inventory, in YAML or INI, from the Network Map's devices and your saved SSH sessions, ready to copy or save for a control node.
  - A saved session of a device on the map joins it (matched by address or name), giving its user name and port. Sessions of devices not on the map are listed on their own.
  - Each device gets the `ansible_network_os` and connection its make and model call for, worked out from what the map read of it: Cisco IOS / IOS XE, NX-OS, IOS XR and ASA, Palo Alto PAN-OS, Juniper Junos, Arista EOS and Fortinet FortiOS. Where the map can't tell, or gets it wrong, select the devices and choose it with **Set Ansible OS** (also on the right-click menu). Linux / Unix servers can be chosen too.
  - Groups by the map's sites, buildings and rooms (nested), kind (switches, routers, firewalls…), Ansible OS (each OS group holds its variables) and session folders (nested). Each grouping can be turned off.
  - Tick the devices to include; **Network Devices**, **All Shown** and **None Shown** tick whatever the filter shows. Switches, routers, firewalls and saved sessions are ticked to start with.
  - Options: `ansible_user` for everything (saved credentials' user names are offered), sessions' own user names, short names without the domain, enable mode (`ansible_become`) for IOS, ASA and EOS, and `nomad_*` variables (kind, model, location, folder) for playbooks to use.
  - The file starts with the `ansible-galaxy collection install` line for the collections it needs. Passwords are never written to it: run with `--ask-pass`, or keep them in ansible-vault. Names Ansible would reject are made safe and unique, and anything worth knowing (a device with no address, an unknown OS, a renamed group) is listed under the inventory.

## [1.22.0] - 2026-10-07

### Added

- **Saved credentials:** save a user name and password (or SSH key) once under a name, such as TACACS or Domain Admin, and choose it in SSH (and so SCP) and Remote Desktop sessions instead of typing the login again. They're encrypted like saved session passwords, including with the master password, and travel in Export/Import NOMAD Terminal backups.
  - **Credential:** at the top of the session editor's SSH section and above Username in the RDP editor. Choosing one fills in its user name and grays out the login fields; **Typed for this session** goes back to the session's own login. Remote Desktop only offers credentials with a password.
  - Mark one credential **Use for New Sessions** (the first one you make is marked automatically) and every new SSH or RDP session starts with it chosen, including the ones from **Create Terminal Session…** / **Create RDP Session…**. Sessions that already have a user name of their own aren't changed.
  - Changing a credential (such as after a password change) updates every session using it. Saving a new password when a login with a credential fails saves it in the credential, for all of its sessions. Deleting a credential leaves its sessions with its user name and password as their own.
  - **Tools > Saved Credentials…** adds, edits and deletes credentials from any page; it's also on the session list's New button arrow menu and the master password button's menu. Right-click a session for **Credential**, or select several for **Use Credential**, to switch existing sessions over in one go. A session's tooltip names its credential.

### Changed

- **Network Map:** **Credentials…** (on the crawl row and in the Map menu) is now **SNMP Credentials…**, so it isn't mistaken for the saved login credentials used by Terminal and Remote Desktop sessions.

### Fixed

- **Tribe maps:** a tribe map's SNMP credentials now reach everyone in the tribe, so nobody has to type them in. They were already kept encrypted on the tribe server, but each computer fetched them only the first time it opened the map, so later changes never reached anyone else.
  - Each computer, and the Map Watcher service, now fetches them again whenever they change on the server. A tribe map that's open switches to the new credentials at once and says so.
  - Credentials changed while the server can't be reached are used on this computer straight away. They're sent with the map's other waiting changes once the server is back.
  - **SNMP Credentials…** says when the credentials belong to a tribe map and are shared. Opening a tribe map that has no shared credentials yet says so too.
  - The first time it syncs after updating, each computer fetches the credentials of every tribe map again.

## [1.21.1] - 2026-10-07

### Fixed

- **Network Map:** computers that announce themselves over LLDP without any capabilities, such as Windows' built-in LLDP agent, no longer appear on the map as network devices. An LLDP neighbor with no capabilities is treated as a host when its port ID is a MAC address or its description names a desktop or server operating system (Windows, macOS, Linux). It is shown as a named host on its switch port.

## [1.21.0] - 2026-10-06

### Added

- **MAC Finder** page (Discover) shows which switch and port a device is plugged into. Type its MAC address in any format (`aa:bb:cc:dd:ee:ff`, `aabb.ccdd.eeff`, `AA-BB-CC-DD-EE-FF`, `aabbcc-ddeeff`, spaces, no separators, dropped leading zeros like `0:1a:2b:...`), part of one (3 or more hex digits), an IP address or a name. Separate several searches with commas, or switch on **List** to paste or load one per line (rows from a spreadsheet or CSV use their first MAC address).
  - **Find** (Enter) searches the open Network Map's last crawl at once, without touching the network.
  - **Locate Now** (Shift+Enter) asks the map's switches over SNMP, using the map's credentials. A whole MAC is asked for directly (a GET per VLAN rather than reading whole MAC tables), first at the switch the map last had it on. It is then followed along the uplink it was learned on until it reaches an edge port; if that fails, every switch is asked.
  - Part of a MAC, or a long list, reads every switch's MAC table once instead. An IP address is turned into a MAC from this computer's ARP (on its own subnets) or the ARP table of the router holding its subnet; a name is looked up in DNS first.
  - Each result shows the switch, port and port description, VLAN, access or trunk mode, IP address, name and vendor. Below it are the path from the map's top switch to the port and the uplinks the MAC was also learned on, with a note when the port is behind an access point or phone, or has more than 8 MACs (likely an unmanaged switch, hub or VM host).
  - **Where it's been:** each map crawl and each Locate Now is recorded in a local history, so every MAC shows the switch ports it has been on and when. A MAC missing from the map shows where it was last seen. The history can be cleared for one MAC or all.
  - The right-click menu offers Locate Now, Show on Network Map and the switch's session, ping and browse actions. Copy Results and Export CSV are also available.
- **Ctrl+S** starts (or stops) a terminal session log and **Ctrl+Shift+S** saves the running config (or cancels one being saved), the same as the **Log Session…** and **Save Config…** buttons below the session. They work anywhere in the session; Ctrl+S is no longer sent to the device as XOFF. Holding Ctrl shows **S** over Log Session and **Shift+S** over Save Config (grayed while the session isn't connected), alongside the command buttons' numbers and even while the Buttons bar is hidden.
- **Add Device to Map…** on every address's right-click menu (tables, logs, labels, map items) and an **Add to Map...** button for Sweep's selected host. Choose the map: the one open on the Network Map page, a saved map, a tribe map, a new map or another map file; then name the device, set its kind and optionally link it to a device on that map. Maps that aren't open are updated without switching to them, unless **Show it on the Network Map page afterwards** is ticked. Addresses already on the chosen map are reported instead of added twice.
- **Create Terminal Session…** and **Create RDP Session…** on the right-click menu of any address that doesn't have a saved session of that kind yet (Sweep, Network Map, IPAM, and addresses in tables, logs and labels on every page): the Terminal or Remote Desktop page's New Session dialog opens with the address filled in, named after the device where the page knows its name and in the folder a quick connection would suggest. A terminal session starts as SSH (choose Telnet in the dialog if you need it), and SSH, SCP and Telnet share these saved sessions, so one entry covers all three. Once it's saved, the menu offers **Open … Session (its name)** instead.
- **Key** in the Network Map's Map menu (and on the classic bar): a window explaining the map's device colors and tags, outlines, monitoring and Watch marks, Compare rings, link line styles, VLAN highlighting, site/building/room boxes, host port boxes and the logical view, each drawn as the map draws it.

### Changed

- NOMAD's own messages in a terminal (such as "Logging to …") redraw the prompt line they interrupted, so typing and Save Config continue from the device's prompt.

## [1.20.0] - 2026-10-05

### Added

- RDP session manager under Connect & Transfer, with saved addresses and encrypted credentials, folders, quick
  connect, recent launches, display and resource settings, and host context actions. Launches Windows Remote Desktop
  Connection in its own windows; encrypted NOMAD backups include RDP sessions and preferences.
- RDP folders are independent of Terminal/SCP folders, including rename, move and delete operations.
- RDP uses a full-width session list with connection settings in columns, a compact action toolbar, search and
  quick launch, and a selected-session summary below the list.
- **Save Config…** in each terminal session captures a device's full running configuration to a local file, independently of scrollback. Includes Cisco, Arista and Juniper profiles and custom commands; failed or cancelled captures preserve the destination.
- **Log Session…**, next to Save Config…, asks where to save a plain-text log and changes to **Stop Logging** while recording. Saved-session automatic logging remains available.
- A searchable **Keyboard Guide** opens with F1, with a companion guide in `docs/keyboard-shortcuts.md`. **Shift+Enter / Shift+Esc** start and stop supported tools, **Alt+A** focuses the adapter picker, and **Ctrl+F** focuses each page's input, search or filter.
- Terminal command buttons show numbered hotkey hints while Ctrl is held. Session shortcuts create sessions and folders, switch sessions, close sessions with confirmation, and move sessions into or out of pop-out windows.

### Changed

- **Ctrl+W** closes the active Terminal/SCP session with confirmation. **Alt+Left / Alt+Right** switch sessions; SCP folder-back uses **Alt+Up**. **Ctrl+L** focuses an SCP file pane's path and retains its shell behavior in Terminal.
- Interface, Network Reset, DHCP Servers and Switch Port pages provide focused search or filtering for their main content.

## [1.19.0] - 2026-10-05

### Added

- **Export SSH Sessions to SecureCRT** (File menu): XML with session folders, hosts, ports, usernames, notes, key paths and saved SSH passwords. Passwords use SecureCRT's salted encryption format and the destination's configuration passphrase, entered and confirmed during export. NOMAD unlocks its saved credentials when needed; unreadable credentials stop the export without replacing an existing file. Private key files and saved key passphrases are excluded. Import into SecureCRT was verified manually.
- **Export / Import NOMAD Terminal Settings and Sessions** (File menu): password-protected portable backups of all saved sessions and credentials, empty folders, recent connections, command buttons, highlighting, Terminal/SCP preferences and text scale. Import validates the backup before replacement confirmation, protects credentials using the destination's Windows account and current NOMAD master password, and rolls back failed saves. Live connections stay open; private keys and logs remain external files.
- **IP address context actions** across tables, text, labels and map items: open terminal or file sessions, browse, diagnose, show in IPAM or on the map, and copy the address. Existing context menus keep their own actions; the clicked cell or text line supplies the target. IPv6 web addresses are formatted correctly.
- **Subnet moves without a VLAN:** choose a routed or point-to-point destination and its target device. Completing the move removes the old VLAN link without creating a destination VLAN link; move checks distinguish routed locations from VLAN interfaces.

### Changed

- The tool drawer uses one scrolling list for Favorites, Recent and tool categories. Favorites and Recent collapse independently. Opening the drawer focuses search, and Enter activates the first visible tool in drawer order.
- VLAN tables and check findings have context menus for their existing actions. Escape clears VLAN highlighting on the map, or cancels a drawing in progress.

### Fixed

- Workbook import keeps subnets found in only Summary or Detailed Info when a bulk source preference is chosen. Those subnets default to import from the available section; conflicting entries still require a choice, and individual subnets can be skipped.
- Network discovery tries all LLDP management addresses before marking a device unreachable. A failed address no longer overrides a ping reply or another pending address; device-read failures still check ping, status counters follow the final outcome, and preview address lists are copied independently.
- VLAN highlighting respects domain boundaries and requires a VLAN to exist on a switch before treating a trunk's allowed list as carrying it. Unset VTP-domain placeholders are normalized consistently.

## [1.18.0] - 2026-10-05

### Added

- **Favorites rail:** one-click access to pinned tools in a narrow strip beside the workspace. Right-click a tool in the drawer to pin or unpin it, or right-click its rail icon to unpin it. Drag rail icons to reorder them; favorites and their order are saved between launches.
- **Tools drawer:** search all tools with **Ctrl+K**, including terms such as "bandwidth" for iperf and "file transfer" for SCP and TFTP. Favorites and recent tools appear above the full list; category headings can be collapsed. Selecting a tool, clicking outside the drawer or pressing Escape closes the temporary drawer.
- **Keep drawer open** retains full navigation beside the workspace and is saved between launches. Toggle it in the drawer, under **View > Keep Tool Drawer Open**, or with **Ctrl+B**.
- Function-specific outline icons for all 30 tools, shared by the rail and drawer, with the selected tool highlighted in green and full tool names available on hover.

### Changed

- The compact rail replaces the full sidebar by default, giving tools more working space. The current tool's name appears above its page. Ctrl+Tab / Ctrl+Shift+Tab still cycle through all pages, and F11 still hides navigation for focus mode.
- Tools are grouped by task: **This Computer**, **Connect & Transfer**, **Discover**, **Diagnostics** (Connectivity & Performance, and DNS & Web), **Network Management**, **Capture & Logs**, and **Utilities**. Network Map, IP Addresses, VLANs, Subnet Placement and SNMP Config are together under Network Management; SNMP Walk is under Discover, and TFTP and Wake-on-LAN are under Connect & Transfer.

## [1.17.0] - 2026-10-05

### Added

- **Move to Another Network** (IP Addresses: right-click a subnet, or **Move...** under the subnet list): moves a subnet and its recorded addresses to another IPAM network, taking the subnets inside it along if you tick so, with its role and Subnet Placement settings; its VLAN links (the old network's domains') are dropped, and a VLAN of the new network can be linked instead (the same number is offered). It's refused while the new network has something in the way (an overlapping subnet, or an address recorded in it) or the subnet is being moved on Subnet Placement. Tribe networks move on the server, in one change (the server needs this version: API level 10); a subnet in this computer's own networks can move into a tribe network (it's shared from then on), but not the other way.
- **Add Subnet** (IP Addresses): what it's for (its role) and a VLAN of the network's domains to link it to (the next free number, or one there is), set as it's added.
- Deleting a subnet also removes its VLAN links and its role and placement settings (it says which first), and is refused while the subnet is being moved on Subnet Placement. Subnet Placement warns of VLAN links or settings left for a subnet that's no longer in IPAM (deleted, or moved by an older NOMAD). Deleting a VLAN says when a subnet move uses it.
- **Subnet roles** (Subnet Placement): what each subnet is for: VLAN, point-to-point, loopbacks, tunnel, routed port, container (a block holding other subnets) or other (not known yet, so nothing is expected of it). Worked out from the network map (tunnel and loopback interfaces, including Palo Alto's tunnel.N and loopback.N; SVIs and subinterfaces; a router's or firewall's port plugged into a switch's access VLAN; the two ends of a link), then IPAM (a loopback subnet, a /32, a /30 or /31, subnets inside it, a name such as Vlan 6) and the VLANs page. Shown in a new **Role** column with a **Role** filter, and in each subnet's details. **Role and Scope** (the button was How to Treat It) can set it (Other included); it's shared with the tribe and kept beside the placements, never on the IPAM subnet.
- **The Manage pages and the map work as one:** choosing a network on IP Addresses, VLANs (a domain of it) or Subnet Placement chooses it on the others, and opening a map of a network chooses that network, including the map reopened when NOMAD starts (but the pages stay where they are while the map is redrawn, by watching say).
- Network Map: **IPAM Network...** (on the bar and the Map menu, which say the map's network once it has one: IPAM Network: TEST TRIBE...): which IPAM network the map is of, suggesting the one holding most of its subnets. Saved with the map, and shared with a tribe map (laptops still on 1.16 don't keep it when they change the map). The VLANs and Subnet Placement pages only check a network against a map of it; Subnet Placement says when the open map is of another network.
- Network Map: a bar says when the map isn't tied to an IPAM network (with IPAM Network...), or is of another network than the other pages are on: **Open** that network's map (a tribe map, or a recent map file, of it; or it says there's none yet) or go **Back to** the map's network. A tribe map no one has tied to a network asks which, once on each computer, when it's opened.
- VLANs page: for a network with no VLAN domain, it shows none (rather than another network's domain, which looked like this one's), with **New Domain for** the network.
- Network Map: **Record in IPAM...** (bar and Map menu; a device's right-click for its own addresses; the Hosts tab's right-click for the hosts chosen): the map's device and host addresses its IPAM network lacks (or has with another MAC), each with a suggested name (the device for its management address, "device port" for an interface, the host's name), to tick, rename and record. Nothing is written until Record Ticked; tribe networks take them offline too. Asks which IPAM network the map is of first, if nobody has said.
- Network Map: the compact bar's Map menu has everything the classic bar has: **Crawl** (shows the crawl row: start from, the adapter's gateway, Start and Stop), and **Credentials...** and **Scope...**, which were only on the crawl row (shown only while Crawl was on, once a map was open).
- Network Map: an **IPAM** column on the Hosts tab (in IPAM and its name, not in IPAM, or another MAC there); the logical view's subnets show their IPAM name and role, outlined orange or red for Subnet Placement's warnings and problems, and "not in IPAM" when the network lacks them; watching notes new hosts and subnets the network lacks in the Watch log.
- IP Addresses: the selected subnet's line says its role, the VLANs it's linked to, whether Subnet Placement finds anything wrong with it, and how many places the map has it in, each linking to that page. Right-click a subnet to show its VLANs, it in Subnet Placement or on the map, or an address to show the device that has it on the map. Nothing is written to IPAM: the exports are unchanged.
- VLANs page: each of a VLAN's subnets shows its role and placement, with links to IP Addresses, Subnet Placement and the map; right-click > Show Subnet in Subnet Placement. A map of another IPAM network isn't used for a domain's VLANs.
- Subnet Placement: links to IP Addresses, the subnet's VLANs and the map in each subnet's details; right-click shows its VLANs on the VLANs page.
- Network Map: right-click a subnet on the logical view to show it in IP Addresses, its VLANs, or Subnet Placement; a device to show its addresses in IP Addresses or its subnets in Subnet Placement; a port to show its VLANs on the VLANs page or its host's address in IP Addresses; a host (Hosts tab) to show its address in IP Addresses. The VLANs tab has **Show on VLANs Page**.
- Subnet Placement checks by role: one loopback address on two devices (a problem), a point-to-point subnet with more than two devices in it, a role set that doesn't fit the map (a tunnel set as point-to-point, say), a tunnel or loopback linked to a VLAN, and a VLAN's subnet (by its name, say) not linked to a VLAN when the network has VLAN domains.

### Changed

- Subnet Placement: a tunnel's ends (a DMVPN hub and its spokes) and a point-to-point link's two ends (a circuit the map has no link for) count as one place, so advertising them isn't "in several places". Router loopbacks (/32s on the map) inside IPAM's loopback subnet belong to it rather than being "not a subnet in this IPAM network". Only VLAN subnets are noted as not linked to a VLAN.
- Network Map and Subnet Placement: an interface address of 0.0.0.0 (mask 0), which pfSense lists beside an interface's real address, is left out. It was taken for a subnet holding everything, so every routed subnet was flagged as "inside 0.0.0.0/0, which is advertised from" the firewall.
- Network Map: an IOS XE router's bridge-domain interfaces (BDI10, or BD10 as its ifName gives them) are treated like SVIs: in the VLAN of their bridge-domain number (which is usually the VLAN's, so it's marked guessed, like a subinterface's), on the VLANs tab, the VLANs page and Subnet Placement.
- VLANs page: a VLAN's subnet list, and Link Subnets Named for VLANs, leave out subnets that aren't VLANs' (point-to-point links, loopbacks, tunnels, routed ports' subnets, containers); a tick box in the VLAN's window lists them too.
- The IP Addresses page's Export to Workbook and Export to CSV are checked against saved copies by the tests, so neither changes by accident.
- Roles need the IPAM server updated to this version (Tools > Tribe Management > Update Service; API level 9) before tribe roles can be set; until then the role choice is turned off. Laptops sync everything once after updating, to fetch roles. Laptops still on 1.16 keep working with the updated server (they don't see roles).

## [1.16.0] - 2026-10-04

### Added

- **Subnet Placement page** (Manage > Subnet Placement): for each subnet of an IPAM network, and each one a device on the open network map has an address in (per VRF), where it's planned to be (the VLANs it's linked to on the VLANs page), where the map finds it, and whether it's **advertised** (other devices have a route to it, from the map's routing tables) or **local**. Places that are one L2 segment count as one: SVIs on a VLAN trunked between switches (HSRP/VRRP), the two ends of a link, a router subinterface and its switch's SVI, and two linked devices with addresses in the subnet when each end of the link can carry it (the addressed port, or a switch port carrying the SVI's VLAN), such as OSPF neighbors on a transit subnet. Each route to an advertised subnet is followed hop by hop to where it leads, which shows which devices advertise it and which only have an address in it (a switch's management SVI, say); addresses in it that routes use as next hops but no device on the map has, and devices linked to it that didn't answer SNMP, are noted as also on it (a router there may advertise it too).
- Subnet Placement checks: an advertised subnet in two places, routers reaching it in different places, an advertised subnet linked to two VLANs, one not where it's planned (on the map in another VLAN), one marked local that other devices have routes to (leaking), one marked advertised that nobody routes to, an advertised subnet inside another advertised one somewhere else, and notes for subnets reused locally, only covered by a summary (counted as local), not linked to a VLAN, or not in IPAM.
- **How to Treat It**: set a subnet as advertised or local over what the routing tables suggest, with a note, or mark its places one L2 segment the map can't see (an unmanaged switch, or a link CDP and LLDP don't show). Kept beside the VLANs, shared with the tribe; nothing on the IPAM subnet changes.
- **Moving subnets**: Plan Move (from a VLAN and device to another, when, and why), Start Move, Check Move (the map shows it only at the new place, and every route to it leading there), Complete Move (relinks it on the VLANs page, adding the VLAN to the domain if it's new) or Cancel Move, with earlier moves listed. While a move is in progress, the subnet advertised from both places is flagged. Moves and treatments are changed online only (the server checks two people aren't moving one subnet at once); the server needs this version (API level 8).
- Network Map: the crawl reads VRFs: which interfaces are in which (CISCO-VRF-MIB, or MPLS-L3VPN-STD-MIB) and each VRF's routing table (MPLS-L3VPN-STD-MIB; a device without it says so in the crawl log). Subnet Placement checks each VRF on its own.
- Network Map: **Read Routes Again** (on the Subnet Placement page) reads the routing tables, VRFs, VLANs and interfaces of every device on the map, without mapping again.
- Network Map: watching notes subnets that appear on, go from or move between the switches it reads again, in the Watch log.

- **VLANs page** (Manage > VLANs): each VLAN domain's VLANs, with their names, status (active, reserved or planned), the IPAM subnets they carry and where the network map found them. A domain is where VLAN numbers are unique (a VTP domain, or a site's switches) and can belong to one IPAM network, whose subnets its VLANs carry. Domains can have ranges set aside for a purpose (100-199 for users, say), and **Next Free** picks the lowest unused number in one. VLANs have history like addresses, export to CSV, and **Show Subnet in IPAM** and **Highlight on Map** go to them on those pages. Names Cisco switches won't take (over 32 characters, or with spaces) are pointed out.
- VLANs are shared with the tribe through the IPAM server, like networks (tribe and local domains, as on the IP Addresses page). They can be changed offline: changes wait as pending and are sent when the server is back, and **Review Refused VLAN Changes** offers the next free number, or discarding, for any someone else beat. Domains can only be changed online. The server needs this version (Tools > Tribe Management > Update Service) before laptops can share VLANs; a laptop syncs everything once after updating, to fetch them.
- **Bring in VLANs from a Network Map** (VLANs page, Domain menu, or the map's VLANs tab): the VLANs the crawl found, compared with a domain (or a new one, named after the VTP domain), to tick what to add, rename or link. Each VLAN interface (an SVI, or a router's subinterface) links the IPAM subnet holding its address, whatever mask either is written with; nothing is added to IPAM. A new domain, or one without an IPAM network, is offered the network holding most of the VLAN interfaces. VLANs deleted from the domain, and names the domain already has, aren't ticked.
- **Link Subnets Named for VLANs** (VLANs page, Domain menu): links IPAM subnets whose names say which VLAN they're in (such as Vlan 6), or whose details do (the Vlan 10 column some workbook pages have), without changing them.
- Network Map: the crawl reads each switch's VLANs and their names, its VTP domain and mode, and every port's VLANs (an access port's VLAN and voice VLAN, a trunk's native and allowed VLANs), from CISCO-VTP-MIB and CISCO-VLAN-MEMBERSHIP-MIB, or Q-BRIDGE-MIB on other switches. They're saved with the map (maps made before need mapping again to have them), shown in a device's details and a port's, and on the new **VLANs** tab: every VLAN by VTP domain, with its switches, access and trunk ports, gateways (VLAN interfaces, and routers' and firewalls' subinterfaces, whose VLAN is guessed from their names) and hosts.
- Network Map: **Highlight on Map** (VLANs tab, double-click a VLAN, or right-click a device or port > Highlight VLAN) fades everything that doesn't carry a VLAN: the links that do are colored by how (tagged on a trunk, native, or between access ports), and a trunk allowing it at one end only is dashed orange. **Show All**, or **Stop Highlighting VLAN** at the top of any right-click menu on the map, puts it back.
- Network Map: **Read VLANs Again** (VLANs tab) reads just the VLANs and IP interfaces of every switch, router and firewall on the map that answers SNMP: quicker than mapping again, and how a map made before this version gets its VLANs.
- Network Map: watching notes VLAN changes in the Watch log when it reads a switch again: VLANs added, gone or renamed, and ports moved to another VLAN (or a trunk's native or allowed VLANs changed). Read VLANs Again notes them there too.
- VLANs page: a **VLAN Interfaces (Map)** column beside the IPAM gateways, from the map open. In a VLAN's window, the subnets holding its VLAN interfaces on the map are marked and listed first, a click anywhere on a subnet's row ticks it, and a domain without an IPAM network can be given one there.
- Network Map: **VLAN checks** on the VLANs tab: a trunk at one end of a link and an access port at the other, native VLANs that differ, VLANs allowed at one end of a trunk only, access ports in VLANs the switch doesn't have, and a VLAN named differently on switches in one VTP domain.

### Changed

- The IP Addresses page, its networks and subnets, and its export to the workbook are unchanged by VLANs: linking a subnet to a VLAN is kept with the VLAN, never on the subnet.
- Network Map: crawls read a switch's VLAN tables once (they were read again to choose which per-VLAN MAC tables to read).
- Network Map: a port IOS names Et0/0 is matched with Ethernet0/0 as CDP gives it (links, hosts and the rest).
- Tick boxes in lists and tables (the VLAN window's subnets, the import and compare reviews) have a visible outline and fill green when ticked: unticked ones were black on black in the dark theme.
- Every table's columns can be dragged wider or narrower: they still fit their contents as rows come in until you drag one, which then keeps your width (double-click its edge to fit it again). Columns that filled the spare room still do, and can be dragged too. Many pages' tables (Subnet Placement, VLANs, the map's tables, Syslog, Latency, Traceroute, Routes, Ports and more) couldn't be resized before.
- Subnet Placement: **Check Move** reads the routes again itself, then checks the move on the map as it is now (it said to Read Routes Again first). Read Routes Again says when it's done.

## [1.15.0] - 2026-10-03

### Added

- Network Map: **Bottom to Top** and **Right to Left** arrangements, for Re-arrange, arranging the devices selected and arranging a site, building or room.
- Network Map: **Spacing** (Compact, Normal, Roomy or Spacious) draws devices closer together or spreads them out, leaving each where it is among the rest (nothing is laid out again). It's on Re-arrange's arrow for the whole map (and Re-arrange uses it from then on), for the devices or groups selected (**Spacing of the 5 Selected**, on the right-click menu too, beside Arrange), and on a group's title menu. Shrinking stops before devices meet, and keeps sites, buildings and rooms from running into each other.
- Network Map: a compact top bar, one row of buttons: **Map** holds New Map, Open, Recent, Save As, Export, Compare and the tribe's maps; **Crawl** shows where to start from (shown anyway while there's no map or a crawl runs); the status keeps to one line (hover over it for all of it). **View > Network Map Top Bar > Classic** puts back the bar as it was.
- Network Map: **New Map** puts the map open away, as it is, so Start makes a new one; pressing Start with a tribe map open asks whether to start a new map or map the tribe map again for everyone.
- Network Map: the map open when NOMAD closes (a file or a tribe map) is opened again when it starts; if it can't be, the page says why and tries again next time.

### Changed

- Network Map: Re-arrange orders each layer so links cross as little as it can find, and a link between two devices in the same layer doesn't run over the ones between; single-link devices (access points) go beside a switch that has links down to other devices, on the side away from them, instead of under it where those links ran through them. With Keep Groups Together, the device linking a group to the rest is on top of it, and the groups are laid out as the links between them go rather than tiled.
- Network Map: what's selected is drawn with a white ring and a light wash, leaving its outline (its type, or up or down while monitored) as it is.
- Network Map: Monitor's and Watch's news share a set amount of room, so the find box keeps its width whatever they say, and a long one (who's watching a tribe map) uses the room a short one leaves.

### Fixed

- Network Map: Monitor and Watch could be off when NOMAD started again although they were on: they're now saved the moment they're turned on or off (and all settings when Windows logs off or restarts), and kept while the map open last time can't be reopened.
- Network Map: Watch's news squeezed the find box until it was hardly usable.
- A crash (the whole program closing) when a page or session was closed while one of its background threads had news still waiting to be delivered: seen with watching a tribe map, and possible on the SCP page and others. Background threads now report to the page itself, which Qt tidies up safely.
- Network Map: two maps started in the same minute were saved to the same file, the second over the first.

## [1.14.0] - 2026-10-03

### Added

- SNMP Config page (in the new SNMP section): builds the Cisco IOS / IOS-XE configuration that sets a Catalyst switch up for NOMAD (a read-only community string and/or SNMPv3 user behind an access list, traps and syslog to the computers watching, CDP and LLDP, link-status logging and MAC notifications on the access ports, write memory), with the commands to take it out again. Copy it, save it, or **Send to Session**: NOMAD types it into a connected terminal session, or one it opens to the switch, a line at a time, after checking it's at the enable (#) prompt. It can fill in the Network Map's credentials, and add its own to the map. The Network Map's Watch tab opens it set up for this computer, in place of the lines it used to list.
- SNMPv3: the Network Map's crawls, checks and watching, the Map Watcher service and the SNMP Walk page can use SNMPv3 users (MD5, SHA-1 or SHA-2 authentication; DES or AES-128/192/256 privacy, with Cisco's key extension for AES-192/256). The map's **Communities...** is now **Credentials...**, with a list of v3 users (tried first, unless that's unticked) and per-subnet `v3:user` entries; Catalyst per-VLAN MAC tables are read in the `vlan-` contexts. A tribe map's users are shared with it, encrypted like its community strings (everyone needs this version to use them). The trap listeners take v3 traps from the map's users, and a device that refuses a user says why (unknown user, wrong password) in the crawl log.
- Terminal sending can be paced for one block even when the session has no line delay (used by the SNMP Config page).
- Watching asks devices on the map that don't answer SNMP again (hourly, and at once when the map's credentials change), and reads any that answer now, so a device set up for SNMP (or SNMPv3) after it was mapped turns solid without mapping again. The Map Watcher service does it too.
- All the watch timers can be set, to any value, on the Watch tab and for the Map Watcher service: new neighbors, new hosts, the SNMP re-check, and how long after a trap or syslog message a switch is read (it was always 45 seconds).
- Network Map: **Check SNMP Again** on any device that doesn't answer SNMP, not only ones added by hand. One the crawl found is read (Crawl from Here) when it answers, and one that doesn't says why when it can.

### Fixed

- Network Map: a starting address that didn't answer SNMP stayed on the map as a second device once the device was read (seen by a neighbor under its name): it's now folded into the device it is.
- Network Map: a device's management address is now the one it answered SNMP at, not one a neighbor's CDP or LLDP advertised (which may not answer, such as an address outside the crawl's scope). Watching used that address, so it could keep asking a switch where it didn't answer.
- Watching follows a switch whose management address stops answering (the management network was renumbered, or the map was made before this fix): it tries the switch's other addresses inside the crawl's scope, and the one that answers becomes its management address, noted in the watch log and saved with the map (and shared, on a tribe map). Addresses corrected by hand are left alone.
- Network Map: a Cisco switch with VLANs but no per-VLAN MAC tables (community@vlan doesn't answer, as on some IOS images) had no hosts: its one MAC table is now read instead, and the crawl log says so.
- Network Map: devices with the same name (switches left with the default name "Switch", or sw1.site-a and sw1.site-b, which both shorten to sw1) were drawn as one device, and the second wasn't read, so the crawl went no further past it. A device is now taken to be one already read only when their IP addresses overlap. Devices that share a name are told apart by address (or, with none, by the port they were seen on), so one already on a map may show as new once when another with its name turns up.

### Changed

- The sidebar has an SNMP section for the SNMP pages: Network Map and SNMP Walk (moved from Discover; SNMP Walk was called SNMP) and the new SNMP Config.
- Tools > IPAM Server is now Tools > Tribe Management, since the tribe shares network maps as well as IPAM. Besides setting up the tribe server, it shows whether this computer is in a tribe, connects to one with a key file, and disconnects from it (warning about IPAM and map changes not sent yet, whichever page they're on). It's now the only place to leave the tribe: Disconnect is gone from the IP Addresses page's Tribe menu, and Leave the Tribe from the Network Map's.
- Network Map: Tribe > Join the Tribe with a Key File is now Connect to the Tribe with a Key File, to match the IP Addresses page.

## [1.13.1] - 2026-10-02

### Added

- Network Map: join the tribe from the map page (Tribe > Join the Tribe with a Key File...), and leave it (Leave the Tribe...). The tribe isn't only for IPAM any more: joining or leaving on either page does both, and leaving warns about tribe map changes not sent yet.

### Fixed

- The tribe server didn't count as part of the tribe on the Network Map page: NOMAD on the server (running as administrator) now uses the server's own key for tribe maps, as the IP Addresses page does, and the Map Watcher service can be installed there. Not as administrator, the Tribe menu says to restart as administrator.

## [1.13.0] - 2026-10-02

### Added

- Network Map: watch for new devices. Tick **Watch** and the switches on the map are asked for their CDP and LLDP neighbors every few minutes; a switch with a new neighbor is read again at once (as Crawl from Here does), so a new switch, router, firewall or access point is added beside the port it was seen on, with its links and hosts. Every switch's MAC table is read again every hour (or as often as chosen) for new hosts. What's found is tagged NEW on the map (a green tag on a device, a dot beside a host) and in a New column on the Devices and Hosts tabs, until it's marked as seen (right-click > Mark as Seen, or Mark All as Seen); the Watch tab logs what was found and where. Hosts seen on the map in the last 30 days aren't news, and deleted devices stay off. Saved with the map.
- Network Map: switches can tell NOMAD at once. With Listen ticked on the Watch tab, syslog (UDP 514) and SNMP traps (UDP 162) from a switch on the map have it read 45 seconds later when a port comes up, CDP or LLDP changes, or a MAC address is learned or moves (Cisco link up/down, CDP, LLDP and MAC-flap messages; linkUp, cold/warm start, LLDP and Cisco MAC-notification traps, v1 and v2c, informs answered). Several from one switch are one reading. The Watch tab lists the lines to paste into a Cisco switch. The Syslog page and watching share port 514.
- Tribe maps: share a network map with the tribe through the IPAM server (Tribe > Share This Map with the Tribe...). Everyone with the tribe key can open it from Tribe; its community strings and scope go with it. Changes are sent as the items they touch (a device, a link, a host, a group, a device's place) and merged item by item, so people working on different parts of the map don't undo each other, and the later change wins on the same item. Changes reach other computers within seconds, and a tribe map opens and changes offline, sending its changes when the server is back. Tribe maps can be renamed, deleted (everyone keeps a copy as a file) or copied to this computer only. They're in the server's nightly backups.
- Only one computer watches a tribe map at a time: the others say who ("watched by WS-12 (NOMAD)") and stand by, taking over if it stops, so the network isn't read twice. A computer that can't reach the tribe server watches anyway and sends what it found later.
- Tools > Map Watcher Service: the NOMAD Map Watcher Windows service watches chosen tribe maps from a computer that's usually on and can reach the switches, with nobody signed in. It takes over from NOMAD left open elsewhere, listens for syslog and traps (opening UDP 514 and 162 in Windows Firewall), and adds what it finds to the tribe maps. `NOMAD.exe --map-watcher` runs it in a console for trying it out.

- Network Map: correct a device the crawl found (right-click > Correct Device...): its name, management address (when CDP gave none, or the wrong one), kind, model or note. Corrections are kept over what later crawls find, the crawl asks the device at the corrected address, and Forget Corrections puts back what was found. Devices can be marked as servers.
- Network Map: deleting a device the crawl found keeps it off the map when mapping again, and the crawl doesn't go through it (unless you start from it). Right-click the map's background > Deleted Devices to bring them back.
- Network Map: SNMP Details on a device uses the community string it answered to during the crawl.
- Network Map: several sites, buildings and rooms can be selected together (Ctrl+click or Shift-drag round their titles, with devices too) to drag, arrange, align or distribute them; each moves as one box.

### Fixed

- Closing a Terminal or SCP tab while it's still connecting (no answer yet, or waiting for a password) no longer leaves NOMAD waiting; the connection is dropped when it finishes.

### Changed

- The IPAM server (API level 6) keeps tribe maps in maps.db beside the IPAM database. Update the service (Tools > IPAM Server > Update Service) to share maps; older servers keep working for IPAM, and the map page says the server needs updating.

## [1.12.0] - 2026-10-01

### Added

- Network Map: add devices and draw links by hand, for what the crawl can't find (an unmanaged switch, a device SNMP can't reach, a port with CDP and LLDP off). Right-click the background > Add Device Here..., or a device > Add Device Linked to This..., Draw Link from Here (then click the other device) or Add Link...; the Devices and Links tabs' right-click menus have them too. A device added by hand with an IP address is checked over SNMP with the map's community strings, as the crawl's devices are, and shown the same way when the community isn't working (dashed, "Pings, no SNMP") or it doesn't answer at all; it's pinged while monitoring. Devices added by hand have italic names, links drawn by hand are dotted (in draw.io exports too), and the Found by and Seen by columns say "Added by hand" and "Drawn by hand". They're saved with the map and carried over (and checked again) when you map again; once a crawl finds the device by its address or name, the crawl's entry takes over its links, hosts, group, place and note, and a link drawn by hand goes once the crawl finds one between the same two devices. Right-click them to edit them, check SNMP again, or delete them.
- Opening an SSH, SCP or Telnet session from the Network Map, IP Addresses or Sweep uses the host's saved session when there is one, with its user name, saved password or key and settings. A saved session is found by any address or name the map knows for the device (its management address, other interface addresses and its name, with or without the domain), or by the address's recorded name in IP Addresses. The menu names the session it will open ("Open SSH Session (Core-SW1)"); with several saved sessions for a host it asks which, and "Open New SSH Session" connects without them. SSH with PuTTY logs in as the saved session's user.
- A session opened that way without a saved session is named after the device or address record, and Save as Session suggests a folder: the device's site, building and room on the map, or the network and subnet in IP Addresses.
- Network Map groups can now be rooms (or workspaces) inside buildings, as well as sites and buildings. Choose Room in New Group (it's already picked when the devices are all in one building), or move a room to another building from its right-click menu. Rooms are drawn as their own boxes inside the building's box, collapse like the other groups, appear as "Site / Building / Room" in the Group column, and are exported to draw.io.
- Undo and Redo on the Network Map (buttons beside Fit, or Ctrl+Z and Ctrl+Y / Ctrl+Shift+Z). They step back and forward through dragging devices, re-arranging, arranging or aligning the selection, and changes to sites, buildings and rooms (including dragging a device into or out of one, which is a single step with the move), on both the physical and logical views. The last 100 changes are kept until another map is opened or crawled.

### Fixed

- Network Map: a link's port label is no longer hidden under a switch's "▾ hosts" badge when the device it goes to is below the switch.

## [1.11.0] - 2026-10-01

### Changed

- Network Map: Crawl from Here adds what it finds to the map open (in the same file, keeping the layout, hosts added by hand and monitoring history) instead of making a new map. It reads that device and what's beyond it, not the devices already read; Start still makes a new map.
- Network Map: faster crawls. 16 devices are read at once instead of 8 (Scope > Devices read at once, up to 64), each SNMP request asks for 50 rows instead of 25, and MAC tables are read by their port and status columns only. On Catalyst IOS, MAC tables are read only for the VLANs the switch's access, voice and native trunk ports use (a VTP domain can list hundreds it doesn't carry), four at a time, and for every VLAN if the switch doesn't say.

### Added

- Network Map: sites and buildings. Select devices, right-click > Group > New Site or Building... to draw a labeled box round them; a building can be in a site. Drag devices into a box to add them or out of it to take them out, and drag a box's title to move everything in it. Double-click the title to collapse a group into one box that keeps its links to the rest of the map (finding a device in it opens it). Selecting a group shows its devices, how many are down and its links out; right-click its title to arrange, rename, move a building to another site, or ungroup. Groups are saved with the map and carried over when you map again, the Devices tab and its CSV have a Group column, and draw.io exports include the boxes.
- Network Map: more ways to arrange. Re-arrange's arrow offers Top to Bottom (as before), Left to Right, Grid and Circle (rings round the core), remembered for next time; with Keep Sites and Buildings Together (on by default) each group is laid out in its own box and the boxes are tiled. Arrange the devices selected where they are, or Align them (left, center, right, top, middle, bottom) and Distribute them evenly across or down, from the arrow or by right-clicking them. Put at the Top uses the arrangement chosen.
- Network Map: the Crawl log says how long each device took and its slowest step (such as "Read core-1 in 14.2 s (slowest: MAC tables 9.8 s)"), and which VLANs' MAC tables were read on each Catalyst.

## [1.10.1] - 2026-09-30

### Added

- Network Map: a Logical (L3) view. Routers, L3 switches and firewalls are joined through the subnets they have addresses in (read over SNMP with their routing tables), with the next hops their routes point to. Select a router for its IP interfaces and routes, or a subnet for the devices and hosts on it; right-click a subnet to sweep it.
- Network Map: after the crawl, traceroute from this computer to what SNMP couldn't show (devices that didn't answer SNMP, next hops that aren't on the map, and static routes' destinations), drawn dashed on the logical view with `*` for hops that didn't answer. It can be turned off under Scope.
- Network Map: Compare with an earlier map lists devices and links that appeared or went away, devices that changed (such as one that stopped answering SNMP), and hosts that moved to another port (and, if you ask, hosts that appeared or went away). New and changed devices are ringed on the map; double-click a difference to go to it.
- Export on the Network Map page saves the view showing, so the logical view can be saved as a picture or a draw.io file too.
- Network Map: the map is drawn while it crawls, adding devices as they're found (where they stay, even if dragged), with the devices being read ringed in green. A progress bar shows devices read, being read, queued and found, those that didn't answer, the time taken and roughly how long is left.
- Network Map: a Crawl tab showing what each device being read is doing now (which table, which VLAN's MAC table, which community string it's trying) and for how long, and a log of the crawl: each device read and what it had, each neighbor found and through which port, why any wasn't asked (outside the scope, too many hops, the device limit, no management address), communities that didn't answer (by number, never the string), tables that couldn't be read and each traceroute's path. Copy Log and Save Log.
- Network Map: Excel-style filters on the Devices, Links and Hosts tabs. Click the ▾ in a column's header to sort A to Z or Z to A, search, and tick the values to show, with how many rows have each (such as Kind: Firewall, or VLAN: 30), including (Blanks). Filters on several columns combine, each column lists only what the others let through, and they stay on when the table is refilled. The tab shows the count while filtered, such as Hosts (12 of 340). Rows a filter hides aren't deleted by Ctrl+A and Delete.
- Network Map: Show in Physical (L2), Show in Logical (L3), Show in Devices and Show in Links on a device's right-click menu, to find it on the other tabs (Show in Links selects all its links). The Devices tab has the same right-click menu, and the Links tab's shows a link's two ends on the map or in Devices.
- Network Map: select several devices and move them together: drag the background to draw a box round them, Ctrl+click to add or remove one, Ctrl+A for everything, then drag any of them. The view now moves with the middle mouse button, or Space and drag.
- Network Map: Show Hosts shows every switch's hosts at once (they're hidden until then, or until you double-click a switch). Each port's box lists its hosts one to a line with each one's VLAN (the first six, then how many more), and boxes keep clear of other switches' boxes.
- Network Map: hosts' VLANs on switches with one MAC table for all VLANs (such as NX-OS), read from Q-BRIDGE-MIB. Before, hosts on those switches had no VLAN.
- Network Map: add hosts by hand for devices that are turned off or unplugged while mapping (right-click a switch, a port's box or the Hosts tab > Add Host...), with a port, name, IP, MAC, VLAN and note. They're drawn dashed, marked "Added by hand" in the Hosts tab and CSV, and kept when you map again; if one is later found by the crawl, that entry takes over and keeps your name and note. Hosts can be edited and deleted (right-click, or Delete on the Hosts tab, which now selects several at once).
- Network Map: monitoring. Tick Monitor (every 10 s to 10 min) to ping the devices on the map: each shows a green dot and its response time, or a red tint and how long it's been down (on both maps), after missing two checks in a row. The Devices tab has a Status column, the device details say since when, and a Monitor tab logs each device going down or coming back with how long it was down. The history is saved with the map and kept when you map again. It keeps going on other pages and resumes when NOMAD starts if it was on.
- Network Map: the find box works on the tab showing, keeping its own text for each: on the Devices, Links and Hosts tabs it filters the rows as you type (words in any column, on top of the column filters), on the Crawl tab it finds text in the log (Enter for the next), and on the maps it finds a device.

### Changed

- Ctrl+F (Tools > Find on This Page) goes to the search or filter box of the page showing (Routing Table, ARP, Connections, Syslog, IP Addresses, Network Map) instead of always the routing table's.
- Network Map: dragging the background moves the view again; hold Shift and drag to draw a box selecting several devices.
- Table filters (Network Map's Devices, Links and Hosts tabs): the small ▾, easily taken for a sort arrow and hard to hit, is now a funnel button at the left of each column header, highlighted when the mouse is over it and filled green while the column is filtered, with a tooltip. Right-clicking a column header opens its filter too. The drop-down opens on the list of values to tick ("Show rows where Kind is:"), with sorting below it.

### Fixed

- Network Map: the Devices, Links and Hosts tables were listed Z to A; they now start A to Z by their first column.
- Network Map: a switch whose neighbors all had just one link (a core with only access switches under it) was drawn with them above it instead of below.

## [1.10.0] - 2026-09-30

### Added

- Network Map page (Discover): start from a core switch or your gateway and NOMAD crawls the network over SNMP, reading each device's CDP and LLDP neighbors and then theirs, within a scope you set (subnets, hops and a device limit). It draws the switches, routers, firewalls and access points with the ports at each end of every link, and puts hosts on the edge ports they're plugged into, from the switches' MAC tables (per VLAN on Catalyst IOS) and the ARP tables, with vendors and phones' names. Devices that answer ping but not SNMP are marked, so a wrong community string or an SNMP ACL stands out. Community strings are tried in order, with per-subnet ones first, and saved encrypted. Drag devices where you want them (kept when you map again), find a device or host by name, IP, MAC or vendor, and right-click a device for SSH, ping, SNMP and more. Maps are saved automatically and export to PNG, SVG, draw.io (which Visio can import) and CSV.
- SNMP page: walk presets for CDP neighbors and Cisco VLANs.

## [1.9.1] - 2026-09-30

### Added

- Hotkeys for command buttons: Ctrl+1 to Ctrl+9 in a session press the first nine buttons (sending to that session, or to all while Type in All is on), whether or not the Buttons bar is showing. Each button's tooltip says its key. Where there's no button with that number, Ctrl+digit goes to the device as before; with six or more buttons, use Ctrl+Shift+6 (not Ctrl+6) for Cisco's abort.
- Rearranging command buttons: drag a button along the bar to where you want it (a marker shows where it will land), or right-click it > Move to Position, which lists each position with its hotkey. Move Left and Move Right are grayed out at the ends. A button's Ctrl+number follows its position.

### Fixed

- The Buttons bar on the Terminal page was far taller than its buttons. It's now one row of buttons tall (plus a scrollbar only when they don't all fit across), so it takes two lines from the sessions instead of six.
- Terminal text jumped when the terminal got shorter: showing the Buttons bar (or Send to All, re-tiling, or making the window shorter) threw away lines from the top of the screen and left the cursor below the prompt, and hiding it again didn't bring them back. Now, as in xterm and Windows Terminal, text only moves when the prompt would otherwise go off the bottom, the lines that move go into the scrollback, and growing again brings them back exactly as they were.
- A network exported to a workbook without a Unit or Location came back from it with its revision date as the Unit: the importer now reads the unit row by column.

## [1.9.0] - 2026-09-29

### Changed

- Sweep results on the IP Addresses page last: the Last Sweep column is now Last Seen, and shows when each address last answered (today 14:05, Sep 27 09:30...) and, when the latest sweep got no answer, when it last did. They're kept in the database, and for tribe networks shared through the IPAM server (sweeps made offline, say in an air-gapped network, are sent when it's back), so everyone sees them, with who swept. Sweeps from the Sweep page's IPAM comparison are kept too. They aren't changes to the records, so they stay out of the history. The IPAM server needs updating for sharing them; until then each laptop keeps its own.

### Added

- Check Data (IP Addresses page, Network menu): lists likely mistakes in a network, most serious first: a name whose number doesn't match its Telephony Rng, a name that looks like a stray user name or note (such as "rojason."), a subnet named Loopback that isn't marked Loopbacks, a device recorded on a subnet's network or broadcast address, addresses outside every subnet, the same MAC on two addresses, reserved addresses with no name, gateways in unusual places and unnamed subnets. Double-click one to go to it; the list stays open, and Check Again re-checks.
- Compare with Workbook (Network menu): compares a network with a page of a newer copy of the addressing workbook (settling its summary and Detailed Info differences as an import does) and lists every difference: subnets and addresses to add, change or remove, and network details. Tick the ones to make and apply them, instead of deleting and importing again, so edits made in NOMAD and the history are kept. Anything changed or deleted in NOMAD since the import, and anything only IPAM has, is left unticked.
- Export to Workbook and Export All Networks to Workbook (Network menu): writes networks as .xlsx pages in the tribe's workbook layout (header, unit row, summary, Unit Base Info, Detailed Info with every address of subnets up to 256, End), so the spreadsheet can be kept up to date from IPAM. It imports back exactly as it went out. The layout has no place for addresses outside every subnet (the export says how many) or for addresses' MACs and descriptions (the CSV export has those).
- Find Free Blocks (right-click a subnet): the unused space in it, as the largest free blocks or every free block of a size you choose, with Add as Subnet.
- Changing many at once: select several addresses to Mark Used, Mark Reserved, or Edit Selected (status, description, or a detail); Ctrl/Shift-click several subnets and Edit Selected Subnets to set a detail (such as Telephony Rng), the description, or Loopbacks.
- Free Address from IPAM on the Interfaces page: pick a network and subnet (it starts with the one the adapter is in) and it fills in the next free address, with the mask and gateway. Once you apply the settings and keep them, the address is recorded in IPAM as used, with this computer's name and the adapter's MAC.
- Narrower searches on the IP Addresses page, which now has a search row of its own under the toolbar: choose what to find (everything, subnets, addresses, used addresses or reserved addresses), which network to look in (or all of them), and which field to match: any, the address or subnet, name, description, MAC, or a detail such as Telephony Rng. Changing any of them redoes the search showing, and results have a Details column (such as Telephony Rng: 68890).

## [1.8.2] - 2026-09-29

### Fixed

- Selecting a loopback subnet on the IP Addresses page showed "Something went wrong: 'Block' object has no attribute 'max_prefixlen'" instead of the subnet.

## [1.8.1] - 2026-09-29

### Added

- Loopback subnets in IPAM: a subnet can be marked Loopbacks (in its settings), meaning every address is a /32 of its own. It has no network, broadcast or gateway address, so Use Next Free can hand out the first and last addresses, the used count includes them, and Sweep Subnet pings them. Import Spreadsheet makes a loopback subnet from each Detailed Info block listed with the mask 255.255.255.255, named as the sheet names it (such as 68900 MAIN TCN Loopback); rows there marked Network or Broadcast are free loopbacks. A block whose addresses aren't one subnet is imported as several, all with the block's name, rather than being left out. Update the IPAM server and laptops together: the server's database gains a column for it.

### Changed

- Disabling an adapter on the Interfaces page now asks afterwards whether to keep it disabled, as changing its IP settings does: if you don't confirm within 15 seconds (say it cut off your remote session), it's enabled again.

## [1.8.0] - 2026-09-29

### Added

- Command buttons on the Terminal page (Buttons, beside Send to All; also View > Terminal Command Buttons): saved commands, or whole blocks of configuration, sent with one click to the session you're in, or to every session while Type in All is on. Right-click a button to send it to all, edit, duplicate, move or delete it. Kept in %APPDATA%\NOMAD\commands.json, shared by every window.
- Line delay (session settings > Sending and Staying Connected): pasting several lines, a command button or Send to All sends them one at a time, so consoles and older switches don't drop characters. The status line shows progress, and right-click the tab > Stop Sending drops the rest.
- Keyword highlighting in terminal sessions: down, err-disabled, % Invalid, notconnect, up, IP and MAC addresses and more in color, only where the device didn't color the text itself. Change the words and colors in View > Terminal Keyword Highlighting, or switch it off in View > Highlight Terminal Keywords.
- Reconnect automatically (session settings, or right-click the tab): when the connection drops, such as a device reloading, NOMAD tries again every 10 seconds (for up to half an hour) until it's back. Not after you type exit or logout, or disconnect it yourself; right-click the tab > Stop Reconnecting stops it.
- Anti-idle (session settings): after a set time without typing, send a space and a backspace (or any text you choose), so the device's exec-timeout doesn't log you out.
- Send to All on the Terminal page (beside Layout): type a command once and send it to every connected session, the sessions on screen, or this window's, each with its own Enter; Up and Down bring back earlier commands. Ctrl+C in its box interrupts every session (unless text in the box is selected, which it copies), Ctrl+Z with the box empty sends Ctrl+Z, and Ctrl+Shift+6 sends Cisco's abort; the Keys menu sends these and Tab, Space, q, Esc and Enter to all. Type in All mirrors your typing into all of them as you go (the bar turns amber while it's on, and closing the bar turns it off). Right-click a tab > Leave Out of Send to All to skip a session (its tab shows ⊘).
- Tiling on the Terminal page: Layout (beside the tabs) shows several sessions at once: two or three side by side or stacked, or a 2 × 2 or 3 × 2 grid, with draggable splitters. Each pane has its own tabs: drag a tab onto another pane, or right-click it > Move to, to move the session there (it stays connected), even into a pane of another window. An empty pane has an Open Session menu (saved sessions, Recent and Quick Connect) that opens a session in that pane, and pop-out windows have a Sessions menu of their own, so sessions can be opened straight into them. Clicking in a pane makes it the active one (outlined in the accent color); new sessions open in an empty pane, or else the active one. Also in View > Terminal Layout. Pop-out windows can be tiled too, and the page remembers its layout.
- Route lookup on the Routing Table page: type an address or network in the filter (such as 10.1.2.3, 10.1.0.0/16, or a partly typed 10.1.) to see every route that covers it, as a router's lookup would, system routes included. The route Windows would use (longest prefix, then lowest metric) is marked ► and named under the table.

### Changed

- The Utilities page is now two pages under Tools: Subnet Calculator and Wake-on-LAN. Saved devices and the last subnet carry over.

### Fixed

- Adding a persistent route failed, because New-NetRoute doesn't accept the persistent store directly. It's now added to both stores at once (replacing an active-only copy of the same route first), and deleting a route removes every matching copy.

## [1.7.0] - 2026-09-29

### Added

- Work as root on the SCP page: right-click the tab (or the remote side) > Work as Root (sudo), or tick "Work as root (sudo) on the SCP page" in a session's settings. The tab reconnects with SFTP run through sudo (as WinSCP does), so browsing, copying, editing and Synchronize all happen as root, and the remote side's title turns amber: "Remote (as root)". NOMAD tries your login password for sudo and asks only if that doesn't work (servers where sudo needs no password just work); the password is kept in memory for that connection only. It says clearly when the user isn't allowed to use sudo, when sudo needs a terminal (requiretty), or when the server's sftp-server can't be found. Needs SFTP (the session's File transfer set to Auto or SFTP).
- Changing owners on the SCP page: Properties has User and Group fields, listing the server's users and groups (numbers work too), and can apply them to everything inside a folder. Links are left alone. A "Permission denied" message suggests Work as Root.

### Fixed

- Selecting text in a terminal while the device was printing could fail with "cannot unpack non-iterable NoneType object" when the mouse button was let go. The selection now stays on the text it covers as new output scrolls it up (as in PuTTY), and is copied when you let go. Once the scrollback was full, it could also copy a different line from the one selected; that's fixed too. While scrolled back, the view keeps showing the same text when the scrollback is full.

## [1.6.2] - 2026-09-29

### Added

- Upload ▶ and ◀ Download buttons under the SCP page's panes copy the selected files to the other side (as F5 does).
- File transfer setting for SSH sessions (Edit Session): Auto uses SFTP when the server has it and SCP otherwise, as before; SFTP only or SCP can be chosen for servers whose SFTP is broken rather than missing.

### Fixed

- Answering "Do the same for the rest of the queue" when a file exists no longer carries on to files queued later: once the queue runs out, the next file that exists is asked about again (or follows the "If it exists" setting).
- Downloading or synchronizing a folder that has links to other folders in it copies what the links lead to, instead of making empty folders. A link that leads back up the tree is skipped. Delete and Permissions still act on a link itself, never on what it leads to.
- The SCP page's local side lists folders in the background, and finds drives without asking each one, so a slow network share or a disconnected mapped drive no longer freezes NOMAD.
- Cancelling an upload in SCP mode (servers without SFTP) removes the part-written file from the server.
- Copies downloaded for Edit With that were left behind (NOMAD didn't close normally) are deleted once they're two days old.
- Cancelling (or pausing) an SCP transfer now stops it straight away. Before, a big download kept going in the background until the rest of the file had arrived, so Cancel seemed to hang; downloads now read ahead 16 MB at a time instead of the whole file, which also keeps memory use down.
- A transfer that stops getting data (Wi-Fi off, VPN dropped, server busy) shows "Stalled: no data for N s" in the queue instead of "Transferring". It carries on by itself if the connection comes back, and Cancel works while it's stalled.
- Browsing on the SCP page gives up after 30 seconds without an answer from the server, instead of showing "Listing..." for ever.
- SSH logins (Terminal and SCP) could occasionally wait 30 seconds and then report a correct password as wrong, when the server answered very quickly. This came from paramiko sending the login request before it was ready to hear the answer.

## [1.6.1] - 2026-09-28

### Added

- SCP wherever SSH is offered in a right-click menu: Open SCP Session on the Sweep and Ports pages (for port 22), SCP on an address on the IP Addresses page, and Open in SCP on SSH sessions in the Terminal page's session list, its Recent list and its tabs. The SCP page offers Open in Terminal the same way.

## [1.6.0] - 2026-09-28

### Changed

- The master password status under the Terminal page's session list ("Master password locked", "unlocked" or "No master password") is now a menu: Unlock or Lock Now, and Master Password Settings (or Set Master Password). It replaces the ⋯ menu: importing sessions moved to File > Import Sessions from PuTTY / SecureCRT, and a new Edit menu has New Session, New Folder and Clear Recent Connections. The master password menu is a button like New.
- File > Import Profiles and Export Profiles are now Import Interface Profiles and Export Interface Profiles, to tell them apart from importing terminal sessions.

### Added

- SCP page (Connect > SCP): a WinSCP-style file manager for SSH servers, using the same saved sessions as the Terminal page (only SSH sessions are listed; editing a session on either page changes it on both). Each tab is its own connection, logging in with the session's saved password, key or agent, and tabs pop out into windows like terminal tabs. This computer's files are on the left and the server's on the right: drag files between them or from Windows Explorer, or select them and press F5; F2 renames, F7 makes a folder, F8 or Delete deletes (local files go to the Recycle Bin), Alt+Enter shows properties, Ctrl+R refreshes and Ctrl+Alt+H shows or hides hidden files. Dragging onto a remote folder moves files there. The last folders used are remembered per server.
- SCP transfers go through a queue with progress, speed and time left, one file at a time on a channel of its own so browsing stays quick. Folders are copied with everything in them. Pause, Cancel and Retry work on the queue: SFTP transfers write to a .filepart file and resume where they stopped (after Pause, a dropped connection or a retry), then replace the target, keeping the replaced file's permissions and the original modification time. When a file exists NOMAD asks (Overwrite, Overwrite if Newer, Rename or Skip, optionally for the rest of the queue), or does what the queue's "If it exists" setting says. Verify compares each file's SHA-256 on both sides after copying (worked out on the server with sha256sum where it can, otherwise by reading the file back), and right-click > Checksum... shows a remote file's SHA-256, MD5 or SHA-1 to compare with an expected value or a local file.
- Editing remote files: F4 or double-click opens a file in NOMAD's editor (find and replace, go to line; the file's encoding and line endings are kept) and Ctrl+S saves it straight back to the server, warning first if it changed there since it was opened. Edit With opens it in another program (Windows' default, or one you choose, such as Notepad++) and uploads it each time it's saved there.
- Synchronize (right-click in the SCP panes, or the tab): compares a local folder with a remote one and lists the differences (only on one side, newer on one side, or different) for review. Choose upload, download or both ways (newer wins); nothing is copied until you press Synchronize, you can untick files or right-click them to choose which copy wins, and replacing a newer file asks first. Compare by checksum finds files edited without changing size.
- Properties and Permissions on remote files: size, modified time, owner and link target, and chmod with checkboxes or an octal value (including set UID, set GID and sticky), optionally for everything inside a folder (folders get Execute wherever Read is set).
- Servers without SFTP still work: NOMAD falls back to SCP, listing folders with ls over SSH (as WinSCP does) and copying files with the scp protocol. Transfers in that mode start again rather than resume.
- Import from SecureCRT (File > Import Sessions from SecureCRT, or right-click the session list): reads a SecureCRT XML export (Tools > Export Settings) and adds its SSH, Telnet, raw TCP and serial sessions under "Imported from SecureCRT", keeping SecureCRT's folders, ports, usernames, descriptions and key files. Saved passwords come across too: NOMAD asks for SecureCRT's configuration passphrase if one was set (Cancel imports the sessions without passwords) and re-encrypts them for your Windows account (and master password, if set). Importing the same file again only adds sessions that aren't there yet.
- Rearranging saved sessions: drag sessions and folders onto a folder to move them there (onto empty space for the top level; a folder takes everything in it). Ctrl-click and Shift-click select several to move, connect or delete at once. Right-click > Move to... picks the folder from a list (and can make a new one), and Move Up a Level lifts a folder out of the one it's in, such as the folders inside "Imported from SecureCRT". Moving a folder where one of the same name exists merges them, and a session whose name is already taken there gets " (2)" added; the folder things came out of stays until you delete it. Dragging is off while the session list is filtered (Move to... still works).
- Recent connections: the last 10 connections (saved sessions and quick connects) are listed under Recent at the top of the session list and in the Sessions ▾ menu. Double-click one to reconnect; right-click a quick connect to save it as a session (the Recent entry then opens the saved one, with its saved password), remove it, or clear the list.

## [1.5.0] - 2026-09-28

### Changed

- The IP Addresses page opens with its subnet list only as wide as its columns need, and a wider window gives the extra room to the addresses. After that the divider stays where it is (drag it to change it).
- Sweep Subnet on the IP Addresses page now sweeps right there instead of switching to the Sweep page: the Last Sweep column fills in as devices answer, with the host names and MAC addresses found shown beside addresses IPAM doesn't have, and Record Answering Devices, Update MACs and the right-click menu save the results to IPAM.

### Added

- IPAM history: History... on an address or subnet (right-click) and Network > Network History list every change with when, who and what changed (such as "Name: sw1 → sw1-core; Status: Used → Reserved"), newest first, filtered to the last day, week, month or all time; an address's history carries on across each time it was freed and recorded again. Network > View As Of shows the network as it was at any moment, read-only, with Back to Now. Laptops keep a copy of the IPAM server's history as they sync, so history works offline (the server needs this version).

## [1.4.0] - 2026-09-28

### Added

- Changing tribe networks offline: while the IPAM server can't be reached, addresses can still be assigned, edited and freed. Each change is kept as pending (shown on the IP Addresses page) and sent in the order made when the server is back, even after a restart; changes the server refuses because someone else got there first are listed under Review Refused Changes, to record at the next free address instead or discard. Subnets and networks still change online only.
- Sweep and ARP compare with IPAM: an IPAM column shows whether each device is in IPAM (with its name), missing, answering with a different MAC address, or answering on a reserved address. Record Not in IPAM records every missing device at once, Recorded but Silent (Sweep) lists recorded addresses that didn't answer, and right-clicking a device records it, updates its MAC or shows it on the IP Addresses page. Where a range is in more than one IPAM network, the one holding the most devices is chosen and another can be picked. Sweep Subnet on the IP Addresses page (or a subnet's right-click menu) sweeps that subnet compared with its IPAM network, listing recorded addresses that don't answer even when nothing does. The IP Addresses page's new Last Sweep column shows what each address did in the latest sweep of it this session, and the subnet's line sums it up.

## [1.3.0] - 2026-09-28

### Added

- IPAM server (for the Tribe: the people sharing your IPAM): the tribe's shared IPAM, run as the NOMAD IPAM Server Windows service on one machine (Tools > IPAM Server installs, updates, starts and removes it and opens port 8443 in the firewall), over HTTPS with a self-signed certificate that laptops pin. Laptops connect with a tribe key file and keep a copy of the tribe's networks for offline lookups, synced the moment anyone changes anything (each laptop keeps a request waiting at the server), with a sync every 5 minutes as a fallback and Sync Now; while online, their changes go straight to the server, which refuses conflicting ones (such as two people taking the same address) and says who got there first. Spreadsheets are imported, and tribe networks added or deleted, only on the server (NOMAD running as administrator there). Every change records the Windows user and computer; the server backs itself up nightly and keeps 14 days.
- The IP Addresses page shows Tribe and Local networks together, with the IPAM server's name and whether it's connected beside the Tribe button. On a laptop, importing a spreadsheet says plainly (on the button, in the import window and afterwards) that it stays on that computer and isn't shared with the tribe.

## [1.2.0] - 2026-09-27

### Added

- IP Addresses page (IPAM): networks kept separate (so air-gapped networks can reuse ranges), each with nested subnets and the addresses used or reserved in them, free addresses worked out rather than stored, Use Next Free, search across every network, and CSV export. Imports the team's addressing workbooks (.xlsx or .csv), asking which to keep wherever a page's summary and Detailed Info disagree, suggesting a gateway wherever the sheet's isn't in its subnet, importing an address written with a mask as the subnet holding it (172.28.101.0/16 is 172.28.0.0/16), and listing rows it can't use; the import window can go full screen; SNMP strings are never imported. Changes are logged with who made them, ready for syncing with a server later.
- Terminal page: an SSH, Telnet, serial and raw TCP client with saved sessions in folders, PuTTY import, tabs that pop out into their own windows, quick connect, select-to-copy and right-click paste, scrollback with find, session logging, and serial break. Saved passwords are encrypted for your Windows account, with an optional master password on top (AES-256, scrypt) that locks after a chosen idle time; host keys are remembered and changes flagged, and older switches that only support SHA-1 SSH algorithms still connect. Sweep and Ports open sessions here.
- SNMP page: walk or get any part of a device's MIB over SNMP v1/v2c, with presets (system, interfaces, IP and ARP tables, MAC address tables, LLDP neighbors, serial numbers) and an Interface Summary of each port's status, speed and error counters. Copy or export to CSV.
- DHCP Servers page: finds every DHCP server answering on the selected adapter's network and flags any besides the one this adapter's lease came from as a possible rogue, and shows every option each server's offer carries (NTP, WINS, static routes, TFTP and boot servers, vendor data and more). Only a request is sent; no address is taken.
- Packet Capture page: capture with Windows' built-in pktmon, filtered by address, port and protocol, and save a pcapng file for Wireshark (needs administrator rights).
- TFTP page: a TFTP server (with upload control and a live transfer list) and a TFTP client for downloading from and uploading to other servers.
- Syslog page: receive syslog over UDP (and optionally TCP), filter by severity or text, and save or log messages to a file.
- Network Reset page: flush DNS, clear ARP, renew all DHCP leases, reset Winsock and TCP/IP, view and turn off a leftover proxy (with Undo), and reset the WinHTTP proxy.
- Sweep's right-click menu can open a host on the SNMP and Packet Capture pages.

### Changed

- More room for terminal sessions: the session list is slimmer (one column, compact New and ⋯ menus) and can be hidden with « beside the tabs, with a Sessions menu in its place; View > Focus Mode (F11) hides the sidebar, adapter bar and status bar on any page; F11 makes a pop-out terminal window full screen.
- The tabs are now a sidebar of pages grouped into This Computer, Test, Discover, DNS & Web and Tools, so every page fits at any text size. Ctrl+Tab and Ctrl+Shift+Tab move between pages. Section headings are shaded bands so the groups stand out, and the sidebar can be hidden (the « button, View > Show Sidebar or Ctrl+B) to give pages more room, leaving a slim strip with a menu of every page.
- The Services tab is now two pages, DNS Servers and Web Check.
- The release steps (README and `python -m nomad.version bump`) now add new files before committing.

### Fixed

- Hiding the Terminal session list and then restarting NOMAD left no way to bring the list back. The list now always shows while no sessions are open.
- An SSH connection whose device hung up just before login could stay on "Connecting..." forever; it now fails straight away with an explanation.
- SSH logins to Cisco IOS XE (and other devices that allow only one "ssh-userauth" service request per connection) were reported as a wrong password even when it was right: the device disconnected before checking it. NOMAD now asks for the service once, as OpenSSH does, and says so plainly if a device does drop the connection during login.

## [1.0.1] - 2026-09-24

### Added

- Ports tab: check whether TCP ports on a host are open, closed or filtered, with presets from common ports up to all 65535. Open web, Remote Desktop and SSH ports straight from the results, or check a web port on the Services tab. Scan Ports is also on the Sweep and ARP tabs.
- ARP tab: the ARP and IPv6 neighbor tables with MAC vendors, warnings about possible ARP spoofing and duplicate IP addresses, and delete entry / clear cache.
- Connections tab: TCP connections and listening TCP/UDP ports with the program that owns each (like netstat -ano), with filtering and optional auto refresh.
- Switch Port tab: find the switch, port and VLAN an adapter is plugged into from LLDP/CDP announcements, using Windows' built-in pktmon (needs administrator rights).
- Services tab: compare DNS servers' response times (add your own, or remove any from the list) and check forward/reverse DNS; check a web server's timings, certificate and reply, following redirects.
- Utilities tab: subnet calculator with subnet splitting, and Wake-on-LAN with saved devices (also on the Sweep and ARP tabs' right-click menus).
- Diagnostics report (Tools > Run Diagnostics Report, Ctrl+R): checks the adapter, gateway, DNS, internet access, route, path MTU and ARP table and saves the findings as a web page.
- View > Text Size makes all text larger or smaller (90% to 200%), with Ctrl+= / Ctrl+- / Ctrl+0 shortcuts. The choice is remembered.
- Help > About is a proper About window with build and runtime details that can be copied.

### Changed

- Traceroute shows loss, latency and jitter for each hop like MTR, probes every hop at once, can keep running until stopped, and copies a text report.
- Sweep shows each host's MAC address, vendor and host name (DNS, or NetBIOS on networks without a DNS server), finds hosts that block ping by using ARP on local subnets, and includes these in the CSV export.
- The MAC vendor list is built in, so vendor lookups work offline. Everything in NOMAD works without internet access.
- The version shows in the title bar and the exe's file name (NOMAD-X.Y.Z.exe).

### Fixed

- After a change that switches an adapter to DHCP, NOMAD keeps checking for up to a minute until the new address arrives, instead of showing the adapter with no address.
- Tracing a host from the Sweep tab while a traceroute is running stops it and starts the new one, instead of refusing.

## [1.0.0] - 2026-09-24

- First versioned release: NIC Manager renamed to NOMAD, with Interfaces, Routing Table, MTU, Ping, Latency, Traceroute, iperf, DNS Lookup and Sweep tabs.
