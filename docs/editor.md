# Editor

The **Editor** page (under Utilities) is a text editor for configurations, like Notepad++. It compares two configurations side by side, and it keeps a config archive: every change to each device's configuration, with who changed it.

**On this page**

- [Edit files](#edit-files)
- [Compare](#compare)
- [Fix commands](#fix-commands)
- [The config archive](#the-config-archive)
- [Review changes](#review-changes)
- [Scheduled backups](#scheduled-backups)
- [Standards](#standards)
- [From other pages](#from-other-pages)

## Edit files

Open files with **Open...** (Ctrl+O), or drag them onto the NOMAD window. Each file opens in its own tab. Tabs aren't reopened the next time NOMAD starts, so NOMAD asks about unsaved changes when you close a tab or NOMAD.

The editor colors Cisco configurations and folds each mode (an interface, `router bgp`, a `line`) with the boxes in the margin. pfSense configs are colored as XML. **Highlight** changes the coloring for a tab.

| Key | What it does |
| --- | --- |
| Ctrl+N / Ctrl+O / Ctrl+S | New tab / open / save |
| Ctrl+Shift+S | Save as a file |
| Ctrl+F4 | Close the tab |
| Ctrl+F / Ctrl+H | Find / find and replace |
| F3 / Shift+F3 | Find next / previous |
| Ctrl+G | Go to a line |
| Alt+drag | Select a column. Typing goes into every line of it. |

Find and replace takes regular expressions. Tick **Regular expression**, then use `\1` in the replacement for the first group. **Replace All** is one step to undo. **Count** says how many matches there are.

## Compare

Use **Compare** to compare:

- this tab with another tab
- this tab with a file
- two files
- this tab with a version you selected in the Archive
- a device's running-config with its startup-config
- a device's running-config with this tab

The two sides scroll together. Blank space keeps the matching lines across from each other. Added lines are green, removed lines are red, changed lines are amber, and blocks that only moved are blue. The strip on the right shows where the changes are, and a click on it goes there. **Next** (F7) and **Prev** (Shift+F7) step through the changes, and the bar says which mode each change is in.

Choose how to compare:

| Mode | What it does |
| --- | --- |
| Plain text | Line by line, like Notepad++. |
| Hide noise | The same, but leaves out lines that change without anyone changing the config: `Building configuration...`, `Current configuration : 1234 bytes`, `! Last configuration change at ...`, `ntp clock-period`, ASA checksums and certificate data. They're shown faint. |
| Section-aware | Compares by mode. A block that moved isn't shown as removed and added, and `switchport access vlan 10` changing to `20` is one change, not two. |

Both sides can be edited. The arrows in the margin copy a change to the other side, and the comparison updates as you type. **Inline** shows both sides in one pane with - and + lines. **Swap Sides** swaps the left and right sides.

## Fix commands

**Fix Commands** in a comparison writes the Cisco commands that make one side like the other. It works for IOS, IOS XE, NX-OS and ASA.

- A line that's only on the wanted side is typed in its mode.
- A line that's only on the current side is removed with `no`.
- A line that replaces another, such as a description, is typed on its own.
- A physical interface is never removed. Its lines are removed instead.
- An ACL's changed rules are removed first and then added, so a rule can take another rule's number.

The commands open in a new tab. Check them, then **Copy** them, save them, or click **Send to Device...**. Sending types them in configuration mode and stops at the first line the device refuses. On IOS it can use the revert timer: the device puts its old configuration back unless NOMAD can log in again afterward. It can also save to the startup-config and pull the new running-config into the archive.

**Send to Device...** doesn't ask which device when NOMAD can tell. A tab of fix commands, an archived copy, or a Compare side goes to the device it came from. Any other tab goes to the device its `hostname` line names, if that device is on the map, in the archive or a saved SSH session. The dialog shows the device. Click **Change...** to pick another one from the same list as **Pull Config...**: the open map's routers, switches, firewalls and WLCs, the archive's devices and your saved SSH sessions. Type to search the list, or type an address. When NOMAD can't tell the device, the list is shown straight away.

## The config archive

The archive keeps a copy of each device's configuration whenever it changes. A pull that's the same as the last copy (noise aside) only records when the device was checked.

- With a tribe, the archive is on the tribe server and everyone sees the same history. A configuration pulled while the server can't be reached waits and is sent when the server is back.
- Without a tribe, the archive is kept on this computer.

The **Archive** tab lists the devices. Open a device to see its versions. Double-click a version to open it. Right-click for more:

- Compare with the copy before, with the newest, or select two versions and compare them.
- **Commands to Put This Version Back** writes the commands that take the device back to that version.
- **Pull Config Now** and **Running vs Startup** read the device over SSH.
- **Leave Out of Scheduled Backups** leaves the device out.
- **Merge Into...** and **Forget...** are there for devices that are no longer on a map. See [Old addresses](#old-addresses).

When two devices in the list have the same name, the address is shown after the name. A device that's no longer on a map shows **Not on a map** in the Status column.

### Old addresses

The archive keeps each device under its management address. When that address changes on the map, for example a DHCP address that changed or a move to the loopback, NOMAD moves the old entry's copies to the new one. It does this when the old entry has the same name as the device on the map, or its address is still one of that device's addresses.

To clean up an entry by hand:

1. Right-click it in the **Archive** list. Select several to do them together.
2. Choose **Merge Into...** to move the saved copies to another device. A device on the map with the same name is offered first.
3. Or choose **Forget...** to remove the entry and its copies. This can't be undone.

Both only work on devices that are no longer on a map. A device on a map would come straight back. With a tribe, the tribe server needs this version of NOMAD.

**Pull Config...** reads a device. Pick it from the list (the open map's routers, switches, firewalls and WLCs, the archive's devices and your saved SSH sessions), or type its address or name. NOMAD logs in with the device's saved SSH session, or the login on the **Backups** tab.

## Review changes

The **Changes** tab lists the newest changes first. Changes that still need a review are bold, and the device gets an amber **CFG** tag on the Network Map. The **Review** column shows where each change stands.

Opening a change doesn't review it. To review a change:

1. Double-click it on the **Changes** tab. It opens beside the copy before it, in section-aware Compare with noise left out. Both sides are read-only, and the compare mode can't be changed while you review.
2. NOMAD goes to the first block of the change. A block is one run of lines removed, added or changed in one place. The bar above the two sides says which block you're on, its line numbers and where it is. In the margin of both sides, an arrow points at the block's first line and a bar runs beside the rest of its lines. If the block only removes lines, the arrow on the right side shows where they were.
3. Read the block, then press **Space** if it was meant to happen (Expected) or **U** if it shouldn't be there (Unexpected). NOMAD goes on to the next block. A block only counts if it's on the screen when you mark it. If you scrolled away, NOMAD shows it again first.
4. If a block is marked **Sensitive**, it touches a line such as a user, AAA, an SNMP community, crypto, the VTY lines or the default route. It needs a note before you can mark it. Press **N** to add a note to any block.
5. When every block has a verdict, click **Finish Review...** and give a reason. If every block was expected, give the ticket number or say why the change was made, and the change is **Approved**. If any block was unexpected, say what's wrong, and the change is **Raised**.

A raised change stays bold, and stays flagged on the map, until someone closes it. Open it and click **Close as Explained...** if the change is all right after all, or **Close as Reverted...** once it has been put back. **Commands to Undo It...** writes the commands that take the device back to the copy before the change. When a later backup shows the unexpected lines gone, NOMAD closes the change as Reverted by itself.

Changes to the same device are reviewed oldest first. If you open a newer one, NOMAD offers to open the older one instead.

When NOMAD sent the lines itself, from the ACLs, VPNs, Port Mirroring, Carry VLAN, NetFlow Config or Editor pages, the bar says who sent them and from which page. That block looks expected, but you still mark it yourself.

A review is labeled **self-reviewed** when your device login made the change, or one of your own pushes typed it. It's labeled **quick** when it took less than a second per block on a change with three or more blocks. Neither stops the review. Both show in the review log and on the NOMAD Dashboard.

Changes that an older version of NOMAD opened before reviews were kept show as **Seen**. They can still be reviewed properly.

The **Reason** column on the **Changes** tab shows why each change was approved, or why it was raised and how it was closed. Hover over the reason to see who did what and when, and the note on each block.

**Reviews** > **Review Log...** lists every review, close and acknowledgement, newest first. Each row shows who made the change (**Changed by**, the login the device names as the last to change its configuration, as on the **Changes** tab) and who reviewed or closed it (**Who**), with the reason, the number of blocks and unexpected blocks, how long it took, the self-reviewed and quick flags, and the block notes. Type in the box at the top, or use the funnel in a column's header, to show only some of them. Double-click one to open its change.

**Reviews** > **Export Review Log...** saves every review, close and acknowledgement as a workbook or CSV, with who made the change, who reviewed it, when, the reason, how long it took and each block's note.

**Reviews** > **Review Settings...** has two settings. With a tribe, they apply on every computer.

- **Allow Acknowledge Without Review** is off unless you turn it on. When it's on, **Acknowledge Without Review...** on the **Changes** tab clears every change still to review, for example after a planned maintenance window. It needs a reason, and the changes are kept as **Acknowledged**, never as reviewed.
- **Sensitive lines** is the list of regular expressions that make a block sensitive. **Defaults** puts back NOMAD's own list.

With a tribe, reviews need the tribe server to run this version of NOMAD. On an older server, NOMAD offers to mark the change reviewed the old way, which shows as **Seen**.

**Changed by** comes from the device. NOMAD reads `! Last configuration change at ... by user` from the running-config. On IOS without a user there, it reads `show archive log config all` when archive logging is on. pfSense gives the user of its last save.

Devices that no computer has backed up for two intervals are listed as overdue, with each computer's reason.

## Scheduled backups

Every router, switch, firewall and WLC on the tribe maps that has a management address is backed up once a day (or the interval you set on the **Backups** tab). Without a tribe, the devices on the open map are backed up. Backups are spread over the day.

To have this computer run backups:

1. Go to the **Backups** tab.
2. In **Log in with**, choose the login for devices without a saved SSH session. It needs a saved password.
3. If devices log in at the > prompt, type the **Enable password**. It's saved on this computer and protected by the master password.
4. Tick **Run scheduled config backups on this computer**.

The **Backups** tab is the only place to set how backups log in. NOMAD's own backups, **Pull Config** and the Map Watcher service all use the same logins.

Backups run while NOMAD is open. The box stays ticked the next time NOMAD starts. If the master password is locked then, backups wait and start as soon as you unlock it. With a tribe, every computer that has this ticked shares the work. The server hands out a few due devices at a time, so two computers never back up the same device. If a computer can't reach a device or log in to it, the device goes to another computer.

The Map Watcher service can run backups too, with nobody signed in. In **Tools** > **Map Watcher Service**, tick **Run the tribe's scheduled config backups**. The service gets the due devices first. It logs in the same way as the **Backups** tab says, and its window shows what that is. The service can't read your saved sessions, so NOMAD copies in the logins it needs, with the passwords encrypted for that computer. These are the usual login, each device's own login, and the login of each device's saved SSH session.

When you change a login on the **Backups** tab, NOMAD gives the service the change straight away. It also looks for changed saved sessions and credentials when it starts and while the **Backups** tab is open. If the master password is locked, the **Backups** tab shows a link to update the service. Updating the service needs NOMAD running as administrator.

Saved passwords are encrypted for the Windows account that saved them. If your saved sessions came from another computer, their passwords can't be read on this one. A backup that needs one says which session it is, and the **Backups** tab lists the ones the service couldn't get. Open each session on this computer and type its password again. Until then, the service uses the usual login for those devices.

### Palo Alto firewalls

NOMAD backs up a Palo Alto (PAN-OS) firewall as set commands, one setting per line, so **Compare** shows exactly what changed. It turns the pager off and runs `show config running`. The login needs an admin role that's allowed the CLI. There's no enable password on PAN-OS. NOMAD doesn't write fix commands for PAN-OS.

### Devices that need a different login

Some devices may not take the usual login, such as a branch router with its own local account. To give a device its own login:

1. On the **Backups** tab, click **Device Logins...** Or right-click devices in the **Archive** and choose **Log In With...**
2. Select the devices. The **Logs in with** column shows what each device uses now: its own login, its saved session, or the usual login. The **Last problem** column shows which ones couldn't be backed up and why.
3. Choose a saved credential and click **Use for Selected**. Only credentials with a saved password are listed.
4. Click **OK**.

A device's own login comes first, then its saved SSH session, then the usual login. **Pull Config** uses it too.

The Map Watcher service gets the device logins too, as soon as you click **OK**.

To leave a device out, right-click it on the map, then **Config** > **Leave Out of Scheduled Backups**.

To see how backups are going:

- The **Archive** tab shows each device's last backup and when the next one is due.
- **Who's backing up** on the **Backups** tab lists the computers running backups now: NOMAD windows and the Map Watcher service. For each, it shows what it's working on, how its last round went, and when it last asked for work. It refreshes every half minute while the tab is open.
- **Recent backups** below it lists the last 500 scheduled backups from every computer, the Map Watcher service included. For each, it shows when it ran, the device, which computer did it, and whether the config changed, was the same, or couldn't be read (and why).

To back up sooner than scheduled, right-click devices in the Archive and choose **Back Up Now (Scheduled)**, or click **Back Up Everything Now** on the **Backups** tab. The devices become due at once, and the computers running backups take them a few at a time. After that, each device keeps its usual interval.

## Standards

A standard lists the lines every device of a kind must have. Write it like a configuration:

```
! STANDARD: Access switch baseline
! applies-to: kind=switch group=Main Campus name=^SW-
hostname {{hostname}}
ntp server 10.1.0.10
no ip http server
~ ^snmp-server community \S+ RO \S+$
line vty 0 4
 transport input ssh
~ ^interface GigabitEthernet1/0/
 spanning-tree portfast
```

- A plain line must be there, in its mode.
- A `no` line must not be there the other way. `no ip http server` passes when the device shows `no ip http server` or has no `ip http server`.
- A `~` line is a regular expression that some line must match. As a mode line, the lines under it are checked in every mode it matches. `~` lines are only reported, because there's no one right line to type.
- `{{hostname}}`, `{{mgmt_ip}}`, `{{kind}}`, `{{platform}}`, `{{site}}`, `{{building}}` and `{{room}}` are filled in for each device from the map.
- `applies-to` picks the devices: `kind=` and `platform=` take lists, `group=` is a site, building or room, and `name=` is a regular expression. Without it, the standard is for every device.

To make one:

1. On the **Standards** tab, click **New**.
2. Edit the standard and press Ctrl+S to save it to the archive.

Every archived device it applies to is checked, and so is every copy that arrives after. The table shows how each device stands. Double-click a row for what fails and the commands that fix it. That tab can be sent to the device as it is.

**Check...** checks the devices you choose now. To check a device that isn't in the archive against a standard file, open the file and use **Compare** > **A Device's Running vs This Tab...**.

## From other pages

- **Network Map:** right-click a router, switch, firewall or WLC, then **Config**. Pull Config, Compare with Last Copy, Running vs Startup, Review the Change, History, Check Against Standard and Leave Out of Scheduled Backups are there.
- **Terminal:** **Save Config...** also puts the running-config in the archive. Right-click the session tab, then **Open Saved Config in Editor**.
- **TFTP:** right-click a transfer for **Open in Editor**, **Compare With...** and **File in Config Archive...**.
- **ACLs & Route Maps**, **VPNs**, **Carry VLAN** and **SNMP Config:** **Show as Diff** compares the device's running-config with how it would look after the change. The "after" side is worked out by NOMAD, so it's close but the device has the last word. Carry VLAN and SNMP Config use the archive's copy from today, or offer to pull one.
