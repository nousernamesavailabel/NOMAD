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

## The config archive

The archive keeps a copy of each device's configuration whenever it changes. A pull that's the same as the last copy (noise aside) only records when the device was checked.

- With a tribe, the archive is on the tribe server and everyone sees the same history. A configuration pulled while the server can't be reached waits and is sent when the server is back.
- Without a tribe, the archive is kept on this computer.

The **Archive** tab lists the devices. Open a device to see its versions. Double-click a version to open it. Right-click for more:

- Compare with the copy before, with the newest, or select two versions and compare them.
- **Commands to Put This Version Back** writes the commands that take the device back to that version.
- **Pull Config Now** and **Running vs Startup** read the device over SSH.
- **Leave Out of Scheduled Backups** leaves the device out.

**Pull Config...** reads a device. Pick it from the list (the open map's routers, switches, firewalls and WLCs, the archive's devices and your saved SSH sessions), or type its address or name. NOMAD logs in with the device's saved SSH session, or the login on the **Backups** tab.

## Review changes

The **Changes** tab lists the newest changes first. Changes that nobody has reviewed are bold, and the device gets an amber **CFG** tag on the Network Map. Double-click a change to compare it with the copy before it. That marks it reviewed for everyone.

**Changed by** comes from the device. NOMAD reads `! Last configuration change at ... by user` from the running-config. On IOS without a user there, it reads `show archive log config all` when archive logging is on. pfSense gives the user of its last save.

Devices that no computer has backed up for two intervals are listed as overdue, with each computer's reason.

## Scheduled backups

Every router, switch, firewall and WLC on the tribe maps that has a management address is backed up once a day (or the interval you set on the **Backups** tab). Without a tribe, the devices on the open map are backed up. Backups are spread over the day.

To have this computer run backups:

1. Go to the **Backups** tab.
2. Choose the login for devices without a saved SSH session. It needs a saved password.
3. Tick **Run scheduled config backups on this computer**.

Backups run while NOMAD is open. With a tribe, every computer that has this ticked shares the work. The server hands out a few due devices at a time, so two computers never back up the same device. If a computer can't reach a device or log in to it, the device goes to another computer.

The Map Watcher service can run backups too, with nobody signed in. In **Tools** > **Map Watcher Service**, tick **Run the tribe's scheduled config backups** and choose a saved credential. The service gets the due devices first.

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
