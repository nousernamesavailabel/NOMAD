# Setting switches up for NOMAD

The **SNMP Config** page (under Network Management) builds the Cisco IOS / IOS-XE configuration a Catalyst switch needs for the [Network Map](network-map.md) and watching, and can type it in for you.

## What it sets up

### Read access

A read-only community string, an SNMPv3 user, or both, limited by a standard access list to the computers running NOMAD.

| Button | What it does |
| --- | --- |
| **Use the Map's Credentials...** | Uses the community strings and SNMPv3 users saved for the open map. Tick which ones (public, private and subnet-specific ones start unticked). Traps go with the first; the rest can read too. |
| **From the Map** | Fills in a single community string or v3 user the map already tries, with its protocols and passwords |
| **Generate** | Makes up a community string or passwords |
| **Add to Network Map** | Has the map try them |

**Generate SNMP Config**, in the map's **SNMP Credentials...** dialog and on its Watch tab, opens this page the same way.

A v3 user goes in a group that can also read the per-VLAN contexts (`context vlan- match prefix`), so the hosts on every VLAN are found.

### Where traps and syslog go

- This computer (**Add This Computer**) and the Map Watcher service's, with the interface they're sent from.
- Traps can be sent with v2c or as the v3 user.
- The traps the Map Watcher acts on (ports coming up, restarts, MAC address notifications) are ticked. Others can be added for the log.

### Access ports

An interface range to turn on link-status logging and MAC address notifications for. Configurations often turn link-status logging off on access ports, which hides a device being plugged in.

## Send it to the switch

1. Click **Send to Session** to pick a connected terminal session, shown with its prompt.
2. Or click **Open SSH Session** to open one from your saved sessions (in their folders) or a **New Session**. NOMAD waits for its prompt.
3. Confirm. NOMAD warns if the session isn't at the enable (#) prompt.
4. NOMAD types the configuration a line at a time, 150 ms apart so older switches don't drop characters, and shows the session so you can watch.

Other options:

- **Copy** and **Save As...** let you paste it yourself.
- **Show: Commands to take it out again** lists the lines that undo it.

## Check the result

On the switch:

```text
show snmp community
show snmp user
show snmp host
show logging
```

The form is remembered, with its passwords encrypted for your Windows account.
