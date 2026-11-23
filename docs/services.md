# Services and firewall

Some NOMAD features run as Windows services, so they keep working when nobody has NOMAD open. Others need a port open in Windows Firewall so devices can reach this computer. **Tools** > **Services & Firewall...** shows all of them in one place. From there you can install, start, stop and remove the services, and open, fix or remove NOMAD's firewall rules.

Each service and page can still be set up on its own, as before. This window is a shortcut to all of them, and a way to check that nothing is missing.

## The services

| Service | What it does | Install it on |
| --- | --- | --- |
| **Tribe Server** | Shares the tribe's IP addresses, VLANs, assets and network maps with NOMAD on every laptop. See [IPAM and the tribe](ipam-and-tribe.md). | One computer that's always on. |
| **Syslog Collector** | Keeps every syslog message devices send, for everyone using NOMAD on the computer. See [Syslog](syslog.md). | The computer the devices send syslog to. |
| **Flow Collector** | Keeps the NetFlow and IPFIX routers send, for everyone using NOMAD on the computer. See [NetFlow](netflow.md). | The computer the routers send flows to. |
| **Map Watcher** | Watches the tribe's maps for new switches, access points and hosts, and runs the scheduled config backups. It can also monitor the maps for the dashboard. See [Network map](network-map.md). | A computer that's always on and can reach the switches. It needs a tribe. |
| **NOMAD Dashboard** | A read-only web site showing the network's state to people without NOMAD. See [NOMAD Dashboard](dashboard.md). | The computer with the Map Watcher and the collectors. It needs a viewer key from the tribe server. |

A laptop usually needs none of them. On a server several people use over Remote Desktop, install the collectors instead of using Start Listening or Collect Here, because only one program can listen on each port.

## Set up a computer

Installing services and changing firewall rules needs administrator rights. Without them, the window shows everything but changes nothing, and offers **Restart as Administrator**.

1. Start NOMAD as administrator (**File** > **Restart as Administrator**).
2. Open **Tools** > **Services & Firewall...**
3. Tick each service this computer should run.
4. Click **Install or Update Ticked**. NOMAD lists what it will do and asks you to confirm.
5. When the **Tribe Server**, **Map Watcher** or **NOMAD Dashboard** window opens, set it up there and click **Install Service**, then close that window. NOMAD carries on with the next service.
6. Look at the firewall list. If any rule says **Missing** or **Needs fixing**, click **Fix All**.

The services are installed in this order: Tribe Server, Syslog Collector, Flow Collector, Map Watcher, NOMAD Dashboard. The Map Watcher needs the tribe, so it goes after the Tribe Server. The dashboard reads all the others, so it goes last. The Syslog Collector goes before the Map Watcher so it has UDP 514 first, and the Map Watcher then reads syslog from it.

The Syslog Collector and Flow Collector are installed with their usual settings, or the settings they had before. To change the port or how long they keep data, select the service and click **Set Up...**

## Manage one service

Select a service in the list, then:

- **Set Up...** opens its own window, the same one as its **Tools** menu item. You can also double-click it.
- **Start** and **Stop** start or stop it.
- **Uninstall...** stops and removes it, along with its firewall rules. Its data stays in its folder, so installing it again carries on where it left off.
- **Open Its Folder** opens the folder it keeps its data in. Only administrators can open it.

**Start All** and **Stop All** act on every installed service. **Uninstall Ticked...** removes the ticked ones.

The status of each service updates every few seconds.

## Keep the services up to date

The **Version** column shows which NOMAD each running service runs. It says **update** when a service runs an older NOMAD than the one you have open, or was started before the code it runs changed. When NOMAD runs from source, only a change to a file that service uses counts.

NOMAD also shows a banner across its window when a service on this computer needs updating. To update them:

1. Start NOMAD as administrator.
2. Click **Update Now** on the banner.

Each service is updated with the settings it has, and no service's window opens. A window shows each service as it's updated, and says why if one couldn't be. Click **Hide** to close it while the update carries on. You can also update a service in **Tools** > **Services & Firewall...**: select it and click **Update**, or tick several and click **Install or Update Ticked**.

**Dismiss** hides the banner until another service needs updating.

## Firewall rules

The firewall list shows every rule NOMAD makes, what uses it, and the port and protocol it should allow. A service's rule follows the port in that service's settings. A page's rule follows the port set on that page now.

| State | What it means |
| --- | --- |
| **Open** | The rule is there and allows the right port. |
| **Not open** | There's no rule. That's fine until you use the page or install the service. |
| **Missing** | The service is installed, but its rule isn't there, so Windows Firewall may block it. |
| **Needs fixing** | The rule allows another port, or lacks a protocol, or was changed to block. |
| **Turned off** | The rule is there but turned off in Windows Firewall. |
| **Left over** | The service isn't installed, or the rule is under NOMAD's old name (NIC Manager). |
| **Not NOMAD's** | The rule's name starts with NOMAD, but NOMAD didn't make it. It may have been made by hand or by another version. |

To change rules:

1. Tick one or more rules.
2. Click **Open Ticked** to allow the ports their services or pages use now. A rule that's already there is replaced.
3. Click **Remove Ticked...** to delete the ticked rules.

**Fix All** opens every rule that's missing, turned off or on the wrong port. **Remove Left Over** deletes the rules of services that aren't installed, and rules under the old name. **Check Again** reads Windows Firewall again.

The window also warns you when the rules can't do their job:

- **Group Policy ignores rules made on this computer.** NOMAD's rules then let nothing through. Ask whoever manages Group Policy to allow NOMAD's ports.
- **Windows Firewall blocks all incoming connections.** This setting overrides every allow rule. Turn it off in **Windows Security** > **Firewall & network protection**.
- **Windows Firewall is off for the network this computer is on.** Nothing is blocked there, so the rules only matter when it's on, or on another network.

## Ports NOMAD uses

| Rule | Used by | Port |
| --- | --- | --- |
| NOMAD IPAM Server | Tribe Server service | TCP 8443 |
| NOMAD Syslog Collector | Syslog Collector service | UDP 514, and TCP 514 if **Also TCP** is ticked |
| NOMAD Flow Collector | Flow Collector service | UDP 2055 |
| NOMAD Map Watcher syslog | Map Watcher service | UDP 514 |
| NOMAD Map Watcher traps | Map Watcher service | UDP 162 |
| NOMAD syslog | Syslog page | UDP 514 |
| NOMAD NetFlow | NetFlow page | UDP 2055 |
| NOMAD TFTP server | TFTP page | UDP 69 |
| NOMAD DHCP test | DHCP Servers page | UDP 68 |
| NOMAD-iperf-server | iperf page, as a server | TCP and UDP 5201 |

These are the usual ports. If you change a port in a service or on a page, its rule follows.
