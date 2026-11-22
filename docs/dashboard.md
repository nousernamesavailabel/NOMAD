# NOMAD Dashboard

The NOMAD Dashboard is a web site that shows the state of the network to people who don't have NOMAD. They open it in a browser, sign in, and see which devices are up or down, what has happened lately, how busy the links are, the VPNs, how full the subnets are, how many hosts each subnet has, the tribe's maps, and trends over time.

The dashboard only shows things. Nobody can change anything from it, and it never asks the network anything itself. Everything it shows comes from NOMAD's other services on the same computer, and from the tribe.

## What it needs

The dashboard runs as a Windows service. Install it on the computer that runs these:

| Service | What the dashboard gets from it |
| --- | --- |
| **Map Watcher** | Whether each device is up or down, link and port traffic, tunnel status, and the IPAM sweeps. Tick **Monitor the watched maps** in its window. |
| **Syslog Collector** | How many syslog messages each device sent in the last day, by severity. The dashboard never shows the messages themselves. |
| **Flow Collector** | Top talkers, destinations, applications and conversations, and the addresses seen in the flows. |
| **Tribe Server** (anywhere on the network) | The tribe's maps, IP addresses and backup results, read with a viewer key. |

The dashboard still works without the collectors, but those parts of it stay empty. Without the Map Watcher it can't show devices up or down.

## Set it up

### 1. Save a viewer key on the tribe server

A viewer key lets the dashboard read the tribe and nothing else. It can't change the tribe, and the tribe server never gives it the maps' SNMP credentials or the saved configs.

1. On the tribe server, start NOMAD as administrator.
2. Open **Tools** > **Tribe Management...**
3. Click **Save Viewer Key File...** and save the file.
4. Copy the file to the dashboard's computer.

If the dashboard runs on the tribe server itself, you can skip this and use **Make One Here** in step 3 instead.

### 2. Turn on monitoring in the Map Watcher

1. On the dashboard's computer, open **Tools** > **Map Watcher Service...**
2. Tick the maps to watch.
3. Under **Monitoring for the Dashboard**, tick **Monitor the watched maps**.
4. Choose how often to ping, how often to read link traffic, and how often to sweep the IPAM subnets.
5. Click **Install Service** (or **Update Service**).

The Map Watcher only monitors the maps it watches. The dashboard shows the other tribe maps too, but their devices show as **Not monitored**.

NOMAD's Network Map shows the Map Watcher's monitoring too, with the same up and down times and uptime as the dashboard. The Map Watcher works them out, and both show them as they are. The Monitor tick box in NOMAD also pings from the computer NOMAD is open on. Its results show in the details pane under **This computer**.

The Map Watcher can also monitor maps that aren't shared with the tribe. Add them under **Maps on This Computer** in its window. The dashboard shows them with the tribe's maps.

### 3. Install the dashboard

1. On the dashboard's computer, start NOMAD as administrator (**File** > **Restart as Administrator**).
2. Open **Tools** > **NOMAD Dashboard Service...**
3. Click **Choose Viewer Key File...** and pick the file from step 1.
4. Change the **HTTPS port** if you need to. The default is 8444.
5. Choose how long to keep history.
6. Click **Install Service**.
7. Under **Logins**, click **Add...** and make a login for each person who'll use it.

The service opens its port in Windows Firewall. People then browse to `https://<computer name>:8444/` and sign in.

## Logins

Each person signs in with their own login name and password. Logins are only for the dashboard. They aren't Windows accounts or NOMAD credentials.

- **Add...** makes a login. Passwords need at least 8 characters.
- **New Password...** changes a login's password. It's signed out everywhere.
- **Kiosk On/Off** makes a login a kiosk login (see below).
- **Remove...** deletes a login. It's signed out everywhere.

Changes to logins work at once, with no restart.

After 5 wrong passwords in a row, that login and that computer have to wait 5 minutes before trying again. An ordinary login is signed out after 12 hours without being used.

## The certificate

The dashboard uses HTTPS. When it's installed it makes a self-signed certificate for the computer. Browsers warn about a self-signed certificate until you tell them to trust it. The dialog shows its SHA-256 fingerprint, so you can check it's the right one.

To avoid the warning, use a certificate from your company's certificate authority:

1. Get a certificate for the dashboard's computer name, with its private key, as a PFX/P12 file or PEM files.
2. In **Tools** > **NOMAD Dashboard Service...**, click **Import Certificate...**
3. Pick the file. If the key is in a separate file, NOMAD asks for that too.
4. Type the password, or leave it empty if there isn't one.

The service restarts with the new certificate. **Use Self-Signed** goes back to a self-signed one.

## The pages

| Page | What it shows |
| --- | --- |
| **Overview** | Counts of devices up, down, being checked and not monitored, what's down now, recent events, each map, the busiest links and the fullest subnets. |
| **Sites** | A tile for each site on each map. A site with a device down is red and lists the devices. Click a tile to open its map. |
| **Map** | The tribe map as NOMAD lays it out and draws it, in Physical (L2) or Logical (L3). Each device's outline shows its status once it's monitored. Its box shows its address and response time, how long it has been up or down, and its uptime over the last 24 hours. Links are colored by how busy they are. Tunnels are dashed. Drag to move around, use the mouse wheel to zoom, and click a device for its details. They are the same details NOMAD's Network Map shows, with the Map Watcher's status, the uptime over 24 hours, 7 days and 30 days, and when it was last checked. On the Logical (L3) view, click a subnet to see the devices and hosts in it. **Hide Details** gives the map the whole width. **Full Screen** gives it the whole screen; press Esc or **Exit Full Screen** to come back. |
| **Devices** | Every device with its status, how long it has been that way, its response time, where it's checked from, and its uptime over 24 hours, 7 days and 30 days. |
| **Events** | The last day: devices going down and coming back, new devices and hosts, links not seen lately, and failed config backups. Below that, how many syslog messages each device sent, by severity. |
| **Traffic** | The traffic on each link and graphed port, as the Map Watcher last read it, and the NetFlow top talkers. |
| **VPNs** | Each tunnel and whether it's up, and the devices checked from routers with IP SLA. |
| **IPAM** | How full each subnet is, and when it was last swept. |
| **Hosts** | How many hosts each subnet has, from the maps, the sweeps and NetFlow. Choose the last 15 minutes, hour, day or week. Each host counts once, however many of these saw it. |
| **Trends** | Graphs of a port's traffic and a subnet's hosts over time, and each device's uptime. |

The dashboard updates itself within a few seconds of anything changing.

The dots at the top right show where the data comes from: the Map Watcher, the tribe, the Syslog Collector and the Flow Collector. Green is working. Red means it can't be read; hover over the dot to see why.

### Downloading and printing

Most pages have **Download CSV** for their table. **Print** prints the page. To save it as a PDF, choose **Save as PDF** in the browser's print window.

## Graph more ports

The Map Watcher reads the traffic on the ports at both ends of every link on the map. To graph other ports too, such as a server's port or an internet uplink:

1. Open the map on NOMAD's **Network Map** page.
2. Right-click the switch or router and choose **Tools** > **Ports to Graph...**
3. Tick the ports to graph. Link ports are always graphed.
4. Click **OK**.

The Map Watcher starts reading them on its next round. NOMAD's [Traffic Graphs](network-map.md#traffic-graphs) page shows the same readings, and its **Keep Its History** box ticks one port the same way.

On the map page, a device's details have a **Graph** link beside each port the Map Watcher reads. It opens that port on the Trends page.

## Kiosk mode for a wall screen

Kiosk mode hides the menus and goes through chosen pages in turn.

1. In **Tools** > **NOMAD Dashboard Service...**, add a login and tick **Kiosk**. A kiosk login stays signed in for a year.
2. On the wall screen's computer, open `https://<computer name>:8444/` and sign in with that login.
3. Change the address to `https://<computer name>:8444/#kiosk?pages=overview,sites,map&every=30`.

`pages` lists the pages to show, and `every` is how many seconds each one stays up. To show one map in the rotation, add `&map=<number>`, using the number from the map page's address.

## History

The dashboard keeps its own history, for the Events page and the trend graphs. Uptime comes from the Map Watcher, which keeps a year of up and down history itself. In **Tools** > **NOMAD Dashboard Service...**:

- **Samples** is how long every reading is kept (30 days by default).
- **hourly** is how long hourly averages and peaks, and the up and down events, are kept (a year by default).
- **at most** is the most space the history can take. Past that, the oldest samples go first.

When the Map Watcher restarts, it picks up where it left off. The time it wasn't running is shown on the **Events** page and doesn't count against anyone's uptime. A "+" after how long a device has been up or down means it has been that way at least that long. If the Map Watcher stops checking for ten minutes or more, the devices are grayed and say "Not checked since" and the time it last checked, as they do in NOMAD.

## Troubleshooting

**The browser can't connect.** Check the service is running in **Tools** > **Services & Firewall...**, and that the **NOMAD Dashboard** firewall rule is **Open**.

**Every device says Not monitored.** The Map Watcher isn't monitoring on this computer. Install it here with **Monitor the watched maps** ticked, and tick the maps.

**A collector shows as from an older NOMAD.** Update that service from this version of NOMAD (**Tools** > **Services & Firewall...**, select it, **Set Up...**, **Update Service**).

**The tribe dot is red.** The dashboard can't reach the tribe server, or its viewer key was changed. Save a new viewer key on the tribe server and choose it again.

The service's log is `dashboard.log` in `%ProgramData%\NOMAD\dashboard`. Only administrators can open that folder.
