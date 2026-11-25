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
| **Overview** | Counts of devices up, down, being checked and not monitored, the hosts seen in the last hour (the same number as the Hosts page), what's down now, recent events, each map, the hosts in each subnet on each map, the busiest links and the fullest subnets. A map's subnets are the ones its devices have addresses in. Click a count at the top to see what's behind it. **Down**, **Up**, **Checking / can't check** and **Not monitored** open the Devices page showing just those devices. **Hosts seen** opens the Hosts page, **Syslog errors** opens the Syslog page showing the devices that sent an error or worse, **NetFlow** opens the Traffic page at its NetFlow top talkers, and **Config changes to review** opens the Reviews page showing the changes to review or raised. |
| **Sites** | A tile for each site on each map. A site with a device down is red and lists the devices. Click a tile to open its map. |
| **Map** | The tribe map as NOMAD lays it out and draws it, in Physical (L2) or Logical (L3). Each device's outline shows its status once it's monitored. Its box shows its address and response time, how long it has been up or down, and its uptime over the last 24 hours. Links are colored by how busy they are. Tunnels are dashed. Drag to move around, use the mouse wheel to zoom, and click a device for its details. They are the same details NOMAD's Network Map shows, with the Map Watcher's status, the uptime over 24 hours, 7 days and 30 days, and when it was last checked. On the Logical (L3) view, click a subnet to see the devices and hosts in it. **Hide Details** gives the map the whole width. **Full Screen** gives it the whole screen; press Esc or **Exit Full Screen** to come back. |
| **Devices** | Every device with its status, its site, building and room, how long it has been that way, its response time, where it's checked from, and its uptime over 24 hours, 7 days and 30 days. A web server checked on a port says so in **Checked from** ("TCP 443"), with why it's down, or its warning in amber when it answers with a server error. Choose a status at the top right to show only those devices. Site, Building and Room are separate columns, so you can filter on each one with the funnel in its header. |
| **Events** | The last day: devices going down and coming back, new devices and hosts, links not seen lately, and failed config backups. |
| **Syslog** | How many syslog messages each device sent in the last day, by severity. Choose **Error or worse** or **Warning or worse** at the top right to show only the devices that sent one. The dashboard never shows the messages themselves. |
| **Traffic** | The traffic on each link and graphed port, as the Map Watcher last read it, and the NetFlow top talkers. |
| **VPNs** | Each tunnel and whether it's up, and the devices checked from routers with IP SLA. |
| **IPAM** | How full each subnet is, and when it was last swept. |
| **Hosts** | How many hosts each subnet has, from the maps, the sweeps and NetFlow. Choose the last 15 minutes, hour, day or week. Each host counts once, however many of these saw it. Switches, routers and other network devices on the maps don't count as hosts, and neither do hosts added to a map by hand. NetFlow only counts an address that sent something, so the addresses a sweep pings don't count unless they answer. |
| **Trends** | Graphs of a port's traffic and a subnet's hosts over time, and each device's uptime. A subnet's graph ends on the number the Hosts page shows for the last hour. |
| **Reviews** | The newest config changes and how each was reviewed in NOMAD's Editor: to review, approved, raised, explained, reverted, acknowledged or seen, who did it, when, the reason, how many blocks and how many were unexpected. Self-reviewed and quick reviews are flagged. Choose **To review or raised**, **Raised** or **Self-reviewed or quick** at the top right to show only those changes. The review log below lists every review, close and acknowledgement, with who made the change, who reviewed it, and the reviewers' notes on each block. The dashboard never shows the configuration lines. It needs the tribe server to run this version of NOMAD. |
| **What's New** | The same notes as **Help** > **What's New** in NOMAD: what each version added and fixed, newest first. The version the dashboard runs is marked. |

The dashboard updates itself within a few seconds of anything changing.

The dots at the top right show where the data comes from: the Map Watcher, the tribe, the Syslog Collector and the Flow Collector. Green is working. Red means it can't be read; hover over the dot to see why.

### Sorting and filtering tables

Every table sorts and filters the same way as the tables in NOMAD.

- Click a column's header to sort by it. Click it again to sort the other way.
- To show only some of a column's values, click the funnel at the left of its header, or right-click the header. Untick the values you don't want and click **OK**. Typing in the list's **Search** box ticks only the values that match. The list also has **Sort A to Z** and **Sort Z to A**, **Clear Filter**, and **Clear All Filters**.
- A filtered column's funnel is green. Filters on several columns work together, and each column's list only offers the values the other filters leave showing.
- A table with more than a few rows also has a **Filter** box above it. It shows only the rows that have every word you type, in any column.
- **Clear Column Filters** above the table removes all of the column filters at once.

Filters stay in place while the page updates itself, until you change them or reload the page.

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

To keep one page up without switching, list only that page. For example, `#kiosk?pages=map&map=<number>` shows just that map. Without `&map=`, it shows the first map. The page still updates itself as things change, and a device you click stays selected. To stop the switching with more than one page listed, use `every=0`, and only the first page is shown.

The tables can still be sorted and filtered in kiosk mode. While a column's filter list is open, the page stays up until the list is closed.

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
