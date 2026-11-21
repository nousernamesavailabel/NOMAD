# NetFlow

The **NetFlow** page (under Capture & Logs) shows who and what is using each router interface. It reads the flows Cisco routers send with Flexible NetFlow: the top talkers, destinations, conversations and applications on an interface, and its rate in and out. The **NetFlow Config** page (under Network Management) builds the router configuration that sends those flows to NOMAD.

The flows are about a minute behind, because a router sends a flow that's still going once a minute. So the live rate beside them comes from the interface's SNMP counters every 5 seconds, read with the Network Map's SNMP credentials.

## Where the flows are collected

Routers send their flows to one address and UDP port (2055). Only one program on a computer can listen on that port. There are two ways to collect:

| | When to use it |
| --- | --- |
| **Collect Here** (NetFlow page) | On your own computer. NOMAD listens only while it's open. |
| **Flow Collector service** (Tools > Flow Collector Service...) | On a server several people use over Remote Desktop, or any computer that should collect all the time. Everyone using NOMAD on that computer sees the same flows, without administrator rights. |

On a shared server, don't use Collect Here: the first person to click it would have the port, and everyone else would see nothing. Install the service instead.

### Install the Flow Collector service

The service needs administrator rights to install. After that, NOMAD reads it in every session on the computer.

1. Start NOMAD as administrator (**File** > **Restart as Administrator**).
2. Open **Tools** > **Flow Collector Service...**
3. Check the UDP port, how long to keep each flow (2 hours by default) and how long to keep the minute summaries (14 days by default).
4. Click **Install Service**. It opens the port in Windows Firewall and starts.

You can also install it from **Tools** > **Services & Firewall...** with its usual settings, along with NOMAD's other services. See [Services and firewall](services.md).

The NetFlow page uses the service whenever it's running. Its flows are kept in `%ProgramData%\NOMAD\flows`, which only administrators can open. NOMAD reads them through the service on 127.0.0.1, so nothing outside the computer can ask for them.

### Collect on your own computer

1. Open the **NetFlow** page and click **Collect Here**.
2. If Windows Firewall blocks the flows, click **Open Firewall Port** (this needs administrator rights).

NOMAD remembers that it was collecting and starts again the next time it opens. The flows are kept in `%LOCALAPPDATA%\NOMAD\flows.db`.

## Set a router up

Start collecting before you set the routers up. Routers send the names of their interfaces and applications as they start, and then every 5 minutes.

1. Open **NetFlow Config**. You can also click **Set Up a Router...** on the NetFlow page, or right-click a router on the map and choose **Tools** > **Set Up NetFlow...**
2. Under **Send to**, add the computer that collects (**Add This Computer**, or the server running the service). You can add two.
3. Set **From interface** to a loopback. NOMAD knows the router by the address its flows come from, so it should be the address the Network Map reads it at.
4. Tick **Name the applications** if the router has NBAR2 (ISR 4000, ASR 1000, Catalyst 8000 and C8000v). Without it, NOMAD names applications from their ports, such as HTTPS or SSH.
5. Choose the interfaces, then send the configuration.

You can send it three ways:

| | What it does |
| --- | --- |
| **Send to Session** | Types the lines into a terminal session at the enable (#) prompt |
| **Copy** or **Save As...** | For pasting it yourself |
| **Set Up over SSH** | Sets it up on each router in **Routers** in turn. With **every interface with an IPv4 address** ticked, each router's own interfaces are read from it. Whatever NOMAD set up before is taken out first, because IOS can't change a flow record that's in use. |

**Take Out over SSH** takes the monitor off every interface it's on and removes the record, exporter and monitor. Check a router with `show flow monitor NOMAD-MONITOR statistics` and `show flow exporter NOMAD-EXPORTER statistics`.

#### What it sets up

- A flow record with the addresses, ports, protocol, input interface and direction, and the output interface, byte and packet counts and times of each flow.
- An exporter for each collector, sending NetFlow v9 (or IPFIX) with the interface and application names.
- A monitor that sends a flow still going every minute (IOS's own default is every 30 minutes) and one that has ended after 15 seconds.
- The monitor on each interface, on input.

Input is enough. NOMAD counts each flow coming in on the interface it arrived on, and going out on the interface it left by. So a monitor on every interface that traffic comes in on shows both directions of all of them. Putting the monitor on output as well would count flows twice.

**Flow times:** router uptime works on every IOS and IOS-XE router. Clock time needs IOS-XE 16 or later. NOMAD corrects for a router clock that's wrong either way.

**Sampling:** on a busy link of an older router, choose to sample 1 packet in N. NOMAD multiplies what it gets back up, but small flows may not show.

## Read the NetFlow page

1. Choose the **Router** and the **Interface**. Routers are named from the open Network Map.
2. Choose **In and out**, **In** (arriving on the interface) or **Out** (leaving the router by it).
3. Choose the time: from the last 5 minutes to the last 14 days.

The line above the graph adds up the time you chose. It shows how much came in and how much went out, the average rate of each, the busiest minute of each, and how many flows there were. These totals come from the flows. With **Every interface** chosen, it shows one total for what went through the router.

The graph shows the interface's rate in and out. The filled bars are a minute at a time from the flows. The lines are live, from SNMP. Under it are the tabs:

| Tab | Shows |
| --- | --- |
| **Top Talkers** | The sources sending the most, and the name the map knows them by |
| **Top Destinations** | Where the most went |
| **Applications** | NBAR's application names, or names from the ports |
| **Conversations** | Source, destination and service, such as HTTPS |
| **Find Flows** | Every flow to or from an address or subnet in the time chosen |

Each minute keeps its top 25 of each, and the rest is counted as **Other**. Right-click a row to copy it or find its flows.

The tables filter and sort the same way as the tables on the Network Map. Click the funnel at the left of a column's header, or right-click the header, to choose which values to show. Click a header to sort by that column. A tab shows how many rows are left, such as "Top Talkers (3 of 25)", while it is filtered. The filters and the sort stay when the page refreshes.

With **Every interface** chosen, each flow counts once, as it came into the router.

Find Flows looks through each flow as it was sent, which is kept for 2 hours unless the collector was set otherwise.

### From the Network Map

| Right-click | Opens the NetFlow page on |
| --- | --- |
| A link | **Top Talkers on This Link (NetFlow)**: the router at one end, on its port |
| A router's or switch's port | **Top Talkers on This Port (NetFlow)** |
| A router or switch | **Tools** > **Top Talkers (NetFlow)** |

## Good to know

- NOMAD reads NetFlow v5, v9 and IPFIX. NetFlow Config builds Cisco IOS and IOS-XE configuration.
- If the NetFlow page says it's waiting for a router's templates, the router hasn't sent them yet. They come within a minute.
- If no flows arrive, check that the router can reach the collector on UDP 2055 and that Windows Firewall lets them in.
- If the live rate is missing, add the router's community string or SNMPv3 user to the Network Map (**SNMP Credentials...**).
