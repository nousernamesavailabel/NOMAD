# Syslog

The **Syslog** page (under Capture & Logs) shows the syslog messages that switches, routers, firewalls and access points send to this computer. Messages are colored by severity. You can filter them by words and by severity, and save them to a file.

## Where the messages are received

Devices send syslog to one address and port (UDP 514). Only one program on a computer can listen on that port. There are two ways to receive:

| | When to use it |
| --- | --- |
| **Start Listening** (Syslog page) | On your own computer. NOMAD receives messages only while it's open, and keeps the latest 20,000 in memory. |
| **Syslog Collector service** (Tools > Syslog Collector Service...) | On a server several people use over Remote Desktop, or any computer that should keep messages all the time. Everyone using NOMAD on that computer sees the same messages and can search everything the service kept, without administrator rights. |

On a shared server, don't use Start Listening: the first person to click it would have the port, and everyone else would see nothing. Install the service instead.

### Install the Syslog Collector service

The service needs administrator rights to install. After that, NOMAD reads it in every session on the computer.

1. Start NOMAD as administrator (**File** > **Restart as Administrator**).
2. Open **Tools** > **Syslog Collector Service...** You can also click **Collector Service...** on the Syslog page.
3. Check the port, and tick **Also TCP** if any device sends syslog over TCP.
4. Set how long to keep messages (90 days by default) and the most space they may use (2 GB by default). When the messages take more than that, the oldest are deleted, even if they're newer than the days to keep.
5. Click **Install Service**. It opens the port in Windows Firewall and starts.

You can also install it from **Tools** > **Services & Firewall...** with its usual settings, along with NOMAD's other services. See [Services and firewall](services.md).

The Syslog page uses the service whenever it's running. The messages are kept in `%ProgramData%\NOMAD\syslog`, which only administrators can open. NOMAD reads them through the service on 127.0.0.1, so nothing outside the computer can ask for them.

To try the collector in a console without installing it, run `NOMAD.exe --syslog-collector`.

### Receive on your own computer

1. Open the **Syslog** page.
2. Pick the address and port to listen on, and tick **Also TCP** if you need it.
3. To keep a copy of every message, tick **Also write to** and choose a file.
4. Click **Start Listening**.
5. If Windows Firewall blocks the messages, click **Open Firewall Port** (this needs administrator rights).

## Send syslog from a device

Point the device's logging at this computer's address. On Cisco IOS, for example:

```
logging host 10.0.0.5
logging trap informational
```

The **SNMP Config** page builds this for you along with the traps (see [SNMP Config](snmp-config.md)).

## Search what the service kept

When the page reads the Syslog Collector service, it starts with the latest 2,000 messages and adds new ones as they come. To look further back:

1. Type the words to look for in the filter box. A message matches when it has every word, in the sender's address or anywhere in the message.
2. Pick the severity, and how far back to look (**Last hour** up to **Everything kept**).
3. Click **Search Kept**, or press Enter in the filter box.

The newest 5,000 matching messages are shown. New messages wait while you look at the results. Click **Back to Live** to see them again.

To search everything one device sent, right-click one of its messages and choose **Search Kept from** its address.

## The Map Watcher and the service

The Map Watcher reads a switch as soon as its syslog says a port came up or a neighbor changed (see [Network Map](network-map.md#instant-news-with-traps-and-syslog)). It normally listens on UDP 514 itself.

When the Syslog Collector service runs on the same computer, the service has the port. The Map Watcher (the service, or NOMAD watching a map) then reads new messages from the Syslog Collector service every couple of seconds instead. It still listens for SNMP traps itself. If the Syslog Collector service is removed, the Map Watcher goes back to listening on the port within a minute.
