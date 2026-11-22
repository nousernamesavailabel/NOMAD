# Web Dashboard build plan

Agreed with the user on 2026-11-20. It ships as one release. This is the developer's plan; the user guide is
`docs/dashboard.md`.

## What it is

The NOMAD Dashboard is a read-only HTTPS web site that shows the state of the network to people who don't have NOMAD.
It runs as a fifth Windows service, on the same computer as the Map Watcher, the Syslog Collector and the Flow
Collector. It never sends anything to the network itself. Everything it shows comes from what the other services
collected, and from the tribe.

## Decisions

| Topic | Decision |
|---|---|
| Where it runs | New Windows service "NOMAD Dashboard", listed in Tools > Services & Firewall |
| Same computer | Must be on the computer with the Map Watcher and the collectors (their APIs stay on 127.0.0.1) |
| Access | LAN, HTTPS, a login for each person. Everyone sees the same thing |
| Certificate | Self-signed on install (fingerprint shown), or import a PFX/PEM from the company CA. Default port 8444 (the Tribe Server has 8443) |
| Tribe access | A new read-only "viewer" tribe key (Tribe API 17). The server only answers GETs for it, and never the map credentials or config texts |
| Device up/down | The Map Watcher runs the ping and IP SLA Monitor for the maps it watches. The app's Monitor tick box is unchanged and still pings from that PC |
| Utilization | The Map Watcher reads the counters of linked ports plus ports marked "Graph on Dashboard" from the map's right-click menu |
| Sweeps | The Map Watcher ping-sweeps the IPAM subnets of its maps' networks on a schedule and saves results to IPAM like a manual sweep |
| Maps covered | All tribe maps |
| Hosts per subnet | Union of map hosts (ARP/MAC), IPAM sweep results and NetFlow addresses, with a window chosen on the page (15 min, 1 h, 24 h, 7 d) and a breakdown by source |
| Trends | Uptime % per device, host count per subnet, interface utilization. Retention is set in the setup dialog |
| Live | Server-Sent Events push, plus a kiosk mode that rotates pages, with long-lived kiosk logins |
| Map | Site tiles first, then the full topology (saved positions, L2 and L3, status, tunnels, utilization colors) |
| Never shown | Raw syslog text, device configs, SNMP communities and users, logins. Wi-Fi user names may show |
| Extras | CSV export of each table and print/PDF (the browser's print). No email alerts, no JSON API for other tools |
| Offline | Every script and style ships inside NOMAD (`nomad/data/dashboard`). No CDN |

## Parts

### 1. Tribe server: viewer key and the graphed section (API 17)

- `ipam/server.py`
  - Add `VIEWER = "viewer"`. `config["viewer_secret"]` is made the first time a viewer key is saved.
  - Add `viewer_key()`, `write_viewer_key()` and `change_viewer_secret()`.
  - `role_for` returns `VIEWER`. `_handle` refuses a viewer anything but the read-only GETs in `VIEWER_GETS` (403),
    so a viewer never gets `/api/maps/secrets` or `/api/configs/version`, and every POST is refused.
  - `API_LEVEL = 17`.
- The key file gets an optional `"role": "viewer"`. `TeamKey.from_dict` reads it. Connecting NOMAD to the tribe
  with a viewer key is refused, with a message that says what the key is for.
- `ipam/client.py`: add `VIEWER_API = 17` and a `SERVER_FEATURES` line.
- `netmap/shared.py`: add a new `GRAPHED` section, keyed `device|port key`. It's held back for servers below API 17,
  like the lock sections. A save no longer deletes items in sections this NOMAD doesn't know, which future-proofs
  newer sections.
- `netmap/model.py`: add `NetworkMap.graphed` as {device key: [ports]}, saved in map files too.
- `netmap/tribe.py`: add `TribeMaps(..., secrets=False)` for the dashboard, which never fetches credentials.
- `ui/tribe_dialog.py`: add "Save Viewer Key File..." and "Change Viewer Key..." on the server.

### 2. Collector endpoints the dashboard needs

- Syslog: `SyslogQueries.counts(start)` returns [[source, severity, count]], served at `/v1/counts` and read with
  `SyslogServiceSource.counts()`. Only counts, never text.
- Flows: `FlowQueries.addresses(start)` returns [[address, last seen]] from the raw flows, served at
  `/v1/addresses` and read with `ServiceSource.addresses()`.

### 3. Map Watcher: Monitor, counters and sweeps

- New module `netmap/watch_monitor.py`. It's Qt-free and driven by a clock, so it can be tested with fakes.
  - `MapMonitor` (one per watched map): a `monitor.StatusTracker`, IP SLA probe discovery (every 10 minutes) and
    polling, a `counters.CounterTracker` for link ports plus graphed ports, and tunnel status via `tunnels.poll`.
  - `MonitorStore`: `status.db` in the watcher's folder, which the dashboard reads read-only. Tables:
    `device_status`, `changes`, `rates`, `tunnels` and `meta` (heartbeats). Changes and rates older than 3 days
    are pruned, because the dashboard keeps its own history.
  - `MonitorRunner`: a thread of its own, so a long crawl doesn't hold up pings. It pings every
    `monitor_interval` (default 60 s) and reads counters every `counter_interval` (default 300 s).
  - `SweepRunner`: a thread of its own. Every `sweep_hours` (default 4, 0 is off) it sweeps the IPv4 subnets of each
    watched map's IPAM network that are no larger than `/sweep_max_prefix` (default /22). It pings without name
    lookups, with ARP only on directly connected subnets and only for hosts that answered ping (so proxy ARP can't
    fake a host). It saves results through a `TeamStore` copy in the watcher's folder (`record_sightings` +
    `send_sightings`).
- `watch_service.py`: the config gets a `"monitor"` block (`enabled`, `interval`, `counter_interval`, `sweep_hours`,
  `sweep_max_prefix`), and the runners start and stop with the engine. Device credentials come from the same
  `options()` as watching.
- `ui/watch_service_dialog.py`: add a "Monitoring for the Dashboard" group for these settings.

### 4. Dashboard service (`nomad/dashboard/`)

| Module | What it does |
|---|---|
| `service.py` | Folder `%ProgramData%\NOMAD\dashboard`, `config.json`, the Windows service (`--dashboard-service`, foreground `--dashboard`), install/uninstall, the firewall rule "NOMAD Dashboard" (TCP) |
| `accounts.py` | `users.json` with scrypt hashes and a kiosk flag. Locks out for 5 minutes after 5 failed sign-ins (per user and per address). Sessions are kept hashed (SHA-256 of the token) in `sessions.json`, so a restart doesn't sign out the wall screens. Idle timeout is 12 h, or 365 days for kiosk logins |
| `tls.py` | Self-signed certificate (EC P-256, this computer's names), import of PFX/P12 or PEM (certificate + key), fingerprint |
| `sources.py` | `TribeView`: a viewer `TeamStore` copy (IPAM + sightings) and `TribeMaps(secrets=False)`, synced with `/api/wait`, plus config backup results. `WatcherView`: reads `status.db` read-only. `CollectorView`: syslog counts, flow tops and flow addresses |
| `history.py` | `history.db`: status changes, raw rates with hourly rollups, host counts per subnet with hourly rollups, and the last time each IP was seen by map or flows. Pruned to `raw_days`, `hourly_days` and `max_gb` |
| `views.py` | Pure functions that turn a `Snapshot` into the JSON for each page, and the CSV rows for each table |
| `engine.py` | The threads: tribe sync, watcher ingest (15 s), collectors (60 s), host counts (5 min), prune (hourly). Builds an immutable snapshot and bumps a revision, which the SSE stream announces |
| `web.py` | HTTPS server (TLS handshake per connection on its own thread, like the tribe server). Routes: `/login`, `/logout`, `/`, `/static/*`, `/api/<page>`, `/api/stream` (SSE), `/export/<table>.csv`. Strict CSP (`'self'` only), `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `no-store`. Cookie is `HttpOnly; Secure; SameSite=Strict`. Login checks Origin |

Pages: Overview, Devices, Events, Traffic, VPNs and probes, IPAM, Hosts per subnet, Map (site tiles, then
topology), and Trends (charts for uptime, utilization and host counts).

### 5. Web front end (`nomad/data/dashboard/`)

- Files: `index.html`, `login.html`, `app.css`, `app.js` and `map.js`.
- Plain JavaScript with no libraries. Charts and the map are drawn in SVG.
- Hash routes, in NOMAD's own dark colors (nomad/ui/theme.py), with a plain light page for printing.
- A print stylesheet, so the browser's Print / Save as PDF gives a clean page.
- Kiosk mode: `#kiosk?pages=overview,devices,map&every=30`.

### 6. NOMAD app

- `services_catalog.py`: add the Dashboard entry, installed last.
- `ipam/service.py`: add the Dashboard to `shared_exe_specs`.
- `ui/dashboard_dialog.py`:
  - Status, port, certificate (self-signed or imported, fingerprint shown), the viewer key file (or made on the
    spot on the tribe server), retention, and logins (add, remove, reset password, kiosk).
  - Buttons: Install/Update, Start, Stop, Uninstall, Open Folder, Open in Browser.
  - A warning when the Map Watcher or the collectors aren't on this computer.
- `main_window.py`: Tools > NOMAD Dashboard Service... (`show_dashboard_service`).
- `Main.py`: `--dashboard-service` and `--dashboard`.
- `netmap_tab.py`: right-click a device > Tools > Graph on Dashboard... (tribe maps, devices that answer SNMP) picks
  ports from its `port_status`.

### 7. Docs

- `docs/dashboard.md` (numbered steps) and a section in `docs/services.md`.
- A line in the README.
- CHANGELOG and What's New under Unreleased. The version bump is the user's call.

### 8. Tests

`tests/test_dashboard_*.py` covers:

- The viewer role on the server
- Graphed items and held sections
- `MapMonitor` with fakes
- `SweepRunner` with fakes
- `MonitorStore` and `HistoryStore` (rollups, retention)
- `views` from a hand-made snapshot
- Accounts: hashing, lockout, sessions
- The web server over real TLS: login, cookie, CSP headers, 401s, SSE, CSV
- Collector endpoints
- The dialogs (pytest-qt)

## Known limits

- All NOMAD services run as Network Service, so Windows can't keep the Dashboard out of the Map Watcher's folder.
  The Dashboard only opens `status.db`, and only read-only.
- NOMAD older than this release editing a tribe map drops the "Graph on Dashboard" marks, as older versions did with
  locks. The tribe version check asks people to update.
- PDF is the browser's Print > Save as PDF.
