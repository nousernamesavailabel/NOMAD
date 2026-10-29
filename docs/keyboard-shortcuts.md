# Keyboard guide

Press **F1** in NOMAD to open the searchable guide. Search by key, action or tool name; **Ctrl+F** focuses the guide's search box. Collapse a workflow group to shorten the list.

## A quick workflow

1. **Ctrl+K** — choose a tool.
2. **Alt+A** — select the network adapter, if needed.
3. **Ctrl+F** — jump to the tool's main input or filter.
4. **Shift+Enter** — start a diagnostic/discovery tool.
5. **Shift+Esc** — stop a running tool. Packet Capture stops and saves.

**Ctrl+Tab** changes tools; **Alt+Left / Alt+Right** changes sessions within Terminal or SCP. **Ctrl+Shift+Enter** moves a session between the main window and a pop-out.

## Important scope changes

- **Shift+Enter / Shift+Esc** run and stop only supported tool pages. Search fields on Network Map and Network Reset, multiline editors, and remote terminals retain their existing key behavior.
- **Alt+Left / Alt+Right** switches sessions on Terminal/SCP. In SCP file lists, folder-back has moved from Alt+Left to **Alt+Up**. **Backspace** still goes up one folder.
- **Ctrl+S** starts (or stops) a terminal session log and **Ctrl+Shift+S** saves the running config, like the buttons below the session. Ctrl+S no longer reaches the remote host as XOFF (output freeze).
- **Ctrl+L** focuses the path only inside an SCP file pane. Terminal Ctrl+L continues to go to the remote shell.
- **Ctrl+W** closes the active SCP session. NOMAD asks before disconnecting, with **Yes** selected so **Enter** confirms, and keeps its warnings for transfers and unsaved edits. In Terminal, Ctrl+W goes to the remote host (nano's Where Is, the shell's delete-word); close a terminal session with its tab's close button.
- **Alt+A** leaves focus mode to reveal the adapter picker.
- Shortcuts use the same enabled actions as buttons. They do not repeat while a key is held.

Shift+Enter starts these tools: Ping, Traceroute, Sweep, Ports, MTU, Latency, iperf, SNMP Walk, DNS Lookup, DNS Servers, Web Check, Packet Capture, DHCP Servers, Switch Port, MAC Finder (Locate Now; Enter in its search box is Find). Stop is available where the tool has a Stop button; DNS Lookup and Web Check do not have cancellation actions.

## Everyday actions

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Shift+Enter | Start the current tool | Diagnostics, discovery and Packet Capture |
| Shift+Esc | Stop the current tool; capture stops and saves | Diagnostics, discovery and capture tools with a Stop button |
| Alt+A | Focus the adapter picker (arrows select) | Main window; leaves focus mode if needed |
| Ctrl+F | Focus the page's main input, search or filter | See Find targets below |
| F1 | Open this keyboard guide | Main window and popped-out Terminal/SCP windows |
| F5 | Refresh network settings | Main window; SCP file lists use F5 to copy |
| Ctrl+R | Run a diagnostics report | Main window; SCP file lists use Ctrl+R to refresh |

## Navigation and view

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Ctrl+K | Find a tool | Main window |
| Ctrl+B | Keep the tool drawer open or close it | Main window |
| Ctrl+Tab / Ctrl+Shift+Tab | Next / previous tool | Main window; Ctrl+Tab in a pop-out cycles sessions |
| Ctrl+PageDown / Ctrl+PageUp | Next / previous tool | Main window, outside terminal text |
| F11 | Toggle focus mode | Main window; toggles full screen in a pop-out |
| Ctrl+= / Ctrl+- / Ctrl+0 | Larger / smaller / default text size | Main window, outside terminal text |
| Tab / Shift+Tab | Next / previous input or control | Forms; plain Tab in terminal text goes to the remote host |

## Saved sessions and terminal windows

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Ctrl+N | Create a saved session in the selected folder | Terminal, SCP, RDP |
| Ctrl+Shift+N | Create a folder under the selected folder | Terminal, SCP, RDP |
| Enter | Open the selected saved session | Session lists |
| Ctrl+W | Close the current session (Enter confirms Yes) | SCP; in Terminal, Ctrl+W goes to the remote host |
| Alt+Left / Alt+Right | Previous / next session (wraps around) | Terminal and SCP |
| Ctrl+Shift+Enter | Pop out this session; move it back from a pop-out | Terminal and SCP |
| Ctrl+1 through Ctrl+9 | Send the corresponding saved command | Terminal text, including when the Buttons bar is hidden |
| Hold Ctrl | Show number overlays above visible command buttons, and S / Shift+S above Log Session / Save Config | Terminal; release Ctrl to hide |
| Ctrl+Shift+F | Find in terminal output | Terminal text |
| Ctrl+Shift+C / Ctrl+Shift+V | Copy selection / paste | Terminal text |
| Shift+PageUp / Shift+PageDown | Scroll terminal output | Terminal text |
| Ctrl+S | Log Session: start logging to a file, or stop logging | Terminal session; replaces the shell's Ctrl+S (XOFF) |
| Ctrl+Shift+S | Save Config: save the running configuration (cancels one being saved) | Connected terminal session |

## SCP files

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Ctrl+L | Focus and select this pane's folder path | SCP file pane; Enter opens the typed folder |
| F5 | Copy selected files to the other side | SCP file list |
| F4 | Edit selected file | SCP file list |
| F2 | Rename selected file | SCP file list |
| F7 | Create a folder | SCP file list |
| F8 / Delete | Delete selected files | SCP file list |
| Alt+Enter | Show file properties | SCP file list |
| Ctrl+R | Refresh this folder | SCP file list |
| Ctrl+Alt+H | Show / hide hidden files | SCP file list |
| Ctrl+Shift+F | Filter file names | SCP file list |
| Backspace | Up one folder | SCP file list |
| Alt+Up | Back to the previous folder | SCP file list; Alt+Left now switches sessions |

## Find targets — Ctrl+F

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Ctrl+F | Host / device | Ping, Traceroute, Ports, MTU, SNMP Walk |
| Ctrl+F | Subnet | Sweep, Subnet Calculator |
| Ctrl+F | Name | Latency, DNS Lookup |
| Ctrl+F | Names to test | DNS Servers |
| Ctrl+F | Web address | Web Check |
| Ctrl+F | Server address; listening port in server mode | iperf |
| Ctrl+F | Session filter; reveals a hidden session list | Terminal, SCP, RDP |
| Ctrl+F | MAC address | Wake-on-LAN |
| Ctrl+F | Address / subnet filter | Packet Capture |
| Ctrl+F | Community string, or its enabling toggle | SNMP Config |
| Ctrl+F | Hosting folder in server section; server address otherwise | TFTP |
| Ctrl+F | Find an adapter by name, description, IP or MAC | Interfaces; Enter selects the match |
| Ctrl+F | Search command output | Network Reset; Enter: next, Shift+Enter: previous, Esc: close search |
| Ctrl+F | Filter discovered switch details | Switch Port |
| Ctrl+F | MAC address, IP address or name to find; the list in List mode | MAC Finder |
| Ctrl+F | Filter server addresses | DHCP Servers |
| Ctrl+F | Page search / filter | Routing Table, ARP, Connections, Syslog, IP Addresses, Network Map, VLANs, Subnet Placement |

## Context and exceptions

| Shortcut | Action | Where it works |
| --- | --- | --- |
| Shift+Enter | Add/update a target when editing its name or host; otherwise start monitoring | Latency |
| Shift+Enter | Start a client test or start the server, according to the selected mode | iperf |
| Shift+Enter / Shift+Esc | Run / Stop shortcuts activate only on supported tool pages | Elsewhere, search navigation, multiline editing and terminal keys keep their normal behavior |
| Terminal controls | Other shell keys keep going to the remote host | Ctrl+C, Ctrl+R, Ctrl+L, Ctrl+B, and plain Esc remain terminal controls |
| Ctrl+L | Changes a folder only in SCP; clears the screen in a shell | Terminal Ctrl+L remains unchanged |
| Ctrl+Shift+N | Saved-session folder, separate from F7's remote/local file folder | SCP |
