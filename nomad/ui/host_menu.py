"""Things to do with a host from a right-click menu (Sweep results, Network Map devices): open a session, browse to
it, ping, trace, scan, read it over SNMP or capture its traffic, each on its own page."""
import ipaddress
import subprocess
import webbrowser

from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QApplication, QMenu, QMessageBox

from ..sweep import find_putty
from ..terminal.sessions import RDP, SSH, TELNET
from .common import add_submenu, drop_empty_submenus, menu_labels

ADD_TO_MAP = "Add Device to Map..."
CONNECT, TOOLS = "Connect", "Tools"


class HostActions:
    def __init__(self, window, parent):
        self.window, self.parent = window, parent

    def add_to(self, menu, host, aliases=(), name="", folder="", snmp=None, sessions=("SSH", "SCP", "Telnet", "RDP"),
               grouped=True, leave_out=()):
        """Add the actions for host to menu. Returns {QAction: callable} for running the chosen one. aliases: the
        host's other addresses and names, for finding its saved sessions; name and folder: what to call a new
        session to it, and the folder to suggest when it's saved; snmp: (community, version) for SNMP Details, when
        the page knows what the host answers to. grouped: sessions and browsing in a Connect submenu and the tools in
        a Tools one, keeping the menu short (not when menu is already a submenu of just these); leave_out: labels of
        entries the page has no use for (Show on Map, on the map)."""
        actions = {}
        connect = add_submenu(menu, CONNECT) if grouped else menu
        tools = add_submenu(menu, TOOLS) if grouped else menu
        pages = [("SSH", self.window.terminal_tab, SSH), ("SCP", self.window.scp_tab, SSH),
                 ("Telnet", self.window.terminal_tab, TELNET)]
        rdp_page = getattr(self.window, "rdp_tab", None)
        if callable(getattr(rdp_page, "saved_matches", None)):
            pages.append(("RDP", rdp_page, RDP))
        for label, page, protocol in pages:
            if label not in sessions:
                continue
            matches = page.saved_matches(host, aliases, protocol)
            if len(matches) == 1:
                text = f"Open {label} Session ({matches[0].name})"
            elif matches:
                text = f"Open {label} Session ({len(matches)} Saved)..."
            else:
                text = f"Open {label} Session"
            actions[connect.addAction(text)] = lambda page=page, protocol=protocol: page.open_address(
                host, protocol, aliases, name, folder)
            if matches:
                actions[connect.addAction(f"Open New {label} Session")] = lambda page=page, protocol=protocol: \
                    page.open_address(host, protocol, aliases, name, folder, use_saved=False)
        if grouped:
            connect.addSeparator()
        # Saving a session, for a host that has none: SSH and Telnet share the Terminal page's (SCP uses its SSH
        # ones), so one entry covers all three
        terminal = self.window.terminal_tab
        if {"SSH", "SCP", "Telnet"} & set(sessions) and not any(
                terminal.saved_matches(host, aliases, protocol) for protocol in (SSH, TELNET)):
            actions[connect.addAction("Create Terminal Session...")] = lambda: self.create_session(
                terminal, SSH, host, name, folder)
        if "RDP" in sessions and callable(getattr(rdp_page, "create_session", None)) and not \
                rdp_page.saved_matches(host, aliases, RDP):
            actions[connect.addAction("Create RDP Session...")] = lambda: self.create_session(
                rdp_page, RDP, host, name, folder)
        if grouped:
            connect.addSeparator()
        actions.update(self.add_missing(connect, {
            "SSH with PuTTY": lambda: self.open_ssh(host, aliases),
            f"Open https://{host}": lambda: self.open_web(host),
            f"Open http://{host}": lambda: self.open_web(host, "http"),
        }, menu, leave_out))
        actions.update(self.add_missing(tools, {
            "Ping": lambda: self.ping(host),
            "Traceroute": lambda: self.trace(host),
            "Monitor Latency": lambda: self.monitor_latency(host),
            "Scan Ports": lambda: self.scan_ports(host),
            "SNMP Details": lambda: self.snmp(host, *(snmp or ())),
            "Capture Traffic...": lambda: self.capture(host),
        }, menu, leave_out))
        if grouped:
            drop_empty_submenus(menu, connect, tools)
        actions.update(self.navigation_actions(menu, host, name, leave_out))
        menu.setProperty("nomadIpActions", list(dict.fromkeys((menu.property("nomadIpActions") or []) + [host])))
        return actions

    @staticmethod
    def add_missing(menu, callbacks, whole=None, leave_out=()):
        """Add the entries whole (menu, or the menu it's a submenu of) doesn't have yet, apart from leave_out."""
        existing = menu_labels(whole if whole is not None else menu) | set(leave_out)
        return {menu.addAction(label): callback for label, callback in callbacks.items() if label not in existing}

    def navigation_actions(self, menu, host, name="", leave_out=()):
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return {}
        return self.add_missing(menu, {
            "Show in IPAM": lambda: self.show_ipam(host),
            "Show on Map": lambda: self.show_map(host),
            ADD_TO_MAP: lambda: self.add_to_map(host, name),
            "Copy IP Address": lambda: QApplication.clipboard().setText(host),
        }, leave_out=leave_out)

    def add_to_map(self, host, name=""):
        """Add the host to a network map (the user chooses which) as a device added by hand."""
        if host:
            self.window.netmap_tab.add_address(host, name)

    def show_ipam(self, host):
        page = self.window.ipam_tab
        self.window.navigator.setCurrentWidget(page)
        stores = page.ipam_stores()
        if not stores:
            return
        address = host.partition("%")[0]
        matches = [(source, network) for source, store in stores for network in store.networks()
                   if store.subnet_for(network.id, address) is not None or store.address(network.id, address)
                   is not None]
        if len(matches) == 1:
            source, network = matches[0]
            page.show_address(source, network.id, address)
        elif matches:
            menu = QMenu(self.parent)
            for source, network in matches:
                menu.addAction(f"{network.name} ({source})", lambda source=source, network=network:
                               page.show_address(source, network.id, address))
            menu.exec_(QCursor.pos())
        else:
            page.search_kind_combo.setCurrentIndex(0)
            page.search_network_combo.setCurrentIndex(0)
            page.search_match_combo.setCurrentIndex(0)
            page.search_input.setText(address)
            page.search()

    def show_map(self, host):
        from ..netmap.l3 import owned_addresses

        page = self.window.netmap_tab
        self.window.navigator.setCurrentWidget(page)
        network_map = page.displayed_map()
        if network_map is not None:
            address = ipaddress.ip_address(host.partition("%")[0])

            def same(value):
                try:
                    return ipaddress.ip_address(value.partition("%")[0]) == address
                except ValueError:
                    return False

            key = next((key for value, key in owned_addresses(network_map).items() if same(value)), None)
            if key is not None:
                page.show_in(page.view, [key])
                return
            found = next((item for item in network_map.hosts if same(item.ip)), None)
            if found is not None:
                page.tabs.setCurrentWidget(page.view)
                if page.view.show_host(found):
                    return
            key = next((key for key, node in page.l3_nodes.items() if same(node.label)), None)
            if key is not None:
                page.show_in(page.l3_view, [key])
                return
        self.window.show_status(f"{host} isn't on the open network map.", "info")

    def create_session(self, page, protocol, host, name="", folder=""):
        """Save a session to host: page's New Session dialog (the Terminal or RDP page's), with the address filled
        in."""
        if host:
            session = page.create_session(host, protocol, name, folder)
            if session is not None:
                self.window.show_status(f"Saved the {session.protocol} session {session.path}.", "info")

    def open_terminal(self, host, protocol):
        """Open a session to host on the Terminal page (its saved session, if it has one)."""
        if host:
            self.window.terminal_tab.open_address(host, protocol)

    def open_ssh(self, host, aliases=()):
        """SSH in PuTTY, as the user of host's saved session if it has just one (PuTTY asks for the password)."""
        if not host:
            return
        putty = find_putty()
        if not putty:
            QMessageBox.warning(self.parent, "PuTTY Not Found",
                                "PuTTY wasn't found on the PATH or in its usual install folders. "
                                "Install PuTTY from https://www.putty.org, then try again.")
            return
        try:
            matches = self.window.terminal_tab.saved_matches(host, aliases, SSH)
            user = ["-l", matches[0].username] if len(matches) == 1 and matches[0].username else []
            subprocess.Popen([putty, "-ssh", *user, host])
        except OSError as error:
            QMessageBox.critical(self.parent, "SSH", f"Couldn't start PuTTY:\n\n{error}")
            return
        self.window.show_status(f"Opened an SSH session to {host}.", "info")

    def open_web(self, host, scheme="https"):
        if host:
            authority = f"[{host.replace('%', '%25')}]" if ":" in host else host
            url = f"{scheme}://{authority}"
            webbrowser.open_new_tab(url)
            self.window.show_status(f"Opened {url}.", "info")

    def ping(self, host):
        if host:
            self.window.navigator.setCurrentWidget(self.window.ping_tab)
            self.window.ping_tab.ping_host(host)

    def trace(self, host):
        if host:
            self.window.navigator.setCurrentWidget(self.window.traceroute_tab)
            self.window.traceroute_tab.trace_host(host)

    def monitor_latency(self, host):
        if host:
            self.window.navigator.setCurrentWidget(self.window.latency_tab)
            self.window.latency_tab.add_target(host, host)

    def scan_ports(self, host):
        if host:
            self.window.navigator.setCurrentWidget(self.window.ports_tab)
            self.window.ports_tab.scan_host(host)

    def snmp(self, host, community=None, version=None):
        if host:
            self.window.navigator.setCurrentWidget(self.window.snmp_tab)
            self.window.snmp_tab.query_host(host, community, version)

    def capture(self, host):
        """Fill in the host on the Packet Capture page; capturing needs a deliberate Start (and admin rights)."""
        if host:
            self.window.navigator.setCurrentWidget(self.window.capture_tab)
            self.window.capture_tab.capture_host(host)
