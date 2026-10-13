"""Small, function-specific navigation symbols, drawn as scalable outline icons.

All artwork is local and uses a shared 24-unit grid. The icon engine renders at
the size Qt requests, including high-DPI sizes, and follows the navigation colors.
"""
from PyQt5.QtCore import QByteArray, QRectF, Qt
from PyQt5.QtGui import QIcon, QIconEngine, QPainter, QPixmap
from PyQt5.QtSvg import QSvgRenderer

from .theme import COLORS


TOOL_ART = {
    # Local network configuration: Ethernet socket, routes, address pairing,
    # connected sockets, and a reset arrow around an adapter.
    "Interfaces": '<path d="M4 4h16v12h-4v4H8v-4H4z M8 4v5m4-5v5m4-5v5"/>',
    "Routing Table": '<path d="M4 20v-5a3 3 0 0 1 3-3h10a3 3 0 0 0 3-3V4'
                     ' M16 7l4-4 3 4 M8 7l4-4 4 4 M12 4v16"/>',
    "ARP": '<rect x="2" y="3" width="8" height="6" rx="1"/>'
           '<rect x="14" y="15" width="8" height="6" rx="1"/>'
           '<path d="M14 6h6v5m-3-3 3 3 3-3 M10 18H4v-5m-3 3 3-3 3 3"/>',
    "Connections": '<path d="M8 7V3m4 4V3 M6 7h8v3a4 4 0 0 1-8 0z'
                   ' M10 14v4a3 3 0 0 0 6 0v-4 M14 14h4m-2-4v4"/>',
    "Network Reset": '<path d="M3 9a9 9 0 1 1 0 6 M3 3v6h6"/>'
                     '<rect x="9" y="9" width="8" height="6" rx="1"/>'
                     '<path d="M11 18h4m-2-3v3"/>',
    "Terminal": '<rect x="2" y="4" width="20" height="16" rx="2"/>'
                '<path d="m6 9 4 3-4 3m7 0h5"/>',
    "RDP": '<rect x="2" y="3" width="20" height="14" rx="2"/>'
           '<path d="M8 21h8m-4-4v4 M6 10h12m-3-3 3 3-3 3"/>',
    "SCP": '<path d="M3 8V3h10l4 4v2 M13 3v4h4 M21 16v5H11l-4-4v-2'
           ' M11 21v-4H7 M3 12h16m-3-3 3 3-3 3"/>',
    "TFTP": '<path d="M4 3h11l4 4v5 M15 3v4h4 M4 3v18h6'
            ' M15 14v8m-3-3 3 3 3-3 M21 22v-8m-3 3 3-3 2 2"/>',
    "Wake-on-LAN": '<path d="M12 2v9 M6 5a9 9 0 1 0 12 0"/>',
    "Sweep": '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/>'
             '<path d="m12 12 6-7"/><circle cx="7" cy="14" r="1"/>',
    "Switch Port": '<rect x="2" y="5" width="20" height="12" rx="2"/>'
                   '<path d="M5 9h3v4H5z M11 9h3v4h-3z M17 9h2m-2 4h2 M6 17v4"/>',
    "MAC Finder": '<rect x="2" y="3" width="14" height="9" rx="2"/>'
                  '<path d="M5 6h2v3H5z M10 6h2v3h-2z M9 12v4"/>'
                  '<circle cx="15" cy="17" r="4"/><path d="m18 20 3 3"/>',
    "DHCP Servers": '<rect x="7" y="2" width="10" height="7" rx="1"/>'
                    '<path d="M10 5h4 M12 9v5H4v3m8-3h8v3"/>'
                    '<rect x="1" y="17" width="6" height="5" rx="1"/>'
                    '<rect x="17" y="17" width="6" height="5" rx="1"/>',
    "SNMP Walk": '<circle cx="5" cy="4" r="2"/><circle cx="12" cy="12" r="2"/>'
                 '<circle cx="19" cy="20" r="2"/><path d="M5 6v6h5m2 2v6h5"/>',
    "Ping": '<path d="M2 8h17m-4-4 4 4-4 4 M22 16H5m4-4-4 4 4 4"/>',
    "Latency": '<circle cx="12" cy="13" r="9"/><path d="M9 1h6m-3 0v3'
               ' M12 7v6l4 2m3-10 2 2"/>',
    "Traceroute": '<circle cx="3" cy="17" r="2"/><circle cx="12" cy="8" r="2"/>'
                  '<circle cx="21" cy="17" r="2"/><path d="m5 15 5-5m4 0 5 5 M8 10h2V8 M17 15h2v-2"/>',
    "MTU": '<rect x="3" y="3" width="18" height="10" rx="1"/>'
           '<path d="M7 3v3m5-3v5m5-5v3 M3 19h18m-15-3-3 3 3 3m12-6 3 3-3 3"/>',
    "Ports": '<rect x="2" y="3" width="15" height="12" rx="2"/>'
             '<path d="M5 7v3m4-3v3m4-3v3 M18 18l4 4"/>'
             '<circle cx="15" cy="15" r="5"/>',
    "iperf": '<path d="M4 19a10 10 0 1 1 16 0 M5 11l2 1m5-8v3m7 4-2 1'
             ' M12 15l5-6 M6 20h12"/><circle cx="12" cy="15" r="2"/>',
    "DNS Lookup": '<circle cx="10" cy="10" r="7"/><ellipse cx="10" cy="10" rx="3" ry="7"/>'
                  '<path d="M3 10h14m-2 5 7 7"/>',
    "DNS Servers": '<rect x="3" y="3" width="18" height="7" rx="2"/>'
                   '<rect x="3" y="14" width="18" height="7" rx="2"/>'
                   '<path d="M7 6h1m4 0h5 M7 17h1m4 0h5 M12 10v4"/>',
    "Web Check": '<rect x="2" y="3" width="20" height="18" rx="2"/>'
                 '<path d="M2 8h20 M5 5.5h1m3 0h1 M7 14l3 3 7-6"/>',
    "Network Map": '<rect x="9" y="2" width="6" height="5" rx="1"/>'
                   '<rect x="2" y="17" width="6" height="5" rx="1"/>'
                   '<rect x="16" y="17" width="6" height="5" rx="1"/>'
                   '<path d="M12 7v5H5v5m7-5h7v5"/>',
    "IP Addresses": '<rect x="3" y="3" width="18" height="18" rx="2"/>'
                    '<path d="M3 9h18M3 15h18M9 3v18m4-12h4m-4 6h4m-4 6h4"/>',
    "VLANs": '<path d="m12 2 10 5-10 5L2 7z M2 12l10 5 10-5 M2 17l10 5 10-5"/>',
    "Subnet Placement": '<path d="M16 8c0 4-5 8-5 8S6 12 6 8a5 5 0 0 1 10 0z"/>'
                        '<circle cx="11" cy="8" r="1.5"/>'
                        '<path d="M11 16v3H3v3m8-3h10v3"/>',
    "SNMP Config": '<path d="M4 5h16M4 12h16M4 19h16 M8 3v4m8 3v4m-6 3v4"/>'
                   '<circle cx="8" cy="5" r="2"/><circle cx="16" cy="12" r="2"/>'
                   '<circle cx="10" cy="19" r="2"/>',
    "ACLs & Route Maps": '<path d="M12 2 4 5v6c0 5 3.5 9 8 11 4.5-2 8-6 8-11V5z"/>'
                         '<path d="M9 9h6M9 13h6M9 17h3"/>',
    "Ansible Inventory": '<rect x="4" y="3" width="16" height="19" rx="2"/>'
                         '<path d="M9 3V1h6v2 M8 9h1m3 0h4 M8 13h1m3 0h4 M8 17h1m3 0h4"/>',
    "Packet Capture": '<path d="M2 7h20M5 7l3 13h8l3-13 M12 2v12m-3-3 3 3 3-3"/>',
    "Syslog": '<path d="M5 2h10l4 4v16H5z M15 2v5h4 M8 11h8m-8 4h8m-8 4h5"/>',
    "Subnet Calculator": '<rect x="5" y="2" width="14" height="20" rx="2"/>'
                         '<path d="M8 6h8 M8 11h1m6 0h1m-8 4h1m6 0h1m-8 4h1m6 0h1"/>',
}

CONTROL_ART = {
    "tools": '<rect x="3" y="3" width="6" height="6" rx="1"/>'
             '<rect x="15" y="3" width="6" height="6" rx="1"/>'
             '<rect x="3" y="15" width="6" height="6" rx="1"/>'
             '<rect x="15" y="15" width="6" height="6" rx="1"/>',
    "close": '<path d="m6 6 12 12M6 18 18 6"/>',
}
FALLBACK_ART = '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 12h8m-4-4v8"/>'


class ToolIconEngine(QIconEngine):
    def __init__(self, art):
        super().__init__()
        self.art = art

    def clone(self):
        return ToolIconEngine(self.art)

    def paint(self, painter, rect, mode, state):
        color = COLORS["accent"] if mode == QIcon.Selected or state == QIcon.On else (
            COLORS["disabled"] if mode == QIcon.Disabled else COLORS["text"])
        svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
               f'fill="none" stroke="{color}" stroke-width="1.7" '
               f'stroke-linecap="round" stroke-linejoin="round">{self.art}</svg>')
        renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
        painter.save()
        renderer.render(painter, QRectF(rect))
        painter.restore()

    def pixmap(self, size, mode, state):
        pixmap = QPixmap(size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        self.paint(painter, pixmap.rect(), mode, state)
        painter.end()
        return pixmap


def tool_icon(title):
    """Return matching artwork for the rail, drawer, search results, and menus."""
    return QIcon(ToolIconEngine(TOOL_ART.get(title, CONTROL_ART.get(title, FALLBACK_ART))))
