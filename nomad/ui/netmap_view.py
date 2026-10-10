"""The drawing on the Network Map page: devices as boxes you can drag, links with the port at each end, each
switch's hosts behind a badge that opens into one box per port, and sites and buildings as boxes round their
devices that can be collapsed into one."""
import math
import time

from PyQt5.QtCore import QLineF, QPointF, QRectF, QSize, QSizeF, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QImage, QKeySequence, QPainter, QPainterPath, \
    QPainterPathStroker, QPen
from PyQt5.QtWidgets import QGraphicsItem, QGraphicsLineItem, QGraphicsScene, QGraphicsView, QStyleOptionGraphicsItem

from ..netmap.l3 import HOP, STAR, SUBNET
from ..netmap.overlays import DASH, DOT
from ..netmap.layout import GROUP_PAD, GROUP_TITLE, NODE_HEIGHT, NODE_WIDTH
from ..netmap.monitor import DOWN, UNKNOWN, UP, duration_text
from ..netmap.vlans import ACCESS, NATIVE, ONE_END, TAGGED
from ..netmap.model import AP, BUILDING, FIREWALL, GROUP_KINDS, KIND_NAMES, NO_SNMP, ROOM, ROUTER, SERVER, \
    SHARED_PORT_HOSTS, SITE, SNMP, SOURCE_NAMES, SWITCH, UNREACHABLE
from .theme import COLORS

KIND_COLORS = {SWITCH: COLORS["link"], ROUTER: COLORS["accent"], FIREWALL: "#ff9f43", AP: "#c792ea",
               SERVER: "#4ecdc4"}
STATUS_COLORS = {UP: COLORS["success"], DOWN: COLORS["error"], UNKNOWN: COLORS["muted"]}
KIND_TAGS = {SWITCH: "SW", ROUTER: "RTR", FIREWALL: "FW", AP: "AP", SERVER: "SRV"}
STRIP_WIDTH = 34
BADGE_HEIGHT = 20
NEWS_HEIGHT = 15  # The NEW tag over a device found by watching
PORT_WIDTH = 210
PORT_HEADER = 18
LINE_HEIGHT = 14
HOST_LINES = 6  # Hosts listed in a port's box; the rest are counted (and in its tooltip and the Hosts tab)
PORT_COLUMNS = 4
PORT_GAP = 12
PROTOCOL_NAMES = {"cdp": "CDP", "lldp": "LLDP", "l3": "address on the subnet", "icmp": "traceroute"}
ZOOM_STEP = 1.15
MIN_ZOOM, MAX_ZOOM = 0.05, 4.0
LABEL_MIN_ZOOM = 0.5  # Port labels are left off below this zoom
COLLAPSED_WIDTH, COLLAPSED_HEIGHT = 200, 64
GROUP_TAGS = {BUILDING: "BLDG", ROOM: "ROOM"}
GROUP_Z = {SITE: -3, BUILDING: -2, ROOM: -1}  # Inner groups' boxes over the ones they're in
GROUP_BOX = "group:"  # Starts a group's key among devices' keys when arranging or lining them up together
NODE_RECT = QRectF(-NODE_WIDTH / 2, -NODE_HEIGHT / 2, NODE_WIDTH, NODE_HEIGHT)
# A VLAN highlighted: how each link carries it, and how faint what doesn't carry it is
VLAN_LINK_COLORS = {TAGGED: COLORS["link"], NATIVE: COLORS["link"], ACCESS: COLORS["accent"], ONE_END: COLORS["warning"]}
VLAN_LINK_NAMES = {TAGGED: "tagged", NATIVE: "native (untagged)", ACCESS: "access ports", ONE_END: "one end only"}
# Carry VLAN's planned path, drawn over the links while its window is open: (color, width, line style)
PATH_PLANNED, PATH_CARRIES, PATH_CHOSEN, PATH_OFFERED, PATH_BLOCKED = "planned", "carries", "chosen", "offered", \
    "blocked"
PATH_STYLES = {PATH_PLANNED: (COLORS["accent"], 5, Qt.DashLine), PATH_CARRIES: (COLORS["accent"], 5, Qt.SolidLine),
               PATH_CHOSEN: (COLORS["warning"], 5, Qt.DashLine), PATH_OFFERED: (COLORS["warning"], 2, Qt.DotLine),
               PATH_BLOCKED: (COLORS["error"], 5, Qt.DashLine)}
PATH_ORDER = [PATH_BLOCKED, PATH_PLANNED, PATH_CHOSEN, PATH_CARRIES, PATH_OFFERED]  # Which shows, for several links
FADED = 0.22
OVERLAY_LINE_STYLES = {DASH: Qt.DashLine, DOT: Qt.DotLine}
OVERLAY_ORDER = ["error", "warning"]  # A line standing for several links shows the worst of their overlay marks


def mark_color(name):
    """An overlay mark's color: a theme color's name ("error") or "#rrggbb"."""
    return QColor(COLORS.get(name, name))


def small_font(scale=0.85, bold=False):
    font = QFont()
    font.setPointSizeF(max(6.0, font.pointSizeF() * scale))
    font.setBold(bold)
    return font


def elided(text, font, width):
    return QFontMetrics(font).elidedText(text, Qt.ElideRight, int(width))


def host_line(host):
    """A host in its port's box: its name and address (or MAC), then its VLAN."""
    names = [part for part in (host.name, host.ip) if part] or [host.mac or "?"]
    return "  ".join(names), f"VLAN {host.vlan}" if host.vlan else "VLAN ?"


def port_height(hosts):
    """A port box's height: a header, a line per host (up to HOST_LINES), and a "more" line."""
    lines = min(len(hosts), HOST_LINES) + (1 if len(hosts) > HOST_LINES else 0)
    return PORT_HEADER + lines * LINE_HEIGHT + 6


def exit_distance(rect, direction):
    """How far a line from (0, 0) along direction (a unit vector) goes before it leaves rect; 0 if it misses it."""
    entry, leave = -math.inf, math.inf
    for d, low, high in ((direction.x(), rect.left(), rect.right()), (direction.y(), rect.top(), rect.bottom())):
        if abs(d) < 1e-9:
            if not low <= 0 <= high:
                return 0.0
            continue
        near, far = sorted((low / d, high / d))
        entry, leave = max(entry, near), min(leave, far)
    return leave if leave >= max(entry, 0) else 0.0


def link_source(link):
    """How a link is known, for its tooltip: CDP, LLDP, traceroute... or drawn by hand."""
    return "drawn by hand" if link.manual else " + ".join(PROTOCOL_NAMES.get(protocol, protocol)
                                                          for protocol in link.protocols)


def host_tooltip(port, hosts):
    lines = [f"{port}:"]
    for host in hosts[:40]:
        parts = [host.mac, host.ip, host.name, host.vendor, f"VLAN {host.vlan}" if host.vlan else "",
                 "(added by hand)" if host.manual else "", host.note]
        lines.append("  " + "  ".join(part for part in parts if part))
    if len(hosts) > 40:
        lines.append(f"  ...and {len(hosts) - 40} more (see the Hosts tab)")
    return "\n".join(lines)


class NodeItem(QGraphicsItem):
    """Something on the map that links join and the user can drag: a device, or on the logical view a subnet or a
    hop traceroute found."""

    def __init__(self, key, label, view):
        super().__init__()
        self.key, self.label, self.view = key, label, view
        self.links = []
        self.port_items = []
        self.host_count = 0
        self.expanded = False
        self.highlight = None  # Color of a ring drawn round it (Compare's added and changed devices)
        self.mark = None  # The overlay showing's netmap.overlays.Mark for it (see MapView.set_overlay)
        self.base_tip = None  # Its tooltip without what the overlay showing adds (once one has)
        self.group_item = None  # The GroupItem it's directly in
        self.setFlags(QGraphicsItem.ItemIsMovable | QGraphicsItem.ItemIsSelectable
                      | QGraphicsItem.ItemSendsGeometryChanges)
        self.setZValue(2)

    def set_highlight(self, color):
        self.highlight = color
        self.update()

    def set_mark(self, mark):
        if self.base_tip is None:
            self.base_tip = self.toolTip()
        self.mark = mark
        self.setToolTip(self.base_tip + (f"\n{mark.note}" if mark is not None and mark.note else ""))
        self.update()

    def draw_highlight(self, painter, rect, radius):
        if self.highlight:
            ring = QPainterPath()
            ring.addRoundedRect(rect.adjusted(-6, -6, 6, 6), radius + 4, radius + 4)
            painter.setPen(QPen(QColor(self.highlight), 5))
            painter.drawPath(ring)

    def draw_selection(self, painter, path, rect, radius):
        """Selected: a white ring just outside the box and a light wash over it, leaving its outline (the device's
        type, or up or down while monitored) as it is."""
        if not self.isSelected():
            return
        wash = QColor(COLORS["selection"])
        wash.setAlpha(28)
        painter.fillPath(path, wash)
        ring = QPainterPath()
        ring.addRoundedRect(rect.adjusted(-3, -3, 3, 3), radius + 2, radius + 2)
        painter.setPen(QPen(QColor(COLORS["selection"]), 2))
        painter.drawPath(ring)

    def center(self):
        return self.pos()

    def footprint(self):
        """The rectangles (round its center) a link's port label has to clear."""
        return [NODE_RECT]

    def itemChange(self, change, value):
        if change == QGraphicsItem.ItemPositionHasChanged:
            for link in self.links:
                link.update_position()
            if self.group_item is not None and not self.view.groups_suspended:
                self.group_item.update_rect()
        elif change == QGraphicsItem.ItemSelectedHasChanged:
            self.update()
        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        super().mousePressEvent(event)
        if event.button() == Qt.LeftButton:
            self.view.begin_node_drag(self)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)
        self.view.node_dragged(self)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        self.view.on_item_moved()


class DeviceItem(NodeItem):
    def __init__(self, device, host_ports, view):
        super().__init__(device.key, device.label, view)
        self.device, self.host_ports = device, host_ports
        self.monitor_state = None  # A monitor.DeviceStatus while the device is monitored
        self.news_text = ""  # "NEW", or "2 new hosts": found by watching and not looked at yet
        self.rect = QRectF(-NODE_WIDTH / 2, -NODE_HEIGHT / 2, NODE_WIDTH, NODE_HEIGHT)
        self.host_count = sum(len(hosts) for hosts in host_ports.values())
        self.badge = QRectF(-45, NODE_HEIGHT / 2 + 4, 90, BADGE_HEIGHT) if self.host_count else QRectF()
        tip = [device.label, KIND_NAMES.get(device.kind, device.kind), device.mgmt_ip, device.platform,
               device.found_by, device.error, device.note]
        if self.host_count:
            tip.append(f"{self.host_count} hosts: double-click to show them by port")
        self.setToolTip("\n".join(part for part in tip if part))

    def boundingRect(self):
        return self.rect.adjusted(-9, -9 - NEWS_HEIGHT, 9, 9).united(self.badge.adjusted(-2, -2, 2, 2))

    def footprint(self):
        return [self.rect, self.badge] if self.host_count else [self.rect]

    def set_news(self, text):
        if text != self.news_text:
            self.news_text = text
            self.update()

    def draw_news(self, painter):
        """A green tag over the top right corner: new to the map, or has new hosts."""
        font = small_font(0.7, bold=True)
        width = QFontMetrics(font).horizontalAdvance(self.news_text) + 12
        tag = QRectF(self.rect.right() - width + 4, self.rect.top() - NEWS_HEIGHT + 3, width, NEWS_HEIGHT)
        path = QPainterPath()
        path.addRoundedRect(tag, NEWS_HEIGHT / 2, NEWS_HEIGHT / 2)
        painter.fillPath(path, QColor(COLORS["success"]))
        painter.setFont(font)
        painter.setPen(QColor(COLORS["panel"]))
        painter.drawText(tag, Qt.AlignCenter, self.news_text)

    def paint(self, painter, option, widget=None):
        device = self.device
        state = self.monitor_state
        color = QColor(KIND_COLORS.get(device.kind, COLORS["muted"]))
        painter.setRenderHint(QPainter.Antialiasing)
        self.draw_highlight(painter, self.rect, 7)
        outline = QColor(COLORS["error"]) if device.source == UNREACHABLE else color
        if state is not None:  # Monitored: up/down outranks the device type, which the tag still names
            outline = QColor(STATUS_COLORS[state.status])
        marked = self.mark is not None
        if marked:  # An overlay's color outranks both (the status dot still says up or down)
            outline = mark_color(self.mark.color)
        pen = QPen(outline, 3 if marked else 2.6 if state is not None else 1.6)
        if device.source != SNMP:
            pen.setStyle(Qt.DashLine)
        path = QPainterPath()
        path.addRoundedRect(self.rect, 7, 7)
        painter.fillPath(path, QColor(COLORS["panel"]))
        strip = QPainterPath()
        strip.addRoundedRect(QRectF(self.rect.left(), self.rect.top(), STRIP_WIDTH, self.rect.height()), 7, 7)
        painter.save()
        painter.setClipRect(QRectF(self.rect.left(), self.rect.top(), STRIP_WIDTH, self.rect.height()))
        faded = QColor(outline)
        faded.setAlpha(60 if state is None and not marked else 140)
        painter.fillPath(strip, faded)
        painter.restore()
        painter.setPen(pen)
        painter.drawPath(path)
        self.draw_selection(painter, path, self.rect, 7)

        painter.setPen(QColor(outline if state is None and not marked else COLORS["text"]))
        painter.setFont(small_font(0.75, bold=True))
        painter.drawText(QRectF(self.rect.left(), self.rect.top(), STRIP_WIDTH, self.rect.height()), Qt.AlignCenter,
                         KIND_TAGS.get(device.kind, "?"))
        if state is not None and state.status == DOWN:  # Tint the box: it's the one to look at
            tint = QColor(COLORS["error"])
            tint.setAlpha(45)
            painter.fillPath(path, tint)
        left = self.rect.left() + STRIP_WIDTH + 6
        width = self.rect.right() - left - (18 if state is not None else 5)
        name_font = small_font(0.95, bold=True)
        name_font.setItalic(device.manual)  # Added by hand, as hosts added by hand are
        painter.setFont(name_font)
        painter.setPen(QColor(COLORS["error"] if device.source == UNREACHABLE else COLORS["text"]))
        painter.drawText(QRectF(left, self.rect.top() + 4, width, 18), Qt.AlignLeft | Qt.AlignVCenter,
                         elided(device.label, name_font, width))
        detail_font = small_font(0.8)
        painter.setFont(detail_font)
        painter.setPen(QColor(COLORS["muted"]))
        address = device.mgmt_ip if device.mgmt_ip != device.label else ""
        if state is not None and state.status == UP and state.rtt is not None:
            address = f"{address}  ·  {'<1' if state.rtt < 1 else state.rtt} ms".strip(" ·")
        lines = [(address, COLORS["muted"])]
        if state is not None and state.status == DOWN:
            lines.append((f"Down for {duration_text(time.time() - state.since)}", COLORS["error"]))
        elif device.source in (NO_SNMP, UNREACHABLE):
            lines.append((SOURCE_NAMES[device.source], COLORS["warning" if device.source == NO_SNMP else "error"]))
        else:
            lines.append((device.platform or (device.sys_descr.splitlines()[0] if device.sys_descr else "")
                          or ("Added by hand" if device.manual else ""), COLORS["muted"]))
        for row, (line, line_color) in enumerate((line, color) for line, color in lines if line):
            painter.setPen(QColor(line_color))
            painter.drawText(QRectF(left, self.rect.top() + 22 + row * 15, width, 15), Qt.AlignLeft | Qt.AlignVCenter,
                             elided(line, detail_font, width))

        if state is not None:
            self.draw_status_dot(painter, state)
        if self.news_text:
            self.draw_news(painter)

        if self.host_count:
            painter.setPen(QPen(QColor(COLORS["border"]), 1))
            badge = QPainterPath()
            badge.addRoundedRect(self.badge, BADGE_HEIGHT / 2, BADGE_HEIGHT / 2)
            painter.fillPath(badge, QColor(COLORS["panel_alt"]))
            painter.drawPath(badge)
            painter.setPen(QColor(COLORS["muted"]))
            painter.setFont(small_font(0.78))
            arrow = "▴" if self.expanded else "▾"
            painter.drawText(self.badge, Qt.AlignCenter, f"{arrow} {self.host_count} host"
                             f"{'' if self.host_count == 1 else 's'}")

    def mouseDoubleClickEvent(self, event):
        self.view.toggle_hosts(self)
        event.accept()

    def draw_status_dot(self, painter, state):
        """Monitoring: green when it answers ping, red when it's down, an empty ring until it's been checked."""
        center = QPointF(self.rect.right() - 10, self.rect.top() + 10)
        color = QColor(STATUS_COLORS[state.status])
        painter.setPen(QPen(color, 1.5))
        painter.setBrush(color if state.status != UNKNOWN else Qt.NoBrush)
        painter.drawEllipse(center, 5.5, 5.5)
        painter.setBrush(Qt.NoBrush)

    def set_expanded(self, expanded):
        if expanded == self.expanded:
            return
        self.expanded = expanded
        for item in self.port_items:
            self.scene().removeItem(item)
        self.port_items = []
        if expanded:
            ports = list(self.host_ports.items())
            columns = min(len(ports), PORT_COLUMNS)
            rows = [ports[start:start + columns] for start in range(0, len(ports), columns)]
            row_heights = [max(port_height(hosts) for _, hosts in row) for row in rows]
            width = columns * (PORT_WIDTH + PORT_GAP) - PORT_GAP
            top = self.clear_space(width, sum(row_heights) + PORT_GAP * len(rows))
            for row, row_height in zip(rows, row_heights):
                for column, (port, hosts) in enumerate(row):
                    item = HostPortItem(self, port, hosts)
                    item.setPos(-width / 2 + PORT_WIDTH / 2 + column * (PORT_WIDTH + PORT_GAP), top)
                    item.set_anchor()
                    self.port_items.append(item)
                top += row_height + PORT_GAP
        self.update()
        if self.group_item is not None:
            self.group_item.update_rect()

    def clear_space(self, width, height):
        """How far below the device (in its coordinates) a block of port boxes fits without covering other
        devices (such as the access points under a switch) or other switches' port boxes."""
        top = NODE_HEIGHT / 2 + BADGE_HEIGHT + 24
        others = [item.sceneBoundingRect() for item in self.scene().items()
                  if isinstance(item, DeviceItem) and item is not self]
        others += [item.mapRectToScene(item.rect).adjusted(-PORT_GAP, -PORT_GAP, PORT_GAP, PORT_GAP)
                   for item in self.scene().items()  # Other switches' hosts, when several are open
                   if isinstance(item, HostPortItem) and item.parentItem() is not self]
        for _ in range(40):
            block = QRectF(self.pos().x() - width / 2, self.pos().y() + top, width, height)
            if not any(block.intersects(other) for other in others):
                break
            top += NODE_HEIGHT / 2
        return top


class HostPortItem(QGraphicsItem):
    """One switch port's hosts, shown when the switch's hosts are opened. A child of the switch, so it moves with it."""

    def __init__(self, parent, port, hosts):
        super().__init__(parent)
        self.port, self.hosts = port, hosts
        self.rect = QRectF(-PORT_WIDTH / 2, 0, PORT_WIDTH, port_height(hosts))  # Hangs from its top middle
        self.anchor = QPointF()
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setToolTip(host_tooltip(port, hosts))

    def set_anchor(self):
        """Where the connector meets the switch's badge, in this item's coordinates."""
        self.prepareGeometryChange()
        self.anchor = QPointF(-self.pos().x(), -self.pos().y() + NODE_HEIGHT / 2 + BADGE_HEIGHT + 4)

    def boundingRect(self):
        return self.rect.adjusted(-2, -2, 2, 2).united(QRectF(self.anchor, QSizeF(1, 1)).adjusted(-2, -2, 2, 2))

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(QPen(QColor(COLORS["border"]), 1, Qt.DotLine))
        painter.drawLine(QPointF(0, self.rect.top()), self.anchor)
        shared = len(self.hosts) > SHARED_PORT_HOSTS
        pen = QPen(QColor(COLORS["selection"] if self.isSelected() else
                          COLORS["warning"] if shared else COLORS["border"]), 2 if self.isSelected() else 1)
        if all(host.manual for host in self.hosts):
            pen.setStyle(Qt.DashLine)  # Only hosts added by hand: not seen by the crawl
        path = QPainterPath()
        path.addRoundedRect(self.rect, 5, 5)
        painter.fillPath(path, QColor(COLORS["panel_alt"]))
        painter.setPen(pen)
        painter.drawPath(path)
        left, width = self.rect.left() + 6, PORT_WIDTH - 12
        bold = small_font(0.78, bold=True)
        painter.setFont(bold)
        painter.setPen(QColor(COLORS["text"]))
        header = QRectF(left, self.rect.top() + 2, width, PORT_HEADER - 2)
        painter.drawText(header, Qt.AlignLeft | Qt.AlignVCenter, self.port)
        if len(self.hosts) > 1:
            painter.setFont(small_font(0.72))
            painter.setPen(QColor(COLORS["warning"] if shared else COLORS["muted"]))
            painter.drawText(header, Qt.AlignRight | Qt.AlignVCenter,
                             f"{len(self.hosts)} hosts" + (": unmanaged switch?" if shared else ""))
        regular, vlan_font = small_font(0.74), small_font(0.7, bold=True)
        vlan_width = QFontMetrics(vlan_font).horizontalAdvance("VLAN 4094") + 4
        top = self.rect.top() + PORT_HEADER
        new_hosts = self.parentItem().view.new_hosts
        for host in self.hosts[:HOST_LINES]:
            name, vlan = host_line(host)
            if host.mac in new_hosts:
                painter.setPen(Qt.NoPen)
                painter.setBrush(QColor(COLORS["success"]))
                painter.drawEllipse(QPointF(left - 3, top + LINE_HEIGHT / 2), 2.5, 2.5)
                painter.setBrush(Qt.NoBrush)
            font = QFont(regular)
            font.setItalic(host.manual)  # Added by hand
            painter.setFont(font)
            painter.setPen(QColor(COLORS["muted"] if host.manual else COLORS["text"]))
            painter.drawText(QRectF(left, top, width - vlan_width, LINE_HEIGHT), Qt.AlignLeft | Qt.AlignVCenter,
                             elided(name, font, width - vlan_width - 4))
            painter.setFont(vlan_font)
            painter.setPen(QColor(COLORS["link"] if host.vlan else COLORS["muted"]))
            painter.drawText(QRectF(left + width - vlan_width, top, vlan_width, LINE_HEIGHT),
                             Qt.AlignRight | Qt.AlignVCenter, vlan)
            top += LINE_HEIGHT
        if len(self.hosts) > HOST_LINES:
            painter.setFont(regular)
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(QRectF(left, top, width, LINE_HEIGHT), Qt.AlignLeft | Qt.AlignVCenter,
                             f"+ {len(self.hosts) - HOST_LINES} more (see the tooltip or the Hosts tab)")


class SimpleNodeItem(NodeItem):
    """A subnet, a router only traceroute found, an unanswered hop (*) or this computer, on the logical view."""

    def __init__(self, node, view):
        super().__init__(node.key, node.label, view)
        self.node = node
        if node.kind == SUBNET:
            self.rect = QRectF(-NODE_WIDTH / 2 + 10, -18, NODE_WIDTH - 20, 36)
        elif node.kind == STAR:
            self.rect = QRectF(-16, -16, 32, 32)
        else:
            self.rect = QRectF(-NODE_WIDTH / 2 + 20, -22, NODE_WIDTH - 40, 44)
        self.setToolTip("\n".join(part for part in (node.label, node.detail) if part))

    def boundingRect(self):
        return self.rect.adjusted(-9, -9, 9, 9)

    def paint(self, painter, option, widget=None):
        node = self.node
        painter.setRenderHint(QPainter.Antialiasing)
        radius = self.rect.height() / 2 if node.kind in (SUBNET, STAR) else 6
        self.draw_highlight(painter, self.rect, radius)
        path = QPainterPath()
        path.addRoundedRect(self.rect, radius, radius)
        painter.fillPath(path, QColor(COLORS["panel_alt"] if node.kind == SUBNET else COLORS["panel"]))
        pen = QPen(QColor(COLORS[node.tone] if node.tone else COLORS["link"] if node.kind == SUBNET
                          else COLORS["muted"]), 2.2 if node.tone in ("error", "warning") else 1.4)
        if node.kind in (HOP, STAR):
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.drawPath(path)
        self.draw_selection(painter, path, self.rect, radius)
        bold = small_font(0.9, bold=True)
        painter.setFont(bold)
        painter.setPen(QColor(COLORS["text"]))
        if node.kind == STAR or not node.detail:
            painter.drawText(self.rect, Qt.AlignCenter, elided(node.label, bold, self.rect.width() - 10))
            return
        painter.drawText(self.rect.adjusted(5, 3, -5, -self.rect.height() / 2), Qt.AlignCenter,
                         elided(node.label, bold, self.rect.width() - 10))
        detail = small_font(0.75)
        painter.setFont(detail)
        painter.setPen(QColor(COLORS["muted"]))
        painter.drawText(self.rect.adjusted(5, self.rect.height() / 2, -5, -3), Qt.AlignCenter,
                         elided(node.detail, detail, self.rect.width() - 10))


class GroupItem(QGraphicsItem):
    """A site, building or room: a box round its devices (and the groups in it) with its name on a title bar, or when
    collapsed one box standing for all of them. Drag the title bar to move everything in it; double-click it to
    collapse or expand. Clicks inside the box (off the title bar) go to the background, so it can still be dragged
    to move around."""

    def __init__(self, group, view):
        super().__init__()
        self.group, self.key, self.view = group, group.key, view
        self.members = []  # DeviceItems directly in it
        self.children = []  # The GroupItems of the groups in it (a site's buildings, a building's rooms)
        self.parent_group = None
        self.links = []  # LinkItems drawn to it while it's collapsed
        self.rect = QRectF()
        self.frozen = False  # Kept still while devices are dragged, so they can be dropped out of it
        self.drop_target = False
        self.drag_from = None
        self.dragged = False
        self.setFlag(QGraphicsItem.ItemIsSelectable)
        self.setZValue(GROUP_Z.get(group.kind, -3))

    @property
    def label(self):
        return self.group.name

    def all_members(self):
        """Its devices and the devices of the groups in it."""
        return self.members + [item for child in self.children for item in child.all_members()]

    def center(self):
        return self.rect.center()

    def depth(self):
        """0 for a group that isn't in one, 1 for one in a group, 2 for one in a group in a group."""
        depth, parent = 0, self.parent_group
        while parent is not None and depth < 3:
            depth, parent = depth + 1, parent.parent_group
        return depth

    def member_rect(self, item):
        rect = item.sceneBoundingRect()
        if item.port_items:  # Its hosts' boxes, while they're showing
            rect = rect.united(item.mapRectToScene(item.childrenBoundingRect()))
        return rect

    def expanded_rect(self):
        """The box round everything in it, as if it weren't collapsed."""
        area = QRectF()
        for item in self.members:
            area = area.united(self.member_rect(item))
        for child in self.children:
            area = area.united(child.expanded_rect() if not child.group.collapsed else child.rect)
        if area.isNull():
            return area
        return area.adjusted(-GROUP_PAD, -GROUP_PAD - GROUP_TITLE, GROUP_PAD, GROUP_PAD)

    def update_rect(self, propagate=True):
        if self.frozen:
            return
        if self.group.collapsed:
            items = self.all_members()
            area = QRectF()
            for item in items:
                area = area.united(QRectF(item.pos().x() - NODE_WIDTH / 2, item.pos().y() - NODE_HEIGHT / 2,
                                          NODE_WIDTH, NODE_HEIGHT))
            rect = QRectF(0, 0, COLLAPSED_WIDTH, COLLAPSED_HEIGHT)
            rect.moveCenter(area.center())
        else:
            rect = self.expanded_rect()
        if rect != self.rect:
            self.prepareGeometryChange()
            self.rect = rect
            for link in self.links:
                link.update_position()
        if propagate and self.parent_group is not None:
            self.parent_group.update_rect()

    def title_rect(self):
        return self.rect if self.group.collapsed else QRectF(self.rect.left(), self.rect.top(), self.rect.width(),
                                                             GROUP_TITLE)

    def shape(self):
        path = QPainterPath()
        path.addRect(self.title_rect())
        return path

    def boundingRect(self):
        return self.rect.adjusted(-8, -8, 8, 8)

    def set_drop_target(self, on):
        if on != self.drop_target:
            self.drop_target = on
            self.update()

    def summary(self):
        members = self.all_members()
        down = sum(1 for item in members if item.monitor_state is not None and item.monitor_state.status == DOWN)
        text = f"{len(members)} device{'' if len(members) == 1 else 's'}"
        if self.children:
            noun = GROUP_KINDS.get(self.children[0].group.kind, "group").lower()
            text += f", {len(self.children)} {noun}{'' if len(self.children) == 1 else 's'}"
        return text, down

    def paint(self, painter, option, widget=None):
        if self.rect.isNull():
            return
        painter.setRenderHint(QPainter.Antialiasing)
        building = self.group.kind != SITE
        color = QColor(COLORS["warning"] if self.group.kind == ROOM else COLORS["link"] if building
                       else COLORS["accent"])
        selected = self.isSelected()
        text, down = self.summary()
        if self.group.collapsed:
            self.paint_collapsed(painter, color, selected, text, down)
            return
        path = QPainterPath()
        path.addRoundedRect(self.rect, 10, 10)
        fill = QColor(color)
        fill.setAlpha(22 if building else 14)
        painter.fillPath(path, fill)
        border = QColor(COLORS["success"] if self.drop_target else COLORS["selection"] if selected else color)
        if not (self.drop_target or selected):
            border.setAlpha(150)
        pen = QPen(border, 2.5 if self.drop_target or selected else 1.4)
        if self.drop_target:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.drawPath(path)
        title = self.title_rect()
        bar = QPainterPath()
        bar.addRoundedRect(title, 10, 10)
        painter.save()
        painter.setClipRect(title)
        fill.setAlpha(60 if building else 45)
        painter.fillPath(bar, fill)
        painter.restore()
        name_font = small_font(0.95, bold=True)
        painter.setFont(name_font)
        painter.setPen(QColor(COLORS["text"]))
        name = f"▾ {self.group.name}"
        name_width = min(QFontMetrics(name_font).horizontalAdvance(name) + 4, title.width() - 20)
        painter.drawText(QRectF(title.left() + 10, title.top(), name_width, title.height()),
                         Qt.AlignLeft | Qt.AlignVCenter, elided(name, name_font, name_width))
        detail = small_font(0.78)
        painter.setFont(detail)
        rest = QRectF(title.left() + 18 + name_width, title.top(), title.width() - name_width - 28, title.height())
        painter.setPen(QColor(COLORS["muted"]))
        painter.drawText(rest, Qt.AlignLeft | Qt.AlignVCenter,
                         elided(f"{GROUP_KINDS.get(self.group.kind, '')}  ·  {text}", detail, rest.width()))
        if down:
            painter.setPen(QColor(COLORS["error"]))
            painter.drawText(rest, Qt.AlignRight | Qt.AlignVCenter, f"{down} down")

    def paint_collapsed(self, painter, color, selected, text, down):
        """A stack of boxes: the top one names the group and says what's in it."""
        for offset in (8, 4):
            back = QPainterPath()
            back.addRoundedRect(self.rect.translated(offset, offset), 8, 8)
            painter.fillPath(back, QColor(COLORS["panel_alt"]))
            painter.setPen(QPen(QColor(COLORS["border"]), 1))
            painter.drawPath(back)
        path = QPainterPath()
        path.addRoundedRect(self.rect, 8, 8)
        painter.fillPath(path, QColor(COLORS["panel"]))
        strip_rect = QRectF(self.rect.left(), self.rect.top(), STRIP_WIDTH + 6, self.rect.height())
        strip = QPainterPath()
        strip.addRoundedRect(strip_rect, 8, 8)
        faded = QColor(color)
        faded.setAlpha(60)
        painter.save()
        painter.setClipRect(strip_rect)
        painter.fillPath(strip, faded)
        painter.restore()
        if down:
            tint = QColor(COLORS["error"])
            tint.setAlpha(45)
            painter.fillPath(path, tint)
        painter.setPen(QPen(QColor(COLORS["selection"]) if selected else color, 3 if selected else 1.8))
        painter.drawPath(path)
        painter.setPen(color)
        painter.setFont(small_font(0.72, bold=True))
        painter.drawText(strip_rect, Qt.AlignCenter, GROUP_TAGS.get(self.group.kind, "SITE"))
        left = strip_rect.right() + 6
        width = self.rect.right() - left - 6
        name_font = small_font(0.95, bold=True)
        painter.setFont(name_font)
        painter.setPen(QColor(COLORS["text"]))
        painter.drawText(QRectF(left, self.rect.top() + 5, width, 18), Qt.AlignLeft | Qt.AlignVCenter,
                         elided(self.group.name, name_font, width))
        detail = small_font(0.8)
        painter.setFont(detail)
        painter.setPen(QColor(COLORS["muted"]))
        painter.drawText(QRectF(left, self.rect.top() + 24, width, 15), Qt.AlignLeft | Qt.AlignVCenter,
                         elided(text, detail, width))
        painter.setPen(QColor(COLORS["error"] if down else COLORS["muted"]))
        painter.drawText(QRectF(left, self.rect.top() + 40, width, 15), Qt.AlignLeft | Qt.AlignVCenter,
                         f"{down} down" if down else "▸ double-click to expand")

    def mousePressEvent(self, event):
        if event.button() != Qt.LeftButton:
            event.ignore()
            return
        if event.modifiers() & Qt.ControlModifier:
            self.setSelected(not self.isSelected())
        elif not self.isSelected():
            self.scene().clearSelection()
            self.setSelected(True)
        # Already selected: keep what's selected with it, so dragging moves them all
        self.drag_from, self.dragged = event.scenePos(), False
        event.accept()

    def mouseMoveEvent(self, event):
        if self.drag_from is None:
            return
        delta = event.scenePos() - self.drag_from
        self.drag_from = event.scenePos()
        self.dragged = True
        if self.isSelected():
            self.view.move_selection(delta)
        else:
            self.view.move_group(self, delta)

    def mouseReleaseEvent(self, event):
        clicked = self.drag_from is not None and not self.dragged
        self.drag_from = None
        if self.dragged:
            self.view.on_item_moved()
        elif clicked and not event.modifiers() & Qt.ControlModifier:  # A click on one of several: just this one
            self.scene().clearSelection()
            self.setSelected(True)

    def mouseDoubleClickEvent(self, event):
        self.view.set_collapsed(self, not self.group.collapsed)
        event.accept()


class LinkItem(QGraphicsItem):
    """The links between two devices: one line, with the ports at each end (and "×2" for a port-channel's
    members). Either end can be a collapsed group, standing in for the devices in it."""

    def __init__(self, a_item, b_item, links, ends, label_of):
        """ends: for each link, its (device on a_item's side, device on b_item's side)."""
        super().__init__()
        self.a_item, self.b_item, self.links, self.ends = a_item, b_item, links, ends
        self.line = QLineF()
        self.setZValue(0)
        self.traced = all(link.protocols == ["icmp"] for link in links)
        self.manual = all(link.manual for link in links)  # Drawn by hand
        self.vlan_kind = None  # How it carries the VLAN highlighted (see MapView.set_vlan_focus)
        self.path_kind = None  # How Carry VLAN's planned path uses it (PATH_STYLES; see MapView.set_path_overlay)
        self.mark = None  # The overlay showing's Mark for it (the worst of its links'), or None
        self.base_tip = "\n".join(
            f"{label_of(a)} {link.port_on(a)}  —  {label_of(b)} {link.port_on(b)}  ({link_source(link)})"
            for link, (a, b) in zip(links, ends))
        self.setToolTip(self.base_tip)
        a_item.links.append(self)
        b_item.links.append(self)
        self.update_position()

    def ports_text(self, item):
        if isinstance(item, GroupItem):
            return ""  # Which device in it is in the tooltip
        side = 0 if item is self.a_item else 1
        ports = [port for port in (link.port_on(ends[side]) for link, ends in zip(self.links, self.ends)) if port]
        return ", ".join(ports) if len(ports) <= 2 else f"{len(ports)} ports"

    def update_position(self):
        self.prepareGeometryChange()
        self.line = QLineF(self.a_item.center(), self.b_item.center())

    def boundingRect(self):
        return QRectF(self.line.p1(), self.line.p2()).normalized().adjusted(-90, -20, 90, 20)

    def shape(self):
        """Just the line (a little wider, to be easy to right-click), not the box round it and its labels."""
        path = QPainterPath(self.line.p1())
        path.lineTo(self.line.p2())
        stroker = QPainterPathStroker()
        stroker.setWidth(10)
        return stroker.createStroke(path)

    def label_point(self, from_start):
        length = self.line.length()
        if length < 1:
            return self.line.p1()
        # Just outside the device's box (and its hosts badge, which a link going down passes through), along the line
        sign = 1 if from_start else -1
        direction = QPointF(self.line.dx() / length * sign, self.line.dy() / length * sign)
        item = self.a_item if from_start else self.b_item
        footprint = item.footprint() if isinstance(item, NodeItem) else [NODE_RECT]
        edge = max(exit_distance(rect, direction) for rect in footprint)
        distance = min(edge + 26, length / 2 - 10)
        start = self.line.p1() if from_start else self.line.p2()
        return start + direction * distance

    def paint(self, painter, option, widget=None):
        painter.setRenderHint(QPainter.Antialiasing)
        count = len(self.links)
        pen = QPen(QColor(COLORS["muted"]), 3.2 if count > 1 else 1.5)
        if self.vlan_kind is not None:
            pen = QPen(QColor(VLAN_LINK_COLORS[self.vlan_kind]), 4 if count > 1 else 3)
        if self.traced or self.vlan_kind in (NATIVE, ONE_END):
            pen.setStyle(Qt.DashLine)
        elif self.manual:
            pen.setStyle(Qt.DotLine)
        if self.mark is not None:
            pen = QPen(mark_color(self.mark.color), self.mark.width or (4 if count > 1 else 3))
            pen.setStyle(OVERLAY_LINE_STYLES.get(self.mark.style, Qt.SolidLine))
        if self.path_kind is not None:
            color, width, style = PATH_STYLES[self.path_kind]
            pen = QPen(QColor(color), width)
            pen.setStyle(style)
        painter.setPen(pen)
        painter.drawLine(self.line)
        if QStyleOptionGraphicsItem.levelOfDetailFromTransform(painter.worldTransform()) < LABEL_MIN_ZOOM:
            return  # Too small to read: zoom in to see the ports
        font = small_font(0.72)
        painter.setFont(font)
        metrics = QFontMetrics(font)
        labels = [(self.label_point(True), self.ports_text(self.a_item)),
                  (self.label_point(False), self.ports_text(self.b_item))]
        if count > 1:
            labels.append((self.line.center(), f"×{count}"))
        for point, text in labels:
            if not text:
                continue
            box = QRectF(0, 0, metrics.horizontalAdvance(text) + 8, metrics.height() + 2)
            box.moveCenter(point)
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(COLORS["background"]))
            painter.drawRoundedRect(box, 3, 3)
            painter.setPen(QColor(COLORS["text"] if text.startswith("×") else COLORS["muted"]))
            painter.drawText(box, Qt.AlignCenter, text)


class MapView(QGraphicsView):
    selection_changed = pyqtSignal(object)  # ("device", key), ("node", key), ("port", key, port) or None
    positions_changed = pyqtSignal()
    context_requested = pyqtSignal(str, object)  # Node key, global position
    port_context_requested = pyqtSignal(str, str, object)  # Switch key, port, global position
    group_context_requested = pyqtSignal(str, object)  # Group key, global position
    groups_changed = pyqtSignal()  # A group was collapsed or expanded here
    devices_dropped = pyqtSignal(object)  # {device key: group key, or "" for none} after a drag in or out of one
    background_context_requested = pyqtSignal(object, object)  # Scene position, global position
    link_context_requested = pyqtSignal(object, object)  # [Link] the line stands for, global position
    link_drawn = pyqtSignal(str, str)  # Drawing a link by hand: from device key, to device key
    device_picked = pyqtSignal(str)  # Picking devices one after another (Carry VLAN's Pick on Map): one clicked
    picking_stopped = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setScene(QGraphicsScene(self))
        self.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        # Drag the background to move around (or with the middle button); Shift and drag to select a group
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.setFocusPolicy(Qt.StrongFocus)
        self.pan_from = None
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setViewportUpdateMode(QGraphicsView.BoundingRectViewportUpdate)
        self.setBackgroundBrush(QColor(COLORS["background"]))
        self.items_by_key = {}
        self.new_hosts = set()  # MACs of hosts found by watching, not looked at yet
        self.link_items = []
        self.links = []
        self.group_items = {}
        self.groups_suspended = False  # Moving many devices at once: the groups' boxes are updated after
        self.groups_editable = True  # Dragging devices in and out of groups (not while crawling)
        self.drag = None  # Devices being dragged: {"moving": set of items, "start": {item: position}}
        self.network_map = None
        self.fit_pending = False
        self.auto_fit = False  # Fitted automatically and not zoomed or panned since: refit when resized
        self.drawing = None  # Drawing a link by hand: (DeviceItem it starts from, the rubber line)
        self.picking = False  # Picking devices one after another: each click on one is device_picked
        self.last_found = None  # (text, match) Find showed last, so Enter again goes on to the next
        self.vlan_focus = None  # netmap.vlans.Focus of the VLAN highlighted, or None
        self.overlay = None  # The netmap.overlays.Overlay showing (one at a time, instead of a VLAN), or None
        self.path_overlay = None  # Carry VLAN's planned path (see set_path_overlay), or None
        self.scene().selectionChanged.connect(self.on_selection_changed)

    def set_map(self, network_map, positions):
        self.cancel_drawing()
        self.scene().clear()
        self.items_by_key, self.link_items, self.group_items, self.drag = {}, [], {}, None
        self.vlan_focus = None  # Its links are new: the page highlights the VLAN again
        self.overlay = None  # Or shows its overlay again
        self.path_overlay = None  # And Carry VLAN draws its path again
        self.network_map, self.links = network_map, network_map.links
        self.groups_suspended = True
        for key, device in network_map.devices.items():
            item = DeviceItem(device, network_map.hosts_by_port(key), self)
            item.setPos(*positions.get(key, (0, 0)))
            self.scene().addItem(item)
            self.items_by_key[key] = item
        self.groups_suspended = False
        self.rebuild_groups()
        self.update_scene_rect()

    def clear_map(self):
        """Show nothing (no map open)."""
        self.cancel_drawing()
        self.scene().clear()
        self.items_by_key, self.link_items, self.group_items, self.drag = {}, [], {}, None
        self.vlan_focus = None  # Its links are new: the page highlights the VLAN again
        self.overlay = None  # Or shows its overlay again
        self.path_overlay = None  # And Carry VLAN draws its path again
        self.network_map, self.links, self.last_found = None, [], None
        self.update_scene_rect()

    def set_graph(self, nodes, links, positions):
        """Show the logical view: l3.L3Nodes (devices drawn as on the physical view) and the links between them."""
        self.cancel_drawing()
        self.scene().clear()
        self.items_by_key, self.link_items, self.group_items, self.drag = {}, [], {}, None
        self.vlan_focus = None  # Its links are new: the page highlights the VLAN again
        self.overlay = None  # Or shows its overlay again
        self.path_overlay = None  # And Carry VLAN draws its path again
        self.network_map, self.links = None, links
        for key, node in nodes.items():
            item = DeviceItem(node.device, {}, self) if node.device is not None else SimpleNodeItem(node, self)
            item.setPos(*positions.get(key, (0, 0)))
            self.scene().addItem(item)
            self.items_by_key[key] = item
        self.rebuild_links()
        self.update_scene_rect()

    def rebuild_links(self):
        """One line per pair of things showing: a device, or the collapsed group standing in for it."""
        for item in self.link_items:
            self.scene().removeItem(item)
        for item in list(self.items_by_key.values()) + list(self.group_items.values()):
            item.links = []
        self.link_items = []
        pairs = {}
        for link in self.links:
            if link.a not in self.items_by_key or link.b not in self.items_by_key:
                continue
            a_item, b_item = self.representative(link.a), self.representative(link.b)
            if a_item is b_item:
                continue  # Inside a collapsed group
            if id(a_item) > id(b_item):
                a_item, b_item = b_item, a_item
            ends = (link.a, link.b) if self.representative(link.a) is a_item else (link.b, link.a)
            entry = pairs.setdefault((id(a_item), id(b_item)), (a_item, b_item, [], []))
            entry[2].append(link)
            entry[3].append(ends)
        for a_item, b_item, links, ends in pairs.values():
            item = LinkItem(a_item, b_item, links, ends, lambda key: self.items_by_key[key].label)
            self.scene().addItem(item)
            self.link_items.append(item)
        if self.vlan_focus is not None or self.overlay is not None:  # The new lines show it too
            self.refresh_overlays()

    # ----------------------------------------------------------------- Groups

    def rebuild_groups(self):
        """Draw the map's sites and buildings again (after they changed), and the links to collapsed ones."""
        for item in self.group_items.values():
            self.scene().removeItem(item)
        self.group_items, self.drag = {}, None
        for item in self.items_by_key.values():
            item.group_item = None
        if self.network_map is not None:
            for group in self.network_map.groups:
                item = GroupItem(group, self)
                self.scene().addItem(item)
                self.group_items[group.key] = item
            for item in self.group_items.values():
                item.parent_group = self.group_items.get(item.group.parent)
                if item.parent_group is not None:
                    item.parent_group.children.append(item)
            for key, group_key in self.network_map.group_of.items():
                item, group_item = self.items_by_key.get(key), self.group_items.get(group_key)
                if item is not None and group_item is not None:
                    item.group_item = group_item
                    group_item.members.append(item)
        self.apply_collapsed()

    def representative(self, key):
        """What's drawn for a device: itself, or the outermost collapsed group it's in."""
        item = self.items_by_key[key]
        shown, group = item, item.group_item
        while group is not None:
            if group.group.collapsed:
                shown = group
            group = group.parent_group
        return shown

    def apply_collapsed(self):
        for key, item in self.items_by_key.items():
            visible = self.representative(key) is item
            if not visible:
                item.setSelected(False)
            item.setVisible(visible)
        for item in self.group_items.values():
            parent = item.parent_group
            hidden = False
            while parent is not None:
                hidden, parent = hidden or parent.group.collapsed, parent.parent_group
            item.setVisible(not hidden)
            # Collapsed, it stands in for a device: over the links to it rather than under everything
            item.setZValue(2 if item.group.collapsed else GROUP_Z.get(item.group.kind, -3))
        self.rebuild_links()
        self.update_groups()

    def set_collapsed(self, group_item, collapsed):
        group_item.group.collapsed = collapsed
        self.apply_collapsed()
        self.update_scene_rect()
        self.groups_changed.emit()

    def set_all_collapsed(self, collapsed):
        for item in self.group_items.values():
            item.group.collapsed = collapsed
        self.apply_collapsed()
        self.update_scene_rect()
        self.groups_changed.emit()

    def update_groups(self):
        """Fit every group's box round what's in it: rooms first, then the buildings and sites round them."""
        for item in sorted(self.group_items.values(), key=lambda item: -item.depth()):
            item.update_rect(propagate=False)

    def reveal(self, key):
        """Expand the collapsed groups hiding a device. Returns True if any were."""
        item = self.items_by_key.get(key)
        group = item.group_item if item is not None else None
        opened = False
        while group is not None:
            if group.group.collapsed:
                group.group.collapsed, opened = False, True
            group = group.parent_group
        if opened:
            self.apply_collapsed()
            self.update_scene_rect()
            self.groups_changed.emit()
        return opened

    def move_group(self, group_item, delta):
        self.groups_suspended = True
        for item in group_item.all_members():
            item.moveBy(delta.x(), delta.y())
        self.groups_suspended = False
        self.update_groups()

    def move_to(self, positions):
        """Move devices to {key: (x, y)}, as when the user drags them (the layout's saved)."""
        self.groups_suspended = True
        for key, (x, y) in positions.items():
            if key in self.items_by_key:
                self.items_by_key[key].setPos(x, y)
        self.groups_suspended = False
        self.update_groups()
        self.update_scene_rect()
        self.positions_changed.emit()

    def selected_keys(self):
        """The devices selected (on the logical view, any node), in the order they're drawn."""
        return [key for key, item in self.items_by_key.items() if item.isSelected() and item.isVisible()]

    def selected_group(self):
        groups = [item for item in self.scene().selectedItems() if isinstance(item, GroupItem)]
        return groups[0].key if len(groups) == 1 else None

    def selected_groups(self):
        """The group keys selected, leaving out ones inside another selected group (they move with it)."""
        chosen = {item for item in self.group_items.values() if item.isSelected() and item.isVisible()}
        found = []
        for key, item in self.group_items.items():
            parent = item.parent_group
            while parent is not None and parent not in chosen:
                parent = parent.parent_group
            if item in chosen and parent is None:
                found.append(key)
        return found

    def sizes(self, keys):
        return {key: (self.items_by_key[key].rect.width(), self.items_by_key[key].rect.height()) for key in keys}

    def boxes(self, keys, groups=()):
        """{key: (center x, center y, width, height)} for devices and groups to arrange or line up together: a
        group's key starts with GROUP_BOX, and devices in one of the groups are left out (they go with it)."""
        found, inside = {}, set()
        for group_key in groups:
            item = self.group_items.get(group_key)
            if item is not None and not item.rect.isNull():
                rect = item.rect
                found[GROUP_BOX + group_key] = (rect.center().x(), rect.center().y(), rect.width(), rect.height())
                inside.update(member.key for member in item.all_members())
        for key in keys:
            item = self.items_by_key.get(key)
            if item is not None and key not in inside:
                found[key] = (item.pos().x(), item.pos().y(), item.rect.width(), item.rect.height())
        return found

    def box_links(self, boxes):
        """(a, b) for each pair of the boxes a link joins (a group's box standing for the devices in it)."""
        box_of = {key: key for key in boxes}
        for box in boxes:
            item = self.group_items.get(box[len(GROUP_BOX):]) if box.startswith(GROUP_BOX) else None
            if item is not None:
                box_of.update((member.key, box) for member in item.all_members())
        return [(box_of[a], box_of[b]) for a, b in ((link.a, link.b) for link in self.links)
                if a in box_of and b in box_of and box_of[a] != box_of[b]]

    def move_boxes(self, centers):
        """Move devices and groups (from boxes()) so their centers are at {key: (x, y)}, as when the user drags them
        (the layout's saved): a group with everything in it."""
        self.groups_suspended = True
        for key, (x, y) in centers.items():
            if key.startswith(GROUP_BOX):
                item = self.group_items.get(key[len(GROUP_BOX):])
                if item is not None:
                    dx, dy = x - item.rect.center().x(), y - item.rect.center().y()
                    for member in item.all_members():
                        member.moveBy(dx, dy)
            elif key in self.items_by_key:
                self.items_by_key[key].setPos(x, y)
        self.groups_suspended = False
        self.update_groups()
        self.update_scene_rect()
        self.positions_changed.emit()

    def move_selection(self, delta):
        """Dragging a group's title: move the groups selected with everything in them, and the devices selected."""
        moving = set()
        for key in self.selected_groups():
            moving.update(self.group_items[key].all_members())
        moving.update(item for item in self.scene().selectedItems() if isinstance(item, NodeItem))
        self.groups_suspended = True
        for item in moving:
            item.moveBy(delta.x(), delta.y())
        self.groups_suspended = False
        self.update_groups()

    def group_boxes(self):
        """[(group, (left, top, width, height))] for each group as if expanded (for draw.io), sites first."""
        boxes = []
        for item in sorted(self.group_items.values(), key=lambda item: item.depth()):
            rect = item.expanded_rect()
            if not rect.isNull():
                boxes.append((item.group, (rect.left(), rect.top(), rect.width(), rect.height())))
        return boxes

    def begin_node_drag(self, item):
        """Devices are about to be dragged: groups they're not all of stay still, so they can be dropped out."""
        if not self.group_items or not self.groups_editable:
            self.drag = None
            return
        moving = {other for other in self.scene().selectedItems() if isinstance(other, NodeItem)} | {item}
        # The groups selected with it go along (what's in them moved here, as Qt only moves what's selected)
        carried = {member for key in self.selected_groups() for member in self.group_items[key].all_members()} - moving
        self.drag = {"moving": moving, "start": {other: QPointF(other.pos()) for other in moving},
                     "carried": carried, "last": QPointF(item.pos())}
        for group_item in self.group_items.values():
            group_item.frozen = not set(group_item.all_members()) <= moving | carried

    def drop_target(self, point):
        """The innermost group showing whose box (as it was when the drag started) holds the point."""
        found = [item for item in self.group_items.values()
                 if item.frozen and item.isVisible() and not item.group.collapsed and item.rect.contains(point)]
        return min(found, key=lambda item: item.rect.width() * item.rect.height(), default=None)

    def node_dragged(self, item):
        if self.drag is None:
            return
        if self.drag["carried"]:
            delta = item.pos() - self.drag["last"]
            self.drag["last"] = QPointF(item.pos())
            self.groups_suspended = True
            for member in self.drag["carried"]:
                member.moveBy(delta.x(), delta.y())
            self.groups_suspended = False
            self.update_groups()
        target = self.drop_target(item.pos())
        for group_item in self.group_items.values():
            group_item.set_drop_target(group_item is target and target is not item.group_item)

    def end_node_drag(self):
        """Devices dropped: into a group's box puts them in it, out of their group's box takes them out."""
        drag, self.drag = self.drag, None
        if drag is None:
            return {}
        changes = {}
        for item in drag["moving"]:
            if item.pos() == drag["start"][item] or not isinstance(item, DeviceItem):
                continue
            current = item.group_item
            if current is not None and not current.frozen:
                continue  # Its whole group moved with it
            target = self.drop_target(item.pos())
            if target is not current:
                changes[item.key] = target.key if target is not None else ""
        for group_item in self.group_items.values():
            group_item.frozen = False
            group_item.set_drop_target(False)
        self.update_groups()
        return changes

    def set_statuses(self, status_of):
        """Monitoring: status_of(key) gives a device's monitor.DeviceStatus, or None if it isn't monitored."""
        for key, item in self.items_by_key.items():
            if isinstance(item, DeviceItem):
                state = status_of(key)
                if state is not item.monitor_state or state is not None:
                    item.monitor_state = state
                    item.update()
        for item in self.group_items.values():
            item.update()  # How many in it are down

    def set_news(self, news):
        """Mark what watching found and nobody's looked at yet (a map's news: {"device:key" or "host:MAC": ...})."""
        self.new_hosts = {ref[5:] for ref in news if ref.startswith("host:")}
        new_devices = {ref[7:] for ref in news if ref.startswith("device:")}
        for key, item in self.items_by_key.items():
            if isinstance(item, DeviceItem):
                hosts = sum(1 for hosts in item.host_ports.values() for host in hosts if host.mac in self.new_hosts)
                item.set_news("NEW" if key in new_devices else f"{hosts} new host{'' if hosts == 1 else 's'}"
                              if hosts else "")
                for port_item in item.port_items:
                    port_item.update()

    def set_vlan_focus(self, focus):
        """Highlight a VLAN (a netmap.vlans.Focus): the devices in it and the links carrying it stay bright (the links
        colored by how they carry it), the rest fade. None shows everything again."""
        self.vlan_focus = focus
        self.refresh_overlays()

    def set_overlay(self, overlay):
        """Show a netmap.overlays.Overlay: its devices and links in their colors, with what it says of them in their
        tooltips, and (if it fades) the rest faded. None takes it off."""
        self.overlay = overlay
        self.refresh_overlays()

    def refresh_overlays(self):
        """Draw the VLAN highlighted, the overlay showing, and Carry VLAN's path (over both), as they are now."""
        focus, overlay = self.vlan_focus, self.overlay
        for key, item in self.items_by_key.items():
            bright = (focus is None or key in focus.devices) and \
                (overlay is None or not overlay.fade or key in overlay.devices)
            item.setOpacity(1.0 if bright else FADED)
            if item.mark is not None or overlay is not None:
                item.set_mark(overlay.devices.get(key) if overlay is not None else None)
        for item in self.link_items:
            kinds = [focus.links.get(id(link)) for link in item.links] if focus is not None else []
            kinds = [kind for kind in kinds if kind]
            item.vlan_kind = (ONE_END if ONE_END in kinds else kinds[0]) if kinds else None
            marks = [overlay.links[id(link)] for link in item.links if id(link) in overlay.links] \
                if overlay is not None else []
            marks.sort(key=lambda mark: OVERLAY_ORDER.index(mark.color) if mark.color in OVERLAY_ORDER
                       else len(OVERLAY_ORDER))
            item.mark = marks[0] if marks else None
            bright = (focus is None or kinds) and (overlay is None or not overlay.fade or marks)
            item.setOpacity(1.0 if bright else FADED)
            tip = item.base_tip
            if item.vlan_kind is not None:
                tip += f"\nVLAN {focus.vlan}: {VLAN_LINK_NAMES[item.vlan_kind]}"
            tip += "".join(f"\n{note}" for note in dict.fromkeys(mark.note for mark in marks if mark.note))
            item.setToolTip(tip)
            item.update()
        for item in self.group_items.values():
            members = item.all_members()
            item.setOpacity(1.0 if not members or any(member.opacity() == 1.0 for member in members) else FADED)
        self.apply_path_overlay()

    def set_path_overlay(self, overlay):
        """Draw Carry VLAN's planned path over the links: {"vlan": number, "devices": keys kept bright, "links":
        {Link.key: (PATH_PLANNED, PATH_CARRIES... , what it does there)}}. None takes it off."""
        self.path_overlay = overlay
        self.set_vlan_focus(self.vlan_focus)  # Opacities and tooltips as the VLAN highlight has them, then the path

    def apply_path_overlay(self):
        overlay = self.path_overlay
        for item in self.link_items:
            tip = item.toolTip().split("\nCarry VLAN")[0]
            found = [overlay["links"][link.key] for link in item.links
                     if overlay is not None and link.key in overlay["links"]]
            found.sort(key=lambda entry: PATH_ORDER.index(entry[0]))
            item.path_kind = found[0][0] if found else None
            if found:
                item.setOpacity(1.0)
                tip += f"\nCarry VLAN {overlay['vlan']}: " + "; ".join(dict.fromkeys(note for _, note in found))
            item.setToolTip(tip)
            item.update()
        if overlay is not None:
            for key in overlay["devices"]:
                item = self.items_by_key.get(key)
                if item is not None:
                    item.setOpacity(1.0)
                    if item.group_item is not None:
                        item.group_item.setOpacity(1.0)

    def set_highlights(self, colors):
        """Ring the items in {key: color}; clear the rest."""
        for key, item in self.items_by_key.items():
            item.set_highlight(colors.get(key))

    def update_scene_rect(self):
        rect = self.scene().itemsBoundingRect()
        self.setSceneRect(rect.adjusted(-2000, -2000, 2000, 2000))

    def positions(self):
        return {key: (item.pos().x(), item.pos().y()) for key, item in self.items_by_key.items()}

    # ----------------------------------------------------------------- Navigation

    def wheelEvent(self, event):
        steps = event.angleDelta().y() / 120
        self.auto_fit = False
        if steps:
            self.zoom(ZOOM_STEP ** steps)
        event.accept()

    def zoom(self, factor):
        current = self.transform().m11()
        factor = max(MIN_ZOOM / current, min(MAX_ZOOM / current, factor))
        self.scale(factor, factor)

    def request_fit(self):
        """Fit the map to the view now if it's showing, or when it's next shown (it needs its real size)."""
        self.fit_pending = True
        if self.isVisible():
            QTimer.singleShot(0, self.fit)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self.auto_fit:
            self.fit()

    # ----------------------------------------------------------------- Drawing a link by hand

    def start_drawing(self, key):
        """A line from the device follows the mouse: click another device to link them (link_drawn), or the
        background, Esc or the right button to stop."""
        self.cancel_drawing()
        item = self.items_by_key.get(key)
        if not isinstance(item, DeviceItem) or not item.isVisible():
            return False
        line = QGraphicsLineItem(QLineF(item.pos(), item.pos()))
        line.setPen(QPen(QColor(COLORS["accent"]), 2, Qt.DashLine))
        line.setZValue(5)
        self.scene().addItem(line)
        self.drawing = (item, line)
        self.viewport().setMouseTracking(True)
        self.viewport().setCursor(Qt.CrossCursor)
        self.setFocus()
        return True

    def start_picking(self):
        """Each click on a device is device_picked, until the background is clicked, Esc or the right button (or
        stop_picking)."""
        self.cancel_drawing()
        self.picking = True
        self.viewport().setCursor(Qt.PointingHandCursor)
        self.setFocus()

    def stop_picking(self):
        if not self.picking:
            return
        self.picking = False
        self.viewport().unsetCursor()
        self.picking_stopped.emit()

    def cancel_drawing(self):
        if self.drawing is None:
            return
        _, line = self.drawing
        self.drawing = None
        try:
            self.scene().removeItem(line)
        except RuntimeError:  # Scene being torn down
            pass
        self.viewport().unsetCursor()

    def device_at(self, pos):
        """The device drawn at a point in the view (or whose hosts' box is there), or None. The line being drawn
        by hand ends under the mouse, on top of everything: look beneath it."""
        rubber = self.drawing[1] if self.drawing is not None else None
        item = next((item for item in self.items(pos) if item is not rubber), None)
        while item is not None and not isinstance(item, DeviceItem):
            item = item.parentItem()
        return item

    def mousePressEvent(self, event):
        self.auto_fit = False
        if self.picking:
            target = self.device_at(event.pos()) if event.button() == Qt.LeftButton else None
            if target is None:
                self.stop_picking()
            else:
                self.device_picked.emit(target.key)
            event.accept()
            return
        if self.drawing is not None:
            start, _ = self.drawing
            target = self.device_at(event.pos()) if event.button() == Qt.LeftButton else None
            if target is start:
                event.accept()
                return  # Still choosing the other end
            self.cancel_drawing()
            if target is not None:
                self.link_drawn.emit(start.key, target.key)
            event.accept()
            return
        if event.button() == Qt.MiddleButton:
            self.pan_from = event.pos()
            self.viewport().setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        if event.button() == Qt.LeftButton:
            # Drag the background to move around; Shift and drag to draw a box selecting what's in it
            boxing = bool(event.modifiers() & Qt.ShiftModifier) and self.itemAt(event.pos()) is None
            self.setDragMode(QGraphicsView.RubberBandDrag if boxing else QGraphicsView.ScrollHandDrag)
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self.drawing is not None:
            start, line = self.drawing
            line.setLine(QLineF(start.pos(), self.mapToScene(event.pos())))
            event.accept()
            return
        if self.pan_from is not None:
            delta = event.pos() - self.pan_from
            self.pan_from = event.pos()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - delta.x())
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - delta.y())
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if self.pan_from is not None:
            self.pan_from = None
            self.viewport().unsetCursor()
            event.accept()
            return
        super().mouseReleaseEvent(event)
        if self.dragMode() == QGraphicsView.RubberBandDrag:
            self.setDragMode(QGraphicsView.ScrollHandDrag)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape and self.picking:
            self.stop_picking()
            event.accept()
        elif event.key() == Qt.Key_Escape and self.drawing is not None:
            self.cancel_drawing()
            event.accept()
        elif event.matches(QKeySequence.SelectAll):
            for item in self.items_by_key.values():
                item.setSelected(item.isVisible())
            event.accept()
        else:
            super().keyPressEvent(event)

    def showEvent(self, event):
        super().showEvent(event)
        if self.fit_pending:
            QTimer.singleShot(0, self.fit)

    def fit(self):
        self.fit_pending = False
        self.auto_fit = True
        rect = self.scene().itemsBoundingRect()
        if rect.isEmpty():
            return
        self.fitInView(rect.adjusted(-40, -40, 40, 40), Qt.KeepAspectRatio)
        if self.transform().m11() > 1.2:
            self.resetTransform()
            self.scale(1.2, 1.2)
            self.centerOn(rect.center())

    def show_device(self, key):
        item = self.items_by_key.get(key)
        if item is None:
            return False
        self.reveal(key)
        self.auto_fit = False
        self.scene().clearSelection()
        item.setSelected(True)
        self.centerOn(item)
        return True

    def show_devices(self, keys):
        """Select these devices (a link's two ends, say) and bring them into view."""
        items = [self.items_by_key[key] for key in keys if key in self.items_by_key]
        if not items:
            return False
        for key in keys:
            self.reveal(key)
        self.auto_fit = False
        self.scene().clearSelection()
        area = QRectF()
        for item in items:
            item.setSelected(True)
            area = area.united(item.sceneBoundingRect())
        if len(items) == 1:
            self.centerOn(items[0])
        else:
            self.ensureVisible(area, 40, 40)
            self.centerOn(area.center())
        return True

    def show_group(self, key):
        item = self.group_items.get(key)
        if item is None:
            return False
        parent, opened = item.parent_group, False
        while parent is not None:
            if parent.group.collapsed:
                parent.group.collapsed, opened = False, True
            parent = parent.parent_group
        if opened:
            self.apply_collapsed()
            self.groups_changed.emit()
        self.auto_fit = False
        self.scene().clearSelection()
        item.setSelected(True)
        self.ensureVisible(item.rect, 40, 40)
        self.centerOn(item.rect.center())
        return True

    def show_host(self, host):
        """Open the host's switch and select its port."""
        item = self.items_by_key.get(host.device)
        if item is None:
            return False
        self.reveal(host.device)
        item.set_expanded(True)
        self.auto_fit = False
        for port_item in item.port_items:
            if port_item.port == host.port:
                self.scene().clearSelection()
                port_item.setSelected(True)
                self.centerOn(port_item)
                return True
        return self.show_device(host.device)

    def find_matches(self, text):
        """Everything matching text (name, address, MAC, platform, vendor): devices, then sites, buildings and
        rooms, then hosts. Each is (kind, key, label), key being a device or group key, or a host's index."""
        text = text.strip().lower()
        if not text:
            return []
        compact = text.replace("-", "").replace(":", "").replace(".", "")
        matches = []
        for key, item in sorted(self.items_by_key.items()):
            device = getattr(item, "device", None)
            values = [item.label] + ([device.mgmt_ip, device.platform] + device.addresses if device else [])
            if any(text in value.lower() for value in values if value):
                matches.append(("device", key, item.label))
        if self.network_map is None:
            return matches
        for group_item in self.group_items.values():
            if text in group_item.group.name.lower():
                matches.append(("group", group_item.key, group_item.group.name))
        for index, host in enumerate(self.network_map.hosts):
            mac = host.mac.replace("-", "").lower()
            if (len(compact) >= 4 and compact in mac) or any(text in value.lower() for value in (host.ip, host.name,
                                                                                               host.vendor) if value):
                matches.append(("host", index, host.name or host.ip or host.mac))
        return matches

    def find(self, text, backward=False):
        """Select the next thing matching text, after the one found last time with the same text (or before it,
        backward), going round. Returns (position, count, label) of the one shown, or None if nothing matches."""
        matches = self.find_matches(text)
        if not matches:
            self.last_found = None
            return None
        last_text, last_match = self.last_found or (None, None)
        index = 0
        if last_text == text.strip().lower() and last_match in matches:
            index = (matches.index(last_match) + (-1 if backward else 1)) % len(matches)
        elif backward:
            index = len(matches) - 1
        kind, key, label = matches[index]
        if kind == "device":
            self.show_device(key)
        elif kind == "group":
            self.show_group(key)
        else:
            self.show_host(self.network_map.hosts[key])
        self.last_found = (text.strip().lower(), matches[index])
        return index + 1, len(matches), label

    def find_all(self, text):
        """Select every device matching text at once. Returns how many."""
        keys = [key for kind, key, _ in self.find_matches(text) if kind == "device"]
        self.last_found = None
        return len(keys) if self.show_devices(keys) else 0

    # ----------------------------------------------------------------- Items talking back

    def set_all_hosts_shown(self, shown):
        """Open (or close) every switch's hosts."""
        for item in self.items_by_key.values():
            if item.host_count:
                item.set_expanded(shown)
        self.update_scene_rect()

    def toggle_hosts(self, item):
        if item.host_count:
            item.set_expanded(not item.expanded)
            self.update_scene_rect()

    def on_item_moved(self):
        changes = self.end_node_drag()
        self.update_scene_rect()
        if changes:  # First, so the move and the change of group are one step for Undo
            self.devices_dropped.emit(changes)
        self.positions_changed.emit()

    def on_selection_changed(self):
        try:
            selected = self.scene().selectedItems()
        except RuntimeError:  # Scene being torn down
            return
        boxes = [item for item in selected if isinstance(item, (NodeItem, GroupItem))]
        if not selected:
            self.selection_changed.emit(None)
        elif len(boxes) > 1 or (boxes and len(selected) > len(boxes)):
            self.selection_changed.emit(("many", len(boxes)))
        elif isinstance(selected[0], GroupItem):
            self.selection_changed.emit(("group", selected[0].key))
        elif isinstance(selected[0], DeviceItem):
            self.selection_changed.emit(("device", selected[0].key))
        elif isinstance(selected[0], SimpleNodeItem):
            self.selection_changed.emit(("node", selected[0].key))
        elif isinstance(selected[0], HostPortItem):
            self.selection_changed.emit(("port", selected[0].parentItem().device.key, selected[0].port))

    def contextMenuEvent(self, event):
        if self.picking:
            self.stop_picking()
            event.accept()
            return
        if self.drawing is not None:
            self.cancel_drawing()
            event.accept()
            return
        item = self.itemAt(event.pos())
        if isinstance(item, LinkItem):
            self.link_context_requested.emit(list(item.links), event.globalPos())
            return
        if isinstance(item, HostPortItem):
            if not item.isSelected():
                self.scene().clearSelection()
                item.setSelected(True)
            self.port_context_requested.emit(item.parentItem().key, item.port, event.globalPos())
            return
        if isinstance(item, GroupItem):
            if not item.isSelected():
                self.scene().clearSelection()
                item.setSelected(True)
            self.group_context_requested.emit(item.key, event.globalPos())
            return
        while item is not None and not isinstance(item, NodeItem):
            item = item.parentItem()
        if item is None:
            self.background_context_requested.emit(self.mapToScene(event.pos()), event.globalPos())
            return
        if not item.isSelected():  # Keep a selection of several when right-clicking one of them
            self.scene().clearSelection()
            item.setSelected(True)
        self.context_requested.emit(item.key, event.globalPos())

    # ----------------------------------------------------------------- Pictures

    def render_image(self, scale=2.0):
        rect = self.scene().itemsBoundingRect().adjusted(-30, -30, 30, 30)
        size = QSize(max(1, math.ceil(rect.width() * scale)), max(1, math.ceil(rect.height() * scale)))
        image = QImage(size, QImage.Format_ARGB32)
        image.fill(QColor(COLORS["background"]))
        painter = QPainter(image)
        painter.setRenderHints(QPainter.Antialiasing | QPainter.TextAntialiasing)
        self.render_scene(painter, QRectF(0, 0, size.width(), size.height()), rect)
        painter.end()
        return image

    def render_svg(self, path):
        from PyQt5.QtSvg import QSvgGenerator  # Only needed for this export
        rect = self.scene().itemsBoundingRect().adjusted(-30, -30, 30, 30)
        generator = QSvgGenerator()
        generator.setFileName(str(path))
        generator.setSize(QSize(math.ceil(rect.width()), math.ceil(rect.height())))
        generator.setViewBox(QRectF(0, 0, rect.width(), rect.height()))
        generator.setTitle("Network map")
        painter = QPainter(generator)
        painter.fillRect(QRectF(0, 0, rect.width(), rect.height()), QColor(COLORS["background"]))
        self.render_scene(painter, QRectF(0, 0, rect.width(), rect.height()), rect)
        painter.end()

    def render_scene(self, painter, target, source):
        selected = self.scene().selectedItems()
        self.scene().clearSelection()  # The picture shouldn't show what happened to be selected
        self.scene().render(painter, target, source)
        for item in selected:
            item.setSelected(True)
