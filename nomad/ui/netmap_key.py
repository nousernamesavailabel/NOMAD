"""The Network Map's key: what its colors, outlines and line styles mean, each drawn as the map draws it."""
from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QGridLayout, QLabel, QScrollArea, QVBoxLayout, QWidget

from ..netmap.model import AP, FIREWALL, ROUTER, SERVER, SHARED_PORT_HOSTS, SWITCH, UNKNOWN
from ..netmap.monitor import DOWN, UNKNOWN as NOT_CHECKED, UP
from ..netmap.vlans import ACCESS, NATIVE, ONE_END, TAGGED
from .netmap_view import KIND_COLORS, KIND_TAGS, PATH_BLOCKED, PATH_CARRIES, PATH_CHOSEN, PATH_OFFERED, PATH_PLANNED, \
    PATH_STYLES, STATUS_COLORS, VLAN_LINK_COLORS
from .theme import COLORS

SWATCH_WIDTH, SWATCH_HEIGHT = 96, 40
STRIP = 24  # The colored strip down a device's left side, scaled down from the map's


def font(scale=0.8, bold=False, italic=False):
    result = QFont()
    result.setPointSizeF(max(6.0, result.pointSizeF() * scale))
    result.setBold(bold)
    result.setItalic(italic)
    return result


def rounded(rect, radius):
    path = QPainterPath()
    path.addRoundedRect(rect, radius, radius)
    return path


def device(kind=SWITCH, dashed=False, unreachable=False, italic=False, status=None, ring=None, selected=False,
           news=False, mark=None):
    """A device's box, as the map draws it: its kind's color (or up/down while monitored, or an overlay's color)
    round it and on its tag."""
    def paint(painter, rect):
        box = rect.adjusted(6, 8 if news else 5, -6, -5)
        color = QColor(KIND_COLORS.get(kind, COLORS["muted"]))
        outline = QColor(COLORS["error"]) if unreachable else color
        if status is not None:
            outline = QColor(STATUS_COLORS[status])
        if mark is not None:
            outline = QColor(COLORS.get(mark, mark))
        if ring:
            ring_color = QColor(ring)
            ring_color.setAlpha(170)
            painter.setPen(QPen(ring_color, 3))
            painter.drawPath(rounded(box.adjusted(-4, -4, 4, 4), 8))
        path = rounded(box, 5)
        painter.fillPath(path, QColor(COLORS["panel"]))
        strip = QRectF(box.left(), box.top(), STRIP, box.height())
        faded = QColor(outline)
        faded.setAlpha(60 if status is None and mark is None else 140)
        painter.save()
        painter.setClipRect(strip)
        painter.fillPath(path, faded)
        painter.restore()
        pen = QPen(outline, 2.6 if mark is not None else 2.4 if status is not None else 1.6)
        if dashed:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.drawPath(path)
        if status == DOWN:
            tint = QColor(COLORS["error"])
            tint.setAlpha(45)
            painter.fillPath(path, tint)
        if selected:
            wash = QColor(COLORS["selection"])
            wash.setAlpha(28)
            painter.fillPath(path, wash)
            painter.setPen(QPen(QColor(COLORS["selection"]), 2))
            painter.drawPath(rounded(box.adjusted(-3, -3, 3, 3), 7))
        painter.setFont(font(0.62, bold=True))
        painter.setPen(QColor(outline if status is None and mark is None else COLORS["text"]))
        painter.drawText(strip, Qt.AlignCenter, KIND_TAGS.get(kind, "?"))
        painter.setFont(font(0.72, bold=True, italic=italic))
        painter.setPen(QColor(COLORS["error"] if unreachable else COLORS["text"]))
        painter.drawText(box.adjusted(STRIP + 4, 0, -14 if status is not None else -2, 0),
                         Qt.AlignLeft | Qt.AlignVCenter, "name")
        if status is not None:
            dot = QColor(STATUS_COLORS[status])
            painter.setPen(QPen(dot, 1.5))
            painter.setBrush(dot if status != NOT_CHECKED else Qt.NoBrush)
            painter.drawEllipse(QPointF(box.right() - 7, box.top() + 7), 3.5, 3.5)
            painter.setBrush(Qt.NoBrush)
        if news:
            tag = QRectF(box.right() - 28, box.top() - 8, 30, 12)
            painter.fillPath(rounded(tag, 6), QColor(COLORS["success"]))
            painter.setFont(font(0.55, bold=True))
            painter.setPen(QColor(COLORS["panel"]))
            painter.drawText(tag, Qt.AlignCenter, "NEW")
    return paint


def line(color=COLORS["muted"], width=1.5, style=Qt.SolidLine, label="", faded=False):
    """A link between two devices (two small boxes), as the map draws it."""
    def paint(painter, rect):
        middle = rect.center().y()
        ends = [QRectF(rect.left(), middle - 7, 14, 14), QRectF(rect.right() - 14, middle - 7, 14, 14)]
        pen_color = QColor(color)
        if faded:
            pen_color.setAlpha(60)
        pen = QPen(pen_color, width)
        pen.setStyle(style)
        painter.setPen(pen)
        painter.drawLine(QPointF(ends[0].right(), middle), QPointF(ends[1].left(), middle))
        painter.setPen(QPen(QColor(COLORS["border"]), 1))
        for end in ends:
            painter.fillPath(rounded(end, 3), QColor(COLORS["panel"]))
            painter.drawPath(rounded(end, 3))
        if label:
            painter.setFont(font(0.62))
            box = QRectF(0, 0, 22, 12)
            box.moveCenter(rect.center())
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(COLORS["background"]))
            painter.drawRoundedRect(box, 3, 3)
            painter.setBrush(Qt.NoBrush)
            painter.setPen(QColor(COLORS["text"]))
            painter.drawText(box, Qt.AlignCenter, label)
    return paint


def group(color, collapsed=False):
    """A site, building or room: a tinted box with a title bar, or a stack of boxes when collapsed."""
    def paint(painter, rect):
        color_ = QColor(color)
        box = rect.adjusted(4, 4, -4, -4)
        if collapsed:
            box = box.adjusted(0, 0, -8, -6)
            for offset in (6, 3):
                back = rounded(box.translated(offset, offset), 5)
                painter.fillPath(back, QColor(COLORS["panel_alt"]))
                painter.setPen(QPen(QColor(COLORS["border"]), 1))
                painter.drawPath(back)
            path = rounded(box, 5)
            painter.fillPath(path, QColor(COLORS["panel"]))
            painter.setPen(QPen(color_, 1.8))
            painter.drawPath(path)
            return
        path = rounded(box, 7)
        fill = QColor(color_)
        fill.setAlpha(22)
        painter.fillPath(path, fill)
        painter.save()
        painter.setClipRect(QRectF(box.left(), box.top(), box.width(), 10))
        fill.setAlpha(60)
        painter.fillPath(path, fill)
        painter.restore()
        border = QColor(color_)
        border.setAlpha(150)
        painter.setPen(QPen(border, 1.4))
        painter.drawPath(path)
    return paint


def port(border=COLORS["border"], dashed=False, new_host=False, italic=False):
    """A switch port's box of hosts (shown with Show Hosts, or by double-clicking a switch)."""
    def paint(painter, rect):
        box = rect.adjusted(4, 4, -4, -4)
        path = rounded(box, 4)
        painter.fillPath(path, QColor(COLORS["panel_alt"]))
        pen = QPen(QColor(border), 1)
        if dashed:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.drawPath(path)
        painter.setFont(font(0.62, bold=True))
        painter.setPen(QColor(COLORS["text"]))
        painter.drawText(box.adjusted(5, 1, -4, -box.height() / 2), Qt.AlignLeft | Qt.AlignVCenter, "Gi1/0/7")
        text = box.adjusted(8 if new_host else 5, box.height() / 2, -4, -1)
        if new_host:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QColor(COLORS["success"]))
            painter.drawEllipse(QPointF(box.left() + 4, text.center().y()), 2.5, 2.5)
            painter.setBrush(Qt.NoBrush)
        painter.setFont(font(0.6, italic=italic))
        painter.setPen(QColor(COLORS["muted"] if italic else COLORS["text"]))
        painter.drawText(text, Qt.AlignLeft | Qt.AlignVCenter, "host")
        painter.setFont(font(0.58, bold=True))
        painter.setPen(QColor(COLORS["link"]))
        painter.drawText(text, Qt.AlignRight | Qt.AlignVCenter, "VLAN 10")
    return paint


def node(shape, color, dashed=False, text=""):
    """Something on the logical view: a subnet (rounded ends), a router traceroute found, or an unanswered hop."""
    def paint(painter, rect):
        if shape == "star":
            box = QRectF(0, 0, 26, 26)
            box.moveCenter(rect.center())
            radius = 13
        elif shape == "subnet":
            box = rect.adjusted(4, 8, -4, -8)
            radius = box.height() / 2
        else:
            box = rect.adjusted(10, 5, -10, -5)
            radius = 5
        path = rounded(box, radius)
        painter.fillPath(path, QColor(COLORS["panel_alt"] if shape == "subnet" else COLORS["panel"]))
        pen = QPen(QColor(color), 2.2 if color in (COLORS["error"], COLORS["warning"]) else 1.4)
        if dashed:
            pen.setStyle(Qt.DashLine)
        painter.setPen(pen)
        painter.drawPath(path)
        painter.setFont(font(0.65, bold=True))
        painter.setPen(QColor(COLORS["text"]))
        painter.drawText(box, Qt.AlignCenter, text)
    return paint


SECTIONS = [
    ("Devices: the color and tag on the left say what kind", [
        (device(SWITCH), "Switch (SW)"),
        (device(ROUTER), "Router (RTR)"),
        (device(FIREWALL), "Firewall (FW)"),
        (device(AP), "Access point (AP)"),
        (device(SERVER), "Server (SRV): only set by hand"),
        (device(UNKNOWN), "Unknown kind (?)"),
    ]),
    ("How a device was found", [
        (device(), "Solid outline: answered SNMP, so its neighbors, MAC and ARP tables were read"),
        (device(dashed=True), "Dashed outline: not read over SNMP. Only seen as a neighbor (out of scope or too "
                              "far), pings but doesn't answer SNMP, or added by hand and not checked yet"),
        (device(dashed=True, unreachable=True), "Red outline and name: answered neither SNMP nor ping"),
        (device(dashed=True, italic=True), "Name in italics: added by hand (kept when you map again)"),
    ]),
    ("Monitoring (Monitor ticked): the outline shows up or down instead of the kind", [
        (device(status=UP), "Green outline and dot: answers ping (its time is beside its address)"),
        (device(status=DOWN), "Red outline, red tint and dot: down (with how long for)"),
        (device(status=NOT_CHECKED), "Gray outline and an empty dot: not pinged yet"),
    ]),
    ("Marks on devices", [
        (device(news=True), "NEW: found by Watch and not looked at yet (or \"2 new hosts\": new hosts on it)"),
        (device(selected=True), "White ring: selected"),
        (device(ring=COLORS["success"]), "Green ring: being read during a crawl, or new since the map you compared "
                                         "with (Compare)"),
        (device(ring=COLORS["warning"]), "Amber ring: changed since the map you compared with (Compare)"),
    ]),
    ("Links", [
        (line(), "Thin line: one link, found by CDP or LLDP (or an address on the same subnet). The ports are "
                 "written at each end when zoomed in"),
        (line(width=3.2, label="×2"), "Thick line with ×2, ×3...: several links between the same two devices, "
                                     "such as a port-channel's members"),
        (line(style=Qt.DashLine), "Dashed line: found only by traceroute"),
        (line(style=Qt.DotLine), "Dotted line: drawn by hand"),
    ]),
    ("A VLAN highlighted (Overlay > Highlight VLAN, a device's right-click menu > VLANs, or the VLANs tab)", [
        (line(VLAN_LINK_COLORS[TAGGED], 3), "Blue: carries it tagged (a trunk)"),
        (line(VLAN_LINK_COLORS[NATIVE], 3, Qt.DashLine), "Blue dashed: carries it as the trunk's native "
                                                         "(untagged) VLAN"),
        (line(VLAN_LINK_COLORS[ACCESS], 3), "Green: carries it between access ports (untagged)"),
        (line(VLAN_LINK_COLORS[ONE_END], 3, Qt.DashLine), "Amber dashed: only one end carries it (a mismatch "
                                                          "worth checking)"),
        (line(faded=True), "Faint: doesn't carry it (devices without it fade too)"),
    ]),
    ("Overlays (the Overlay button, or right-click a device or link > What If It Fails?): one at a time, what "
     "they don't mark fades (except Color By). The bar over the map says what each color means", [
        (device(mark=COLORS["error"]), "Red outline: fails, or would be cut off (What If It Fails?); the only way "
                                       "to switches, routers or firewalls (Single Points of Failure); a problem on "
                                       "one of its ports (Trunk and Port Problems)"),
        (device(mark=COLORS["warning"]), "Amber outline: the only way to other devices (APs, phones...), or a "
                                         "warning on one of its ports"),
        (device(mark=COLORS["success"]), "Green outline: still connected, where \"cut off\" is measured from (the "
                                         "device put at the top, else the one the map started from); in the VRF, "
                                         "or with an address in the subnet; or the root bridge (Spanning Tree)"),
        (line(COLORS["error"], 3, Qt.DashLine), "Red dashed: a link that fails, is down at an end (Link Speed), "
                                                "is blocked by spanning tree, or is seeing errors (Utilization)"),
        (line(COLORS["error"], 3), "Red: a link cut off with what's beyond it, or a trunk/access or native VLAN "
                                   "mismatch"),
        (line(COLORS["warning"], 3, Qt.DashLine), "Amber dashed: VLANs allowed at one end only, in the VRF at one "
                                                  "end only"),
        (line(COLORS["warning"], 3), "Amber: the only link to part of the network"),
        (line("#58a6ff", 3), "Link Speed: color and thickness by speed (orange 100 Mb/s or less, blue 1 Gb/s, "
                             "teal 2.5 to 10 Gb/s, purple 25 to 40, white 100 and up)"),
        (line(COLORS["success"], 3), "Utilization (while monitoring): green under 30% busy, amber to 70% (or "
                                     "discarding), red over 70%"),
        (device(mark="#c792ea"), "Color By: one color per model, software version, site... (gray: not known or "
                                 "one of the rarer ones)"),
    ]),
    ("Carry VLAN (while its window is open): the route planned", [
        (line(*PATH_STYLES[PATH_PLANNED]), "Thick green dashed: a link of the route the VLAN will be added to"),
        (line(*PATH_STYLES[PATH_CARRIES]), "Thick green: a link of the route that carries it (already, or once "
                                           "sent and verified)"),
        (line(*PATH_STYLES[PATH_CHOSEN]), "Thick amber dashed: a redundant link ticked to carry it too"),
        (line(*PATH_STYLES[PATH_OFFERED]), "Amber dotted: a redundant link not ticked (left as it is)"),
        (line(*PATH_STYLES[PATH_BLOCKED]), "Red dashed: a link of the route that can't carry it (an access port in "
                                           "another VLAN)"),
        (device(ring=COLORS["warning"]), "Amber ring: a switch the plan changes"),
        (device(ring=COLORS["success"]), "Green ring: a switch of the route that needs nothing, or verified done"),
    ]),
    ("Sites, buildings and rooms", [
        (group(COLORS["accent"]), "Green box: a site"),
        (group(COLORS["link"]), "Blue box: a building"),
        (group(COLORS["warning"]), "Amber box: a room"),
        (group(COLORS["link"], collapsed=True), "A stack of boxes: a group collapsed into one (double-click it to "
                                                "expand it). \"2 down\" in red while monitoring"),
    ]),
    ("Hosts on switch ports (Show Hosts, or double-click a switch)", [
        (port(), "A port's box: the hosts on it (name and address, or MAC) and their VLAN"),
        (port(COLORS["warning"]), f"Amber box: more than {SHARED_PORT_HOSTS} hosts on one port, probably an "
                                  "unmanaged switch or a hypervisor"),
        (port(dashed=True, italic=True), "Dashed box, gray italics: hosts added by hand, not seen by the crawl"),
        (port(new_host=True), "Green dot: a host found by Watch and not looked at yet"),
    ]),
    ("Logical (L3) view", [
        (device(ROUTER), "Devices: drawn as on the physical view"),
        (node("subnet", COLORS["link"], text="10.1.2.0/24"), "Rounded ends: a subnet (its IPAM name and role "
                                                             "under it)"),
        (node("subnet", COLORS["error"], text="10.1.2.0/24"), "Red subnet: Subnet Placement found a problem"),
        (node("subnet", COLORS["warning"], text="10.1.2.0/24"), "Amber subnet: Subnet Placement has a warning"),
        (node("subnet", COLORS["muted"], text="10.1.2.0/24"), "Gray subnet: not in the map's IPAM network"),
        (node("box", COLORS["muted"], dashed=True, text="10.9.9.1"), "Dashed box: a next hop or router found by "
                                                                     "traceroute only, or this computer"),
        (node("star", COLORS["muted"], dashed=True, text="*"), "*: a traceroute hop that didn't answer"),
    ]),
]


class Swatch(QWidget):
    """One sample, drawn on the map's background."""

    def __init__(self, draw, parent=None):
        super().__init__(parent)
        self.draw = draw
        self.setFixedSize(SWATCH_WIDTH, SWATCH_HEIGHT)

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(COLORS["background"]))
        self.draw(painter, QRectF(self.rect()).adjusted(2, 2, -2, -2))
        painter.end()


class MapKeyDialog(QDialog):
    """The map's key, beside the map (it doesn't block it)."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Network Map Key")
        self.resize(560, 680)
        layout = QVBoxLayout(self)
        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        body = QWidget()
        grid = QGridLayout(body)
        grid.setColumnStretch(1, 1)
        grid.setHorizontalSpacing(12)
        row = 0
        for title, entries in SECTIONS:
            heading = QLabel(title)
            heading.setStyleSheet(f"font-weight: bold; color: {COLORS['accent']};"
                                  f"{' margin-top: 10px;' if row else ''}")
            heading.setWordWrap(True)
            grid.addWidget(heading, row, 0, 1, 2)
            row += 1
            for draw, text in entries:
                grid.addWidget(Swatch(draw, body), row, 0, Qt.AlignTop)
                label = QLabel(text)
                label.setWordWrap(True)
                grid.addWidget(label, row, 1, Qt.AlignVCenter)
                row += 1
        grid.setRowStretch(row, 1)
        scroll.setWidget(body)
        layout.addWidget(scroll, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)

    def entries(self):
        """The texts it explains, for tests: [(section title, [text, ...])]."""
        return [(title, [text for _, text in entries]) for title, entries in SECTIONS]
