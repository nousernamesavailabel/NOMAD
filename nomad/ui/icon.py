"""NOMAD's icon, drawn in code: radar rings with a compass needle, in the theme colors.

Run as a script to write the .ico used for the packaged exe:  python -m nomad.ui.icon build\\nomad.ico
"""
import struct
import sys

from PyQt5.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt
from PyQt5.QtGui import QColor, QIcon, QImage, QPainter, QPainterPath, QPen, QPixmap

from .theme import COLORS

ICON_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def draw_icon(size):
    """Render the icon as a square QImage of the given size."""
    image = QImage(size, size, QImage.Format_ARGB32)
    image.fill(Qt.transparent)
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.scale(size / 64, size / 64)  # Drawn on a 64 x 64 grid
    detailed = size >= 32

    # Rounded tile
    painter.setPen(QPen(QColor(COLORS["border"]), 1.5))
    painter.setBrush(QColor(COLORS["background"]))
    painter.drawRoundedRect(QRectF(1.5, 1.5, 61, 61), 13, 13)

    # Radar rings and crosshair
    center = QPointF(32, 32)
    ring_pen = QPen(QColor(COLORS["accent_dim"]), 2.5 if detailed else 4)
    painter.setPen(ring_pen)
    painter.setBrush(Qt.NoBrush)
    painter.drawEllipse(center, 24, 24)
    if detailed:
        painter.drawEllipse(center, 14, 14)
        ring_pen.setWidthF(1.5)
        painter.setPen(ring_pen)
        painter.drawLine(QPointF(32, 8), QPointF(32, 56))
        painter.drawLine(QPointF(8, 32), QPointF(56, 32))

    # Compass needle pointing north-east: bright half forward, muted half behind
    painter.translate(center)
    painter.rotate(45)
    width = 6 if detailed else 8
    for tip, color in ((-21, COLORS["accent"]), (21, COLORS["muted"])):
        needle = QPainterPath()
        needle.moveTo(0, tip)
        needle.lineTo(width, 0)
        needle.lineTo(-width, 0)
        needle.closeSubpath()
        painter.fillPath(needle, QColor(color))
    painter.resetTransform()
    painter.scale(size / 64, size / 64)

    # Hub and a couple of radar blips
    painter.setPen(Qt.NoPen)
    painter.setBrush(QColor(COLORS["text"]))
    painter.drawEllipse(center, 3 if detailed else 4, 3 if detailed else 4)
    if detailed:
        painter.setBrush(QColor(COLORS["accent"]))
        for x, y in ((18, 22), (44, 45)):
            painter.drawEllipse(QPointF(x, y), 2.5, 2.5)
    painter.end()
    return image


def app_icon():
    icon = QIcon()
    for size in ICON_SIZES:
        icon.addPixmap(QPixmap.fromImage(draw_icon(size)))
    return icon


def _png_bytes(image):
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    return bytes(data)


def write_ico(path):
    """Write a multi-size .ico (PNG-compressed entries, supported since Windows Vista)."""
    images = [_png_bytes(draw_icon(size)) for size in ICON_SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = len(header) + 16 * len(images)
    entries, data = b"", b""
    for size, png in zip(ICON_SIZES, images):
        dimension = 0 if size >= 256 else size  # 0 means 256 in the ICO format
        entries += struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(png), offset + len(data))
        data += png
    with open(path, "wb") as file:
        file.write(header + entries + data)


if __name__ == "__main__":
    from pathlib import Path

    from PyQt5.QtGui import QGuiApplication
    app = QGuiApplication(sys.argv[:1] + ["-platform", "offscreen"])
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "nomad.ico")
    output.parent.mkdir(parents=True, exist_ok=True)
    write_ico(output)
    print(f"Wrote {output}")
