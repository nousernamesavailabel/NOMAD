"""The splash shown while NOMAD starts, so a slow start doesn't look like nothing happened.

The packaged exe shows build\\splash.png (drawn here, with "Starting...") from the moment it's opened, while it
unpacks; NOMAD then puts the same picture up itself and closes that one, and says what it's loading as it goes.

Run as a script to write the picture for the build:  python -m nomad.ui.splash build\\splash.png
"""
import sys

from PyQt5.QtCore import QRect, QRectF, Qt
from PyQt5.QtGui import QColor, QFont, QImage, QPainter, QPen, QPixmap
from PyQt5.QtWidgets import QSplashScreen

from .. import __version__
from ..system import APP_FULL_NAME, APP_NAME
from .icon import draw_icon
from .theme import COLORS

SPLASH_WIDTH, SPLASH_HEIGHT = 480, 240
STARTING = "Starting..."
STATUS_TOP = 176  # Where the status line and progress bar go: the part redrawn as NOMAD starts


def _font(pixels, bold=False):
    font = QFont("Segoe UI")
    font.setPixelSize(pixels)
    font.setBold(bold)
    return font


def draw_splash():
    """The splash without its status line: the icon, name and version on the theme's background."""
    image = QImage(SPLASH_WIDTH, SPLASH_HEIGHT, QImage.Format_RGB32)
    image.fill(QColor(COLORS["background"]))
    painter = QPainter(image)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setRenderHint(QPainter.TextAntialiasing)
    painter.setPen(QPen(QColor(COLORS["border"]), 1))
    painter.drawRect(QRectF(0.5, 0.5, SPLASH_WIDTH - 1, SPLASH_HEIGHT - 1))
    painter.drawImage(32, 40, draw_icon(96))
    painter.setPen(QColor(COLORS["text"]))
    painter.setFont(_font(40, bold=True))
    painter.drawText(QRect(152, 44, SPLASH_WIDTH - 172, 50), Qt.AlignLeft | Qt.AlignVCenter, APP_NAME)
    painter.setPen(QColor(COLORS["muted"]))
    painter.setFont(_font(13))
    painter.drawText(QRect(152, 94, SPLASH_WIDTH - 172, 40), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap,
                     APP_FULL_NAME)
    painter.setPen(QColor(COLORS["accent"]))
    painter.drawText(QRect(152, 118, SPLASH_WIDTH - 172, 20), Qt.AlignLeft | Qt.AlignTop, f"Version {__version__}")
    painter.end()
    return image


def draw_status(painter, message, progress):
    """The status line and a thin progress bar (progress from 0 to 1) along the bottom of the splash."""
    painter.setRenderHint(QPainter.TextAntialiasing)
    painter.setPen(QColor(COLORS["text"]))
    painter.setFont(_font(13))
    painter.drawText(QRect(32, STATUS_TOP, SPLASH_WIDTH - 64, 22), Qt.AlignLeft | Qt.AlignVCenter, message)
    track = QRect(32, STATUS_TOP + 30, SPLASH_WIDTH - 64, 4)
    painter.fillRect(track, QColor(COLORS["panel_alt"]))
    done = int(track.width() * max(0.0, min(1.0, progress)))
    if done:
        painter.fillRect(QRect(track.left(), track.top(), done, track.height()), QColor(COLORS["accent"]))


def draw_build_splash():
    """The picture the packaged exe shows while it unpacks: the splash saying it's starting."""
    image = draw_splash()
    painter = QPainter(image)
    draw_status(painter, STARTING, 0)
    painter.end()
    return image


class StartupSplash(QSplashScreen):
    """The splash, saying what NOMAD is doing. step() repaints it there and then: nothing else runs while the main
    window is built, and letting events run then could start pages before the window they belong to exists."""

    def __init__(self):
        super().__init__(QPixmap.fromImage(draw_splash()), Qt.WindowStaysOnTopHint)
        self.message = STARTING
        self.progress = 0.0

    def step(self, message, progress=None):
        self.message = message
        if progress is not None:
            self.progress = progress
        self.repaint()

    def drawContents(self, painter):
        draw_status(painter, self.message, self.progress)


def close_bootloader_splash():
    """Close the packaged exe's own splash, once this one is up (there's none when run from source)."""
    try:
        import pyi_splash
    except ImportError:
        return
    try:
        pyi_splash.close()
    except RuntimeError:  # Already closed
        pass


if __name__ == "__main__":
    from pathlib import Path

    from PyQt5.QtGui import QGuiApplication
    app = QGuiApplication(sys.argv[:1])  # Not offscreen, as for the icon: that has no fonts on Windows
    output = Path(sys.argv[1] if len(sys.argv) > 1 else "splash.png")
    output.parent.mkdir(parents=True, exist_ok=True)
    if not draw_build_splash().save(str(output), "PNG"):
        sys.exit(f"Couldn't write {output}")
    print(f"Wrote {output}")
