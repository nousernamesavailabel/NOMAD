"""A port's traffic in and out over time, drawn from what traffic_history keeps: the Map Watcher's readings in solid
lines (the same as the NOMAD Dashboard's graph), this computer's own in dashed lines where the Watcher has none (kept
while the Network Map's Monitor is on, and read live while the graph shows), and each hour's peak in dotted over a
long span. Hovering shows the readings nearest the pointer."""
import time

from PyQt5.QtCore import QPointF, QRectF, Qt
from PyQt5.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QSizePolicy, QToolTip, QWidget

from ..netmap import traffic_history
from .theme import COLORS

IN_COLOR, OUT_COLOR = "#3b82f6", "#f59e0b"


def format_rate(bits_per_second):
    """Bits per second for display, such as "12.3 Mb/s"."""
    value = float(bits_per_second or 0)
    for unit in ("b/s", "kb/s", "Mb/s", "Gb/s"):
        if value < 1000 or unit == "Gb/s":
            return f"{value:.0f} {unit}" if unit == "b/s" else f"{value:.1f} {unit}"
        value /= 1000
    return ""


def nice_ceiling(value):
    """The axis top for value: 1, 2 or 5 times a power of ten."""
    if value <= 0:
        return 1.0
    power = 1.0
    while power * 10 <= value:
        power *= 10
    while power > value:
        power /= 10
    for step in (1, 2, 5, 10):
        if power * step >= value:
            return power * step
    return power * 10


def runs(points, gap):
    """points split where two are further apart than gap seconds (a pause in the readings, drawn as a gap)."""
    found, current = [], []
    for point in points:
        if current and point[0] - current[-1][0] > gap:
            found.append(current)
            current = []
        current.append(point)
    if current:
        found.append(current)
    return found


class TrafficGraph(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.watcher = []  # [[time, in, out, peak in, peak out]] from the Map Watcher
        self.own = []  # [[time, in, out, ...]] this computer's, where the Watcher has none (and live readings)
        self.hourly = False
        self.start, self.end = time.time() - 86400, time.time()
        self.note = ""
        self.setMinimumHeight(200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMouseTracking(True)
        self.plot = QRectF()

    def set_data(self, watcher, own, live, start, end, hourly=False, note=""):
        """watcher, own: [[time, in b/s, out b/s, peak in, peak out]]; live: [(time, in b/s, out b/s)] read just
        now. This computer's readings only show where the Watcher has none."""
        self.watcher = sorted(watcher)
        mine = traffic_history.outside(sorted(own), self.watcher, hourly)
        last = max([point[0] for point in self.watcher + mine], default=0)
        mine += [[when, rate_in, rate_out, rate_in, rate_out] for when, rate_in, rate_out in live if when > last]
        self.own = sorted(mine)
        self.hourly, self.start, self.end, self.note = hourly, start, end, note
        self.update()

    def visible(self, points):
        return [point for point in points if self.start - 3600 <= point[0] <= self.end]

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(COLORS["input"]))
        metrics = painter.fontMetrics()
        left = metrics.horizontalAdvance("000.0 Mb/s") + 10
        plot = QRectF(left, 8, max(1, self.width() - left - 12), max(1, self.height() - 2 * metrics.height() - 26))
        self.plot = plot
        watcher, own = self.visible(self.watcher), self.visible(self.own)
        peak_column = 3 if self.hourly else 1
        peak = max([max(point[peak_column], point[2]) for point in watcher]
                   + [max(point[1], point[2]) for point in own] + [0])
        top = nice_ceiling(peak * 1.1)
        grid = QPen(QColor(COLORS["border"]), 1)
        for step in range(5):
            y = plot.top() + plot.height() * step / 4
            painter.setPen(grid)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(QRectF(0, y - 10, left - 6, 20), Qt.AlignRight | Qt.AlignVCenter,
                             format_rate(top * (4 - step) / 4))
        span = max(1.0, self.end - self.start)

        def x_of(when):
            return plot.left() + (when - self.start) / span * plot.width()

        def y_of(rate):
            return plot.bottom() - max(0.0, min(1.0, rate / top)) * plot.height()

        if not watcher and not own:
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(plot.adjusted(20, 0, -20, 0), Qt.AlignCenter | Qt.TextWordWrap,
                             self.note or "No readings of this port in this time.")
        painter.setClipRect(plot)

        def draw(points, column, color, style, width):
            pen = QPen(QColor(color), width)
            pen.setStyle(style)
            painter.setPen(pen)
            for run in runs(points, traffic_history.gap_seconds(points, self.hourly)):
                if len(run) == 1:
                    painter.drawEllipse(QPointF(x_of(run[0][0]), y_of(run[0][column])), 1.5, 1.5)
                    continue
                path = QPainterPath(QPointF(x_of(run[0][0]), y_of(run[0][column])))
                for point in run[1:]:
                    path.lineTo(QPointF(x_of(point[0]), y_of(point[column])))
                painter.drawPath(path)

        if self.hourly:
            draw(watcher, 3, IN_COLOR, Qt.DotLine, 1)
        for column, color in ((1, IN_COLOR), (2, OUT_COLOR)):
            draw(own, column, color, Qt.DashLine, 1.5)
            draw(watcher, column, color, Qt.SolidLine, 2)
        painter.setClipping(False)
        painter.setPen(QColor(COLORS["muted"]))
        labels = QRectF(plot.left(), plot.bottom() + 4, plot.width(), metrics.height())
        stamp = "%H:%M" if span <= 86400 else "%d %b %H:%M" if span <= 8 * 86400 else "%d %b"
        painter.drawText(labels, Qt.AlignLeft, time.strftime(stamp, time.localtime(self.start)))
        painter.drawText(labels, Qt.AlignHCenter, time.strftime(stamp, time.localtime(self.start + span / 2)))
        painter.drawText(labels, Qt.AlignRight, time.strftime(stamp, time.localtime(self.end)))
        legend = QRectF(plot.left(), labels.bottom() + 4, plot.width(), metrics.height())
        text = "■ In   ■ Out    solid: the Map Watcher    dashed: this computer"
        if self.hourly:
            text += "    dotted: peak in (hourly)"
        painter.drawText(legend, Qt.AlignHCenter, text)
        width = metrics.horizontalAdvance(text)
        x = legend.left() + (legend.width() - width) / 2
        box = metrics.horizontalAdvance("■")
        painter.fillRect(QRectF(x, legend.top() + 3, box, metrics.height() - 6), QColor(IN_COLOR))
        x2 = x + metrics.horizontalAdvance("■ In   ")
        painter.fillRect(QRectF(x2, legend.top() + 3, box, metrics.height() - 6), QColor(OUT_COLOR))

    def nearest(self, x):
        """The reading nearest x on the graph: (point, "the Map Watcher" or "this computer"), or None."""
        if self.plot.width() <= 0:
            return None
        when = self.start + (x - self.plot.left()) / self.plot.width() * (self.end - self.start)
        found = [(abs(point[0] - when), point, "the Map Watcher") for point in self.visible(self.watcher)]
        found += [(abs(point[0] - when), point, "this computer") for point in self.visible(self.own)]
        if not found:
            return None
        _, point, source = min(found, key=lambda item: item[0])
        reach = (self.end - self.start) / 40 + (3600 if self.hourly else 0)
        return (point, source) if abs(point[0] - when) <= reach else None

    def tooltip_text(self, point, source):
        stamp = time.strftime("%d %b %H:%M" if not self.hourly else "%d %b %H:00", time.localtime(point[0]))
        text = f"{stamp} ({source})\nIn {format_rate(point[1])}, out {format_rate(point[2])}"
        if self.hourly and source == "the Map Watcher":
            text = f"{stamp}, the hour's average ({source})\nIn {format_rate(point[1])}, out {format_rate(point[2])}" \
                   f"\nPeak in {format_rate(point[3])}, out {format_rate(point[4])}"
        return text

    def mouseMoveEvent(self, event):
        found = self.nearest(event.pos().x()) if self.plot.contains(QPointF(event.pos())) else None
        if found is None:
            QToolTip.hideText()
        else:
            QToolTip.showText(event.globalPos(), self.tooltip_text(*found), self)
        super().mouseMoveEvent(event)
