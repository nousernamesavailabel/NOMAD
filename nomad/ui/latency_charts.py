"""Latency tab charts: a semicircle gauge per target and a graph of every target over time."""
import time

from PyQt5.QtCore import QPointF, QRectF, QSize, Qt
from PyQt5.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import QGridLayout, QScrollArea, QSizePolicy, QWidget

from ..latency import latency_level
from .theme import COLORS

# Series colors, one per target in turn; red is left out because it marks lost pings
SERIES_COLORS = ["#35f28b", "#58a6ff", "#f0b429", "#c678dd", "#56d4dd", "#ff9e64", "#e6edf3", "#a3be8c",
                 "#f78fb3", "#8b98a5"]
LOSS_LANE_HEIGHT = 5
LEVEL_COLORS = {"good": COLORS["success"], "fair": COLORS["warning"], "poor": COLORS["error"], None: COLORS["muted"]}


def format_ms(ms):
    """Whole milliseconds, with "<1" for replies Windows reports as 0 ms (like ping.exe's "time<1ms")."""
    return "<1" if ms < 1 else f"{ms:.0f}"


def series_color(index):
    return QColor(SERIES_COLORS[index % len(SERIES_COLORS)])


class LatencyGauge(QWidget):
    """Semicircle meter showing a target's average latency against the shared scale."""

    def __init__(self, name, color, parent=None):
        super().__init__(parent)
        self.name, self.color = name, color
        self.stats, self.error = None, ""
        self.scale = (0.0, 200.0)
        self.setMinimumSize(170, 150)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def sizeHint(self):
        return QSize(200, 160)

    def update_value(self, stats, error, scale):
        self.stats, self.error, self.scale = stats, error, scale
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(self.rect()).adjusted(1, 1, -1, -1)
        painter.setPen(QPen(QColor(COLORS["border"]), 1))
        painter.setBrush(QColor(COLORS["panel"]))
        painter.drawRoundedRect(rect, 6, 6)

        # Header: color swatch and name
        painter.fillRect(QRectF(rect.left() + 10, rect.top() + 11, 10, 10), self.color)
        painter.setPen(QColor(COLORS["text"]))
        bold = QFont(self.font())
        bold.setBold(True)
        painter.setFont(bold)
        painter.drawText(QRectF(rect.left() + 26, rect.top() + 5, rect.width() - 32, 22), Qt.AlignVCenter,
                         painter.fontMetrics().elidedText(self.name, Qt.ElideRight, int(rect.width() - 32)))

        stats = self.stats
        lost = stats is not None and stats.last_lost
        average = stats.average if stats else None
        low, high = self.scale
        fraction = 1.0 if lost else 0.0 if average is None else max(0.0, min(1.0, (average - low) / (high - low)))
        color = QColor(COLORS["error"] if lost else LEVEL_COLORS[latency_level(average)])

        # Arc: a 180 degree track with the value drawn over it
        caption_height = 22
        available = QRectF(rect.left() + 12, rect.top() + 32, rect.width() - 24, rect.height() - 32 - caption_height)
        radius = max(10.0, min(available.width() / 2, available.height() - 4))
        center = QPointF(available.center().x(), available.top() + radius + 2)
        arc_rect = QRectF(center.x() - radius, center.y() - radius, 2 * radius, 2 * radius)
        thickness = max(6.0, radius * 0.16)
        arc_rect.adjust(thickness / 2, thickness / 2, -thickness / 2, -thickness / 2)
        painter.setPen(QPen(QColor(COLORS["input"]), thickness, Qt.SolidLine, Qt.FlatCap))
        painter.drawArc(arc_rect, 180 * 16, -180 * 16)
        if fraction > 0:
            painter.setPen(QPen(color, thickness, Qt.SolidLine, Qt.FlatCap))
            painter.drawArc(arc_rect, 180 * 16, int(-180 * 16 * fraction))

        # Value in the middle of the arc
        value_font = QFont(self.font())
        value_font.setBold(True)
        value_font.setPixelSize(max(12, int(radius * 0.38)))
        painter.setFont(value_font)
        painter.setPen(color if (lost or average is not None) else QColor(COLORS["muted"]))
        text = "LOST" if lost else "—" if average is None else format_ms(average)
        value_rect = QRectF(center.x() - radius, center.y() - radius * 0.62, 2 * radius, radius * 0.5)
        painter.drawText(value_rect, Qt.AlignCenter, text)
        if not lost and average is not None:
            small = QFont(self.font())
            small.setPixelSize(max(9, int(radius * 0.16)))
            painter.setFont(small)
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(QRectF(center.x() - radius, center.y() - radius * 0.14, 2 * radius, radius * 0.2),
                             Qt.AlignCenter, "ms avg")

        # Caption: last reply and loss, or why it's failing
        painter.setFont(self.font())
        if stats is None or stats.sent == 0:
            caption = "No data yet"
        elif lost:
            caption = f"{self.error or 'No reply'} · {stats.loss_percent:.0f}% loss"
        else:
            last = f"{format_ms(stats.last)} ms" if stats.last is not None else "—"
            caption = f"last {last} · {stats.loss_percent:.0f}% loss"
        painter.setPen(QColor(COLORS["error"] if lost else COLORS["muted"]))
        caption_rect = QRectF(rect.left() + 6, rect.bottom() - caption_height - 2, rect.width() - 12, caption_height)
        painter.drawText(caption_rect, Qt.AlignCenter,
                         painter.fontMetrics().elidedText(caption, Qt.ElideRight, int(caption_rect.width())))


class GaugePanel(QScrollArea):
    """Scrollable gauges, laid out in as many columns as fit the visible width."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.gauges = []
        self.columns = 0
        contents = QWidget()
        self.grid = QGridLayout(contents)
        self.grid.setContentsMargins(0, 0, 4, 0)
        self.setWidget(contents)
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setMinimumWidth(190)

    def set_widgets(self, widgets):
        for gauge in self.gauges:
            self.grid.removeWidget(gauge)
            gauge.deleteLater()
        self.gauges, self.columns = list(widgets), 0
        self.relayout()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.relayout()

    def relayout(self):
        width = self.viewport().width() - self.grid.contentsMargins().right()
        spacing = self.grid.horizontalSpacing()
        minimum = max((gauge.minimumWidth() for gauge in self.gauges), default=1)
        columns = max(1, min(len(self.gauges), (width + spacing) // (minimum + spacing)))
        if columns == self.columns:
            return
        self.columns = columns
        for gauge in self.gauges:
            self.grid.removeWidget(gauge)
        for index, gauge in enumerate(self.gauges):
            self.grid.addWidget(gauge, index // columns, index % columns)
        for row in range(self.grid.rowCount()):
            self.grid.setRowStretch(row, 0)
        self.grid.setRowStretch(self.grid.rowCount(), 1)


class LatencyGraph(QWidget):
    """Latency over time for several targets, with lost pings shown as red bands."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.series = []  # [(name, QColor, [(time, rtt or None), ...])]
        self.scale = (0.0, 200.0)
        self.window_seconds = 600
        self.setMinimumSize(320, 200)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def set_series(self, series, scale, window_seconds):
        self.series, self.scale, self.window_seconds = series, scale, window_seconds
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(COLORS["input"]))
        metrics = painter.fontMetrics()
        left, right, top, bottom = metrics.horizontalAdvance("0000") + 12, 12, 10, metrics.height() + 10
        plot = QRectF(left, top, max(1, self.width() - left - right), max(1, self.height() - top - bottom))
        low, high = self.scale
        span = max(1e-9, high - low)

        # Grid and y-axis labels
        grid_pen = QPen(QColor(COLORS["border"]), 1)
        for step in range(5):
            y = plot.top() + plot.height() * step / 4
            painter.setPen(grid_pen)
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(QRectF(0, y - 10, left - 6, 20), Qt.AlignRight | Qt.AlignVCenter,
                             f"{high - span * step / 4:.0f}")

        drawable = [series for series in self.series if series[2]]
        if not drawable:
            painter.setPen(QColor(COLORS["muted"]))
            painter.drawText(plot, Qt.AlignCenter, "No data yet. Click Start to begin monitoring.")
            return

        now = time.time()
        start = max(now - self.window_seconds, min(samples[0][0] for _, _, samples in drawable))
        duration = max(1e-9, now - start)

        def x_of(timestamp):
            return plot.left() + (timestamp - start) / duration * plot.width()

        def y_of(rtt):
            return plot.bottom() - max(0.0, min(1.0, (rtt - low) / span)) * plot.height()

        painter.setClipRect(plot.adjusted(-4, -4, 4, 4))
        # Lost pings: a thin lane per target along the top, red wherever its pings were lost
        lanes_bottom = plot.top()
        for _, color, samples in drawable:
            if all(rtt is not None for _, rtt in samples):
                continue
            lane = QRectF(plot.left(), lanes_bottom + 2, plot.width(), LOSS_LANE_HEIGHT)
            painter.fillRect(QRectF(lane.left(), lane.top(), 4, lane.height()), color)
            for index, (timestamp, rtt) in enumerate(samples):
                if rtt is None:  # Lost until the next ping (or now, for the latest)
                    until = samples[index + 1][0] if index + 1 < len(samples) else now
                    band_left = max(x_of(timestamp), lane.left() + 5)
                    painter.fillRect(QRectF(band_left, lane.top(), max(2.0, x_of(until) - band_left),
                                            lane.height()), QColor(COLORS["error"]))
            lanes_bottom = lane.bottom()

        for _, color, samples in drawable:
            # The latency line, broken wherever a ping was lost
            painter.setPen(QPen(color, 2))
            painter.setBrush(color)
            path, points = QPainterPath(), 0
            for timestamp, rtt in samples:
                if rtt is None:
                    if points == 1:
                        painter.drawEllipse(path.currentPosition(), 2, 2)
                    points = 0
                    continue
                point = QPointF(x_of(timestamp), y_of(rtt))
                if points:
                    path.lineTo(point)
                else:
                    path.moveTo(point)
                points += 1
            if points == 1:
                painter.drawEllipse(path.currentPosition(), 2, 2)
            painter.setBrush(Qt.NoBrush)
            painter.drawPath(path)
            last_reply = next(((t, rtt) for t, rtt in reversed(samples) if rtt is not None), None)
            if last_reply:
                painter.setBrush(color)
                painter.drawEllipse(QPointF(x_of(last_reply[0]), y_of(last_reply[1])), 3, 3)
                painter.setBrush(Qt.NoBrush)
        painter.setClipping(False)

        # Time labels
        painter.setPen(QColor(COLORS["muted"]))
        label_rect = QRectF(plot.left(), plot.bottom() + 4, plot.width(), metrics.height())
        painter.drawText(label_rect, Qt.AlignLeft, time.strftime("%H:%M:%S", time.localtime(start)))
        painter.drawText(label_rect, Qt.AlignRight, time.strftime("%H:%M:%S", time.localtime(now)))

        # Legend, top right below the loss lanes; a target that is currently losing pings is flagged in red
        y = lanes_bottom + 6
        for name, color, samples in drawable:
            losing = samples[-1][1] is None
            label = f"{name}  LOST" if losing else name
            width = metrics.horizontalAdvance(label)
            box = QRectF(plot.right() - width - 30, y - 2, width + 26, metrics.height() + 4)
            background = QColor(COLORS["panel"])
            background.setAlpha(220)
            painter.fillRect(box, background)
            painter.fillRect(QRectF(box.left() + 5, y + metrics.height() / 2 - 4, 9, 9), color)
            painter.setPen(QColor(COLORS["error"] if losing else COLORS["text"]))
            painter.drawText(QRectF(box.left() + 19, y, width + 4, metrics.height()), Qt.AlignVCenter, label)
            y += metrics.height() + 6
