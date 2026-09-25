"""NOMAD's dark color scheme (from the RADAR sweep tool): slate panels with a green accent."""
import ctypes
import sys

from PyQt5.QtCore import QEvent, QObject, Qt
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QPalette
from PyQt5.QtWidgets import QPushButton, QTableView

COLORS = {
    "background": "#11161c",
    "panel": "#1a2129",
    "panel_alt": "#202932",
    "input": "#0d1217",
    "hover": "#2b3641",
    "border": "#303a44",
    "text": "#e6edf3",
    "muted": "#8b98a5",
    "disabled": "#5e6872",
    "accent": "#35f28b",
    "accent_hover": "#6cffad",
    "accent_dim": "#237a50",
    "on_accent": "#08120d",
    "success": "#35f28b",
    "warning": "#f0b429",
    "error": "#ff6b6b",
    "link": "#58a6ff",
    "warning_background": "#3a3020",
    "success_background": "#17372a",
}

STYLESHEET = """
QMainWindow, QDialog {{ background: {background}; }}
QToolTip {{ background: {panel_alt}; color: {text}; border: 1px solid {border}; padding: 4px; }}

QTabWidget::pane {{ background: {panel}; border: 1px solid {border}; top: -1px; }}
QTabBar::tab {{ background: {background}; color: {muted}; border: 1px solid {border}; border-bottom: none;
               padding: 7px 14px; margin-right: 2px; }}
QTabBar::tab:selected {{ background: {panel}; color: {accent}; border-top: 2px solid {accent}; }}
QTabBar::tab:hover:!selected {{ color: {text}; }}

QGroupBox {{ border: 1px solid {border}; margin-top: 12px; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; color: {accent}; font-weight: bold; }}

QPushButton {{ background: {panel_alt}; color: {text}; border: 1px solid {border}; padding: 5px 12px; }}
QPushButton:hover {{ background: {hover}; }}
QPushButton:pressed {{ background: {input}; }}
QPushButton:disabled {{ background: {panel}; color: {disabled}; }}
QPushButton:flat {{ background: transparent; border: none; color: {muted}; }}
QPushButton:flat:hover {{ color: {accent}; }}
QPushButton[accent="true"] {{ background: {accent}; color: {on_accent}; border: none; font-weight: bold; }}
QPushButton[accent="true"]:hover {{ background: {accent_hover}; }}
QPushButton[accent="true"]:disabled {{ background: {accent_dim}; color: {panel}; }}

QLineEdit, QSpinBox, QComboBox, QPlainTextEdit, QTextEdit {{
    background: {input}; color: {text}; border: 1px solid {border}; padding: 2px;
    selection-background-color: {accent_dim}; }}
QLineEdit:focus, QSpinBox:focus, QComboBox:focus, QPlainTextEdit:focus {{ border: 1px solid {accent_dim}; }}
QLineEdit:disabled, QSpinBox:disabled, QComboBox:disabled {{ color: {disabled}; }}
QComboBox QAbstractItemView {{ background: {panel_alt}; color: {text}; selection-background-color: {accent_dim}; }}

QTableWidget, QTableView, QListWidget {{ background: {input}; alternate-background-color: {panel};
    color: {text}; gridline-color: {border}; border: 1px solid {border};
    selection-background-color: {accent_dim}; selection-color: {text}; }}
QHeaderView::section {{ background: {panel_alt}; color: {muted}; border: none;
    border-right: 1px solid {border}; border-bottom: 1px solid {border}; padding: 5px; font-weight: bold; }}

QProgressBar {{ background: {input}; border: 1px solid {border}; color: {text}; text-align: center; }}
QProgressBar::chunk {{ background: {accent}; }}

QMenuBar {{ background: {background}; color: {text}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background: {hover}; }}
QMenu {{ background: {panel_alt}; color: {text}; border: 1px solid {border}; }}
QMenu::separator {{ height: 1px; background: {border}; margin: 4px 8px; }}
QStatusBar {{ background: {background}; color: {muted}; }}
"""


def apply_theme(app):
    """Style the whole application with the dark scheme."""
    app.setStyle("Fusion")
    palette = QPalette()
    roles = {
        QPalette.Window: "background", QPalette.WindowText: "text", QPalette.Base: "input",
        QPalette.AlternateBase: "panel", QPalette.ToolTipBase: "panel_alt", QPalette.ToolTipText: "text",
        QPalette.Text: "text", QPalette.Button: "panel_alt", QPalette.ButtonText: "text",
        QPalette.BrightText: "error", QPalette.Highlight: "accent_dim", QPalette.HighlightedText: "text",
        QPalette.Link: "link", QPalette.PlaceholderText: "disabled",
    }
    for role, name in roles.items():
        palette.setColor(role, QColor(COLORS[name]))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        palette.setColor(QPalette.Disabled, role, QColor(COLORS["disabled"]))
    app.setPalette(palette)
    app.setStyleSheet(STYLESHEET.format(**COLORS))
    app.setProperty("base_point_size", app.font().pointSizeF())  # Windows' text size, for set_text_scale
    if sys.platform == "win32":
        app.title_bar_styler = TitleBarStyler(app)  # Kept on app so it lives as long as the app does
        app.installEventFilter(app.title_bar_styler)


# DwmSetWindowAttribute attributes
DWMWA_USE_IMMERSIVE_DARK_MODE = 20
DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19
DWMWA_BORDER_COLOR = 34  # Windows 11 only, like the two below
DWMWA_CAPTION_COLOR = 35
DWMWA_TEXT_COLOR = 36


def _colorref(name):
    color = QColor(COLORS[name])
    return color.red() | color.green() << 8 | color.blue() << 16


def style_title_bar(window):
    """Give a window a dark title bar: exactly the app's colors on Windows 11, standard dark on Windows 10."""
    hwnd = int(window.winId())
    set_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute

    def set_value(attribute, value):
        value = ctypes.c_uint32(value)
        return set_attribute(hwnd, attribute, ctypes.byref(value), ctypes.sizeof(value)) == 0  # S_OK

    if not set_value(DWMWA_USE_IMMERSIVE_DARK_MODE, 1):
        set_value(DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, 1)
    # Custom colors fail harmlessly before Windows 11, leaving the dark mode colors
    set_value(DWMWA_CAPTION_COLOR, _colorref("background"))
    set_value(DWMWA_TEXT_COLOR, _colorref("text"))
    set_value(DWMWA_BORDER_COLOR, _colorref("border"))


class TitleBarStyler(QObject):
    """Styles the title bar of each window and dialog as it is first shown."""

    def eventFilter(self, watched, event):
        if (event.type() == QEvent.Show and watched.isWidgetType() and watched.isWindow()
                and watched.windowType() in (Qt.Window, Qt.Dialog) and not watched.property("dark_title_bar")):
            watched.setProperty("dark_title_bar", True)
            try:
                style_title_bar(watched)
            except (AttributeError, OSError):  # No DWM (e.g. very old Windows); keep the default title bar
                pass
        return False


# Text Size menu choices: (scale, label)
TEXT_SCALES = [(0.9, "90%"), (1.0, "100% (default)"), (1.1, "110%"), (1.25, "125%"), (1.5, "150%"),
               (1.75, "175%"), (2.0, "200%")]
DEFAULT_TEXT_SCALE = 1.0
TABLE_ROW_PADDING = 8


def set_text_scale(app, scale):
    """Make all text scale times Windows' normal size, updating windows that are already open."""
    base = app.property("base_point_size") or app.font().pointSizeF()
    font = QFont(app.font())
    font.setPointSizeF(base * scale)
    app.setFont(font)
    # Widgets styled by the stylesheet keep their old font until it's applied again
    app.setStyleSheet(app.styleSheet())
    row_height = QFontMetrics(font).height() + TABLE_ROW_PADDING
    for widget in app.allWidgets():
        if isinstance(widget, QTableView):
            widget.verticalHeader().setDefaultSectionSize(row_height)


def monospace_font(bold=False):
    """Consolas at the app's current text size: only the family is set, so it follows set_text_scale."""
    font = QFont()
    font.setFamily("Consolas")
    font.setStyleHint(QFont.Monospace)
    if bold:
        font.setBold(True)
    return font


def accent_button(text):
    """A push button in the accent color, for the main action on a tab."""
    button = QPushButton(text)
    button.setProperty("accent", True)
    return button
