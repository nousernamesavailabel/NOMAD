"""Dialogs: keep/revert countdown, log viewer, save profile, and about."""
import os
import platform
import sys

from PyQt5.QtCore import PYQT_VERSION_STR, QT_VERSION_STR, Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import QApplication, QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QHBoxLayout, QLabel, \
    QLineEdit, QPlainTextEdit, QPushButton, QVBoxLayout

from .. import __version__
from ..logs import log_file_path
from ..system import APP_FULL_NAME, APP_NAME
from .icon import app_icon
from .theme import COLORS, monospace_font


class KeepChangesDialog(QDialog):
    """Asks whether to keep new network settings, reverting automatically if nobody answers.

    If the change cut off the connection (for example over Remote Desktop), the countdown runs out
    and the previous settings come back on their own.
    """

    def __init__(self, parent, summary, seconds=15):
        super().__init__(parent)
        self.setWindowTitle("Keep These Settings?")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.remaining = seconds

        layout = QVBoxLayout(self)
        heading = QLabel("The new settings have been applied. Do you want to keep them?")
        font = QFont(heading.font())
        font.setBold(True)
        heading.setFont(font)
        layout.addWidget(heading)
        summary_label = QLabel(summary)
        summary_label.setWordWrap(True)
        layout.addWidget(summary_label)
        self.countdown_label = QLabel()
        layout.addWidget(self.countdown_label)

        buttons = QDialogButtonBox()
        self.keep_button = buttons.addButton("Keep Changes", QDialogButtonBox.AcceptRole)
        self.revert_button = buttons.addButton("Revert", QDialogButtonBox.RejectRole)
        self.revert_button.setDefault(True)  # Pressing Enter by accident is the safe choice
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.tick)
        self.timer.start(1000)
        self.update_countdown()

    def tick(self):
        self.remaining -= 1
        if self.remaining <= 0:
            self.timer.stop()
            self.reject()
        else:
            self.update_countdown()

    def update_countdown(self):
        self.countdown_label.setText(f"Reverting to the previous settings in {self.remaining} seconds...")


class LogDialog(QDialog):
    """Shows the app's log as it is written."""

    line_logged = pyqtSignal(str)

    def __init__(self, parent, memory_handler):
        super().__init__(parent)
        self.setWindowTitle("NOMAD Log")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.resize(900, 500)
        self.memory_handler = memory_handler

        layout = QVBoxLayout(self)
        self.text = QPlainTextEdit(self)
        self.text.setReadOnly(True)
        self.text.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.text.setFont(monospace_font())
        self.text.setPlainText("\n".join(memory_handler.lines))
        self.text.moveCursor(self.text.textCursor().End)
        layout.addWidget(self.text)

        button_layout = QHBoxLayout()
        copy_button = QPushButton("Copy All")
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(self.text.toPlainText()))
        open_button = QPushButton("Open Log Folder")
        open_button.clicked.connect(lambda: os.startfile(log_file_path().parent))
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        button_layout.addWidget(copy_button)
        button_layout.addWidget(open_button)
        button_layout.addStretch()
        button_layout.addWidget(close_button)
        layout.addLayout(button_layout)

        # Log records can arrive from any thread; the signal delivers them on the UI thread
        self.line_logged.connect(self.text.appendPlainText)
        memory_handler.add_listener(self.line_logged.emit)

    def done(self, result):
        self.memory_handler.remove_listener(self.line_logged.emit)
        super().done(result)

    def closeEvent(self, event):
        self.memory_handler.remove_listener(self.line_logged.emit)
        super().closeEvent(event)


class SaveProfileDialog(QDialog):
    """Asks for a profile name and whether to include the MTU."""

    def __init__(self, parent, existing_names, default_name="", mtu=None):
        super().__init__(parent)
        self.setWindowTitle("Save Profile")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)
        self.existing_names = set(existing_names)

        layout = QFormLayout(self)
        self.name_input = QLineEdit(default_name)
        self.name_input.setPlaceholderText("e.g. Lab network")
        layout.addRow("Profile name:", self.name_input)
        self.include_mtu_check = QCheckBox(f"Include MTU ({mtu})" if mtu else "Include MTU")
        self.include_mtu_check.setEnabled(mtu is not None)
        layout.addRow("", self.include_mtu_check)
        self.warning_label = QLabel()
        self.warning_label.setStyleSheet(f"color: {COLORS['warning']};")
        layout.addRow(self.warning_label)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        layout.addRow(self.buttons)

        self.name_input.textChanged.connect(self.on_name_changed)
        self.on_name_changed(default_name)

    def on_name_changed(self, text):
        name = text.strip()
        self.buttons.button(QDialogButtonBox.Save).setEnabled(bool(name))
        self.warning_label.setText(f"This will replace the existing profile '{name}'."
                                   if name in self.existing_names else "")

    @property
    def name(self):
        return self.name_input.text().strip()

    @property
    def include_mtu(self):
        return self.include_mtu_check.isChecked()


class AboutDialog(QDialog):
    """Help > About: the app's name, version and what it does, with version details that can be copied."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle(f"About {APP_NAME}")
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(app_icon().pixmap(64, 64))
        icon_label.setAlignment(Qt.AlignTop)
        header.addWidget(icon_label)
        header.addSpacing(12)
        titles = QVBoxLayout()
        name_label = QLabel(APP_NAME)
        font = QFont(name_label.font())
        font.setPointSizeF(font.pointSizeF() * 1.8)
        font.setBold(True)
        name_label.setFont(font)
        titles.addWidget(name_label)
        version_label = QLabel(f"Version {__version__}")
        version_label.setStyleSheet(f"color: {COLORS['accent']}; font-weight: bold;")
        titles.addWidget(version_label)
        full_name_label = QLabel(APP_FULL_NAME)
        full_name_label.setStyleSheet(f"color: {COLORS['muted']};")
        titles.addWidget(full_name_label)
        header.addLayout(titles)
        header.addStretch()
        layout.addLayout(header)

        description = QLabel("A friendlier front end for Windows network settings: adapters, routes, MTU, ping, "
                             "traceroute, latency monitoring, iperf bandwidth tests, DNS lookups and subnet sweeps.")
        description.setWordWrap(True)
        layout.addWidget(description)

        self.details = version_details()
        details_label = QLabel(self.details)
        details_label.setStyleSheet(f"color: {COLORS['muted']};")
        details_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(details_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        copy_button = buttons.addButton("Copy Version Info", QDialogButtonBox.ActionRole)
        copy_button.clicked.connect(lambda: QApplication.clipboard().setText(f"{APP_NAME} {__version__}\n{self.details}"))
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.setMinimumWidth(460)


def version_details():
    """Build and runtime versions, for bug reports."""
    build = "packaged exe" if getattr(sys, "frozen", False) else "running from source"
    return (f"Build: {build}\n"
            f"Python {platform.python_version()}, Qt {QT_VERSION_STR}, PyQt {PYQT_VERSION_STR}\n"
            f"{platform.platform()}")
