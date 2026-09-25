"""NOMAD (Network Operations, Monitoring And Diagnostics): a friendlier GUI for Windows network settings.

Run with:  python Main.py   (or pythonw Main.py to avoid a console window)
"""
import ctypes
import logging
import sys
import traceback

from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QMessageBox

from nomad.logs import log_file_path, setup_logging
from nomad.system import APP_NAME, LEGACY_APP_NAME
from nomad.ui.main_window import MainWindow
from nomad.ui.icon import app_icon
from nomad.ui.theme import apply_theme

log = logging.getLogger("nomad")


def install_exception_hook():
    """Log unexpected errors and show them, instead of PyQt aborting the whole app."""
    def handle(exception_type, exception, trace):
        log.critical("Unhandled error:\n%s", "".join(traceback.format_exception(exception_type, exception, trace)))
        if QApplication.instance() is not None:
            QMessageBox.critical(None, "Unexpected Error",
                                 f"Something went wrong: {exception}\n\nDetails are in the log:\n{log_file_path()}")
    sys.excepthook = handle


def migrate_settings():
    """Copy window settings saved under the app's old name, the first time the new name is used."""
    settings = QSettings()
    if settings.allKeys():
        return
    legacy = QSettings(LEGACY_APP_NAME, LEGACY_APP_NAME)
    for key in legacy.allKeys():
        settings.setValue(key, legacy.value(key))
    if legacy.allKeys():
        log.info("Copied settings from %s", LEGACY_APP_NAME)


def main():
    """Main entry point for the application."""
    memory_log_handler = setup_logging()
    install_exception_hook()
    if sys.platform == "win32":
        # Show NOMAD's own icon on the taskbar instead of grouping it under python.exe
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NOMAD.NOMAD")
    app = QApplication(sys.argv)
    app.setOrganizationName(APP_NAME)
    app.setApplicationName(APP_NAME)
    migrate_settings()
    apply_theme(app)
    app.setWindowIcon(app_icon())
    window = MainWindow(memory_log_handler)
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
