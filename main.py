"""NOMAD: Network Operations, Monitoring And Diagnostics.

Run with:  python Main.py   (or pythonw Main.py to avoid a console window)
"""
import ctypes
import logging
import sys
import traceback

from PyQt5.QtCore import QSettings
from PyQt5.QtWidgets import QApplication, QMessageBox

from nomad import __version__
from nomad.logs import log_file_path, setup_logging
from nomad.system import (APP_NAME, ELEVATED_FOR_FLAG, LEGACY_APP_NAME, RESTARTED_FLAG, account_name, elevated_for,
                          is_admin, relaunch_as_admin, shift_held)
from nomad.ui.icon import app_icon
from nomad.ui.single_instance import InstanceServer, bring_to_front, find_running_copy, hang_up, needs_asking
from nomad.ui.splash import StartupSplash, close_bootloader_splash
from nomad.ui.theme import apply_theme
from nomad.ui.yes_default import install_yes_by_default

START_AS_ADMIN_SETTING = "startup/as_administrator"  # The same as MainWindow's, read before it's loaded

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


def hand_over_to_open_copy(splash, admin):
    """If NOMAD is open already, show it instead of starting another. Asks first when it's another version, or
    this copy has administrator rights it hasn't. Returns (handed over: stop here, another copy stays open)."""
    running, socket = find_running_copy()
    if running is None:
        return False, False
    if needs_asking(running, __version__, admin):
        splash.hide()
        if running.version != __version__:
            text = (f"{APP_NAME} {running.version} is already open"
                    f"{' as administrator' if running.admin else ''}.\n\nSwitch to it, or open {APP_NAME} "
                    f"{__version__} as well?")
            other = f"Open {__version__} Too"
        else:
            text = (f"{APP_NAME} is already open without administrator rights.\n\nSwitch to it, or open this copy, "
                    "as administrator, as well? (To have just the one with the rights, close the open one first.)")
            other = "Open as Administrator Too"
        box = QMessageBox(QMessageBox.Question, APP_NAME, text)
        switch = box.addButton("Switch to It", QMessageBox.AcceptRole)
        box.addButton(other, QMessageBox.ActionRole)
        box.setDefaultButton(switch)
        box.setEscapeButton(switch)
        box.exec_()
        if box.clickedButton() is not switch:
            hang_up(socket)
            log.info("%s %s is open too", APP_NAME, running.version)
            splash.show()
            return False, True
    log.info("%s is already open: showing it instead", APP_NAME)
    bring_to_front(socket)
    return True, True


def start_as_admin_wanted():
    """Always Start as Administrator is on, and Shift isn't held to start without the rights this once."""
    if not QSettings().value(START_AS_ADMIN_SETTING, False, bool):
        return False
    if shift_held():
        log.info("Shift held: starting without administrator rights this once")
        return False
    return True


def main():
    """Main entry point for the application."""
    if "--ipam-service" in sys.argv:  # Started by Windows as the NOMAD IPAM Server service
        from nomad.ipam.service import run_service_dispatcher
        run_service_dispatcher()
        return
    if "--map-watcher-service" in sys.argv:  # Started by Windows as the NOMAD Map Watcher service
        from nomad.netmap.watch_service import run_service_dispatcher
        run_service_dispatcher()
        return
    if "--map-watcher" in sys.argv:  # The Map Watcher in this console, for trying it out or troubleshooting
        from nomad.netmap.watch_service import run_in_foreground
        run_in_foreground()
        return
    if "--ipam-server" in sys.argv:  # The IPAM server in this console, for trying it out or troubleshooting
        from nomad.ipam.server import run_in_foreground
        run_in_foreground()
        return
    memory_log_handler = setup_logging()
    install_exception_hook()
    log.info("Starting %s %s", APP_NAME, __version__)
    if sys.platform == "win32":
        # Show NOMAD's own icon on the taskbar instead of grouping it under python.exe
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("NOMAD.NOMAD")
    app = QApplication(sys.argv)
    app.setOrganizationName(APP_NAME)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(__version__)
    migrate_settings()
    apply_theme(app)
    install_yes_by_default(app)
    app.setWindowIcon(app_icon())
    # Up as soon as Qt is: the packaged exe's own splash (shown while it unpacks) looks the same and goes now
    splash = StartupSplash()
    splash.show()
    app.processEvents()  # Nothing else exists yet to run
    close_bootloader_splash()

    admin = is_admin()
    other_copy_open = False
    if RESTARTED_FLAG not in sys.argv:  # Not started by a copy that's closing, which would be handed over to
        handed_over, other_copy_open = hand_over_to_open_copy(splash, admin)
        if handed_over:
            return
    declined = False
    if not admin and start_as_admin_wanted():
        splash.step("Asking for administrator rights...")
        if relaunch_as_admin([RESTARTED_FLAG, ELEVATED_FOR_FLAG + account_name()]):
            log.info("Started again as administrator")
            return
        declined = True
        log.info("Administrator rights declined: starting without them")

    instance_server = InstanceServer(__version__, admin, app)
    if not other_copy_open:  # Opening NOMAD again shows this copy (while the other is open, that one answers)
        instance_server.listen()
    app.aboutToQuit.connect(instance_server.close)
    splash.step("Loading...", 0.05)
    log.debug("Startup: loading the pages' code")
    from nomad.ui.main_window import MainWindow  # Imported once the splash is up: it loads every page's code
    window = MainWindow(memory_log_handler, splash, elevated_for(sys.argv))
    window.instance_server = instance_server
    instance_server.show_requested.connect(window.bring_to_front)
    splash.step("Opening...", 1.0)
    window.show()
    splash.finish(window)
    window.splash = None
    if declined:
        window.show_status("Started without administrator rights: Windows' prompt for them was answered No. "
                           "File > Always Start as Administrator turns asking off.", "warning", 30000)
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
