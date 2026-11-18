"""Word from other pages to the Editor (kept apart so the Terminal needn't import the Editor): a running-config the
Terminal saved, and a file to open."""
from PyQt5 import sip
from PyQt5.QtCore import QObject, pyqtSignal


class ConfigEvents(QObject):
    saved = pyqtSignal(object)  # {"host", "name", "prompt", "path", "text"}: the Terminal's Save Running Config
    open_requested = pyqtSignal(str)  # A file to open in the Editor


_events = None


def config_events():
    """The one ConfigEvents (made again if Qt has deleted it, as it does when its application goes)."""
    global _events
    if _events is None or sip.isdeleted(_events):
        _events = ConfigEvents()
    return _events
