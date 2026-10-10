"""Enter answers Yes: every yes/no question NOMAD asks starts with Yes (or OK) as the default button, wherever and
however the box was made. Tabbing to No (or Cancel) makes that the button Enter presses, as usual in Qt."""
from PyQt5.QtCore import QEvent, QObject
from PyQt5.QtWidgets import QMessageBox

ACCEPTING_ROLES = (QMessageBox.AcceptRole, QMessageBox.YesRole)


def default_to_yes(box):
    """Make the box's yes button its default: Yes, else OK, else the accepting one of two custom buttons ("Delete" /
    Cancel). Boxes with more choices than yes or no keep the default they were given."""
    for standard in (QMessageBox.Yes, QMessageBox.Ok):
        button = box.button(standard)
        if button is not None:
            box.setDefaultButton(button)
            return
    buttons = box.buttons()
    accepting = [button for button in buttons if box.buttonRole(button) in ACCEPTING_ROLES]
    if len(buttons) == 2 and len(accepting) == 1:
        box.setDefaultButton(accepting[0])


class YesByDefault(QObject):
    """Application event filter: as each message box opens, makes Yes its default (see default_to_yes)."""

    def eventFilter(self, watched, event):
        if event.type() == QEvent.Show and not event.spontaneous() and isinstance(watched, QMessageBox):
            default_to_yes(watched)
        return False


def install_yes_by_default(app):
    app.yes_by_default = YesByDefault(app)  # Kept on app so it lives as long as the app does
    app.installEventFilter(app.yes_by_default)
