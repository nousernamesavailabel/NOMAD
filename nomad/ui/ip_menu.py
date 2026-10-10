"""Append host actions to existing context menus, or supply a menu for IP displays.

The application filter covers dynamically created pages and dialogs too. Context events
are delivered to their original widget first, preserving its selection and menu logic.
Only the menu shown during that delivery gets an additional, independently wired submenu.
"""
import html
import ipaddress
import itertools
import re

from PyQt5.QtCore import QEvent, QModelIndex, QObject, Qt
from PyQt5.QtGui import QContextMenuEvent
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QComboBox, QGraphicsTextItem, QGraphicsView, \
    QHeaderView, QLabel, QLineEdit, QMenu, QPlainTextEdit, QTextEdit, QWidget

from .host_menu import HostActions


def ip_addresses(text):
    """Validated IPv4/IPv6 literals, preserving scopes and removing URL brackets/ports."""
    found = []
    text = html.unescape(re.sub(r"<[^>]*>", " ", str(text)))
    for match in re.finditer(r"(?<![\w.])[\da-fA-F:.]+(?:%[\w.-]+)?(?![\w.])", text):
        value = match.group().strip(".")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            # IPv4 sockets often display address:port; unbracketed IPv6 is an address.
            value, separator, port = value.rpartition(":")
            if not separator or not port.isdigit() or ":" in value:
                continue
            try:
                address = ipaddress.IPv4Address(value)
            except ValueError:
                continue
        value = str(address)
        if value not in found:
            found.append(value)
    return found


def addresses_at(widget, position):
    """Use the clicked cell first, then its row; never use a different selected row."""
    if isinstance(widget, QHeaderView) or isinstance(widget.parentWidget(), QHeaderView):
        return []
    view = widget if isinstance(widget, QAbstractItemView) else widget.parentWidget()
    if isinstance(view, QAbstractItemView):
        point = view.viewport().mapFromGlobal(widget.mapToGlobal(position))
        index = view.indexAt(point)
        if not index.isValid():
            return []
        found = ip_addresses(index.data(Qt.DisplayRole) or "")
        if found:
            return found
        # Walk siblings until invalid: QListWidget's list model makes columnCount() private in PyQt.
        cells = itertools.takewhile(QModelIndex.isValid,
                                    (index.sibling(index.row(), column) for column in itertools.count()))
        return list(dict.fromkeys(address for cell in cells for address in ip_addresses(cell.data() or "")))
    view = widget if isinstance(widget, QGraphicsView) else widget.parentWidget()
    if isinstance(view, QGraphicsView):
        point = view.viewport().mapFromGlobal(widget.mapToGlobal(position))
        item = view.itemAt(point)
        while item is not None:
            if isinstance(item, QGraphicsTextItem):
                found = ip_addresses(item.toPlainText())
            elif hasattr(item, "hosts"):
                found = list(dict.fromkeys(address for host in item.hosts for address in ip_addresses(host.ip)))
            elif hasattr(item, "device"):
                found = ip_addresses(item.device.mgmt_ip)
            else:
                found = ip_addresses(getattr(item, "label", ""))
            if found:
                return found
            item = item.parentItem()
        return []
    if isinstance(widget, QLineEdit):
        return ip_addresses(widget.text()) if widget.echoMode() == QLineEdit.Normal else []
    if isinstance(widget, (QTextEdit, QPlainTextEdit)) or isinstance(widget.parentWidget(), (QTextEdit,
                                                                                            QPlainTextEdit)):
        editor = widget if isinstance(widget, (QTextEdit, QPlainTextEdit)) else widget.parentWidget()
        point = editor.viewport().mapFromGlobal(widget.mapToGlobal(position))
        return ip_addresses(editor.cursorForPosition(point).block().text())
    if isinstance(widget, QLabel):
        return ip_addresses(widget.text())
    if isinstance(widget, QComboBox):
        return ip_addresses(widget.currentText())
    return []


class IpContextMenus(QObject):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.pending = []
        self.delivering = False
        QApplication.instance().installEventFilter(self)

    def add_to(self, menu, addresses):
        handled = menu.property("nomadIpActions") or []
        addresses = [address for address in addresses if address not in handled]
        if not addresses:
            return
        if menu.actions():
            menu.addSeparator()
        for address in addresses:
            submenu = menu.addMenu(f"IP: {address}")
            actions = HostActions(self.window, menu).add_to(submenu, address, grouped=False)  # Already its own
            # Existing menus often dispatch exec_() through their own action dictionary.
            # Connect these new actions directly, leaving that dictionary untouched.
            for action, callback in actions.items():
                action.triggered.connect(lambda checked=False, callback=callback: callback())

    def eventFilter(self, widget, event):
        if event.type() == QEvent.Show and isinstance(widget, QMenu) and self.pending:
            addresses, self.pending = self.pending, []
            self.add_to(widget, addresses)
        if event.type() != QEvent.ContextMenu or self.delivering or not isinstance(widget, QWidget):
            return False
        if not (widget is self.window or self.window.isAncestorOf(widget)):
            return False
        if widget.contextMenuPolicy() in (Qt.NoContextMenu, Qt.PreventContextMenu):
            return False
        addresses = addresses_at(widget, event.pos())
        if not addresses:
            return False
        self.pending = addresses
        self.delivering = True
        try:
            forwarded = QContextMenuEvent(event.reason(), event.pos(), event.globalPos(), event.modifiers())
            QApplication.sendEvent(widget, forwarded)
            if self.pending and not forwarded.isAccepted():
                self.pending = []
                menu = QMenu(widget)
                self.add_to(menu, addresses)
                menu.exec_(event.globalPos())
                menu.deleteLater()
            event.accept()
        finally:
            self.pending = []
            self.delivering = False
        return True
