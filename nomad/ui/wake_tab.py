"""Wake-on-LAN tab: wake a computer by its MAC address, and keep the devices woken often."""
import logging

from PyQt5.QtWidgets import QFormLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPushButton, QVBoxLayout, \
    QWidget

from ..oui import format_mac, vendor
from ..wol import WakeTarget, destinations, send_magic_packet, targets_from_json, targets_to_json, \
    validate_broadcast
from .common import SortableTableItem, read_only_table, set_hint, set_invalid
from .theme import accent_button

log = logging.getLogger(__name__)

WAKE_COLUMNS = ["Name", "MAC Address", "Vendor", "Subnet Broadcast"]


class WakeTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.wake_targets = []
        self.init_ui()
        self.update_wake_buttons()

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Wake a computer whose network card is set up for Wake-on-LAN. The packet is broadcast on "
                       "every connected subnet; for a computer on another subnet, give that subnet's broadcast "
                       "address (the router must allow directed broadcasts).")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        self.wake_name_input = QLineEdit()
        self.wake_name_input.setPlaceholderText("Optional, to save it")
        self.wake_mac_input = QLineEdit()
        self.wake_mac_input.setPlaceholderText("00-11-22-33-44-55")
        self.wake_broadcast_input = QLineEdit()
        self.wake_broadcast_input.setPlaceholderText("Optional, such as 192.168.20.255")
        form = QFormLayout()
        form.addRow("Name:", self.wake_name_input)
        form.addRow("MAC address:", self.wake_mac_input)
        form.addRow("Subnet broadcast:", self.wake_broadcast_input)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        self.wake_button = accent_button("Wake")
        self.save_wake_button = QPushButton("Save")
        self.delete_wake_button = QPushButton("Delete")
        for button in (self.wake_button, self.save_wake_button, self.delete_wake_button):
            buttons.addWidget(button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.wake_status = QLabel()
        self.wake_status.setWordWrap(True)
        layout.addWidget(self.wake_status)
        self.wake_table = read_only_table(WAKE_COLUMNS)
        layout.addWidget(self.wake_table, 1)

        self.wake_button.clicked.connect(self.wake)
        self.wake_mac_input.returnPressed.connect(self.wake)
        self.wake_mac_input.textChanged.connect(lambda: set_invalid(self.wake_mac_input, False))
        self.wake_broadcast_input.textChanged.connect(lambda: set_invalid(self.wake_broadcast_input, False))
        self.save_wake_button.clicked.connect(self.save_target)
        self.delete_wake_button.clicked.connect(self.delete_target)
        self.wake_table.itemSelectionChanged.connect(self.on_target_selected)
        self.wake_table.doubleClicked.connect(lambda _: self.wake())
        self.wake_name_input.textChanged.connect(self.update_wake_buttons)

    def read_wake_form(self):
        """Returns a WakeTarget from the form, or None after showing what's wrong."""
        mac = format_mac(self.wake_mac_input.text())
        if not mac:
            set_invalid(self.wake_mac_input, True)
            set_hint(self.wake_status, "Enter the computer's MAC address, such as 00-11-22-33-44-55.", "error")
            return None
        try:
            broadcast = validate_broadcast(self.wake_broadcast_input.text())
        except ValueError as error:
            set_invalid(self.wake_broadcast_input, True)
            set_hint(self.wake_status, str(error), "error")
            return None
        return WakeTarget(self.wake_name_input.text().strip(), mac, broadcast)

    def wake(self):
        target = self.read_wake_form()
        if target is None:
            return
        addresses = [address for adapter in self.window.snapshot.real_adapters() if adapter.status == "Up"
                     for address in adapter.ipv4 if not address.ip.is_link_local]
        try:
            sent = send_magic_packet(target.mac, destinations(addresses, target.broadcast))
        except (OSError, ValueError) as error:
            set_hint(self.wake_status, f"Couldn't send the wake-up packet: {error}", "error")
            return
        who = target.name or target.mac
        set_hint(self.wake_status, f"Sent the wake-up packet for {who} ({sent} broadcast{'' if sent == 1 else 's'}). "
                                   "A computer usually takes 10-60 seconds to start; try pinging it.", "success")
        log.info("Sent Wake-on-LAN for %s", target.mac)

    def wake_device(self, mac, name=""):
        """Fill in a device from another tab (Sweep, ARP)."""
        self.wake_mac_input.setText(mac)
        self.wake_name_input.setText(name)
        self.wake_broadcast_input.clear()
        set_hint(self.wake_status, "Press Wake to send the packet, or Save to keep this device.", "info")

    def save_target(self):
        target = self.read_wake_form()
        if target is None:
            return
        if not target.name:
            set_hint(self.wake_status, "Give the device a name to save it.", "error")
            self.wake_name_input.setFocus()
            return
        self.wake_targets = [saved for saved in self.wake_targets if saved.name != target.name] + [target]
        self.wake_targets.sort(key=lambda saved: saved.name.lower())
        self.fill_wake_table(select=target.name)
        set_hint(self.wake_status, f"Saved {target.name}.", "success")

    def delete_target(self):
        target = self.selected_target()
        if target is None:
            return
        reply = QMessageBox.question(self, "Delete Device", f"Delete the saved device {target.name}?",
                                     QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.Yes:
            self.wake_targets.remove(target)
            self.fill_wake_table()

    def fill_wake_table(self, select=None):
        self.wake_table.setRowCount(len(self.wake_targets))
        for row, target in enumerate(self.wake_targets):
            for column, value in enumerate([target.name, target.mac, vendor(target.mac), target.broadcast]):
                self.wake_table.setItem(row, column, SortableTableItem(value, data=target))
            if target.name == select:
                self.wake_table.selectRow(row)
        self.update_wake_buttons()

    def selected_target(self):
        rows = self.wake_table.selectionModel().selectedRows()
        return self.wake_table.item(rows[0].row(), 0).data_object if rows else None

    def on_target_selected(self):
        target = self.selected_target()
        if target is not None:
            self.wake_name_input.setText(target.name)
            self.wake_mac_input.setText(target.mac)
            self.wake_broadcast_input.setText(target.broadcast)
        self.update_wake_buttons()

    def update_wake_buttons(self):
        self.delete_wake_button.setEnabled(self.selected_target() is not None)

    # ----------------------------------------------------------------- Tab interface

    def focus_find(self):
        self.wake_mac_input.setFocus()
        self.wake_mac_input.selectAll()

    def save_settings(self, settings):
        # The key is kept from the old Utilities tab, so saved devices carry over
        settings.setValue("utilities/wake_targets", targets_to_json(self.wake_targets))

    def restore_settings(self, settings):
        self.wake_targets = targets_from_json(settings.value("utilities/wake_targets", "[]", str))
        self.fill_wake_table()

    def shutdown(self):
        pass
