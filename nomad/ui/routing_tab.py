"""Routing table tab: view, filter, add, edit and delete IPv4/IPv6 routes."""
import ipaddress
import logging

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor, QFont, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QApplication, QCheckBox, QComboBox, QFormLayout, QGroupBox, \
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPushButton, QShortcut, QTableWidget, \
    QVBoxLayout, QWidget

from ..routes import add_route, build_route_copy_command, delete_route, validate_route_input
from ..snapshot import Route
from ..system import CommandError
from .common import SortableTableItem, set_hint, set_invalid
from .theme import COLORS

log = logging.getLogger(__name__)

ROUTE_COLUMNS = ['Destination', 'Netmask', 'Gateway', 'Interface', 'Metric', 'Persistent', 'Delete']
COL_INTERFACE = ROUTE_COLUMNS.index('Interface')
COL_DELETE = ROUTE_COLUMNS.index('Delete')

DEFAULT_ROUTE_COLOR = COLORS["warning_background"]
ADDED_ROUTE_COLOR = COLORS["success_background"]
PERSISTENT_ROUTE_COLOR = COLORS["link"]
INACTIVE_ROUTE_COLOR = COLORS["disabled"]


class RoutingTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.selected_route = None
        self.session_added_routes = set()  # match_keys of routes added or updated from this app
        self.route_form_spec = None  # Validated route from the form, or None
        self.restoring_route_selection = False
        self.init_ui()
        window.snapshot_changed.connect(lambda _: self.populate())
        self.apply_route_family_to_form()
        self.populate()

    # ----------------------------------------------------------------- UI setup

    def init_ui(self):
        routing_layout = QVBoxLayout(self)

        # Toolbar: address family, filter and system route toggle
        toolbar_layout = QHBoxLayout()
        self.route_family_combo = QComboBox(self)
        self.route_family_combo.addItem("IPv4", 4)
        self.route_family_combo.addItem("IPv6", 6)
        toolbar_layout.addWidget(self.route_family_combo)

        self.route_filter_input = QLineEdit(self)
        self.route_filter_input.setPlaceholderText("Filter by destination, gateway, interface... (Ctrl+F)")
        self.route_filter_input.setClearButtonEnabled(True)
        toolbar_layout.addWidget(self.route_filter_input, 1)

        self.hide_system_routes_check = QCheckBox("Hide system routes", self)
        self.hide_system_routes_check.setChecked(True)
        self.hide_system_routes_check.setToolTip(
            "Hide loopback, multicast, broadcast and host routes that Windows manages automatically.")
        toolbar_layout.addWidget(self.hide_system_routes_check)
        routing_layout.addLayout(toolbar_layout)

        # Read-only table of routes
        self.routing_table_widget = QTableWidget(self)
        self.routing_table_widget.setColumnCount(len(ROUTE_COLUMNS))
        self.routing_table_widget.setHorizontalHeaderLabels(ROUTE_COLUMNS)
        self.routing_table_widget.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.routing_table_widget.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.routing_table_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.routing_table_widget.verticalHeader().setVisible(False)
        self.routing_table_widget.setSortingEnabled(True)
        self.routing_table_widget.sortByColumn(0, Qt.AscendingOrder)
        self.routing_table_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        header = self.routing_table_widget.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeToContents)
        header.setSectionResizeMode(COL_INTERFACE, QHeaderView.Stretch)
        routing_layout.addWidget(self.routing_table_widget, 1)

        # Row count and color legend
        info_layout = QHBoxLayout()
        self.route_count_label = QLabel(self)
        info_layout.addWidget(self.route_count_label)
        info_layout.addStretch()
        legend_label = QLabel(
            f'<span style="background:{DEFAULT_ROUTE_COLOR}">&nbsp;Default route&nbsp;</span>&nbsp; '
            f'<span style="background:{ADDED_ROUTE_COLOR}">&nbsp;Added this session&nbsp;</span>&nbsp; '
            f'<span style="color:{PERSISTENT_ROUTE_COLOR}">Persistent</span>&nbsp; '
            f'<span style="color:{INACTIVE_ROUTE_COLOR}">Inactive</span>', self)
        info_layout.addWidget(legend_label)
        routing_layout.addLayout(info_layout)

        # Form for adding and editing routes
        self.destination_input = QLineEdit(self)
        self.netmask_input = QLineEdit(self)
        self.route_gateway_input = QLineEdit(self)
        self.route_interface_combo = QComboBox(self)
        self.metric_input = QLineEdit(self)
        self.metric_input.setToolTip("Route metric. Windows adds the interface metric to it, so the table shows "
                                     "the combined value. Leave blank for automatic.")
        self.persistent_check = QCheckBox("Persistent (survives reboot)", self)
        self.route_hint_label = QLabel(self)
        self.route_hint_label.setWordWrap(True)

        route_form_layout = QFormLayout()
        route_form_layout.addRow("Network Destination:", self.destination_input)
        route_form_layout.addRow("Netmask:", self.netmask_input)
        route_form_layout.addRow("Gateway:", self.route_gateway_input)
        route_form_layout.addRow("Interface:", self.route_interface_combo)
        route_form_layout.addRow("Metric:", self.metric_input)
        route_form_layout.addRow("", self.persistent_check)
        route_form_layout.addRow(self.route_hint_label)

        self.add_button = QPushButton("Add Route", self)
        self.update_route_button = QPushButton("Update Selected", self)
        self.delete_button = QPushButton("Delete Selected", self)
        self.clear_route_button = QPushButton("Clear Form", self)
        button_layout = QHBoxLayout()
        for button in (self.add_button, self.update_route_button, self.delete_button, self.clear_route_button):
            button_layout.addWidget(button)
        route_form_layout.addRow(button_layout)

        route_form_group = QGroupBox("Add / Edit Route", self)
        route_form_group.setLayout(route_form_layout)
        routing_layout.addWidget(route_form_group)

        # Connect signals
        self.route_family_combo.currentIndexChanged.connect(self.on_route_family_changed)
        self.route_filter_input.textChanged.connect(self.apply_route_filters)
        self.hide_system_routes_check.toggled.connect(self.apply_route_filters)
        self.routing_table_widget.itemSelectionChanged.connect(self.on_route_selected)
        self.routing_table_widget.customContextMenuRequested.connect(self.show_route_context_menu)
        self.destination_input.textChanged.connect(self.on_destination_changed)
        for line_edit in (self.destination_input, self.netmask_input, self.route_gateway_input, self.metric_input):
            line_edit.textChanged.connect(self.validate_route_form)
        self.route_interface_combo.currentIndexChanged.connect(self.validate_route_form)
        self.add_button.clicked.connect(self.add_route)
        self.update_route_button.clicked.connect(self.update_selected_route)
        self.delete_button.clicked.connect(self.delete_selected_route)
        self.clear_route_button.clicked.connect(self.clear_route_form)
        delete_shortcut = QShortcut(QKeySequence.Delete, self.routing_table_widget)
        delete_shortcut.setContext(Qt.WidgetShortcut)
        delete_shortcut.activated.connect(self.delete_selected_route)

    # ----------------------------------------------------------------- Tab interface

    def save_settings(self, settings):
        settings.setValue("routes/family", self.current_route_family())
        settings.setValue("routes/hide_system", self.hide_system_routes_check.isChecked())

    def restore_settings(self, settings):
        index = self.route_family_combo.findData(settings.value("routes/family", 4, int))
        self.route_family_combo.setCurrentIndex(max(index, 0))
        self.hide_system_routes_check.setChecked(settings.value("routes/hide_system", True, bool))

    def shutdown(self):
        pass

    def focus_filter(self):
        self.route_filter_input.setFocus()
        self.route_filter_input.selectAll()

    # ----------------------------------------------------------------- Table

    @property
    def adapters(self):
        return self.window.snapshot.adapters

    def current_route_family(self):
        return self.route_family_combo.currentData()

    def populate(self, select_key=None):
        """Redraw the table and interface list from the latest snapshot."""
        self.populate_route_interface_combo()
        self.fill_route_table(select_key)
        self.validate_route_form()

    def fill_route_table(self, select_key=None):
        """Show the routes for the selected address family in the table."""
        family = self.current_route_family()
        if select_key is None and self.selected_route is not None:
            select_key = self.selected_route.match_key

        table = self.routing_table_widget
        table.setSortingEnabled(False)  # Sorting while inserting would scramble rows
        table.setRowCount(0)
        routes = [route for route in self.window.snapshot.routes if route.family == family]
        table.setRowCount(len(routes))

        for row_index, route in enumerate(routes):
            for column, (text, sort_key) in enumerate(self.route_cells(route)):
                item = SortableTableItem(text, sort_key, route)
                self.style_route_item(item, route)
                table.setItem(row_index, column, item)

            # The delete button captures the route rather than the row index, because sorting moves rows
            delete_button = QPushButton("Delete", self)
            delete_button.clicked.connect(lambda _, route=route: self.confirm_and_delete_route(route))
            table.setCellWidget(row_index, COL_DELETE, delete_button)

        table.setSortingEnabled(True)
        self.apply_route_filters()

        # Reselect the previously selected route without overwriting what's in the form
        self.selected_route = None
        self.restoring_route_selection = True
        try:
            table.clearSelection()
            for row in range(table.rowCount()):
                if table.item(row, 0).data_object.match_key == select_key:
                    table.selectRow(row)
                    table.scrollToItem(table.item(row, 0))
                    break
        finally:
            self.restoring_route_selection = False
        self.update_route_buttons()

    def route_cells(self, route):
        """Return (display text, sort key) for each column of a route's row."""
        network = route.network
        if route.family == 4:
            destination = str(network.network_address)
            netmask = f"{network.netmask} (/{network.prefixlen})"
        else:
            destination = str(network)
            netmask = f"/{network.prefixlen}"
        gateway_key = (0, 0) if route.on_link else (1, int(ipaddress.ip_address(route.gateway)))
        interface = self.describe_route_interface(route)
        metric = "" if route.metric is None else str(route.metric)
        if route.persistent:
            persistent = "Yes" if route.active else "Yes (inactive)"
        else:
            persistent = ""
        return [
            (destination, (int(network.network_address), network.prefixlen)),
            (netmask, network.prefixlen),
            (route.gateway, gateway_key),
            (interface, interface.lower()),
            (metric, -1 if route.metric is None else route.metric),
            (persistent, persistent),
            ("", 0),
        ]

    def style_route_item(self, item, route):
        """Highlight the default route, routes added from this app, persistent and inactive routes."""
        tooltips = []
        if route.is_default:
            item.setBackground(QColor(DEFAULT_ROUTE_COLOR))
            font = QFont(item.font())
            font.setBold(True)
            item.setFont(font)
            tooltips.append("Default route: traffic with no more specific route is sent here.")
        elif route.match_key in self.session_added_routes:
            item.setBackground(QColor(ADDED_ROUTE_COLOR))
            tooltips.append("Added or updated from NOMAD this session.")
        if not route.active:
            item.setForeground(QColor(INACTIVE_ROUTE_COLOR))
            tooltips.append("Persistent route that isn't currently active (its gateway or interface may be "
                            "unavailable).")
        elif route.persistent:
            item.setForeground(QColor(PERSISTENT_ROUTE_COLOR))
            tooltips.append("Persistent route: it is restored when Windows restarts.")
        if route.route_metric is not None and route.interface_metric is not None:
            tooltips.append(f"Metric {route.metric} = route metric {route.route_metric} + interface metric "
                            f"{route.interface_metric}.")
        if tooltips:
            item.setToolTip("\n".join(tooltips))

    def describe_route_interface(self, route):
        adapter = self.adapters.get(route.interface)
        if adapter is None:
            return f"Interface {route.interface}"
        if route.family == 4 and adapter.ipv4:
            return f"{adapter.name} ({adapter.ipv4[0].ip})"
        return f"{adapter.name} (index {adapter.index})"

    def describe_route(self, route):
        gateway = "on-link" if route.on_link else f"via {route.gateway}"
        return f"{route.network} {gateway} ({self.describe_route_interface(route)})"

    def apply_route_filters(self):
        """Hide rows that don't match the filter text or are hidden system routes."""
        table = self.routing_table_widget
        filter_text = self.route_filter_input.text().strip().lower()
        hide_system = self.hide_system_routes_check.isChecked()

        visible_count = 0
        for row in range(table.rowCount()):
            route = table.item(row, 0).data_object
            hidden = (hide_system and route.is_system and not route.persistent
                      and route.match_key not in self.session_added_routes)
            if not hidden and filter_text:
                row_text = " ".join(table.item(row, column).text().lower() for column in range(COL_DELETE))
                hidden = filter_text not in row_text
            table.setRowHidden(row, hidden)
            if not hidden:
                visible_count += 1

        self.route_count_label.setText(
            f"Showing {visible_count} of {table.rowCount()} IPv{self.current_route_family()} routes")

    # ----------------------------------------------------------------- Form

    def on_route_family_changed(self):
        """Switch the table and the form between IPv4 and IPv6."""
        self.clear_route_form()
        self.apply_route_family_to_form()
        self.fill_route_table()
        self.validate_route_form()

    def apply_route_family_to_form(self):
        """Adjust the form's placeholders and fields for the selected address family."""
        if self.current_route_family() == 4:
            self.destination_input.setPlaceholderText("e.g. 10.0.0.0 or 10.0.0.0/24")
            self.netmask_input.setEnabled("/" not in self.destination_input.text())
            self.netmask_input.setPlaceholderText("e.g. 255.255.255.0 (filled in automatically for /24 notation)")
            self.route_gateway_input.setPlaceholderText("e.g. 192.168.1.1 (leave blank for an on-link route)")
        else:
            self.destination_input.setPlaceholderText("e.g. 2001:db8::/32")
            self.netmask_input.clear()
            self.netmask_input.setEnabled(False)
            self.netmask_input.setPlaceholderText("Not used for IPv6 (include the prefix length in the destination)")
            self.route_gateway_input.setPlaceholderText("e.g. fe80::1 (leave blank for an on-link route)")
        self.metric_input.setPlaceholderText("Optional, 1-9999 (blank = automatic)")
        self.populate_route_interface_combo()

    def populate_route_interface_combo(self):
        """Fill the interface dropdown with connected interfaces for the selected address family."""
        family = self.current_route_family()
        combo = self.route_interface_combo
        previous = combo.currentData()

        combo.blockSignals(True)
        combo.clear()
        combo.addItem("Automatic (the interface on the gateway's subnet)" if family == 4
                      else "Select an interface...", None)
        for adapter in sorted(self.adapters.values(), key=lambda adapter: adapter.name.lower()):
            if not adapter.connected or family not in adapter.families:
                continue
            if family == 4 and not adapter.ipv4:
                continue
            combo.addItem(adapter.label(family), adapter.index)
        index = combo.findData(previous) if previous is not None else 0
        combo.setCurrentIndex(max(index, 0))
        combo.blockSignals(False)

    def on_destination_changed(self, text):
        """Fill in the netmask when the destination is typed in CIDR notation (e.g. 10.0.0.0/24)."""
        if self.current_route_family() != 4:
            return
        text = text.strip()
        if "/" in text:
            try:
                network = ipaddress.IPv4Network(text, strict=False)
            except ValueError:
                return
            self.netmask_input.setText(str(network.netmask))
            self.netmask_input.setEnabled(False)
        elif not self.netmask_input.isEnabled():
            self.netmask_input.setEnabled(True)

    def validate_route_form(self):
        """Validate the route form as the user types, flagging bad fields and enabling buttons."""
        spec, errors, warnings = validate_route_input(
            self.current_route_family(), self.destination_input.text(), self.netmask_input.text(),
            self.route_gateway_input.text(), self.metric_input.text(), self.route_interface_combo.currentData(),
            self.adapters)
        self.route_form_spec = spec

        fields = {
            "destination": self.destination_input,
            "netmask": self.netmask_input,
            "gateway": self.route_gateway_input,
            "metric": self.metric_input,
        }
        # Only outline fields the user has typed in, so an empty form isn't covered in red
        for name, line_edit in fields.items():
            set_invalid(line_edit, name in errors and bool(line_edit.text().strip()))

        form_touched = any(line_edit.text().strip() for line_edit in fields.values())
        if errors and form_touched:
            set_hint(self.route_hint_label, next(iter(errors.values())), "error")
        elif warnings:
            set_hint(self.route_hint_label, warnings[0], "warning")
        elif spec is not None:
            adapter = self.adapters.get(spec["interface"])
            summary = f"Ready: {spec['network']} {'via ' + spec['gateway'] if spec['gateway'] else 'on-link'}"
            if adapter is not None:
                summary += f" on {adapter.name}"
            set_hint(self.route_hint_label, summary, "info")
        else:
            self.route_hint_label.clear()

        self.update_route_buttons()

    def update_route_buttons(self):
        """Enable the form buttons that make sense for the current form and selection."""
        form_valid = self.route_form_spec is not None
        self.add_button.setEnabled(form_valid)
        self.update_route_button.setEnabled(form_valid and self.selected_route is not None)
        self.delete_button.setEnabled(self.selected_route is not None)

    def on_route_selected(self):
        """Copy the selected route into the form so it can be edited or deleted."""
        items = self.routing_table_widget.selectedItems()
        self.selected_route = items[0].data_object if items else None
        if self.selected_route is not None and not self.restoring_route_selection:
            self.load_route_into_form(self.selected_route)
        self.update_route_buttons()

    def load_route_into_form(self, route):
        network = route.network
        if route.family == 4:
            self.destination_input.setText(str(network.network_address))
            self.netmask_input.setText(str(network.netmask))
        else:
            self.destination_input.setText(str(network))
        self.route_gateway_input.setText("" if route.on_link else route.gateway)
        index = self.route_interface_combo.findData(route.interface)
        self.route_interface_combo.setCurrentIndex(max(index, 0))
        self.metric_input.setText(str(route.route_metric) if route.route_metric else "")
        self.persistent_check.setChecked(route.persistent)

    def clear_route_form(self):
        """Clear the form and the table selection."""
        self.routing_table_widget.clearSelection()
        for line_edit in (self.destination_input, self.netmask_input, self.route_gateway_input, self.metric_input):
            line_edit.clear()
        self.route_interface_combo.setCurrentIndex(0)
        self.persistent_check.setChecked(False)

    def read_route_form(self):
        """Return the validated route spec from the form, or None (after explaining why)."""
        spec, errors, _ = validate_route_input(
            self.current_route_family(), self.destination_input.text(), self.netmask_input.text(),
            self.route_gateway_input.text(), self.metric_input.text(), self.route_interface_combo.currentData(),
            self.adapters)
        if errors:
            QMessageBox.warning(self, "Invalid Route", "\n".join(errors.values()))
            return None
        spec["persistent"] = self.persistent_check.isChecked()
        return spec

    def spec_key(self, spec):
        return Route(self.current_route_family(), spec["network"], spec["gateway"], spec["interface"]).match_key

    # ----------------------------------------------------------------- Changes

    def add_route(self):
        """Add a new route from the form."""
        spec = self.read_route_form()
        if spec is None:
            return
        family = self.current_route_family()
        new_key = self.spec_key(spec)

        def added(_):
            self.session_added_routes.add(new_key)
            self.window.show_status(f"Added route {spec['network']} "
                                    f"{'via ' + spec['gateway'] if spec['gateway'] else 'on-link'}"
                                    f"{' (persistent)' if spec['persistent'] else ''}.")
            self.populate(select_key=new_key)

        self.window.run_change(
            f"Adding route {spec['network']}",
            lambda: add_route(family, spec["network"], spec["gateway"], spec["interface"], spec["metric"],
                              spec["persistent"]),
            on_success=added)

    def update_selected_route(self):
        """Replace the selected route with the values in the form (delete, then add)."""
        original = self.selected_route
        if original is None:
            QMessageBox.warning(self, "No Route Selected", "Select a route in the table to update.")
            return
        spec = self.read_route_form()
        if spec is None:
            return

        if original.is_default:
            reply = QMessageBox.warning(
                self, "Update Default Route",
                "Updating the default route removes it briefly, which interrupts network traffic. Continue?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return

        family = self.current_route_family()
        new_key = self.spec_key(spec)

        def replace_route():
            delete_route(original)
            try:
                add_route(family, spec["network"], spec["gateway"], spec["interface"], spec["metric"],
                          spec["persistent"])
            except CommandError as error:
                # Put the original route back so a typo doesn't leave the machine without it
                try:
                    add_route(original.family, original.network, "" if original.on_link else original.gateway,
                              original.interface, original.route_metric or None, original.persistent)
                except CommandError as restore_error:
                    raise CommandError(error.command,
                                       f"{error}\n\nThe original route could NOT be restored: {restore_error}\n\n"
                                       f"Restore it in PowerShell with:\n{build_route_copy_command(original)}")
                raise CommandError(error.command, f"{error}\n\nThe original route was restored.")

        def updated(_):
            self.session_added_routes.discard(original.match_key)
            self.session_added_routes.add(new_key)
            self.window.show_status(f"Updated route {spec['network']}.")
            self.populate(select_key=new_key)

        self.window.run_change(f"Updating route {original.network}", replace_route, on_success=updated)

    def delete_selected_route(self):
        if self.selected_route is None:
            return
        self.confirm_and_delete_route(self.selected_route)

    def confirm_and_delete_route(self, route):
        """Ask for confirmation, with a stronger warning for critical routes, then delete the route."""
        description = self.describe_route(route)
        if route.is_default:
            message = (f"Delete the default route {description}?\n\n"
                       "All traffic without a more specific route uses it. Deleting it will probably cut this "
                       "computer off from the internet and other networks until it is re-added.")
        elif route.is_system:
            message = (f"Delete {description}?\n\n"
                       "This is a system route that Windows manages (loopback, multicast, broadcast or a local "
                       "address). Deleting it can break local networking until the adapter is restarted.")
        else:
            message = f"Delete route {description}?"
            if route.persistent:
                message += "\n\nThis route is persistent; it will also be removed from the saved routes."

        ask = QMessageBox.warning if route.is_default or route.is_system else QMessageBox.question
        if ask(self, "Confirm Delete", message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No) != QMessageBox.Yes:
            return

        def deleted(_):
            self.session_added_routes.discard(route.match_key)
            if self.selected_route is route:
                self.selected_route = None
            self.window.show_status(f"Deleted route {route.network}.")

        self.window.run_change(f"Deleting route {route.network}", lambda: delete_route(route), on_success=deleted)

    def show_route_context_menu(self, position):
        """Right-click menu for a route: edit, delete, copy."""
        item = self.routing_table_widget.itemAt(position)
        if item is None:
            return
        self.routing_table_widget.selectRow(item.row())
        route = item.data_object

        menu = QMenu(self)
        edit_action = menu.addAction("Edit")
        delete_action = menu.addAction("Delete")
        menu.addSeparator()
        copy_row_action = menu.addAction("Copy Row")
        copy_command_action = menu.addAction("Copy as PowerShell Command")

        chosen = menu.exec_(self.routing_table_widget.viewport().mapToGlobal(position))
        if chosen is edit_action:
            self.load_route_into_form(route)
            self.destination_input.setFocus()
        elif chosen is delete_action:
            self.confirm_and_delete_route(route)
        elif chosen is copy_row_action:
            row = item.row()
            QApplication.clipboard().setText("\t".join(
                self.routing_table_widget.item(row, column).text() for column in range(COL_DELETE)))
            self.window.show_status("Copied row to the clipboard.", "info")
        elif chosen is copy_command_action:
            QApplication.clipboard().setText(build_route_copy_command(route))
            self.window.show_status("Copied command to the clipboard.", "info")
