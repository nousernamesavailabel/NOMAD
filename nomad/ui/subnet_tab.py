"""Subnet calculator tab: network, broadcast, host range and counts, and splitting a network into smaller subnets."""
from PyQt5.QtWidgets import QHBoxLayout, QLabel, QLineEdit, QPushButton, QSpinBox, QVBoxLayout, QWidget

from ..subnet import describe, host_range, parse_subnet, prefix_for_hosts, split
from .common import SortableTableItem, read_only_table, set_hint, set_invalid

SPLIT_COLUMNS = ["Subnet", "Network Address", "First Host", "Last Host", "Broadcast", "Wildcard Mask", "Addresses"]


class SubnetTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.network = None
        self.init_ui()
        window.adapter_changed.connect(lambda _: self.update_adapter_button())
        window.snapshot_changed.connect(lambda _: self.update_adapter_button())
        self.update_adapter_button()

    def init_ui(self):
        layout = QVBoxLayout(self)
        input_row = QHBoxLayout()
        self.subnet_input = QLineEdit()
        self.subnet_input.setPlaceholderText("192.168.1.10/24, 10.0.0.5 255.255.252.0 or 2001:db8::/48")
        self.adapter_button = QPushButton("Adapter's Address")
        input_row.addWidget(self.subnet_input, 1)
        input_row.addWidget(self.adapter_button)
        layout.addLayout(input_row)
        self.subnet_status = QLabel()
        self.subnet_status.setWordWrap(True)
        layout.addWidget(self.subnet_status)

        self.details_table = read_only_table(["", ""])
        self.details_table.horizontalHeader().setVisible(False)
        layout.addWidget(self.details_table, 3)

        split_row = QHBoxLayout()
        split_row.addWidget(QLabel("Split into /"))
        self.split_prefix_input = QSpinBox()
        self.split_prefix_input.setRange(1, 128)
        self.split_prefix_input.setButtonSymbols(QSpinBox.NoButtons)
        split_row.addWidget(self.split_prefix_input)
        split_row.addWidget(QLabel("or subnets of at least"))
        self.hosts_input = QSpinBox()
        self.hosts_input.setRange(1, 2 ** 31 - 1)
        self.hosts_input.setButtonSymbols(QSpinBox.NoButtons)
        self.hosts_input.setToolTip("Works out the prefix for subnets that each hold this many hosts.")
        split_row.addWidget(self.hosts_input)
        split_row.addWidget(QLabel("hosts"))
        self.split_button = QPushButton("Split")
        split_row.addWidget(self.split_button)
        split_row.addStretch()
        layout.addLayout(split_row)
        self.split_status = QLabel()
        self.split_status.setWordWrap(True)
        layout.addWidget(self.split_status)
        self.split_table = read_only_table(SPLIT_COLUMNS)
        layout.addWidget(self.split_table, 2)

        self.subnet_input.textChanged.connect(self.calculate)
        self.adapter_button.clicked.connect(self.use_adapter_address)
        self.hosts_input.editingFinished.connect(self.use_host_count)
        self.split_button.clicked.connect(self.split_subnet)
        self.split_prefix_input.editingFinished.connect(self.split_subnet)

    def adapter_address(self):
        adapter = self.window.current_adapter()
        return str(adapter.ipv4[0]) if adapter is not None and adapter.ipv4 else None

    def update_adapter_button(self):
        address = self.adapter_address()
        self.adapter_button.setEnabled(address is not None)
        self.adapter_button.setText(f"Adapter's Address ({address})" if address else "Adapter's Address")
        if address and not self.subnet_input.text().strip():
            self.subnet_input.setText(address)

    def use_adapter_address(self):
        address = self.adapter_address()
        if address:
            self.subnet_input.setText(address)

    def calculate_subnet(self, text):
        """Show a subnet in the calculator (from the IPAM page)."""
        self.subnet_input.setText(text)

    def calculate(self):
        self.split_table.setRowCount(0)
        self.split_status.clear()
        try:
            address, network = parse_subnet(self.subnet_input.text())
        except ValueError as error:
            self.network = None
            self.details_table.setRowCount(0)
            set_invalid(self.subnet_input, bool(self.subnet_input.text().strip()))
            set_hint(self.subnet_status, str(error) if self.subnet_input.text().strip() else "", "error")
            self.split_button.setEnabled(False)
            return
        set_invalid(self.subnet_input, False)
        self.subnet_status.clear()
        self.network = network
        rows = describe(address, network)
        self.details_table.setRowCount(len(rows))
        for row, (label, value) in enumerate(rows):
            self.details_table.setItem(row, 0, SortableTableItem(label))
            self.details_table.setItem(row, 1, SortableTableItem(value))
        can_split = network.prefixlen < network.max_prefixlen
        self.split_button.setEnabled(can_split)
        self.split_prefix_input.setRange(min(network.prefixlen + 1, network.max_prefixlen), network.max_prefixlen)
        if can_split and self.split_prefix_input.value() <= network.prefixlen:
            self.split_prefix_input.setValue(network.prefixlen + 1)

    def use_host_count(self):
        if self.network is None:
            return
        try:
            prefix = prefix_for_hosts(self.hosts_input.value(), self.network.version)
        except ValueError as error:
            set_hint(self.split_status, str(error), "error")
            return
        if prefix <= self.network.prefixlen:
            set_hint(self.split_status, f"Subnets of {self.hosts_input.value():,} hosts need a /{prefix}, which is "
                                        f"no smaller than {self.network}.", "warning")
            return
        self.split_prefix_input.setValue(prefix)
        self.split_subnet()

    def split_subnet(self):
        if self.network is None:
            return
        try:
            subnets, total = split(self.network, self.split_prefix_input.value())
        except ValueError as error:
            set_hint(self.split_status, str(error), "error")
            return
        self.split_table.setRowCount(len(subnets))
        for row, subnet in enumerate(subnets):
            first, last, _ = host_range(subnet)
            broadcast = str(subnet.broadcast_address) if subnet.version == 4 and subnet.prefixlen <= 30 else ""
            wildcard = str(subnet.hostmask) if subnet.version == 4 else ""
            values = [str(subnet), str(subnet.network_address), str(first), str(last), broadcast, wildcard,
                      f"{subnet.num_addresses:,}"]
            for column, value in enumerate(values):
                self.split_table.setItem(row, column, SortableTableItem(value))
        hosts = host_range(subnets[0])[2] if subnets else 0
        shown = f" (showing the first {len(subnets):,})" if len(subnets) < total else ""
        set_hint(self.split_status, f"{total:,} subnets of /{self.split_prefix_input.value()}, {hosts:,} hosts "
                                    f"each{shown}.", "info")

    # ----------------------------------------------------------------- Tab interface

    def focus_find(self):
        self.subnet_input.setFocus()
        self.subnet_input.selectAll()

    def save_settings(self, settings):
        # The key is kept from the old Utilities tab
        settings.setValue("utilities/subnet", self.subnet_input.text())

    def restore_settings(self, settings):
        self.subnet_input.setText(settings.value("utilities/subnet", "", str))
        self.update_adapter_button()

    def shutdown(self):
        pass
