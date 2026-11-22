"""Right-click a device on the map > Tools > Ports to Graph: choose which of its ports' traffic is kept for graphs, besides
the ports at the ends of its links (always kept): by the Map Watcher (for the NOMAD Dashboard and every NOMAD's Traffic
Graphs page), and by this computer while the map's Monitor is on."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QDialogButtonBox, QLabel, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout

from ..netmap.model import port_key, port_sort_key


def device_ports(network_map, key):
    """(the device's ports in order, the keys of those at the ends of links)."""
    device = network_map.devices[key]
    linked = {port_key(link.port_on(key)): link.port_on(key) for link in network_map.links_of(key)}
    ports = {port_key(port): port for port in device.port_status}
    ports.update({port_key(port): port for port in network_map.graphed.get(key, [])})
    ports.update(linked)
    return sorted(ports.values(), key=port_sort_key), set(linked)


class GraphPortsDialog(QDialog):
    def __init__(self, parent, network_map, key):
        super().__init__(parent)
        device = network_map.devices[key]
        self.setWindowTitle(f"Ports to Graph: {device.label}")
        self.setMinimumSize(380, 460)
        layout = QVBoxLayout(self)
        note = QLabel("Tick the ports whose traffic is kept for graphs: by the Map Watcher (for the NOMAD Dashboard "
                      "and every NOMAD's Traffic Graphs page), and by this computer while Monitor is on. Ports at the "
                      "ends of links are always kept.")
        note.setWordWrap(True)
        layout.addWidget(note)
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Filter")
        self.filter_input.setClearButtonEnabled(True)
        layout.addWidget(self.filter_input)
        self.ports_list = QListWidget()
        layout.addWidget(self.ports_list, 1)
        ports, linked = device_ports(network_map, key)
        chosen = {port_key(port) for port in network_map.graphed.get(key, [])}
        for port in ports:
            status = device.port_status.get(port, {})
            text = port + (f"  ({status.get('oper')})" if status.get("oper") else "")
            if port_key(port) in linked:
                text += "  - a link: always kept"
            item = QListWidgetItem(text)
            item.setData(Qt.UserRole, port)
            if port_key(port) in linked:
                item.setFlags(item.flags() & ~Qt.ItemIsEnabled)
                item.setCheckState(Qt.Checked)
            else:
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Checked if port_key(port) in chosen else Qt.Unchecked)
            self.ports_list.addItem(item)
        if not ports:
            layout.addWidget(QLabel("No ports were read on it: crawl it again first."))
        self.linked = linked
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        self.filter_input.textChanged.connect(self.filter_ports)

    def filter_ports(self, text):
        text = text.strip().lower()
        for row in range(self.ports_list.count()):
            item = self.ports_list.item(row)
            item.setHidden(bool(text) and text not in item.text().lower())

    def chosen(self):
        """The ports ticked (not counting those at the ends of links)."""
        return [self.ports_list.item(row).data(Qt.UserRole) for row in range(self.ports_list.count())
                if self.ports_list.item(row).checkState() == Qt.Checked
                and port_key(self.ports_list.item(row).data(Qt.UserRole)) not in self.linked]
