"""Searchable keyboard guide, grouped by workflow rather than one long message box."""
from PyQt5.QtCore import QRect, QSize, Qt
from PyQt5.QtGui import QFontMetrics, QKeySequence
from PyQt5.QtWidgets import QAbstractItemView, QDialog, QDialogButtonBox, QHeaderView, QLabel, QLineEdit, \
    QShortcut, QTreeWidget, QTreeWidgetItem, QVBoxLayout


RUN_TOOLS = "Ping, Traceroute, Sweep, Ports, MTU, Latency, iperf, SNMP Walk, DNS Lookup, DNS Servers, Web Check, Packet Capture, DHCP Servers, Switch Port, MAC Finder (Locate Now)"

SHORTCUT_SECTIONS = [
    ("Everyday actions", [
        ("Shift+Enter", "Start the current tool", "Diagnostics, discovery and Packet Capture"),
        ("Shift+Esc", "Stop the current tool; capture stops and saves", "Diagnostics, discovery and capture tools with a Stop button"),
        ("Alt+A", "Focus the adapter picker (arrows select)", "Main window; leaves focus mode if needed"),
        ("Ctrl+F", "Focus the page's main input, search or filter", "See Find targets below"),
        ("F1", "Open this keyboard guide", "Main window and popped-out Terminal/SCP windows"),
        ("F5", "Refresh network settings", "Main window; SCP file lists use F5 to copy"),
        ("Ctrl+R", "Run a diagnostics report", "Main window; SCP file lists use Ctrl+R to refresh"),
    ]),
    ("Navigation and view", [
        ("Ctrl+K", "Find a tool", "Main window"),
        ("Ctrl+B", "Keep the tool drawer open or close it", "Main window"),
        ("Ctrl+Tab / Ctrl+Shift+Tab", "Next / previous tool", "Main window; Ctrl+Tab in a pop-out cycles sessions"),
        ("Ctrl+PageDown / Ctrl+PageUp", "Next / previous tool", "Main window, outside terminal text"),
        ("F11", "Toggle focus mode", "Main window; toggles full screen in a pop-out"),
        ("Ctrl+= / Ctrl+- / Ctrl+0", "Larger / smaller / default text size", "Main window, outside terminal text"),
        ("Tab / Shift+Tab", "Next / previous input or control", "Forms; plain Tab in terminal text goes to the remote host"),
    ]),
    ("Saved sessions and terminal windows", [
        ("Ctrl+N", "Create a saved session in the selected folder", "Terminal, SCP, RDP"),
        ("Ctrl+Shift+N", "Create a folder under the selected folder", "Terminal, SCP, RDP"),
        ("Enter", "Open the selected saved session", "Session lists"),
        ("Ctrl+W", "Close the current session (Enter confirms Yes)", "SCP; in Terminal, Ctrl+W goes to the remote host"),
        ("Alt+Left / Alt+Right", "Previous / next session (wraps around)", "Terminal and SCP"),
        ("Ctrl+Shift+Enter", "Pop out this session; move it back from a pop-out", "Terminal and SCP"),
        ("Ctrl+1 through Ctrl+9", "Send the corresponding saved command", "Terminal text, including when the Buttons bar is hidden"),
        ("Hold Ctrl", "Show number overlays above visible command buttons, and S / Shift+S above Log Session / Save Config", "Terminal; release Ctrl to hide"),
        ("Ctrl+Shift+F", "Find in terminal output", "Terminal text"),
        ("Ctrl+Shift+C / Ctrl+Shift+V", "Copy selection / paste", "Terminal text"),
        ("Shift+PageUp / Shift+PageDown", "Scroll terminal output", "Terminal text"),
        ("Ctrl+S", "Log Session: start logging to a file, or stop logging", "Terminal session; replaces the shell's Ctrl+S (XOFF)"),
        ("Ctrl+Shift+S", "Save Config: save the running configuration (cancels one being saved)", "Connected terminal session"),
    ]),
    ("SCP files", [
        ("Ctrl+L", "Focus and select this pane's folder path", "SCP file pane; Enter opens the typed folder"),
        ("F5", "Copy selected files to the other side", "SCP file list"),
        ("F4", "Edit selected file", "SCP file list"),
        ("F2", "Rename selected file", "SCP file list"),
        ("F7", "Create a folder", "SCP file list"),
        ("F8 / Delete", "Delete selected files", "SCP file list"),
        ("Alt+Enter", "Show file properties", "SCP file list"),
        ("Ctrl+R", "Refresh this folder", "SCP file list"),
        ("Ctrl+Alt+H", "Show / hide hidden files", "SCP file list"),
        ("Ctrl+Shift+F", "Filter file names", "SCP file list"),
        ("Backspace", "Up one folder", "SCP file list"),
        ("Alt+Up", "Back to the previous folder", "SCP file list; Alt+Left now switches sessions"),
    ]),
    ("Find targets — Ctrl+F", [
        ("Ctrl+F", "Host / device", "Ping, Traceroute, Ports, MTU, SNMP Walk"),
        ("Ctrl+F", "Subnet", "Sweep, Subnet Calculator"),
        ("Ctrl+F", "Name", "Latency, DNS Lookup"),
        ("Ctrl+F", "Names to test", "DNS Servers"),
        ("Ctrl+F", "Web address", "Web Check"),
        ("Ctrl+F", "Server address; listening port in server mode", "iperf"),
        ("Ctrl+F", "Session filter; reveals a hidden session list", "Terminal, SCP, RDP"),
        ("Ctrl+F", "MAC address", "Wake-on-LAN"),
        ("Ctrl+F", "Address / subnet filter", "Packet Capture"),
        ("Ctrl+F", "Community string, or its enabling toggle", "SNMP Config"),
        ("Ctrl+F", "Hosting folder in server section; server address otherwise", "TFTP"),
        ("Ctrl+F", "Find an adapter by name, description, IP or MAC", "Interfaces; Enter selects the match"),
        ("Ctrl+F", "Search command output", "Network Reset; Enter: next, Shift+Enter: previous, Esc: close search"),
        ("Ctrl+F", "Filter discovered switch details", "Switch Port"),
        ("Ctrl+F", "MAC address, IP address or name to find; the list in List mode", "MAC Finder"),
        ("Ctrl+F", "Filter devices", "Ansible Inventory"),
        ("Ctrl+F", "Filter server addresses", "DHCP Servers"),
        ("Ctrl+F", "Page search / filter", "Routing Table, ARP, Connections, Syslog, IP Addresses, Network Map, VLANs, Subnet Placement"),
    ]),
    ("Context and exceptions", [
        ("Shift+Enter", "Add/update a target when editing its name or host; otherwise start monitoring", "Latency"),
        ("Shift+Enter", "Start a client test or start the server, according to the selected mode", "iperf"),
        ("Shift+Enter / Shift+Esc", "Run / Stop shortcuts activate only on supported tool pages", "Elsewhere, search navigation, multiline editing and terminal keys keep their normal behavior"),
        ("Terminal controls", "Other shell keys keep going to the remote host", "Ctrl+C, Ctrl+R, Ctrl+L, Ctrl+B, and plain Esc remain terminal controls"),
        ("Ctrl+L", "Changes a folder only in SCP; clears the screen in a shell", "Terminal Ctrl+L remains unchanged"),
        ("Ctrl+Shift+N", "Saved-session folder, separate from F7's remote/local file folder", "SCP"),
    ]),
]


class ShortcutGuide(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Keyboard Guide")
        self.resize(1000, 700)
        self.setMinimumSize(760, 480)
        layout = QVBoxLayout(self)
        self.context_label = QLabel()
        self.context_label.setWordWrap(True)
        layout.addWidget(self.context_label)
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search by key, action or tool — e.g. Shift+Enter, folder, Ping")
        self.search_input.setClearButtonEnabled(True)
        layout.addWidget(self.search_input)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Shortcut", "Action", "Where it works"])
        self.tree.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tree.setAlternatingRowColors(True)
        self.tree.setWordWrap(True)
        self.tree.setTextElideMode(Qt.ElideNone)
        self.tree.setColumnWidth(0, 215)
        self.tree.setColumnWidth(1, 345)
        self.tree.header().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.tree, 1)
        self.groups = []
        for title, rows in SHORTCUT_SECTIONS:
            group = QTreeWidgetItem(self.tree, [title])
            group.setFirstColumnSpanned(True)
            font = group.font(0)
            font.setBold(True)
            group.setFont(0, font)
            group.setExpanded(True)
            for row in rows:
                item = QTreeWidgetItem(group, list(row))
                if title == "Everyday actions" and row[0] in ("Shift+Enter", "Shift+Esc"):
                    item.setData(0, Qt.UserRole, RUN_TOOLS)
                for column, text in enumerate(row):
                    item.setToolTip(column, text)
            self.groups.append(group)
        self.empty_label = QLabel("No shortcuts match. Try a tool name or action.")
        self.empty_label.hide()
        layout.addWidget(self.empty_label)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.close)
        layout.addWidget(buttons)
        self.search_input.textChanged.connect(self.apply_filter)
        QShortcut(QKeySequence("Ctrl+F"), self).activated.connect(self.focus_search)
        self.tree.header().sectionResized.connect(self.fit_rows)
        self.fit_rows()

    def fit_rows(self):
        metrics = QFontMetrics(self.tree.font())
        for group in self.groups:
            for index in range(group.childCount()):
                item = group.child(index)
                height = metrics.height()
                for column in range(3):
                    width = max(40, self.tree.columnWidth(column) - (50 if column == 0 else 12))
                    rect = metrics.boundingRect(QRect(0, 0, width, 10000), Qt.TextWordWrap, item.text(column))
                    height = max(height, rect.height())
                item.setSizeHint(0, QSize(0, height + 8))

    def show_for_page(self, title):
        self.context_label.setText(f"Current tool: {title}. Search to narrow the guide, or browse the workflow groups below.")
        self.search_input.clear()
        self.show()
        self.raise_()
        self.activateWindow()
        self.focus_search()

    def focus_search(self):
        self.search_input.setFocus()
        self.search_input.selectAll()

    def apply_filter(self):
        words = self.search_input.text().lower().split()
        visible = 0
        for group in self.groups:
            matches = 0
            for index in range(group.childCount()):
                item = group.child(index)
                text = " ".join([group.text(0), *(item.text(column) for column in range(3)),
                                 item.data(0, Qt.UserRole) or ""]).lower()
                match = all(word in text for word in words)
                item.setHidden(not match)
                matches += int(match)
            group.setHidden(matches == 0)
            if words:
                group.setExpanded(True)
            visible += matches
        self.empty_label.setVisible(visible == 0)
