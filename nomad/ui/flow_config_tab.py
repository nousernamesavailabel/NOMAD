"""NetFlow Config page: build the Cisco IOS / IOS-XE Flexible NetFlow configuration that sends a router's flows to
NOMAD (flowconfig.py), then copy it, type it into a terminal session, or set it up over SSH on several routers at
once (each one's interfaces read from it, if chosen, and what NOMAD set up before taken out first)."""
import json
import logging

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtWidgets import QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, \
    QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QSplitter, \
    QToolButton, QVBoxLayout, QWidget

from .. import flowconfig
from ..netmap.model import ROUTER, short_port
from ..resolve import NameNotFound, is_host_name
from .common import StoppableThread, set_hint
from .name_lookup import NameResolver, looking_up
from .session_send import SessionSender
from .ssh_push import LoginRow
from .theme import accent_button, monospace_font

log = logging.getLogger(__name__)

MONITORED_COMMAND = "show running-config | include ^interface|flow monitor"
FORM_ROOM = 1.15
MIN_PREVIEW = 380


def split_items(text):
    return [item for item in text.replace(",", " ").split() if item]


class FlowPushThread(StoppableThread):
    """Sets NetFlow up on (or takes it off) each router in turn over SSH."""
    router_started = pyqtSignal(str)
    router_done = pyqtSignal(str, bool, str, str)  # Address, ok, what happened, transcript

    def __init__(self, routers, options, interfaces, every_routed, setting_up, make_pusher, parent=None):
        super().__init__(parent)
        self.routers, self.options, self.interfaces = list(routers), options, list(interfaces)
        self.every_routed, self.setting_up, self.make_pusher = every_routed, setting_up, make_pusher

    def run(self):
        pusher = self.make_pusher(lambda: self.stopping)
        try:
            for address in self.routers:
                if self.stopping:
                    break
                self.router_started.emit(address)
                try:
                    ok, message, transcript = self.one(pusher, address)
                except Exception as error:
                    log.exception("NetFlow setup on %s failed", address)
                    ok, message, transcript = False, str(error), ""
                self.router_done.emit(address, ok, message, transcript)
        finally:
            pusher.close()

    def one(self, pusher, address):
        shell = pusher.shell(address)
        if shell is None:
            return False, f"Couldn't log in: {pusher.problems.get(address, 'no reason given')}", ""
        options = self.options
        names = [options.monitor, flowconfig.monitor6(options)]
        running = shell.run(MONITORED_COMMAND)
        monitored = flowconfig.parse_monitored(running, names)
        removal = pusher.take_away(address, "\n".join(flowconfig.undo(
            flowconfig.FlowOptions(**{**options.__dict__, "write_memory": False}), monitored)))
        refused = [(line, errors) for line, errors in removal.refused
                   if not flowconfig.harmless_removal(line, errors)]
        if removal.problem and not removal.refused:
            return False, removal.problem, removal.transcript
        if not self.setting_up:
            if refused:
                line, errors = refused[0]
                return False, f"It refused {line}: {errors[0]}", removal.transcript
            if options.write_memory:
                saved, said = pusher.save_config(address)
                if not saved:
                    return False, f"Taken out, but write memory failed: {said}", removal.transcript
            taken = len(monitored)
            return True, (f"Taken out (from {taken} interface{'s' if taken != 1 else ''})." if taken else
                          "Taken out (it was on no interface)."), removal.transcript
        interfaces = self.interfaces
        if self.every_routed and not interfaces:  # Interfaces typed are the ones wanted
            interfaces = flowconfig.routed_interfaces(shell.run("show ip interface brief"),
                                                      flowconfig.configured_interfaces(running))
            if not interfaces:
                return False, "It has no interface with an IPv4 address that's up to monitor.", removal.transcript
        outcome = pusher.set_up(address, "\n".join(flowconfig.build(options, interfaces)))
        transcript = removal.transcript + "\n" + outcome.transcript
        if not outcome.ok:
            return False, outcome.problem or "It refused a line.", transcript
        shown = ", ".join(short_port(name) for name in interfaces[:6]) + (" ..." if len(interfaces) > 6 else "")
        return True, f"Set up on {shown}. Its flows reach NOMAD within a minute.", transcript


class FlowConfigTab(QWidget):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.lines = []
        self.thread = None
        self.results = {}  # Address -> (ok, message, transcript)
        self.names = NameResolver(window, self)
        self.names.changed.connect(self.update_preview)
        self.name_problems, self.names_typed = [], []
        self.init_ui()
        self.session_sender = SessionSender(self, window, self.status_label)
        self.update_preview()

    # ----------------------------------------------------------------- Layout

    def init_ui(self):
        layout = QVBoxLayout(self)
        intro = QLabel("Builds the Cisco IOS / IOS-XE Flexible NetFlow configuration that sends a router's flows to "
                       "NOMAD, for the NetFlow page. Start collecting first (NetFlow page: Collect Here or the Flow "
                       "Collector service), then set the routers up: they send the interface and application names "
                       "as they start.")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        splitter = QSplitter()
        self.splitter = splitter
        self.sized = False
        layout.addWidget(splitter, 1)

        form_widget = QWidget()
        form_layout = QVBoxLayout(form_widget)
        form_layout.addWidget(self.make_destination_group())
        form_layout.addWidget(self.make_record_group())
        form_layout.addWidget(self.make_interfaces_group())
        form_layout.addStretch(1)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setWidget(form_widget)
        scroll.setMinimumWidth(form_widget.sizeHint().width() + scroll.verticalScrollBar().sizeHint().width() + 4)
        self.form_scroll = scroll
        splitter.addWidget(scroll)

        preview = QWidget()
        preview_layout = QVBoxLayout(preview)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        show_row = QHBoxLayout()
        show_row.addWidget(QLabel("Show:"))
        self.show_combo = QComboBox()
        self.show_combo.addItem("Configuration to add", "add")
        self.show_combo.addItem("Commands to take it out again", "undo")
        show_row.addWidget(self.show_combo)
        show_row.addStretch(1)
        preview_layout.addLayout(show_row)
        self.preview = QPlainTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setFont(monospace_font())
        self.preview.setLineWrapMode(QPlainTextEdit.NoWrap)
        preview_layout.addWidget(self.preview, 1)
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        preview_layout.addWidget(self.status_label)
        buttons = QHBoxLayout()
        self.send_button = QToolButton()
        self.send_button.setText("Send to Session")
        self.send_button.setPopupMode(QToolButton.InstantPopup)
        self.send_menu = QMenu(self.send_button)
        self.send_menu.aboutToShow.connect(self.fill_send_menu)
        self.send_button.setMenu(self.send_menu)
        self.send_button.setToolTip("Type the configuration into a terminal session to the router, a line at a time.")
        self.copy_button = QPushButton("Copy")
        self.save_button = QPushButton("Save As...")
        for widget in (self.send_button, self.copy_button, self.save_button):
            buttons.addWidget(widget)
        buttons.addStretch(1)
        preview_layout.addLayout(buttons)

        ssh = QGroupBox("Over SSH, on several routers at once")
        ssh_layout = QVBoxLayout(ssh)
        routers_row = QHBoxLayout()
        self.routers_input = QLineEdit()
        self.routers_input.setPlaceholderText("Router addresses or names, such as 10.0.0.1 core-rtr2")
        self.map_button = QToolButton()
        self.map_button.setText("From the Map")
        self.map_button.setPopupMode(QToolButton.InstantPopup)
        self.map_menu = QMenu(self.map_button)
        self.map_menu.aboutToShow.connect(self.fill_map_menu)
        self.map_button.setMenu(self.map_menu)
        self.map_button.setToolTip("Add a router on the open Network Map (and the ports of its links)")
        routers_row.addWidget(QLabel("Routers:"))
        routers_row.addWidget(self.routers_input, 1)
        routers_row.addWidget(self.map_button)
        ssh_layout.addLayout(routers_row)
        self.routed_check = QCheckBox("No interfaces typed: every interface with an IPv4 address that's up, read "
                                      "from each router")
        self.routed_check.setToolTip("Used only when the Interfaces box is empty: interfaces typed are always the "
                                     "ones set up. Interfaces the router made for itself (PIM register tunnels, "
                                     "Virtual-Access) are left out.")
        self.routed_check.setChecked(True)
        ssh_layout.addWidget(self.routed_check)
        self.login_row = LoginRow(self, getattr(self.window, "session_store", None), "NetFlow Config")
        ssh_layout.addWidget(self.login_row)
        push_row = QHBoxLayout()
        self.push_button = accent_button("Set Up over SSH")
        self.push_button.setToolTip("On each router: take out what NOMAD set up before (a flow record in use can't "
                                    "be changed), then send the configuration.")
        self.remove_button = QPushButton("Take Out over SSH")
        self.stop_button = QPushButton("Stop")
        self.stop_button.setEnabled(False)
        for widget in (self.push_button, self.remove_button, self.stop_button):
            push_row.addWidget(widget)
        push_row.addStretch(1)
        ssh_layout.addLayout(push_row)
        self.result_view = QPlainTextEdit()
        self.result_view.setReadOnly(True)
        self.result_view.setMaximumHeight(120)
        self.result_view.setPlaceholderText("How each router went")
        ssh_layout.addWidget(self.result_view)
        preview_layout.addWidget(ssh)
        check = QLabel("Check it on the router with show flow monitor NOMAD-MONITOR statistics and show flow exporter "
                       "NOMAD-EXPORTER statistics.")
        check.setWordWrap(True)
        check.setEnabled(False)
        preview_layout.addWidget(check)
        splitter.addWidget(preview)
        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.show_combo.currentIndexChanged.connect(self.update_preview)
        self.copy_button.clicked.connect(self.copy)
        self.save_button.clicked.connect(self.save_as)
        self.push_button.clicked.connect(self.push)
        self.remove_button.clicked.connect(self.take_out)
        self.stop_button.clicked.connect(self.stop_push)
        self.routers_input.textChanged.connect(self.update_buttons)
        self.routed_check.toggled.connect(self.update_preview)
        for widget in form_widget.findChildren(QLineEdit):
            widget.textChanged.connect(self.update_preview)
        for widget in form_widget.findChildren(QCheckBox):
            widget.toggled.connect(self.update_preview)
        for widget in form_widget.findChildren(QComboBox):
            widget.currentIndexChanged.connect(self.update_preview)
        for widget in form_widget.findChildren(QSpinBox):
            widget.valueChanged.connect(self.update_preview)

    def make_destination_group(self):
        group = QGroupBox("Where the flows go")
        form = QFormLayout(group)
        row = QHBoxLayout()
        self.destinations_input = QLineEdit()
        self.destinations_input.setPlaceholderText("This computer, or the one running the Flow Collector service")
        self.this_computer_button = QToolButton()
        self.this_computer_button.setText("Add This Computer")
        self.this_computer_button.setPopupMode(QToolButton.InstantPopup)
        self.this_computer_menu = QMenu(self.this_computer_button)
        self.this_computer_menu.aboutToShow.connect(self.fill_address_menu)
        self.this_computer_button.setMenu(self.this_computer_menu)
        row.addWidget(self.destinations_input, 1)
        row.addWidget(self.this_computer_button)
        form.addRow("Send to:", row)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(flowconfig.DEFAULT_PORT)
        form.addRow("UDP port:", self.port_input)
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("Recommended: a loopback, such as Loopback0")
        self.source_input.setToolTip("The interface whose address the flows come from: NOMAD knows the router by "
                                     "it, so make it the address the Network Map reads it at.")
        form.addRow("From interface:", self.source_input)
        self.vrf_input = QLineEdit()
        self.vrf_input.setPlaceholderText("Only if the collector is reached through a VRF (such as Mgmt-intf)")
        form.addRow("VRF:", self.vrf_input)
        return group

    def make_record_group(self):
        group = QGroupBox("What the routers send")
        form = QFormLayout(group)
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("NetFlow v9 (every IOS and IOS-XE router)", flowconfig.V9)
        self.protocol_combo.addItem("IPFIX", flowconfig.IPFIX)
        form.addRow("Format:", self.protocol_combo)
        self.timestamps_combo = QComboBox()
        self.timestamps_combo.addItem("Router uptime (every IOS and IOS-XE router)", flowconfig.UPTIME)
        self.timestamps_combo.addItem("Clock time (IOS-XE 16 and later, Catalyst 9000)", flowconfig.ABSOLUTE)
        form.addRow("Flow times:", self.timestamps_combo)
        self.applications_check = QCheckBox("Name the applications (NBAR2: ISR 4000, ASR 1000, Catalyst 8000, "
                                            "C8000v)")
        self.applications_check.setToolTip("Without it NOMAD names applications by their ports (HTTPS, SSH...).")
        form.addRow("", self.applications_check)
        self.ipv6_check = QCheckBox("IPv6 too")
        form.addRow("", self.ipv6_check)
        sampling_row = QHBoxLayout()
        self.sampling_input = QSpinBox()
        self.sampling_input.setRange(0, 65535)
        self.sampling_input.setSpecialValueText("Every packet")
        self.sampling_input.setPrefix("1 in ")
        self.sampling_input.setToolTip("For busy links on older routers: NOMAD multiplies what's sampled back up.")
        sampling_row.addWidget(self.sampling_input)
        sampling_row.addStretch(1)
        form.addRow("Sampling:", sampling_row)
        timeouts = QHBoxLayout()
        self.active_input, self.inactive_input = QSpinBox(), QSpinBox()
        for widget, value in ((self.active_input, 60), (self.inactive_input, 15)):
            widget.setRange(1, 604800)
            widget.setValue(value)
            widget.setSuffix(" s")
        timeouts.addWidget(QLabel("Active:"))
        timeouts.addWidget(self.active_input)
        timeouts.addWidget(QLabel("Inactive:"))
        timeouts.addWidget(self.inactive_input)
        timeouts.addStretch(1)
        self.active_input.setToolTip("A flow still going is sent this often: a minute keeps the NetFlow page a "
                                     "minute behind (IOS's own is 30 minutes).")
        form.addRow("Cache timeouts:", timeouts)
        names = QHBoxLayout()
        self.record_input, self.exporter_input, self.monitor_input = QLineEdit("NOMAD-RECORD"), \
            QLineEdit("NOMAD-EXPORTER"), QLineEdit("NOMAD-MONITOR")
        for label, widget in (("Record", self.record_input), ("Exporter", self.exporter_input),
                              ("Monitor", self.monitor_input)):
            names.addWidget(QLabel(label + ":"))
            names.addWidget(widget, 1)
        form.addRow("Names:", names)
        return group

    def make_interfaces_group(self):
        group = QGroupBox("Interfaces to monitor (input)")
        form = QFormLayout(group)
        self.interfaces_input = QLineEdit()
        self.interfaces_input.setPlaceholderText("Such as Gi0/0/0, Gi0/0/1, Tunnel10")
        self.interfaces_input.setToolTip("Monitored as traffic comes in; NOMAD counts it going out of the other "
                                         "interface too, so put it on every interface traffic comes in on.")
        form.addRow("Interfaces:", self.interfaces_input)
        self.write_check = QCheckBox("Save it (write memory)")
        form.addRow("", self.write_check)
        return group

    def showEvent(self, event):
        super().showEvent(event)
        if not self.sized:
            QTimer.singleShot(0, self.size_form)

    def size_form(self):
        total = sum(self.splitter.sizes())
        if self.sized or total <= 0:
            return
        self.sized = True
        form = int(self.form_scroll.minimumWidth() * FORM_ROOM)
        form = max(self.form_scroll.minimumWidth(), min(form, total - MIN_PREVIEW))
        self.splitter.setSizes([form, total - form])

    # ----------------------------------------------------------------- The form

    def addresses(self, text):
        items = []
        for index, item in enumerate(split_items(text)):
            found = None
            try:
                found = self.names.address(item, 4, slot=("to", index))
                if found is None:
                    self.name_problems.append(looking_up(item))
            except NameNotFound as error:
                self.name_problems.append(str(error))
            except ValueError:
                pass
            if found is None:
                if is_host_name(item):
                    self.names_typed.append(item)
                items.append(item)
                continue
            items.append(found.address)
        return items

    def options(self):
        self.name_problems, self.names_typed = [], []
        return flowconfig.FlowOptions(
            destinations=self.addresses(self.destinations_input.text()), port=self.port_input.value(),
            source_interface=self.source_input.text().strip(), vrf=self.vrf_input.text().strip(),
            protocol=self.protocol_combo.currentData(), timestamps=self.timestamps_combo.currentData(),
            applications=self.applications_check.isChecked(), ipv6=self.ipv6_check.isChecked(),
            interfaces=flowconfig.split_interfaces(self.interfaces_input.text()),
            sampling=self.sampling_input.value(), active=self.active_input.value(),
            inactive=self.inactive_input.value(), record=self.record_input.text().strip(),
            exporter=self.exporter_input.text().strip(), monitor=self.monitor_input.text().strip(),
            write_memory=self.write_check.isChecked())

    def update_preview(self, *_):
        options = self.options()
        found = flowconfig.problems(options)
        if self.names_typed:
            found = list(dict.fromkeys(self.name_problems)) + [
                problem for problem in found if not any(f"'{name}'" in problem for name in self.names_typed)]
        self.problems_found = found
        if found:
            self.lines = []
            self.preview.setPlainText("")
            set_hint(self.status_label, " ".join(found[:3]) + (" ..." if len(found) > 3 else ""), "warning")
        else:
            undo = self.show_combo.currentData() == "undo"
            self.lines = flowconfig.undo(options) if undo else flowconfig.build(options)
            self.preview.setPlainText("\n".join(self.lines))
            caution = flowconfig.cautions(options)
            note = [] if options.interfaces else ["No interfaces typed: the monitor goes on none (over SSH, tick "
                                                  "every interface with an address)."]
            set_hint(self.status_label, " ".join([f"{len(self.lines)} lines, from the enable (#) prompt."] + note +
                                                 caution), "warning" if caution or note else "info")
        self.routed_check.setEnabled(not options.interfaces)
        has_lines = bool(self.lines)
        for widget in (self.send_button, self.copy_button, self.save_button):
            widget.setEnabled(has_lines)
        self.update_buttons()

    def update_buttons(self, *_):
        busy = self.thread is not None
        ready = not getattr(self, "problems_found", []) and bool(split_items(self.routers_input.text()))
        self.push_button.setEnabled(ready and not busy)
        self.remove_button.setEnabled(ready and not busy)
        self.stop_button.setEnabled(busy)

    def fill_address_menu(self):
        self.this_computer_menu.clear()
        addresses = self.local_addresses()
        for address in addresses:
            self.this_computer_menu.addAction(address, lambda address=address: self.add_destination(address))
        if not addresses:
            self.this_computer_menu.addAction("No IPv4 address on this computer").setEnabled(False)

    def local_addresses(self):
        found = []
        snapshot = getattr(self.window, "snapshot", None)
        adapters = snapshot.real_adapters() if snapshot is not None and hasattr(snapshot, "real_adapters") else []
        current = self.window.current_adapter() if hasattr(self.window, "current_adapter") else None
        for adapter in ([current] if current is not None else []) + list(adapters):
            for address in getattr(adapter, "ipv4", []) or []:
                ip = getattr(address, "ip", address)
                if not ip.is_link_local and not ip.is_loopback and str(ip) not in found:
                    found.append(str(ip))
        return found

    def add_destination(self, address):
        items = split_items(self.destinations_input.text())
        if address not in items:
            self.destinations_input.setText(" ".join(items + [address]))

    def map_routers(self):
        """The routers on the open Network Map: [(label, address, [port names of its links and addresses])]."""
        page = getattr(self.window, "netmap_tab", None)
        network_map = getattr(page, "network_map", None)
        if network_map is None:
            return []
        found = []
        for key, device in network_map.devices.items():
            if device.kind != ROUTER or not device.mgmt_ip:
                continue
            ports = [port for link in network_map.links for end, port in ((link.a, link.a_port), (link.b, link.b_port))
                     if end == key and port]
            ports += [item[2] for item in device.interfaces_l3 or [] if len(item) > 2 and item[2]]
            ports = [port for port in dict.fromkeys(ports) if not flowconfig.SKIPPED_INTERFACES.match(port)]
            found.append((device.label, device.mgmt_ip, ports))
        return sorted(found, key=lambda item: item[0].lower())

    def fill_map_menu(self):
        self.map_menu.clear()
        for label, address, ports in self.map_routers():
            self.map_menu.addAction(f"{label} ({address})",
                                    lambda address=address, ports=ports: self.use_router(address, ports))
        if self.map_menu.isEmpty():
            self.map_menu.addAction("No routers on the open Network Map").setEnabled(False)

    def use_router(self, address, ports=()):
        items = split_items(self.routers_input.text())
        if address not in items:
            self.routers_input.setText(" ".join(items + [address]))
        if ports and not self.interfaces_input.text().strip():
            self.interfaces_input.setText(", ".join(ports))

    def prefill(self, routers=(), ports=(), destination=""):
        """From the Network Map or the NetFlow page: send to destination (this computer), from these routers."""
        if destination:
            self.add_destination(destination)
        elif not self.destinations_input.text().strip():
            local = self.local_addresses()
            if local:
                self.add_destination(local[0])
        for address in routers:
            self.use_router(address)
        if ports:
            self.interfaces_input.setText(", ".join(ports))
            self.routed_check.setChecked(False)

    # ----------------------------------------------------------------- Copy, save and send

    def text(self):
        return "\n".join(self.lines) + "\n"

    def copy(self):
        QApplication.clipboard().setText(self.text())
        set_hint(self.status_label, "Copied. Paste it at the router's enable (#) prompt.", "success")

    def save_as(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save Configuration", "nomad-netflow-config.txt",
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as file:
                file.write(self.text())
        except OSError as error:
            QMessageBox.critical(self, "Save Configuration", f"Couldn't save it:\n\n{error}")
            return
        set_hint(self.status_label, f"Saved to {path}.", "success")

    def fill_send_menu(self):
        self.session_sender.fill_menu(self.send_menu, self.text)

    def send_to(self, view):
        return bool(self.lines) and self.session_sender.send_to(view, self.text())

    @property
    def waiting(self):
        return self.session_sender.waiting

    # ----------------------------------------------------------------- Over SSH

    def push(self):
        self.start_push(True)

    def take_out(self):
        routers = split_items(self.routers_input.text())
        if QMessageBox.question(self, "Take Out NetFlow", f"Take NOMAD's NetFlow off {', '.join(routers)}? Its "
                                f"monitor comes off every interface it's on, and its record, exporter and monitor "
                                f"go.") != QMessageBox.Yes:
            return
        self.start_push(False)

    def start_push(self, setting_up):
        if self.thread is not None:
            return
        routers = split_items(self.routers_input.text())
        options = self.options()
        if flowconfig.problems(options) or not routers:
            return
        every = self.routed_check.isChecked() and not options.interfaces
        if setting_up and not every and not options.interfaces:
            set_hint(self.status_label, "Type the interfaces to monitor, or tick every interface with an address.",
                     "warning")
            return
        logins = self.login_row.logins(self.status_label, [(router, ()) for router in routers])
        if logins is None:
            return
        self.result_view.clear()
        self.thread = FlowPushThread(routers, options, options.interfaces, every, setting_up,
                                     self.login_row.pusher_maker(logins), self)
        self.thread.router_started.connect(self.on_router_started)
        self.thread.router_done.connect(self.on_router_done)
        self.thread.finished.connect(self.on_push_finished)
        self.setting_up = setting_up
        self.thread.start()
        self.update_buttons()
        set_hint(self.status_label, ("Setting NetFlow up" if setting_up else "Taking NetFlow out") +
                 f" on {len(routers)} router{'s' if len(routers) != 1 else ''}...", "info")

    def stop_push(self):
        if self.thread is not None:
            self.thread.stop()

    def on_router_started(self, address):
        self.result_view.appendPlainText(f"{address}: logging in...")

    def on_router_done(self, address, ok, message, transcript):
        self.results[address] = (ok, message, transcript)
        self.result_view.appendPlainText(f"{address}: {'OK' if ok else 'FAILED'}. {message}")
        if not ok and transcript:
            log.info("NetFlow config on %s:\n%s", address, transcript[-4000:])

    def on_push_finished(self):
        self.thread = None
        failed = [address for address, (ok, _, _) in self.results.items() if not ok]
        if failed:
            set_hint(self.status_label, f"{len(failed)} router{'s' if len(failed) != 1 else ''} failed: "
                                        f"{', '.join(failed)}. What they said is in View Log.", "error")
        elif self.setting_up:
            set_hint(self.status_label, "Done. The flows show on the NetFlow page within a minute.", "success")
        else:
            set_hint(self.status_label, "Taken out.", "success")
        self.results = {}
        self.update_buttons()

    # ----------------------------------------------------------------- Page interface

    def focus_find(self):
        self.destinations_input.setFocus()
        self.destinations_input.selectAll()

    def save_settings(self, settings):
        options = self.options()
        settings.setValue("flowconfig/form", json.dumps({
            "destinations": self.destinations_input.text(), "port": options.port,
            "source": self.source_input.text(), "vrf": self.vrf_input.text(), "protocol": options.protocol,
            "timestamps": options.timestamps, "applications": options.applications, "ipv6": options.ipv6,
            "sampling": options.sampling, "active": options.active, "inactive": options.inactive,
            "record": self.record_input.text(), "exporter": self.exporter_input.text(),
            "monitor": self.monitor_input.text(), "interfaces": self.interfaces_input.text(),
            "routed": self.routed_check.isChecked(), "write": options.write_memory,
            "routers": self.routers_input.text()}))
        self.login_row.save_settings(settings, "flowconfig")

    def restore_settings(self, settings):
        try:
            form = json.loads(settings.value("flowconfig/form", "", str) or "{}")
        except ValueError:
            form = {}
        for key, widget, default in (("destinations", self.destinations_input, ""), ("source", self.source_input, ""),
                                     ("vrf", self.vrf_input, ""), ("record", self.record_input, "NOMAD-RECORD"),
                                     ("exporter", self.exporter_input, "NOMAD-EXPORTER"),
                                     ("monitor", self.monitor_input, "NOMAD-MONITOR"),
                                     ("interfaces", self.interfaces_input, ""), ("routers", self.routers_input, "")):
            widget.setText(str(form.get(key, default)))
        self.port_input.setValue(int(form.get("port", flowconfig.DEFAULT_PORT)))
        self.protocol_combo.setCurrentIndex(max(0, self.protocol_combo.findData(form.get("protocol", flowconfig.V9))))
        self.timestamps_combo.setCurrentIndex(max(0, self.timestamps_combo.findData(
            form.get("timestamps", flowconfig.UPTIME))))
        self.applications_check.setChecked(bool(form.get("applications", False)))
        self.ipv6_check.setChecked(bool(form.get("ipv6", False)))
        self.sampling_input.setValue(int(form.get("sampling", 0)))
        self.active_input.setValue(int(form.get("active", 60)))
        self.inactive_input.setValue(int(form.get("inactive", 15)))
        self.routed_check.setChecked(bool(form.get("routed", True)))
        self.write_check.setChecked(bool(form.get("write", False)))
        self.login_row.restore_settings(settings, "flowconfig")
        self.update_preview()

    def shutdown(self):
        self.session_sender.stop_waiting()
        if self.thread is not None:
            from .common import release_thread
            self.thread.stop()
            release_thread(self.thread, 3000)
            self.thread = None
