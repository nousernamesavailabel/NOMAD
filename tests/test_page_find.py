"""Ctrl+F reaches page inputs even from widgets that handle their own shortcuts."""
import ipaddress
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QAction, QApplication, QComboBox, QDialog, QInputDialog, QMainWindow, QMessageBox, QShortcut, QPlainTextEdit, QStackedWidget, QWidget

from nomad.snapshot import Adapter, NetworkSnapshot
from nomad.dhcp import Offer
from nomad.lldp import Neighbor
from nomad.terminal.commands import CommandStore
from nomad.terminal.highlight import HighlightStore
from nomad.terminal.sessions import RDP, SSH, Session, SessionStore
from nomad.ui.file_panes import FileList, FilePane
from nomad.ui.iperf_tab import IperfTab
from nomad.ui.latency_tab import LatencyTab
from nomad.ui.main_window import MainWindow
from nomad.ui.mtu_tab import MtuTab
from nomad.ui.ping_tab import PingTab
from nomad.ui.ports_tab import PortsTab
from nomad.ui.scp_tab import ScpTab
from nomad.ui.sweep_tab import SweepTab
from nomad.ui.terminal_tab import TerminalTab
from nomad.ui.adapter_tab import AdapterTab, AdapterSearchDialog
from nomad.ui import adapter_tab
from nomad.ui.capture_tab import CaptureTab
from nomad.ui.dhcp_tab import DhcpTab
from nomad.ui.dns_servers_tab import DnsServersTab
from nomad.ui.lookup_tab import LookupTab
from nomad.ui.netreset_tab import NetworkResetTab
from nomad.ui.snmp_config_tab import SnmpConfigTab
from nomad.ui.snmp_tab import SnmpTab
from nomad.ui.subnet_tab import SubnetTab
from nomad.ui.switch_tab import SwitchTab
from nomad.ui.mac_finder_tab import MacFinderTab
from nomad.ui.inventory_tab import InventoryTab
from nomad.ui.tftp_tab import TftpTab, cisco_tips_html
from nomad.ui.traceroute_tab import TracerouteTab
from nomad.ui.wake_tab import WakeTab
from nomad.ui.web_check_tab import WebCheckTab
from nomad.ui.rdp_tab import RdpTab
from nomad.ui.shortcut_guide import ShortcutGuide
from nomad.ui.workflow_shortcuts import install_workflow_shortcuts


class Window(QMainWindow):
    snapshot_changed = pyqtSignal(object)
    adapter_changed = pyqtSignal(object)
    focus_mode = False

    def __init__(self):
        super().__init__()
        self.snapshot = NetworkSnapshot()
        self.navigator = QStackedWidget()
        self.setCentralWidget(self.navigator)
        self.adapter_combo = QComboBox(self)
        self.help_requests = 0
        action = QAction(self)
        action.setShortcut("Ctrl+F")
        action.triggered.connect(lambda: MainWindow.focus_find(self))
        self.addAction(action)
        install_workflow_shortcuts(self)

    def current_adapter(self):
        return None

    def clear_busy(self, key):
        pass

    def show_shortcuts(self):
        self.help_requests += 1

    def set_focus_mode(self, visible):
        self.focus_mode = visible


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def window(app):
    window = Window()
    window.resize(1200, 900)
    window.show()
    window.activateWindow()
    app.processEvents()
    yield window
    for index in range(window.navigator.count()):
        window.navigator.widget(index).shutdown()
    window.close()
    window.deleteLater()
    app.processEvents()


def press_find(window, page, source, target):
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    target.setText("existing value")
    window.activateWindow()
    QApplication.processEvents()
    source.setFocus()
    QApplication.processEvents()
    assert QApplication.focusWidget() is source
    QTest.keyClick(source, Qt.Key_F, Qt.ControlModifier)
    assert QApplication.focusWidget() is target
    assert target.selectedText() == "existing value"


@pytest.mark.parametrize("page_type,field", [
    (PingTab, "host_input"), (SweepTab, "subnet_input"), (PortsTab, "host_input"),
    (LatencyTab, "name_input"), (MtuTab, "host_input"), (IperfTab, "host_input"),
    (TracerouteTab, "host_input"), (LookupTab, "name_input"), (DnsServersTab, "names_input"),
    (WebCheckTab, "url_input"), (SnmpTab, "host_input"), (SubnetTab, "subnet_input"),
    (WakeTab, "wake_mac_input"), (CaptureTab, "address_input"), (SnmpConfigTab, "community_input"),
    (SwitchTab, "filter_input"), (MacFinderTab, "search_input"), (DhcpTab, "filter_input"),
    (NetworkResetTab, "find_input"), (InventoryTab, "filter_input"),
])
def test_ctrl_f_focuses_diagnostic_input(window, page_type, field):
    page = page_type(window)
    press_find(window, page, page, getattr(page, field))


def test_iperf_server_mode_focuses_visible_port(window):
    page = IperfTab(window)
    page.server_radio.setChecked(True)
    window.navigator.addWidget(page)
    page.server_port_input.setText("5201")
    page.output.setFocus()
    QApplication.processEvents()
    QTest.keyClick(page.output, Qt.Key_F, Qt.ControlModifier)
    assert page.server_radio.isChecked()
    assert QApplication.focusWidget() is page.server_port_input
    assert page.server_port_input.selectedText() == "5201"


@pytest.mark.parametrize("kind", ["terminal", "scp"])
@pytest.mark.parametrize("hidden", [False, True])
def test_ctrl_f_from_session_content_reveals_session_filter(window, tmp_path, kind, hidden):
    store = SessionStore(str(tmp_path / "sessions.json"))
    if kind == "terminal":
        page = TerminalTab(window, store, HighlightStore(str(tmp_path / "highlights.json")),
                           CommandStore(str(tmp_path / "commands.json")))
        view = page.make_view(Session("test", SSH, "localhost"))
        page.tabs.add_view(view)
        page.show_page(1)
        source = view.view
        sent = []
        source.key_input.connect(sent.append)
    else:
        page = ScpTab(window, store)
        source = FileList("local", "test", page.stack)
        page.stack.addWidget(source)
        page.stack.setCurrentWidget(source)
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    if hidden:
        page.set_manager_visible(False)
    press_find(window, page, source, page.manager.filter_input)
    assert page.manager.isVisible()
    assert page.splitter.sizes()[0] > 0
    if kind == "terminal":
        assert sent == []


def test_scp_file_filter_uses_ctrl_shift_f(window):
    listing = FileList("local", "test", window)
    window.setCentralWidget(listing)
    commands = []
    listing.command.connect(commands.append)
    listing.setFocus()
    QApplication.processEvents()
    QTest.keyClick(listing, Qt.Key_F, Qt.ControlModifier | Qt.ShiftModifier)
    assert commands == ["filter"]


@pytest.mark.parametrize("section", ["server", "client"])
def test_tftp_find_stays_in_active_section(window, section):
    page = TftpTab(window)
    source = page.port_input if section == "server" else page.remote_input
    target = page.folder_input if section == "server" else page.client_host
    press_find(window, page, source, target)


def test_cisco_tips_fill_in_this_server_and_a_served_image(window, tmp_path):
    page = TftpTab(window)
    (tmp_path / "notes.txt").write_text("x")
    (tmp_path / "c9300-universalk9.bin").write_bytes(b"x")
    page.folder_input.setText(str(tmp_path))
    page.address_combo.addItem("10.1.1.5", "10.1.1.5")
    page.address_combo.setCurrentIndex(page.address_combo.count() - 1)
    assert page.tips_file_name() == "c9300-universalk9.bin"
    assert page.tips_server_address() == "10.1.1.5"
    text = cisco_tips_html(page.tips_server_address(), page.tips_file_name())
    assert "ip tftp blocksize 8192" in text and "ip scp server enable" in text
    assert "copy tftp://10.1.1.5/c9300-universalk9.bin flash:" in text
    page.folder_input.setText(str(tmp_path / "missing"))
    assert page.tips_file_name() == "image.bin"
    assert "tftp://&lt;this computer&gt;/" in cisco_tips_html("<this computer>", "image.bin")


def test_reset_output_search_wraps_and_reports_missing_text(window):
    page = NetworkResetTab(window)
    window.navigator.addWidget(page)
    page.output.setPlainText("first error\nsecond error\n")
    page.focus_find()
    page.find_input.setText("error")
    first = page.output.textCursor().selectionStart()
    QTest.keyClick(page.find_input, Qt.Key_Return)
    second = page.output.textCursor().selectionStart()
    assert second > first
    QTest.keyClick(page.find_input, Qt.Key_Return)
    assert page.output.textCursor().selectionStart() == first
    QTest.keyClick(page.find_input, Qt.Key_Return, Qt.ShiftModifier)
    assert page.output.textCursor().selectionStart() == second
    page.find_input.setText("missing")
    assert page.find_status.text() == "No matches"
    assert page.output.toPlainText() == "first error\nsecond error\n"
    QTest.keyClick(page.find_input, Qt.Key_Escape)
    assert not page.find_bar.isVisible()
    assert QApplication.focusWidget() is page.output


def test_switch_filter_matches_details_and_new_results(window):
    page = SwitchTab(window)
    window.navigator.addWidget(page)
    page.add_neighbor(Neighbor(protocol="LLDP", source_mac="aa", system_name="Core", port_id="Gi1/0/1"))
    page.add_neighbor(Neighbor(protocol="LLDP", source_mac="bb", system_name="Access", description="line one\nHQ floor 2"))
    page.filter_input.setText("hq floor")
    assert page.tree.topLevelItem(0).isHidden()
    assert not page.tree.topLevelItem(1).isHidden()
    page.add_neighbor(Neighbor(protocol="LLDP", source_mac="cc", system_name="Other"))
    assert page.tree.topLevelItem(2).isHidden()
    page.filter_input.clear()
    assert all(not page.tree.topLevelItem(index).isHidden() for index in range(3))


def test_dhcp_filter_keeps_details_in_sync_and_filters_new_offers(window):
    page = DhcpTab(window)
    window.navigator.addWidget(page)
    for server in ("10.0.0.1", "10.0.0.2"):
        page.add_offer(Offer(server, server, "10.0.0.100"))
    page.filter_input.setText("10.0.0.2")
    assert page.table.isRowHidden(0)
    assert page.selected_offer().server == "10.0.0.2"
    page.add_offer(Offer("10.0.0.3", "10.0.0.3", "10.0.0.100"))
    assert page.table.isRowHidden(2)
    page.filter_input.setText("missing")
    assert page.selected_offer() is None
    assert page.details.rowCount() == 0
    page.filter_input.clear()
    assert all(not page.table.isRowHidden(row) for row in range(3))


def test_snmp_config_disabled_community_focuses_toggle_without_changing_config(window):
    page = SnmpConfigTab(window)
    window.navigator.addWidget(page)
    page.community_check.setChecked(False)
    page.focus_find()
    assert QApplication.focusWidget() is page.community_check
    assert not page.community_check.isChecked()


def test_adapter_search_filters_addresses_and_accepts_with_enter(window):
    window.adapter_combo = QComboBox(window)
    for index, name in (("1", "Ethernet"), ("2", "Wi-Fi")):
        window.adapter_combo.addItem(name, index)
        window.snapshot.adapters[index] = Adapter(index, name, mac=f"00-00-00-00-00-0{index}",
                                                   ipv4=[ipaddress.IPv4Interface(f"10.0.{index}.2/24")])
    dialog = AdapterSearchDialog(window)
    dialog.show()
    dialog.activateWindow()
    QApplication.processEvents()
    dialog.search_input.setText("10.0.2")
    assert dialog.results.item(0).isHidden()
    assert dialog.results.currentItem().data(Qt.UserRole) == "2"
    dialog.search_input.setText("missing")
    assert not dialog.choose_button.isEnabled()
    QTest.keyClick(dialog.search_input, Qt.Key_Return)
    assert dialog.isVisible()
    dialog.search_input.setText("wi-fi")
    QTest.keyClick(dialog.search_input, Qt.Key_Return)
    assert dialog.result() == QDialog.Accepted
    dialog.deleteLater()


def test_interfaces_ctrl_f_selects_matching_adapter(window, monkeypatch):
    window.adapter_combo = QComboBox(window)
    window.profile_store = SimpleNamespace(sorted=lambda: [], get=lambda name: None, profiles={})
    window.flush_dns = lambda: None
    for index, name in (("1", "Ethernet"), ("2", "Wi-Fi")):
        window.adapter_combo.addItem(name, index)
        window.snapshot.adapters[index] = Adapter(index, name)
    page = AdapterTab(window)
    window.navigator.addWidget(page)

    class SearchDialog(AdapterSearchDialog):
        def exec_(self):
            def choose():
                self.search_input.setText("wi-fi")
                QTest.keyClick(self.search_input, Qt.Key_Return)
            QTimer.singleShot(0, choose)
            return super().exec_()

    monkeypatch.setattr(adapter_tab, "AdapterSearchDialog", SearchDialog)
    page.setFocus()
    QApplication.processEvents()
    QTest.keyClick(page, Qt.Key_F, Qt.ControlModifier)
    assert window.adapter_combo.currentData() == "2"


@pytest.mark.parametrize("kind", ["terminal", "scp", "rdp"])
def test_ctrl_n_creates_saved_session_in_selected_folder(window, tmp_path, monkeypatch, kind):
    path = str(tmp_path / "sessions.json")
    store = SessionStore(path)
    if kind == "terminal":
        page = TerminalTab(window, store, HighlightStore(str(tmp_path / "highlights.json")),
                           CommandStore(str(tmp_path / "commands.json")))
        view = page.make_view(Session("open", SSH, "localhost"))
        page.tabs.add_view(view)
        page.show_page(1)
        source = view.view
        sent = []
        source.key_input.connect(sent.append)
        page.set_manager_visible(False)
    elif kind == "scp":
        page = ScpTab(window, store)
        source = FileList("local", "test", page.stack)
        page.stack.addWidget(source)
        page.stack.setCurrentWidget(source)
        page.set_manager_visible(False)
    else:
        page = RdpTab(window, store)
        source = page.manager.tree
    created = []

    class Dialog:
        def __init__(self, parent, session, folders, title, store):
            self.session = session
            session.name = "New saved session"
            session.host = "server.example.com"
            created.append(session)

        def exec_(self):
            return QDialog.Accepted

    monkeypatch.setattr(page.manager, "dialog_class", Dialog)
    monkeypatch.setattr(page.manager, "selected_folder", lambda: "HQ")
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    window.activateWindow()
    QApplication.processEvents()
    source.setFocus()
    QTest.keyClick(source, Qt.Key_N, Qt.ControlModifier)
    assert len(created) == 1
    session = created[0]
    assert session.folder == "HQ"
    assert session.protocol == (RDP if kind == "rdp" else SSH)
    assert store.get(session.id).name == "New saved session"
    assert SessionStore(path).get(session.id).host == "server.example.com"
    if kind == "terminal":
        assert sent == []


@pytest.mark.parametrize("page_type,start,stop", [
    (PingTab, "start_button", "stop_button"), (TracerouteTab, "start_button", "stop_button"),
    (SweepTab, "start_button", "stop_button"), (PortsTab, "start_button", "stop_button"),
    (MtuTab, "run_button", "stop_button"), (LatencyTab, "start_button", "stop_button"),
    (IperfTab, "start_button", "stop_button"), (SnmpTab, "walk_button", "stop_button"),
    (DnsServersTab, "dns_start_button", "dns_stop_button"), (LookupTab, "lookup_button", None),
    (WebCheckTab, "web_button", None), (CaptureTab, "start_button", "stop_button"),
    (DhcpTab, "start_button", "stop_button"), (SwitchTab, "start_button", "stop_button"),
    (MacFinderTab, "locate_button", "stop_button"),
])
def test_run_and_stop_use_current_tools_enabled_buttons(window, page_type, start, stop):
    page = page_type(window)
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    page.setFocus()
    QApplication.processEvents()
    events = []
    start_button = getattr(page, start)
    start_button.clicked.disconnect()
    start_button.clicked.connect(lambda: events.append("start"))
    start_button.setEnabled(True)
    for key in (Qt.Key_Return, Qt.Key_Enter):
        QTest.keyClick(page, key, Qt.ShiftModifier)
    assert events == ["start", "start"]
    start_button.setEnabled(False)
    QTest.keyClick(page, Qt.Key_Return, Qt.ShiftModifier)
    assert events == ["start", "start"]
    if stop:
        stop_button = getattr(page, stop)
        stop_button.clicked.disconnect()
        stop_button.clicked.connect(lambda: events.append("stop"))
        stop_button.setEnabled(True)
        QTest.keyClick(page, Qt.Key_Escape, Qt.ShiftModifier)
        QTest.keyClick(page, Qt.Key_Escape, Qt.ShiftModifier)
        assert events[-2:] == ["stop", "stop"]
        stop_button.setEnabled(False)
        QTest.keyClick(page, Qt.Key_Escape, Qt.ShiftModifier)
        assert len(events) == 4


def test_run_uses_latency_edit_target_and_iperf_server_mode(window):
    latency = LatencyTab(window)
    window.navigator.addWidget(latency)
    actions = []
    latency.add_button.clicked.disconnect()
    latency.add_button.clicked.connect(lambda: actions.append("target"))
    latency.add_button.setEnabled(True)
    latency.host_input.setFocus()
    QApplication.processEvents()
    QTest.keyClick(latency.host_input, Qt.Key_Return, Qt.ShiftModifier)
    assert actions == ["target"]
    iperf = IperfTab(window)
    window.navigator.addWidget(iperf)
    window.navigator.setCurrentWidget(iperf)
    iperf.server_radio.setChecked(True)
    iperf.start_server_button.clicked.disconnect()
    iperf.stop_server_button.clicked.disconnect()
    iperf.start_server_button.clicked.connect(lambda: actions.append("server start"))
    iperf.stop_server_button.clicked.connect(lambda: actions.append("server stop"))
    iperf.start_server_button.setEnabled(True)
    iperf.stop_server_button.setEnabled(True)
    iperf.setFocus()
    QApplication.processEvents()
    QTest.keyClick(iperf, Qt.Key_Return, Qt.ShiftModifier)
    QTest.keyClick(iperf, Qt.Key_Escape, Qt.ShiftModifier)
    assert actions == ["target", "server start", "server stop"]


def test_adapter_and_help_shortcuts(window):
    page = PingTab(window)
    window.navigator.addWidget(page)
    window.focus_mode = True
    page.setFocus()
    QApplication.processEvents()
    QTest.keyClick(page, Qt.Key_A, Qt.AltModifier)
    assert not window.focus_mode
    assert QApplication.focusWidget() is window.adapter_combo
    QTest.keyClick(window.adapter_combo, Qt.Key_F1)
    assert window.help_requests == 1


@pytest.mark.parametrize("source_name", ["list", "filter_input", "path_input"])
def test_scp_ctrl_l_focuses_current_panes_path(window, source_name):
    page = ScpTab(window, SessionStore())
    pane = FilePane("local", "test", page.stack)
    page.stack.addWidget(pane)
    page.stack.setCurrentWidget(pane)
    window.navigator.addWidget(page)
    pane.path_input.setText("C:/folder")
    pane.filter_input.show()
    source = getattr(pane, source_name)
    source.setFocus()
    QApplication.processEvents()
    QTest.keyClick(source, Qt.Key_L, Qt.ControlModifier)
    assert QApplication.focusWidget() is pane.path_input
    assert pane.path_input.selectedText() == "C:/folder"


def test_scp_ctrl_w_closes_the_current_session(window, monkeypatch):
    page = ScpTab(window, SessionStore())
    window.navigator.addWidget(page)
    view = page.make_view(Session(name="files", protocol=SSH, host="files"))
    window.navigator.setCurrentWidget(page)
    page.show_page(1)
    page.tabs.add_view(view)
    view.state = "Connected"
    asked = []
    def confirm(*args):
        asked.append(args[-1])
        return args[-1]
    monkeypatch.setattr(QMessageBox, "question", confirm)
    view.local.list.setFocus()
    QApplication.processEvents()
    QTest.keyClick(view.local.list, Qt.Key_W, Qt.ControlModifier)
    assert asked == [QMessageBox.Yes]
    assert page.tabs.count() == 0


def test_terminal_has_no_ctrl_w_shortcut(window, tmp_path):
    page = TerminalTab(window, SessionStore(str(tmp_path / "sessions.json")),
                       HighlightStore(str(tmp_path / "highlights.json")), CommandStore(str(tmp_path / "commands.json")))
    keys = [shortcut.key().toString() for shortcut in page.tabs.findChildren(QShortcut)]
    assert "Ctrl+W" not in keys
    page.shutdown()


def test_guide_searches_keys_tools_and_actions(window, tmp_path):
    guide = ShortcutGuide(window)
    guide.show_for_page("Ping")
    QApplication.processEvents()
    guide.search_input.setText("folder")
    visible = [group.child(index) for group in guide.groups for index in range(group.childCount())
               if not group.isHidden() and not group.child(index).isHidden()]
    assert visible
    assert all("folder" in " ".join(item.text(column) for column in range(3)).lower() for item in visible)
    guide.search_input.setText("Shift+Enter")
    assert not guide.groups[0].isHidden()
    guide.search_input.setText("no such shortcut")
    assert guide.empty_label.isVisible()
    QTest.keyClick(guide.search_input, Qt.Key_F, Qt.ControlModifier)
    assert guide.search_input.selectedText() == "no such shortcut"
    guide.search_input.clear()
    QApplication.processEvents()
    guide.grab().save(str(tmp_path / "keyboard-guide.png"))
    guide.close()


@pytest.mark.parametrize("kind", ["terminal", "scp", "rdp"])
def test_ctrl_shift_n_creates_saved_session_folder(window, tmp_path, monkeypatch, kind):
    store = SessionStore(str(tmp_path / "sessions.json"))
    if kind == "terminal":
        page = TerminalTab(window, store, HighlightStore(str(tmp_path / "highlights.json")),
                           CommandStore(str(tmp_path / "commands.json")))
        view = page.make_view(Session("open", SSH, "localhost"))
        page.tabs.add_view(view)
        page.show_page(1)
        source = view.view
        page.set_manager_visible(False)
    elif kind == "scp":
        page = ScpTab(window, store)
        source = FileList("local", "test", page.stack)
        page.stack.addWidget(source)
        page.stack.setCurrentWidget(source)
    else:
        page = RdpTab(window, store)
        source = page.manager.tree
    monkeypatch.setattr(page.manager, "selected_folder", lambda: "HQ")
    monkeypatch.setattr(QInputDialog, "getText", lambda *args: ("IDF 1", True))
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    window.activateWindow()
    source.setFocus()
    QApplication.processEvents()
    QTest.keyClick(source, Qt.Key_N, Qt.ControlModifier | Qt.ShiftModifier)
    assert "HQ/IDF 1" in page.store.all_folders()


def test_shift_shortcuts_leave_multiline_text_and_terminal_keys_alone(window, tmp_path):
    class EditorPage(QWidget):
        def shutdown(self):
            pass

    editor = EditorPage()
    text = QPlainTextEdit(editor)
    window.navigator.addWidget(editor)
    text.setPlainText("line")
    text.moveCursor(text.textCursor().End)
    text.setFocus()
    QApplication.processEvents()
    QTest.keyClick(text, Qt.Key_Return, Qt.ShiftModifier)
    assert text.toPlainText() == "line\n"
    page = TerminalTab(window, SessionStore(str(tmp_path / "sessions.json")),
                       HighlightStore(str(tmp_path / "highlights.json")),
                       CommandStore(str(tmp_path / "commands.json")))
    view = page.make_view(Session("open", SSH, "localhost"))
    page.tabs.add_view(view)
    page.show_page(1)
    window.navigator.addWidget(page)
    window.navigator.setCurrentWidget(page)
    view.view.setFocus()
    QApplication.processEvents()
    sent = []
    view.view.key_input.connect(sent.append)
    QTest.keyClick(view.view, Qt.Key_Return, Qt.ShiftModifier)
    QTest.keyClick(view.view, Qt.Key_Escape, Qt.ShiftModifier)
    assert sent == ["\r", "\x1b"]
