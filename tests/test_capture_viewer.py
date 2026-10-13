"""Packet Capture's viewer: opening a capture, filters, the details and bytes, summaries, problems, following a
stream, ERSPAN unwrapped; and the page around it (SPAN copies on an adapter, opening what was just saved)."""
import ipaddress
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from capture_samples import erspan_wrap, frame_ip, sample_packets, udp, write_pcapng  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QAction, QApplication, QMenu, QWidget  # noqa: E402

from nomad.netmap import mirror  # noqa: E402
from nomad.ui import capture_tab, capture_viewer  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    def __init__(self, adapters=()):
        super().__init__()
        self.snapshot = SimpleNamespace(real_adapters=lambda: list(adapters))

    def set_busy(self, key, text):
        pass

    def clear_busy(self, key):
        pass

    def require_admin(self, what):
        return True


def wait(viewer):
    for _ in range(400):
        thread = viewer.loader or viewer.filterer
        if thread is None:
            break
        thread.wait(25)
        QApplication.processEvents()
    QApplication.processEvents()


@pytest.fixture
def viewer(app, tmp_path):
    window = Window()
    page = capture_viewer.CaptureViewer(window)
    page.sample_path = str(write_pcapng(tmp_path / "sample.pcapng", sample_packets()))
    yield page
    page.shutdown()
    page.deleteLater()
    window.deleteLater()


def numbers(viewer):
    return [viewer.model.packet(row).number for row in range(viewer.model.rowCount())]


def test_open_filter_and_look_at_a_packet(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    assert viewer.model.rowCount() == 35
    assert "sample.pcapng: 35 packets (1 ERSPAN frames inside)" in viewer.status_label.text()
    assert viewer.tabs.tabText(2).startswith("Problems (")
    assert viewer.unwrap_button.isVisibleTo(viewer) and viewer.unwrap_button.text() == "Show Mirrored Frames"

    viewer.filter_input.setText("tcp.port == 80")
    assert capture_viewer.FILTER_OK in viewer.filter_input.styleSheet()
    viewer.apply_filter()
    wait(viewer)
    assert numbers(viewer) == [10, 11, 12, 13, 14, 15, 16]
    assert "Showing 7 that match the filter" in viewer.status_label.text()

    viewer.table.selectRow(3)  # The HTTP request
    QApplication.processEvents()
    titles = [viewer.details.topLevelItem(index).text(0) for index in range(viewer.details.topLevelItemCount())]
    assert titles[0].startswith("Frame 13") and titles[-1] == "Hypertext Transfer Protocol"
    ip = viewer.details.topLevelItem(2)
    source = next(ip.child(index) for index in range(ip.childCount())
                  if ip.child(index).text(0).startswith("Source address"))
    viewer.details.setCurrentItem(source)
    selections = viewer.hex.extraSelections()
    assert len(selections) == 2  # Bytes 26-29: the hex and the text of the second line
    assert selections[0].cursor.selectedText() == "0a 00 0a 09" and selections[1].cursor.selectedText() == "...."

    viewer.filter_input.setText("tcp.port == http")
    assert capture_viewer.FILTER_BAD in viewer.filter_input.styleSheet()
    assert "needs a number" in viewer.filter_input.toolTip()
    viewer.apply_filter()
    assert "needs a number" in viewer.status_label.text() and viewer.model.rowCount() == 7  # Left as it was

    viewer.clear_filter()
    wait(viewer)
    assert viewer.model.rowCount() == 35


def menu_action(menu, *path):
    """The entry at path (submenu titles, then the entry's text) in menu."""
    for text in path:
        action = next(action for action in menu.actions() if action.text() == text)
        menu = action.menu() or menu
    return action


def test_the_list_shows_ports_in_their_own_columns(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    model = viewer.model
    assert [model.headerData(column, Qt.Horizontal) for column in range(model.columnCount())] == [
        "No.", "Time", "Source", "Src Port", "Destination", "Dst Port", "Protocol", "Length", "Info"]

    def row(number):
        index = model.row_of(number)
        return [model.data(model.index(index, column)) for column in range(model.columnCount())]

    http = model.packet(model.row_of(13))
    assert row(13)[2:7] == ["10.0.10.9", str(http.sport), "10.0.20.80", "80", "HTTP"]
    assert model.data(model.index(model.row_of(13), 5), Qt.TextAlignmentRole) == int(Qt.AlignRight | Qt.AlignVCenter)
    arp = next(packet for packet in viewer.view.packets if packet.protocol == "ARP")
    assert row(arp.number)[3] == row(arp.number)[5] == ""  # No ports

    model.sort(5, Qt.AscendingOrder)  # By destination port: the ones without come first
    ports = [model.packet(index).dport for index in range(model.rowCount())]
    assert ports[0] is None and ports[-1] == max(port for port in ports if port is not None)
    model.sort(0, Qt.AscendingOrder)

    viewer.menu_packet = http
    viewer.copy_summary()
    assert QApplication.clipboard().text().split("	")[2:7] == ["10.0.10.9", str(http.sport), "10.0.20.80", "80",
                                                                  "HTTP"]
    viewer.menu_packet = None


def test_right_click_adds_to_the_filter(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    viewer.apply_filter_text("tcp")
    wait(viewer)
    packet = viewer.model.packet(viewer.model.row_of(13))  # The HTTP request
    filters, clicked = viewer.row_filters(packet, 4)  # Right-clicked its destination
    assert filters[0] == "ip.addr == 10.0.20.80" and clicked
    assert "tcp.port == 80" in filters and "http" in filters
    assert viewer.row_filters(packet, 8)[0][0] == "tcp.port == 80"  # Info: the port it's to
    assert viewer.row_filters(packet, 5) == (viewer.row_filters(packet, 8)[0], True)  # Its destination port
    assert viewer.row_filters(packet, 3)[0][0] == f"tcp.port == {packet.sport}"  # Its source port
    assert viewer.row_filters(packet, 0)[1] is False  # No.: nothing in particular

    menu = QMenu(viewer)
    viewer.add_filter_menus(menu, filters, clicked)
    assert [action.text() for action in menu.actions() if action.menu()] == [
        "Add to Filter", "Add to Filter with Or", "Exclude from Filter"]
    assert menu_action(menu, "Add to Filter", "ip.addr == 10.0.20.80").menu() is None
    assert menu.actions()[-3].menu().defaultAction().text() == "ip.addr == 10.0.20.80"
    menu_action(menu, "Add to Filter", "ip.addr == 10.0.20.80").trigger()
    wait(viewer)
    assert viewer.filter_input.text() == "tcp && ip.addr == 10.0.20.80"
    assert numbers(viewer) == [10, 11, 12, 13, 14, 15, 16]
    menu_action(menu, "Exclude from Filter", "http").trigger()
    wait(viewer)
    assert viewer.filter_input.text() == "tcp && ip.addr == 10.0.20.80 && !http"
    assert 13 not in numbers(viewer) and 10 in numbers(viewer)
    menu_action(menu, "Add to Filter with Or", "tcp.port == 80").trigger()
    wait(viewer)
    assert viewer.filter_input.text() == "tcp && ip.addr == 10.0.20.80 && !http || tcp.port == 80"
    assert 13 in numbers(viewer)

    # A line of the packet's details: its own field, or the protocol it's under
    viewer.clear_filter()
    wait(viewer)
    viewer.table.selectRow(viewer.model.row_of(13))
    QApplication.processEvents()
    ip = viewer.details.topLevelItem(2)
    lines = {ip.child(index).text(0).split(":")[0]: ip.child(index) for index in range(ip.childCount())}
    assert capture_viewer.detail_filter(lines["Source address"]) == "ip.src == 10.0.10.9"
    assert capture_viewer.detail_filter(lines["Header checksum"]) == "ip"
    assert capture_viewer.detail_filter(None) == ""
    viewer.apply_filter_text("udp")
    wait(viewer)
    action = QAction("Add to Filter with Or", viewer)
    action.setData(("or", "ip.src == 10.0.10.9"))
    action.triggered.connect(viewer.filter_from_menu)
    action.trigger()
    wait(viewer)
    assert viewer.filter_input.text() == "udp || ip.src == 10.0.10.9"
    menu.deleteLater()
    action.deleteLater()


def test_sorting_and_filtering_keep_the_packet_looked_at(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    viewer.table.sortByColumn(7, Qt.DescendingOrder)  # Length
    lengths = [viewer.model.packet(row).wire_length for row in range(viewer.model.rowCount())]
    assert lengths == sorted(lengths, reverse=True)
    row = viewer.model.row_of(21)
    viewer.table.selectRow(row)
    viewer.apply_filter_text("tls || dns")
    wait(viewer)
    assert viewer.selected_packet().number == 21


def test_summaries_and_problems_show_their_packets(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    assert "35 packets" in viewer.headline.text()
    viewer.conversation_combo.setCurrentIndex(viewer.conversation_combo.findData("tcp"))
    table = viewer.conversation_table
    rows = {table.item(row, 0).text(): row for row in range(table.rowCount())}
    http = rows["10.0.10.9:51000 (laptop9)"]
    assert table.item(http, 1).text() == "10.0.20.80:80 (intranet.example.com)"
    viewer.filter_from_table(table.item(http, 2))
    wait(viewer)
    assert viewer.filter_input.text() == "tcp.stream == 0" and viewer.tabs.currentIndex() == 0
    assert numbers(viewer) == [10, 11, 12, 13, 14, 15, 16]

    tree = viewer.problem_tree
    problems = [tree.topLevelItem(index) for index in range(tree.topLevelItemCount())]
    duplicate = next(item for item in problems if item.text(2) == "Duplicate IP address 10.0.10.50")
    assert duplicate.text(0) == "Error"
    tree.setCurrentItem(duplicate)
    assert "Claimed by 00:11:22:33:44:55" in viewer.problem_detail.text() and viewer.problem_button.isEnabled()
    viewer.filter_problem()
    wait(viewer)
    assert numbers(viewer) == [3, 4]

    width, rows = viewer.chart.width_seconds, viewer.chart.rows
    assert sum(count for count, _ in rows) == 35
    viewer.filter_time(0.0, width)
    wait(viewer)
    assert viewer.filter_input.text().startswith("frame.time_relative >= 0 && frame.time_relative <")
    assert viewer.neighbor_table.rowCount() == 2
    protocols = [viewer.protocol_tree.topLevelItem(0).text(0)]
    assert protocols == ["eth"]


def test_follow_a_stream(viewer):
    viewer.open(viewer.sample_path)
    wait(viewer)
    viewer.table.selectRow(viewer.model.row_of(13))
    viewer.follow_selected()
    dialog = viewer.followers[-1]
    text = dialog.text.toPlainText()
    assert text.startswith("GET /index.html HTTP/1.1") and text.count("GET /index.html") == 1
    assert "HTTP/1.1 500 Internal Server Error" in text
    dialog.format_combo.setCurrentIndex(1)
    assert dialog.text.toPlainText().startswith("00000000  47 45 54 20")
    dialog.direction_combo.setCurrentIndex(2)  # The server's side only
    assert "GET" not in dialog.text.toPlainText()
    dialog.filter_packets()
    wait(viewer)
    assert viewer.filter_input.text() == "tcp.stream == 0"
    dialog.close()


def test_erspan_capture_opens_unwrapped_and_switches(viewer, tmp_path):
    inner = [frame_ip("00:de:ad:00:00:01", "00:de:ad:00:00:02", "172.16.0.1", "172.16.0.2", 17,
                      udp(1000 + number, 5001, b"q")) for number in range(4)]
    path = write_pcapng(tmp_path / "erspan.pcapng", [(number * 0.1, erspan_wrap(frame))
                                                     for number, frame in enumerate(inner)])
    viewer.open(str(path))
    wait(viewer)
    assert viewer.view.unwrapped and viewer.unwrap_button.text() == "Show as Captured"
    assert viewer.model.packet(0).src == "172.16.0.1"
    viewer.toggle_unwrapped()
    wait(viewer)
    assert not viewer.view.unwrapped and viewer.model.packet(0).protocol == "UDP"
    assert viewer.model.packet(0).src == "172.16.0.1"  # Decoded through to the frame inside, as Wireshark does
    assert viewer.unwrap_button.text() == "Show Mirrored Frames"


def test_a_file_that_isnt_a_capture(viewer, tmp_path):
    path = tmp_path / "notes.pcapng"
    path.write_bytes(b"this is not a capture file, not at all")
    viewer.open(str(path))
    wait(viewer)
    assert "Couldn't open notes.pcapng: It isn't a pcapng or pcap capture." in viewer.status_label.text()
    assert viewer.model.rowCount() == 0


def test_the_page_folds_its_settings_away(app):
    window = Window()
    page = capture_tab.CaptureTab(window)
    assert not page.settings_panel.isHidden() and page.settings_button.text() == "Settings: all traffic"
    page.show_settings(False)
    assert page.settings_panel.isHidden() and not page.settings_button.isChecked()
    page.address_input.setText("10.0.0.5")
    page.port_input.setText("443")
    assert page.settings_button.text() == "Settings: to or from 10.0.0.5 port 443"  # Seen while folded away
    page.port_input.setText("nope")
    assert page.settings_button.text() == "Settings: check the filter"
    page.settings_button.click()
    assert not page.settings_panel.isHidden()
    page.show_settings(False)
    page.capture_host("10.0.0.9")  # Filled in from another page: shown, to see what was
    assert not page.settings_panel.isHidden()
    page.viewer.shutdown()
    page.deleteLater()
    window.deleteLater()


def test_the_page_offers_span_copies_on_an_adapter(app, tmp_path, monkeypatch):
    adapters = [SimpleNamespace(name="Wi-Fi", description="Intel Wi-Fi 6", mac="00-50-56-AA-00-08",
                                ipv4=[ipaddress.IPv4Interface("192.168.5.25/24")]),
                SimpleNamespace(name="Ethernet 2", description="USB GbE", mac="00-50-56-AA-00-09",
                                ipv4=[ipaddress.IPv4Interface("169.254.33.7/16")])]
    window = Window(adapters)
    page = capture_tab.CaptureTab(window)
    page.capture_span("Ethernet 2")
    assert page.span_check.isChecked() and page.span_adapter_combo.currentData() == "Ethernet 2"
    assert page.span_adapter_combo.itemData(0) == "Ethernet 2"  # Wired first
    assert page.span_address() == "169.254.33.7"
    assert "Ready to capture the copies the switch sends Ethernet 2" in page.status_label.text()

    made = []

    class FakeCapture:
        def __init__(self, capture_filter, whole, size, promiscuous, live=False):
            made.append(promiscuous)
            self.filter, self.promiscuous, self.promiscuous_problem = capture_filter, object(), ""
            self.running = True
            self.live, self.live_problem, self.feed = False, "", None

        def start(self):
            pass

        def elapsed(self):
            return 0.0

        def size(self):
            return 0

    monkeypatch.setattr(capture_tab, "Capture", FakeCapture)
    monkeypatch.setattr(capture_tab, "find_pktmon", lambda: "pktmon.exe")
    monkeypatch.setattr(capture_tab, "run_in_background", lambda function, done, failed: done(function()))
    page.output_input.setText(str(tmp_path / "out.pcapng"))
    page.start()
    assert made == ["169.254.33.7"] and "Promiscuous mode on for Ethernet 2" in page.capture_note
    page.timer.stop()
    page.capture = None
    page.finish_capture()

    page.capture_erspan("10.18.0.122", 7)  # ERSPAN needs no promiscuous mode
    assert not page.span_check.isChecked() and page.unwrap_check.isChecked()
    page.shutdown()
    page.deleteLater()
    window.deleteLater()


def test_capture_here_for_span_to_this_pcs_port(app):
    from nomad.ui import mirror_tab
    record = mirror.MirrorRecord("ABC123", kind=mirror.SPAN, to_this_pc=True, adapter="Ethernet 2")
    assert mirror_tab.can_capture_here(record)
    assert not mirror_tab.can_capture_here(mirror.MirrorRecord("X", kind=mirror.SPAN, to_this_pc=True))
    assert mirror_tab.can_capture_here(mirror.MirrorRecord("Y", kind=mirror.ERSPAN, to_this_pc=True,
                                                           origin_ip="10.18.0.122"))
    asked = []
    page = SimpleNamespace(window=SimpleNamespace(capture_tab=SimpleNamespace(
        capture_span=asked.append, capture_erspan=lambda *arguments: asked.append(arguments)), navigator=None))
    mirror_tab.MirrorTab.capture_record(page, record)
    assert asked == ["Ethernet 2"]
    again = mirror.record_from_dict(mirror.asdict(record))
    assert again.adapter == "Ethernet 2"
