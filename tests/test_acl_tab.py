"""The ACLs page and its SSH side: reading a device, editing, the lockout block, sending with the revert timer
(confirmed from a new login, or put back), Send to Session, the library and Changes Sent."""
import os
from types import SimpleNamespace

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import pyqtSignal  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox, QWidget  # noqa: E402
from test_mirror import ConfigChannel, FakePushShell, campus  # noqa: E402

from nomad.netmap import acl, configpush, macssh  # noqa: E402
from nomad.netmap.acl import V4  # noqa: E402
from nomad.terminal.sessions import Session, SessionStore  # noqa: E402
from nomad.terminal.transports import ConnectionFailed  # noqa: E402
from nomad.ui import acl_tab  # noqa: E402

RUNNING = """Building configuration...
hostname sw1
ip access-list extended WEB-IN
 permit tcp any host 10.1.1.10 eq www
 deny   ip any any
ip access-list standard MGMT
 permit 10.0.10.0 0.0.0.255
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
 ip access-group WEB-IN in
interface GigabitEthernet1/0/1
line vty 0 15
 access-class MGMT in
end"""
SHOW = """Extended IP access list WEB-IN
    10 permit tcp any host 10.1.1.10 eq www (7 matches)
    20 deny ip any any (3 matches)
Standard IP access list MGMT
    10 permit 10.0.10.0, wildcard bits 0.0.0.255"""
FILE_SYSTEMS = """File Systems:

     Size(b)       Free(b)      Type  Flags  Prefixes
*  1621966848    1395765248      disk     rw   flash:
           -             -    opaque     rw   system:"""


class AclDevice(ConfigChannel):
    """A switch answering the commands the ACLs page sends."""

    def __init__(self, refuse=()):
        super().__init__(start="sw1#", refuse=refuse)
        self.archive = ""
        self.confirms = self.reverts = self.saves = 0

    def answer(self, word):
        if word == "show running-config":
            return RUNNING
        if word == "show ip access-lists":
            return SHOW
        if word == "show ipv6 access-list":
            return ""
        if word.startswith("show ip cef"):
            return "10.0.10.0/24\n  attached to Vlan10"
        if word == "show running-config | section archive":
            return f"archive\n path {self.archive}" if self.archive else ""
        if word == "show file systems":
            return FILE_SYSTEMS
        if word == "configure confirm":
            self.confirms += 1
            return ""
        if word == "configure revert now":
            self.reverts += 1
            return "Rollback:Acquired Configuration lock."
        if word == "write memory":
            self.saves += 1
            return "Building configuration...\n[OK]"
        return None

    def send(self, text):
        word = text.strip()
        reply = self.answer(word)
        if reply is None:
            if word.startswith("path "):
                self.archive = word.split()[1]
            super().send(text)
            return
        self.sent.append(text)
        self.out.append(word + "\r\n" + reply.replace("\n", "\r\n") + ("\r\n" if reply else "") + self.prompt())


class Logins:
    """FakePushShell, where logins after the first can be made to fail."""
    fail_after = None
    opened = 0


class CountingShell(FakePushShell):
    def open(self):
        Logins.opened += 1
        if Logins.fail_after is not None and Logins.opened > Logins.fail_after:
            raise ConnectionFailed("Authentication failed.")
        super().open()


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class MapPage(QWidget):
    map_shown = pyqtSignal()

    def __init__(self, network_map):
        super().__init__()
        self.network_map = network_map

    def session_hints(self, network_map, device):
        return {"aliases": [], "name": device.name, "folder": ""}


class Window(QWidget):
    def __init__(self, network_map, sessions):
        super().__init__()
        self.netmap_tab = MapPage(network_map)
        self.session_store = sessions
        self.busy = []

    def set_busy(self, key, text):
        self.busy.append(text)

    def clear_busy(self, key):
        pass


@pytest.fixture
def page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    device = AclDevice()
    FakePushShell.channels = {"10.0.0.1": device}
    Logins.fail_after, Logins.opened = None, 0
    monkeypatch.setattr(acl_tab, "local_address_toward", lambda address: "10.0.10.9")
    sessions = SessionStore(str(tmp_path / "sessions.json"))
    window = Window(campus(), sessions)
    tab = acl_tab.AclTab(window, store=acl.AclStore(tmp_path / "acls.json"))
    tab.shell_factory = CountingShell
    tab.logins = lambda: (macssh.SshLogins(fallback=Session("", username="admin"), password="pw"), "")
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    tab.device_switch = device
    yield tab
    tab.shutdown()
    window.deleteLater()


def wait(tab):
    for _ in range(600):
        thread = tab.reader or tab.sender_thread
        if thread is None:
            break
        thread.wait(50)
        QApplication.processEvents()
    QApplication.processEvents()


def read_sw1(page):
    page.prefill("SW1", "WEB-IN")
    wait(page)
    assert page.current_key == "map:SW1" and page.device() is not None, page.notes
    assert page.current_acl() is not None and page.current_acl().name == "WEB-IN"


def add_rule(page, text, at=None):
    item = page.current_acl()
    rule = acl.parse_rule(text, item.family, item.kind)
    item.rules.insert(len(item.rules) - 1 if at is None else at, rule)
    page.edited()


def test_lists_map_devices_and_the_scratch_pad(page):
    keys = [page.device_list.item(row).data(acl_tab.Qt.UserRole) for row in range(page.device_list.count())]
    assert keys[0] == acl_tab.SCRATCH and {"map:SW1", "map:R1", "map:SW2", "map:SW9"} <= set(keys)


def test_reads_and_shows_the_acl_with_its_counts(page):
    read_sw1(page)
    assert page.rules_table.rowCount() == 2
    assert page.rules_table.item(0, 0).text() == "10" and page.rules_table.item(0, 8).text() == "7"
    assert "Vlan10 in" in page.applied_label.text()
    assert page.device().toward_pc == "Vlan10"
    assert not page.send_button.isEnabled()  # Nothing changed yet


def test_edit_preview_and_send_with_the_revert_timer_confirmed_from_a_new_login(page):
    read_sw1(page)
    add_rule(page, "permit tcp any host 10.1.1.11 eq 443")
    preview = page.preview.toPlainText().splitlines()
    assert preview[0] == "configure terminal revert timer 5"
    assert " 15 permit tcp any host 10.1.1.11 eq 443" in preview and preview[-1] == "end"
    assert page.rules_table.item(1, 0).text() == "15"  # The number it gets when sent
    assert page.send_button.isEnabled()
    page.send_current()
    wait(page)
    device = page.device_switch
    sent = [text.strip() for text in device.sent]
    assert "path flash:nomad-revert" in sent  # NOMAD set an archive path for the timer
    assert "configure terminal revert timer 5" in sent and "15 permit tcp any host 10.1.1.11 eq 443" in sent
    assert device.confirms == 1 and device.reverts == 0 and Logins.opened >= 2  # Confirmed from a new login
    entry = page.store.history[0]
    assert entry.outcome.startswith("Confirmed") and "flash:nomad-revert" in entry.outcome
    assert "no 15" in entry.undo
    assert page.save_button.isEnabled()  # Read again: nothing waiting, confirmed
    page.save_startup()
    wait(page)
    assert device.saves == 1


def test_a_failed_new_login_puts_it_back_right_away(page):
    read_sw1(page)
    add_rule(page, "permit udp any any eq 123")
    Logins.opened, Logins.fail_after = 0, 1  # The send's own login works, the new one after the change doesn't
    page.send_current()
    wait(page)
    device = page.device_switch
    assert device.reverts == 1 and device.confirms == 0
    assert page.store.history[0].outcome.startswith("Put back")
    assert page.changes_for("map:SW1")  # The edits are kept to fix and send again


def test_a_refused_line_reverts(page):
    read_sw1(page)
    add_rule(page, "permit tcp any any eq 8443")
    page.device_switch.refuse = {"15 permit tcp any any eq 8443"}
    page.send_current()
    wait(page)
    assert page.device_switch.reverts == 1 and page.device_switch.confirms == 0
    assert "Put back" in page.store.history[0].outcome and "refused" in page.store.history[0].outcome


def test_lockout_blocks_sending_until_ticked(page):
    read_sw1(page)
    page.current_item = (acl_tab.KIND_ACL, (V4, "MGMT"))
    page.fill_items()
    item = page.current_acl()
    item.rules = [acl.parse_rule("permit 10.0.20.0 0.0.0.255", V4, acl.STANDARD)]
    page.edited()
    assert "access-class MGMT would refuse" in page.lockout_label.text()
    assert not page.send_button.isEnabled() and page.console_check.isVisibleTo(page)
    page.console_check.setChecked(True)
    assert page.send_button.isEnabled()


def test_send_to_session_then_confirm(page, monkeypatch):
    read_sw1(page)
    add_rule(page, "permit icmp any any echo")
    sent = []
    view = SimpleNamespace(title="sw1 session")
    monkeypatch.setattr(page.session_sender, "send_to", lambda view, text, what="", tag=None: sent.append(text) or
                        True)
    page.lines_sent(view, ("changes", "map:SW1"))
    assert page.confirm_button.isEnabled() and "Typed into sw1 session" in page.store.history[0].outcome
    assert page.waiting_box.isVisibleTo(page) and "typed into sw1 session" in page.waiting_label.text()
    page.confirm_waiting()
    assert sent == ["configure confirm"] and not page.confirm_button.isEnabled()
    assert page.store.history[0].outcome.startswith("Confirmed in sw1 session")


def test_send_left_for_me_to_confirm_then_confirm(page):
    read_sw1(page)
    page.confirm_combo.setCurrentIndex(page.confirm_combo.findData(acl_tab.CONFIRM_MANUAL))
    add_rule(page, "permit tcp any host 10.1.1.11 eq 443")
    page.send_current()
    wait(page)
    device = page.device_switch
    assert device.confirms == 0 and device.reverts == 0 and Logins.opened >= 2  # A new login was tried, no more
    assert "map:SW1" in page.waiting and page.waiting_box.isVisibleTo(page)
    assert "waiting to be confirmed" in page.store.history[0].outcome
    assert page.confirm_button.isEnabled() and not page.save_button.isEnabled()
    add_rule(page, "permit udp any any eq 53")
    assert "waiting to be confirmed" in page.blocked("map:SW1")  # Nothing more until it's confirmed or put back
    page.confirm_waiting()
    wait(page)
    assert device.confirms == 1 and "map:SW1" not in page.waiting
    assert page.store.history[0].outcome.startswith("Confirmed")
    assert not page.waiting_box.isVisibleTo(page)


def test_left_to_confirm_then_put_back_or_run_out(page):
    read_sw1(page)
    page.confirm_combo.setCurrentIndex(page.confirm_combo.findData(acl_tab.CONFIRM_MANUAL))
    add_rule(page, "permit tcp any host 10.1.1.11 eq 443")
    page.send_current()
    wait(page)
    page.put_back_now()
    wait(page)
    assert page.device_switch.reverts == 1 and "map:SW1" not in page.waiting
    assert page.store.history[0].outcome.startswith("Put back")
    # Not confirmed in time: the device puts it back itself, and NOMAD says so
    add_rule(page, "permit tcp any host 10.1.1.12 eq 443")
    page.send_current()
    wait(page)
    import datetime
    page.waiting["map:SW1"].deadline = datetime.datetime.now() - datetime.timedelta(minutes=1)
    page.on_tick()
    wait(page)
    assert "map:SW1" not in page.waiting and "Not confirmed" in page.store.history[0].outcome


def test_scratch_pad_library_and_putting_it_on_a_device(page, monkeypatch):
    page.current_key = acl_tab.SCRATCH
    page.fill_devices()
    page.on_device_chosen()
    scratch = page.device()
    scratch.acls[(V4, "WEB-IN")] = acl.Acl("WEB-IN", rules=[
        acl.parse_rule("permit tcp any host 10.1.1.10 eq www", V4, acl.EXTENDED),
        acl.parse_rule("permit tcp any host 10.1.1.10 eq 443", V4, acl.EXTENDED),
        acl.parse_rule("deny ip any any", V4, acl.EXTENDED)])
    page.current_item = (acl_tab.KIND_ACL, (V4, "WEB-IN"))
    page.edited()
    assert not page.send_button.isEnabled()  # Not a device
    monkeypatch.setattr(acl_tab.QInputDialog, "getText", lambda *args, **kwargs: ("Web", True))
    page.save_to_library()
    assert page.store.library[0].name == "Web"
    read_sw1(page)
    page.fill_library()
    page.library_table.selectRow(0)
    page.use_library_here()
    lines = page.preview.toPlainText().splitlines()
    assert lines[1:-1] == ["ip access-list extended WEB-IN", " 15 permit tcp any host 10.1.1.10 eq 443", " exit"]


def test_pusher_read_acls_alone(monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    FakePushShell.channels = {"10.0.0.1": AclDevice()}
    logins = macssh.SshLogins(fallback=Session("", username="admin"), password="pw")
    pusher = configpush.Pusher(logins, shell_factory=FakePushShell)
    device = pusher.read_acls("10.0.0.1", pc_ip="10.0.10.9")
    assert device.read and device.hostname == "sw1" and [rule.hits for rule in device.acl(V4, "WEB-IN").rules] == \
        [7, 3]
    assert device.toward_pc == "Vlan10"


def test_rule_dialog_builds_what_is_typed(app):
    from nomad.ui.acl_dialogs import NewAclDialog, RuleDialog
    item = acl.Acl("WEB-IN")
    dialog = RuleDialog(None, item, choices=[])
    dialog.action_combo.setCurrentText("deny")
    dialog.protocol_combo.setCurrentText("tcp")
    dialog.src.input.setText("10.1.0.0 255.255.0.0")  # A mask: made a wildcard
    dialog.dst.input.setText("10.2.2.2")
    dialog.dst_ports.op.setCurrentIndex(dialog.dst_ports.op.findData("eq"))
    dialog.dst_ports.input.setText("www 443")
    dialog.established_check.setChecked(True)
    dialog.log_combo.setCurrentIndex(dialog.log_combo.findData("log"))
    dialog.remark_input.setPlainText("web replies")
    rule = dialog.build()
    assert rule.body() == "deny tcp 10.1.0.0 0.0.255.255 host 10.2.2.2 eq 80 443 established log"
    assert rule.remark == "web replies" and "subnet mask was typed" in dialog.problem_label.text()
    dialog.dst_ports.input.setText("nosuchport")
    dialog.update_preview()
    assert not dialog.buttons.button(dialog.buttons.Ok).isEnabled()
    dialog.deleteLater()

    standard = RuleDialog(None, acl.Acl("MGMT", kind=acl.STANDARD), choices=[])
    standard.src.input.setText("10.18.0.0/24")
    assert standard.build().body(V4, acl.STANDARD) == "permit 10.18.0.0 0.0.0.255"
    standard.deleteLater()

    new = NewAclDialog(None, {(V4, "WEB-IN")})
    new.name_input.setText("WEB-IN")
    assert "has WEB-IN already" in new.problem()
    new.name_input.setText("150")
    new.kind_combo.setCurrentIndex(new.kind_combo.findData(acl.STANDARD))
    assert "extended ACL's number" in new.problem()
    new.kind_combo.setCurrentIndex(new.kind_combo.findData(acl.EXTENDED))
    assert new.problem() == "" and new.made().numbered
    new.deleteLater()


def test_apply_to_an_interface_and_take_off(page, monkeypatch):
    from nomad.ui import acl_dialogs

    def choose(dialog):
        dialog.interface_combo.setCurrentIndex(dialog.interface_combo.findData("GigabitEthernet1/0/1"))
        dialog.direction_combo.setCurrentIndex(dialog.direction_combo.findData(acl.OUT))
        return acl_dialogs.QDialog.Accepted

    read_sw1(page)
    assert page.apply_button.isVisibleTo(page) and page.apply_button.isEnabled()
    monkeypatch.setattr(acl_dialogs.ApplyDialog, "exec_", choose)
    page.apply_acl()
    lines = page.preview.toPlainText().splitlines()
    assert lines[1:-1] == ["interface GigabitEthernet1/0/1", " ip access-group WEB-IN out", " exit"]
    assert "GigabitEthernet1/0/1 out" in page.applied_label.text()
    use = next(use for use in page.device().uses_of(page.current_acl()) if use.target == "GigabitEthernet1/0/1")
    page.take_off(use)
    assert not page.changes_for("map:SW1")


def type_number(page, row, text):
    page.rules_table.item(row, 0).setText(text)  # As the cell's editor does
    page.take_pending_number()


def test_typing_sequence_numbers_in_the_table(page):
    read_sw1(page)
    add_rule(page, "permit tcp any host 10.1.1.11 eq 443")  # Line 2, 15 to begin with
    assert page.rules_table.item(1, 0).flags() & acl_tab.Qt.ItemIsEditable
    assert not page.rules_table.item(1, 1).flags() & acl_tab.Qt.ItemIsEditable
    type_number(page, 1, "12")
    assert " 12 permit tcp any host 10.1.1.11 eq 443" in page.preview.toPlainText().splitlines()
    type_number(page, 1, "5")  # Its number is its place: above rule 10 now
    assert page.current_acl().rules[0].body() == "permit tcp any host 10.1.1.11 eq 443"
    assert page.rules_table.item(0, 0).text() == "5" and "Moved to line 1" in page.status_label.text()
    type_number(page, 0, "20")  # The deny keeps 20: refused
    assert "has number 20 already" in page.status_label.text() and page.rules_table.item(0, 0).text() == "5"
    type_number(page, 1, "30 (was 10)")  # The device's rule 10, renumbered: below the deny now
    lines = page.preview.toPlainText().splitlines()
    assert lines[2:6] == [" 5 permit tcp any host 10.1.1.11 eq 443", " no 10", " 30 permit tcp any host 10.1.1.10 eq 80",
                          " exit"]
    assert page.rules_table.item(2, 0).text() == "30 (was 10)"
    type_number(page, 2, "")  # Nothing: an automatic number again, where it is now
    assert page.current_acl().rules[2].want_seq == 0


def test_number_from_the_rule_dialog(page, monkeypatch):
    from nomad.ui import acl_dialogs

    def fill(dialog):
        assert dialog.number_input.text() == "10"  # The rule's number to begin with
        dialog.number_input.setText("15")
        dialog.rule = dialog.build()
        return acl_dialogs.QDialog.Accepted

    read_sw1(page)
    page.select_rows([0])
    monkeypatch.setattr(acl_dialogs.RuleDialog, "exec_", fill)
    page.edit_rule()
    assert [rule.want_seq for rule in page.current_acl().rules] == [15, 0]
    assert " 15 permit tcp any host 10.1.1.10 eq 80" in page.preview.toPlainText().splitlines()


def test_double_click_types_a_number_on_seq_and_opens_the_rule_elsewhere(page, monkeypatch):
    from PyQt5.QtTest import QTest
    from nomad.ui import acl_dialogs
    opened = []
    monkeypatch.setattr(acl_dialogs.RuleDialog, "exec_", lambda dialog: opened.append(dialog) or 0)
    read_sw1(page)
    page.resize(1400, 900)
    page.show()
    table = page.rules_table
    for column, editing in ((0, True), (3, False)):
        rect = table.visualItemRect(table.item(0, column))
        QTest.mouseClick(table.viewport(), acl_tab.Qt.LeftButton, pos=rect.center())
        QTest.mouseDClick(table.viewport(), acl_tab.Qt.LeftButton, pos=rect.center())
        QApplication.processEvents()
        assert (table.state() == table.EditingState) == editing
        assert bool(opened) == (not editing)
        QTest.keyClick(table.viewport(), acl_tab.Qt.Key_Escape)
    page.hide()
