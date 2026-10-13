"""The ACLs page's prefix lists and route maps: reading them, editing entries (numbers typed in), applying them,
sending (with the revert timer) and the BGP soft clears offered after, the route tester, the library, and the
dialogs."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication, QMessageBox  # noqa: E402
from test_acl_tab import AclDevice, CountingShell, Logins, Window, wait  # noqa: E402
from test_mirror import FakePushShell, campus  # noqa: E402

from nomad.netmap import acl, macssh, routepolicy  # noqa: E402
from nomad.netmap.acl import V4  # noqa: E402
from nomad.netmap.routepolicy import BGP, ROUTE_MAP, MapEntry, PrefixEntry  # noqa: E402
from nomad.terminal.sessions import Session, SessionStore  # noqa: E402
from nomad.ui import acl_tab, policy_dialogs  # noqa: E402

RUNNING = """Building configuration...
hostname sw1
ip access-list standard MGMT
 permit 10.0.10.0 0.0.0.255
interface Vlan10
 ip address 10.0.10.1 255.255.255.0
interface GigabitEthernet1/0/1
 ip address 10.9.9.1 255.255.255.252
line vty 0 15
 access-class MGMT in
router ospf 1
 redistribute connected subnets
router bgp 65001
 neighbor 10.9.9.2 remote-as 65002
 !
 address-family ipv4
  neighbor 10.9.9.2 activate
  neighbor 10.9.9.2 route-map FROM-ISP in
 exit-address-family
ip prefix-list CUSTOMERS seq 5 permit 10.20.0.0/16 le 24
ip prefix-list CUSTOMERS seq 10 deny 0.0.0.0/0 le 32
route-map FROM-ISP permit 10
 match ip address prefix-list CUSTOMERS
 set local-preference 200
route-map FROM-ISP deny 20
end"""
SHOW_PREFIX = """ip prefix-list CUSTOMERS:
   count: 2, range entries: 2, sequences: 5 - 10, refcount: 2
   seq 5 permit 10.20.0.0/16 le 24 (hit count: 12, refcount: 1)
   seq 10 deny 0.0.0.0/0 le 32 (hit count: 3, refcount: 1)
"""


class PolicyDevice(AclDevice):
    def __init__(self):
        super().__init__()
        self.cleared = []

    def answer(self, word):
        if word == "show running-config":
            return RUNNING
        if word == "show ip prefix-list detail":
            return SHOW_PREFIX
        if word == "show route-map":
            return ""
        if word.startswith("clear ip bgp"):
            self.cleared.append(word)
            return ""
        return super().answer(word)


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture
def page(app, tmp_path, monkeypatch):
    monkeypatch.setattr(macssh, "QUIET", 0)
    device = PolicyDevice()
    FakePushShell.channels = {"10.0.0.1": device}
    Logins.fail_after, Logins.opened = None, 0
    monkeypatch.setattr(acl_tab, "local_address_toward", lambda address: "10.0.10.9")
    window = Window(campus(), SessionStore(str(tmp_path / "sessions.json")))
    tab = acl_tab.AclTab(window, store=acl.AclStore(tmp_path / "acls.json"))
    tab.shell_factory = CountingShell
    tab.logins = lambda: (macssh.SshLogins(fallback=Session("", username="admin"), password="pw"), "")
    monkeypatch.setattr(QMessageBox, "question", lambda *args, **kwargs: QMessageBox.Yes)
    tab.device_switch = device
    yield tab
    tab.shutdown()
    window.deleteLater()


def read(page):
    page.prefill("SW1")
    wait(page)
    assert page.device() is not None, page.notes


def show(page, kind, key):
    page.current_item = (kind, key)
    page.fill_items()


def tree_titles(page):
    return [page.items_tree.topLevelItem(row).text(0) for row in range(page.items_tree.topLevelItemCount())]


def test_reads_and_shows_prefix_lists_and_route_maps(page):
    read(page)
    assert "IPv4 Prefix Lists" in tree_titles(page) and "Route Maps" in tree_titles(page)
    show(page, acl_tab.KIND_PLIST, (V4, "CUSTOMERS"))
    editor = page.plist_editor
    assert page.editor.currentWidget() is editor
    assert editor.table.rowCount() == 2 and editor.table.item(0, 6).text() == "12"  # Hit counts
    assert "route map FROM-ISP" in editor.applied_label.text()
    show(page, acl_tab.KIND_RMAP, "FROM-ISP")
    editor = page.rmap_editor
    assert page.editor.currentWidget() is editor
    assert editor.table.item(0, 2).text() == "ip address prefix-list CUSTOMERS"
    assert "BGP 10.9.9.2 in" in editor.applied_label.text()


def test_edit_a_prefix_list_typing_a_number_then_send_and_soft_clear(page):
    read(page)
    show(page, acl_tab.KIND_PLIST, (V4, "CUSTOMERS"))
    editor = page.plist_editor
    item = page.current_plist()
    item.entries.insert(1, PrefixEntry(0, "permit", "10.30.0.0/16", le=24))
    page.edited()
    assert editor.table.item(1, 0).text() == "7"  # Between 5 and 10
    editor.set_number(1, 8)
    assert editor.table.item(1, 0).text() == "8"
    preview = page.preview.toPlainText().splitlines()
    assert "ip prefix-list CUSTOMERS seq 8 permit 10.30.0.0/16 le 24" in preview
    # The route tester tries the list as it will be
    editor.test_prefix.setText("10.30.4.0/24")
    editor.run_test()
    assert "Permitted by entry 8" in editor.test_result.text() and "On the device now: denied" in \
        editor.test_result.text()
    page.send_current()
    wait(page)
    device = page.device_switch
    assert device.confirms == 1 and page.store.history[0].outcome.startswith("Confirmed")
    # FROM-ISP matches CUSTOMERS and is on 10.9.9.2 in: a soft clear is offered, not ticked
    assert page.soft_box.isVisibleTo(page) and page.soft_list.count() == 1
    assert page.soft_list.item(0).checkState() == Qt.Unchecked and not page.soft_button.isEnabled()
    page.soft_list.item(0).setCheckState(Qt.Checked)
    assert page.soft_button.isEnabled()
    page.soft_clear()
    wait(page)
    assert device.cleared == ["clear ip bgp 10.9.9.2 soft in"]
    assert page.store.history[0].title == "BGP soft clear" and page.store.history[0].outcome == "Soft cleared"
    assert not page.soft_box.isVisibleTo(page)


def test_route_map_entry_edit_and_apply(page, monkeypatch):
    read(page)
    show(page, acl_tab.KIND_RMAP, "FROM-ISP")
    editor = page.rmap_editor
    item = page.current_rmap()
    item.entries[0].sets = ["local-preference 300"]
    item.entries.insert(1, MapEntry(0, "permit", ["ip address prefix-list CUSTOMERS"], ["weight 100"]))
    page.edited()
    lines = page.preview.toPlainText().splitlines()
    assert "route-map FROM-ISP permit 15" in lines
    assert "route-map FROM-ISP permit 10" in lines and " no set local-preference 200" in lines
    # Put it on the redistribution into OSPF too: the dialog picks the redistribution there
    dialog = policy_dialogs.PolicyApplyDialog(None, page.device(), ROUTE_MAP, item)
    dialog.radios[routepolicy.REDIST].setChecked(True)
    dialog.redist_what_combo.setCurrentIndex(dialog.redist_what_combo.findData("redistribute connected"))
    use = dialog.use()
    assert use.line == "redistribute connected subnets route-map FROM-ISP" and use.path == ("router ospf 1",)
    dialog.deleteLater()
    routepolicy.set_use(page.device(), use)
    page.edited()
    lines = page.preview.toPlainText().splitlines()
    assert " redistribute connected subnets route-map FROM-ISP" in lines
    # BGP neighbor out, from the dialog
    dialog = policy_dialogs.PolicyApplyDialog(None, page.device(), ROUTE_MAP, item)
    assert dialog.radios[BGP].isChecked()
    dialog.bgp_direction_combo.setCurrentIndex(dialog.bgp_direction_combo.findData(routepolicy.OUT))
    use = dialog.use()
    assert use.path == ("router bgp 65001", "address-family ipv4") and \
        use.line == "neighbor 10.9.9.2 route-map FROM-ISP out"
    dialog.deleteLater()
    # Checks see where it's used: as-path means nothing to OSPF
    item.entries[0].matches.append("as-path 5")
    page.edited()
    texts = [editor.findings_list.item(row).text() for row in range(editor.findings_list.count())]
    assert any("isn't supported for OSPF" in text for text in texts)


def test_route_tester_follows_the_map(page):
    read(page)
    show(page, acl_tab.KIND_RMAP, "FROM-ISP")
    editor = page.rmap_editor
    editor.test_prefix.setText("10.20.5.0/24")
    editor.run_test()
    assert "Permitted by entry 10: sets local-preference 200" in editor.test_result.text()
    assert editor.selected_rows() == [0]
    editor.test_prefix.setText("192.168.0.0/16")
    editor.run_test()
    assert "Denied by entry 20" in editor.test_result.text()


def test_new_prefix_list_and_route_map_library(page, monkeypatch):
    read(page)
    show(page, acl_tab.KIND_RMAP, "FROM-ISP")
    monkeypatch.setattr(acl_tab.QInputDialog, "getText", lambda *args, **kwargs: ("ISP policy", True))
    page.rmap_editor.save_to_library()
    entry = page.store.library[0]
    assert entry.item == "route-map FROM-ISP" and "ip prefix-list CUSTOMERS seq 5" in entry.config
    page.fill_library()
    assert page.library_table.item(0, 1).text() == "Route map FROM-ISP"
    # On the Scratch Pad: the route map and the prefix list it matches come with it
    page.current_key = acl_tab.SCRATCH
    page.fill_devices()
    page.on_device_chosen()
    page.library_table.selectRow(0)
    page.use_library_here()
    scratch = page.device()
    assert "FROM-ISP" in scratch.route_maps and (V4, "CUSTOMERS") in scratch.prefix_lists
    assert page.current_item == (acl_tab.KIND_RMAP, "FROM-ISP")
    dialog = policy_dialogs.NewPolicyDialog(None, routepolicy.PREFIX_LIST, scratch.prefix_lists,
                                            [("A copy", scratch.prefix_lists[(V4, "CUSTOMERS")])])
    dialog.name_input.setText("CUSTOMERS")
    assert "has CUSTOMERS already" in dialog.problem()
    dialog.name_input.setText("CUSTOMERS-2")
    dialog.start_combo.setCurrentIndex(1)
    made = dialog.made()
    assert made.name == "CUSTOMERS-2" and [entry.want_seq for entry in made.entries] == [5, 10]
    dialog.deleteLater()


def test_entry_dialogs(app):
    plist = routepolicy.PrefixList("L")
    dialog = policy_dialogs.PrefixEntryDialog(None, plist, choices=[])
    dialog.prefix.input.setText("10.1.2.3/16")
    dialog.le_input.setValue(24)
    entry = dialog.build()
    assert entry.prefix == "10.1.0.0/16" and entry.le == 24 and "Host bits" in dialog.problem_label.text()
    assert "/16 to /24 prefixes within 10.1.0.0/16" in dialog.explain_label.text()
    dialog.ge_input.setValue(8)
    dialog.update_preview()
    assert not dialog.buttons.button(dialog.buttons.Ok).isEnabled()
    dialog.deleteLater()
    device = acl.parse_running(RUNNING)
    rmap = device.route_maps["FROM-ISP"]
    dialog = policy_dialogs.MapEntryDialog(None, rmap, rmap.entries[0], device, 10, [20])
    dialog.matches.keyword_combo.setCurrentText("ip address prefix-list")
    dialog.matches.value_combo.setCurrentText("OTHER")
    dialog.matches.add()  # Added to the line with the same keyword
    dialog.continue_combo.setCurrentIndex(dialog.continue_combo.findData("20"))
    entry = dialog.build()
    assert entry.matches == ["ip address prefix-list CUSTOMERS OTHER"] and entry.cont == "20"
    assert "continue 20" in dialog.preview.text()
    dialog.deleteLater()
