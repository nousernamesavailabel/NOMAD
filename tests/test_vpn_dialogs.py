"""The New VPN and router dialogs react to a DMVPN role change straight away."""
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialogButtonBox

from nomad.netmap import vpn
from nomad.netmap.vpn import DMVPN, HUB, SPOKE
from nomad.ui.vpn_dialogs import MemberDialog, NewVpnDialog
from tests.test_vpn import design
from tests.test_vpn_tab import app  # noqa: F401


def dmvpn_dialog():
    dialog = NewVpnDialog(None, [("R6", "R6"), ("R7", "R7")], chosen=("R6", "R7"), name="D1", kind=DMVPN)
    return dialog


def ok(dialog):
    return dialog.buttons.button(QDialogButtonBox.Ok).isEnabled()


def test_a_spoke_made_hub_counts_without_touching_anything_else(app):  # noqa: F811
    dialog = dmvpn_dialog()
    assert not dialog.far_box.isHidden()  # Only spokes: the hub's set up by hand
    assert not ok(dialog)  # ...and its WAN address isn't typed yet
    dialog.table.cellWidget(0, 1).setCurrentIndex(dialog.table.cellWidget(0, 1).findData(HUB))
    assert dialog.far_box.isHidden()
    assert ok(dialog)
    assert dialog.chosen() == [("R6", HUB), ("R7", SPOKE)]
    dialog.table.cellWidget(0, 1).setCurrentIndex(dialog.table.cellWidget(0, 1).findData(SPOKE))
    assert not dialog.far_box.isHidden()
    assert not ok(dialog)


def test_only_hubs_says_so_at_once(app):  # noqa: F811
    dialog = dmvpn_dialog()
    for row in range(2):
        dialog.table.cellWidget(row, 1).setCurrentIndex(dialog.table.cellWidget(row, 1).findData(HUB))
    assert ok(dialog)
    assert "Only hubs" in dialog.hint.text()


def test_picking_a_role_ticks_the_router(app):  # noqa: F811
    dialog = NewVpnDialog(None, [("R6", "R6"), ("R7", "R7")], chosen=("R7",), name="D1", kind=DMVPN)
    assert dialog.table.item(0, 0).checkState() == Qt.Unchecked
    dialog.table.cellWidget(0, 1).setCurrentIndex(dialog.table.cellWidget(0, 1).findData(HUB))
    assert dialog.table.item(0, 0).checkState() == Qt.Checked
    assert dialog.chosen() == [("R6", HUB), ("R7", SPOKE)]
    assert dialog.far_box.isHidden()
    assert ok(dialog)


def test_hub_order_only_for_a_hub(app):  # noqa: F811
    item, found = design(DMVPN)
    spoke = item.member("R6")
    dialog = MemberDialog(None, item, spoke, found["R6"])
    assert not dialog.hub_order.isEnabled()
    dialog.role_combo.setCurrentIndex(dialog.role_combo.findData(HUB))
    assert dialog.hub_order.isEnabled()
    dialog.role_combo.setCurrentIndex(dialog.role_combo.findData(vpn.SPOKE))
    assert not dialog.hub_order.isEnabled()
    assert MemberDialog(None, item, item.member("R5"), found["R5"]).hub_order.isEnabled()
