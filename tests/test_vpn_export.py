"""VPNs page: Export > Every Router to a Folder writes a file per router (and one with the lines that undo it), by-hand
sides and templates included, keys hidden unless Show keys is ticked."""
import os

from PyQt5.QtWidgets import QMessageBox

from nomad.netmap.vpn import DMVPN, HUB, VTI
from nomad.ui import vpn_tab
from nomad.ui.export_progress import wait_for_exports
from tests.test_vpn_tab import new_vti, page, read_both  # noqa: F401 (page: a fixture)
from tests.test_vpn_tab import app  # noqa: F401


def export_to(page, folder, monkeypatch, answer=QMessageBox.Yes):  # noqa: F811
    """Export > Every Router to a Folder into folder; the questions asked (each answered answer)."""
    asked = []
    monkeypatch.setattr(vpn_tab.QFileDialog, "getExistingDirectory", lambda *args, **kwargs: str(folder))
    monkeypatch.setattr(QMessageBox, "question", lambda parent, title, text, *args: asked.append(text) or answer)
    assert page.export_all_action.isEnabled()
    page.export_all()
    assert wait_for_exports()
    return asked


def read(folder, name):
    with open(os.path.join(folder, name), encoding="utf-8") as file:
        return file.read()


def test_a_file_per_router_and_one_that_undoes_it(page, tmp_path, monkeypatch):  # noqa: F811
    design = new_vti(page)
    assert page.export_keys() == ["map:R6", "map:R7"]
    asked = export_to(page, tmp_path, monkeypatch)
    assert not asked  # Keys hidden: nothing to ask
    assert sorted(os.listdir(tmp_path)) == ["LAB - R6 (8.0.0.22) (undo).txt", "LAB - R6 (8.0.0.22).txt",
                                            "LAB - R7 (8.0.0.26) (undo).txt", "LAB - R7 (8.0.0.26).txt"]
    r6 = read(tmp_path, "LAB - R6 (8.0.0.22).txt")
    first, rest = r6.split("\n", 1)
    assert first.startswith("! VPN LAB: R6 (8.0.0.22) (peer), exported ")
    assert rest == page.preview_text(undo=False, reveal=False, key="map:R6") + "\n"
    assert "configure terminal revert timer 10" in rest and "! R7" not in rest  # Only R6's own lines
    assert design.auth.psk not in r6 and "pre-shared-key ********" in r6
    undo = read(tmp_path, "LAB - R6 (8.0.0.22) (undo).txt")
    assert "the lines that undo it" in undo.splitlines()[0] and "no interface Tunnel10" in undo
    assert "Saved 4 files" in page.status_label.text() and "keys hidden" in page.status_label.text()
    assert not [name for name in os.listdir(tmp_path) if name.endswith(".tmp")]
    assert page.export_folder == str(tmp_path)


def test_keys_shown_are_asked_about_then_exported(page, tmp_path, monkeypatch):  # noqa: F811
    design = new_vti(page)
    page.show_keys_check.setChecked(True)
    asked = export_to(page, tmp_path, monkeypatch, answer=QMessageBox.No)
    assert len(asked) == 1 and "plain text" in asked[0] and not os.listdir(tmp_path)
    export_to(page, tmp_path, monkeypatch)
    assert design.auth.psk in read(tmp_path, "LAB - R7 (8.0.0.26).txt")


def test_files_already_there_are_replaced_only_when_said(page, tmp_path, monkeypatch):  # noqa: F811
    new_vti(page)
    (tmp_path / "LAB - R6 (8.0.0.22).txt").write_text("old", encoding="utf-8")
    asked = export_to(page, tmp_path, monkeypatch, answer=QMessageBox.No)
    assert len(asked) == 1 and "LAB - R6 (8.0.0.22).txt" in asked[0]
    assert os.listdir(tmp_path) == ["LAB - R6 (8.0.0.22).txt"] and read(tmp_path, "LAB - R6 (8.0.0.22).txt") == "old"
    export_to(page, tmp_path, monkeypatch)
    assert len(os.listdir(tmp_path)) == 4 and read(tmp_path, "LAB - R6 (8.0.0.22).txt") != "old"


def test_a_dmvpn_exports_its_by_hand_side_and_the_new_spokes_template(page, tmp_path, monkeypatch):  # noqa: F811
    read_both(page)
    page.make_new("CLOUD", DMVPN, [("map:R6", HUB)], far="8.0.0.26")
    page.show_design()
    keys = page.export_keys()
    assert keys == ["map:R6", "side:peer:8.0.0.26", "side:new:spoke"]
    export_to(page, tmp_path, monkeypatch)
    names = sorted(os.listdir(tmp_path))
    assert names == ["CLOUD - 8.0.0.26 (undo).txt", "CLOUD - 8.0.0.26.txt", "CLOUD - New spoke.txt",
                     "CLOUD - R6 (8.0.0.22) (undo).txt", "CLOUD - R6 (8.0.0.22).txt"]  # No undo for the template: nothing to undo yet
    assert ", by hand), exported" in read(tmp_path, "CLOUD - 8.0.0.26.txt").splitlines()[0]
    spoke = read(tmp_path, "CLOUD - New spoke.txt")
    assert spoke.startswith("! VPN CLOUD: New spoke (spoke, template)") and "<SPOKE-TUNNEL-IP>" in spoke
    assert spoke.split("\n", 1)[1] == page.preview_text(undo=False, reveal=False, key="side:new:spoke") + "\n"


def test_a_template_exports_every_side(page, tmp_path, monkeypatch):  # noqa: F811
    page.make_template("BRANCH/2 : test", VTI)
    assert page.export_keys() == ["side:slot:a", "side:slot:b"]
    export_to(page, tmp_path, monkeypatch)
    assert sorted(os.listdir(tmp_path)) == ["BRANCH_2 _ test - Side A.txt", "BRANCH_2 _ test - Side B.txt"]
    assert "<A-WAN-IP>" in read(tmp_path, "BRANCH_2 _ test - Side A.txt")


def test_nothing_to_export_without_a_vpn(page):  # noqa: F811
    assert page.export_keys() == []
    page.update_buttons()
    assert not page.export_all_action.isEnabled() and not page.export_button.isEnabled()


def test_file_names_windows_takes():
    taken = set()
    assert vpn_tab.export_file_name('LAB - R6/a:b*?"<>|', taken) == "LAB - R6_a_b______"
    assert vpn_tab.export_file_name("LAB - r6/a:b*?\"<>|", taken) == "LAB - r6_a_b______ 2"  # Same name to Windows
    assert vpn_tab.export_file_name("CON", taken) == "_CON"
    assert vpn_tab.export_file_name("nul.backup", taken) == "_nul.backup"
    assert vpn_tab.export_file_name("Edge. ", taken) == "Edge"
    assert vpn_tab.export_file_name("...", taken) == "vpn"
    assert vpn_tab.export_file_name("tab\there", taken) == "tab_here"
