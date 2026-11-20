"""Exports with a progress bar: the file is written on a worker thread behind a progress dialog with Cancel, and a
cancelled or failed export leaves no half-written file (nor spoils one already there)."""
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad import exporting  # noqa: E402
from nomad.exporting import ExportCancelled, Progress, saving, write_csv  # noqa: E402
from nomad.ipam.spreadsheet import read_pages  # noqa: E402
from nomad.ipam.store import RESERVED, USED, IpamStore  # noqa: E402
from nomad.ipam.workbook import NetworkCopy, copies, csv_rows, export_workbook  # noqa: E402
from nomad.ui import ipam_tab as ipam_module  # noqa: E402
from nomad.ui.export_progress import exports_running, run_export, wait_for_exports  # noqa: E402
from nomad.ui.ipam_tab import LOCAL, IpamTab  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    def __getattr__(self, name):
        return lambda *args, **kwargs: None


def sample(tmp_path):
    store = IpamStore(str(tmp_path / "ipam.db"), user="tester")
    network = store.add_network("11AB SIPR")
    store.add_subnet(network.id, "10.0.0.0/24", "LAN", gateway="10.0.0.1")
    store.add_subnet(network.id, "10.0.0.0/28", "Inner")
    store.add_subnet(network.id, "10.0.1.0/29", "Loopbacks", loopbacks=True)
    store.set_address(network.id, "10.0.0.5", USED, "pc5", mac="aabb.ccdd.eeff")
    store.set_address(network.id, "10.0.0.50", RESERVED, "printer")
    store.set_address(network.id, "10.0.1.0", USED, "rtr1")
    store.set_address(network.id, "10.9.9.9", USED, "outside")
    return store, network


# --------------------------------------------------------------------- The writing side (no Qt)

def test_progress_reports_stages_and_steps():
    reports = []
    progress = Progress(lambda *report: reports.append(report))
    progress.stage("Writing rows", 3)
    for _ in range(3):
        progress.step()
    progress.stage("Saving...")
    assert reports[0] == (0, 3, "Writing rows") and (3, 3, "Writing rows") in reports
    assert reports[-1] == (0, 0, "Saving...")


def test_a_stopped_progress_cancels_at_the_next_step():
    stop = threading.Event()
    progress = Progress(stop_event=stop)
    progress.stage("Writing rows", 10)
    progress.step()
    stop.set()
    with pytest.raises(ExportCancelled):
        progress.step()
    with pytest.raises(ExportCancelled):
        progress.stage("Next part")


def test_write_csv_writes_header_and_rows(tmp_path):
    path = tmp_path / "out.csv"
    assert write_csv(path, [["a", 1], ["b", 2]], ["Name", "Value"]) == 2
    assert path.read_text(encoding="utf-8-sig").splitlines() == ["Name,Value", "a,1", "b,2"]
    assert os.listdir(tmp_path) == ["out.csv"]


def test_a_cancelled_csv_leaves_the_old_file_alone(tmp_path):
    path = tmp_path / "out.csv"
    path.write_text("old", encoding="utf-8")
    stop = threading.Event()

    class Rows(list):
        def __iter__(self):  # Cancel pressed once two rows are written
            for number, row in enumerate(super().__iter__()):
                if number == 2:
                    stop.set()
                yield row

    with pytest.raises(ExportCancelled):
        write_csv(path, Rows([n] for n in range(100)), progress=Progress(stop_event=stop))
    assert path.read_text(encoding="utf-8") == "old" and os.listdir(tmp_path) == ["out.csv"]


def test_saving_puts_the_file_in_place_only_when_complete(tmp_path):
    path = tmp_path / "out.txt"
    with pytest.raises(RuntimeError):
        with saving(path) as temporary:
            open(temporary, "w").write("half")
            raise RuntimeError("stopped")
    assert not os.listdir(tmp_path)
    with saving(path) as temporary:
        open(temporary, "w").write("whole")
    assert path.read_text() == "whole" and os.listdir(tmp_path) == ["out.txt"]


def test_a_copied_network_exports_the_same_as_the_store(tmp_path):
    store, network = sample(tmp_path)
    copy = NetworkCopy(store, network)
    subnets = store.subnets(network.id)
    assert csv_rows(copy, network.id, subnets) == csv_rows(store, network.id, subnets)
    export_workbook(tmp_path / "store.xlsx", [(store, network)])
    export_workbook(tmp_path / "copy.xlsx", copies([(store, network)]))
    assert read_pages(str(tmp_path / "store.xlsx")) == read_pages(str(tmp_path / "copy.xlsx"))
    assert copy.subnets("another network") == [] and copy.addresses("another network") == []


def test_workbook_progress_goes_page_by_page_then_saves(tmp_path):
    store, network = sample(tmp_path)
    second = store.add_network("22CD NIPR")
    store.add_subnet(second.id, "172.16.0.0/24", "LAN")
    texts = []
    export_workbook(tmp_path / "all.xlsx", copies([(store, network), (store, second)]),
                    Progress(lambda done, total, text: texts.append(text)))
    assert any("page 1 of 2" in text for text in texts) and any("page 2 of 2" in text for text in texts)
    assert texts[-1] == "Saving the workbook..."


# --------------------------------------------------------------------- The progress dialog

def test_run_export_reports_the_result(app, tmp_path):
    parent, results = QWidget(), []

    def work(progress):
        progress.stage("Counting", 5)
        for _ in range(5):
            progress.step()
        return "done"

    run_export(parent, "Export Test", work, results.append, results.append, lambda: results.append("cancelled"))
    assert wait_for_exports() and results == ["done"] and not exports_running()
    parent.deleteLater()


def test_run_export_reports_an_error(app, tmp_path):
    parent, errors = QWidget(), []

    def work(progress):
        raise OSError(13, "Permission denied")

    run_export(parent, "Export Test", work, None, errors.append)
    assert wait_for_exports() and isinstance(errors[0], OSError)
    parent.deleteLater()


def test_cancel_stops_the_export_and_removes_its_file(app, tmp_path):
    parent, results = QWidget(), []
    path = tmp_path / "big.csv"
    started = threading.Event()

    def work(progress):
        progress.stage("Writing rows", 10_000_000)
        with saving(path) as temporary, open(temporary, "w") as file:
            while True:
                file.write("row\n")
                started.set()
                progress.step()

    run = run_export(parent, "Export Test", work, results.append, results.append,
                     lambda: results.append("cancelled"))
    assert started.wait(10)
    run.dialog.canceled.emit()  # As the Cancel button (or Esc) does
    assert wait_for_exports() and results == ["cancelled"]
    assert not os.listdir(tmp_path)
    parent.deleteLater()


# --------------------------------------------------------------------- The IP Addresses page's exports

@pytest.fixture
def tab(app, tmp_path):
    store, network = sample(tmp_path)
    page = IpamTab(Window())
    page.local_store, page.source, page.network_id = store, LOCAL, network.id
    page.fill_networks(f"{LOCAL}:{network.id}")
    yield page, store, network
    page.deleteLater()


def test_export_to_csv(tab, tmp_path, monkeypatch):
    page, store, network = tab
    path = str(tmp_path / "out.csv")
    monkeypatch.setattr(ipam_module.QFileDialog, "getSaveFileName", lambda *args, **kwargs: (path, ""))
    page.export_csv()
    assert wait_for_exports()
    text = open(path, encoding="utf-8-sig").read()
    assert text.startswith("Subnet,Subnet Name") and "pc5" in text and "aabb.ccdd.eeff" in text
    assert "Exported 11AB SIPR" in page.status_label.text()


def test_export_every_network_to_a_workbook(tab, tmp_path, monkeypatch):
    page, store, network = tab
    store.add_network("22CD NIPR")
    path = str(tmp_path / "all.xlsx")
    monkeypatch.setattr(ipam_module.QFileDialog, "getSaveFileName", lambda *args, **kwargs: (path, ""))
    page.export_workbook(every=True)
    assert wait_for_exports()
    assert [title for title, _ in read_pages(path)] == ["11AB SIPR", "22CD NIPR"]
    status = page.status_label.text()
    assert "Exported 2 networks" in status and "1 recorded address outside every subnet" in status


def test_a_failed_export_says_so(tab, tmp_path, monkeypatch):
    page, store, network = tab
    path = str(tmp_path / "out.csv")
    monkeypatch.setattr(ipam_module.QFileDialog, "getSaveFileName", lambda *args, **kwargs: (path, ""))

    def refuse(source, target):
        raise PermissionError(13, "The file is open in another program")

    monkeypatch.setattr(exporting, "replace_file", refuse)
    page.export_csv()
    assert wait_for_exports()
    assert "Couldn't save" in page.status_label.text() and "open in another program" in page.status_label.text()
    assert not [name for name in os.listdir(tmp_path) if name.startswith("out.csv")]  # No half file left behind
