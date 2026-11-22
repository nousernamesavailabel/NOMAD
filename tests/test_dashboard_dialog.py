"""NOMAD's side of the dashboard: Tools > NOMAD Dashboard Service, the map's Graph on Dashboard, and the Map Watcher's
monitoring settings."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import Qt  # noqa: E402
from PyQt5.QtWidgets import QApplication, QWidget  # noqa: E402

from nomad.dashboard import service as dashboard_service, tls  # noqa: E402
from nomad.dashboard.accounts import UserFile  # noqa: E402
from nomad.ipam import service as ipam_service  # noqa: E402
from nomad.ipam.client import TeamKey  # noqa: E402
from nomad.netmap import watch_monitor, watch_service  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Window(QWidget):
    admin = True


@pytest.fixture
def dialog(app, tmp_path, monkeypatch):
    from nomad.ui import dashboard_dialog
    monkeypatch.setattr(dashboard_service, "dashboard_dir", lambda: tmp_path)
    monkeypatch.setattr(dashboard_service, "status", lambda: ipam_service.NOT_INSTALLED)
    monkeypatch.setattr(ipam_service, "secure_service_folder", lambda directory: directory.mkdir(exist_ok=True))
    monkeypatch.setattr(ipam_service, "status", lambda spec=None: ipam_service.NOT_INSTALLED)
    monkeypatch.setattr(dashboard_dialog.DashboardDialog, "tribe_server_here", staticmethod(lambda: False))
    window = Window()
    shown = dashboard_dialog.DashboardDialog(window)
    yield shown
    shown.deleteLater()
    window.deleteLater()


def viewer_key():
    return TeamKey.from_dict({"format": 1, "server_id": "s", "hosts": ["tribe.example"], "port": 8443,
                              "fingerprint": "a" * 64, "secret": "viewer-secret", "role": "viewer"})


def test_install_waits_for_a_viewer_key_and_logins_are_kept_hashed(dialog, tmp_path, monkeypatch):
    assert not dialog.install_button.isEnabled()
    assert "No viewer key" in dialog.key_label.text()
    dialog.new_key = viewer_key()
    dialog.show_key()
    dialog.refresh()
    assert dialog.install_button.isEnabled() and "tribe.example" in dialog.key_label.text()
    assert dialog.change_logins(lambda: UserFile(tmp_path).add("alice", "correct horse"), "added")
    assert dialog.logins_table.rowCount() == 1 and dialog.logins_table.item(0, 0).text() == "alice"
    assert "correct horse" not in (tmp_path / "users.json").read_text()
    dialog.logins_table.selectRow(0)
    assert dialog.remove_button.isEnabled()
    installed = []
    monkeypatch.setattr(dashboard_service, "install", installed.append)
    monkeypatch.setattr("nomad.ui.dashboard_dialog.run_in_background",
                        lambda action, done, failed: (action(), done(None)))
    dialog.port_input.setValue(9443)
    dialog.install()
    [config] = installed
    assert config["port"] == 9443 and config["tribe"]["role"] == "viewer"
    assert config["tribe"]["secret"] != "viewer-secret"  # Encrypted for this computer
    assert dialog.new_key is None and dialog.tribe == config["tribe"]


def test_the_certificate_is_described(dialog, tmp_path):
    tls.make_self_signed(tmp_path)
    (tmp_path / "config.json").write_text("{}", encoding="utf-8")
    dialog.show_certificate()
    assert "Self-signed" in dialog.cert_label.text() and "SHA-256" in dialog.cert_label.text()


def test_an_imported_pem_certificate_must_match_its_key(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    tls.make_self_signed(first)
    tls.make_self_signed(second)
    chain, key = tls.load_import(first / "cert.pem", key_path=first / "key.pem")
    tls.check_pair(chain, key)
    with pytest.raises(tls.CertificateError, match="isn't the certificate's"):
        tls.load_import(first / "cert.pem", key_path=second / "key.pem")


def test_graph_on_dashboard_lists_ports_with_links_always_kept(app):
    from nomad.netmap.model import SNMP, SWITCH, Device, Link, NetworkMap
    from nomad.ui.graph_ports_dialog import GraphPortsDialog
    network_map = NetworkMap()
    network_map.devices = {"s1": Device("s1", "S1", "10.0.0.2", kind=SWITCH, source=SNMP,
                                        port_status={"Gi1/0/1": {"oper": "up"}, "Gi1/0/2": {"oper": "up"},
                                                     "Gi1/0/10": {"oper": "down"}}),
                           "s2": Device("s2", "S2", kind=SWITCH)}
    network_map.links = [Link("s1", "Gi1/0/1", "s2", "Gi0/1")]
    network_map.graphed = {"s1": ["Gi1/0/10"]}
    dialog = GraphPortsDialog(None, network_map, "s1")
    ports = [dialog.ports_list.item(row).data(Qt.UserRole) for row in range(dialog.ports_list.count())]
    assert ports == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/10"]
    assert not dialog.ports_list.item(0).flags() & Qt.ItemIsEnabled  # A link: always kept
    assert dialog.chosen() == ["Gi1/0/10"]
    dialog.ports_list.item(1).setCheckState(Qt.Checked)
    assert dialog.chosen() == ["Gi1/0/2", "Gi1/0/10"]
    dialog.filter_input.setText("10")
    assert dialog.ports_list.item(1).isHidden() and not dialog.ports_list.item(2).isHidden()
    dialog.deleteLater()


def test_the_watchers_config_carries_its_monitoring():
    key = TeamKey.from_dict({"format": 1, "server_id": "s", "hosts": ["h"], "port": 1, "fingerprint": "b" * 64,
                             "secret": "x"})
    config = watch_service.make_config(key, [3], protect=lambda text: text,
                                       monitoring={"interval": 120, "sweep_hours": 0})
    settings = watch_monitor.monitor_settings(config)
    assert settings["interval"] == 120 and settings["sweep_hours"] == 0 and settings["enabled"]
    older = dict(config)
    del older["monitor"]  # A config from before: monitoring on, with the defaults
    assert watch_monitor.monitor_settings(older) == watch_monitor.MONITOR_DEFAULTS
