"""The SNMP Config page: the form, the preview, saving its settings, the Network Map's credentials, and sending the
configuration into a terminal session."""
import ipaddress
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from PyQt5.QtCore import QSettings, Qt  # noqa: E402
from PyQt5.QtTest import QTest  # noqa: E402
from PyQt5.QtWidgets import QApplication, QDialog, QMessageBox, QWidget  # noqa: E402

from nomad.snmpv3 import V3User  # noqa: E402
from nomad.terminal.sessions import SSH, TELNET, Session  # noqa: E402
from nomad.ui import session_send, snmp_config_tab  # noqa: E402
from nomad.ui.snmp_config_tab import SnmpConfigTab  # noqa: E402
from nomad.ui.terminal_view import CONNECTED, DISCONNECTED  # noqa: E402

USER = V3User("nomad", "sha", "authpass1", "aes128", "privpass1")


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


class Adapter:
    ipv4 = [ipaddress.IPv4Interface("10.0.0.50/24"), ipaddress.IPv4Interface("169.254.1.1/16")]


class MapPage:
    def __init__(self):
        self.tried = ["public"]

    def credentials(self):
        return list(self.tried)

    def add_credential(self, credential):
        if credential in self.tried:
            return False
        self.tried.insert(0, credential)
        return True


class Model:
    def __init__(self, prompt):
        self.prompt = prompt

    def cursor_position(self):
        return type("Position", (), {"line": 0})()

    def line_text(self, line):
        return self.prompt


class View:
    def __init__(self, title, prompt="access-sw-02#"):
        self.title, self.state, self.model = title, CONNECTED, Model(prompt)
        self.sent = []

    def send_block(self, text, final_enter=True, min_delay=0):
        self.sent.append((text, min_delay))
        return self.state == CONNECTED


class Store:
    def __init__(self):
        self.sessions = [Session(name="core", protocol=SSH, host="10.0.0.1", username="admin", folder="HQ/IDF 1"),
                         Session(name="access-sw-09", protocol=SSH, host="10.0.0.9", username="admin"),
                         Session(name="old-router", protocol=TELNET, host="10.0.0.254")]


class Terminal:
    def __init__(self, views):
        self.views = views
        self.opened = []
        self.store = Store()

    def all_views(self):
        return list(self.views)

    def all_tabs(self):
        return []

    def open_address(self, address, protocol, use_saved=True):
        view = View(address, prompt="")
        self.opened.append((address, protocol, use_saved))
        self.views.append(view)
        return view

    def open_session(self, session):
        view = View(session.name, prompt="")
        self.opened.append(session.name)
        self.views.append(view)
        return view


class Window(QWidget):
    def __init__(self, views=()):
        super().__init__()
        self.netmap_tab = MapPage()
        self.terminal_tab = Terminal(list(views))
        self.shown = []

    def current_adapter(self):
        return Adapter()

    def show_terminal(self, then):
        self.shown.append("terminal")
        then()


@pytest.fixture
def page(app):
    page = SnmpConfigTab(Window([View("access-sw-02")]))
    page.community_input.setText("n0mad-RO")
    page.destinations_input.setText("10.0.0.50")
    return page


def test_preview_follows_the_form(page):
    assert "snmp-server community n0mad-RO RO NOMAD-SNMP" in page.lines
    assert " permit host 10.0.0.50" in page.lines  # Allowed to read: where traps go, by default
    assert page.send_button.isEnabled() and page.preview.toPlainText().startswith("configure terminal")
    page.ports_input.setText("Gi1/0/1 - 48")
    assert "interface range Gi1/0/1 - 48" in page.lines
    page.traps_group.setChecked(False)
    assert not any(line.startswith("snmp-server host") for line in page.lines)
    page.show_combo.setCurrentIndex(page.show_combo.findData("undo"))
    assert "no snmp-server community n0mad-RO" in page.lines


def test_problems_show_and_nothing_can_be_sent(page):
    page.destinations_input.setText("")
    assert page.lines == [] and not page.send_button.isEnabled() and not page.copy_button.isEnabled()
    assert "Add where traps and syslog" in page.status_label.text()


def test_v3_user_and_v3_traps(page):
    page.community_check.setChecked(False)
    page.set_v3_user(USER)
    page.trap_version_combo.setCurrentIndex(page.trap_version_combo.findData("v3"))
    assert page.v3_user() == USER
    assert "snmp-server user nomad NOMAD v3 auth sha authpass1 priv aes 128 privpass1 access NOMAD-SNMP" in page.lines
    assert "snmp-server host 10.0.0.50 version 3 priv nomad" in page.lines
    page.auth_combo.setCurrentIndex(page.auth_combo.findData("none"))
    assert not page.priv_combo.isEnabled() and page.v3_user().priv == "none"


def test_generated_secrets_are_valid(page):
    page.community_input.setText("")
    page.community_check.setChecked(True)
    page.v3_check.setChecked(True)
    page.community_input.setText(snmp_config_tab.secrets.token_urlsafe(12))
    page.generate_passwords()
    assert page.lines and page.show_passwords.isChecked()


def test_add_this_computer_offers_its_addresses(page):
    assert page.local_addresses() == ["10.0.0.50"]  # Not the link-local one
    page.destinations_input.setText("10.0.0.60")
    page.add_destination("10.0.0.50")
    page.add_destination("10.0.0.50")
    assert page.destinations_input.text() == "10.0.0.60 10.0.0.50"


def test_the_maps_credentials(page):
    other = V3User("branch", "sha256", "authpass2", "aes256", "privpass2")
    page.window.netmap_tab.tried = ["public", USER]
    page.window.netmap_tab.overrides = [("10.9.0.0/16", other), ("10.8.0.0/16", "branch-ro")]
    page.fill_map_community_menu()
    assert [action.text() for action in page.map_community_menu.actions()] == ["public", "branch-ro"]
    page.map_community_menu.actions()[1].trigger()
    assert page.community_check.isChecked() and page.community_input.text() == "branch-ro"
    page.fill_map_user_menu()
    users = page.map_user_menu.actions()
    assert [action.text() for action in users] == [USER.label, other.label]
    users[1].trigger()
    assert page.v3_check.isChecked() and page.v3_user() == other  # Its protocols and passwords too
    page.community_input.setText("n0mad-RO")
    page.set_v3_user(USER)
    page.add_to_map()
    assert page.window.netmap_tab.tried[0] == "n0mad-RO"
    assert "now tries community n0mad-RO first" in page.status_label.text()
    page.add_to_map()
    assert "already tries" in page.status_label.text()


def test_from_the_map_says_when_there_is_nothing(page):
    page.window.netmap_tab.tried = []
    page.fill_map_user_menu()
    page.fill_map_community_menu()
    for menu in (page.map_user_menu, page.map_community_menu):
        assert len(menu.actions()) == 1 and not menu.actions()[0].isEnabled()
    assert "no SNMPv3 users" in page.map_user_menu.actions()[0].text()


def test_prefill_from_the_watch_tab(page):
    page.prefill("10.0.0.70", USER)
    assert page.destinations_input.text() == "10.0.0.50 10.0.0.70"
    assert page.v3_user() == USER and page.trap_version_combo.currentData() == "v3"


def test_the_maps_credentials_all_at_once(page, monkeypatch):
    """Use the Map's Credentials: public is left out while there's anything else, those for subnets unless ticked."""
    other = V3User("branch", "sha256", "authpass2", "none")
    page.window.netmap_tab.tried = [USER, other, "public", "corp-ro", "lab-ro"]
    page.window.netmap_tab.overrides = [("10.8.0.0/16", "branch-ro"), ("10.9.0.0/16", USER)]
    entries = page.map_credential_entries()
    assert entries[-1] == ("branch-ro", "10.8.0.0/16") and len(entries) == 6  # USER isn't listed twice
    assert snmp_config_tab.default_choice(entries) == [USER, other, "corp-ro", "lab-ro"]
    assert snmp_config_tab.default_choice([("public", "")]) == ["public"]  # When it's all there is
    shown = []

    def exec_(dialog):
        shown.append([dialog.list.item(row).text() for row in range(dialog.list.count())])
        dialog.list.item(5).setCheckState(Qt.Checked)  # branch-ro, for its subnet
        return QDialog.Accepted
    monkeypatch.setattr(snmp_config_tab.MapCredentialsDialog, "exec_", exec_)
    page.choose_map_credentials()
    assert shown[0][2] == "Community public" and shown[0][5] == "Community branch-ro  (for 10.8.0.0/16)"
    assert page.community_input.text() == "corp-ro" and page.v3_user() == USER
    assert page.more_credentials == ["lab-ro", "branch-ro", other]
    assert not page.more_widget.isHidden() and "community lab-ro" in page.more_label.text()
    for line in ("snmp-server community corp-ro RO NOMAD-SNMP", "snmp-server community lab-ro RO NOMAD-SNMP",
                 "snmp-server community branch-ro RO NOMAD-SNMP",
                 "snmp-server user branch NOMAD v3 auth sha-2 256 authpass2 access NOMAD-SNMP",
                 "snmp-server user nomad NOMAD v3 auth sha authpass1 priv aes 128 privpass1 access NOMAD-SNMP"):
        assert line in page.lines
    assert "snmp-server community public RO NOMAD-SNMP" not in page.lines
    page.community_check.setChecked(False)  # The map's other community strings go with the box
    assert not any(line.startswith("snmp-server community") for line in page.lines)
    assert "community" not in page.more_label.text()
    page.community_check.setChecked(True)
    page.clear_more()
    assert page.more_widget.isHidden() and "snmp-server community lab-ro RO NOMAD-SNMP" not in page.lines


def test_only_users_from_the_map_send_v3_traps(page):
    page.use_map_credentials([USER])
    assert not page.community_check.isChecked() and page.trap_version_combo.currentData() == "v3"
    assert "snmp-server host 10.0.0.50 version 3 priv nomad" in page.lines
    page.use_map_credentials(["corp-ro"])
    assert not page.v3_check.isChecked() and page.trap_version_combo.currentData() == "v2c"


def test_the_map_without_credentials_says_so(page, monkeypatch):
    page.window.netmap_tab.tried = []
    said = []
    monkeypatch.setattr(QMessageBox, "information", lambda *args: said.append(args[2]))
    page.choose_map_credentials()
    assert "no SNMP credentials" in said[0]


def test_prefill_with_the_maps_credentials(page):
    page.window.netmap_tab.tried = [USER, "public", "corp-ro"]
    page.prefill("10.0.0.70", from_map=True)
    assert page.v3_user() == USER and page.community_input.text() == "corp-ro" and page.more_credentials == []
    assert "snmp-server community public RO NOMAD-SNMP" not in page.lines


def test_the_maps_other_credentials_are_kept_with_the_settings(page, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    page.use_map_credentials(["corp-ro", "lab-ro", USER, V3User("branch", "sha", "authpass2", "none")])
    page.save_settings(settings)
    settings.sync()
    assert "lab-ro" not in (tmp_path / "settings.ini").read_text(encoding="utf-8", errors="replace")
    other = SnmpConfigTab(Window())
    other.restore_settings(settings)
    assert other.more_credentials == page.more_credentials and other.lines == page.lines


def test_settings_round_trip_keeps_secrets_encrypted(page, tmp_path):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.IniFormat)
    page.set_v3_user(USER)
    page.location_input.setText("HQ IDF 2")
    page.trap_checks["config"].setChecked(True)
    page.save_settings(settings)
    settings.sync()
    text = (tmp_path / "settings.ini").read_text(encoding="utf-8", errors="replace")
    assert "privpass1" not in text and "n0mad-RO" not in text
    other = SnmpConfigTab(Window())
    other.restore_settings(settings)
    assert other.lines == page.lines


def test_send_to_a_session_at_the_enable_prompt(page, monkeypatch):
    view = page.window.terminal_tab.views[0]
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.Yes)
    page.fill_send_menu()
    labels = [action.text() for action in page.send_menu.actions()]
    assert labels[0] == "access-sw-02  (access-sw-02#)" and labels[-1] == "Open SSH Session"
    open_menu = page.send_menu.actions()[-1].menu()
    entries = [action.text() for action in open_menu.actions() if not action.isSeparator()]
    assert entries == ["New Session...", "HQ", "access-sw-09"]  # Saved SSH sessions in folders; not Telnet ones
    hq = next(action.menu() for action in open_menu.actions() if action.text() == "HQ")
    idf = hq.actions()[0].menu()
    assert hq.actions()[0].text() == "IDF 1" and [action.text() for action in idf.actions()] == ["core"]
    assert page.send_to(view)
    assert view.sent == [(page.text(), session_send.SEND_DELAY)]
    assert page.window.shown == ["terminal"]


def test_a_session_not_at_enable_is_warned_about(page, monkeypatch):
    view = View("access-sw-03", prompt="access-sw-03>")
    asked = []

    def exec_(box):
        asked.append((box.icon(), box.text()))
        return QMessageBox.No
    monkeypatch.setattr(QMessageBox, "exec_", exec_)
    assert not page.send_to(view)
    assert asked[0][0] == QMessageBox.Warning and "enable (#) prompt" in asked[0][1]
    assert view.sent == []


def test_a_session_opened_to_send_to_waits_for_its_prompt(page, monkeypatch, app):
    monkeypatch.setattr(session_send.QInputDialog, "getText", lambda *args, **kwargs: ("10.0.0.12", True))
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.Yes)
    page.open_new_session()
    terminal = page.window.terminal_tab
    assert terminal.opened == [("10.0.0.12", SSH, False)]  # A new session, not a saved one
    view = terminal.views[-1]
    QTest.qWait(700)
    assert view.sent == []  # No prompt yet
    view.model.prompt = "acc2#"
    QTest.qWait(1200)
    assert view.sent and page.waiting is None


def test_a_session_at_user_exec_is_not_sent_to(page, monkeypatch):
    monkeypatch.setattr(session_send.QInputDialog, "getText", lambda *args, **kwargs: ("10.0.0.13", True))
    page.open_new_session()
    view = page.window.terminal_tab.views[-1]
    view.model.prompt = "acc3>"
    QTest.qWait(1200)
    assert view.sent == [] and "type enable" in page.status_label.text() and page.waiting is None


def test_a_session_that_never_connects_gives_up(page, monkeypatch):
    monkeypatch.setattr(session_send.QInputDialog, "getText", lambda *args, **kwargs: ("10.0.0.14", True))
    page.open_new_session()
    view = page.window.terminal_tab.views[-1]
    view.state = DISCONNECTED
    QTest.qWait(1200)
    assert view.sent == [] and "didn't connect" in page.status_label.text()


@pytest.mark.parametrize("total, expected", [(1400, 960), (1300, 920), (1100, 800)])
def test_the_form_starts_with_room_to_spare(page, total, expected):
    """1.2 times the width it needs, leaving the preview at least MIN_PREVIEW (but never less than the form needs)."""
    page.form_scroll.setMinimumWidth(800)
    page.splitter.sizes = lambda: [total // 2, total - total // 2]
    given = []
    page.splitter.setSizes = given.append
    page.sized = False
    page.size_form()
    assert given == [[expected, total - expected]] and page.sized
    page.size_form()  # Once only: after that, where the user drags it stays
    assert len(given) == 1


def test_a_saved_session_is_opened_and_sent_to(page, monkeypatch):
    monkeypatch.setattr(QMessageBox, "exec_", lambda self: QMessageBox.Yes)
    page.open_saved(page.window.terminal_tab.store.sessions[1])
    view = page.window.terminal_tab.views[-1]
    assert page.window.terminal_tab.opened == ["access-sw-09"]
    view.model.prompt = "access-sw-09#"
    QTest.qWait(1200)
    assert view.sent and page.waiting is None
