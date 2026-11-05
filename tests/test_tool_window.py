"""Tools popped out of the main window to windows of their own, and back."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
from PyQt5.QtCore import QSettings, QSize, pyqtSignal
from PyQt5.QtWidgets import QApplication, QComboBox, QMainWindow, QMenu, QWidget

from nomad.ui.main_window import MainWindow
from nomad.ui.navigation import Navigator
from nomad.ui.tool_window import GEOMETRY_SETTING, OPEN_SETTING, ToolWindow


class Page(QWidget):
    def __init__(self):
        super().__init__()
        self.found = False

    def focus_find(self):
        self.found = True


class Main(QMainWindow):
    """The parts of MainWindow a tool window works with, using MainWindow's own pop-out code."""
    adapter_changed = pyqtSignal(object)
    snapshot_changed = pyqtSignal(object)
    pop_out_tool = MainWindow.pop_out_tool
    bring_back_tool = MainWindow.bring_back_tool
    tool_window_closed = MainWindow.tool_window_closed
    restore_tool_windows = MainWindow.restore_tool_windows
    is_page_showing = MainWindow.is_page_showing
    bring_to_front = MainWindow.bring_to_front

    def __init__(self, settings):
        super().__init__()
        self.settings = settings
        self.adapter_combo = QComboBox(self)
        self.adapter_combo.addItems(["Ethernet", "Wi-Fi"])
        self.adapter_combo.currentIndexChanged.connect(self.on_adapter_selected)
        self.navigator = Navigator(self)
        self.setCentralWidget(self.navigator)
        self.shown = []
        self.refreshes = 0
        self.pages = {}
        for title in ("Interfaces", "Ping", "Network Map", "Terminal"):
            self.pages[title] = Page()
            self.navigator.add_page(self.pages[title], title)
        self.navigator.fixed_pages = {self.pages["Terminal"]}
        self.navigator.popOutRequested.connect(self.pop_out_tool)
        self.navigator.bringBackRequested.connect(self.bring_back_tool)

    def on_adapter_selected(self, index):
        self.adapter_changed.emit(index)

    def page_shown(self, page):
        self.shown.append(page)

    def refresh(self):
        self.refreshes += 1


@pytest.fixture
def main(tmp_path):
    app = QApplication.instance() or QApplication([])
    window = Main(QSettings(str(tmp_path / "tools.ini"), QSettings.IniFormat))
    window.resize(900, 600)
    window.show()
    app.processEvents()
    yield window
    for tool in list(window.navigator.popped.values()):
        tool.closing_app = True
        tool.close()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_popping_out_moves_the_page_and_shows_another(main):
    nav, ping = main.navigator, main.pages["Ping"]
    nav.setCurrentWidget(nav.page_titled("Interfaces"))
    nav.setCurrentWidget(ping)
    nav.pop_out_current()
    window = nav.popped[ping]
    assert isinstance(window, ToolWindow) and window.isVisible()
    assert ping.window() is window and ping.isVisible()
    assert nav.stack.indexOf(ping) < 0
    assert nav.currentWidget() is main.pages["Interfaces"]  # The page used before it
    assert nav.title(nav.currentWidget()) == nav.page_title.text() == "Interfaces"
    assert window.windowTitle().startswith("Ping - ")
    assert main.is_page_showing(ping)


def test_links_to_a_popped_out_tool_bring_its_window_forward(main):
    nav, ping = main.navigator, main.pages["Ping"]
    main.pop_out_tool(ping)
    window = nav.popped[ping]
    window.showMinimized()
    nav.setCurrentWidget(ping)  # The other pages' Ping... links
    assert not window.isMinimized()
    assert nav.currentWidget() is main.pages["Interfaces"]
    nav.activate_title("Ping")  # The drawer and the rail
    assert nav.currentWidget() is main.pages["Interfaces"]
    nav.sidebar.setCurrentRow(nav._row_of(ping))  # Even a stray row change leaves the main window's page alone
    assert nav.currentWidget() is main.pages["Interfaces"]
    assert nav.sidebar.currentRow() == nav._row_of(main.pages["Interfaces"])
    titles = []
    for _ in range(3):  # Ctrl+Tab skips it
        nav.step(1)
        titles.append(nav.title(nav.currentWidget()))
    assert titles == ["Network Map", "Terminal", "Interfaces"]


def test_closing_the_window_puts_the_page_back_in_its_place(main):
    nav, ping = main.navigator, main.pages["Ping"]
    main.pop_out_tool(ping)
    main.pop_out_tool(main.pages["Interfaces"])
    nav.popped[ping].close()
    QApplication.processEvents()
    assert ping not in nav.popped
    assert nav.currentWidget() is ping and ping.window() is main
    nav.bringBackRequested.emit(main.pages["Interfaces"])  # Bring Back to the Main Window
    QApplication.processEvents()
    assert not nav.popped
    assert [nav.stack.widget(index) for index in range(nav.count())] == \
        [main.pages[title] for title in ("Interfaces", "Ping", "Network Map", "Terminal")]


def test_terminal_stays_in_the_main_window(main):
    nav, terminal = main.navigator, main.pages["Terminal"]
    nav.setCurrentWidget(terminal)
    assert nav.pop_button.isHidden()
    nav.pop_out_current()
    main.pop_out_tool(terminal)
    assert not nav.popped
    nav.setCurrentWidget(main.pages["Ping"])
    assert not nav.pop_button.isHidden()


def test_tool_menus_offer_pop_out_and_bring_back(main):
    nav, ping = main.navigator, main.pages["Ping"]
    menu = QMenu()
    nav.add_window_action(menu, ping)
    nav.add_window_action(menu, main.pages["Terminal"])
    assert [action.text() for action in menu.actions()] == ["Pop Out to a Window"]
    menu.actions()[0].trigger()
    assert ping in nav.popped
    menu = QMenu()
    nav.add_window_action(menu, ping)
    assert [action.text() for action in menu.actions()] == ["Bring Back to the Main Window"]
    assert "own window" in next(nav.favorite_list.item(row).toolTip() for row in range(nav.favorite_list.count())
                                if nav.favorite_list.item(row).data(256) == "Ping")


def test_the_adapter_picker_is_the_main_windows(main):
    main.pop_out_tool(main.pages["Ping"])
    window = main.navigator.popped[main.pages["Ping"]]
    assert window.adapter_combo.count() == 2
    window.adapter_combo.activated.emit(1)
    assert main.adapter_combo.currentIndex() == 1
    main.adapter_combo.setCurrentIndex(0)
    assert window.adapter_combo.currentIndex() == 0


def test_shortcuts_act_on_the_popped_out_page(main):
    page = main.pages["Network Map"]
    main.pop_out_tool(page)
    window = main.navigator.popped[page]
    actions = {action.text(): action for action in window.actions()}
    actions["Find on This Page"].trigger()
    assert page.found
    actions["Refresh"].trigger()
    assert main.refreshes == 1
    assert not actions["Run Current Tool"].isEnabled()  # A plain page: Shift+Enter stays the page's own
    actions["Back to Main Window"].trigger()
    QApplication.processEvents()
    assert page not in main.navigator.popped


def test_popped_out_tools_and_their_places_come_back_next_time(main):
    main.settings.setValue(OPEN_SETTING, ["Network Map", "No Such Tool"])
    main.restore_tool_windows()
    page = main.pages["Network Map"]
    assert list(main.navigator.popped) == [page]
    window = main.navigator.popped[page]
    window.setGeometry(120, 130, 1240, 520)
    window.close()
    QApplication.processEvents()
    assert main.settings.value(GEOMETRY_SETTING + "Network Map") is not None
    main.pop_out_tool(page)
    assert main.navigator.popped[page].size() == QSize(1240, 520)


def test_dialogs_over_the_main_window_open_over_the_tool_in_use(main):
    from PyQt5.QtWidgets import QDialog
    from nomad.ui.tool_window import DialogsFollowTools
    follow = DialogsFollowTools(main)
    QApplication.instance().installEventFilter(follow)
    page = main.pages["Network Map"]
    main.move(0, 0)
    main.pop_out_tool(page)
    window = main.navigator.popped[page]
    window.setGeometry(1500, 400, 1000, 600)
    window.activateWindow()
    QApplication.processEvents()
    if QApplication.activeWindow() is not window:
        pytest.skip("This platform plugin doesn't activate windows")
    dialog = QDialog(main)  # As the pages ask: QMessageBox.question(self.window, ...)
    dialog.resize(300, 200)
    dialog.show()
    assert (dialog.geometry().center() - window.frameGeometry().center()).manhattanLength() < 20
    dialog.close()
    main.activateWindow()
    QApplication.processEvents()
    if QApplication.activeWindow() is main:  # The main window in use: Qt's place, over it
        other = QDialog(main)
        other.show()
        assert main.frameGeometry().contains(other.geometry().center())
        other.close()
