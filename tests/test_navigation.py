"""Tool navigation preserves pages while search and favorites change."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
import pytest
from PyQt5.QtCore import QSettings, Qt
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import QApplication, QWidget
from nomad.ui.navigation import Navigator, NavigationDelegate, PAGE_ROLE, SECTION_ROLE

@pytest.fixture
def nav():
    app = QApplication.instance() or QApplication([])
    navigation = Navigator()
    navigation.resize(1000, 700)
    navigation.add_section("This Computer")
    navigation.add_page(QWidget(), "Interfaces")
    navigation.add_section("Diagnostics")
    navigation.add_page(QWidget(), "Ping")
    navigation.add_page(QWidget(), "iperf")
    navigation.show()
    app.processEvents()
    yield navigation
    navigation.close()
    navigation.deleteLater()
    app.processEvents()

def test_search_alias_and_activation(nav):
    original = nav.currentWidget()
    nav.open_search()
    nav.search.setText("bandwidth")
    assert [nav.sidebar.item(row).text() for row in nav.page_rows()
            if not nav.sidebar.item(row).isHidden()] == ["iperf"]
    nav.activate_first()
    assert nav.title(nav.currentWidget()) == "iperf"
    assert not nav.panel.isVisible()
    nav.activate_title("Interfaces")
    assert nav.currentWidget() is original

def test_favorites_settings_and_empty_list(nav, tmp_path):
    settings = QSettings(str(tmp_path / "navigation.ini"), QSettings.IniFormat)
    nav.favorites = ["Ping", "Interfaces"]
    nav.save_settings(settings)
    nav.favorites = []
    nav.restore_settings(settings)
    assert nav.favorites == ["Ping", "Interfaces"]
    assert nav.favorite_list.item(0).data(256) == "Ping"
    nav.toggle_favorite("Ping")
    nav.toggle_favorite("Interfaces")
    nav.save_settings(settings)
    nav.restore_settings(settings)
    assert nav.favorites == []

def test_focus_mode_and_pinned_drawer(nav):
    nav.set_sidebar_visible(True)
    nav.activate_title("Ping")
    assert nav.panel.isVisible()
    assert nav.content.layout().contentsMargins().left() == 360
    nav.set_navigation_hidden(True)
    assert not nav.panel.isVisible() and not nav.rail.isVisible()
    nav.set_navigation_hidden(False)
    assert nav.panel.isVisible() and nav.rail.isVisible()
    nav.dismiss_drawer()
    assert nav.content.layout().contentsMargins().left() == 0

def test_keyboard_cycle_does_not_follow_search_filter(nav):
    nav.search.setText("Ping")
    nav.step(1)
    assert nav.title(nav.currentWidget()) == "Ping"
    nav.step(1)
    assert nav.title(nav.currentWidget()) == "iperf"


def test_category_collapse_does_not_hide_search_results(nav):
    heading = nav.sidebar.item(0)
    nav.activate_item(heading)
    assert nav.sidebar.item(1).isHidden()
    nav.search.setText("adapter")
    assert not nav.sidebar.item(1).isHidden()
    nav.search.clear()
    assert nav.sidebar.item(1).isHidden()

def test_drag_order_persists(nav, tmp_path):
    nav.favorites = ["Interfaces", "Ping"]
    nav.rebuild_rail()
    model = nav.favorite_list.model()
    from PyQt5.QtCore import QModelIndex
    assert model.moveRows(QModelIndex(), 0, 1, QModelIndex(), 2)
    assert nav.favorites == ["Ping", "Interfaces"]
    settings = QSettings(str(tmp_path / "order.ini"), QSettings.IniFormat)
    nav.save_settings(settings)
    nav.restore_settings(settings)
    assert nav.favorites == ["Ping", "Interfaces"]

def test_outside_click_closes_drawer(nav):
    from PyQt5.QtCore import Qt
    from PyQt5.QtTest import QTest
    nav.open_drawer()
    QTest.mouseClick(nav.currentWidget(), Qt.LeftButton)
    assert not nav.panel.isVisible()


@pytest.mark.parametrize("opening", ["shortcut", "mouse"])
@pytest.mark.parametrize("key", [Qt.Key_Return, Qt.Key_Enter])
def test_enter_opens_first_search_result(nav, opening, key):
    nav.add_page(QWidget(), "Traceroute")
    nav.add_page(QWidget(), "Trace Details")
    nav.activateWindow()
    QApplication.processEvents()
    if opening == "shortcut":
        QTest.keyClick(nav, Qt.Key_K, Qt.ControlModifier)
    else:
        QTest.mouseClick(nav.pages_button, Qt.LeftButton)
    assert nav.panel.isVisible()
    assert QApplication.focusWidget() is nav.search
    QTest.keyClicks(nav.search, "trace")
    QTest.keyClick(nav.search, key)
    assert nav.title(nav.currentWidget()) == "Traceroute"
    assert not nav.panel.isVisible()


def test_enter_uses_first_visible_tool_in_drawer_order(nav):
    nav.favorites = ["Ping", "Interfaces"]
    nav.open_drawer()
    QTest.keyClick(nav.search, Qt.Key_Return)
    assert nav.title(nav.currentWidget()) == "Ping"
    nav.open_drawer()
    # Clicking a header focuses the list; Enter should still open its first tool.
    QTest.mouseClick(nav.drawer_list.viewport(), Qt.LeftButton,
                     pos=nav.drawer_list.visualItemRect(nav.drawer_list.item(0)).center())
    QTest.keyClick(nav.drawer_list, Qt.Key_Return)
    assert nav.title(nav.currentWidget()) == "Ping"  # First Recent item
    assert not nav.panel.isVisible()


@pytest.mark.parametrize("section", ["Favorites", "Recent"])
def test_quick_headers_share_theme_and_collapse_independently(nav, section):
    nav.open_drawer()
    assert isinstance(nav.drawer_list.itemDelegate(), NavigationDelegate)
    assert isinstance(nav.sidebar.itemDelegate(), NavigationDelegate)
    original = nav.currentWidget()

    def heading():
        return next(nav.drawer_list.item(row) for row in range(nav.drawer_list.count())
                    if nav.drawer_list.item(row).data(SECTION_ROLE) == section)

    def section_pages():
        pages, current = [], None
        for row in range(nav.drawer_list.count()):
            item = nav.drawer_list.item(row)
            if item.data(PAGE_ROLE) is None:
                current = item.data(SECTION_ROLE)
            elif current == section:
                pages.append(item.text())
        return pages

    expanded = section_pages()
    assert expanded
    QTest.mouseClick(nav.drawer_list.viewport(), Qt.LeftButton,
                     pos=nav.drawer_list.visualItemRect(heading()).center())
    assert not section_pages()
    assert nav.currentWidget() is original
    assert nav.panel.isVisible()
    assert section in nav.collapsed_sections
    assert ("Recent" if section == "Favorites" else "Favorites") not in nav.collapsed_sections
    nav.search.setText("adapter")
    assert not nav.sidebar.item(1).isHidden()
    nav.search.clear()
    assert not section_pages()
    QTest.mouseClick(nav.drawer_list.viewport(), Qt.LeftButton,
                     pos=nav.drawer_list.visualItemRect(heading()).center())
    assert section_pages() == expanded


def test_enter_with_no_search_results_keeps_drawer_open(nav):
    original = nav.currentWidget()
    nav.open_search()
    nav.search.setText("no matching tool")
    QTest.keyClick(nav.search, Qt.Key_Return)
    assert nav.currentWidget() is original
    assert nav.panel.isVisible()


def test_drawer_sections_share_space_without_nested_scrolling(nav):
    nav.favorites = ["Interfaces", "Ping", "iperf"]
    nav.recent = ["iperf", "Ping", "Interfaces"]
    nav.open_drawer()
    QApplication.processEvents()
    listing = nav.drawer_list
    headers = [listing.item(row).data(SECTION_ROLE) for row in range(listing.count())
               if listing.item(row).data(PAGE_ROLE) is None]
    assert headers == ["Favorites", "Recent", "This Computer", "Diagnostics"]
    assert listing.verticalScrollBar().maximum() == 0
    last = listing.item(listing.count() - 1)
    assert listing.viewport().rect().contains(listing.visualItemRect(last))

    category = next(listing.item(row) for row in range(listing.count())
                    if listing.item(row).data(SECTION_ROLE) == "This Computer")
    expanded_top = listing.visualItemRect(category).top()
    for section in ("Favorites", "Recent"):
        heading = next(listing.item(row) for row in range(listing.count())
                       if listing.item(row).data(SECTION_ROLE) == section)
        QTest.mouseClick(listing.viewport(), Qt.LeftButton,
                         pos=listing.visualItemRect(heading).center())
    QApplication.processEvents()
    category = next(listing.item(row) for row in range(listing.count())
                    if listing.item(row).data(SECTION_ROLE) == "This Computer")
    assert listing.visualItemRect(category).top() < expanded_top
    assert listing.height() > nav.content.height() // 2
    assert listing.verticalScrollBar().maximum() == 0


def test_unified_drawer_category_click_preserves_page_and_cycle_order(nav):
    nav.open_drawer()
    item = next(nav.drawer_list.item(row) for row in range(nav.drawer_list.count())
                if nav.drawer_list.item(row).text() == "iperf")
    QTest.mouseClick(nav.drawer_list.viewport(), Qt.LeftButton,
                     pos=nav.drawer_list.visualItemRect(item).center())
    assert nav.title(nav.currentWidget()) == "iperf"
    nav.step(1)
    assert nav.title(nav.currentWidget()) == "Interfaces"
    assert nav.count() == 3


def test_escape_closes_the_drawer_without_taking_the_pages_escape(nav):
    nav.open_search()
    QTest.keyClick(nav.search, Qt.Key_Escape)
    assert not nav.drawer_open and not nav.panel.isVisible()
