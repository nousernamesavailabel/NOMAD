"""Tool navigation: favorites rail, searchable drawer, and persistent page stack."""
from PyQt5.QtCore import QEvent, QRect, QSize, Qt, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QFontMetrics, QIcon, QKeySequence, QPen
from PyQt5.QtWidgets import QAbstractItemView, QHBoxLayout, QListWidget, QListWidgetItem, QMenu, QShortcut, \
    QStackedWidget, QStyle, QStyledItemDelegate, QStyleOptionViewItem, QToolButton, QVBoxLayout, QWidget

from .theme import COLORS
from .tool_icons import tool_icon

PAGE_ROLE = Qt.UserRole
SECTION_ROLE = Qt.UserRole + 1  # A heading's name as written, before it is shown in capitals
ITEM_PADDING = 22 + 18 + 3 + 8  # Left and right padding and the selection bar (theme.py), plus breathing room
HEADER_PADDING = 12  # Left indent of a heading's text
HEADER_GAP = 10  # Space above each heading after the first, separating the sections
HEADER_MARGIN = 6  # Space above and below a heading's text inside its band


def header_font(base):
    """Headings: bold, slightly smaller capitals with a little letter spacing. Built from the list's own font, so
    they follow View > Text Size."""
    font = QFont(base)
    font.setBold(True)
    font.setPointSizeF(base.pointSizeF() * 0.9)
    font.setLetterSpacing(QFont.PercentageSpacing, 110)
    return font


def is_header(index):
    return index.data(PAGE_ROLE) is None


class NavigationDelegate(QStyledItemDelegate):
    """Draws section headings as shaded bands with a divider above; pages are drawn normally (styled by theme.py)."""

    def paint(self, painter, option, index):
        if not is_header(index):
            super().paint(painter, option, index)
            return
        painter.save()
        gap = HEADER_GAP if index.row() > 0 else 0
        band = QRect(option.rect.left(), option.rect.top() + gap, option.rect.width(), option.rect.height() - gap)
        painter.fillRect(band, QColor(COLORS["panel_alt"]))
        painter.setPen(QPen(QColor(COLORS["border"]), 1))
        painter.drawLine(band.topLeft(), band.topRight())
        painter.drawLine(band.bottomLeft(), band.bottomRight())
        painter.setFont(header_font(option.font))
        painter.setPen(QColor(COLORS["accent"]))
        text_rect = band.adjusted(HEADER_PADDING, 0, -4, 0)
        painter.drawText(text_rect, Qt.AlignVCenter | Qt.AlignLeft | Qt.TextWordWrap, index.data(Qt.DisplayRole))
        painter.restore()

    def sizeHint(self, option, index):
        if not is_header(index):
            return super().sizeHint(option, index)
        metrics = QFontMetrics(header_font(option.font))
        gap = HEADER_GAP if index.row() > 0 else 0
        available = max(80, self.parent().viewport().width() - HEADER_PADDING - 8)
        height = metrics.boundingRect(QRect(0, 0, available, 1000), Qt.TextWordWrap,
                                      index.data(Qt.DisplayRole)).height()
        return QSize(available + HEADER_PADDING + 8, height + 2 * HEADER_MARGIN + gap)


def navigation_button(text, tooltip):
    button = QToolButton()
    button.setObjectName("navigationButton")
    button.setText(text)
    button.setToolTip(tooltip)
    button.setAutoRaise(True)
    return button


class FavoriteIconDelegate(QStyledItemDelegate):
    """Center rail icons independently of text layout and platform list styling."""

    def paint(self, painter, option, index):
        styled = QStyleOptionViewItem(option)
        self.initStyleOption(styled, index)
        icon = QIcon(styled.icon)
        styled.icon = QIcon()
        styled.text = ""
        painter.save()
        styled.widget.style().drawControl(QStyle.CE_ItemViewItem, styled, painter, styled.widget)
        painter.restore()
        size = self.parent().iconSize()
        rect = QRect(0, 0, size.width(), size.height())
        rect.moveCenter(option.rect.center())
        mode = QIcon.Selected if option.state & QStyle.State_Selected else QIcon.Normal
        icon.paint(painter, rect, Qt.AlignCenter, mode)


class SidebarNavigator(QWidget):
    """A sidebar of pages under section headings. Offers the parts of QTabWidget's interface the app uses."""
    currentChanged = pyqtSignal(int)  # Index of the page in the stack
    sidebarToggled = pyqtSignal(bool)  # True when the sidebar is shown

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Shown while the sidebar is hidden: a menu of every page, and a button to bring the sidebar back
        self.rail = QWidget(self)
        self.rail.setObjectName("navigationRail")
        rail_layout = QVBoxLayout(self.rail)
        rail_layout.setContentsMargins(0, 2, 0, 2)
        rail_layout.setSpacing(2)
        self.pages_button = navigation_button("≡", "Go to a page")
        self.pages_menu = QMenu(self.pages_button)
        self.pages_menu.aboutToShow.connect(self.fill_pages_menu)
        self.pages_button.setMenu(self.pages_menu)
        self.pages_button.setPopupMode(QToolButton.InstantPopup)
        self.show_button = navigation_button("»", "Show the sidebar (Ctrl+B)")
        self.show_button.clicked.connect(lambda: self.set_sidebar_visible(True))
        rail_layout.addWidget(self.pages_button)
        rail_layout.addWidget(self.show_button)
        rail_layout.addStretch()
        self.rail.setVisible(False)

        self.panel = QWidget(self)
        self.panel.setObjectName("navigationPanel")
        panel_layout = QVBoxLayout(self.panel)
        panel_layout.setContentsMargins(0, 0, 0, 0)
        panel_layout.setSpacing(0)
        top_row = QHBoxLayout()
        top_row.setContentsMargins(0, 2, 2, 0)
        top_row.addStretch()
        self.hide_button = navigation_button("«", "Hide the sidebar for more room (Ctrl+B)")
        self.hide_button.clicked.connect(lambda: self.set_sidebar_visible(False))
        top_row.addWidget(self.hide_button)
        panel_layout.addLayout(top_row)

        self.sidebar = QListWidget(self.panel)
        self.sidebar.setObjectName("navigation")
        self.sidebar.setItemDelegate(NavigationDelegate(self.sidebar))
        self.sidebar.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.sidebar.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.sidebar.setSelectionMode(QAbstractItemView.SingleSelection)
        self.sidebar.installEventFilter(self)  # Resize to fit the names when the text size changes
        panel_layout.addWidget(self.sidebar, 1)

        self.stack = QStackedWidget(self)
        self.stack.setObjectName("pages")
        layout.addWidget(self.rail)
        layout.addWidget(self.panel)
        layout.addWidget(self.stack, 1)
        self.sidebar.currentRowChanged.connect(self._on_row_changed)

        for keys, step in ((("Ctrl+Tab", "Ctrl+PgDown"), 1), (("Ctrl+Shift+Tab", "Ctrl+PgUp"), -1)):
            for key in keys:
                shortcut = QShortcut(QKeySequence(key), self)
                shortcut.setContext(Qt.WindowShortcut)
                shortcut.activated.connect(lambda step=step: self.step(step))

    def add_section(self, title):
        item = QListWidgetItem(title.upper())
        item.setFlags(Qt.NoItemFlags)  # A heading: can't be selected, and arrow keys skip it
        item.setData(PAGE_ROLE, None)
        item.setData(SECTION_ROLE, title)
        self.sidebar.addItem(item)
        self.update_width()

    def add_page(self, widget, title):
        self.stack.addWidget(widget)
        item = QListWidgetItem(title)
        item.setIcon(tool_icon(title))
        item.setData(PAGE_ROLE, widget)
        self.sidebar.addItem(item)
        if self.sidebar.currentRow() < 0:
            self.sidebar.setCurrentItem(item)
        self.update_width()

    def update_width(self):
        """As wide as the longest name at the current text size, plus a scrollbar only if the list needs one."""
        metrics = self.sidebar.fontMetrics()
        headers = QFontMetrics(header_font(self.sidebar.font()))
        widths = [headers.horizontalAdvance(item.text()) + HEADER_PADDING + 8 if item.data(PAGE_ROLE) is None
                  else metrics.horizontalAdvance(item.text()) + ITEM_PADDING
                  for item in (self.sidebar.item(row) for row in range(self.sidebar.count()))]
        width = max(widths, default=0)
        content_height = sum(max(self.sidebar.sizeHintForRow(row), metrics.height())
                             for row in range(self.sidebar.count()))
        if content_height > self.sidebar.viewport().height() > 0:
            width += self.sidebar.style().pixelMetric(QStyle.PM_ScrollBarExtent)
        width += 2 * self.sidebar.frameWidth()
        if width != self.sidebar.width():
            self.sidebar.setFixedWidth(width)

    def eventFilter(self, watched, event):
        if watched is self.sidebar and event.type() in (QEvent.FontChange, QEvent.StyleChange, QEvent.Resize):
            self.update_width()
        return False

    # ----------------------------------------------------------------- Showing and hiding the sidebar

    def sidebar_visible(self):
        """The user's choice (kept while focus mode hides the navigation entirely)."""
        return getattr(self, "sidebar_shown", True)

    def set_sidebar_visible(self, visible):
        if visible == self.sidebar_visible():
            return
        self.sidebar_shown = visible
        self.apply_navigation()
        if visible and not self.navigation_hidden:
            self.sidebar.setFocus()
        self.sidebarToggled.emit(visible)

    navigation_hidden = False

    def set_navigation_hidden(self, hidden):
        """Hide the sidebar and its slim strip altogether (focus mode), without changing the user's choice."""
        self.navigation_hidden = hidden
        self.apply_navigation()

    def apply_navigation(self):
        shown = self.sidebar_visible()
        self.panel.setVisible(shown and not self.navigation_hidden)
        self.rail.setVisible(not shown and not self.navigation_hidden)

    def toggle_sidebar(self):
        self.set_sidebar_visible(not self.sidebar_visible())

    def fill_pages_menu(self):
        """The menu on the slim strip: every page under its section, with the current one ticked."""
        self.pages_menu.clear()
        current = self.currentWidget()
        for row in range(self.sidebar.count()):
            item = self.sidebar.item(row)
            widget = item.data(PAGE_ROLE)
            if widget is None:
                if not self.pages_menu.isEmpty():
                    self.pages_menu.addSeparator()
                heading = self.pages_menu.addAction(item.data(SECTION_ROLE))
                heading.setEnabled(False)
                font = QFont(self.pages_menu.font())
                font.setBold(True)
                heading.setFont(font)
                continue
            action = self.pages_menu.addAction(item.text(), lambda widget=widget: self.setCurrentWidget(widget))
            action.setCheckable(True)
            action.setChecked(widget is current)

    # ----------------------------------------------------------------- QTabWidget-like interface

    def setCurrentWidget(self, widget):
        row = self._row_of(widget)
        if row is not None:
            self.sidebar.setCurrentRow(row)

    def currentWidget(self):
        return self.stack.currentWidget()

    def widget(self, index):
        return self.stack.widget(index)

    def count(self):
        return self.stack.count()

    def title(self, widget):
        row = self._row_of(widget)
        return self.sidebar.item(row).text() if row is not None else ""

    def page_rows(self):
        return [row for row in range(self.sidebar.count()) if self.sidebar.item(row).data(PAGE_ROLE) is not None]

    def step(self, direction):
        """Move to the next (1) or previous (-1) page, wrapping around."""
        rows = self.page_rows()
        if not rows:
            return
        current = self.sidebar.currentRow()
        position = rows.index(current) if current in rows else 0
        self.sidebar.setCurrentRow(rows[(position + direction) % len(rows)])

    def _row_of(self, widget):
        return next((row for row in range(self.sidebar.count())
                     if self.sidebar.item(row).data(PAGE_ROLE) is widget), None)

    def _on_row_changed(self, row):
        item = self.sidebar.item(row)
        widget = item.data(PAGE_ROLE) if item is not None else None
        if widget is None:
            return
        self.stack.setCurrentWidget(widget)
        self.currentChanged.emit(self.stack.indexOf(widget))


class Navigator(SidebarNavigator):
    """Compact favorites rail and a searchable drawer over the current page."""

    def __init__(self, parent=None):
        from PyQt5.QtWidgets import QApplication, QCheckBox, QLabel, QLineEdit
        super().__init__(parent)
        self.favorites = ["Interfaces", "Terminal", "Network Map", "IP Addresses", "Ping"]
        self.recent = []
        self.drawer_open = False
        self.sidebar_shown = False
        self.sections = {}
        self.section = ""
        self.collapsed_sections = set()
        self.layout().removeWidget(self.panel)
        self.layout().removeWidget(self.stack)
        self.content = QWidget(self)
        content_layout = QVBoxLayout(self.content)
        content_layout.setContentsMargins(0, 0, 0, 0)
        self.page_title = QLabel()
        self.page_title.setContentsMargins(12, 6, 12, 6)
        content_layout.addWidget(self.page_title)
        content_layout.addWidget(self.stack, 1)
        self.layout().addWidget(self.content, 1)
        self.panel.setParent(self.content)
        self.panel.setMinimumWidth(320)
        self.panel.setObjectName("toolDrawer")
        drawer_title = QLabel("Tools")
        drawer_title.setContentsMargins(8, 4, 8, 4)
        self.panel.layout().itemAt(0).layout().insertWidget(0, drawer_title)
        self.pages_button.setMenu(None)
        self.pages_button.setPopupMode(QToolButton.DelayedPopup)
        self.pages_button.clicked.connect(self.open_drawer)
        self.pages_button.setToolTip("Tools (Ctrl+K)")
        self.pages_button.setText("")
        self.pages_button.setIcon(tool_icon("tools"))
        self.pages_button.setIconSize(QSize(24, 24))
        self.pages_button.setFixedSize(52, 44)
        self.pages_button.setAccessibleName("Open tools")
        self.show_button.hide()
        self.rail.setFixedWidth(56)
        self.favorite_list = QListWidget()
        self.favorite_list.setObjectName("favoriteRail")
        self.favorite_list.setIconSize(QSize(24, 24))
        self.favorite_list.setItemDelegate(FavoriteIconDelegate(self.favorite_list))
        self.sidebar.setIconSize(QSize(20, 20))
        self.favorite_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.favorite_list.setDragDropMode(QAbstractItemView.InternalMove)
        self.favorite_list.itemClicked.connect(lambda item: self.activate_title(item.data(Qt.UserRole)))
        self.favorite_list.model().rowsMoved.connect(self.favorites_moved)
        self.favorite_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.favorite_list.customContextMenuRequested.connect(self.rail_menu)
        self.rail.layout().insertWidget(1, self.favorite_list, 1)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Find a tool... (Ctrl+K)")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.fill_drawer)
        self.search.returnPressed.connect(self.activate_first)
        self.panel.layout().insertWidget(1, self.search)
        # Keep the original sidebar as the page registry for stack navigation.
        # The drawer shows favorites, recents, and categories in one shared viewport.
        self.panel.layout().removeWidget(self.sidebar)
        self.sidebar.hide()
        self.drawer_list = QListWidget(self.panel)
        self.drawer_list.setObjectName("navigation")
        self.drawer_list.setItemDelegate(NavigationDelegate(self.drawer_list))
        self.drawer_list.setIconSize(QSize(20, 20))
        self.drawer_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.drawer_list.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.drawer_list.itemClicked.connect(self.activate_item)
        self.panel.layout().insertWidget(2, self.drawer_list, 1)
        self.drawer_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.drawer_list.customContextMenuRequested.connect(
            lambda pos: self.pin_menu(self.drawer_list, pos))
        self.keep_open = QCheckBox("Keep drawer open")
        self.keep_open.toggled.connect(self.set_sidebar_visible)
        self.panel.layout().addWidget(self.keep_open)
        self.hide_button.clicked.disconnect()
        self.hide_button.clicked.connect(self.dismiss_drawer)
        self.hide_button.setToolTip("Close tool drawer")
        self.hide_button.setText("")
        self.hide_button.setIcon(tool_icon("close"))
        self.hide_button.setIconSize(QSize(20, 20))
        self.hide_button.setAccessibleName("Close tool drawer")
        self.content.installEventFilter(self)
        QApplication.instance().installEventFilter(self)
        shortcut = QShortcut(QKeySequence("Ctrl+K"), self)
        shortcut.setContext(Qt.WindowShortcut)
        shortcut.activated.connect(self.open_search)
        # Escape closes the drawer in eventFilter, not by a window-wide shortcut: one would make the pages' own Esc
        # shortcuts (the map's Show All, find bars) ambiguous, and then neither fires
        self.apply_navigation()

    def add_section(self, title):
        self.section = title
        super().add_section(title)
        item = self.sidebar.item(self.sidebar.count() - 1)
        item.setFlags(Qt.ItemIsEnabled)
        if title.startswith("Diagnostics:"):
            item.setText("DIAGNOSTICS: " + ("CONNECTIVITY" if "Connectivity" in title else "DNS & WEB"))
        item.setToolTip(title + " — click to expand or collapse")

    def add_page(self, widget, title):
        self.sections[title] = self.section
        super().add_page(widget, title)
        self.rebuild_rail()

    def update_width(self):
        if hasattr(self, "content"):
            self.sidebar.setFixedWidth(360)
        else:
            super().update_width()

    def position_drawer(self):
        self.sidebar.setFixedWidth(min(360, self.content.width()))
        self.panel.setGeometry(0, 0, min(360, self.content.width()), self.content.height())
        self.panel.raise_()

    def eventFilter(self, watched, event):
        if hasattr(self, "content"):
            if (event.type() == QEvent.KeyPress and event.key() in (Qt.Key_Return, Qt.Key_Enter)
                    and self.panel.isVisible() and isinstance(watched, QWidget)
                    and (watched is self.panel or self.panel.isAncestorOf(watched))):
                self.activate_first()
                return True
            if (event.type() == QEvent.KeyPress and event.key() == Qt.Key_Escape and self.drawer_open
                    and not self.sidebar_visible() and isinstance(watched, QWidget)
                    and watched.window() is self.window()):
                self.close_drawer()  # Only reached when no page shortcut took the Escape
                return True
            if watched is self.content and event.type() == QEvent.Resize:
                self.position_drawer()
            if event.type() == QEvent.MouseButtonPress and self.drawer_open and not self.sidebar_visible():
                if isinstance(watched, QWidget) and watched.window() is self.window():
                    point = self.panel.mapFromGlobal(event.globalPos())
                    if not self.panel.rect().contains(point) and watched is not self.pages_button:
                        self.close_drawer()
        return super().eventFilter(watched, event)

    def apply_navigation(self):
        if not hasattr(self, "content"):
            return super().apply_navigation()
        self.rail.setVisible(not self.navigation_hidden)
        self.panel.setVisible((self.drawer_open or self.sidebar_visible()) and not self.navigation_hidden)
        self.page_title.setVisible(not self.navigation_hidden)
        self.content.layout().setContentsMargins(360 if self.sidebar_visible() and not self.navigation_hidden else 0, 0, 0, 0)
        self.position_drawer()

    def set_sidebar_visible(self, visible):
        self.sidebar_shown = bool(visible)
        self.drawer_open = bool(visible)
        self.keep_open.blockSignals(True)
        self.keep_open.setChecked(bool(visible))
        self.keep_open.blockSignals(False)
        self.fill_drawer()
        self.apply_navigation()
        self.sidebarToggled.emit(bool(visible))

    def open_drawer(self):
        self.drawer_open = True
        self.fill_drawer()
        self.apply_navigation()
        self.search.setFocus()

    def open_search(self):
        self.open_drawer()
        self.search.setFocus()
        self.search.selectAll()

    def close_drawer(self):
        if not self.sidebar_visible():
            self.drawer_open = False
            self.apply_navigation()

    def dismiss_drawer(self):
        self.set_sidebar_visible(False)

    def activate_title(self, title):
        for row in self.page_rows():
            item = self.sidebar.item(row)
            if item.text() == title:
                self.activate_item(item)
                return

    def activate_item(self, item):
        if item.data(PAGE_ROLE) is None:
            section = item.data(SECTION_ROLE)
            if section:
                if section in self.collapsed_sections:
                    self.collapsed_sections.remove(section)
                else:
                    self.collapsed_sections.add(section)
                self.fill_drawer()
            return
        if item.data(PAGE_ROLE) is not None:
            self.setCurrentWidget(item.data(PAGE_ROLE))
            self.close_drawer()
            self.stack.currentWidget().setFocus()

    def activate_first(self):
        for row in range(self.drawer_list.count()):
            item = self.drawer_list.item(row)
            if item.data(PAGE_ROLE) is not None and not item.isHidden():
                self.activate_item(item)
                return

    def fill_drawer(self):
        query = self.search.text().strip().casefold()
        aliases = {"iperf": "bandwidth throughput", "SCP": "file transfer ssh", "RDP": "remote desktop mstsc windows",
                   "TFTP": "file transfer firmware",
                   "Network Map": "topology snmp", "Interfaces": "adapter nic ip configuration",
                   "ARP": "neighbors mac",
                   "MAC Finder": "mac address table locate trace switch port find where plugged", "Ports": "scan tcp", "DNS Servers": "dns benchmark",
                   "Ansible Inventory": "ansible playbook hosts yaml ini export automation"}
        self.drawer_list.clear()
        if not query:
            for heading, titles in (("Favorites", self.favorites), ("Recent", self.recent)):
                header = QListWidgetItem(heading.upper())
                header.setFlags(Qt.ItemIsEnabled)
                header.setData(SECTION_ROLE, heading)
                header.setToolTip(heading + " — click to expand or collapse")
                self.drawer_list.addItem(header)
                if heading in self.collapsed_sections:
                    continue
                for title in titles:
                    for row in self.page_rows():
                        source = self.sidebar.item(row)
                        if source.text() == title:
                            item = QListWidgetItem(title)
                            item.setIcon(source.icon())
                            item.setData(PAGE_ROLE, source.data(PAGE_ROLE))
                            self.drawer_list.addItem(item)
        heading, visible = None, False
        for row in range(self.sidebar.count()):
            item = self.sidebar.item(row)
            if item.data(PAGE_ROLE) is None:
                if heading is not None:
                    heading.setHidden(not visible)
                heading, visible = item, False
            else:
                match = query in (item.text() + " " + self.sections[item.text()] + " " + aliases.get(item.text(), "")).casefold()
                item.setHidden(not match or (not query and self.sections[item.text()] in self.collapsed_sections))
                visible |= match
        if heading is not None:
            heading.setHidden(not visible)
        for row in range(self.sidebar.count()):
            source = self.sidebar.item(row)
            if not source.isHidden():
                self.drawer_list.addItem(QListWidgetItem(source))
        self.position_drawer()

    def rebuild_rail(self):
        self.favorite_list.clear()
        for title in self.favorites:
            if title not in self.sections:
                continue
            item = QListWidgetItem(tool_icon(title), "")
            item.setData(Qt.UserRole, title)
            item.setData(Qt.AccessibleTextRole, title)
            item.setToolTip(title + " — drag to reorder; right-click to unpin")
            item.setTextAlignment(Qt.AlignCenter)
            item.setSizeHint(QSize(48, max(44, self.fontMetrics().height() + 16)))
            self.favorite_list.addItem(item)
            if title == self.title(self.currentWidget()):
                self.favorite_list.setCurrentItem(item)

    def favorites_moved(self, *args):
        self.favorites = [self.favorite_list.item(i).data(Qt.UserRole) for i in range(self.favorite_list.count())]
        self.fill_drawer()

    def toggle_favorite(self, title):
        if title in self.favorites:
            self.favorites.remove(title)
        else:
            self.favorites.append(title)
        self.rebuild_rail()
        self.fill_drawer()

    def pin_menu(self, listing, pos):
        item = listing.itemAt(pos)
        if item is None or item.data(PAGE_ROLE) is None:
            return
        title = self.title(item.data(PAGE_ROLE))
        menu = QMenu(self)
        menu.addAction("Unpin from Favorites" if title in self.favorites else "Pin to Favorites",
                       lambda: self.toggle_favorite(title))
        menu.exec_(listing.mapToGlobal(pos))

    def rail_menu(self, pos):
        item = self.favorite_list.itemAt(pos)
        if item is not None:
            title = item.data(Qt.UserRole)
            menu = QMenu(self)
            menu.addAction("Unpin " + title, lambda: self.toggle_favorite(title))
            menu.exec_(self.favorite_list.mapToGlobal(pos))

    def restore_settings(self, settings):
        favorites = settings.value("navigation/favorites", self.favorites)
        if isinstance(favorites, str):
            favorites = [favorites]
        self.favorites = list(dict.fromkeys(title for title in favorites if title in self.sections))
        recent = settings.value("navigation/recent", [])
        if isinstance(recent, str):
            recent = [recent]
        self.recent = [title for title in recent if title in self.sections][:5]
        self.rebuild_rail()
        self.set_sidebar_visible(settings.value("navigation/keep_open", False, bool))

    def save_settings(self, settings):
        settings.setValue("navigation/favorites", self.favorites)
        settings.setValue("navigation/recent", self.recent)
        settings.setValue("navigation/keep_open", self.sidebar_visible())

    def _on_row_changed(self, row):
        super()._on_row_changed(row)
        if hasattr(self, "page_title"):
            title = self.title(self.currentWidget())
            self.page_title.setText(title)
            self.recent = [title] + [name for name in self.recent if name != title][:4]
            self.rebuild_rail()
