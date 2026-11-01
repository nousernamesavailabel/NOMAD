"""Network Map icons locked in place: nothing moves them, they're marked, and they last."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402
from netmap_fakes import build_network  # noqa: E402
from PyQt5.QtCore import QEvent, QPointF, QRectF, Qt  # noqa: E402
from PyQt5.QtGui import QColor, QImage, QMouseEvent, QPainter  # noqa: E402
from PyQt5.QtWidgets import QApplication, QGraphicsItem, QMenu  # noqa: E402
from test_ipam_server import key_for, server, small_map, tribe_maps  # noqa: E402,F401
from test_netmap_tab import Window  # noqa: E402

from nomad.ipam.client import LOCK_API, TeamClient  # noqa: E402
from nomad.ipam.store import IpamError  # noqa: E402
from nomad.netmap import shared, store  # noqa: E402
from nomad.netmap.crawl import CrawlSettings, Crawler  # noqa: E402
from nomad.netmap.layout import COMPACT, HORIZONTAL, LEFT, NODE_HEIGHT, NODE_WIDTH, SPACIOUS, TOP_DOWN, \
    clear_of  # noqa: E402
from nomad.netmap.model import NetworkMap  # noqa: E402
from nomad.ui import netmap_tab  # noqa: E402
from nomad.ui.netmap_key import device  # noqa: E402
from nomad.ui.netmap_view import DeviceItem, SimpleNodeItem  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def crawl():
    network = build_network()
    return Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                   client_factory=network.client, pinger=network.ping, echo=network.echo).run()


@pytest.fixture
def crawled():
    return crawl()


@pytest.fixture
def tab(app, tmp_path, monkeypatch):
    monkeypatch.setattr(store, "maps_dir", lambda: tmp_path)
    page = netmap_tab.NetworkMapTab(Window())
    page.resize(1200, 800)
    yield page
    page.shutdown()


def shown(tab, crawled, app):
    tab.setParent(None)  # Its window is never shown, and Qt only passes the mouse to a view that is
    tab.on_crawled(crawled)
    tab.show()
    tab.tabs.setCurrentWidget(tab.view)
    tab.view.resetTransform()
    for _ in range(3):
        app.processEvents()
    return tab.view


def where(view):
    return {key: tuple(position) for key, position in view.positions().items()}


def drag(view, start, end):
    """Press, move and release the left button as a real drag does. The scene finds the item under the mouse by the
    event's screen position, so unlike test_netmap_tab's drag (for the background) this gives one."""
    viewport = view.viewport()
    for kind, point, buttons in ((QEvent.MouseButtonPress, start, Qt.LeftButton),
                                 (QEvent.MouseMove, (start + end) / 2, Qt.LeftButton),
                                 (QEvent.MouseMove, end, Qt.LeftButton),
                                 (QEvent.MouseButtonRelease, end, Qt.NoButton)):
        QApplication.sendEvent(viewport, QMouseEvent(kind, QPointF(point), QPointF(viewport.mapToGlobal(point)),
                                                     Qt.LeftButton, buttons, Qt.NoModifier))


def drag_item(view, item, by=QPointF(150, 90)):
    view.centerOn(item)
    start = view.mapFromScene(item.pos())
    drag(view, start, view.mapFromScene(item.pos() + by))


def device_menu(tab, view, key):
    """What the lock actions on a device's right-click menu say, and do."""
    menu, actions = QMenu(), {}
    selected = view.selected_keys()
    tab.add_lock_actions(menu, actions, view, selected if key in selected else [key])
    return {action.text(): run for action, run in actions.items()}


# --------------------------------------------------------------------- Dragging

def test_a_locked_icon_cant_be_dragged_and_says_why(tab, crawled, app):
    view = shown(tab, crawled, app)
    item = view.items_by_key["core"]
    start = view.positions()["core"]
    clear_space = QPointF(-300, -200)  # So it isn't dropped on another, which the next press would find instead
    drag_item(view, item, clear_space)
    assert view.positions()["core"] != start  # This drag does move an unlocked one
    tab.set_locked(view, ["core"], True)
    assert not item.flags() & QGraphicsItem.ItemIsMovable
    before = where(view)
    drag_item(view, item, clear_space)
    assert where(view) == before
    assert f"{item.label} is locked in place" in tab.status_label.text()
    assert item.isSelected()  # Still selected like any other
    tab.set_locked(view, ["core"], False)
    drag_item(view, item, clear_space)
    assert view.positions()["core"] != before["core"]
    tab.hide()


def test_dragging_a_selection_leaves_the_locked_ones(tab, crawled, app):
    view = shown(tab, crawled, app)
    tab.set_locked(view, ["acc1"], True)
    view.items_by_key["core"].setSelected(True)
    view.items_by_key["acc1"].setSelected(True)
    before = where(view)
    drag_item(view, view.items_by_key["core"])
    assert view.positions()["acc1"] == before["acc1"]
    assert view.positions()["core"] != before["core"]

    before = where(view)  # Started on the locked one: nothing goes
    drag_item(view, view.items_by_key["acc1"])
    assert where(view) == before
    tab.hide()


def test_a_click_on_a_locked_icon_says_nothing(tab, crawled, app):
    view = shown(tab, crawled, app)
    tab.set_locked(view, ["core"], True)
    message = tab.status_label.text()
    item = view.items_by_key["core"]
    view.centerOn(item)
    point = view.mapFromScene(item.pos())
    drag(view, point, point)
    assert tab.status_label.text() == message and item.isSelected()
    tab.hide()


# --------------------------------------------------------------------- Groups

def grouped(tab, crawled):
    tab.on_crawled(crawled)
    network_map = tab.network_map
    room = network_map.new_group("Closet")
    network_map.set_group(["acc1", "acc2"], room.key)
    tab.groups_edited()
    return room.key, tab.view.group_items[room.key]


def test_dragging_a_group_leaves_a_locked_member_inside_its_box(tab, crawled):
    key, item = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, ["acc1"], True)
    before = where(view)
    view.move_group(item, QPointF(400, 0))
    view.update_groups()
    assert view.positions()["acc1"] == before["acc1"]
    assert view.positions()["acc2"][0] == before["acc2"][0] + 400
    assert item.rect.contains(view.items_by_key["acc1"].sceneBoundingRect())  # The box stretches round it
    assert tab.network_map.group_of["acc1"] == key


def test_a_selected_group_dragged_by_its_title_leaves_a_locked_member(tab, crawled):
    _, item = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, ["acc1"], True)
    item.setSelected(True)
    before = where(view)
    view.move_selection(QPointF(0, 300))
    assert view.positions()["acc1"] == before["acc1"]
    assert view.positions()["acc2"][1] == before["acc2"][1] + 300


def test_a_group_selected_with_a_dragged_device_leaves_a_locked_member(tab, crawled):
    _, item = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, ["acc1"], True)
    item.setSelected(True)
    core = view.items_by_key["core"]
    core.setSelected(True)
    view.begin_node_drag(core)
    assert view.items_by_key["acc1"] not in view.drag["carried"]
    assert view.items_by_key["acc2"] in view.drag["carried"]
    view.end_node_drag()


def test_a_locked_device_is_left_out_of_a_drag_into_a_group(tab, crawled):
    key, _ = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, ["core"], True)
    core = view.items_by_key["core"]
    other = next(item for name, item in view.items_by_key.items() if name not in ("core", "acc1", "acc2"))
    core.setSelected(True)
    other.setSelected(True)
    view.begin_node_drag(other)
    assert core not in view.drag["moving"] and other in view.drag["moving"]
    view.end_node_drag()


def test_group_menu_locks_and_unlocks_its_devices(tab, crawled):
    key, _ = grouped(tab, crawled)
    tab.set_locked(tab.view, tab.network_map.members(key), True)
    assert tab.network_map.locked == ["acc1", "acc2"]
    tab.set_locked(tab.view, ["acc2"], False)
    assert tab.view.locked_keys() == ["acc1"]


# --------------------------------------------------------------------- Arranging

def test_rearrange_works_round_a_locked_icon(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    tab.tabs.setCurrentWidget(view)
    view.items_by_key["core"].setPos(0, 0)
    tab.set_locked(view, ["core"], True)
    tab.rearrange(TOP_DOWN)
    assert view.items_by_key["core"].pos() == QPointF(0, 0)
    assert tab.network_map.positions["core"] == (0, 0)
    assert view.items_by_key["core"].locked  # Drawn again, still locked
    for key, (x, y) in view.positions().items():
        if key != "core":  # Nothing's landed on it
            assert abs(x) >= NODE_WIDTH or abs(y) >= NODE_HEIGHT


def test_put_at_the_top_keeps_a_locked_icon(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    view.items_by_key["acc1"].setPos(4000, 4000)
    tab.set_locked(view, ["acc1"], True)
    tab.put_at_top("core")
    assert view.positions()["acc1"] == (4000, 4000)


def test_arrange_selected_and_spacing_leave_locked_ones(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    keys = list(view.items_by_key)
    tab.set_locked(view, ["acc1"], True)
    before = view.positions()["acc1"]
    tab.arrange_selected(view, keys, style=TOP_DOWN)
    assert view.positions()["acc1"] == before
    tab.space_out(view, keys, (), netmap_tab.NORMAL)
    assert view.positions()["acc1"] == before


def test_align_and_distribute_leave_locked_ones(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    keys = list(view.items_by_key)
    tab.set_locked(view, ["acc1"], True)
    before = view.positions()["acc1"]
    tab.align_selected(view, keys, LEFT)
    assert view.positions()["acc1"] == before
    tab.align_selected(view, keys, HORIZONTAL)
    assert view.positions()["acc1"] == before


def test_the_rest_line_up_with_a_locked_icon(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    view.items_by_key["acc1"].setPos(500, 0)
    view.items_by_key["acc2"].setPos(0, 300)
    tab.set_locked(view, ["acc1"], True)
    tab.align_selected(view, ["acc1", "acc2"], LEFT)  # acc2 was further left, but acc1 can't go to it
    assert view.positions()["acc1"] == (500, 0)
    assert view.positions()["acc2"] == (500, 300)


def test_arranging_keeps_the_arrangement_round_a_locked_icon(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    keys = ["core", "acc1", "acc2"]
    view.items_by_key["acc2"].setPos(3000, 3000)
    tab.set_locked(view, ["acc2"], True)
    tab.arrange_selected(view, keys, style=TOP_DOWN)
    placed = view.positions()
    assert placed["acc2"] == (3000, 3000)
    assert abs(placed["core"][0] - 3000) < 1000 and abs(placed["core"][1] - 3000) < 1000  # Came to it


def test_spacing_two_with_one_locked_moves_the_other(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    view.items_by_key["acc1"].setPos(0, 0)
    view.items_by_key["acc2"].setPos(400, 0)
    tab.set_locked(view, ["acc1"], True)
    tab.space_out(view, ["acc1", "acc2"], (), SPACIOUS)
    wide = view.positions()["acc2"][0]
    tab.space_out(view, ["acc1", "acc2"], (), COMPACT)
    assert view.positions()["acc1"] == (0, 0)  # The locked one stays, and the other goes to each spacing's distance
    assert view.positions()["acc2"][0] < wide


def test_all_selected_locked_nothing_moves(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    keys = ["core", "acc1"]
    tab.set_locked(view, keys, True)
    before = where(view)
    tab.arrange_selected(view, keys, style=TOP_DOWN)
    tab.align_selected(view, keys, LEFT)
    tab.space_out(view, keys, (), netmap_tab.NORMAL)
    assert where(view) == before


def test_a_group_with_only_locked_devices_stays_when_arranged(tab, crawled):
    key, item = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, tab.network_map.members(key), True)
    before = where(view)
    tab.arrange_group(key)
    assert where(view) == before


def test_selected_groups_fall_in_around_a_group_all_locked(tab, crawled):
    key, item = grouped(tab, crawled)
    view = tab.view
    tab.set_locked(view, tab.network_map.members(key), True)
    before = view.positions()
    center = item.rect.center()
    tab.align_selected(view, ["core"], LEFT, [key])
    assert view.positions()["acc1"] == before["acc1"] and view.positions()["acc2"] == before["acc2"]
    assert item.rect.center() == center


def test_clear_of_moves_only_what_lands_on_a_fixed_one():
    placed = clear_of({"a": (0, 0), "b": (2000, 0), "fixed": (9, 9)}, {"fixed": (0, 0)})
    assert placed["fixed"] == (0, 0)
    assert placed["b"] == (2000, 0)  # Nowhere near
    assert abs(placed["a"][0]) >= NODE_WIDTH
    assert placed["a"] != placed["b"]


# --------------------------------------------------------------------- Menus

def test_lock_labels_follow_what_is_selected(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    assert list(device_menu(tab, view, "core")) == ["Lock Position"]
    device_menu(tab, view, "core")["Lock Position"]()
    assert view.items_by_key["core"].locked
    assert list(device_menu(tab, view, "core")) == ["Unlock Position"]

    for key in ("core", "acc1", "acc2"):
        view.items_by_key[key].setSelected(True)
    assert list(device_menu(tab, view, "core")) == ["Lock 3 Selected", "Unlock 3 Selected"]  # All of them, both ways
    device_menu(tab, view, "core")["Lock 3 Selected"]()
    assert sorted(view.locked_keys()) == ["acc1", "acc2", "core"]
    assert "3 icons" in tab.status_label.text()
    assert list(device_menu(tab, view, "core")) == ["Unlock 3 Selected"]
    device_menu(tab, view, "core")["Unlock 3 Selected"]()
    assert view.locked_keys() == []


def layout_entries(tab, view, keys):
    menu = QMenu()
    tab.add_selection_actions(menu, view, keys)
    return [action.text() for action in menu.actions()]


def test_layout_stays_on_the_menu_with_locked_devices_selected(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    keys = ["core", "acc1"]
    unlocked = layout_entries(tab, view, keys)
    assert unlocked[0] == "Arrange the 2 Selected"
    tab.set_locked(view, ["core"], True)
    assert layout_entries(tab, view, keys) == unlocked  # One locked: the same, counting both
    tab.set_locked(view, keys, True)
    assert layout_entries(tab, view, keys) == unlocked  # Both locked: still there


def test_arrange_menu_has_the_lock_actions(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    tab.tabs.setCurrentWidget(view)

    def entries():
        tab.fill_arrange_menu()
        return {action.text(): action for action in tab.arrange_menu.actions() if "ock" in action.text()}

    assert not entries()["Lock Selected"].isEnabled() and not entries()["Unlock All"].isEnabled()
    view.items_by_key["core"].setSelected(True)
    entries()["Lock Selected"].trigger()
    assert view.locked_keys() == ["core"]
    menu = entries()
    assert menu["Unlock Selected"].isEnabled() and not menu["Lock Selected"].isEnabled()
    view.scene().clearSelection()
    entries()["Unlock All (1)"].trigger()
    assert view.locked_keys() == []


def test_locks_are_offered_on_the_logical_views_subnets(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.l3_view
    tab.tabs.setCurrentWidget(view)
    key = next(key for key, item in view.items_by_key.items() if isinstance(item, SimpleNodeItem))
    device_menu(tab, view, key)["Lock Position"]()
    assert view.items_by_key[key].locked
    assert "Locked in place" in view.items_by_key[key].toolTip()
    assert tab.network_map.l3_locked == [key] and tab.network_map.locked == []


def test_no_lock_actions_during_a_crawl(tab, crawled):
    tab.on_crawled(crawled)
    tab.worker = object()
    try:
        assert not device_menu(tab, tab.view, "core")
    finally:
        tab.worker = None


# --------------------------------------------------------------------- Each view its own

def test_each_view_has_its_own_locks(tab, crawled):
    tab.on_crawled(crawled)
    tab.set_locked(tab.view, ["core"], True)
    assert tab.view.items_by_key["core"].locked
    assert not tab.l3_view.items_by_key["core"].locked


# --------------------------------------------------------------------- How it looks

def box_picture(item, locked):
    item.set_locked(locked)
    picture = QImage(240, 120, QImage.Format_ARGB32)
    picture.fill(QColor("black"))
    painter = QPainter(picture)
    painter.translate(120, 60)
    item.paint(painter, None)
    painter.end()
    return picture


def test_padlock_only_adds_to_the_strip_and_leaves_the_rest_as_it_was(tab, crawled):
    tab.on_crawled(crawled)
    item = tab.view.items_by_key["core"]
    plain, marked = box_picture(item, False), box_picture(item, True)
    assert plain != marked
    changed = [(x - 120, y - 60) for x in range(240) for y in range(120) if plain.pixel(x, y) != marked.pixel(x, y)]
    assert all(item.rect.left() <= x <= item.rect.left() + 34 and y > 5 for x, y in changed)
    assert not any(x < item.rect.left() or y > item.rect.bottom() for x, y in changed)


def test_padlock_is_left_out_of_pictures(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    plain = view.render_image(scale=1)
    tab.set_locked(view, ["core"], True)
    assert view.render_image(scale=1) == plain
    assert not view.exporting


def test_the_key_can_draw_it(app):
    picture, plain = QImage(96, 40, QImage.Format_ARGB32), QImage(96, 40, QImage.Format_ARGB32)
    for image, locked in ((picture, True), (plain, False)):
        image.fill(QColor("black"))
        painter = QPainter(image)
        device(locked=locked)(painter, QRectF(image.rect()))
        painter.end()
    assert picture != plain


# --------------------------------------------------------------------- Keeping them

def test_locks_saved_with_the_map_and_kept_when_mapped_again(tab, crawled):
    tab.on_crawled(crawled)
    tab.set_locked(tab.view, ["core"], True)
    tab.set_locked(tab.l3_view, ["core"], True)
    position = tab.view.positions()["core"]
    reloaded = store.load(tab.map_path)
    assert reloaded.locked == ["core"] and reloaded.l3_locked == ["core"]

    tab.on_crawled(crawl())
    assert tab.network_map.locked == ["core"] and tab.view.items_by_key["core"].locked
    assert tab.l3_view.items_by_key["core"].locked
    assert tab.view.positions()["core"] == position


def test_map_saved_before_locks_opens_with_none():
    assert NetworkMap.from_json('{"devices": []}').locked == []


def test_deleted_device_loses_its_lock():
    network_map = crawl()
    network_map.locked, network_map.l3_locked = ["core"], ["core"]
    network_map.remove_devices(["core"])
    assert network_map.locked == [] and network_map.l3_locked == []


def test_a_lock_follows_a_device_folded_into_another():
    network_map = crawl()
    network_map.locked, network_map.l3_locked = ["acc1"], ["acc1"]
    network_map.fold_device("acc1", network_map.devices["acc2"])
    assert network_map.locked == ["acc2"] and network_map.l3_locked == ["acc2"]


def test_undo_puts_locks_back(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    tab.record_layout()
    item = view.items_by_key["core"]
    item.setPos(100, 100)
    view.positions_changed.emit()
    tab.set_locked(view, ["core"], True)
    assert tab.undo_button.isEnabled()
    tab.undo()
    assert not item.locked and item.pos() == QPointF(100, 100)
    tab.undo()
    assert item.pos() != QPointF(100, 100)  # Undo moves it: at that step it wasn't locked
    tab.redo()
    tab.redo()
    assert item.locked and tab.network_map.locked == ["core"]


def test_undoing_past_a_lock_still_moves_the_icon(tab, crawled):
    tab.on_crawled(crawled)
    view = tab.view
    item = view.items_by_key["core"]
    start = item.pos()
    item.setPos(start + QPointF(300, 0))
    view.positions_changed.emit()
    tab.set_locked(view, ["core"], True)
    tab.undo()
    tab.undo()
    assert item.pos() == start and not item.locked


def test_locks_are_drawn_while_crawling_again(tab, crawled):
    tab.on_crawled(crawled)
    tab.set_locked(tab.view, ["core"], True)
    tab.live_positions = dict(tab.network_map.positions)
    tab.extending = False
    snapshot = crawl()
    tab.show_live(snapshot)
    assert tab.view.items_by_key["core"].locked
    tab.live_map = None


# --------------------------------------------------------------------- Tribe maps

def test_locks_flatten_and_build():
    network_map = small_map()
    network_map.locked, network_map.l3_locked = ["core", "gone"], ["subnet:10.0.0.0/24"]
    items = shared.flatten(network_map)
    assert items[(shared.LOCKED, "core")] is True
    built = shared.build(items)
    assert built.locked == ["core"]  # Not a device on the map
    assert built.l3_locked == ["subnet:10.0.0.0/24"]


def test_locks_shared_through_the_tribe(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    map_id = alice.create("HQ", small_map(), {}, {})
    edited, _ = alice.load(map_id)
    edited.locked = ["core"]
    assert alice.save(map_id, edited) == 1
    alice.sync()
    assert alice.pending_count() == 0
    bob.sync()
    assert bob.load(map_id)[0].locked == ["core"]

    theirs, _ = bob.load(map_id)
    theirs.locked = []
    bob.save(map_id, theirs)
    bob.sync()
    alice.sync()
    assert alice.load(map_id)[0].locked == []


def test_shared_map_keeps_locks_it_was_shared_with(server, tmp_path):
    alice, bob = tribe_maps(server, tmp_path, "alice"), tribe_maps(server, tmp_path, "bob")
    network_map = small_map()
    network_map.locked = ["acc1"]
    map_id = alice.create("HQ", network_map, {}, {})
    bob.sync()
    assert bob.load(map_id)[0].locked == ["acc1"]


class OldServerClient:
    """A client of a server below LOCK_API: a real one, but the server says it's older and refuses a whole push with
    a lock in it (as _write does for a section it doesn't know)."""

    def __init__(self, client):
        self.client, self.api = client, LOCK_API - 1

    def __getattr__(self, name):
        return getattr(self.client, name)

    def status(self):
        return dict(self.client.status(), api=self.api)

    def map_request(self, action, **arguments):
        if self.api < LOCK_API and any(change["section"] in shared.LOCK_SECTIONS
                                       for change in arguments.get("changes", [])):
            raise IpamError("Unknown part of a map: 'locked'.")
        return self.client.map_request(action, **arguments)


def old_server_maps(server, tmp_path, user):
    from nomad.netmap.tribe import TribeMaps
    key = key_for(server)
    return TribeMaps(key.server_id, OldServerClient(TeamClient(key, user=user)), tmp_path / f"{user}-old.db")


def test_locks_wait_here_on_an_older_server(server, tmp_path):
    alice = old_server_maps(server, tmp_path, "alice")
    bob = tribe_maps(server, tmp_path, "bob")
    alice.sync()  # Learns how old the server is
    map_id = alice.create("HQ", small_map(), {}, {})
    edited, _ = alice.load(map_id)
    edited.locked = ["core"]
    edited.positions["core"] = (9.0, 9.0)
    alice.save(map_id, edited)
    alice.sync()  # The position goes; the lock would have failed the whole push
    bob.sync()
    assert bob.load(map_id)[0].positions["core"] == (9.0, 9.0)
    assert bob.load(map_id)[0].locked == []
    assert alice.load(map_id)[0].locked == ["core"]  # Still locked here
    assert alice.pending_count() == 0  # Not shown as waiting to send

    alice.client.api = LOCK_API  # The server's updated: they go with the next sync
    alice.sync()
    alice.sync()
    bob.sync()
    assert bob.load(map_id)[0].locked == ["core"]


def test_first_sync_with_an_older_server_doesnt_fail_on_a_lock(server, tmp_path):
    """A lock made before this copy has ever spoken to the server mustn't lose the sync."""
    alice = old_server_maps(server, tmp_path, "alice")
    map_id = alice.create("HQ", small_map(), {}, {})
    edited, _ = alice.load(map_id)
    edited.locked = ["core"]
    alice.save(map_id, edited)
    alice.sync()
    assert alice.online and alice.load(map_id)[0].locked == ["core"]


def test_server_says_it_keeps_locks(server, tmp_path):
    maps = tribe_maps(server, tmp_path, "alice")
    maps.sync()
    assert maps.sends_locks


def test_map_shared_to_an_older_server_keeps_its_locks_here(server, tmp_path):
    alice = old_server_maps(server, tmp_path, "alice")
    alice.sync()
    network_map = small_map()
    network_map.locked = ["acc1"]
    map_id = alice.create("HQ", network_map, {}, {})
    assert alice.load(map_id)[0].locked == ["acc1"]
    alice.sync()
    assert alice.load(map_id)[0].locked == ["acc1"]


def test_status_line_says_when_the_tribe_server_is_too_old_for_locks(tab, crawled, monkeypatch):
    tab.on_crawled(crawled)
    monkeypatch.setattr(tab, "update_tribe_label", lambda: None)

    class Maps:
        too_old_for_locks = True

        def save(self, *arguments):
            return 0

    class Tribe:
        maps = Maps()

        def save(self, *arguments):
            return 0

    tab.tribe, keep = Tribe(), tab.tribe
    tab.tribe_map_id = 1
    try:
        tab.set_locked(tab.view, ["core"], True)
        assert "too old to share locks" in tab.status_label.text()
    finally:
        tab.tribe, tab.tribe_map_id = keep, None


def test_device_items_have_a_tooltip_note(tab, crawled):
    tab.on_crawled(crawled)
    item = tab.view.items_by_key["core"]
    assert isinstance(item, DeviceItem)
    assert "Locked in place" not in item.toolTip()
    tab.set_locked(tab.view, ["core"], True)
    assert "Unlock Position" in item.toolTip()
    tab.set_locked(tab.view, ["core"], False)
    assert "Locked in place" not in item.toolTip()
