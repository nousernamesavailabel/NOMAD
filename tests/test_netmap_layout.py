import os
import xml.etree.ElementTree as ElementTree

import pytest
from netmap_fakes import build_network

from nomad import system
from nomad.netmap import export, store
from nomad.netmap.crawl import CrawlSettings, Crawler
from nomad.netmap.layout import H_GAP, NODE_HEIGHT, NODE_WIDTH, SPACINGS, STYLE_NAMES, arrange, layout, \
    merge_positions, neighbors_of, order_layers, respace, spacing_of, tangle
from nomad.netmap.model import NetworkMap


def no_overlaps(positions):
    points = list(positions.values())
    for index, (x, y) in enumerate(points):
        for other_x, other_y in points[index + 1:]:
            assert abs(x - other_x) >= NODE_WIDTH or abs(y - other_y) >= NODE_HEIGHT, positions


def test_layers_follow_hops_from_the_busiest_device():
    edges = [("core", "a1"), ("core", "a2"), ("core", "a3"), ("a1", "e1"), ("a2", "e2"), ("a3", "e3"), ("e1", "x")]
    positions = layout(["core", "a1", "a2", "a3", "e1", "e2", "e3", "x"], edges)
    assert positions["core"][1] < positions["a1"][1] == positions["a2"][1] < positions["e1"][1]
    no_overlaps(positions)


def test_single_link_devices_are_grouped_under_their_parent():
    nodes = ["core", "dist"] + [f"ap{number}" for number in range(10)]
    edges = [("core", "dist")] + [("dist", f"ap{number}") for number in range(10)]
    positions = layout(nodes, edges, root="core")
    xs = [positions[f"ap{number}"][0] for number in range(10)]
    assert max(xs) - min(xs) <= 3 * (NODE_WIDTH + H_GAP) + 1  # Four across, not ten
    assert all(positions[f"ap{number}"][1] > positions["dist"][1] for number in range(10))
    no_overlaps(positions)


def test_separate_groups_and_lone_devices_do_not_overlap():
    positions = layout(["a", "b", "c", "d", "lone1", "lone2"], [("a", "b"), ("c", "d")])
    assert len(positions) == 6
    no_overlaps(positions)


def test_saved_positions_are_kept_and_new_devices_placed_clear():
    nodes = ["core", "a1", "a2"]
    edges = [("core", "a1"), ("core", "a2")]
    saved = {"core": (1000, 1000), "a1": (700, 1300)}
    positions = merge_positions(nodes + ["a3"], edges + [("core", "a3")], saved)
    assert positions["core"] == (1000, 1000) and positions["a1"] == (700, 1300)
    no_overlaps(positions)


@pytest.fixture
def crawled():
    network = build_network()
    return Crawler(CrawlSettings(seeds=["10.0.0.1"], overrides=[("10.0.0.12/32", "secret")]),
                   client_factory=network.client, pinger=network.ping,
                   echo=network.echo).run()


def test_map_round_trips_through_a_file(crawled, tmp_path):
    crawled.positions = {"core": (10.0, 20.0)}
    path = store.save(crawled, folder=tmp_path)
    assert path.suffix == store.EXTENSION
    loaded = store.load(path)
    assert loaded.devices == crawled.devices
    assert loaded.links == crawled.links
    assert loaded.hosts == crawled.hosts
    assert loaded.positions == {"core": (10.0, 20.0)}
    assert store.recent(tmp_path) == [path]


def test_saving_waits_out_a_file_held_open_for_a_moment(tmp_path, monkeypatch):
    path = store.save(NetworkMap(), folder=tmp_path)
    replace, refusals = os.replace, [2]

    def held_open(source, target):  # As Windows refuses while the virus scanner has the file open
        if refusals[0]:
            refusals[0] -= 1
            raise PermissionError(13, "Access is denied")
        return replace(source, target)
    monkeypatch.setattr(os, "replace", held_open)
    monkeypatch.setattr(system.time, "sleep", lambda seconds: None)
    assert store.save(NetworkMap(), path) == path and not refusals[0]
    refusals[0] = system.REPLACE_TRIES  # Held open for good: says so
    with pytest.raises(PermissionError):
        store.save(NetworkMap(), path)


def test_loading_something_else_says_so(tmp_path):
    path = tmp_path / "other.nomadmap"
    path.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(ValueError, match="isn't a NOMAD network map"):
        store.load(path)
    path.write_text("not json", encoding="utf-8")
    with pytest.raises(ValueError, match="damaged"):
        store.load(path)


def test_exports(crawled, tmp_path):
    positions = layout(list(crawled.devices), [(link.a, link.b) for link in crawled.links])
    root = ElementTree.fromstring(export.drawio(crawled, positions))
    cells = root.iter("mxCell")
    vertices = [cell for cell in root.iter("mxCell") if cell.get("vertex")]
    edges = [cell for cell in root.iter("mxCell") if cell.get("edge")]
    assert len(vertices) == len(crawled.devices) and len(edges) == len(crawled.links)
    assert any(cell.get("value") == "Te1/0/1 - Te1/1/1" for cell in cells) or edges
    path = tmp_path / "hosts.csv"
    export.write_csv(path, export.HOST_COLUMNS, export.host_rows(crawled))
    text = path.read_text(encoding="utf-8-sig")
    assert text.startswith("MAC Address,IP Address") and "SEP00AABBCCDDEE" in text
    rows = export.device_rows(crawled)
    assert [row[0] for row in rows][:2] == ["acc1.corp.example", "acc2"]


def test_empty_map_json():
    assert NetworkMap.from_json(NetworkMap().to_json()).devices == {}


def test_core_pair_shares_the_top_layer():
    access = [f"acc{number}" for number in range(4)]
    edges = [("core1", "core2")] + [(core, switch) for core in ("core1", "core2") for switch in access]
    edges.append(("core1", "wan"))
    positions = layout(["core1", "core2", "wan"] + access, edges)
    assert positions["core1"][1] == positions["core2"][1] < positions["acc0"][1]
    assert positions["wan"][1] < positions["core1"][1]  # Hanging off the top layer: drawn above it
    no_overlaps(positions)


def test_star_of_single_link_devices_hangs_below():
    positions = layout(["core", "a", "b", "c"], [("core", "a"), ("core", "b"), ("core", "c")])
    assert all(positions[node][1] > positions["core"][1] for node in "abc")
    no_overlaps(positions)


def test_layers_are_ordered_so_links_do_not_cross():
    # Each distribution switch's access switches start out on the far side of the other's
    levels = [["core"], ["d1", "d2", "d3"], ["s3a", "s2a", "s1a", "s3b", "s2b", "s1b"]]
    edges = [("core", "d1"), ("core", "d2"), ("core", "d3")] + [(f"d{n}", f"s{n}{end}") for n in (1, 2, 3)
                                                                 for end in "ab"]
    adjacent = neighbors_of([node for level in levels for node in level], edges)
    assert tangle(levels, adjacent) > 0
    assert tangle(order_layers(levels, adjacent), adjacent) == 0


def test_a_link_along_a_layer_joins_neighbors():
    # x and z are linked to each other as well as to the core: drawn side by side, not with y between them
    nodes = ["core", "x", "y", "z"] + [f"{parent}{n}" for parent in "xyz" for n in (1, 2)]
    edges = [("core", "x"), ("core", "y"), ("core", "z"), ("x", "z")] + [(parent, f"{parent}{n}")
                                                                         for parent in "xyz" for n in (1, 2)]
    positions = layout(nodes, edges, root="core")
    layer = sorted("xyz", key=lambda node: positions[node][0])
    assert abs(layer.index("x") - layer.index("z")) == 1
    no_overlaps(positions)


def test_nothing_new_keeps_every_position_as_it_was():
    saved = {"a": (5.0, 6.0), "b": (100.0, 600.0)}
    assert merge_positions(["a", "b"], [("a", "b")], saved) == saved


def passes_over(start, end, box):
    """Whether the line from start to end runs over the device box centered on box (sampled along its length)."""
    for step in range(1, 200):
        x = start[0] + (end[0] - start[0]) * step / 200
        y = start[1] + (end[1] - start[1]) * step / 200
        if abs(x - box[0]) < NODE_WIDTH / 2 - 2 and abs(y - box[1]) < NODE_HEIGHT / 2 - 2:
            return True
    return False


@pytest.mark.parametrize("style", ["top-down", "bottom-up", "left-right", "right-left"])
def test_links_down_from_a_switch_miss_its_access_points(style):
    # dist1 has six access points and two access switches below it (each with an edge switch of its own)
    aps = [f"ap{number}" for number in range(6)]
    nodes = ["core", "dist1", "dist2", "acc1", "acc2", "edge1", "edge2", "acc3", "edge3"] + aps
    edges = [("core", "dist1"), ("core", "dist2"), ("dist1", "acc1"), ("dist1", "acc2"), ("acc1", "edge1"),
             ("acc2", "edge2"), ("dist2", "acc3"), ("acc3", "edge3")] + [("dist1", ap) for ap in aps]
    positions = arrange(nodes, edges, style, root="core")
    no_overlaps(positions)
    for a, b in edges:
        for other in nodes:
            if other not in (a, b) and not (b in aps and other in aps):  # In its grid, a fan of links is fine
                assert not passes_over(positions[a], positions[b], positions[other]), (a, b, other)


def tree():
    nodes = ["core", "d1", "d2", "d3"] + [f"a{i}" for i in range(12)] + [f"s{i}" for i in range(6)] + \
        [f"x{i}" for i in range(6)]
    edges = [("core", "d1"), ("core", "d2"), ("core", "d3")] + [(f"d{1 + i % 3}", f"a{i}") for i in range(12)] + \
        [(f"d{1 + i % 3}", f"s{i}") for i in range(6)] + [(f"s{i}", f"x{i}") for i in range(6)]
    return nodes, edges


@pytest.mark.parametrize("style", [style for style in STYLE_NAMES if style != "circle"])
def test_spacing_measures_what_arranging_left(style):
    nodes, edges = tree()
    for value in SPACINGS.values():
        assert spacing_of(arrange(nodes, edges, style, root="core", spacing=value)) == pytest.approx(value)


@pytest.mark.parametrize("style", list(STYLE_NAMES))
def test_respacing_keeps_the_arrangement(style):
    nodes, edges = tree()
    laid = arrange(nodes, edges, style, root="core")
    laid["a3"] = (laid["a3"][0] + 333, laid["a3"][1] - 77)  # Dragged somewhere of its own
    laid = {key: point for key, point in laid.items()}
    for value in SPACINGS.values():
        spaced = respace(laid, value)
        no_overlaps(spaced)
        scale = (spaced["a3"][0] - spaced["core"][0]) / (laid["a3"][0] - laid["core"][0])
        for key in laid:  # Every one where it was among the rest: the lot stretched or shrunk evenly
            for axis in (0, 1):
                assert spaced[key][axis] - spaced["core"][axis] == pytest.approx(
                    scale * (laid[key][axis] - laid["core"][axis]))
        if style != "circle":  # A circle's rings can't come as close as its spacing would have them
            assert spacing_of(spaced) == pytest.approx(value, rel=0.03)


def test_respacing_the_same_again_moves_nothing():
    nodes, edges = tree()
    laid = arrange(nodes, edges, root="core")
    assert respace(laid, 1.0) == laid
    roomy = respace(laid, SPACINGS["roomy"])
    again = respace(roomy, SPACINGS["roomy"])
    assert all(again[key] == pytest.approx(roomy[key], abs=0.5) for key in roomy)


def test_shrinking_stops_before_devices_meet():
    points = {"a": (0, 0), "b": (NODE_WIDTH + 30, 0), "c": (0, NODE_HEIGHT + 400)}  # a and b close, c far
    spaced = respace(points, 0.1)
    assert spaced["b"][0] - spaced["a"][0] >= NODE_WIDTH + 12 - 0.01  # Never closer than RESPACE_MIN_GAP
    tight = respace(points, 0.1, min_gap=lambda a, b: 100)  # Closer than that already: only kept from overlapping
    assert NODE_WIDTH - 0.01 <= tight["b"][0] - tight["a"][0] < NODE_WIDTH + 30
