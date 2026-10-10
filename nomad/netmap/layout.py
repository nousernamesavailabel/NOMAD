"""Placing a map's devices: layers by hop distance from the top device, ordered to keep links from crossing (and
links between devices in the same layer from running over the devices between them).

Devices with a single link (access points, a lone router) sit in a small grid beside the device they hang off, on the
side away from its other links (not under it, where its links down would run through them), so a switch with thirty
access points doesn't make its layer thirty wide. Positions are the centers of the devices.

The same layers can run bottom to top, left to right or right to left, or the devices go in a grid or in rings round
the top device; with groups (sites, buildings and rooms), each group is laid out on its own and the groups' boxes are
tiled. Spacing stretches or shrinks the gaps between devices (not the devices). Align and distribute line up devices
the user chose.
"""
import bisect
import functools
import math

NODE_WIDTH, NODE_HEIGHT = 170, 58
H_GAP, V_GAP = 40, 120
LEAF_COLUMNS = 4
LEAF_GAP = 26
SIDE_DROP = 1.5  # How many rows below a device the grid of single-link devices beside it starts
COMPONENT_GAP = 160
DETOUR_COST = 2  # A link drawn over a device looks like it's linked to it too: worse than two links crossing
SWEEPS = 24  # Most passes made ordering the layers to keep links from crossing
QUICK_SWEEPS = 4  # Placing devices new to a map among those already placed: no need to be thorough
SETTLED = 4  # Stop once this many passes in a row haven't untangled anything more
SWAP_ROUNDS = 6  # Most times over each layer swapping neighbors that cross less the other way round
PEER_SHARE = 0.6  # Share of the top device's links a neighbor needs to sit beside it
PEER_MIN_LINKS = 3
RING_GAP = 230  # Between a circle's rings
GRID_ROW = NODE_HEIGHT + 50  # Leaves room for a switch's hosts badge
GROUP_PAD = 24  # Space inside a group's box round what's in it
GROUP_TITLE = 26  # A group's title bar
GROUP_GAP = 90  # Between groups' boxes when arranged by group
DISTRIBUTE_MIN_GAP = 20
RESPACE_ROUNDS = 4  # Most times respace() measures again and corrects
RESPACE_MIN_GAP = 12  # Closest respace() brings two that were apart (Compact leaves 15.6 between rows)

# Arrangements
TOP_DOWN, BOTTOM_UP, LEFT_RIGHT, RIGHT_LEFT, GRID, CIRCLE = \
    "top-down", "bottom-up", "left-right", "right-left", "grid", "circle"
STYLE_NAMES = {TOP_DOWN: "Top to Bottom", BOTTOM_UP: "Bottom to Top", LEFT_RIGHT: "Left to Right",
               RIGHT_LEFT: "Right to Left", GRID: "Grid", CIRCLE: "Circle"}
FLIPPED = {BOTTOM_UP: (TOP_DOWN, 1), RIGHT_LEFT: (LEFT_RIGHT, 0)}  # Laid out as, then turned round along axis
# Spacing: how much the gaps between devices (and groups) are stretched
COMPACT, NORMAL, ROOMY, SPACIOUS = "compact", "normal", "roomy", "spacious"
SPACINGS = {COMPACT: 0.6, NORMAL: 1.0, ROOMY: 1.6, SPACIOUS: 2.4}
SPACING_NAMES = {COMPACT: "Compact", NORMAL: "Normal", ROOMY: "Roomy", SPACIOUS: "Spacious"}
# Lining up
LEFT, CENTER, RIGHT, TOP, MIDDLE, BOTTOM = "left", "center", "right", "top", "middle", "bottom"
HORIZONTAL, VERTICAL = "horizontal", "vertical"


def leaf_block(count, spacing=1.0):
    """(width, height) of the grid of count single-link devices."""
    if not count:
        return 0, 0
    columns = min(count, LEAF_COLUMNS)
    rows = math.ceil(count / columns)
    return columns * (NODE_WIDTH + H_GAP * spacing) - H_GAP * spacing, rows * (NODE_HEIGHT + LEAF_GAP * spacing)


def neighbors_of(nodes, edges):
    adjacent = {node: set() for node in nodes}
    for a, b in edges:
        if a in adjacent and b in adjacent and a != b:
            adjacent[a].add(b)
            adjacent[b].add(a)
    return adjacent


def components(adjacent):
    seen, found = set(), []
    for start in sorted(adjacent):
        if start in seen:
            continue
        group, stack = [], [start]
        seen.add(start)
        while stack:
            node = stack.pop()
            group.append(node)
            for other in adjacent[node]:
                if other not in seen:
                    seen.add(other)
                    stack.append(other)
        found.append(group)
    return sorted(found, key=lambda group: (-len(group), min(group)))


def layout_component(group, adjacent, root=None, weight=lambda node: 0, thorough=True, leaf_grids=True, spacing=1.0):
    """Positions for one connected group, with its top-left corner near (0, 0). Returns ({node: (x, y)}, width).
    thorough: work harder at keeping links from crossing (Re-arrange), rather than just quickly. leaf_grids: put
    single-link devices in a grid by the device they hang off (not for groups' boxes, which aren't device-sized).
    spacing: the gaps' stretch."""
    if len(group) == 1:
        return {group[0]: (NODE_WIDTH / 2, NODE_HEIGHT / 2)}, NODE_WIDTH
    if root not in group:
        root = max(group, key=lambda node: (len(adjacent[node]), weight(node), node))
    # A core pair: neighbors of the top device with nearly as many links go on the top layer beside it
    peers = sorted(node for node in adjacent[root] if len(adjacent[root]) >= PEER_MIN_LINKS
                   and len(adjacent[node]) >= max(PEER_MIN_LINKS, PEER_SHARE * len(adjacent[root])))
    depth = {node: 0 for node in [root] + peers}
    order = [root] + peers
    for node in order:  # Breadth first
        for other in sorted(adjacent[node]):
            if other not in depth:
                depth[other] = depth[node] + 1
                order.append(other)

    leaves = {}  # Parent -> [leaf]
    if len(group) > 2 and leaf_grids:
        for node in group:
            if depth[node] and len(adjacent[node]) == 1:
                parent = next(iter(adjacent[node]))
                if len(adjacent[parent]) > 1 or parent == root:
                    leaves.setdefault(parent, []).append(node)
    leaf_set = {leaf for items in leaves.values() for leaf in items}
    layers = {}
    for node in order:
        if node not in leaf_set:
            layers.setdefault(depth[node], []).append(node)
    levels = [layers[level] for level in sorted(layers)]
    # Off the top layer (a WAN router, a firewall): above it, clear of the links to the layers below. Off a device
    # with links down (or along its layer) to others: off to the side away from its other links, so they don't run
    # through them. Off the rest (an access switch's access points): below it
    above = {node: sorted(leaves.pop(node)) for node in levels[0] if node in leaves and len(levels) > 1}
    beside = {node: sorted(items) for node, items in leaves.items()
              if any(other not in leaf_set and depth[other] >= depth[node] for other in adjacent[node])}
    below = {node: sorted(items) for node, items in leaves.items() if node not in beside}

    levels = order_layers(levels, adjacent, thorough)

    h_gap, leaf_gap = H_GAP * spacing, LEAF_GAP * spacing
    block = functools.partial(leaf_block, spacing=spacing)
    slot_widths = [[NODE_WIDTH + h_gap + block(len(beside[node]))[0] if node in beside
                    else max(NODE_WIDTH, block(len(above.get(node, below.get(node, []))))[0])
                    for node in level]
                   for level in levels]
    row = NODE_HEIGHT + leaf_gap
    tops, y = [], NODE_HEIGHT / 2  # Each layer's height down the page (the same whichever side grids go)
    for level in levels:
        tops.append(y)
        lowest = max([block(len(below[node]))[1] for node in level if node in below]
                     + [block(len(beside[node]))[1] + (SIDE_DROP - 1) * row for node in level if node in beside]
                     + [0])  # How far the layer's grids reach below it
        y += NODE_HEIGHT + (lowest + leaf_gap if lowest else 0) + V_GAP * spacing
    layer_of = {node: number for number, level in enumerate(levels) for node in level}
    # Where they'd go with the grids on no side in particular; then each grid goes on the side where fewer of its
    # device's links to others would run through it (or else away from them)
    shifts = {}  # How far each device is from the middle of its slot: its grid's on the other side
    centers = across_layers(levels, slot_widths, adjacent, shifts, h_gap)
    for node in beside:
        grid_width, grid_height = block(len(beside[node]))
        others = [(centers[other], tops[layer_of[other]]) for other in adjacent[node] if other not in leaf_set]
        here = tops[layer_of[node]]

        def through(side):
            x = centers[node] - side * (grid_width + h_gap) / 2
            near = x + side * (NODE_WIDTH / 2 + h_gap)
            box = (min(near, near + side * grid_width), here + SIDE_DROP * row - NODE_HEIGHT / 2,
                   max(near, near + side * grid_width), here + (SIDE_DROP - 1) * row + grid_height - leaf_gap / 2)
            return sum(cuts((x, here), other, box) for other in others)

        away = 1 if not others or sum(x for x, _ in others) / len(others) <= centers[node] else -1
        side = min((1, -1), key=lambda side: (through(side), side != away))  # The grid's
        shifts[node] = -side * (grid_width + h_gap) / 2
    centers = across_layers(levels, slot_widths, adjacent, shifts, h_gap)
    left = min(centers[node] - slot / 2 for level, widths in zip(levels, slot_widths)
               for node, slot in zip(level, widths))
    width = max(centers[node] + slot / 2 for level, widths in zip(levels, slot_widths)
                for node, slot in zip(level, widths)) - left
    positions = {}
    for level, widths, y in zip(levels, slot_widths, tops):
        for node, slot in zip(level, widths):
            center = centers[node] - left
            positions[node] = (center + shifts.get(node, 0), y)
            place_grid(positions, above.get(node, []), center, y - row, -1, spacing)
            if node in below:
                place_grid(positions, below[node], center, y + row, 1, spacing)
            if node in beside:  # Off to one side, starting a little below it (so links to it run down, not along)
                side = -1 if shifts[node] > 0 else 1
                place_grid(positions, beside[node], center + side * (slot - block(len(beside[node]))[0]) / 2,
                           y + SIDE_DROP * row, 1, spacing)
    return positions, width


def cuts(start, end, box):
    """Whether the straight line from start to end runs through box (left, top, right, bottom)."""
    low, high = 0.0, 1.0
    for origin, delta, near, far in ((start[0], end[0] - start[0], box[0], box[2]),
                                     (start[1], end[1] - start[1], box[1], box[3])):
        if abs(delta) < 1e-9:
            if not near <= origin <= far:
                return False
            continue
        enter, leave = sorted(((near - origin) / delta, (far - origin) / delta))
        low, high = max(low, enter), min(high, leave)
        if low > high:
            return False
    return True


def across_layers(levels, slot_widths, linked, shifts, gap=H_GAP):
    """Where along its layer each device goes, its order kept: as near as it can be to the middle of what
    it links to in the layer above, then below, then above again (so links run more up and down than across, and
    don't cut across other devices on the way), clear of its neighbors. shifts: how far a device is from the
    middle of its slot (its grid of single-link devices is beside it); gap: between slots. Returns {node: the middle
    of its slot}."""
    longest = max(sum(widths) + gap * (len(widths) - 1) for widths in slot_widths)
    centers = {}
    for level, widths in zip(levels, slot_widths):  # To start with: each layer centered under the longest
        x = (longest - (sum(widths) + gap * (len(widths) - 1))) / 2
        for node, slot in zip(level, widths):
            centers[node] = x + slot / 2
            x += slot + gap
    count = len(levels)
    down = [(index, index - 1) for index in range(1, count)]  # Each layer by the one above it
    up = [(index, index + 1) for index in range(count - 2, -1, -1)]  # And by the one below
    for index, reference in down + up + down:
        level, widths, there = levels[index], slot_widths[index], set(levels[reference])
        wants = []
        for node, slot in zip(level, widths):
            ends = [centers[other] + shifts.get(other, 0) for other in linked[node] if other in there]
            wants.append((sum(ends) / len(ends) - shifts.get(node, 0) if ends else centers[node]) - slot / 2)
        for node, slot, start in zip(level, widths, spread(wants, widths, gap)):
            centers[node] = start + slot / 2
    return centers


def place_grid(positions, leaves, center, top, direction, spacing=1.0):
    """Put single-link devices in a grid centered on center, its first row at top and the rest going down
    (direction 1) or up (-1)."""
    block_width, _ = leaf_block(len(leaves), spacing)
    columns = min(len(leaves), LEAF_COLUMNS) or 1
    for number, leaf in enumerate(leaves):
        row, column = divmod(number, columns)
        positions[leaf] = (center - block_width / 2 + NODE_WIDTH / 2 + column * (NODE_WIDTH + H_GAP * spacing),
                           top + direction * row * (NODE_HEIGHT + LEAF_GAP * spacing))


def crossings(upper, lower, adjacent):
    """How many of the links between two neighboring layers cross each other."""
    place = {node: index for index, node in enumerate(lower)}
    ends = sorted((top, place[other]) for top, node in enumerate(upper) for other in adjacent[node] if other in place)
    count, seen = 0, []
    for _, bottom in ends:  # Each link crosses the ones from further left that end further right
        count += len(seen) - bisect.bisect_right(seen, bottom)
        bisect.insort(seen, bottom)
    return count


def detours(level, adjacent):
    """How many devices the links along a layer pass over: drawn straight, such a link runs through every box
    between its ends, as if it were linked to them too."""
    place = {node: index for index, node in enumerate(level)}
    return sum(place[other] - place[node] - 1 for node in level for other in adjacent[node]
               if place.get(other, -1) > place[node])


def tangle(levels, adjacent):
    """What ordering the layers keeps small: links that cross, and (worse) devices that links along a layer pass
    over."""
    return (sum(crossings(upper, lower, adjacent) for upper, lower in zip(levels, levels[1:]))
            + DETOUR_COST * sum(detours(level, adjacent) for level in levels))


def pair_crossings(left, right):
    """Crossings between two devices' links to a neighboring layer (the sorted places of their other ends), the
    first drawn to the left of the second."""
    return sum(bisect.bisect_left(right, end) for end in left) if left and right else 0


def swap_gain(level, index, here, ends, adjacent):
    """How much less tangled the layer would be with the devices at index and index + 1 swapped. ends: for the
    layers above and below, each device's pair_crossings ends."""
    left, right = level[index], level[index + 1]
    gain = sum(pair_crossings(side[left], side[right]) - pair_crossings(side[right], side[left]) for side in ends)
    for node, step in ((left, 1), (right, -1)):  # Links along the layer: moving towards the other end shortens them
        for other in adjacent[node]:
            if other in here and other not in (left, right):
                gain += DETOUR_COST if (here[other] - here[node]) * step > 0 else -DETOUR_COST
    return gain


def transpose(levels, adjacent):
    """Swap neighbors in each layer wherever that untangles links, until no swap helps."""
    for _ in range(SWAP_ROUNDS):
        swapped = False
        for number, level in enumerate(levels):
            ends = []
            for other_level in (levels[number - 1] if number else [],
                                levels[number + 1] if number + 1 < len(levels) else []):
                place = {node: index for index, node in enumerate(other_level)}
                ends.append({node: sorted(place[other] for other in adjacent[node] if other in place)
                             for node in level})
            here = {node: index for index, node in enumerate(level)}
            for index in range(len(level) - 1):
                if swap_gain(level, index, here, ends, adjacent) > 0:
                    level[index], level[index + 1] = level[index + 1], level[index]
                    here[level[index]], here[level[index + 1]] = index, index + 1
                    swapped = True
        if not swapped:
            return


def order_layers(levels, adjacent, thorough=True):
    """Order each layer to keep links from crossing: by where each device's links are in the layer above (then
    below), then (thorough) swapping neighbors where that helps, over and over, keeping the least tangled order
    found."""
    levels = [list(level) for level in levels]
    best, least, calm = [list(level) for level in levels], tangle(levels, adjacent), 0
    for sweep in range(SWEEPS if thorough else QUICK_SWEEPS):
        if not least:
            break
        down = sweep % 2 == 0
        for index in range(1, len(levels)) if down else range(len(levels) - 2, -1, -1):
            reference = levels[index - 1] if down else levels[index + 1]
            place = {node: position for position, node in enumerate(reference)}
            linked, free = {}, []
            for position, node in enumerate(levels[index]):
                ends = [place[other] for other in adjacent[node] if other in place]
                if ends:
                    linked[node] = (sum(ends) / len(ends), position)
                else:
                    free.append(position)  # Nothing to go by: it keeps its place
            moving = iter(sorted(linked, key=linked.get))
            free = set(free)
            levels[index] = [levels[index][position] if position in free else next(moving)
                             for position in range(len(levels[index]))]
        if thorough:
            transpose(levels, adjacent)
        score = tangle(levels, adjacent)
        if score < least:
            best, least, calm = [list(level) for level in levels], score, 0
        else:
            calm += 1
            if calm >= SETTLED:
                break
    return best


def circle_component(group, adjacent, root=None, weight=lambda node: 0, spacing=1.0):
    """Rings round the top device by hops from it, each device near the ones it links to on the ring inside.
    Returns ({node: (x, y)}, width) with the top-left corner near (0, 0)."""
    if root not in group:
        root = max(group, key=lambda node: (len(adjacent[node]), weight(node), node))
    depth, order = {root: 0}, [root]
    for node in order:
        for other in sorted(adjacent[node]):
            if other not in depth:
                depth[other] = depth[node] + 1
                order.append(other)
    rings = {}
    for node in order:
        rings.setdefault(depth[node], []).append(node)
    angles, radii, radius = {root: -math.pi / 2}, [0], 0
    for level in range(1, len(rings)):
        ring = rings[level]
        wanted = {}
        for node in ring:  # The circular mean of where its links on the ring inside are
            inside = [angles[other] for other in adjacent[node] if other in angles]
            wanted[node] = math.atan2(sum(map(math.sin, inside)), sum(map(math.cos, inside))) if inside else 0
        ring.sort(key=lambda node: (wanted[node] + math.pi / 2) % (2 * math.pi))
        # Rings at least a device's width apart, so devices at the sides of two rings can't overlap
        radius = max(radius + NODE_WIDTH + (RING_GAP - NODE_WIDTH) * spacing,
                     len(ring) * (NODE_WIDTH + H_GAP * spacing) / (2 * math.pi))
        radii.append(radius)
        # The first ring starts at the top; two go either side, as the boxes are wider than they're tall
        start = wanted[ring[0]] if level > 1 else -math.pi / 2 + (math.pi / 2 if len(ring) == 2 else 0)
        for number, node in enumerate(ring):
            angles[node] = start + 2 * math.pi * number / len(ring)
    center = (radius + NODE_WIDTH / 2, radius + NODE_HEIGHT / 2)
    positions = {node: (center[0] + radii[depth[node]] * math.cos(angles[node]),
                        center[1] + radii[depth[node]] * math.sin(angles[node])) for node in order}
    return positions, 2 * radius + NODE_WIDTH


def layout(nodes, edges, root=None, weight=lambda node: 0, component=layout_component, spacing=1.0):
    """{node: (x, y)} for every node: connected groups side by side, largest first, lone devices in a row after.
    spacing: the gaps' stretch (component is given it too, unless it's 1)."""
    if spacing != 1:
        component = functools.partial(component, spacing=spacing)
    adjacent = neighbors_of(nodes, edges)
    positions, x = {}, 0
    lone = []
    for group in components(adjacent):
        if len(group) == 1:
            lone.append(group[0])
            continue
        placed, width = component(group, adjacent, root, weight)
        for node, (node_x, node_y) in placed.items():
            positions[node] = (node_x + x, node_y)
        x += width + COMPONENT_GAP * spacing
    if lone:
        h_gap, v_gap = H_GAP * spacing, V_GAP * spacing
        bottom = max((y for _, y in positions.values()), default=-v_gap) + v_gap + NODE_HEIGHT
        per_row = max(LEAF_COLUMNS, int(max(x, NODE_WIDTH) // (NODE_WIDTH + h_gap)))
        for number, node in enumerate(sorted(lone)):
            row, column = divmod(number, per_row)
            positions[node] = (NODE_WIDTH / 2 + column * (NODE_WIDTH + h_gap),
                               bottom + row * (NODE_HEIGHT + LEAF_GAP * spacing))
    return positions


def overlaps(point, others):
    return any(abs(point[0] - x) < NODE_WIDTH + H_GAP / 2 and abs(point[1] - y) < NODE_HEIGHT + LEAF_GAP / 2
               for x, y in others)


def merge_positions(nodes, edges, saved, root=None, weight=lambda node: 0):
    """Keep where the user put devices; place new ones near their placed neighbors, clear of everything else."""
    kept = {node: tuple(saved[node]) for node in nodes if node in saved}
    if len(kept) == len(nodes):
        return kept  # Nothing new to place (as on every redraw)
    fresh = layout(nodes, edges, root, weight,
                   component=layout_component if not kept else functools.partial(layout_component, thorough=False))
    if not kept:
        return fresh
    adjacent = neighbors_of(nodes, edges)
    result = dict(kept)
    new_nodes = [node for node in nodes if node not in kept]
    bottom = max(y for _, y in kept.values()) + NODE_HEIGHT + V_GAP
    for node in sorted(new_nodes, key=lambda node: fresh[node][1]):
        anchors = [other for other in adjacent[node] if other in kept]
        if anchors:  # Move with the neighbor it was laid out beside
            anchor = anchors[0]
            point = (fresh[node][0] - fresh[anchor][0] + kept[anchor][0],
                     fresh[node][1] - fresh[anchor][1] + kept[anchor][1])
        else:
            point = (fresh[node][0], fresh[node][1] + bottom)
        while overlaps(point, result.values()):
            point = (point[0] + NODE_WIDTH + H_GAP, point[1])
        result[node] = point
    return result


# ----------------------------------------------------------------- Arranging


def arrange_flat(nodes, edges, style=TOP_DOWN, root=None, weight=lambda node: 0, leaf_grids=True, spacing=1.0):
    """{node: (x, y)} in one of the arrangements, ignoring groups. leaf_grids: as layout_component's. spacing: the
    gaps' stretch."""
    style, axis = FLIPPED.get(style, (style, None))
    if axis is not None:  # Bottom to top, right to left: top to bottom turned upside down, left to right turned round
        return mirrored(arrange_flat(nodes, edges, style, root, weight, leaf_grids, spacing), axis)
    if style == CIRCLE:
        return layout(nodes, edges, root, weight, component=circle_component, spacing=spacing)
    positions = layout(nodes, edges, root, weight, component=functools.partial(layout_component,
                                                                                 leaf_grids=leaf_grids),
                       spacing=spacing)
    h_gap = H_GAP * spacing
    if style == LEFT_RIGHT:  # The layers turned on their side, spaced for boxes that are wider than tall
        stretch = (NODE_WIDTH + h_gap) / (NODE_HEIGHT + LEAF_GAP * spacing)
        return {node: (y * stretch, x / stretch) for node, (x, y) in positions.items()}
    if style == GRID:  # In the order the layers had them, so linked devices stay near each other
        order = sorted(positions, key=lambda node: (positions[node][1], positions[node][0], node))
        grid_row = NODE_HEIGHT + (GRID_ROW - NODE_HEIGHT) * spacing
        columns = max(1, round(math.sqrt(len(order) * 1.6 * grid_row / (NODE_WIDTH + h_gap))))
        return {node: (NODE_WIDTH / 2 + (number % columns) * (NODE_WIDTH + h_gap),
                       NODE_HEIGHT / 2 + (number // columns) * grid_row) for number, node in enumerate(order)}
    return positions


def mirrored(points, axis, sizes=None):
    """{key: (x, y)} turned round along axis (0: left for right, 1: top for bottom), taking up the same space.
    sizes: {key: (width, height)} where they aren't all device-sized."""
    if not points:
        return {}
    sizes = sizes or {}

    def half(key):
        return sizes.get(key, (NODE_WIDTH, NODE_HEIGHT))[axis] / 2

    total = (min(point[axis] - half(key) for key, point in points.items())
             + max(point[axis] + half(key) for key, point in points.items()))
    return {key: tuple(total - value if number == axis else value for number, value in enumerate(point))
            for key, point in points.items()}


def normalized(positions):
    """The positions moved so the boxes' top-left corner is at (0, 0), and the (width, height) they take up."""
    if not positions:
        return {}, 0, 0
    left = min(x for x, _ in positions.values()) - NODE_WIDTH / 2
    top = min(y for _, y in positions.values()) - NODE_HEIGHT / 2
    moved = {node: (x - left, y - top) for node, (x, y) in positions.items()}
    return (moved, max(x for x, _ in moved.values()) + NODE_WIDTH / 2,
            max(y for _, y in moved.values()) + NODE_HEIGHT / 2)


def pack(sizes, gap=GROUP_GAP):
    """Tile blocks of [(width, height)] in rows, in order, about as wide as they're tall (a bit wider, like a
    screen), each row centered under the widest. Returns the top-left corner of each and the (width, height) of
    the lot."""
    if not sizes:
        return [], 0, 0
    area = sum((width + gap) * (height + gap) for width, height in sizes)
    limit = max(max(width for width, _ in sizes), math.sqrt(area * 1.6))
    rows, x, y, row_height = [[]], 0, 0, 0  # Rows of [index, x, y]
    for index, (width, height) in enumerate(sizes):
        if x and x + width > limit:
            rows.append([])
            x, y, row_height = 0, y + row_height + gap, 0
        rows[-1].append((index, x, y))
        row_height = max(row_height, height)
        x += width + gap
    widths = [max(x + sizes[index][0] for index, x, _ in row) for row in rows]
    corners = [None] * len(sizes)
    for row, row_width in zip(rows, widths):
        for index, x, y in row:
            corners[index] = (x + (max(widths) - row_width) / 2, y)
    return corners, max(widths), y + row_height


def arrange(nodes, edges, style=TOP_DOWN, root=None, weight=lambda node: 0, path_of=None, order=lambda key: key,
            spacing=1.0):
    """{node: (x, y)} in an arrangement. With path_of (node -> [site, building, room], or fewer, of group keys) each
    group is arranged on its own inside a box (GROUP_PAD round it, GROUP_TITLE above). The boxes (and the devices in
    no group, together) are then arranged as the links between them go, as devices are; or with no links between
    them, tiled, the devices in no group first and then the groups in order(key) order. spacing: how much the gaps
    between devices, and between the boxes, are stretched."""
    path_of = path_of or {}
    if not any(path_of.get(node) for node in nodes):
        return arrange_flat(nodes, edges, style, root, weight, spacing=spacing)
    adjacent = neighbors_of(nodes, edges)

    def uplink(members):
        """The top device for some devices laid out together: the map's top device, if it's one of them, or else
        the one with links leaving them (the most linked of those), so those links don't run past the rest."""
        if root in members:
            return root
        inside = set(members)
        leaving = [node for node in members if adjacent[node] - inside]
        return max(leaving, key=lambda node: (len(adjacent[node] & inside), weight(node), node)) if leaving else None

    def place(members, level):
        direct = [node for node in members if len(path_of.get(node) or ()) <= level]
        inner = {}
        for node in members:
            if len(path_of.get(node) or ()) > level:
                inner.setdefault(path_of[node][level], []).append(node)
        blocks, block_of = [], {}  # (positions, width, height); node -> its block's index
        if direct:
            blocks.append(normalized(arrange_flat(direct, edges, style, uplink(direct), weight, spacing=spacing)))
            block_of.update(dict.fromkeys(direct, 0))
        for key in sorted(inner, key=order):
            positions, width, height = place(inner[key], level + 1)
            block_of.update(dict.fromkeys(inner[key], len(blocks)))
            blocks.append(({node: (x + GROUP_PAD, y + GROUP_PAD + GROUP_TITLE) for node, (x, y) in positions.items()},
                           width + 2 * GROUP_PAD, height + 2 * GROUP_PAD + GROUP_TITLE))
        sizes = [(width, height) for _, width, height in blocks]
        between = sorted({(block_of[a], block_of[b]) for a, b in edges
                          if a in block_of and b in block_of and block_of[a] != block_of[b]})
        if between:  # Laid out as their links go, as devices are, so the links between them cross as little
            centers = arrange_boxes(dict(enumerate(sizes)), between, style, root=block_of.get(uplink(members)),
                                    weight=lambda index: sum(weight(node) for node in blocks[index][0]),
                                    gap=GROUP_GAP * spacing, spacing=spacing)
            corners = [(centers[index][0] - width / 2, centers[index][1] - height / 2)
                       for index, (width, height) in enumerate(sizes)]
            width = max(left + size[0] for (left, _), size in zip(corners, sizes))
            height = max(top + size[1] for (_, top), size in zip(corners, sizes))
        else:
            corners, width, height = pack(sizes, GROUP_GAP * spacing)
        placed = {}
        for (positions, _, _), (left, top) in zip(blocks, corners):
            placed.update({node: (x + left, y + top) for node, (x, y) in positions.items()})
        return placed, width, height

    return place(list(nodes), 0)[0]


def arrange_in_place(positions, edges, style=TOP_DOWN, root=None, weight=lambda node: 0, path_of=None,
                     order=lambda key: key, spacing=1.0):
    """Arrange just these devices ({node: (x, y)} where they are now), keeping the top-left corner of the lot
    where it was."""
    if not positions:
        return {}
    left = min(x for x, _ in positions.values()) - NODE_WIDTH / 2
    top = min(y for _, y in positions.values()) - NODE_HEIGHT / 2
    placed, _, _ = normalized(arrange(list(positions), edges, style, root, weight, path_of, order, spacing))
    return {node: (x + left, y + top) for node, (x, y) in placed.items()}


def align(positions, how, sizes=None):
    """Line up {node: (x, y)} by their left, center or right edges, or top, middle or bottom. sizes: {node:
    (width, height)} where they aren't all device-sized."""
    if not positions:
        return {}
    sizes = sizes or {}

    def half(node, axis):
        return sizes.get(node, (NODE_WIDTH, NODE_HEIGHT))[axis] / 2

    axis = 0 if how in (LEFT, CENTER, RIGHT) else 1
    low = min(point[axis] - half(node, axis) for node, point in positions.items())
    high = max(point[axis] + half(node, axis) for node, point in positions.items())
    result = {}
    for node, point in positions.items():
        if how in (LEFT, TOP):
            value = low + half(node, axis)
        elif how in (RIGHT, BOTTOM):
            value = high - half(node, axis)
        else:
            value = (low + high) / 2
        result[node] = (value, point[1]) if axis == 0 else (point[0], value)
    return result


def distribute(positions, direction, sizes=None):
    """Space {node: (x, y)} evenly across (horizontal) or down (vertical) between the first and the last, at
    least DISTRIBUTE_MIN_GAP apart so ones lined up on top of each other spread out."""
    if len(positions) < 2:
        return dict(positions)
    sizes = sizes or {}
    axis = 0 if direction == HORIZONTAL else 1
    nodes = sorted(positions, key=lambda node: (positions[node][axis], positions[node][1 - axis], node))
    extent = [sizes.get(node, (NODE_WIDTH, NODE_HEIGHT))[axis] for node in nodes]
    start = positions[nodes[0]][axis] - extent[0] / 2
    end = positions[nodes[-1]][axis] + extent[-1] / 2
    gap = max(DISTRIBUTE_MIN_GAP, (end - start - sum(extent)) / (len(nodes) - 1))
    result, edge = {}, start
    for node, size in zip(nodes, extent):
        result[node] = (edge + size / 2, positions[node][1]) if axis == 0 else (positions[node][0], edge + size / 2)
        edge += size + gap
    return result


# ----------------------------------------------------------------- Spacing out what's there


def apart(dx, dy, half_widths, half_heights, scale=1.0):
    """How far apart two boxes are, as a spacing (1.0: as Normal leaves them): the gap between them the way they're
    apart, over the gap Normal leaves that way (H_GAP side by side, LEAF_GAP one above the other). Below 0 when they
    overlap. dx, dy: from one's center to the other's (times scale); half_widths, half_heights: their halves added."""
    return max((scale * abs(dx) - half_widths) / H_GAP, (scale * abs(dy) - half_heights) / LEAF_GAP)


def nearest_pairs(points, sizes=None):
    """For each of {key: (x, y)}, (dx, dy, half widths, half heights) to the one nearest it that it doesn't overlap."""
    sizes = sizes or {}
    keys = list(points)
    found = []
    for a in keys:
        (ax, ay), (aw, ah) = points[a], sizes.get(a, (NODE_WIDTH, NODE_HEIGHT))
        best = None
        for b in keys:
            if b == a:
                continue
            (bx, by), (bw, bh) = points[b], sizes.get(b, (NODE_WIDTH, NODE_HEIGHT))
            pair = (bx - ax, by - ay, (aw + bw) / 2, (ah + bh) / 2)
            separation = apart(*pair)
            if separation >= 0 and (best is None or separation < best[0]):
                best = (separation, pair)
        if best is not None:
            found.append(best[1])
    return found


def spacing_of(points, sizes=None):
    """How far apart {key: (x, y)} are now, as a spacing (1.0: as Normal leaves them, whichever way they were
    arranged): how far each typically is from its nearest neighbor. None when no two are apart."""
    pairs = nearest_pairs(points, sizes)
    if not pairs:
        return None
    return sorted(apart(*pair) for pair in pairs)[len(pairs) // 2]


def nearest_spacing(value):
    """The key of the spacing (SPACINGS) within a fifth of value, if there is one."""
    if not value or value <= 0:
        return None
    key = min(SPACINGS, key=lambda key: abs(math.log(SPACINGS[key] / value)))
    return key if abs(math.log(SPACINGS[key] / value)) < math.log(1.2) else None


def respace(points, spacing, sizes=None, min_gap=lambda a, b: RESPACE_MIN_GAP):
    """{key: (x, y)} stretched or shrunk evenly about the top-left one, so they're as far apart as spacing leaves
    things (spacing_of), keeping how they're arranged. Shrinking stops before any two that were apart come closer
    than min_gap(a, b) (two closer than that already, before they'd overlap). sizes: {key: (width, height)} where
    they aren't all device-sized."""
    scale, scaled = 1.0, dict(points)
    for _ in range(RESPACE_ROUNDS):  # Stretched, a box's nearest neighbor can be another: measured again
        pairs = nearest_pairs(scaled, sizes)
        if not pairs:
            return dict(points)
        middle = len(pairs) // 2
        if abs(sorted(apart(*pair) for pair in pairs)[middle] - spacing) < 0.02 * spacing:
            break
        low, high = 0.01, 100.0
        for _ in range(50):  # Grows with the scale
            step = math.sqrt(low * high)
            low, high = (step, high) if sorted(apart(*pair, step) for pair in pairs)[middle] < spacing else (low, step)
        scale *= high
        scaled = {key: (x * scale, y * scale) for key, (x, y) in points.items()}
    if scale < 1:
        sizes = sizes or {}
        keys = list(points)
        for number, a in enumerate(keys):
            (ax, ay), (aw, ah) = points[a], sizes.get(a, (NODE_WIDTH, NODE_HEIGHT))
            for b in keys[number + 1:]:
                (bx, by), (bw, bh) = points[b], sizes.get(b, (NODE_WIDTH, NODE_HEIGHT))
                dx, dy, half_widths, half_heights = abs(bx - ax), abs(by - ay), (aw + bw) / 2, (ah + bh) / 2
                gap = max(dx - half_widths, dy - half_heights)
                if gap < 0:
                    continue  # Overlapping already
                need = min_gap(a, b)
                if gap < need:
                    need = 0  # Close already: only kept from overlapping
                ways = [(need + half) / distance for distance, half in ((dx, half_widths), (dy, half_heights))
                        if distance > 1e-9]
                scale = max(scale, min(ways))  # Kept that far apart one way or the other
    left = min(x for x, _ in points.values())
    top = min(y for _, y in points.values())
    return {key: (left + (x - left) * scale, top + (y - top) * scale) for key, (x, y) in points.items()}


# ----------------------------------------------------------------- Arranging boxes (groups among devices)


def arrange_boxes(sizes, edges, style=TOP_DOWN, weight=lambda node: 0, gap=GROUP_GAP, root=None, spacing=1.0):
    """Centers {key: (x, y)} for boxes of {key: (width, height)} (groups' boxes, perhaps with devices among them) in
    an arrangement, the top-left corner of the lot at (0, 0). They're laid out as if they were device-sized, then
    each row of that (each column, left to right) is spread out to fit the boxes' real sizes, gap apart: each box as
    near as it can be to the middle of the boxes it links to in the rows before (a grid's rows are just centered).
    In a circle, the whole circle is stretched to fit the biggest. Bottom to top and right to left are top to bottom
    and left to right turned round."""
    if not sizes:
        return {}
    style, axis = FLIPPED.get(style, (style, None))
    if axis is not None:
        return mirrored(arrange_boxes(sizes, edges, style, weight, gap, root, spacing), axis, sizes)
    flat = arrange_flat(list(sizes), edges, style, root, weight, leaf_grids=False, spacing=spacing)
    if style == CIRCLE:
        stretch_x = max(1, (max(width for width, _ in sizes.values()) + gap) / (NODE_WIDTH + H_GAP * spacing))
        stretch_y = max(1, (max(height for _, height in sizes.values()) + gap) / (NODE_HEIGHT + LEAF_GAP * spacing))
        centers = {key: (x * stretch_x, y * stretch_y) for key, (x, y) in flat.items()}
        left = min(x - sizes[key][0] / 2 for key, (x, _) in centers.items())
        top = min(y - sizes[key][1] / 2 for key, (_, y) in centers.items())
        return {key: (x - left, y - top) for key, (x, y) in centers.items()}
    across = 1 if style == LEFT_RIGHT else 0  # The axis a row runs along
    lines = {}
    for key, point in flat.items():
        lines.setdefault(round(point[1 - across], 3), []).append(key)
    rows = [sorted(lines[at], key=lambda key: (flat[key][across], key)) for at in sorted(lines)]
    lengths = [sum(sizes[key][across] for key in row) + gap * (len(row) - 1) for row in rows]
    adjacent = neighbors_of(list(sizes), edges)
    result, offset = {}, 0
    for row, length in zip(rows, lengths):
        wants, along = [], (max(lengths) - length) / 2  # Centered on the longest row, failing anything better
        for key in row:
            linked = [result[other][across] for other in adjacent[key] if other in result]
            if linked and style != GRID:
                wants.append(sum(linked) / len(linked) - sizes[key][across] / 2)
            else:
                wants.append(along)
            along += sizes[key][across] + gap
        for key, start in zip(row, spread(wants, [sizes[key][across] for key in row], gap)):
            center = [0, 0]
            center[across] = start + sizes[key][across] / 2
            center[1 - across] = offset + sizes[key][1 - across] / 2  # Lined up along the row's top (or left)
            result[key] = tuple(center)
        offset += max(sizes[key][1 - across] for key in row) + gap
    low = min(point[across] - sizes[key][across] / 2 for key, point in result.items())
    return {key: tuple(value - low if axis == across else value for axis, value in enumerate(point))
            for key, point in result.items()}


def spread(wants, sizes, gap):
    """Where boxes in a row start (in order along it, sizes long), as near as they can be to where they want to
    start without overlapping or coming closer than gap: those that would overlap move together, to the average of
    where they want to be."""
    runs = []  # [first box, last box, sum over its boxes of (where it wants to start - its offset in the run)]
    for index, want in enumerate(wants):
        runs.append([index, index, want])
        while len(runs) > 1:
            before, after = runs[-2], runs[-1]
            length = sum(sizes[before[0]:before[1] + 1]) + gap * (before[1] - before[0] + 1)
            if before[2] / (before[1] - before[0] + 1) + length <= after[2] / (after[1] - after[0] + 1):
                break
            before[2] += after[2] - length * (after[1] - after[0] + 1)
            before[1] = after[1]
            runs.pop()
    starts = []
    for first, last, total in runs:
        start = total / (last - first + 1)
        for index in range(first, last + 1):
            starts.append(start)
            start += sizes[index] + gap
    return starts


def arrange_boxes_in_place(boxes, edges, style=TOP_DOWN, weight=lambda node: 0, spacing=1.0):
    """arrange_boxes for {key: (center x, center y, width, height)} where they are now, keeping the top-left corner
    of the lot where it was. Returns their new centers {key: (x, y)}."""
    if not boxes:
        return {}
    left = min(x - width / 2 for x, _, width, _ in boxes.values())
    top = min(y - height / 2 for _, y, _, height in boxes.values())
    placed = arrange_boxes({key: (width, height) for key, (_, _, width, height) in boxes.items()}, edges, style,
                           weight, GROUP_GAP * spacing, spacing=spacing)
    return {key: (x + left, y + top) for key, (x, y) in placed.items()}
