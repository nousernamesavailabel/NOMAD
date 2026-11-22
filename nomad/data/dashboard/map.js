// The NOMAD Dashboard's map: the tribe map drawn in SVG as NOMAD lays it out and paints it (app.css has the colors),
// with each device's status, links colored by how busy they are, tunnels, and the site / building / room boxes.
// Drag to pan, wheel to zoom.
"use strict";
window.NomadMap = (function () {
  const SVG = "http://www.w3.org/2000/svg";
  const W = 170, H = 58, STRIP = 34, R = 7;
  const KIND_TAGS = {switch: "SW", router: "RTR", firewall: "FW", wlc: "WLC", ap: "AP", server: "SRV"};
  const GROUP_KINDS = {site: "Site", building: "Building", room: "Room"};
  const MONITORED = new Set(["up", "down", "unknown", "cant"]);
  // The strip down a device's left side: its rounded corners on the left only
  const STRIP_PATH = `M${R},0 H${STRIP} V${H} H${R} A${R},${R} 0 0 1 0,${H - R} V${R} A${R},${R} 0 0 1 ${R},0 Z`;

  function el(tag, attrs, text) {
    const node = document.createElementNS(SVG, tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value !== undefined && value !== null) node.setAttribute(name, String(value));
    }
    if (text !== undefined) node.textContent = text;
    return node;
  }

  function utilClass(percent) {
    if (percent === null || percent === undefined) return "";
    if (percent >= 80) return "util-high";
    if (percent >= 50) return "util-mid";
    return "util-low";
  }

  function trim(text, length) {
    text = String(text || "");
    return text.length > length ? text.slice(0, length - 1) + "…" : text;
  }

  // How long, in a few letters, never rounded up (as NOMAD's boxes say it): 40 s, 12 min, 5 h 12 min, 3 d 5 h
  function shortFor(since) {
    const s = Math.max(0, Math.floor(Date.now() / 1000 - since));
    if (s < 60) return `${s} s`;
    if (s < 3600) return `${Math.floor(s / 60)} min`;
    if (s < 86400) {
      const hours = Math.floor(s / 3600), minutes = Math.floor(s / 60) % 60;
      return minutes ? `${hours} h ${minutes} min` : `${hours} h`;
    }
    const days = Math.floor(s / 86400), hours = Math.floor(s / 3600) % 24;
    return hours ? `${days} d ${hours} h` : `${days} d`;
  }

  // "R5" from "R5 (vrf MGMT-B)": the router a device is checked from, without the VRF (as NOMAD's boxes say it)
  function viaRouter(via) {
    return String(via || "").split(" (vrf ")[0];
  }

  // The two lines under a device's name, as NOMAD's boxes have them, with its uptime: [[text, class], ...]
  function detailLines(node) {
    let address = node.address || "";
    if (node.status === "up" && node.rtt !== null && node.rtt !== undefined) {
      if (!node.stale_text) address = [address, `${node.rtt < 1 ? "<1" : node.rtt} ms`].filter(Boolean).join(" · ");
    }
    const uptime = node.uptime !== null && node.uptime !== undefined ? `${node.uptime}%` : "";
    // "+": monitoring started again after it last changed, and knows only that it's been so at least this long
    const plus = node.exact === false ? "+" : "";
    const lasted = (word) => [node.since ? `${word} ${shortFor(node.since)}${plus}` : word, uptime].filter(Boolean).join(" · ");
    let second;
    if (node.stale_text) second = [node.stale_text, ""];  // The Map Watcher stopped: grayed, as it was then
    else if (node.status === "down") second = [lasted("Down"), "bad"];
    else if (node.status === "cant") second = [`Can't check: ${node.problem || ""}`, "warn"];
    else if (node.via) second = [[`Via ${viaRouter(node.via)}`, uptime].filter(Boolean).join(" · "), ""];
    else if (node.status === "up") second = [lasted("Up"), "good"];
    else if (node.status === "unknown") second = ["Being checked", ""];
    else second = [node.platform || "", ""];
    return [[address, ""], second];
  }

  function draw(box, data, onSelect, keep, selectedKey) {
    box.textContent = "";
    const svg = el("svg", {"aria-label": "Network map", role: "img"});
    const world = el("g");
    svg.appendChild(world);
    const nodes = new Map(data.nodes.map((node) => [node.key, node]));

    for (const group of data.groups || []) {
      const g = el("g", {class: `group ${group.kind || "site"}`});
      g.appendChild(el("rect", {class: "group-box", x: group.x, y: group.y, width: group.w, height: group.h, rx: 10}));
      const {x, y, w} = group, band = 30;
      g.appendChild(el("path", {class: "group-band",
        d: `M${x + 10},${y} H${x + w - 10} A10,10 0 0 1 ${x + w},${y + 10} V${y + band} H${x} V${y + 10} A10,10 0 0 1 ${x + 10},${y} Z`}));
      const inside = data.nodes.filter((n) => n.x >= x && n.x <= x + w && n.y >= y && n.y <= y + group.h);
      const down = inside.filter((n) => n.status === "down").length;
      const name = el("text", {class: "group-name", x: x + 12, y: y + 20}, `▾ ${group.name}`);
      name.appendChild(el("tspan", {class: "group-kind", dx: 10},
        `${GROUP_KINDS[group.kind] || ""}  ·  ${inside.length} device${inside.length === 1 ? "" : "s"}`));
      g.appendChild(name);
      if (down) g.appendChild(el("text", {class: "group-down", x: x + w - 12, y: y + 20, "text-anchor": "end"}, `${down} down`));
      world.appendChild(g);
    }
    const linkLayer = el("g");
    world.appendChild(linkLayer);
    for (const link of data.links) {
      const a = nodes.get(link.a), b = nodes.get(link.b);
      if (!a || !b) continue;
      const line = el("line", {class: `link ${link.unseen ? "unseen" : ""} ${utilClass(link.percent)}`,
        x1: a.x, y1: a.y, x2: b.x, y2: b.y});
      const tip = `${a.label} ${link.a_port || ""} – ${b.label} ${link.b_port || ""}` +
        (link.percent !== null && link.percent !== undefined ? `\n${link.percent}% used` : "") +
        (link.unseen ? "\nNot seen on the last read" : "");
      line.appendChild(el("title", {}, tip));
      linkLayer.appendChild(line);
    }
    for (const tunnel of data.tunnels || []) {
      const a = nodes.get(tunnel.a), b = nodes.get(tunnel.b);
      if (!a || !b) continue;
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2 - Math.max(40, Math.hypot(b.x - a.x, b.y - a.y) / 6);
      const path = el("path", {class: `tunnel ${tunnel.state}`, d: `M${a.x},${a.y} Q${mx},${my} ${b.x},${b.y}`});
      path.appendChild(el("title", {}, tunnel.text));
      linkLayer.appendChild(path);
    }
    const nodeLayer = el("g");
    world.appendChild(nodeLayer);
    let selected = null;
    for (const node of data.nodes) {
      const isSubnet = node.node === "subnet" || node.node === "hop" || node.node === "star";
      const monitored = !isSubnet && MONITORED.has(node.status);
      const classes = isSubnet ? "subnet" : `kind-${node.kind || "unknown"} ${node.status || "unmonitored"}` +
        (monitored ? " monitored" : "") + (node.stale_text ? " stale" : "");
      const g = el("g", {class: `node ${classes}`, transform: `translate(${node.x - W / 2},${node.y - H / 2})`,
        tabindex: 0});
      g.appendChild(el("rect", {class: "box", width: W, height: H, rx: R}));
      if (isSubnet) {
        g.appendChild(el("text", {class: "name", x: 10, y: 22}, trim(node.label, 22)));
        g.appendChild(el("text", {class: "sub", x: 10, y: 42}, trim(node.detail, 26)));
      } else {
        g.appendChild(el("path", {class: "strip", d: STRIP_PATH}));
        g.appendChild(el("text", {class: "tag", x: STRIP / 2, y: H / 2 + 4}, KIND_TAGS[node.kind] || "?"));
        g.appendChild(el("rect", {class: "tint", width: W, height: H, rx: R}));
        g.appendChild(el("text", {class: "name", x: STRIP + 6, y: 18}, trim(node.label, monitored ? 16 : 18)));
        detailLines(node).forEach(([text, tone], row) => {
          g.appendChild(el("text", {class: `sub ${tone}`, x: STRIP + 6, y: 34 + row * 15}, trim(text, 22)));
        });
        if (monitored) g.appendChild(el("circle", {class: "dot", cx: W - 10, cy: 10, r: 5.5}));
      }
      const uptimeTip = node.uptime !== null && node.uptime !== undefined ? `\nUp ${node.uptime}% of the last 24 hours` : "";
      g.appendChild(el("title", {}, node.label + (node.status_text ? ` – ${node.status_text}` : "") + uptimeTip));
      if (selectedKey && node.key === selectedKey) {
        g.classList.add("selected");
        selected = g;
      }
      g.addEventListener("click", (event) => {
        event.stopPropagation();
        if (selected) selected.classList.remove("selected");
        g.classList.add("selected");
        selected = g;
        onSelect(node);
      });
      g.addEventListener("keydown", (event) => {
        if (event.key === "Enter") g.dispatchEvent(new MouseEvent("click"));
      });
      nodeLayer.appendChild(g);
    }
    box.appendChild(svg);

    // Fit, pan and zoom (by changing the viewBox)
    const xs = data.nodes.map((n) => n.x), ys = data.nodes.map((n) => n.y);
    for (const group of data.groups || []) { xs.push(group.x, group.x + group.w); ys.push(group.y, group.y + group.h); }
    const bounds = xs.length ? {x: Math.min(...xs) - W, y: Math.min(...ys) - H, w: Math.max(...xs) - Math.min(...xs) + 2 * W,
      h: Math.max(...ys) - Math.min(...ys) + 2 * H} : {x: 0, y: 0, w: 800, h: 600};
    let view = keep && keep.view ? {...keep.view} : {...bounds};
    const apply = () => svg.setAttribute("viewBox", `${view.x} ${view.y} ${view.w} ${view.h}`);
    apply();
    let drag = null;
    svg.addEventListener("pointerdown", (event) => {
      if (event.target.closest && event.target.closest(".node")) return;
      drag = {x: event.clientX, y: event.clientY, view: {...view}};
      svg.classList.add("dragging");
      svg.setPointerCapture(event.pointerId);
    });
    svg.addEventListener("pointermove", (event) => {
      if (!drag) return;
      const scale = view.w / svg.clientWidth;
      view.x = drag.view.x - (event.clientX - drag.x) * scale;
      view.y = drag.view.y - (event.clientY - drag.y) * scale;
      apply();
    });
    const end = () => { drag = null; svg.classList.remove("dragging"); };
    svg.addEventListener("pointerup", end);
    svg.addEventListener("pointercancel", end);
    svg.addEventListener("wheel", (event) => {
      event.preventDefault();
      const factor = event.deltaY > 0 ? 1.15 : 1 / 1.15;
      const rect = svg.getBoundingClientRect();
      const px = view.x + (event.clientX - rect.left) / rect.width * view.w;
      const py = view.y + (event.clientY - rect.top) / rect.height * view.h;
      view = {x: px - (px - view.x) * factor, y: py - (py - view.y) * factor, w: view.w * factor, h: view.h * factor};
      apply();
    }, {passive: false});
    svg.addEventListener("click", () => {
      if (selected) selected.classList.remove("selected");
      selected = null;
      onSelect(null);
    });
    return {
      fit() { view = {...bounds}; apply(); },
      zoom(factor) {
        const cx = view.x + view.w / 2, cy = view.y + view.h / 2;
        view = {x: cx - view.w * factor / 2, y: cy - view.h * factor / 2, w: view.w * factor, h: view.h * factor};
        apply();
      },
      state() { return {view: {...view}}; },
    };
  }

  return {draw};
})();
