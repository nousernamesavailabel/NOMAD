// The NOMAD Dashboard: each page's data comes from /api/page/<page>, and the page is drawn again whenever the server
// says the data changed (Server-Sent Events). Everything shown is set as text, never as HTML.
"use strict";
(function () {
  const main = document.getElementById("main");
  const state = {page: "", params: {}, sort: {}, filters: {}, picks: {}, picker: null, map: null, mapKeep: {}, refreshTimer: null,
    kiosk: null, loading: false, selected: null, mapFull: false, browserFull: false,
    detailsHidden: readPref("map-details-hidden") === "1", detailsCache: null};

  // This browser's own choices (whether the map's details are hidden): may be refused, so never relied on
  function readPref(name) { try { return localStorage.getItem(name); } catch (error) { return null; } }
  function writePref(name, value) { try { localStorage.setItem(name, value); } catch (error) { /* Not kept */ } }

  // ----------------------------------------------------------------- Helpers

  function h(tag, attrs, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attrs || {})) {
      if (value === undefined || value === null || value === false) continue;
      if (name === "class") node.className = value;
      else if (name.startsWith("on")) node.addEventListener(name.slice(2), value);
      else node.setAttribute(name, value === true ? "" : String(value));
    }
    for (const child of children.flat(Infinity)) {  // Lists of lists too, such as the details' [dt, dd] pairs
      if (child === null || child === undefined || child === false) continue;
      node.appendChild(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  async function api(path) {
    const reply = await fetch(path, {credentials: "same-origin", headers: {"Accept": "application/json"}});
    if (reply.status === 401) {
      location.replace("/login" + location.hash);
      throw new Error("Signed out");
    }
    const data = await reply.json().catch(() => ({}));
    if (!reply.ok) throw new Error(data.error || `The dashboard said ${reply.status}`);
    return data;
  }

  function pad(n) { return String(n).padStart(2, "0"); }
  function fmtTime(seconds) {
    if (!seconds) return "";
    const d = new Date(seconds * 1000), now = new Date();
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
    if (d.toDateString() === now.toDateString()) return time;
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${time}`;
  }
  function fmtAgo(seconds) {
    if (!seconds) return "";
    let s = Math.max(0, Date.now() / 1000 - seconds);
    if (s < 60) return `${Math.round(s)} s`;
    s /= 60;
    if (s < 60) return `${Math.round(s)} min`;
    s /= 60;
    if (s < 48) return `${Math.round(s)} h`;
    return `${Math.round(s / 24)} days`;
  }
  function fmtBits(bps) {
    if (bps === null || bps === undefined) return "";
    const units = ["b/s", "kb/s", "Mb/s", "Gb/s", "Tb/s"];
    let i = 0;
    while (bps >= 1000 && i < units.length - 1) { bps /= 1000; i++; }
    return `${bps.toFixed(bps < 10 && i ? 1 : 0)} ${units[i]}`;
  }
  function fmtBytes(bytes) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    bytes = bytes || 0;
    while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
    return `${bytes.toFixed(bytes < 10 && i ? 1 : 0)} ${units[i]}`;
  }
  function fmtPercent(value) { return value === null || value === undefined ? "" : `${value}%`; }
  function status(code, text) { return h("span", {class: `status ${code}`}, text || code); }
  function bar(percent) {
    const value = Math.max(0, Math.min(100, percent || 0));
    const span = h("span");
    span.style.width = `${value}%`;
    return h("div", {class: "bar-cell"}, h("div", {class: `bar ${value >= 90 ? "full" : value >= 70 ? "hot" : ""}`},
      span), h("span", {class: "number small"}, fmtPercent(percent)));
  }
  function stat(label, value, tone, href) {
    return h(href ? "a" : "div", {class: `stat ${tone || ""}`, href}, h("div", {class: "value"}, value),
      h("div", {class: "label"}, label));
  }
  function hostCount(total, macOnly) {
    return `${total} host${total === 1 ? "" : "s"}` + (macOnly ? ` (and ${macOnly} with no address)` : "");
  }
  function panel(title, ...body) { return h("section", {class: "panel"}, title ? h("h2", {}, title) : null, ...body); }
  // Panels in two columns, each column stacked on its own so a short panel doesn't leave a gap under it.
  // Given in reading order (left, right, left, ...); one column on a narrow screen keeps that order.
  function stacks(...panels) {
    return h("div", {class: "grid two"}, [0, 1].map((side) =>
      h("div", {class: "stack"}, panels.filter((_, index) => index % 2 === side))));
  }
  function empty(text) { return h("p", {class: "empty"}, text); }
  function head(title, subtitle, ...tools) {
    return h("div", {class: "page-head"}, h("div", {}, h("h1", {}, title), subtitle ? h("div", {class: "muted"},
      subtitle) : null), h("div", {class: "tools"}, ...tools));
  }
  function csvLink(name, params) {
    const query = new URLSearchParams(params || {}).toString();
    return h("a", {class: "plain-link", href: `/export/${name}.csv${query ? "?" + query : ""}`, download: ""},
      "Download CSV");
  }
  function notices(freshness) {
    const items = [];
    if (freshness && freshness.watcher && !freshness.watcher.ok) items.push(freshness.watcher.text);
    if (freshness && freshness.tribe && !freshness.tribe.ok) items.push(freshness.tribe.text);
    return items.map((text) => h("div", {class: "notice"}, text));
  }

  // A table as NOMAD's: click a header to sort, click its funnel (or right-click the header) for an Excel-style list
  // of the column's values to tick, and type in the box above to show only rows with every word. Filters on several
  // columns combine, and are kept by the values ticked, so they carry over when the page is drawn again.
  // columns: [{key, label, number, render(row), value(row)}]: value sorts, the text shown filters.
  const BLANK = "(Blanks)";
  function compareValues(x, y) {
    if (x === y) return 0;
    if (x === null || x === undefined || x === "") return 1;
    if (y === null || y === undefined || y === "") return -1;
    return typeof x === "number" && typeof y === "number" ? x - y :
      String(x).localeCompare(String(y), undefined, {numeric: true, sensitivity: "base"});
  }
  function funnelIcon() {
    const SVG = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("viewBox", "0 0 10 10");
    svg.setAttribute("aria-hidden", "true");
    const path = document.createElementNS(SVG, "path");
    path.setAttribute("d", "M0.5 1h9L6 5.2V9L4 8V5.2z");
    svg.appendChild(path);
    return svg;
  }
  function table(id, columns, rows, options) {
    options = options || {};
    const sort = state.sort[id] || options.sort || null;
    const picks = state.picks[id] || (state.picks[id] = {});  // Column key -> Set of the texts shown
    for (const key of Object.keys(picks)) if (!columns.some((column) => column.key === key)) delete picks[key];
    const words = (state.filters[id] || "").toLowerCase().split(/\s+/).filter(Boolean);
    // Each cell drawn once: its node to show and its text to filter on
    const cells = rows.map((row) => columns.map((column) => {
      const shown = column.render ? column.render(row) : (row[column.key] ?? "");
      return {shown, text: shown instanceof Node ? shown.textContent.trim() : String(shown ?? "").trim()};
    }));
    const passes = (index, skip) => {
      for (const [place, column] of columns.entries()) {
        const allowed = picks[column.key];
        if (allowed && column.key !== skip && !allowed.has(cells[index][place].text)) return false;
      }
      if (!words.length) return true;
      const line = cells[index].map((cell) => cell.text).concat(columns.map((column) => {
        const value = column.value ? column.value(rows[index]) : rows[index][column.key];
        return value === null || value === undefined || typeof value === "object" ? "" : String(value);
      })).join(" ").toLowerCase();
      return words.every((word) => line.includes(word));
    };
    let order = rows.map((_, index) => index).filter((index) => passes(index));
    if (sort) {
      const column = columns.find((item) => item.key === sort.key);
      if (column) {
        const value = (index) => column.value ? column.value(rows[index]) : rows[index][column.key];
        order = order.map((index) => [index, value(index)]).sort((a, b) => {
          const result = compareValues(a[1], b[1]);
          return sort.down ? -result : result;
        }).map((pair) => pair[0]);
      }
    }
    const filtered = Object.keys(picks).length > 0;
    const header = h("tr", {}, columns.map((column) => {
      const open = (event) => {
        event.preventDefault();
        event.stopPropagation();
        openPicker(id, columns, column, cells, passes, event.currentTarget.closest("th"));
      };
      return h("th", {
        class: `${column.number ? "number" : ""} ${sort && sort.key === column.key ? (sort.down ? "sorted-down" :
          "sorted-up") : ""}`,
        oncontextmenu: open,
        onclick: () => {
          const now = state.sort[id];
          state.sort[id] = {key: column.key, down: now && now.key === column.key ? !now.down : !!column.number};
          render(state.data);
        }},
      h("button", {type: "button", class: `funnel ${picks[column.key] ? "active" : ""}`, onclick: open,
        title: picks[column.key] ? `Filtered: choose which ${column.label} to show` : `Filter by ${column.label}`,
        "aria-label": `Filter by ${column.label}`}, funnelIcon()),
      column.label);
    }));
    const body = order.map((index) => h("tr", {class: options.rowClass ? options.rowClass(rows[index]) : ""},
      columns.map((column, place) => h("td", {class: column.number ? "number" : ""}, cells[index][place].shown))));
    if (!body.length && rows.length) {
      body.push(h("tr", {}, h("td", {class: "muted", colspan: columns.length}, "No rows match the filters.")));
    }
    const countText = order.length === rows.length ? `${rows.length} row${rows.length === 1 ? "" : "s"}` :
      `${order.length} of ${rows.length} rows`;
    const wrap = h("div", {class: "table-wrap", id: `table-${id}`},
      rows.length ? h("table", {}, h("thead", {}, header), h("tbody", {}, body)) :
        empty(options.empty || "Nothing to show."));
    if (options.filterOnly) {
      const count = document.getElementById(`count-${id}`);
      if (count) count.textContent = countText;
      return wrap;
    }
    const parts = [];
    if (rows.length > 8 || words.length || filtered) {
      const input = h("input", {class: "filter", id: `filter-${id}`, type: "search", placeholder: "Filter",
        value: state.filters[id] || "", "aria-label": "Filter the table"});
      input.addEventListener("input", () => {
        state.filters[id] = input.value;
        document.getElementById(`table-${id}`).replaceWith(table(id, columns, rows, {...options, filterOnly: true}));
      });
      parts.push(h("div", {class: "page-head table-tools"}, input,
        h("span", {class: "muted small", id: `count-${id}`}, countText),
        filtered ? h("button", {type: "button", class: "plain small", onclick: () => {
          state.picks[id] = {};
          render(state.data);
        }}, "Clear Column Filters") : null));
    }
    return h("div", {}, ...parts, wrap);
  }

  // The funnel's drop-down: the column's values (over the rows the other columns' filters let through, as Excel
  // does) to tick, a search box that ticks what it matches, and sorting
  function closePicker() {
    if (!state.picker) return;
    state.picker.remove();
    state.picker = null;
    document.removeEventListener("mousedown", pickerOutside, true);
    document.removeEventListener("keydown", pickerKey, true);
  }
  function pickerOutside(event) { if (state.picker && !state.picker.contains(event.target)) closePicker(); }
  function pickerKey(event) { if (event.key === "Escape") closePicker(); }
  function openPicker(id, columns, column, cells, passes, anchor) {
    closePicker();
    const place = columns.indexOf(column);
    const counts = new Map();
    cells.forEach((row, index) => {
      if (passes(index, column.key)) counts.set(row[place].text, (counts.get(row[place].text) || 0) + 1);
    });
    const values = [...counts.keys()].sort(compareValues);
    const picks = state.picks[id];
    const allowed = picks[column.key];
    const items = values.map((text) => {
      const box = h("input", {type: "checkbox"});
      box.checked = !allowed || allowed.has(text);
      const label = h("label", {}, box, h("span", {class: text ? "" : "muted"}, text || BLANK),
        h("span", {class: "count"}, counts.get(text)));
      return {text, box, label};
    });
    const all = h("input", {type: "checkbox"});
    const updateAll = () => {
      const shown = items.filter((item) => !item.label.hidden);
      const ticked = shown.filter((item) => item.box.checked).length;
      all.checked = shown.length > 0 && ticked === shown.length;
      all.indeterminate = ticked > 0 && ticked < shown.length;
    };
    all.addEventListener("change", () => {
      for (const item of items) if (!item.label.hidden) item.box.checked = all.checked;
      updateAll();
    });
    for (const item of items) item.box.addEventListener("change", updateAll);
    const search = h("input", {type: "search", placeholder: "Search", "aria-label": "Search the values"});
    search.addEventListener("input", () => {
      const text = search.value.trim().toLowerCase();
      for (const item of items) {
        item.label.hidden = !!text && !(item.text || BLANK).toLowerCase().includes(text);
        if (text) item.box.checked = !item.label.hidden;  // As in Excel: searching ticks what matches
      }
      updateAll();
    });
    const apply = () => {
      const chosen = new Set(items.filter((item) => item.box.checked && !item.label.hidden).map((item) => item.text));
      if (chosen.size === items.length) delete picks[column.key];  // Everything ticked: no filter, as in NOMAD
      else picks[column.key] = chosen;
      closePicker();
      render(state.data);
    };
    search.addEventListener("keydown", (event) => { if (event.key === "Enter") { event.preventDefault(); apply(); } });
    const act = (text, action) => h("button", {type: "button", class: "plain", onclick: () => {
      closePicker();
      action();
      render(state.data);
    }}, text);
    const others = Object.keys(picks).some((key) => key !== column.key);
    const popup = h("div", {class: "picker", role: "dialog", "aria-label": `Filter by ${column.label}`},
      h("div", {class: "picker-title"}, `Show rows where ${column.label} is:`),
      search,
      h("div", {class: "picker-list"}, h("label", {}, all, h("span", {}, "(Select All)")),
        items.map((item) => item.label)),
      h("div", {class: "picker-buttons"},
        h("button", {type: "button", onclick: apply}, "OK"),
        h("button", {type: "button", class: "plain", onclick: closePicker}, "Cancel")),
      h("div", {class: "picker-menu"},
        allowed ? act(`Clear Filter from "${column.label}"`, () => { delete picks[column.key]; }) : null,
        others ? act("Clear All Filters", () => { state.picks[id] = {}; }) : null,
        act(column.number ? "Sort Smallest to Largest" : "Sort A to Z", () => {
          state.sort[id] = {key: column.key, down: false};
        }),
        act(column.number ? "Sort Largest to Smallest" : "Sort Z to A", () => {
          state.sort[id] = {key: column.key, down: true};
        })));
    updateAll();
    document.body.appendChild(popup);
    state.picker = popup;
    // Under the header cell (above it if there's no room below), kept on the screen
    const rect = anchor.getBoundingClientRect();
    const width = popup.offsetWidth, height = popup.offsetHeight;
    const left = Math.max(8, Math.min(rect.left, window.innerWidth - width - 8));
    const top = rect.bottom + height + 8 > window.innerHeight && rect.top - height - 4 > 0 ?
      rect.top - height - 4 : rect.bottom + 2;
    popup.style.left = `${left + window.scrollX}px`;
    popup.style.top = `${top + window.scrollY}px`;
    document.addEventListener("mousedown", pickerOutside, true);
    document.addEventListener("keydown", pickerKey, true);
    search.focus();
  }

  // A line chart: points [[time, a, b, peakA, peakB]]
  function chart(points, options) {
    const SVG = "http://www.w3.org/2000/svg";
    const svg = document.createElementNS(SVG, "svg");
    svg.setAttribute("class", "chart");
    const width = 900, height = 260, left = 64, right = 12, top = 10, bottom = 28;
    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    const add = (tag, attrs, text) => {
      const node = document.createElementNS(SVG, tag);
      for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, String(value));
      if (text !== undefined) node.textContent = text;
      svg.appendChild(node);
      return node;
    };
    if (!points.length) {
      add("text", {x: width / 2, y: height / 2, class: "tick", "text-anchor": "middle"}, "No samples in this time yet");
      return svg;
    }
    let t0 = points[0][0], t1 = points[points.length - 1][0];
    if (t1 - t0 < 60) { t0 -= 1800; t1 += 1800; }  // One sample: a span round it
    const series = options.series;
    let max = 0;
    for (const point of points) for (const index of series) max = Math.max(max, point[index] || 0);
    max = max || 1;
    const x = (t) => left + (t - t0) / Math.max(1, t1 - t0) * (width - left - right);
    const y = (v) => top + (1 - v / max) * (height - top - bottom);
    for (let i = 0; i <= 4; i++) {
      const v = max * i / 4;
      add("line", {x1: left, x2: width - right, y1: y(v), y2: y(v), class: "grid-line"});
      add("text", {x: left - 6, y: y(v) + 4, class: "tick", "text-anchor": "end"}, options.format(v));
    }
    for (let i = 0; i <= 5; i++) {
      const t = t0 + (t1 - t0) * i / 5;
      add("text", {x: x(t), y: height - 8, class: "tick", "text-anchor": i === 0 ? "start" : i === 5 ? "end" : "middle"},
        fmtTime(t));
    }
    const classes = options.classes;
    series.forEach((index, n) => {
      const d = points.map((point, i) => `${i ? "L" : "M"}${x(point[0]).toFixed(1)},${y(point[index] || 0).toFixed(1)}`)
        .join(" ");
      add("path", {d, class: classes[n]});
      if (points.length < 40) {  // Few samples: mark each one
        for (const point of points) add("circle", {cx: x(point[0]), cy: y(point[index] || 0), r: 3, class: classes[n]});
      }
    });
    return svg;
  }

  // ----------------------------------------------------------------- Pages

  const DEVICE_STATUS_ORDER = {down: 0, cant: 1, unknown: 2, up: 3, unmonitored: 4};
  const deviceColumns = [
    {key: "status", label: "Status", render: (r) => status(r.status, r.status_text), value: (r) => DEVICE_STATUS_ORDER[r.status]},
    {key: "name", label: "Name"},
    {key: "address", label: "Address", render: (r) => h("span", {class: "mono"}, r.address)},
    {key: "kind", label: "Kind"},
    {key: "map", label: "Map"},
    {key: "group", label: "Site / Building / Room"},
    {key: "since", label: "For", render: (r) => r.stale_text ? r.stale_text : r.since ? fmtAgo(r.since) + (r.exact === false ? "+" : "") : "",
     value: (r) => r.since ? -r.since : null},
    {key: "rtt", label: "Response", number: true, render: (r) => r.rtt === null || r.rtt === undefined ? "" : `${r.rtt} ms`},
    {key: "via", label: "Checked from", render: (r) => r.via || (r.problem ? h("span", {class: "muted"}, r.problem) : "")},
    {key: "uptime_24h", label: "Up 24 h", number: true, render: (r) => fmtPercent(r.uptime_24h)},
    {key: "uptime_7d", label: "Up 7 d", number: true, render: (r) => fmtPercent(r.uptime_7d)},
    {key: "uptime_30d", label: "Up 30 d", number: true, render: (r) => fmtPercent(r.uptime_30d)},
  ];

  const pages = {
    overview(data) {
      const c = data.counts;
      return [
        ...notices(data.freshness),
        head("Overview", `${data.total} devices on ${data.maps.length} tribe map${data.maps.length === 1 ? "" : "s"}`),
        h("div", {class: "stats"},
          stat("Down", c.down, c.down ? "down" : "up"),
          stat("Up", c.up, "up"),
          stat("Checking / can't check", c.unknown + c.cant, c.unknown + c.cant ? "warn" : ""),
          stat("Not monitored", c.unmonitored),
          stat(`Hosts seen (last ${data.hosts.window})`, data.hosts.total, "accent", `#hosts?window=${data.hosts.window}`),
          stat("Syslog errors (24 h)", data.syslog_severe, data.syslog_severe ? "warn" : ""),
          stat("NetFlow (last hour)", data.flows.available ? fmtBytes(data.flows.bytes) : "–", "accent")),
        stacks(
          panel("Down now", data.down.length ? table("ov-down", deviceColumns.slice(0, 7), data.down) :
            empty("Nothing is down.")),
          panel("Recent events", data.events.length ? h("div", {}, data.events.map((event) => h("div", {class: "event"},
            h("span", {class: `pill ${event.kind}`}, event.kind), " ", h("span", {class: "muted small"}, fmtTime(event.at)),
            " ", event.text))) : empty("Nothing has happened in the last day.")),
          panel("Maps", table("ov-maps", [
            {key: "name", label: "Map", render: (r) => h("a", {href: `#map?id=${r.id}`}, r.name)},
            {key: "total", label: "Devices", number: true},
            {key: "down", label: "Down", number: true, value: (r) => r.counts.down,
              render: (r) => r.counts.down ? status("down", String(r.counts.down)) : "0"},
            {key: "up", label: "Up", number: true, value: (r) => r.counts.up, render: (r) => r.counts.up},
            {key: "hosts", label: `Hosts (${data.hosts.window})`, number: true},
            {key: "monitored", label: "Monitored", render: (r) => r.monitored ? "Yes" : h("span", {class: "muted"}, "No")},
          ], data.maps, {empty: "No tribe maps yet."})),
          panel(`Hosts per subnet on the maps (last ${data.hosts.window})`, data.map_subnets.length ? table("ov-subnets", [
            {key: "map", label: "Map"},
            {key: "subnet", label: "Subnet", render: (r) => h("a", {class: "mono",
              href: `#trends?${new URLSearchParams({subnet: r.subnet, network: r.network})}`}, r.subnet)},
            {key: "name", label: "Name"},
            {key: "total", label: "Hosts", number: true},
            {key: "percent", label: "Of the subnet", number: true, render: (r) => bar(r.percent)},
          ], data.map_subnets) : empty("No subnets on the maps yet: they come from the devices' interface addresses.")),
          panel("Busiest links", data.busiest.length ? table("ov-busy", [
            {key: "name", label: "Device"}, {key: "port", label: "Port"}, {key: "to", label: "To"},
            {key: "percent", label: "Use", number: true, render: (r) => bar(r.percent)},
          ], data.busiest) : empty("No link traffic read yet.")),
          panel("Fullest subnets", data.fullest.length ? table("ov-full", [
            {key: "subnet", label: "Subnet", render: (r) => h("span", {class: "mono"}, r.subnet)},
            {key: "name", label: "Name"}, {key: "network", label: "Network"},
            {key: "percent", label: "Used", number: true, render: (r) => bar(r.percent)},
          ], data.fullest) : empty("No IPAM subnets yet."))),
      ];
    },

    sites(data) {
      return [
        ...notices(data.freshness),
        head("Sites", "Each site's devices: click one to open its map"),
        data.sites.length ? h("div", {class: "tiles"}, data.sites.map((tile) => h("div", {
          class: `tile ${tile.state}`, tabindex: 0, role: "link",
          onclick: () => { location.hash = `#map?id=${tile.map_id}`; },
          onkeydown: (event) => { if (event.key === "Enter") location.hash = `#map?id=${tile.map_id}`; }},
        h("div", {class: "site"}, tile.site), h("div", {class: "muted small"}, tile.map),
        h("div", {class: "counts"}, status("up", `${tile.counts.up} up`),
          tile.counts.down ? status("down", `${tile.counts.down} down`) : null,
          tile.counts.unknown + tile.counts.cant ? status("unknown", `${tile.counts.unknown + tile.counts.cant} checking`) : null,
          tile.counts.unmonitored ? status("unmonitored", `${tile.counts.unmonitored} not monitored`) : null),
        tile.down.length ? h("div", {class: "down-list"}, "Down: " + tile.down.join(", ") +
          (tile.down_count > tile.down.length ? ` and ${tile.down_count - tile.down.length} more` : "")) : null)))
          : empty("No tribe maps yet: share a map with the tribe from NOMAD's Network Map page."),
      ];
    },

    map(data) {
      const maps = data.maps || [];
      const id = Number(state.params.id || (maps[0] && maps[0].id) || 0);
      if (!state.params.id && id) {
        // Not in kiosk mode: its address has to stay #kiosk... so the wall screen comes back to it after a reload
        if (!document.body.classList.contains("kiosk")) {
          history.replaceState(null, "", `#map?id=${id}&view=${state.params.view || "l2"}`);
        }
        state.params.id = String(id);
        load();
        return [h("p", {class: "muted"}, "Loading...")];
      }
      if (!maps.length) return [head("Map"), empty("No tribe maps yet.")];
      const select = h("select", {"aria-label": "Map", onchange: () => { location.hash = `#map?id=${select.value}&view=${state.params.view || "l2"}`; }},
        maps.map((item) => h("option", {value: item.id, selected: item.id === id}, item.name)));
      const view = state.params.view || "l2";
      const viewButton = (code, label) => h("button", {class: `plain ${view === code ? "active" : ""}`,
        onclick: () => { location.hash = `#map?id=${id}&view=${code}`; }}, label);
      const box = h("div", {class: "map-box"});
      const details = h("div", {class: "panel details"}, h("h2", {}, "Details"),
        h("p", {class: "muted"}, "Click a device to see its details."));
      const controls = h("div", {class: "map-controls"},
        h("button", {class: "plain", title: "Zoom in", onclick: () => state.map && state.map.zoom(1 / 1.3)}, "+"),
        h("button", {class: "plain", title: "Zoom out", onclick: () => state.map && state.map.zoom(1.3)}, "−"),
        h("button", {class: "plain", title: "Fit the map", onclick: () => state.map && state.map.fit()}, "Fit"),
        h("span", {class: "gap"}),
        h("button", {class: "plain", title: "Show or hide the device details beside the map",
          onclick: () => setDetailsHidden(!state.detailsHidden)}, state.detailsHidden ? "Show Details" : "Hide Details"),
        h("button", {class: "plain", title: state.mapFull ? "Back to the page (Esc)" : "Give the map the whole screen (Esc to come back)",
          onclick: () => setMapFull(!state.mapFull)}, state.mapFull ? "Exit Full Screen" : "Full Screen"));
      const title = h("div", {class: "map-title"}, `${data.map ? data.map.name : "Map"} – ${view === "l3" ? "Logical (L3)" : "Physical (L2)"}`);
      const legend = h("div", {class: "map-legend"},
        h("span", {}, status("up", "Up")), h("span", {}, status("down", "Down")),
        h("span", {}, status("unknown", "Checking")), h("span", {}, status("unmonitored", "Not monitored")),
        h("span", {class: "muted"}, "Boxes: up or down for how long (+: at least) · uptime over 24 h"),
        view === "l2" ? h("span", {class: "muted"}, "Links: green < 50%, amber < 80%, red busier; faint: not seen lately; dashed: tunnels") : null);
      const wrapper = h("div", {class: `map-layout ${state.detailsHidden ? "no-details" : ""}`}, h("div", {}, box), details);
      setTimeout(() => {
        const keepKey = `${id}:${view}`;
        state.map = window.NomadMap.draw(box, data, (node) => showDetails(details, node), state.mapKeep[keepKey],
          state.selected);
        state.mapKeepKey = keepKey;
        box.appendChild(title);
        box.appendChild(controls);
        box.appendChild(legend);
        if (state.selected) {
          const node = data.nodes.find((item) => item.key === state.selected);
          if (node) showDetails(details, node);
        }
      });
      return [...notices(data.freshness),
        head(data.map ? data.map.name : "Map", data.nodes.length ? `${data.nodes.length} ${view === "l3" ? "nodes" : "devices"}` : "",
          select, viewButton("l2", "Physical (L2)"), viewButton("l3", "Logical (L3)")), wrapper];
    },

    devices(data) {
      const filter = state.params.status || "";
      const rows = filter ? data.devices.filter((row) => row.status === filter) : data.devices;
      const choose = h("select", {"aria-label": "Status", onchange: () => {
        location.hash = choose.value ? `#devices?status=${choose.value}` : "#devices";
      }}, [["", "Every status"], ["down", "Down"], ["up", "Up"], ["unknown", "Checking"], ["cant", "Can't check"],
        ["unmonitored", "Not monitored"]].map(([value, label]) => h("option", {value, selected: value === filter}, label)));
      return [...notices(data.freshness),
        head("Devices", `${rows.length} of ${data.devices.length}`, choose, csvLink("devices")),
        table("devices", deviceColumns, rows, {rowClass: (r) => r.status === "down" ? "row-down" : ""})];
    },

    events(data) {
      return [...notices(data.freshness),
        head("Events", "The last day: devices up and down, new devices and hosts, links gone quiet, failed backups, "
             + "and when the Map Watcher wasn't monitoring",
          csvLink("events")),
        table("events", [
          {key: "at", label: "When", render: (r) => fmtTime(r.at), value: (r) => -(r.at || 0)},
          {key: "kind", label: "Kind", render: (r) => h("span", {class: `pill ${r.kind}`}, r.kind)},
          {key: "map", label: "Map"},
          {key: "text", label: "What happened"},
        ], data.events, {empty: "Nothing has happened in the last day."}),
        h("div", {class: "page-head"}, h("h2", {}, "Syslog in the last day (counts only)"), csvLink("syslog")),
        data.syslog_available ? table("syslog", [
          {key: "source", label: "Sender", render: (r) => h("span", {class: "mono"}, r.source)},
          {key: "name", label: "Device"},
          {key: "emergency", label: "Emerg", number: true}, {key: "alert", label: "Alert", number: true},
          {key: "critical", label: "Crit", number: true}, {key: "error", label: "Error", number: true},
          {key: "warning", label: "Warn", number: true}, {key: "notice", label: "Notice", number: true},
          {key: "info", label: "Info", number: true}, {key: "debug", label: "Debug", number: true},
          {key: "total", label: "Total", number: true},
        ], data.syslog, {empty: "No syslog in the last day."}) :
          empty("The Syslog Collector isn't answering on the dashboard's computer.")];
    },

    traffic(data) {
      const flows = data.flows;
      const top = (id, title, rows, label) => panel(title, rows.length ? table(id, [
        {key: "0", label, render: (r) => h("span", {class: "mono"}, r[0]), value: (r) => r[0]},
        {key: "1", label: "Bytes", number: true, render: (r) => fmtBytes(r[1]), value: (r) => r[1]},
        {key: "3", label: "Flows", number: true, value: (r) => r[3], render: (r) => r[3]},
      ], rows) : empty("None."));
      return [...notices(data.freshness),
        head("Traffic", "Links and graphed ports, as the Map Watcher last read them", csvLink("traffic")),
        table("links", [
          {key: "name", label: "Device"}, {key: "port", label: "Port"}, {key: "to", label: "Linked to"},
          {key: "map", label: "Map"},
          {key: "in_bps", label: "In", number: true, render: (r) => fmtBits(r.in_bps)},
          {key: "out_bps", label: "Out", number: true, render: (r) => fmtBits(r.out_bps)},
          {key: "speed", label: "Speed", number: true, render: (r) => r.speed ? fmtBits(r.speed * 1e6) : ""},
          {key: "percent", label: "Use", number: true, render: (r) => bar(r.percent)},
          {key: "peak_percent", label: "Peak today", number: true, render: (r) => fmtPercent(r.peak_percent)},
          {key: "at", label: "Read", render: (r) => fmtTime(r.at)},
        ], data.links, {empty: "No traffic read yet: the Map Watcher reads the ports at the ends of links every few minutes."}),
        h("h2", {class: "section"}, `NetFlow, last ${Math.round((flows.span || 3600) / 60)} min`),
        flows.available ? h("div", {class: "grid two"},
          top("f-src", "Top sources", flows.sources, "Source"), top("f-dst", "Top destinations", flows.destinations, "Destination"),
          top("f-app", "Top applications", flows.applications, "Application"),
          top("f-conv", "Top conversations", flows.conversations, "Conversation")) :
          empty("The Flow Collector isn't answering on the dashboard's computer.")];
    },

    vpns(data) {
      return [...notices(data.freshness), head("VPNs and probes", "", csvLink("vpns")),
        table("tunnels", [
          {key: "state", label: "State", render: (r) => status(r.state, r.state_text)},
          {key: "a", label: "End A", render: (r) => `${r.a} ${r.a_port}`},
          {key: "b", label: "End B", render: (r) => `${r.b} ${r.b_port}`},
          {key: "kind", label: "Kind"}, {key: "ipsec", label: "IPsec", render: (r) => r.ipsec ? "Yes" : "No"},
          {key: "map", label: "Map"},
        ], data.tunnels, {empty: "No tunnels on the tribe maps."}),
        h("h2", {class: "section"}, "Devices checked from routers (IP SLA)"),
        table("probes", [
          {key: "status", label: "Status", render: (r) => status(r.status, r.status_text)},
          {key: "name", label: "Device"}, {key: "address", label: "Address"},
          {key: "via", label: "Checked from"},
          {key: "rtt", label: "Response", number: true, render: (r) => r.rtt === null ? "" : `${r.rtt} ms`},
          {key: "problem", label: "Problem"}, {key: "map", label: "Map"},
        ], data.probes, {empty: "No device is checked from a router."})];
    },

    ipam(data) {
      return [...notices(data.freshness), head("IPAM", "How full each subnet is", csvLink("ipam")),
        table("ipam", [
          {key: "network", label: "Network"},
          {key: "subnet", label: "Subnet", render: (r) => h("span", {class: "mono"}, r.subnet)},
          {key: "name", label: "Name"},
          {key: "used", label: "Used", number: true}, {key: "size", label: "Size", number: true},
          {key: "percent", label: "Full", number: true, render: (r) => bar(r.percent)},
          {key: "swept", label: "Last swept", render: (r) => r.swept ? fmtTime(r.swept) : "", value: (r) => r.swept || 0},
        ], data.subnets, {empty: "No IPAM subnets in the tribe yet."})];
    },

    hosts(data) {
      const windowButtons = data.windows.map((code) => h("button", {class: `plain ${data.window === code ? "active" : ""}`,
        onclick: () => { location.hash = `#hosts?window=${code}`; }}, `Last ${code}`));
      return [...notices(data.freshness),
        head("Hosts per subnet", `${hostCount(data.total, data.mac_only_total)} seen in the last ${data.window}: on the `
             + "maps' switch tables, in sweeps or in NetFlow, network devices left out",
          ...windowButtons, csvLink("hosts", {window: data.window})),
        table("hosts", [
          {key: "network_name", label: "Network"},
          {key: "subnet", label: "Subnet", render: (r) => h("a", {class: "mono",
            href: `#trends?${new URLSearchParams({subnet: r.subnet, network: r.network})}`}, r.subnet)},
          {key: "name", label: "Name"},
          {key: "total", label: "Hosts", number: true},
          {key: "map", label: "On the map", number: true}, {key: "sweep", label: "Sweeps", number: true},
          {key: "flow", label: "NetFlow", number: true},
          {key: "percent", label: "Of the subnet", number: true, render: (r) => bar(r.percent)},
        ], data.subnets, {empty: "No hosts seen in this time."}),
        data.mac_only.length ? h("div", {}, h("h2", {class: "section"}, "Hosts on the maps with no address, by VLAN"),
          table("mac-only", [{key: "map", label: "Map"}, {key: "vlan", label: "VLAN", number: true},
            {key: "count", label: "Hosts", number: true}], data.mac_only)) : null];
    },

    trends(data) {
      const span = state.params.span || "24h";
      const spanButtons = data.spans.map((code) => h("button", {class: `plain ${span === code ? "active" : ""}`,
        onclick: () => setParam("span", code)}, code));
      const portKey = state.params.port || "";
      const portSelect = h("select", {"aria-label": "Port", onchange: () => setParam("port", portSelect.value)},
        h("option", {value: ""}, "Choose a port..."),
        data.ports.map((item) => {
          const value = `${item.map_id}|${item.device}|${item.port}`;
          return h("option", {value, selected: value === portKey}, `${item.name} ${item.port}${item.to ? " to " + item.to : ""} (${item.map})`);
        }));
      const subnet = state.params.subnet || "";
      const network = state.params.network || (data.subnets.find((item) => item.subnet === subnet) || {}).network || "";
      const subnetSelect = h("select", {"aria-label": "Subnet", onchange: () => {
        const [chosenNetwork, chosen] = subnetSelect.value ? JSON.parse(subnetSelect.value) : ["", ""];
        const params = {...state.params, subnet: chosen, network: chosenNetwork};
        for (const name of ["subnet", "network"]) if (!params[name]) delete params[name];
        location.hash = `#trends?${new URLSearchParams(params)}`;
      }},
        h("option", {value: ""}, "Choose a subnet..."),
        data.subnets.map((item) => h("option", {value: JSON.stringify([item.network, item.subnet]),
          selected: item.subnet === subnet && item.network === network},
          `${item.subnet}${item.name ? " " + item.name : ""} (${item.network_name})`)));
      const portBox = h("div", {}), subnetBox = h("div", {});
      if (portKey) {
        const [map, device, port] = portKey.split("|");
        api(`/api/series/port?${new URLSearchParams({map, device, port, span})}`).then((series) => {
          portBox.replaceChildren(chart(series.points, {series: [1, 2, 3], classes: ["series-a", "series-b", "series-peak"],
            format: fmtBits}), h("div", {class: "chart-legend"}, h("span", {class: "a"}, "In"), h("span", {class: "b"}, "Out"),
            h("span", {class: "p"}, "Peak in (hourly)")));
        }).catch((error) => portBox.replaceChildren(empty(error.message)));
      } else portBox.appendChild(empty("Choose a port to see its traffic."));
      if (subnet) {
        api(`/api/series/subnet?${new URLSearchParams({subnet, network, span})}`).then((series) => {
          subnetBox.replaceChildren(chart(series.points, {series: [1, 2], classes: ["series-a", "series-peak"],
            format: (v) => String(Math.round(v))}), h("div", {class: "chart-legend"}, h("span", {class: "a"},
            "Hosts seen in the hour"), h("span", {class: "p"}, "Peak")));
        }).catch((error) => subnetBox.replaceChildren(empty(error.message)));
      } else subnetBox.appendChild(empty("Choose a subnet to see how many hosts it has had."));
      return [...notices(data.freshness), head("Trends", "", ...spanButtons),
        h("div", {class: "grid two"},
          panel("Port traffic", h("div", {class: "page-head"}, portSelect), portBox),
          panel("Hosts in a subnet", h("div", {class: "page-head"}, subnetSelect), subnetBox)),
        h("div", {class: "page-head"}, h("h2", {}, "Uptime (from the Map Watcher's checks)"), csvLink("uptime")),
        table("uptime", [
          {key: "name", label: "Device"}, {key: "map", label: "Map"},
          {key: "status", label: "Now", render: (r) => status(r.status, r.status)},
          {key: "uptime_24h", label: "24 h", number: true, render: (r) => fmtPercent(r.uptime_24h)},
          {key: "uptime_7d", label: "7 days", number: true, render: (r) => fmtPercent(r.uptime_7d)},
          {key: "uptime_30d", label: "30 days", number: true, render: (r) => fmtPercent(r.uptime_30d)},
        ], data.uptime, {empty: "No device has been checked yet."})];
    },
  };

  function showDetails(box, node) {
    if (!node) {
      state.selected = null;
      box.replaceChildren(h("h2", {}, "Details"), h("p", {class: "muted"}, "Click a device to see its details."));
      return;
    }
    state.selected = node.key;
    if (node.node === "hop" || node.node === "star") {  // Traceroute hops: just what the map says of them
      box.replaceChildren(h("h2", {}, node.label), node.detail ? h("p", {class: "muted"}, node.detail) : null);
      return;
    }
    // What NOMAD's details pane shows (netmap/details.py), asked for when picked and again each time the page is
    // drawn; the last answer shows meanwhile so it doesn't flicker
    const mapId = state.params.id;
    const cacheKey = `${mapId}:${node.key}`;
    if (state.detailsCache && state.detailsCache.key === cacheKey) drawDetails(box, node, state.detailsCache.data);
    else box.replaceChildren(h("h2", {}, node.label), h("p", {class: "muted"}, "Loading..."));
    api(`/api/details?${new URLSearchParams({map: mapId, key: node.key})}`).then((data) => {
      state.detailsCache = {key: cacheKey, data};
      if (state.selected === node.key && box.isConnected) drawDetails(box, node, data);
    }).catch((error) => {
      if (state.selected === node.key && box.isConnected) {
        box.replaceChildren(h("h2", {}, node.label), h("p", {class: "muted"}, `Couldn't get its details: ${error.message}`));
      }
    });
  }

  // A device's details as sections of paragraphs, bold lines and two-column tables, as the app draws them
  function drawDetails(box, node, data, mapId = state.params.id) {
    const parts = [h("h2", {}, data.title)];
    for (const section of data.sections) {
      if (section.title) parts.push(h("h3", {}, section.title));
      for (const block of section.blocks) {
        if (block.p !== undefined) parts.push(h("p", {class: "detail-text"}, block.p));
        else if (block.label !== undefined) parts.push(h("p", {class: "detail-label"}, block.label));
        else {
          // A port the Map Watcher reads: a link to its graph on the Trends page, as NOMAD's Graph opens its own
          const graphs = block.graph || [];
          parts.push(h("table", {class: `detail-rows ${block.bold ? "labels" : ""}`},
            block.rows.map(([left, right], index) => h("tr", {},
              h("td", {}, left),
              h("td", {}, block.bold && left === "Status" && node.status ? status(node.status, right) : right,
                graphs[index] ? [" ", h("a", {href: `#trends?${new URLSearchParams({port: `${mapId}|${node.key}|${graphs[index]}`})}`},
                  "Graph")] : null)))));
        }
      }
    }
    box.replaceChildren(...parts);
  }

  // ----------------------------------------------------------------- Map: details and full screen

  function setDetailsHidden(hidden) {
    state.detailsHidden = hidden;
    writePref("map-details-hidden", hidden ? "1" : "0");
    if (state.page === "map" && state.data) render(state.data);
  }

  // Full screen: the map covers the page (body.map-full), and the browser goes full screen too when it lets us.
  // Esc, or leaving the browser's full screen, comes back.
  function setMapFull(full, redraw = true) {
    state.mapFull = full;
    document.body.classList.toggle("map-full", full);
    if (full && document.documentElement.requestFullscreen && !document.fullscreenElement) {
      document.documentElement.requestFullscreen().then(() => { state.browserFull = true; }).catch(() => {});
    } else if (!full && state.browserFull) {
      state.browserFull = false;
      if (document.fullscreenElement && document.exitFullscreen) document.exitFullscreen().catch(() => {});
    }
    if (redraw && state.page === "map" && state.data) render(state.data);
  }

  document.addEventListener("fullscreenchange", () => {
    if (!document.fullscreenElement && state.browserFull) {
      state.browserFull = false;
      if (state.mapFull) setMapFull(false);
    }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && state.mapFull && !document.fullscreenElement) setMapFull(false);
  });

  // ----------------------------------------------------------------- Routing and refreshing

  function parseHash() {
    const [page, query] = (location.hash.replace(/^#/, "") || "overview").split("?");
    return {page: page || "overview", params: Object.fromEntries(new URLSearchParams(query || ""))};
  }

  function setParam(name, value) {
    const params = {...state.params, [name]: value};
    if (!value) delete params[name];
    const query = new URLSearchParams(params).toString();
    location.hash = `#${state.page}${query ? "?" + query : ""}`;
  }

  function render(data) {
    state.data = data;
    const builder = pages[state.page];
    if (!builder) return;
    if (state.mapFull && state.page !== "map") setMapFull(false, false);
    const scroll = window.scrollY;
    const active = document.activeElement;
    const focused = active && active.classList.contains("filter") ? active.id : "";
    if (state.map && state.mapKeepKey) state.mapKeep[state.mapKeepKey] = state.map.state();
    closePicker();
    main.replaceChildren(...builder(data));
    window.scrollTo(0, scroll);
    if (focused) {
      const input = document.getElementById(focused);
      if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
    }
    showSources(data.freshness);
    document.getElementById("print-footer").textContent =
      `NOMAD Dashboard – ${document.title} – printed ${new Date().toLocaleString()}`;
  }

  function showSources(freshness) {
    const box = document.getElementById("sources");
    if (!freshness) return;
    box.replaceChildren(...["watcher", "tribe", "syslog", "flows"].map((name) => {
      const item = freshness[name];
      return h("span", {class: `source-dot ${item && item.ok ? "ok" : "bad"}`, title: item ? item.text : name});
    }));
    document.getElementById("updated").textContent = `Updated ${fmtTime(freshness.now)}`;
  }

  async function load() {
    const {page, params} = state;
    const query = new URLSearchParams(params);
    if (page === "trends") { query.delete("port"); query.delete("subnet"); query.delete("span"); }
    try {
      state.loading = true;
      const data = await api(`/api/page/${page}${query.toString() ? "?" + query : ""}`);
      if (page !== state.page) return;
      render(data);
    } catch (error) {
      if (error.message !== "Signed out") main.replaceChildren(h("div", {class: "notice"}, `Couldn't load this page: ${error.message}`));
    } finally {
      state.loading = false;
    }
  }

  function route() {
    const {page, params} = parseHash();
    if (page === "kiosk") { startKiosk(params); return; }
    const changed = page !== state.page;
    state.page = pages[page] ? page : "overview";
    state.params = params;
    if (changed) { state.selected = null; main.replaceChildren(h("p", {class: "muted"}, "Loading...")); }
    for (const link of document.querySelectorAll("#nav a")) {
      link.classList.toggle("current", link.dataset.page === state.page);
    }
    document.title = `NOMAD Dashboard – ${state.page[0].toUpperCase()}${state.page.slice(1)}`;
    load();
  }

  function refreshSoon() {
    clearTimeout(state.refreshTimer);
    state.refreshTimer = setTimeout(() => {
      if (state.picker) refreshSoon();  // Not while a column's filter list is open: its counts would go stale
      else if (!state.loading && !document.hidden) load();
    }, 1200);
  }

  function listen() {
    let source = null;
    const open = () => {
      source = new EventSource("/api/stream");
      source.addEventListener("revision", refreshSoon);
      source.onerror = () => {
        // Signed out, or the service restarted: the browser retries by itself; check we're still signed in
        api("/api/me").catch(() => {});
      };
    };
    open();
    document.addEventListener("visibilitychange", () => { if (!document.hidden) refreshSoon(); });
  }

  // ----------------------------------------------------------------- Kiosk mode: #kiosk?pages=overview,sites,map&every=30

  function startKiosk(params) {
    document.body.classList.add("kiosk");
    const list = (params.pages || "overview,sites,devices").split(",").filter((name) => pages[name]);
    // every=0 (or off, or a single page) stays on the first page: it still updates itself, without being drawn
    // afresh on a timer, so a device clicked on the map stays selected
    const still = list.length < 2 || ["0", "off", "no"].includes(String(params.every || "").toLowerCase());
    const every = Math.max(10, Number(params.every) || 30) * 1000;
    let index = 0;
    const show = () => {
      if (state.picker) return;  // Someone is choosing a column's filter: stay on this page until they're done
      state.page = list[index % list.length];
      state.params = state.page === "map" && params.map ? {id: params.map} : {};
      state.selected = null;
      load();
      index++;
    };
    clearInterval(state.kiosk);
    state.kiosk = still ? null : setInterval(show, every);
    show();
  }

  // ----------------------------------------------------------------- Start

  document.getElementById("print").addEventListener("click", () => window.print());
  document.getElementById("sign-out").addEventListener("click", async () => {
    await fetch("/api/logout", {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "X-NOMAD-Dashboard": "1"}, body: "{}"}).catch(() => {});
    location.replace("/login");
  });
  api("/api/me").then((me) => {
    document.getElementById("who").textContent = me.user;
    if (me.kiosk && !location.hash.startsWith("#kiosk")) document.getElementById("sign-out").hidden = true;
  }).catch(() => {});
  window.addEventListener("hashchange", route);
  route();
  listen();
})();
