// topology.js - the bus-spine floor diagram (P1, P2, P3, P4, D2, D6).
//
// Renders devices as HTML cards grouped into floor swimlanes (UG, EG, DG,
// Außenbereich) and rooms, with the 14-device Technik room drawn as a bordered
// distribution cabinet. A single SVG underlay per scroll container carries the
// vertical bus spine, a drop-line per card and selection edges; it is laid out
// in content coordinates from offsetLeft/offsetTop after the cards mount and on
// resize. The animation scheduler flashes cards/tree rows and (when the browser
// supports offset-path) sends a traveling pulse along the spine from sender to
// listeners for each telegram.

const FLOOR_ORDER = ["UG", "EG", "DG", "Außenbereich"];
const CABINET_ROOMS = new Set(["Technik"]);
const UNKNOWN_FLOOR = "Ohne Zuordnung"; // trailing section for unplaced devices
const MAX_PULSES = 6; // concurrent traveling pulses
const MAX_EDGE_LISTENERS = 12; // bound selection edges to avoid a hairball
const MAX_PARTNER_EDGES = 24; // bound device-partner edges to avoid a hairball
const PULSE_MS = 520; // pulse travel duration
const RECENT_TINT_MS = 3500; // recent-activity tint lifetime after a flash
const SVG_NS = "http://www.w3.org/2000/svg";

/**
 * Split a KNX individual address (a.b.c) into a comparable number.
 * @param {string} addr
 * @returns {number}
 */
function iaKey(addr) {
  const p = String(addr).split(".").map((n) => parseInt(n, 10) || 0);
  return (p[0] || 0) * 0x10000 + (p[1] || 0) * 0x100 + (p[2] || 0);
}

/**
 * Instantiate a <template> by id and return its first element child.
 * @param {string} id
 * @returns {HTMLElement}
 */
function cloneTpl(id) {
  const tpl = document.getElementById(id);
  return tpl.content.firstElementChild.cloneNode(true);
}

/**
 * The topology controller. Owns the card DOM + SVG underlay and syncs both
 * with the store (selection, search dimming) and the live telegram stream.
 */
class Topology {
  /**
   * @param {import('./store.js').Store} store
   * @param {{tree?:Object, container?:HTMLElement}} ctx
   */
  constructor(store, ctx) {
    this.store = store;
    this.tree = ctx.tree || null;
    this.root = ctx.container || document.getElementById("topology");

    /** @type {Map<string, HTMLElement>} device address -> card element */
    this.cardByDevice = new Map();
    /** @type {Map<string, HTMLElement>} device address -> floor-body it lives in */
    this.floorBodyByDevice = new Map();
    /** @type {Map<string, {label:HTMLElement, body:HTMLElement, floor:string}>} */
    this.floorSections = new Map();
    /** @type {Map<string, {x:number, y:number}>} device -> spine drop point */
    this.dropPoints = new Map();
    /** @type {{x:number, y:number}} spine head (unknown source IAs) */
    this.headPoint = { x: 0, y: 0 };
    /** @type {number} content-space x of the vertical spine */
    this.spineX = 0;
    /**
     * The live view state (mirrors store.view). Topology renders from this
     * declaratively rather than layering ad-hoc selection classes.
     * @type {import('./store.js').ViewState}
     */
    this.viewState = store.view || { mode: "all", kind: null, id: null, partners: [], focusDevices: [] };
    /** @type {{x:number, y:number}|null} GA-node anchor in ga-focus mode */
    this.gaNodePoint = null;

    // SVG underlay layers.
    this.svg = null;
    this.spineLayer = null; // spine + drop lines (static)
    this.edgeLayer = null; // selection edges (rebuilt on selection)
    this.pulseLayer = null; // traveling pulses

    /** @type {Set<Element>} live pulses (bounded by MAX_PULSES) */
    this.activePulses = new Set();
    /** @type {Map<string, Object>} coalesced telegrams for the next frame */
    this.pending = new Map();
    /** @type {number|null} rAF handle */
    this.rafId = null;

    this.supportsOffsetPath =
      typeof CSS !== "undefined" &&
      typeof CSS.supports === "function" &&
      CSS.supports("offset-path", 'path("M0 0")');
    this.reducedMotion =
      typeof matchMedia === "function" &&
      matchMedia("(prefers-reduced-motion: reduce)").matches;

    this._build();
    this._installSvg();
    this._buildBanner();
    this._observeResize();

    // The topology renders from the derived view state, not raw selection.
    store.on("view", (v) => this._applyView(v));
    // Search dimming: main.js sets store.filterText and toggles body.query-active.
    store.on("filter", (q) => this._applyDimming(q));
    // Live-effects toggle: when off, suppress all card/tree/GA flashes and
    // spine pulses. Log is never affected (that wiring is in log.js).
    store.on("flash-enabled", () => {});

    // Lay out once the cards have real geometry.
    requestAnimationFrame(() => this.relayout());
    // A second pass after fonts/scrollbars settle.
    if (typeof window !== "undefined") {
      window.addEventListener("load", () => this.relayout(), { once: true });
    }
  }

  // --- DOM construction ----------------------------------------------------

  _build() {
    this.root.textContent = "";

    const cardHost = document.createElement("div");
    cardHost.className = "topo-cards";
    this.root.appendChild(cardHost);
    this.cardHost = cardHost;

    // Bucket devices by floor then room, preserving unknown floors/rooms.
    const devices = this.store.devicesSorted();
    /** @type {Map<string, Map<string, Array<Object>>>} */
    const byFloor = new Map();
    for (const d of devices) {
      const floor = d.floor || UNKNOWN_FLOOR;
      const room = d.room || "—";
      if (!byFloor.has(floor)) byFloor.set(floor, new Map());
      const rooms = byFloor.get(floor);
      if (!rooms.has(room)) rooms.set(room, []);
      rooms.get(room).push(d);
    }

    // Ordered floor list: known order first, then any extras (incl. unknown).
    const floorNames = [
      ...FLOOR_ORDER.filter((f) => byFloor.has(f)),
      ...[...byFloor.keys()].filter((f) => !FLOOR_ORDER.includes(f)),
    ];

    for (const floor of floorNames) {
      const lane = document.createElement("section");
      lane.className = "floor-swimlane";
      lane.dataset.floor = floor;

      const label = document.createElement("button");
      label.type = "button";
      label.className = "floor-label";
      label.textContent = floor;
      label.setAttribute("aria-expanded", "true");
      const body = document.createElement("div");
      body.className = "floor-body";
      // Section collapse toggles body visibility then relayouts the spine.
      // The user-collapsed state is tracked so focus mode does not fight it.
      label.addEventListener("click", () => {
        if (label.classList.contains("focus-hidden")) return; // inert in focus mode
        const collapsed = body.hidden;
        body.hidden = !collapsed;
        label.setAttribute("aria-expanded", String(collapsed));
        label.classList.toggle("collapsed", !collapsed);
        lane.dataset.userCollapsed = collapsed ? "0" : "1";
        this.relayout();
      });

      lane.append(label, body);
      cardHost.appendChild(lane);
      this.floorSections.set(floor, { label, body, floor, lane });

      const rooms = byFloor.get(floor);
      // Cabinet rooms first (they anchor the floor visually), then the rest.
      const roomNames = [...rooms.keys()].sort((a, b) => {
        const ca = CABINET_ROOMS.has(a) ? 0 : 1;
        const cb = CABINET_ROOMS.has(b) ? 0 : 1;
        return ca - cb || a.localeCompare(b);
      });
      for (const room of roomNames) {
        this._buildRoom(body, floor, room, rooms.get(room));
      }
    }
  }

  _buildRoom(parent, floor, room, devices) {
    devices.sort((a, b) => iaKey(a.address) - iaKey(b.address));
    const isCabinet = CABINET_ROOMS.has(room);

    const block = document.createElement("div");
    block.className = isCabinet ? "room-block cabinet-cluster" : "room-block";
    block.dataset.room = room;

    const title = document.createElement("div");
    title.className = isCabinet ? "cabinet-title" : "room-title";
    title.textContent = room === "—" ? "(kein Raum)" : room;
    if (isCabinet) title.textContent = `${room} · ${devices.length} Geräte`;
    block.appendChild(title);

    const grid = document.createElement("div");
    grid.className = "floor-cards";
    block.appendChild(grid);

    for (const d of devices) {
      grid.appendChild(this._buildCard(d));
      this.floorBodyByDevice.set(d.address, parent);
      // Remember the room block so focus mode can hide empty rooms.
      const card = this.cardByDevice.get(d.address);
      if (card) card.dataset.roomBlock = "1";
      this._roomBlockByDevice = this._roomBlockByDevice || new Map();
      this._roomBlockByDevice.set(d.address, block);
    }
    parent.appendChild(block);
  }

  _buildCard(d) {
    const card = cloneTpl("tpl-device-card");
    card.dataset.device = d.address;
    card.querySelector("[data-field=addr]").textContent = d.address;
    card.querySelector("[data-field=name]").textContent = d.name || d.address;
    const type = d.product
      ? [d.product.manufacturer, d.product.order_number].filter(Boolean).join(" ")
      : "";
    card.querySelector("[data-field=type]").textContent = type;
    card.querySelector("[data-field=room]").textContent = d.room || "";

    // No device orphan badge: an actuator with hundreds of objects and only a
    // few linked (or none) is normal in KNX, so an all-unlinked device is not a
    // warning. The badge element stays hidden.

    card.addEventListener("click", () => this.store.select("device", d.address));
    this.cardByDevice.set(d.address, card);
    return card;
  }

  // --- SVG underlay --------------------------------------------------------

  _installSvg() {
    const svg = document.createElementNS(SVG_NS, "svg");
    svg.classList.add("topo-underlay");
    svg.setAttribute("aria-hidden", "true");
    // Arrowhead marker for focus-mode direction edges.
    const defs = document.createElementNS(SVG_NS, "defs");
    const marker = document.createElementNS(SVG_NS, "marker");
    marker.setAttribute("id", "topo-arrow");
    marker.setAttribute("viewBox", "0 0 10 10");
    marker.setAttribute("refX", "8");
    marker.setAttribute("refY", "5");
    marker.setAttribute("markerWidth", "6");
    marker.setAttribute("markerHeight", "6");
    marker.setAttribute("orient", "auto-start-reverse");
    const arrowPath = document.createElementNS(SVG_NS, "path");
    arrowPath.setAttribute("d", "M 0 0 L 10 5 L 0 10 z");
    arrowPath.setAttribute("class", "topo-arrow-head");
    marker.appendChild(arrowPath);
    defs.appendChild(marker);
    svg.appendChild(defs);
    // Three stacked groups so we can rebuild edges/pulses without touching the spine.
    this.spineLayer = document.createElementNS(SVG_NS, "g");
    this.spineLayer.setAttribute("class", "spine-layer");
    this.edgeLayer = document.createElementNS(SVG_NS, "g");
    this.edgeLayer.setAttribute("class", "edge-layer");
    this.pulseLayer = document.createElementNS(SVG_NS, "g");
    this.pulseLayer.setAttribute("class", "pulse-layer");
    svg.append(this.spineLayer, this.edgeLayer, this.pulseLayer);
    // Underlay sits behind the cards inside the same scroll container.
    this.root.insertBefore(svg, this.cardHost);
    this.svg = svg;
  }

  _observeResize() {
    if (typeof ResizeObserver === "undefined") return;
    let scheduled = false;
    const ro = new ResizeObserver(() => {
      if (scheduled) return;
      scheduled = true;
      requestAnimationFrame(() => {
        scheduled = false;
        this.relayout();
      });
    });
    ro.observe(this.root);
    ro.observe(this.cardHost);
    this._resizeObserver = ro;
  }

  /**
   * Recompute the spine geometry from live card offsets and repaint the static
   * underlay (spine + drop lines). Selection edges are rebuilt too so they
   * follow the cards. Cheap enough to call on every resize/collapse.
   *
   * The geometry map is derived from whatever cards are currently visible, so
   * entering/leaving focus mode (which hides non-participants) just needs a
   * relayout to reflow the spine and drop lines correctly.
   */
  relayout() {
    if (!this.svg) return;
    const w = this.root.scrollWidth;
    const h = this.root.scrollHeight;
    this.svg.setAttribute("width", String(w));
    this.svg.setAttribute("height", String(h));
    this.svg.setAttribute("viewBox", `0 0 ${w} ${h}`);

    // Spine runs down a narrow left gutter of the content area.
    this.spineX = 10;
    const topPad = 6;
    const bottomPad = 6;
    this.headPoint = { x: this.spineX, y: topPad + 4 };

    // Drop point per visible card: vertical mid of the card, at the spine x.
    this.dropPoints.clear();
    const hostLeft = this.cardHost.offsetLeft;
    const hostTop = this.cardHost.offsetTop;
    for (const [addr, card] of this.cardByDevice) {
      if (card.offsetParent === null) continue; // hidden (collapsed section)
      const cx = this._cardCenter(card, hostLeft, hostTop);
      this.dropPoints.set(addr, cx);
    }

    // Repaint spine + drop lines.
    this.spineLayer.textContent = "";
    const spine = document.createElementNS(SVG_NS, "line");
    spine.setAttribute("class", "bus-spine");
    spine.setAttribute("x1", String(this.spineX));
    spine.setAttribute("y1", String(topPad));
    spine.setAttribute("x2", String(this.spineX));
    spine.setAttribute("y2", String(Math.max(topPad, h - bottomPad)));
    this.spineLayer.appendChild(spine);

    // Line-head node (unknown source IAs: gateway, bussard itself).
    const head = document.createElementNS(SVG_NS, "circle");
    head.setAttribute("class", "spine-head");
    head.setAttribute("cx", String(this.headPoint.x));
    head.setAttribute("cy", String(this.headPoint.y));
    head.setAttribute("r", "5");
    this.spineLayer.appendChild(head);

    for (const [, pt] of this.dropPoints) {
      const drop = document.createElementNS(SVG_NS, "line");
      drop.setAttribute("class", "drop-line");
      drop.setAttribute("x1", String(this.spineX));
      drop.setAttribute("y1", String(pt.y));
      drop.setAttribute("x2", String(pt.x));
      drop.setAttribute("y2", String(pt.y));
      this.spineLayer.appendChild(drop);
    }

    // In ga-focus mode, draw the GA node prominently on the spine, vertically
    // centered on the participating cards, then rebuild edges through it.
    this.gaNodePoint = null;
    if (this.viewState && this.viewState.mode === "ga-focus") {
      this._drawGaNode();
    }

    // Rebuild edges for the current view (their anchors moved).
    this._renderEdges();
  }

  /**
   * Draw the focused GA as a labeled node on the spine. Placed at the vertical
   * midpoint of the participating cards (or the pane middle if none are laid
   * out), offset just right of the spine so its label is readable.
   */
  _drawGaNode() {
    const v = this.viewState;
    const g = this.store.groupByAddr.get(v.id);
    const pts = v.focusDevices
      .map((a) => this.dropPoints.get(a))
      .filter(Boolean);
    let y;
    if (pts.length) {
      y = pts.reduce((s, p) => s + p.y, 0) / pts.length;
    } else {
      y = this.root.scrollHeight / 2;
    }
    const x = this.spineX;
    this.gaNodePoint = { x, y };

    const grp = document.createElementNS(SVG_NS, "g");
    grp.setAttribute("class", "ga-node");
    const dot = document.createElementNS(SVG_NS, "circle");
    dot.setAttribute("cx", String(x));
    dot.setAttribute("cy", String(y));
    dot.setAttribute("r", "7");
    dot.setAttribute("class", "ga-node-dot");
    grp.appendChild(dot);

    // Label box: address + name + DPT, anchored just right of the spine.
    const labelX = x + 16;
    const addr = v.id;
    const name = (g && g.name) || "(unnamed)";
    const dpt = g && g.dpt ? g.dpt : "";
    const text = document.createElementNS(SVG_NS, "text");
    text.setAttribute("x", String(labelX));
    text.setAttribute("y", String(y));
    text.setAttribute("class", "ga-node-label");
    text.setAttribute("dominant-baseline", "middle");
    const t1 = document.createElementNS(SVG_NS, "tspan");
    t1.setAttribute("class", "ga-node-addr");
    t1.textContent = addr;
    text.appendChild(t1);
    const t2 = document.createElementNS(SVG_NS, "tspan");
    t2.setAttribute("class", "ga-node-name");
    t2.setAttribute("dx", "8");
    t2.textContent = name;
    text.appendChild(t2);
    if (dpt) {
      const t3 = document.createElementNS(SVG_NS, "tspan");
      t3.setAttribute("class", "ga-node-dpt");
      t3.setAttribute("dx", "8");
      t3.textContent = dpt;
      text.appendChild(t3);
    }
    grp.appendChild(text);
    this.spineLayer.appendChild(grp);
  }

  /**
   * Content-space anchor point on a card's left edge (where a drop line meets).
   * @param {HTMLElement} card
   * @param {number} hostLeft
   * @param {number} hostTop
   * @returns {{x:number, y:number, left:number, right:number}}
   */
  _cardCenter(card, hostLeft, hostTop) {
    // offsetLeft/Top are relative to offsetParent; walk up to the scroll root.
    let left = 0;
    let top = 0;
    let el = card;
    while (el && el !== this.root) {
      left += el.offsetLeft;
      top += el.offsetTop;
      el = el.offsetParent;
    }
    const y = top + card.offsetHeight / 2;
    return { x: left, y, left, right: left + card.offsetWidth };
  }

  // --- view-driven rendering (items 2,3,4,6) -------------------------------

  /**
   * Apply a derived {@link import('./store.js').ViewState}. This is the single
   * entry point the topology renders from: it sets the card classes (selected /
   * partner / dimmed), toggles focus mode (hiding non-participants), relayouts
   * when the geometry map changed, draws the edges, and scrolls the primary
   * target into view. Called on every `view` event.
   * @param {import('./store.js').ViewState} v
   */
  _applyView(v) {
    const prevMode = this.viewState ? this.viewState.mode : "all";
    this.viewState = v || { mode: "all", kind: null, id: null, partners: [], focusDevices: [] };

    // Focus mode hides non-participants, so the set of visible cards changes;
    // apply visibility first, then relayout so drop points match, then edges.
    const enteringOrLeavingFocus =
      this.viewState.mode === "ga-focus" || prevMode === "ga-focus";
    this._applyFocusVisibility();
    this._applyCardClasses();
    if (enteringOrLeavingFocus) {
      // Geometry map changed (cards hidden/shown): relayout rebuilds the spine,
      // drop points, GA node and edges in one pass.
      this.relayout();
    } else {
      this._renderEdges();
    }
    this._updateBanner();
    this._scrollPrimaryIntoView();
  }

  /**
   * Set per-card classes from the current view state. Clears all first, then
   * applies: selected (device or GA-focus GA), partner, dimmed (non-partner in
   * device-partners mode).
   */
  _applyCardClasses() {
    const v = this.viewState;
    for (const card of this.cardByDevice.values()) {
      card.classList.remove("selected", "partner", "partner-dimmed", "focus-part");
    }
    if (v.mode === "device-partners") {
      const self = this.cardByDevice.get(v.id);
      if (self) self.classList.add("selected");
      const partnerAddrs = new Set(v.partners.map((p) => p.device));
      for (const [addr, card] of this.cardByDevice) {
        if (addr === v.id) continue;
        if (partnerAddrs.has(addr)) card.classList.add("partner");
        else card.classList.add("partner-dimmed");
      }
    } else if (v.mode === "ga-focus") {
      for (const addr of v.focusDevices) {
        const card = this.cardByDevice.get(addr);
        if (card) card.classList.add("focus-part");
      }
    }
  }

  /**
   * In ga-focus mode, hide every card that does not participate in the focused
   * GA and collapse floor sections with no participants. In every other mode,
   * restore full visibility (respecting the user's own collapse choices).
   */
  _applyFocusVisibility() {
    const v = this.viewState;
    const focus = v.mode === "ga-focus";
    document.body.classList.toggle("topo-focus", focus);

    if (!focus) {
      // Restore: show all cards and room blocks; un-force floor sections.
      for (const card of this.cardByDevice.values()) card.classList.remove("focus-hidden");
      if (this._roomBlockByDevice) {
        for (const block of new Set(this._roomBlockByDevice.values())) {
          block.classList.remove("focus-hidden");
        }
      }
      for (const [, sec] of this.floorSections) {
        sec.label.classList.remove("focus-hidden");
        // Restore the user's collapse choice.
        const userCollapsed = sec.lane.dataset.userCollapsed === "1";
        sec.body.hidden = userCollapsed;
        sec.label.classList.toggle("collapsed", userCollapsed);
        sec.label.setAttribute("aria-expanded", String(!userCollapsed));
      }
      return;
    }

    const keep = new Set(v.focusDevices);
    // Cards: hide non-participants.
    for (const [addr, card] of this.cardByDevice) {
      card.classList.toggle("focus-hidden", !keep.has(addr));
    }
    // Room blocks: hide a block if none of its devices participate.
    if (this._roomBlockByDevice) {
      const blockDevices = new Map();
      for (const [addr, block] of this._roomBlockByDevice) {
        if (!blockDevices.has(block)) blockDevices.set(block, []);
        blockDevices.get(block).push(addr);
      }
      for (const [block, addrs] of blockDevices) {
        const any = addrs.some((a) => keep.has(a));
        block.classList.toggle("focus-hidden", !any);
      }
    }
    // Floor sections: expand (so participants are visible) and hide the whole
    // lane if it has no participant.
    for (const [, sec] of this.floorSections) {
      const body = sec.body;
      const anyVisible = [...this.cardByDevice].some(
        ([addr, card]) => keep.has(addr) && this.floorBodyByDevice.get(addr) === body,
      );
      sec.label.classList.toggle("focus-hidden", !anyVisible);
      // Force-expand participating lanes so their cards lay out.
      if (anyVisible) {
        body.hidden = false;
        sec.label.classList.remove("collapsed");
      } else {
        body.hidden = true;
      }
    }
  }

  /**
   * Rebuild the edge layer from the current view state. In device-partners mode:
   * one edge per partner from the selected card to the partner (via the spine),
   * titled with the shared GAs. In ga-focus mode: edges from each sender card to
   * the GA node and from the GA node to each listener card, with direction. In
   * `all` mode: nothing.
   */
  _renderEdges() {
    if (!this.edgeLayer) return;
    this.edgeLayer.textContent = "";
    const v = this.viewState;
    if (v.mode === "device-partners") this._renderPartnerEdges(v);
    else if (v.mode === "ga-focus") this._renderFocusEdges(v);
  }

  /**
   * Draw one edge per communication partner: selected card -> spine -> partner
   * card. Bounded to {@link MAX_PARTNER_EDGES}. Each edge carries a title with
   * the shared GAs so hovering reveals the relationship.
   * @param {import('./store.js').ViewState} v
   */
  _renderPartnerEdges(v) {
    const from = this.dropPoints.get(v.id);
    if (!from) return;
    let drawn = 0;
    for (const p of v.partners) {
      if (drawn >= MAX_PARTNER_EDGES) break;
      const to = this.dropPoints.get(p.device);
      if (!to) continue;
      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("class", "sel-edge partner-edge");
      path.setAttribute("d", this._edgePathBetween(from, to));
      const title = document.createElementNS(SVG_NS, "title");
      title.textContent = `shared: ${p.gas.join(", ")}`;
      path.appendChild(title);
      this.edgeLayer.appendChild(path);
      drawn += 1;
    }
  }

  /**
   * Draw focus-mode edges through the GA node: sender cards -> GA node (send
   * direction) and GA node -> listener cards (listen direction). Bounded.
   * @param {import('./store.js').ViewState} v
   */
  _renderFocusEdges(v) {
    const node = this.gaNodePoint;
    if (!node) return;
    const senders = this.store.gaSenders.get(v.id) || [];
    const listeners = this.store.gaListeners.get(v.id) || [];
    const seenS = new Set();
    let count = 0;
    for (const s of senders) {
      if (count >= MAX_EDGE_LISTENERS || seenS.has(s.device)) continue;
      seenS.add(s.device);
      const pt = this.dropPoints.get(s.device);
      if (!pt) continue;
      this._appendFocusEdge(pt, node, "sender");
      count += 1;
    }
    const seenL = new Set();
    count = 0;
    for (const l of listeners) {
      if (count >= MAX_EDGE_LISTENERS || seenL.has(l.device)) continue;
      seenL.add(l.device);
      const pt = this.dropPoints.get(l.device);
      if (!pt) continue;
      this._appendFocusEdge(node, pt, "listener");
      count += 1;
    }
  }

  _appendFocusEdge(from, to, kind) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("class", `sel-edge ${kind} focus-edge`);
    path.setAttribute("marker-end", "url(#topo-arrow)");
    path.setAttribute("d", this._edgePathBetween(from, to));
    this.edgeLayer.appendChild(path);
  }

  /**
   * Build a curved path from the spine to a card anchor.
   * @param {{x:number, y:number}} pt
   * @returns {string} SVG path data
   */
  _edgePath(pt) {
    const midX = (this.spineX + pt.x) / 2;
    return `M ${this.spineX} ${pt.y} C ${midX} ${pt.y}, ${midX} ${pt.y}, ${pt.x} ${pt.y}`;
  }

  /**
   * Build a path between two card anchors routed via the spine gutter:
   * from -> spine(from.y) -> spine(to.y) -> to. Keeps edges off the cards.
   * @param {{x:number, y:number}} from
   * @param {{x:number, y:number}} to
   * @returns {string} SVG path data
   */
  _edgePathBetween(from, to) {
    return (
      `M ${from.x} ${from.y} L ${this.spineX} ${from.y} ` +
      `L ${this.spineX} ${to.y} L ${to.x} ${to.y}`
    );
  }

  /**
   * Scroll the primary selected card into the topology pane's viewport if it is
   * outside, then flash it once so the eye lands. Applies to device selection
   * (the selected card) and GA focus (the first participating card).
   */
  _scrollPrimaryIntoView() {
    const v = this.viewState;
    let addr = null;
    if (v.mode === "device-partners") addr = v.id;
    else if (v.mode === "ga-focus") addr = v.focusDevices[0] || null;
    if (!addr) return;
    const card = this.cardByDevice.get(addr);
    if (!card || card.offsetParent === null) return;
    if (!this._isCardInView(card)) {
      card.scrollIntoView({ block: "center", behavior: "smooth" });
    }
    // Flash once so the target is easy to spot (independent of the flash toggle:
    // this is a selection cue, not live traffic).
    card.classList.remove("locate");
    void card.offsetWidth;
    card.classList.add("locate");
    const clear = () => {
      card.classList.remove("locate");
      card.removeEventListener("animationend", clear);
    };
    card.addEventListener("animationend", clear);
  }

  /**
   * Whether a card is (roughly) within the topology pane's scroll viewport.
   * @param {HTMLElement} card
   * @returns {boolean}
   */
  _isCardInView(card) {
    const pane = this.root;
    const cr = card.getBoundingClientRect();
    const pr = pane.getBoundingClientRect();
    return cr.bottom > pr.top && cr.top < pr.bottom;
  }

  // --- focus banner (item 4) -----------------------------------------------

  _buildBanner() {
    const banner = document.createElement("div");
    banner.className = "topo-filter-banner";
    banner.hidden = true;
    const label = document.createElement("span");
    label.className = "tfb-label";
    const close = document.createElement("button");
    close.type = "button";
    close.className = "tfb-close";
    close.textContent = "✕";
    close.title = "Clear filter (Esc)";
    close.setAttribute("aria-label", "Clear group-address filter");
    close.addEventListener("click", () => this.store.deselect());
    banner.append(label, close);
    // The banner is pinned to the top of the topology pane.
    this.root.appendChild(banner);
    this.banner = banner;
    this.bannerLabel = label;
  }

  _updateBanner() {
    if (!this.banner) return;
    const v = this.viewState;
    if (v.mode !== "ga-focus") {
      this.banner.hidden = true;
      return;
    }
    const g = this.store.groupByAddr.get(v.id);
    const name = (g && g.name) || "(unnamed)";
    const dpt = g && g.dpt ? ` · ${g.dpt}` : "";
    this.bannerLabel.textContent = `Filtered by ${v.id} ${name}${dpt}`;
    this.banner.hidden = false;
  }

  // --- search dimming (P4) -------------------------------------------------

  _applyDimming(query) {
    const q = String(query || "").trim().toLowerCase();
    if (!q) {
      for (const card of this.cardByDevice.values()) card.classList.remove("dimmed");
      return;
    }
    const terms = q.split(/\s+/).filter(Boolean);
    for (const [addr, card] of this.cardByDevice) {
      const d = this.store.deviceByAddr.get(addr);
      const hay = [
        addr,
        d && d.name,
        d && d.room,
        d && d.floor,
        d && d.product && d.product.manufacturer,
        d && d.product && d.product.order_number,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      const match = terms.every((t) => hay.includes(t));
      card.classList.toggle("dimmed", !match);
    }
  }

  // --- animation scheduler (D2/D6) -----------------------------------------

  /**
   * Ingest a telegram for animation. Coalesces same-GA telegrams within a
   * frame and drains once per rAF so bursts stay cheap.
   * @param {Object} telegram - a telegram row from the SSE stream.
   */
  animate(telegram) {
    if (!telegram || telegram.dest_type !== "group" || !telegram.destination) return;
    // Latest telegram for a GA wins within the frame (coalesce).
    this.pending.set(telegram.destination, telegram);
    if (this.rafId == null) {
      this.rafId = requestAnimationFrame(() => this._flush());
    }
  }

  _flush() {
    this.rafId = null;
    const batch = [...this.pending.values()];
    this.pending.clear();
    for (const t of batch) this._animateOne(t);
  }

  _animateOne(t) {
    const ga = t.destination;
    // Live-effects toggle: user disabled all traffic visuals. The log still
    // appends (that path is in log.js); the topology stays quiet.
    if (!this.store.flashEnabled) return;
    // In ga-focus mode, only the focused GA animates so the filtered view is
    // not disturbed by unrelated live traffic.
    if (this.viewState && this.viewState.mode === "ga-focus" && ga !== this.viewState.id) {
      return;
    }
    const suspicious = this.store.isSuspiciousGa(ga);
    const senders = this.store.gaSenders.get(ga) || [];
    const listeners = this.store.gaListeners.get(ga) || [];

    // Source card / line head as the pulse origin.
    const srcPt = this._sourcePoint(t.source, senders);

    // Flash sender + listener cards (always, cheap).
    for (const s of senders) this._flashCard(s.device, suspicious);
    for (const l of listeners) this._flashCard(l.device, suspicious);

    // Reduced motion or no offset-path support: flash-only, no pulses.
    if (this.reducedMotion || !this.supportsOffsetPath) return;

    // Fan-out policy: >4 listeners -> single pulse to spine + spine glow.
    if (listeners.length > 4) {
      this._spineGlow(suspicious);
      const spineTop = this._nearestDrop(srcPt);
      this._spawnPulse(srcPt, { x: this.spineX, y: spineTop }, suspicious);
      return;
    }

    // Otherwise a pulse from the source to each listener (bounded by budget).
    if (listeners.length === 0) {
      // No listeners: pulse from source to the spine to visualise the write.
      this._spawnPulse(srcPt, { x: this.spineX, y: srcPt.y }, suspicious);
      return;
    }
    for (const l of listeners) {
      const pt = this.dropPoints.get(l.device);
      if (pt) this._spawnPulse(srcPt, pt, suspicious);
    }
  }

  /**
   * Resolve the pulse origin: the source device card if known, else the first
   * sender card, else the line-head node (unknown source IAs).
   * @param {string} source
   * @param {Array<Object>} senders
   * @returns {{x:number, y:number}}
   */
  _sourcePoint(source, senders) {
    if (source && this.dropPoints.has(source)) return this.dropPoints.get(source);
    if (senders.length && this.dropPoints.has(senders[0].device)) {
      return this.dropPoints.get(senders[0].device);
    }
    return this.headPoint;
  }

  _nearestDrop(pt) {
    return pt ? pt.y : this.headPoint.y;
  }

  _flashCard(addr, suspicious) {
    const card = this.cardByDevice.get(addr);
    if (!card) return;
    const cls = suspicious ? "flash-suspicious" : "flash";
    card.classList.remove(cls);
    void card.offsetWidth; // reflow so the animation restarts (works for rapid repeats)
    card.classList.add(cls);
    const clear = () => {
      card.classList.remove(cls);
      card.removeEventListener("animationend", clear);
    };
    card.addEventListener("animationend", clear);
    // Recent-activity tint: keep a subtle tint for a few seconds after the glow,
    // decaying via CSS. Re-triggered on each telegram so bursts stay tinted.
    if (!this.reducedMotion) this._markRecent(card);
  }

  /**
   * Keep a subtle recent-activity tint on a card for a few seconds after a
   * flash, decaying via a CSS animation. Re-arming clears the prior timer so
   * rapid repeats extend the tint rather than flicker it.
   * @param {HTMLElement} card
   */
  _markRecent(card) {
    this._recentTimers = this._recentTimers || new Map();
    const prev = this._recentTimers.get(card);
    if (prev) clearTimeout(prev);
    card.classList.remove("recent");
    void card.offsetWidth;
    card.classList.add("recent");
    const timer = setTimeout(() => {
      card.classList.remove("recent");
      this._recentTimers.delete(card);
    }, RECENT_TINT_MS);
    this._recentTimers.set(card, timer);
  }

  _spineGlow(suspicious) {
    const spine = this.spineLayer.querySelector(".bus-spine");
    if (!spine) return;
    const cls = suspicious ? "glow-suspicious" : "glow";
    spine.classList.remove(cls);
    void this.spineLayer.getBBox(); // force a layout flush so the class re-applies
    spine.classList.add(cls);
    setTimeout(() => spine.classList.remove(cls), PULSE_MS);
  }

  /**
   * Spawn a traveling pulse along an offset-path from `from` to `to`, routed
   * via the spine (down the gutter then across). Respects the pulse budget.
   * @param {{x:number, y:number}} from
   * @param {{x:number, y:number}} to
   * @param {boolean} suspicious
   */
  _spawnPulse(from, to, suspicious) {
    if (this.activePulses.size >= MAX_PULSES) return;
    const circle = document.createElementNS(SVG_NS, "circle");
    circle.setAttribute("r", "4");
    circle.setAttribute("class", suspicious ? "topo-pulse suspicious" : "topo-pulse");
    // Route: from -> spine(from.y) -> spine(to.y) -> to.
    const d =
      `M ${from.x} ${from.y} ` +
      `L ${this.spineX} ${from.y} ` +
      `L ${this.spineX} ${to.y} ` +
      `L ${to.x} ${to.y}`;
    circle.style.offsetPath = `path("${d}")`;
    circle.style.offsetRotate = "0deg";
    this.pulseLayer.appendChild(circle);
    this.activePulses.add(circle);

    const anim = circle.animate(
      [{ offsetDistance: "0%" }, { offsetDistance: "100%" }],
      { duration: PULSE_MS, easing: "ease-in-out" },
    );
    const done = () => {
      this.activePulses.delete(circle);
      circle.remove();
    };
    anim.onfinish = done;
    anim.oncancel = done;
  }
}

/**
 * Entry point called by main.js. Builds the topology and returns the handle it
 * animates against (main.js calls `.animate(telegram)` and `.relayout()`).
 * @param {import('./store.js').Store} store
 * @param {{tree?:Object, container?:HTMLElement}} ctx
 * @returns {Topology}
 */
export function init(store, ctx) {
  return new Topology(store, ctx || {});
}
