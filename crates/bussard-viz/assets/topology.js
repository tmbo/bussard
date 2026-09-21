// topology.js - the bus-spine floor diagram (P1, P2, P3, P4, D2, D6).
//
// Renders devices as HTML cards grouped into floor swimlanes and rooms, with
// device-dense rooms (a distribution cabinet holds many DIN-rail devices) drawn
// as a bordered cluster. A single SVG underlay per scroll container carries the
// vertical bus spine, a drop-line per card and selection edges; it is laid out
// in content coordinates from offsetLeft/offsetTop after the cards mount and on
// resize. The animation scheduler flashes cards/tree rows and (when the browser
// supports offset-path) sends a traveling pulse along the spine from sender to
// listeners for each telegram.

// Floor ordering is data-driven: nothing here may depend on one installation's
// room or floor names. Known storey abbreviations (German and English) get a
// fixed rank so a house reads bottom-to-top; any other label sorts after them,
// alphabetically. Matching is case-insensitive on the trimmed label.
const FLOOR_RANK = new Map([
  ["kg", -30],
  ["ug", -20],
  ["basement", -20],
  ["eg", 0],
  ["ground", 0],
  ["ground floor", 0],
  ["og", 10],
  ["1. og", 10],
  ["first floor", 10],
  ["2. og", 20],
  ["second floor", 20],
  ["dg", 30],
  ["attic", 30],
  ["outdoor", 90],
  ["roof", 95],
]);
const UNRANKED_FLOOR = 500; // any label the table does not know
// A room holding at least this many devices is drawn as a distribution cabinet
// (a bordered cluster anchoring its floor). Counting devices rather than
// matching a room name keeps this independent of any one installation.
const CABINET_MIN_DEVICES = 4;
const UNKNOWN_FLOOR = "Unassigned"; // trailing section for unplaced devices
const MAX_PULSES = 6; // concurrent traveling pulses
const MAX_EDGE_LISTENERS = 12; // bound selection edges to avoid a hairball
const MAX_PARTNER_EDGES = 24; // bound device-partner edges to avoid a hairball
const PULSE_MS = 520; // pulse travel duration
const RECENT_TINT_MS = 3500; // recent-activity tint lifetime after a flash
const SVG_NS = "http://www.w3.org/2000/svg";

// --- electrician-style wiring geometry (item 2) ---------------------------
// The spine runs down a narrow left gutter. Cards sit to the right of a dot
// CORRIDOR (GUTTER_W px wide) so animated dots and selection edges never run
// over a card border. Wiring is orthogonal only: each card drops straight down
// from its bottom edge to a horizontal ROW FEEDER drawn in the gap below the
// row, the feeder runs left to the spine, and the spine carries traffic
// vertically between rows. See the geometry doc in `relayout`.
const SPINE_X = 12; // content-space x of the vertical bus spine
const GUTTER_W = 40; // dot-corridor width between the spine and the first card
const ROW_EPS = 8; // px tolerance when grouping cards into a visual row by top

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
 * Sort rank for a floor label: known storey abbreviations first (bottom to
 * top), anything else after them. Case-insensitive on the trimmed label.
 * @param {string} floor
 * @returns {number}
 */
function floorRank(floor) {
  const key = String(floor).trim().toLowerCase();
  const rank = FLOOR_RANK.get(key);
  return rank == null ? UNRANKED_FLOOR : rank;
}

/**
 * Whether a room's device list is dense enough to draw as a distribution
 * cabinet. Purely a count, so it holds for any installation.
 * @param {Array<Object>} devices
 * @returns {boolean}
 */
function isCabinetRoom(devices) {
  return !!devices && devices.length >= CABINET_MIN_DEVICES;
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
    /**
     * Per-card wiring anchors in content coordinates. `x` is the card's
     * horizontal center (where the vertical drop lives), `dropY` the card's
     * bottom edge (top of the drop), `feederY` the horizontal row feeder the
     * drop lands on. `y` mirrors `feederY` so legacy call sites reading `.y`
     * still route via the feeder.
     * @type {Map<string, {x:number, y:number, dropY:number, feederY:number, rowRight:number}>}
     */
    this.dropPoints = new Map();
    /**
     * One entry per visible card ROW: the feeder line geometry. `y` is the
     * feeder's vertical position (in the gap below the row); `right` the x of
     * the row's rightmost drop (feeder spans SPINE_X..right).
     * @type {Array<{y:number, right:number}>}
     */
    this.rowFeeders = [];
    /** @type {{x:number, y:number}} spine head (unknown source IAs) */
    this.headPoint = { x: 0, y: 0 };
    /** @type {number} content-space x of the vertical spine */
    this.spineX = SPINE_X;
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
    // Programming-mode set (item 4): cards whose IA is in the set get a red
    // pulsing glow + PROG badge. Composes with selection/partner/focus styling.
    store.on("prog", (set) => this._applyProg(set));
    // Live-effects toggle: when off, suppress all card/tree/GA flashes and
    // spine pulses. Log is never affected (that wiring is in log.js).
    store.on("flash-enabled", () => {});

    // Apply any programming-mode set already present on the store (e.g. after a
    // model reload that carried it across).
    this._applyProg(store.progDevices);

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

    // Ordered floor list: ranked storeys bottom-to-top, then anything else
    // alphabetically, with the unplaced-devices bucket last.
    const floorNames = [...byFloor.keys()].sort((a, b) => {
      if (a === UNKNOWN_FLOOR) return b === UNKNOWN_FLOOR ? 0 : 1;
      if (b === UNKNOWN_FLOOR) return -1;
      return floorRank(a) - floorRank(b) || a.localeCompare(b);
    });

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
        const ca = isCabinetRoom(rooms.get(a)) ? 0 : 1;
        const cb = isCabinetRoom(rooms.get(b)) ? 0 : 1;
        return ca - cb || a.localeCompare(b);
      });
      for (const room of roomNames) {
        this._buildRoom(body, floor, room, rooms.get(room));
      }
    }
  }

  _buildRoom(parent, floor, room, devices) {
    devices.sort((a, b) => iaKey(a.address) - iaKey(b.address));
    const isCabinet = isCabinetRoom(devices);

    const block = document.createElement("div");
    block.className = isCabinet ? "room-block cabinet-cluster" : "room-block";
    block.dataset.room = room;

    const title = document.createElement("div");
    title.className = isCabinet ? "cabinet-title" : "room-title";
    title.textContent = room === "—" ? "(no room)" : room;
    if (isCabinet) title.textContent = `${room} · ${devices.length} devices`;
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

    // GEOMETRY MODEL (electrician-style row feeders):
    //   * The bus spine is a vertical line at SPINE_X.
    //   * A GUTTER_W-wide dot corridor sits between the spine and the cards
    //     (reserved by .topo-cards margin-left in CSS), so nothing routes over a
    //     card border.
    //   * Visible cards are grouped into ROWS by their top offset. Each row gets
    //     one horizontal FEEDER drawn in the gap BELOW the row.
    //   * Every card DROPS straight down from its bottom-center to its feeder.
    //   * The feeder runs from the card drops left to the spine.
    //   * All edges/pulses route: card -> drop -> feeder -> spine -> (vertical)
    //     -> target feeder -> target drop -> target card. Orthogonal only.
    this.spineX = SPINE_X;
    const topPad = 6;
    const bottomPad = 6;
    this.headPoint = { x: this.spineX, y: topPad + 4 };

    // Measure every visible card in content coordinates.
    /** @type {Array<{addr:string, cx:number, top:number, bottom:number}>} */
    const boxes = [];
    for (const [addr, card] of this.cardByDevice) {
      if (card.offsetParent === null) continue; // hidden (collapsed section)
      const b = this._cardBox(card);
      boxes.push({ addr, cx: b.cx, top: b.top, bottom: b.bottom });
    }

    // Group cards into visual rows by their top offset (within ROW_EPS), then
    // place each row's feeder in the gap just below the row's tallest card.
    boxes.sort((a, b) => a.top - b.top || a.cx - b.cx);
    this.dropPoints.clear();
    this.rowFeeders = [];
    let i = 0;
    while (i < boxes.length) {
      const rowTop = boxes[i].top;
      const row = [];
      while (i < boxes.length && Math.abs(boxes[i].top - rowTop) <= ROW_EPS) {
        row.push(boxes[i]);
        i += 1;
      }
      const rowBottom = Math.max(...row.map((b) => b.bottom));
      // Feeder sits a few px below the row bottom, inside the inter-row gap.
      const feederY = rowBottom + 7;
      const rowRight = Math.max(...row.map((b) => b.cx));
      this.rowFeeders.push({ y: feederY, right: rowRight });
      for (const b of row) {
        this.dropPoints.set(b.addr, {
          x: b.cx,
          y: feederY, // legacy `.y` == feeder y so old routing still works
          dropY: b.bottom,
          feederY,
          rowRight,
        });
      }
    }

    // Repaint spine + feeders + drops (static faint underlay).
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

    // Row feeders (horizontal), then per-card drops (vertical).
    for (const f of this.rowFeeders) {
      const feeder = document.createElementNS(SVG_NS, "line");
      feeder.setAttribute("class", "feeder-line");
      feeder.setAttribute("x1", String(this.spineX));
      feeder.setAttribute("y1", String(f.y));
      feeder.setAttribute("x2", String(f.right));
      feeder.setAttribute("y2", String(f.y));
      this.spineLayer.appendChild(feeder);
    }
    for (const [, pt] of this.dropPoints) {
      const drop = document.createElementNS(SVG_NS, "line");
      drop.setAttribute("class", "drop-line");
      drop.setAttribute("x1", String(pt.x));
      drop.setAttribute("y1", String(pt.dropY));
      drop.setAttribute("x2", String(pt.x));
      drop.setAttribute("y2", String(pt.feederY));
      this.spineLayer.appendChild(drop);
    }

    // In ga-focus mode, place the GA-node marker on the spine (a small dot; the
    // GA identity text lives in the top banner, never over the card grid).
    this.gaNodePoint = null;
    if (this.viewState && this.viewState.mode === "ga-focus") {
      this._drawGaNode();
    }

    // Rebuild edges for the current view (their anchors moved).
    this._renderEdges();
  }

  /**
   * Place the focused GA as a small marker on the spine, at the vertical
   * midpoint of the participating cards' feeders (or the pane middle if none are
   * laid out). NO label is drawn here: the GA identity (address, name, DPT) is
   * carried by the top filter banner, so nothing ever floats over the cards.
   * The direction arrowhead offset (see `_appendFocusEdge`) keeps the arrow off
   * the marker.
   */
  _drawGaNode() {
    const v = this.viewState;
    const pts = v.focusDevices
      .map((a) => this.dropPoints.get(a))
      .filter(Boolean);
    let y;
    if (pts.length) {
      y = pts.reduce((s, p) => s + p.feederY, 0) / pts.length;
    } else {
      y = this.root.scrollHeight / 2;
    }
    const x = this.spineX;
    this.gaNodePoint = { x, y };

    const grp = document.createElementNS(SVG_NS, "g");
    grp.setAttribute("class", "ga-node");
    // A subtle halo so the marker reads against the spine without a label.
    const halo = document.createElementNS(SVG_NS, "circle");
    halo.setAttribute("cx", String(x));
    halo.setAttribute("cy", String(y));
    halo.setAttribute("r", "9");
    halo.setAttribute("class", "ga-node-halo");
    grp.appendChild(halo);
    const dot = document.createElementNS(SVG_NS, "circle");
    dot.setAttribute("cx", String(x));
    dot.setAttribute("cy", String(y));
    dot.setAttribute("r", "6");
    dot.setAttribute("class", "ga-node-dot");
    grp.appendChild(dot);
    this.spineLayer.appendChild(grp);
  }

  /**
   * A card's wiring box in content coordinates: horizontal center `cx` and its
   * `top`/`bottom` edges. offsetLeft/Top are relative to offsetParent, so walk
   * up to the scroll root accumulating both.
   * @param {HTMLElement} card
   * @returns {{cx:number, top:number, bottom:number}}
   */
  _cardBox(card) {
    let left = 0;
    let top = 0;
    let el = card;
    while (el && el !== this.root) {
      left += el.offsetLeft;
      top += el.offsetTop;
      el = el.offsetParent;
    }
    return {
      cx: left + card.offsetWidth / 2,
      top,
      bottom: top + card.offsetHeight,
    };
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
    const DIR = ["dir-incoming", "dir-outgoing", "dir-both"];
    for (const card of this.cardByDevice.values()) {
      card.classList.remove("selected", "partner", "partner-dimmed", "focus-part", ...DIR);
    }
    if (v.mode === "device-partners") {
      const self = this.cardByDevice.get(v.id);
      if (self) self.classList.add("selected");
      const byAddr = new Map(v.partners.map((p) => [p.device, p]));
      for (const [addr, card] of this.cardByDevice) {
        if (addr === v.id) continue;
        const p = byAddr.get(addr);
        if (p) {
          // Direction tint (item 6): partners that send TO the selection are
          // incoming (green); partners that receive FROM it are outgoing
          // (orange); a partner doing both gets the dual treatment.
          card.classList.add("partner", `dir-${p.direction}`);
        } else {
          card.classList.add("partner-dimmed");
        }
      }
    } else if (v.mode === "ga-focus") {
      // Sender cards = outgoing (they emit onto the GA); listeners = incoming.
      const roles = this.store.gaDirections(v.id);
      for (const addr of v.focusDevices) {
        const card = this.cardByDevice.get(addr);
        if (!card) continue;
        card.classList.add("focus-part", `dir-${roles.get(addr) || "incoming"}`);
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
   * Draw one edge per communication partner, colored by data-flow direction
   * (item 6): incoming partners green, outgoing partners orange, `both` gets a
   * dual (incoming + outgoing) pair of edges. Each edge is a full orthogonal
   * path from the selected card, down its drop, along its feeder, up/down the
   * spine, along the partner's feeder, up its drop, to the partner card
   * (item 3). Bounded to {@link MAX_PARTNER_EDGES}.
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
      const dirs = p.direction === "both" ? ["incoming", "outgoing"] : [p.direction];
      for (const dir of dirs) {
        const path = document.createElementNS(SVG_NS, "path");
        path.setAttribute("class", `sel-edge partner-edge dir-${dir}`);
        path.setAttribute("marker-end", "url(#topo-arrow)");
        // Incoming: data flows partner -> selection. Outgoing: selection ->
        // partner. Orient the arrow accordingly.
        path.setAttribute("d", dir === "incoming"
          ? this._wirePath(to, from)
          : this._wirePath(from, to));
        const title = document.createElementNS(SVG_NS, "title");
        title.textContent = `${dir} · shared: ${p.gas.join(", ")}`;
        path.appendChild(title);
        this.edgeLayer.appendChild(path);
      }
      drawn += 1;
    }
  }

  /**
   * Draw focus-mode edges through the GA node marker: sender cards -> GA
   * (outgoing, orange) and GA -> listener cards (incoming, green). A device that
   * both sends and listens gets both edges. Bounded.
   * @param {import('./store.js').ViewState} v
   */
  _renderFocusEdges(v) {
    const node = this.gaNodePoint;
    if (!node) return;
    const senders = this.store.gaSenders.get(v.id) || [];
    const listeners = this.store.gaListeners.get(v.id) || [];
    // Terminate/originate edges a few px off the marker so no edge line pierces
    // the GA dot (S10/1b). The direction arrowhead no longer sits at the spine
    // junction: it rides mid-feeder instead (see _appendFocusEdge), so the
    // junction stays clean (green line-end + amber dot only, no arrow pile-up).
    const nodeAnchor = (fromY) => ({
      x: node.x,
      y: fromY <= node.y ? node.y - 11 : node.y + 11,
    });
    const seenS = new Set();
    let count = 0;
    for (const s of senders) {
      if (count >= MAX_EDGE_LISTENERS || seenS.has(s.device)) continue;
      seenS.add(s.device);
      const pt = this.dropPoints.get(s.device);
      if (!pt) continue;
      // Sender emits ONTO the GA: outgoing (from the sender's perspective). Data
      // flows card -> spine, so the mid-feeder arrow points toward the spine.
      this._appendFocusEdge(pt, nodeAnchor(pt.feederY), "outgoing");
      count += 1;
    }
    const seenL = new Set();
    count = 0;
    for (const l of listeners) {
      if (count >= MAX_EDGE_LISTENERS || seenL.has(l.device)) continue;
      seenL.add(l.device);
      const pt = this.dropPoints.get(l.device);
      if (!pt) continue;
      // Listener receives FROM the GA: incoming (from the listener's
      // perspective). Data flows spine -> card, so the mid-feeder arrow points
      // toward the card.
      this._appendFocusEdge(nodeAnchor(pt.feederY), pt, "incoming");
      count += 1;
    }
  }

  /**
   * Append a focus-mode direction edge. `from`/`to` are wiring anchors or the
   * GA-node point on the spine; `dir` is `outgoing` or `incoming`. The direction
   * arrowhead is placed MID-FEEDER (via a marker-mid vertex) rather than at the
   * spine junction, so it never overlaps the GA dot (S10/1b). Whichever endpoint
   * is a card contributes the feeder segment that carries the arrow.
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} from
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} to
   * @param {'incoming'|'outgoing'} dir
   */
  _appendFocusEdge(from, to, dir) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("class", `sel-edge focus-edge dir-${dir}`);
    // No junction arrow: the line runs clean into the spine (S10/1b). The
    // direction is carried by a standalone arrow glyph placed mid-feeder below.
    path.setAttribute("d", this._wirePath(from, to));
    this.edgeLayer.appendChild(path);

    // Place a standalone arrowhead at the midpoint of the CARD's feeder segment,
    // pointing along the data-flow direction. For outgoing (card -> spine) the
    // card is `from`; for incoming (spine -> card) the card is `to`. The arrow
    // points left (toward the spine) for outgoing, right (toward the card) for
    // incoming, so both read as "away from the GA marker".
    const card = from.dropY != null ? from : to.dropY != null ? to : null;
    if (!card) return;
    const midX = (card.x + this.spineX) / 2;
    // Outgoing: flow toward the spine (leftward => angle 180). Incoming: flow
    // toward the card (rightward => angle 0).
    const angle = dir === "outgoing" ? 180 : 0;
    const arrow = document.createElementNS(SVG_NS, "path");
    arrow.setAttribute("class", `focus-arrow dir-${dir}`);
    // A small triangle centred on the feeder midpoint, rotated to the flow.
    arrow.setAttribute("d", "M -4 -4 L 4 0 L -4 4 z");
    arrow.setAttribute("transform", `translate(${midX} ${card.feederY}) rotate(${angle})`);
    this.edgeLayer.appendChild(arrow);
  }

  /**
   * Build a fully orthogonal wire between two anchors, never crossing a card.
   * Each anchor may be a card wiring point ({x, dropY, feederY}) or a spine
   * point (the GA node / spine head, where feederY is absent). The route is:
   *   card top (dropY) -> down its drop to its feederY -> left along the feeder
   *   to the spine -> vertical along the spine to the other feederY -> right
   *   along that feeder -> up its drop to the other card top.
   * When an endpoint is on the spine (no feederY), it starts/ends at the spine
   * at that endpoint's y directly.
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} a
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} b
   * @returns {string} SVG path data
   */
  _wirePath(a, b) {
    const seg = [];
    // Start point: card top if a is a card, else the spine at a.y.
    if (a.dropY != null && a.feederY != null) {
      seg.push(`M ${a.x} ${a.dropY}`); // card bottom edge
      seg.push(`L ${a.x} ${a.feederY}`); // down the drop to the feeder
      seg.push(`L ${this.spineX} ${a.feederY}`); // along the feeder to the spine
    } else {
      seg.push(`M ${this.spineX} ${a.y}`); // spine point (GA node / head)
    }
    const by = b.feederY != null ? b.feederY : b.y;
    seg.push(`L ${this.spineX} ${by}`); // vertical along the spine
    if (b.dropY != null && b.feederY != null) {
      seg.push(`L ${b.x} ${b.feederY}`); // along the target feeder
      seg.push(`L ${b.x} ${b.dropY}`); // up the target drop to the card
    }
    return seg.join(" ");
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

    // The GA identity lives IN the banner (item 1): amber badge + address +
    // name + DPT, so the focused group address has a dedicated home that can
    // never collide with the card grid. No floating labels over the cards.
    const badge = document.createElement("span");
    badge.className = "tfb-badge";
    badge.textContent = "GROUP ADDRESS";
    const addr = document.createElement("span");
    addr.className = "tfb-addr mono";
    const name = document.createElement("span");
    name.className = "tfb-name";
    const dpt = document.createElement("span");
    dpt.className = "tfb-dpt mono";

    const close = document.createElement("button");
    close.type = "button";
    close.className = "tfb-close";
    close.textContent = "✕";
    close.title = "Clear filter (Esc)";
    close.setAttribute("aria-label", "Clear group-address filter");
    close.addEventListener("click", () => this.store.deselect());

    banner.append(badge, addr, name, dpt, close);
    // The banner is pinned to the TOP of the topology pane, above the cards.
    this.root.insertBefore(banner, this.root.firstChild);
    this.banner = banner;
    this.bannerAddr = addr;
    this.bannerName = name;
    this.bannerDpt = dpt;
  }

  _updateBanner() {
    if (!this.banner) return;
    const v = this.viewState;
    if (v.mode !== "ga-focus") {
      this.banner.hidden = true;
      return;
    }
    const g = this.store.groupByAddr.get(v.id);
    this.bannerAddr.textContent = v.id;
    this.bannerName.textContent = (g && g.name) || "(unnamed)";
    if (g && g.dpt) {
      this.bannerDpt.textContent = g.dpt;
      this.bannerDpt.hidden = false;
    } else {
      this.bannerDpt.hidden = true;
    }
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

  // --- programming mode (item 4) -------------------------------------------

  /**
   * Apply the programming-mode set: cards whose device is in `set` get the
   * `prog` class (red pulsing glow) and reveal their PROG badge; all others
   * clear it. The treatment composes with selection/partner/focus classes
   * (the CSS ensures the red glow beats dimming and the badge stays visible).
   * @param {Set<string>|Iterable<string>} set - device addresses in prog mode.
   */
  _applyProg(set) {
    const prog = set instanceof Set ? set : new Set(set || []);
    for (const [addr, card] of this.cardByDevice) {
      const on = prog.has(addr);
      card.classList.toggle("prog", on);
      const badge = card.querySelector("[data-field=prog]");
      if (badge) badge.hidden = !on;
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
      this._spawnPulse(srcPt, { x: this.spineX, y: srcPt.y }, suspicious);
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
   * @returns {{x:number, y:number, feederY?:number, dropY?:number}}
   */
  _sourcePoint(source, senders) {
    if (source && this.dropPoints.has(source)) return this.dropPoints.get(source);
    if (senders.length && this.dropPoints.has(senders[0].device)) {
      return this.dropPoints.get(senders[0].device);
    }
    return this.headPoint;
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
   * through the wiring corridor (drop -> feeder -> spine -> feeder -> drop) so
   * the dot never crosses a card. Respects the pulse budget.
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} from
   * @param {{x:number, y:number, feederY?:number, dropY?:number}} to
   * @param {boolean} suspicious
   */
  _spawnPulse(from, to, suspicious) {
    if (this.activePulses.size >= MAX_PULSES) return;
    const circle = document.createElementNS(SVG_NS, "circle");
    circle.setAttribute("r", "4");
    circle.setAttribute("class", suspicious ? "topo-pulse suspicious" : "topo-pulse");
    const d = this._wirePath(from, to);
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
