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
const PULSE_MS = 520; // pulse travel duration
const FLASH_MS = 200; // matches the CSS glow-out keyframe
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
    /** @type {Map<string, {x:number, y:number}>} device -> spine drop point */
    this.dropPoints = new Map();
    /** @type {{x:number, y:number}} spine head (unknown source IAs) */
    this.headPoint = { x: 0, y: 0 };
    /** @type {number} content-space x of the vertical spine */
    this.spineX = 0;

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
    this._observeResize();

    // Two-way selection with the store.
    store.on("selection", (sel) => this._applySelection(sel));
    // Search dimming: main.js sets store.filterText and toggles body.query-active.
    store.on("filter", (q) => this._applyDimming(q));

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
      label.addEventListener("click", () => {
        const collapsed = body.hidden;
        body.hidden = !collapsed;
        label.setAttribute("aria-expanded", String(collapsed));
        label.classList.toggle("collapsed", !collapsed);
        this.relayout();
      });

      lane.append(label, body);
      cardHost.appendChild(lane);

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

    // Rebuild edges for the current selection (their anchors moved).
    this._applySelection(this.store.selection);
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

  // --- selection edges (P2/P3) ---------------------------------------------

  _applySelection(sel) {
    // Card highlight.
    for (const card of this.cardByDevice.values()) card.classList.remove("selected");
    this.edgeLayer.textContent = "";
    if (!sel || !sel.kind) return;

    if (sel.kind === "device") {
      const card = this.cardByDevice.get(sel.id);
      if (card) card.classList.add("selected");
      // Draw this device's GAs: each of its send/listen edges to the spine.
      const gas = this.store.deviceGAs.get(sel.id);
      if (gas) {
        for (const ga of gas) this._drawGaEdges(ga, false);
      }
    } else if (sel.kind === "ga") {
      this._drawGaEdges(sel.id, true);
    }
  }

  /**
   * Draw sender/listener edges for a GA: sender cards -> spine -> listener
   * cards. Bounded so a fan-out GA does not produce a hairball.
   * @param {string} ga
   * @param {boolean} highlightCards - also add .selected to the touched cards.
   */
  _drawGaEdges(ga, highlightCards) {
    const senders = this.store.gaSenders.get(ga) || [];
    const listeners = this.store.gaListeners.get(ga) || [];
    const refs = [
      ...senders.map((s) => ({ addr: s.device, kind: "sender" })),
      ...listeners.map((l) => ({ addr: l.device, kind: "listener" })),
    ].slice(0, MAX_EDGE_LISTENERS);

    for (const ref of refs) {
      const pt = this.dropPoints.get(ref.addr);
      if (!pt) continue;
      if (highlightCards) {
        const card = this.cardByDevice.get(ref.addr);
        if (card) card.classList.add("selected");
      }
      const path = document.createElementNS(SVG_NS, "path");
      path.setAttribute("class", `sel-edge ${ref.kind}`);
      path.setAttribute("d", this._edgePath(pt));
      this.edgeLayer.appendChild(path);
    }
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
    void card.offsetWidth; // reflow so the animation restarts
    card.classList.add(cls);
    const clear = () => {
      card.classList.remove(cls);
      card.removeEventListener("animationend", clear);
    };
    card.addEventListener("animationend", clear);
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
