// gatree.js — the group-address tree (main > middle > sub).
//
// Builds the four-plus main groups expanded to the middle level by default.
// Sub rows are created lazily on first expand and then kept in the DOM.
// Rows carry data-ga for O(1) live-value updates via a Map<ga, el>. Orphan
// warnings roll up from sub rows to middle headers. Selection is two-way with
// the store.

const ACTIVE_WINDOW_MS = 5000;

/**
 * Split a group address into numeric [main, middle, sub].
 * @param {string} ga
 * @returns {[number, number, number]}
 */
function gaParts(ga) {
  const p = ga.split("/").map((n) => parseInt(n, 10));
  return [p[0], p[1], p[2]];
}

/**
 * Instantiate a <template> by id and return its first element child.
 * @param {string} id
 * @returns {HTMLElement}
 */
function clone(id) {
  const tpl = document.getElementById(id);
  return tpl.content.firstElementChild.cloneNode(true);
}

/**
 * The GA tree controller. Owns a DOM subtree and syncs it with the store.
 */
export class GaTree {
  /**
   * @param {HTMLElement} root — container to render into.
   * @param {import('./store.js').Store} store
   */
  constructor(root, store) {
    this.root = root;
    this.store = store;
    /** @type {Map<string, HTMLElement>} ga -> value cell */
    this.valueCells = new Map();
    /** @type {Map<string, HTMLElement>} ga -> sub row */
    this.subRows = new Map();
    /** @type {Map<string, {header:HTMLElement, body:HTMLElement, groups:Array<Object>}>} */
    this.middles = new Map();
    /** @type {Map<string, number>} ga -> last activity timestamp (ms) */
    this.lastActivity = new Map();

    this._build();

    store.on("selection", (sel) => this._applySelection(sel));
    store.on("ga-value", ({ ga, record }) => this.updateValue(ga, record));
  }

  // --- construction -------------------------------------------------------

  _build() {
    this.root.textContent = "";
    const groups = this.store.groupsSorted();

    // Group the GAs by main then middle.
    /** @type {Map<number, Map<number, Array<Object>>>} */
    const byMain = new Map();
    for (const g of groups) {
      const [main, mid] = gaParts(g.address);
      if (!byMain.has(main)) byMain.set(main, new Map());
      const mids = byMain.get(main);
      if (!mids.has(mid)) mids.set(mid, []);
      mids.get(mid).push(g);
    }

    for (const [main, mids] of [...byMain.entries()].sort((a, b) => a[0] - b[0])) {
      const mainRow = clone("tpl-ga-main");
      mainRow.querySelector("[data-field=addr]").textContent = String(main);
      mainRow.querySelector("[data-field=name]").textContent =
        this._rangeName(main, null) || "";
      this.root.appendChild(mainRow);

      const mainBody = document.createElement("div");
      mainBody.className = "ga-main-body";
      this.root.appendChild(mainBody);

      for (const [mid, gas] of [...mids.entries()].sort((a, b) => a[0] - b[0])) {
        this._buildMiddle(mainBody, main, mid, gas);
      }
    }
  }

  _buildMiddle(parent, main, mid, gas) {
    const midRow = clone("tpl-ga-middle");
    const key = `${main}/${mid}`;
    midRow.querySelector("[data-field=addr]").textContent = key;
    midRow.querySelector("[data-field=name]").textContent =
      this._rangeName(main, mid) || "";
    midRow.querySelector("[data-field=count]").textContent = `(${gas.length})`;

    const body = document.createElement("div");
    body.className = "ga-middle-body";
    body.hidden = false; // middle level expanded by default

    const orphans = gas.filter((g) => this._isOrphan(g)).length;
    const orphanEl = midRow.querySelector("[data-field=orphan]");
    if (orphans > 0) {
      orphanEl.textContent = "⚠";
      orphanEl.title = `${orphans} orphan GA(s)`;
      orphanEl.hidden = false;
    }

    midRow.addEventListener("click", () => {
      body.hidden = !body.hidden;
      midRow.classList.toggle("collapsed", body.hidden);
      if (!body.hidden) this._ensureSubs(body, gas);
    });

    parent.appendChild(midRow);
    parent.appendChild(body);
    this.middles.set(key, { header: midRow, body, groups: gas });

    // Expanded by default -> create sub rows now.
    this._ensureSubs(body, gas);
  }

  _ensureSubs(body, gas) {
    if (body.dataset.filled === "1") return;
    for (const g of gas) {
      const row = this._buildSub(g);
      body.appendChild(row);
    }
    body.dataset.filled = "1";
  }

  _buildSub(g) {
    const row = clone("tpl-ga-sub");
    row.dataset.ga = g.address;
    row.querySelector("[data-field=addr]").textContent = g.address;
    row.querySelector("[data-field=name]").textContent = g.name || "(unnamed)";
    if (!g.name) row.classList.add("unnamed");

    const dptEl = row.querySelector("[data-field=dpt]");
    if (g.dpt) {
      dptEl.textContent = g.dpt;
    } else {
      dptEl.hidden = true;
    }

    const valueCell = row.querySelector("[data-field=value]");
    valueCell.dataset.ga = g.address;
    this.valueCells.set(g.address, valueCell);

    const orphanEl = row.querySelector("[data-field=orphan]");
    if (this._isOrphan(g)) {
      orphanEl.textContent = "⚠";
      orphanEl.title = this._orphanReason(g);
      orphanEl.hidden = false;
      row.classList.add("orphan");
    }
    if (g.protected) row.classList.add("protected");

    row.addEventListener("click", (ev) => {
      ev.stopPropagation();
      this.store.select("ga", g.address);
    });

    this.subRows.set(g.address, row);
    return row;
  }

  // --- helpers ------------------------------------------------------------

  _rangeName(main, mid) {
    const key = mid == null ? String(main) : `${main}/${mid}`;
    const r = (this.store.model.ranges || []).find((x) => x.key === key);
    return r ? r.name : null;
  }

  _isOrphan(g) {
    // Only one-sided *linked* GAs are flagged. A fully-unlinked GA (no sender and
    // no listener) is a reserve address, which is normal in KNX and not flagged.
    const hasSender = !!(g.senders && g.senders.length);
    const hasListener = !!(g.listeners && g.listeners.length);
    return (hasSender && !hasListener) || (hasListener && !hasSender);
  }

  _orphanReason(g) {
    const hasSender = !!(g.senders && g.senders.length);
    const hasListener = !!(g.listeners && g.listeners.length);
    if (hasSender && !hasListener) return "senders but no listener";
    return "listeners but no sender";
  }

  // --- live updates -------------------------------------------------------

  /**
   * Update the live-value cell for a GA and register recent activity so the
   * enclosing middle header shows an activity dot.
   * @param {string} ga
   * @param {Object} record — {value, payload, ...}
   */
  updateValue(ga, record) {
    const cell = this.valueCells.get(ga);
    if (cell) {
      cell.textContent =
        record.value != null ? String(record.value) : String(record.payload || "");
      cell.classList.remove("flash");
      // Force reflow so re-adding the class restarts the animation.
      void cell.offsetWidth;
      cell.classList.add("flash");
    }
    this.lastActivity.set(ga, Date.now());
    this._refreshActivityDots();
  }

  _refreshActivityDots() {
    const now = Date.now();
    for (const [key, m] of this.middles) {
      const active = m.groups.some((g) => {
        const t = this.lastActivity.get(g.address);
        return t && now - t < ACTIVE_WINDOW_MS;
      });
      const dot = m.header.querySelector("[data-field=activity]");
      if (dot) dot.classList.toggle("active", active);
    }
  }

  // --- selection ----------------------------------------------------------

  _applySelection(sel) {
    for (const row of this.subRows.values()) row.classList.remove("selected");
    if (sel.kind === "ga") {
      const row = this.subRows.get(sel.id);
      if (row) row.classList.add("selected");
    }
  }

  /**
   * Reveal a GA: walk parents, expand, scroll into view (centered) and flash.
   * @param {string} ga
   */
  expandTo(ga) {
    const [main, mid] = gaParts(ga);
    const key = `${main}/${mid}`;
    const m = this.middles.get(key);
    if (m) {
      m.body.hidden = false;
      m.header.classList.remove("collapsed");
      this._ensureSubs(m.body, m.groups);
    }
    const row = this.subRows.get(ga);
    if (row) {
      row.scrollIntoView({ block: "center", behavior: "smooth" });
      row.classList.remove("flash");
      void row.offsetWidth;
      row.classList.add("flash");
    }
  }
}
