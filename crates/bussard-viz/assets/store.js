// store.js — pure data layer for the KNX visualization.
//
// NO DOM access lives here. The store ingests the /api/model contract,
// builds lookup indexes, derives the P5 problems list and a search index,
// holds runtime state (selection, live values, log filters, pause flag) and
// exposes a tiny pub/sub bus. The log filter-predicate parser and the
// telegram ring buffer also live here so test.html can unit-test them
// without a browser.

/**
 * @typedef {Object} Selection
 * @property {'device'|'ga'|null} kind
 * @property {string|null} id  device address or group address
 */

/**
 * @typedef {Object} ViewState
 * @property {'all'|'device-partners'|'ga-focus'} mode
 * @property {'device'|'ga'|null} kind  — selection kind that drives the view
 * @property {string|null} id  — selected device or GA address
 * @property {Array<{device:string, gas:Array<string>, direction:'incoming'|'outgoing'|'both'}>} partners
 *   — partner devices (device-partners mode), each with the GAs it shares with
 *   the selected device and its data-flow direction relative to the selection:
 *   `incoming` (the partner sends onto a GA the selection listens to),
 *   `outgoing` (the partner listens to a GA the selection sends onto), or
 *   `both`.
 * @property {Array<string>} focusDevices  — participating device addresses
 *   (ga-focus mode): senders and listeners of the focused GA.
 */

const LS_FLASH_KEY = "bussard-viz.flash-effects";

/**
 * Build a comparator sort key for a KNX individual address (a.b.c).
 * @param {string} addr
 * @returns {number}
 */
function iaSortKey(addr) {
  const parts = String(addr).split(".").map((n) => parseInt(n, 10) || 0);
  return (parts[0] || 0) * 0x10000 + (parts[1] || 0) * 0x100 + (parts[2] || 0);
}

/**
 * Build a comparator sort key for a group address (m/mid/sub).
 * @param {string} addr
 * @returns {number}
 */
function gaSortKey(addr) {
  const parts = String(addr).split("/").map((n) => parseInt(n, 10) || 0);
  return (parts[0] || 0) * 0x10000 + (parts[1] || 0) * 0x100 + (parts[2] || 0);
}

/**
 * The central application store. Construct once from an /api/model payload.
 */
export class Store {
  /**
   * @param {Object} model — parsed /api/model JSON matching the contract.
   */
  constructor(model) {
    /** @type {Object} raw model payload */
    this.model = model || { devices: [], groups: [], ranges: [], stats: {} };

    /** @type {Map<string, Object>} device address -> device */
    this.deviceByAddr = new Map();
    /** @type {Map<string, Object>} group address -> group */
    this.groupByAddr = new Map();
    /** @type {Map<string, Array<Object>>} ga -> sender refs */
    this.gaSenders = new Map();
    /** @type {Map<string, Array<Object>>} ga -> listener refs */
    this.gaListeners = new Map();
    /** @type {Map<string, Set<string>>} device address -> set of GAs it touches */
    this.deviceGAs = new Map();

    /** @type {Array<{kind:string,id:string,haystack:string,label:string,sub:string}>} */
    this.searchEntries = [];

    /** @type {Array<Object>} derived P5 problems */
    this.problems = [];
    /** @type {{unusedComObjects:number, unusedGroupAddresses:number}} neutral info counts */
    this.info = { unusedComObjects: 0, unusedGroupAddresses: 0 };

    // Runtime state (mutated over the lifetime of the page).
    /** @type {Selection} */
    this.selection = { kind: null, id: null };
    /**
     * Derived view state: the single source of truth topology renders from.
     * Recomputed on every selection change from the store indexes.
     * @type {ViewState}
     */
    this.view = {
      mode: "all",
      kind: null,
      id: null,
      partners: [],
      focusDevices: [],
    };
    /**
     * Whether live-traffic visual effects (card/tree/GA flashes and spine
     * pulses) are enabled. The log is never affected by this flag. Persisted in
     * localStorage; defaults to on. prefers-reduced-motion still wins in the
     * view layer regardless of this value.
     * @type {boolean}
     */
    this.flashEnabled = this._loadFlashEnabled();
    /** @type {Map<string, Object>} ga -> last value record */
    this.lastValue = new Map();
    /**
     * Individual addresses currently in KNX programming mode (prog LED on).
     * Fed from the /api/state `prog` array and live `prog` SSE events. Empty
     * (the default) means none, so the feature is harmless when the backend
     * never reports it.
     * @type {Set<string>}
     */
    this.progDevices = new Set();
    /** @type {boolean} log paused */
    this.paused = false;
    /** @type {string} raw log filter text */
    this.filterText = "";
    /** @type {{state:string, connected:boolean, transport:string|null}} */
    this.busStatus = { state: "unknown", connected: false, transport: null };

    /** @type {Map<string, Set<Function>>} pub/sub subscribers */
    this._subs = new Map();

    this._buildIndexes();
    this._buildSearchIndex();
    this._computeProblems();
  }

  // --- index construction -------------------------------------------------

  _buildIndexes() {
    for (const d of this.model.devices || []) {
      this.deviceByAddr.set(d.address, d);
      const gas = new Set();
      for (const co of d.com_objects || []) {
        if (co.send) gas.add(co.send);
        for (const l of co.listen || []) gas.add(l);
      }
      this.deviceGAs.set(d.address, gas);
    }
    for (const g of this.model.groups || []) {
      this.groupByAddr.set(g.address, g);
      this.gaSenders.set(g.address, g.senders || []);
      this.gaListeners.set(g.address, g.listeners || []);
    }
  }

  _buildSearchIndex() {
    const entries = [];
    for (const d of this.model.devices || []) {
      const parts = [
        d.address,
        d.name,
        d.description,
        d.floor,
        d.room,
        d.product && d.product.manufacturer,
        d.product && d.product.order_number,
      ].filter(Boolean);
      entries.push({
        kind: "device",
        id: d.address,
        label: d.name || d.address,
        sub: [d.address, d.floor, d.room].filter(Boolean).join(" · "),
        haystack: parts.join(" ").toLowerCase(),
      });
    }
    for (const g of this.model.groups || []) {
      const parts = [
        g.address,
        g.name,
        g.description,
        g.dpt,
        g.range && g.range.main,
        g.range && g.range.middle,
      ].filter(Boolean);
      entries.push({
        kind: "ga",
        id: g.address,
        label: g.name || g.address,
        sub: [g.address, g.dpt].filter(Boolean).join(" · "),
        haystack: parts.join(" ").toLowerCase(),
      });
    }
    this.searchEntries = entries;
  }

  _computeProblems() {
    // The analysis is computed server-side by bussard_model::analysis (the same
    // code path as `bussard audit`) and shipped as `model.analysis`. Only
    // one-sided linked GAs are problems; unlinked com objects and fully-unused
    // GAs are neutral info counts.
    const analysis = this.model.analysis || {};
    this.problems = Array.isArray(analysis.findings) ? analysis.findings : [];
    const info = analysis.info || {};
    this.info = {
      unusedComObjects: info.unlinked_com_objects || 0,
      unusedGroupAddresses: info.unused_group_addresses || 0,
    };
  }

  // --- queries ------------------------------------------------------------

  /**
   * Sorted device list (by individual address).
   * @returns {Array<Object>}
   */
  devicesSorted() {
    return [...(this.model.devices || [])].sort(
      (a, b) => iaSortKey(a.address) - iaSortKey(b.address),
    );
  }

  /**
   * Sorted group list (by group address).
   * @returns {Array<Object>}
   */
  groupsSorted() {
    return [...(this.model.groups || [])].sort(
      (a, b) => gaSortKey(a.address) - gaSortKey(b.address),
    );
  }

  /**
   * Is a write to this GA suspicious? A write arriving on the bus always has a
   * live sender, so a GA with zero listeners means the telegram goes nowhere.
   * Unknown destinations (not in the model) are suspicious too. This matches the
   * "ga-no-listener" problem semantics (senders present, no listeners).
   * @param {string} ga
   * @returns {boolean}
   */
  isSuspiciousGa(ga) {
    const listeners = this.gaListeners.get(ga);
    if (!this.groupByAddr.has(ga)) return true; // unknown destination
    return !listeners || listeners.length === 0;
  }

  /**
   * Run a search query against the prebuilt index. Space-separated terms are
   * ANDed. Returns matches grouped by kind, capped per group.
   * @param {string} query
   * @param {number} [perGroup=8]
   * @returns {{devices:Array<Object>, groups:Array<Object>}}
   */
  search(query, perGroup = 8) {
    const q = String(query || "").trim().toLowerCase();
    const out = { devices: [], groups: [] };
    if (!q) return out;
    const terms = q.split(/\s+/).filter(Boolean);
    for (const e of this.searchEntries) {
      if (terms.every((t) => e.haystack.includes(t))) {
        const bucket = e.kind === "device" ? out.devices : out.groups;
        if (bucket.length < perGroup) bucket.push(e);
      }
    }
    return out;
  }

  // --- runtime mutations (emit events) ------------------------------------

  /**
   * Set the current selection, recompute the derived view state, and notify
   * listeners. A `selection` event carries the raw selection (for the tree /
   * inspector / tab wiring); a `view` event carries the derived {@link ViewState}
   * the topology renders from. Both fire on every change so downstream views
   * stay consistent.
   *
   * A device selection puts the view into `device-partners` mode (selected card
   * plus its communication partners). A GA selection puts it into `ga-focus`
   * mode (only the participating cards plus the GA node). Deselecting returns to
   * `all`.
   * @param {'device'|'ga'|null} kind
   * @param {string|null} id
   */
  select(kind, id) {
    this.selection = { kind: kind || null, id: id || null };
    this.view = this._computeView(this.selection);
    this.emit("selection", this.selection);
    this.emit("view", this.view);
  }

  /** Clear the selection (returns the view to `all`). */
  deselect() {
    this.select(null, null);
  }

  /**
   * Derive the {@link ViewState} for a selection. Pure: reads only the store
   * indexes, mutates nothing. Exposed shape is stable so test.html can assert
   * the transitions.
   * @param {Selection} sel
   * @returns {ViewState}
   */
  _computeView(sel) {
    if (!sel || !sel.kind) {
      return { mode: "all", kind: null, id: null, partners: [], focusDevices: [] };
    }
    if (sel.kind === "device") {
      return {
        mode: "device-partners",
        kind: "device",
        id: sel.id,
        partners: this.communicationPartners(sel.id),
        focusDevices: [],
      };
    }
    // GA selection -> focus mode over its senders + listeners.
    return {
      mode: "ga-focus",
      kind: "ga",
      id: sel.id,
      partners: [],
      focusDevices: this.gaParticipants(sel.id),
    };
  }

  /**
   * Communication partners of a device: every other device that sends on a GA
   * this device listens to, or listens on a GA this device sends. Computed from
   * the sender/listener indexes. Returns one entry per partner device (not per
   * GA) with the sorted list of GAs shared with the selected device and a
   * data-flow `direction` relative to the selection:
   *   `outgoing` — the partner only *listens* to a GA the selection *sends* onto
   *                (data flows out of the selection to the partner);
   *   `incoming` — the partner only *sends* onto a GA the selection *listens* to
   *                (data flows into the selection from the partner);
   *   `both`     — the partner does both.
   * @param {string} deviceAddr
   * @returns {Array<{device:string, gas:Array<string>, direction:'incoming'|'outgoing'|'both'}>}
   */
  communicationPartners(deviceAddr) {
    const d = this.deviceByAddr.get(deviceAddr);
    if (!d) return [];
    /** @type {Map<string, {gas:Set<string>, out:boolean, in:boolean}>} */
    const byPartner = new Map();
    const add = (addr, ga, dir) => {
      if (!addr || addr === deviceAddr) return;
      let rec = byPartner.get(addr);
      if (!rec) {
        rec = { gas: new Set(), out: false, in: false };
        byPartner.set(addr, rec);
      }
      rec.gas.add(ga);
      if (dir === "out") rec.out = true;
      else rec.in = true;
    };
    for (const co of d.com_objects || []) {
      // Devices listening to a GA this device sends on: data flows OUT to them.
      if (co.send) {
        for (const l of this.gaListeners.get(co.send) || []) add(l.device, co.send, "out");
      }
      // Devices sending on a GA this device listens to: data flows IN from them.
      for (const ga of co.listen || []) {
        for (const s of this.gaSenders.get(ga) || []) add(s.device, ga, "in");
      }
    }
    const out = [];
    for (const [device, rec] of byPartner) {
      const direction = rec.out && rec.in ? "both" : rec.out ? "outgoing" : "incoming";
      out.push({
        device,
        gas: [...rec.gas].sort((a, b) => gaSortKey(a) - gaSortKey(b)),
        direction,
      });
    }
    out.sort((a, b) => iaSortKey(a.device) - iaSortKey(b.device));
    return out;
  }

  /**
   * Devices participating in a GA: the union of its senders and listeners
   * (deduplicated, sorted by individual address).
   * @param {string} ga
   * @returns {Array<string>}
   */
  gaParticipants(ga) {
    const set = new Set();
    for (const s of this.gaSenders.get(ga) || []) if (s.device) set.add(s.device);
    for (const l of this.gaListeners.get(ga) || []) if (l.device) set.add(l.device);
    return [...set].sort((a, b) => iaSortKey(a) - iaSortKey(b));
  }

  /**
   * Classify a GA's participating devices by their role, from the perspective of
   * the GA. A device that only *sends* onto the GA emits data onto it
   * (`outgoing` relative to the sender). A device that only *listens* receives
   * from it (`incoming` relative to the listener). A device doing both is
   * `both`. Used by ga-focus mode to color sender cards/edges outgoing and
   * listener cards/edges incoming.
   * @param {string} ga
   * @returns {Map<string, 'incoming'|'outgoing'|'both'>} device addr -> role
   */
  gaDirections(ga) {
    /** @type {Map<string, {send:boolean, listen:boolean}>} */
    const roles = new Map();
    const mark = (addr, key) => {
      if (!addr) return;
      let rec = roles.get(addr);
      if (!rec) {
        rec = { send: false, listen: false };
        roles.set(addr, rec);
      }
      rec[key] = true;
    };
    for (const s of this.gaSenders.get(ga) || []) mark(s.device, "send");
    for (const l of this.gaListeners.get(ga) || []) mark(l.device, "listen");
    /** @type {Map<string, 'incoming'|'outgoing'|'both'>} */
    const out = new Map();
    for (const [addr, rec] of roles) {
      out.set(addr, rec.send && rec.listen ? "both" : rec.send ? "outgoing" : "incoming");
    }
    return out;
  }

  // --- flash-effects toggle -----------------------------------------------

  /**
   * Read the persisted flash-effects preference; defaults to enabled.
   * @returns {boolean}
   */
  _loadFlashEnabled() {
    try {
      if (typeof localStorage === "undefined") return true;
      const v = localStorage.getItem(LS_FLASH_KEY);
      return v === null ? true : v === "1";
    } catch {
      return true;
    }
  }

  /**
   * Toggle or set whether live-traffic visual effects are enabled, persist the
   * choice, and notify listeners. The log is never affected by this flag.
   * @param {boolean} [value] — if omitted, toggles.
   * @returns {boolean} the new value
   */
  setFlashEnabled(value) {
    this.flashEnabled = value === undefined ? !this.flashEnabled : !!value;
    try {
      if (typeof localStorage !== "undefined") {
        localStorage.setItem(LS_FLASH_KEY, this.flashEnabled ? "1" : "0");
      }
    } catch {
      // Storage unavailable (private mode); keep the in-memory value.
    }
    this.emit("flash-enabled", this.flashEnabled);
    return this.flashEnabled;
  }

  /**
   * Record a live value for a GA (from a telegram) and notify listeners.
   * @param {string} ga
   * @param {Object} record — {value, payload, dpt, apci, ts_utc, source, seq}
   */
  setValue(ga, record) {
    this.lastValue.set(ga, record);
    this.emit("ga-value", { ga, record });
  }

  /**
   * Replace the set of devices in programming mode and notify listeners. Accepts
   * any iterable of individual addresses (array from the state fetch or the
   * `prog` SSE event). A null/undefined/empty list clears the set. Idempotent-
   * safe: always emits so views resync even on a repeated identical set.
   * @param {?Iterable<string>} devices - individual addresses in prog mode.
   * @returns {Set<string>} the new prog set
   */
  setProgDevices(devices) {
    this.progDevices = new Set();
    if (devices) {
      for (const a of devices) if (a) this.progDevices.add(String(a));
    }
    this.emit("prog", this.progDevices);
    return this.progDevices;
  }

  /**
   * Whether an individual address is currently in programming mode.
   * @param {string} addr
   * @returns {boolean}
   */
  isProg(addr) {
    return this.progDevices.has(addr);
  }

  /**
   * Set the bus status and notify listeners.
   *
   * `gateway` is the resolved endpoint the server is talking to, e.g.
   * `192.0.2.10:3671` or `multicast 224.0.23.12:3671`, and `loopback` says
   * whether that is a loopback address (the simulator) rather than a real
   * installation. The send widgets name both before every write.
   *
   * @param {{state:string, connected:boolean, transport?:string, gateway?:string, loopback?:boolean}} status
   */
  setBusStatus(status) {
    this.busStatus = {
      state: status.state,
      connected: !!status.connected,
      transport: status.transport || null,
      gateway: status.gateway || null,
      loopback: !!status.loopback,
    };
    this.emit("bus-status", this.busStatus);
  }

  /**
   * Toggle or set the paused flag.
   * @param {boolean} [value] — if omitted, toggles.
   * @returns {boolean} the new paused state
   */
  setPaused(value) {
    this.paused = value === undefined ? !this.paused : !!value;
    this.emit("paused", this.paused);
    return this.paused;
  }

  /**
   * Update the raw log filter text and notify listeners.
   * @param {string} text
   */
  setFilter(text) {
    this.filterText = text || "";
    this.emit("filter", this.filterText);
  }

  // --- pub/sub ------------------------------------------------------------

  /**
   * Subscribe to a topic. Returns an unsubscribe function.
   * Topics: selection, view, ga-value, telegram, bus-status, filter, paused,
   * flash-enabled, prog.
   * @param {string} topic
   * @param {Function} fn
   * @returns {Function} unsubscribe
   */
  on(topic, fn) {
    let set = this._subs.get(topic);
    if (!set) {
      set = new Set();
      this._subs.set(topic, set);
    }
    set.add(fn);
    return () => set.delete(fn);
  }

  /**
   * Emit a topic with a payload to all subscribers.
   * @param {string} topic
   * @param {*} payload
   */
  emit(topic, payload) {
    const set = this._subs.get(topic);
    if (!set) return;
    for (const fn of set) {
      try {
        fn(payload);
      } catch (err) {
        // A misbehaving subscriber must not break the emit loop.
        if (typeof console !== "undefined") console.error(err);
      }
    }
  }
}

/**
 * Parse a log filter query into a predicate over telegram rows.
 *
 * Grammar (space-separated terms, all ANDed together):
 *   d/d/d        exact group address
 *   d/d/*        GA subtree (main/middle/*)
 *   d/*          GA subtree (main/*)
 *   d.d.d        source device (individual address)
 *   apci:read    apci equals read | write | response
 *   is:suspicious   GA has no listener
 *   <text>       case-insensitive substring over the row haystack
 *
 * @param {string} query
 * @param {(ga:string)=>boolean} [isSuspicious] — predicate for is:suspicious.
 * @returns {(row:Object)=>boolean} predicate; matches everything if empty.
 */
export function parseFilter(query, isSuspicious) {
  const raw = String(query || "").trim();
  if (!raw) return () => true;
  const suspFn = isSuspicious || (() => false);
  const terms = raw.split(/\s+/).filter(Boolean);
  /** @type {Array<(row:Object)=>boolean>} */
  const preds = [];

  for (const term of terms) {
    const lower = term.toLowerCase();

    // apci:<kind>
    if (lower.startsWith("apci:")) {
      const kind = lower.slice(5);
      preds.push((row) => String(row.apci || "").toLowerCase() === kind);
      continue;
    }
    // is:suspicious (or is:<flag>)
    if (lower.startsWith("is:")) {
      const flag = lower.slice(3);
      if (flag === "suspicious") {
        preds.push((row) => suspFn(row.destination));
      } else {
        // Unknown is: flag never matches.
        preds.push(() => false);
      }
      continue;
    }
    // Group address (exact or subtree). Contains a slash.
    if (term.includes("/")) {
      const parts = term.split("/");
      if (parts[parts.length - 1] === "*") {
        // Subtree: match on the non-wildcard prefix.
        const prefix = parts.slice(0, -1).join("/") + "/";
        preds.push((row) => String(row.destination || "").startsWith(prefix));
      } else {
        preds.push((row) => row.destination === term);
      }
      continue;
    }
    // Source device (individual address): d.d.d
    if (/^\d+\.\d+\.\d+$/.test(term)) {
      preds.push((row) => row.source === term);
      continue;
    }
    // Free text substring over a computed haystack.
    preds.push((row) => rowHaystack(row).includes(lower));
  }

  return (row) => preds.every((p) => p(row));
}

/**
 * Build a lowercase haystack for a telegram row (used by free-text filtering).
 * @param {Object} row
 * @returns {string}
 */
export function rowHaystack(row) {
  return [
    row.source,
    row.source_name,
    row.destination,
    row.destination_name,
    row.apci,
    row.value,
    row.dpt,
    row.object_name,
    row.note,
  ]
    .filter((v) => v !== null && v !== undefined && v !== "")
    .join(" ")
    .toLowerCase();
}

/**
 * Fixed-capacity ring buffer for telegram scrollback. Oldest entries are
 * overwritten once the cap is reached.
 */
export class RingBuffer {
  /**
   * @param {number} [cap=5000]
   */
  constructor(cap = 5000) {
    /** @type {number} */
    this.cap = cap;
    /** @type {Array<*>} */
    this._buf = new Array(cap);
    /** @type {number} write cursor */
    this._head = 0;
    /** @type {number} number of live entries */
    this.size = 0;
  }

  /**
   * Push a value, overwriting the oldest entry when full.
   * @param {*} value
   */
  push(value) {
    this._buf[this._head] = value;
    this._head = (this._head + 1) % this.cap;
    if (this.size < this.cap) this.size += 1;
  }

  /**
   * Return the live entries in insertion order (oldest first).
   * @returns {Array<*>}
   */
  toArray() {
    const out = [];
    if (this.size < this.cap) {
      for (let i = 0; i < this.size; i++) out.push(this._buf[i]);
    } else {
      for (let i = 0; i < this.cap; i++) {
        out.push(this._buf[(this._head + i) % this.cap]);
      }
    }
    return out;
  }

  /** Drop all entries. */
  clear() {
    this._buf = new Array(this.cap);
    this._head = 0;
    this.size = 0;
  }
}

export { iaSortKey, gaSortKey };
