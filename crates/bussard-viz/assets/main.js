// main.js — boot sequence and top-level wiring for the KNX viz page.
//
// Fetches the model + state, builds the store, initializes the GA tree,
// header status dot, and global search, wires keyboard shortcuts, and opens
// the traffic stream. Wave-2 modules (topology/inspector/log) are imported
// defensively so this page still boots while they are placeholders.
//
// The model can be reloaded without a page refresh (issue #65). A `model` SSE
// event, or the header reload button, triggers a rebuild: the model is
// refetched, a fresh store is built, and the view modules are re-initialized
// against it. The long-lived wiring (search, keyboard, header status, tabs,
// traffic stream) reads the live store/tree/wave2 through a shared `app`
// context, so it survives a rebuild without being re-registered. The log buffer
// is preserved across a reload (telegrams are model-independent); only its store
// reference is repointed so new rows resolve names and suspicious marks against
// the new model.

import { Store } from "./store.js";
import { fetchModel, fetchState, connectTraffic, reloadModel } from "./api.js";
import { GaTree } from "./gatree.js";

const SEARCH_DEBOUNCE_MS = 100;

// The shared, mutable app context. Long-lived wiring closes over this object
// and always reads the current store/tree/wave2, so a reload can swap them in
// place without re-registering listeners.
const app = { store: null, tree: null, wave2: null };

/** Boot the application. */
async function boot() {
  const model = await loadModel();
  buildViews(model);

  // Debug escape hatch (the single permitted global).
  window.__debug = { get store() { return app.store; }, get tree() { return app.tree; } };

  // Long-lived wiring: registered once, reads the live app context.
  initSearch();
  initHeaderStatus();
  initKeyboard();
  initTabs();
  initReloadButton();

  // Load the initial state snapshot (last values + bus status).
  try {
    const state = await fetchState();
    applyState(app.store, state);
  } catch {
    // No live server (standalone dev). Leave defaults in place.
  }

  // Open the live stream once; telegrams route to the live app context, and a
  // `model` event triggers a rebuild.
  connectTrafficStream();
  window.__debug.wave2 = app.wave2;
}

/**
 * Build (or rebuild) the store and the view modules from a model payload.
 *
 * On the first call it constructs everything. On a reload it constructs a fresh
 * store and re-initializes the view modules that render model-derived DOM
 * (topology, inspector, GA tree), while preserving the existing log instance
 * (its scrollback is model-independent) and repointing it at the new store.
 * @param {Object} model — parsed /api/model payload.
 */
function buildViews(model) {
  const store = new Store(model);
  app.store = store;

  renderStats(store);
  renderProblems(store);

  const treeRoot = document.getElementById("ga-tree");
  app.tree = new GaTree(treeRoot, store);

  // Wave-2 modules render into their own containers (which they clear on init),
  // so a fresh init replaces their DOM. The log keeps its buffer across reloads.
  const previousLog = app.wave2 && app.wave2.log;
  app.wave2 = loadWave2Sync(store, app.tree, previousLog);
}

/**
 * Load the model from the server, falling back to the checked-in fixture so
 * the page can be developed standalone.
 * @returns {Promise<Object>}
 */
async function loadModel() {
  try {
    return await fetchModel();
  } catch {
    const res = await fetch("/assets/fixture-model.json");
    return res.json();
  }
}

function renderStats(store) {
  const el = document.getElementById("stats");
  if (!el) return;
  const s = store.model.stats || {};
  el.textContent = `${s.devices || 0} devices · ${s.groups || 0} groups · ${s.links || 0} links`;
  const proj = document.getElementById("project-name");
  if (proj) proj.textContent = store.model.project || "KNX";
}

function renderProblems(store) {
  const counter = document.getElementById("problems-count");
  if (counter) counter.textContent = String(store.problems.length);
  const btn = document.getElementById("problems-btn");
  if (btn) btn.classList.toggle("has-problems", store.problems.length > 0);
}

/**
 * Apply the /api/state snapshot into the store.
 * @param {Store} store
 * @param {Object} state
 */
function applyState(store, state) {
  if (state.bus) {
    store.setBusStatus({
      state: state.bus.state,
      connected: state.bus.connected,
      transport: state.bus.transport,
    });
  }
  const values = state.values || {};
  for (const ga of Object.keys(values)) {
    store.setValue(ga, values[ga]);
  }
}

// --- search ---------------------------------------------------------------

function initSearch() {
  const input = document.getElementById("search-input");
  const dropdown = document.getElementById("search-results");
  if (!input || !dropdown) return;

  let timer = null;
  const run = () => {
    const q = input.value;
    const results = app.store.search(q, 8);
    renderSearchResults(dropdown, results, input);
    document.body.classList.toggle("query-active", !!q.trim());
    app.store.setFilter(q); // keeps a query-active dim state consistent
  };

  input.addEventListener("input", () => {
    clearTimeout(timer);
    timer = setTimeout(run, SEARCH_DEBOUNCE_MS);
  });

  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      const first = dropdown.querySelector(".search-item");
      if (first) first.click();
    } else if (ev.key === "Escape") {
      dropdown.hidden = true;
    }
  });

  document.addEventListener("click", (ev) => {
    if (!dropdown.contains(ev.target) && ev.target !== input) dropdown.hidden = true;
  });
}

function renderSearchResults(dropdown, results, input) {
  dropdown.textContent = "";
  const total = results.devices.length + results.groups.length;
  if (total === 0) {
    dropdown.hidden = true;
    return;
  }
  const addGroup = (title, items) => {
    if (!items.length) return;
    const head = document.createElement("div");
    head.className = "search-group";
    head.textContent = title;
    dropdown.appendChild(head);
    for (const e of items) {
      const item = document.createElement("button");
      item.type = "button";
      item.className = "search-item";
      item.innerHTML = "";
      const label = document.createElement("span");
      label.className = "search-label";
      label.textContent = e.label;
      const sub = document.createElement("span");
      sub.className = "search-sub";
      sub.textContent = e.sub;
      item.append(label, sub);
      item.addEventListener("click", () => {
        app.store.select(e.kind, e.id);
        if (e.kind === "ga") app.tree.expandTo(e.id);
        dropdown.hidden = true;
        input.blur();
      });
      dropdown.appendChild(item);
    }
  };
  addGroup("Devices", results.devices);
  addGroup("Groups", results.groups);
  dropdown.hidden = false;
}

// --- header status ---------------------------------------------------------

function initHeaderStatus() {
  const dot = document.getElementById("bus-status-dot");
  const label = document.getElementById("bus-status-label");
  const apply = (status) => {
    if (dot) {
      dot.dataset.state = status.connected ? "connected" : status.state || "offline";
    }
    if (label) label.textContent = status.connected ? "connected" : status.state || "offline";
  };
  // The store instance changes on reload, but the bus status is re-applied from
  // the live stream, so a subscription on the current store is refreshed each
  // rebuild via the shared apply below.
  app._applyBusStatus = apply;
  apply(app.store.busStatus);
  subscribeBusStatus();
}

// Re-subscribe the header apply to the current store (called on each rebuild).
function subscribeBusStatus() {
  if (app._applyBusStatus) app.store.on("bus-status", app._applyBusStatus);
}

// --- reload button ---------------------------------------------------------

function initReloadButton() {
  const btn = document.getElementById("reload-btn");
  const errEl = document.getElementById("reload-error");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    if (btn.disabled) return;
    btn.disabled = true;
    btn.classList.add("reloading");
    if (errEl) {
      errEl.hidden = true;
      errEl.textContent = "";
    }
    try {
      // The server swaps the model and emits a `model` SSE event; the stream
      // handler rebuilds the views. Trigger a rebuild here too, so a standalone
      // page (or a missed event) still refreshes.
      await reloadModel();
      await rebuildFromServer();
    } catch (err) {
      if (errEl) {
        errEl.textContent = err && err.message ? err.message : "reload failed";
        errEl.hidden = false;
      }
    } finally {
      btn.disabled = false;
      btn.classList.remove("reloading");
    }
  });
}

// --- tabs ------------------------------------------------------------------

function initTabs() {
  const tabs = document.querySelectorAll(".tab");
  const bodies = {
    groups: document.getElementById("tab-groups"),
    inspector: document.getElementById("tab-inspector"),
  };
  const show = (name) => {
    tabs.forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
    for (const key of Object.keys(bodies)) {
      const el = bodies[key];
      if (!el) continue;
      const on = key === name;
      el.hidden = !on;
      el.classList.toggle("active", on);
    }
  };
  tabs.forEach((t) => t.addEventListener("click", () => show(t.dataset.tab)));
  // Selecting anything jumps to the Inspector tab (wave-2 fills the panel). The
  // subscription is refreshed on each rebuild via subscribeTabs().
  app._showTab = show;
  subscribeTabs();
}

function subscribeTabs() {
  if (app._showTab) {
    app.store.on("selection", (sel) => {
      if (sel.kind) app._showTab("inspector");
    });
  }
}

// --- keyboard --------------------------------------------------------------

function initKeyboard() {
  document.addEventListener("keydown", (ev) => {
    const inField =
      ev.target &&
      (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA");
    if (ev.key === "/" && !inField) {
      ev.preventDefault();
      const input = document.getElementById("search-input");
      if (input) input.focus();
    } else if (ev.key === "Escape") {
      app.store.deselect();
      const input = document.getElementById("search-input");
      if (input && document.activeElement === input) input.blur();
    } else if (ev.key === "p" && !inField) {
      app.store.setPaused();
    }
  });
}

// --- traffic ----------------------------------------------------------------

function connectTrafficStream() {
  const onTelegram = (t) => {
    const store = app.store;
    const wave2 = app.wave2;
    if (t.destination) {
      store.setValue(t.destination, {
        value: t.value,
        payload: t.payload,
        dpt: t.dpt,
        apci: t.apci,
        ts_utc: t.ts_utc,
        source: t.source,
        seq: t.seq,
      });
    }
    store.emit("telegram", t);
    if (wave2.log && typeof wave2.log.append === "function") wave2.log.append(t);
    if (wave2.topology && typeof wave2.topology.animate === "function") {
      wave2.topology.animate(t);
    }
  };
  const onStatus = (s) => {
    app.store.setBusStatus({ state: s.state, connected: s.connected, transport: s.transport });
  };
  const onModel = () => {
    // The server swapped the model; refetch and rebuild the views.
    rebuildFromServer();
  };
  try {
    if (typeof EventSource !== "undefined") {
      connectTraffic(onTelegram, onStatus, { backlog: 50, onModel });
    }
  } catch {
    // No live stream available (standalone dev); page stays static.
  }
}

/**
 * Refetch the model and rebuild the views. Idempotent and safe to call from
 * both the SSE `model` handler and the reload button. Preserves the bus status
 * (re-applied from the live stream) and the log scrollback.
 * @returns {Promise<void>}
 */
async function rebuildFromServer() {
  const model = await loadModel();
  const previousBus = app.store ? app.store.busStatus : null;
  buildViews(model);
  // Re-attach the long-lived subscriptions that live on the store instance.
  subscribeBusStatus();
  subscribeTabs();
  // Carry the last-known bus status onto the fresh store's header.
  if (previousBus) app.store.setBusStatus(previousBus);
  window.__debug.wave2 = app.wave2;
}

// --- defensive wave-2 imports ----------------------------------------------

// Cache the wave-2 module namespaces after the first dynamic import so a rebuild
// can re-init synchronously without another await.
const wave2Modules = { topology: null, inspector: null, log: null, loaded: false };

/**
 * Dynamically import the wave-2 modules once. Missing modules or missing init
 * exports are tolerated so the wave-1 page boots against placeholders.
 * @returns {Promise<void>}
 */
async function preloadWave2() {
  if (wave2Modules.loaded) return;
  const tryLoad = async (name, path) => {
    try {
      const mod = await import(path);
      if (mod && typeof mod.init === "function") wave2Modules[name] = mod;
    } catch {
      // Placeholder or absent module; skip silently.
    }
  };
  await Promise.all([
    tryLoad("topology", "./topology.js"),
    tryLoad("inspector", "./inspector.js"),
    tryLoad("log", "./log.js"),
  ]);
  wave2Modules.loaded = true;
}

/**
 * Initialize the wave-2 modules against a store. Topology and inspector are
 * always re-initialized (they render model-derived DOM into containers they
 * clear). The log is preserved across reloads: an existing instance is
 * repointed at the new store rather than rebuilt, so its scrollback survives.
 * @param {Store} store
 * @param {GaTree} tree
 * @param {?Object} previousLog — the log instance from before a reload, if any.
 * @returns {{topology:?Object, inspector:?Object, log:?Object}}
 */
function loadWave2Sync(store, tree, previousLog) {
  const out = { topology: null, inspector: null, log: null };
  const init = (name, container) => {
    const mod = wave2Modules[name];
    if (mod && typeof mod.init === "function") {
      try {
        return mod.init(store, { tree, container });
      } catch {
        return null;
      }
    }
    return null;
  };
  out.topology = init("topology", document.getElementById("topology"));
  out.inspector = init("inspector", document.getElementById("inspector-panel"));
  if (previousLog) {
    // Preserve the log buffer across a reload; only repoint it at the new store
    // so new rows resolve suspicious marks and selection against the new model.
    previousLog.store = store;
    out.log = previousLog;
  } else {
    out.log = init("log", document.getElementById("log-body"));
  }
  return out;
}

if (typeof document !== "undefined") {
  const start = async () => {
    await preloadWave2();
    await boot();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start);
  } else {
    start();
  }
}
