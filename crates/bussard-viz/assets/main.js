// main.js — boot sequence and top-level wiring for the KNX viz page.
//
// Fetches the model + state, builds the store, initializes the GA tree,
// header status dot, and global search, wires keyboard shortcuts, and opens
// the traffic stream. Wave-2 modules (topology/inspector/log) are imported
// defensively so this page still boots while they are placeholders.

import { Store } from "./store.js";
import { fetchModel, fetchState, connectTraffic } from "./api.js";
import { GaTree } from "./gatree.js";

const SEARCH_DEBOUNCE_MS = 100;

/** Boot the application. */
async function boot() {
  const model = await loadModel();
  const store = new Store(model);

  // Debug escape hatch (the single permitted global).
  window.__debug = { store, model };

  renderStats(store);
  renderProblems(store);

  const treeRoot = document.getElementById("ga-tree");
  const tree = new GaTree(treeRoot, store);

  initSearch(store, tree);
  initHeaderStatus(store);
  initKeyboard(store);
  initTabs(store);

  // Load the initial state snapshot (last values + bus status).
  try {
    const state = await fetchState();
    applyState(store, state);
  } catch {
    // No live server (standalone dev). Leave defaults in place.
  }

  // Open the live stream; route telegrams to the store + wave-2 log module.
  const wave2 = await loadWave2(store, tree);
  connectTrafficStream(store, tree, wave2);

  window.__debug.tree = tree;
  window.__debug.wave2 = wave2;
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

function initSearch(store, tree) {
  const input = document.getElementById("search-input");
  const dropdown = document.getElementById("search-results");
  if (!input || !dropdown) return;

  let timer = null;
  const run = () => {
    const q = input.value;
    const results = store.search(q, 8);
    renderSearchResults(dropdown, results, store, tree, input);
    document.body.classList.toggle("query-active", !!q.trim());
    store.setFilter(q); // keeps a query-active dim state consistent
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

function renderSearchResults(dropdown, results, store, tree, input) {
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
        store.select(e.kind, e.id);
        if (e.kind === "ga") tree.expandTo(e.id);
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

function initHeaderStatus(store) {
  const dot = document.getElementById("bus-status-dot");
  const label = document.getElementById("bus-status-label");
  const apply = (status) => {
    if (dot) {
      dot.dataset.state = status.connected ? "connected" : status.state || "offline";
    }
    if (label) label.textContent = status.connected ? "connected" : status.state || "offline";
  };
  apply(store.busStatus);
  store.on("bus-status", apply);
}

// --- tabs ------------------------------------------------------------------

function initTabs(store) {
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
  // Selecting anything jumps to the Inspector tab (wave-2 fills the panel).
  store.on("selection", (sel) => {
    if (sel.kind) show("inspector");
  });
}

// --- keyboard --------------------------------------------------------------

function initKeyboard(store) {
  document.addEventListener("keydown", (ev) => {
    const inField =
      ev.target &&
      (ev.target.tagName === "INPUT" || ev.target.tagName === "TEXTAREA");
    if (ev.key === "/" && !inField) {
      ev.preventDefault();
      const input = document.getElementById("search-input");
      if (input) input.focus();
    } else if (ev.key === "Escape") {
      store.deselect();
      const input = document.getElementById("search-input");
      if (input && document.activeElement === input) input.blur();
    } else if (ev.key === "p" && !inField) {
      store.setPaused();
    }
  });
}

// --- traffic ----------------------------------------------------------------

function connectTrafficStream(store, tree, wave2) {
  const onTelegram = (t) => {
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
    store.setBusStatus({ state: s.state, connected: s.connected, transport: s.transport });
  };
  try {
    if (typeof EventSource !== "undefined") {
      connectTraffic(onTelegram, onStatus, { backlog: 50 });
    }
  } catch {
    // No live stream available (standalone dev); page stays static.
  }
}

// --- defensive wave-2 imports ----------------------------------------------

/**
 * Dynamically import the wave-2 modules. Missing modules or missing init
 * exports are tolerated so the wave-1 page boots against placeholders.
 * @param {Store} store
 * @param {GaTree} tree
 * @returns {Promise<{topology:?Object, inspector:?Object, log:?Object}>}
 */
async function loadWave2(store, tree) {
  const out = { topology: null, inspector: null, log: null };
  const tryInit = async (name, path, container) => {
    try {
      const mod = await import(path);
      if (mod && typeof mod.init === "function") {
        out[name] = mod.init(store, { tree, container });
      }
    } catch {
      // Placeholder or absent module; skip silently.
    }
  };
  await Promise.all([
    tryInit("topology", "./topology.js", document.getElementById("topology")),
    tryInit("inspector", "./inspector.js", document.getElementById("inspector-panel")),
    tryInit("log", "./log.js", document.getElementById("log-body")),
  ]);
  return out;
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", boot);
  } else {
    boot();
  }
}
