// layout.js - the resizable inspector panel (issue #252).
//
// The right-hand panel holds the inspector, whose com-object table (grouped by
// channel) is the widest thing on the page. Its width is a CSS custom property
// on #app-main; the grid clamps it between INSPECTOR_MIN_WIDTH and "viewport
// minus GRAPH_MIN_WIDTH", so the graph keeps a usable minimum even without JS.
// A drag handle between the panes changes it, and the chosen width is kept in
// localStorage when storage is available.

/**
 * Default inspector width in CSS pixels. The widest com-object table in the
 * synthetic fixture (1.1.3 "Switch Actuator 8-fold") needs 690 px at its
 * natural, unwrapped width, 718 px with the panel padding. 780 px leaves about
 * 60 px of headroom for longer labels (real installations have German
 * channel and object names); anything longer wraps inside the table.
 */
export const INSPECTOR_DEFAULT_WIDTH = 780;

/**
 * Narrowest inspector the handle allows. The fixture tables still fit here
 * because names, GA chips and remote-device labels wrap.
 */
export const INSPECTOR_MIN_WIDTH = 360;

/** The topology graph never gets narrower than this while dragging. */
export const GRAPH_MIN_WIDTH = 480;

/** Width of the drag handle column between the graph and the panel. */
export const RESIZER_WIDTH = 6;

/** localStorage key for the remembered inspector width. */
export const LS_INSPECTOR_WIDTH_KEY = "bussard-viz.inspector-width";

/** Width change per arrow-key press on the focused handle. */
const KEY_STEP = 16;

/**
 * Clamp a requested inspector width to the allowed range for a viewport.
 * The maximum leaves GRAPH_MIN_WIDTH for the graph (next to the handle), but
 * never drops below the
 * minimum (on a very narrow window the panel wins over the graph).
 * @param {number} width - requested width in CSS pixels.
 * @param {number} viewport - viewport width in CSS pixels.
 * @returns {number}
 */
export function clampInspectorWidth(width, viewport) {
  const max = Math.max(INSPECTOR_MIN_WIDTH, viewport - GRAPH_MIN_WIDTH - RESIZER_WIDTH);
  const w = Number.isFinite(width) ? width : INSPECTOR_DEFAULT_WIDTH;
  return Math.round(Math.min(max, Math.max(INSPECTOR_MIN_WIDTH, w)));
}

/**
 * Read the remembered width. Returns null when storage is missing, throws
 * (private window, blocked site data) or holds no usable number.
 * @param {?Storage} storage
 * @returns {?number}
 */
export function loadInspectorWidth(storage) {
  try {
    if (!storage) return null;
    const raw = storage.getItem(LS_INSPECTOR_WIDTH_KEY);
    if (raw == null) return null;
    const n = Number.parseInt(raw, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
  } catch {
    return null;
  }
}

/**
 * Remember a width. Storage failures are ignored: the width then lasts for
 * this page only.
 * @param {?Storage} storage
 * @param {number} width
 */
export function saveInspectorWidth(storage, width) {
  try {
    if (storage) storage.setItem(LS_INSPECTOR_WIDTH_KEY, String(Math.round(width)));
  } catch {
    // No storage: keep the width in the page only.
  }
}

/** localStorage, or null when even touching it throws. */
function defaultStorage() {
  try {
    return typeof localStorage === "undefined" ? null : localStorage;
  } catch {
    return null;
  }
}

/**
 * Wire the drag handle between the graph and the right panel.
 *
 * Drag with the pointer, or focus the handle and use the arrow keys; a double
 * click (or Home) goes back to the default width.
 * @param {{main?:HTMLElement, handle?:HTMLElement, storage?:?Storage}} [opts]
 */
export function initPanelResizer(opts = {}) {
  const main = opts.main || document.getElementById("app-main");
  const handle = opts.handle || document.getElementById("panel-resizer");
  if (!main || !handle) return;
  const storage = opts.storage === undefined ? defaultStorage() : opts.storage;

  // `preferred` is what the user chose; `width` is that choice clamped to the
  // current window, so growing the window again restores the choice.
  let preferred = loadInspectorWidth(storage) ?? INSPECTOR_DEFAULT_WIDTH;
  let width = preferred;
  const apply = (w, persist) => {
    width = clampInspectorWidth(w, window.innerWidth);
    preferred = width;
    main.style.setProperty("--inspector-width", `${width}px`);
    handle.setAttribute("aria-valuenow", String(width));
    if (persist) saveInspectorWidth(storage, width);
  };
  handle.setAttribute("aria-valuemin", String(INSPECTOR_MIN_WIDTH));
  apply(width, false);

  handle.addEventListener("pointerdown", (ev) => {
    if (ev.button !== 0) return;
    ev.preventDefault();
    handle.setPointerCapture(ev.pointerId);
    main.classList.add("resizing");
    const right = main.getBoundingClientRect().right;
    const onMove = (e) => apply(right - e.clientX, false);
    const onUp = () => {
      handle.removeEventListener("pointermove", onMove);
      handle.removeEventListener("pointerup", onUp);
      handle.removeEventListener("pointercancel", onUp);
      main.classList.remove("resizing");
      saveInspectorWidth(storage, width);
    };
    handle.addEventListener("pointermove", onMove);
    handle.addEventListener("pointerup", onUp);
    handle.addEventListener("pointercancel", onUp);
  });

  handle.addEventListener("dblclick", () => apply(INSPECTOR_DEFAULT_WIDTH, true));
  handle.addEventListener("keydown", (ev) => {
    // The panel sits on the right: moving the handle left widens it.
    if (ev.key === "ArrowLeft") apply(width + KEY_STEP, true);
    else if (ev.key === "ArrowRight") apply(width - KEY_STEP, true);
    else if (ev.key === "Home") apply(INSPECTOR_DEFAULT_WIDTH, true);
    else return;
    ev.preventDefault();
  });

  // Re-clamp when the window size changes, keeping the user's choice.
  window.addEventListener("resize", () => {
    const keep = preferred;
    apply(keep, false);
    preferred = keep;
  });
}
