// log.js - the bottom telegram drawer (D1, D3, D4, D5, D6).
//
// A 5000-entry RingBuffer holds scrollback; the DOM is capped at 1000 rows and
// appends are batched once per rAF from a DocumentFragment. Follow mode auto
// disables on scroll-up and offers a "⤓ follow (+N)" pill to jump back to the
// tail. Pause keeps the buffer filling behind a "+N new" banner. The filter
// input uses store.parseFilter and applies to both incoming rows and a full
// re-filter of the buffer. Row click selects the GA (Alt-click the source
// device), reveals it in the tree, and flashes the sender card. Writes to GAs
// with no listeners (or GAs missing from the model) are marked suspicious.

import { RingBuffer, parseFilter } from "./store.js";

const RING_CAP = 5000;
const DOM_CAP = 1000; // max rendered rows; older rows are trimmed from the top
const OLDER_CHUNK = 500; // "load older" prepend size

/**
 * Instantiate a <template> by id and return its first element child.
 * @param {string} id
 * @returns {HTMLElement}
 */
function cloneTpl(id) {
  const tpl = document.getElementById(id);
  return tpl.content.firstElementChild.cloneNode(true);
}

/** Format an ISO timestamp as HH:MM:SS.mmm (local time). */
function formatTime(tsUtc) {
  const d = tsUtc ? new Date(tsUtc) : new Date();
  if (Number.isNaN(d.getTime())) return "--:--:--.---";
  const p2 = (n) => String(n).padStart(2, "0");
  const p3 = (n) => String(n).padStart(3, "0");
  return `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}.${p3(d.getMilliseconds())}`;
}

/** Compact glyph for an APCI kind. */
function apciGlyph(apci) {
  switch (apci) {
    case "write":
      return "→";
    case "read":
      return "?";
    case "response":
      return "←";
    default:
      return "·";
  }
}

/**
 * The log drawer controller. Owns the RingBuffer + rendered rows and wires the
 * toolbar controls from index.html.
 */
class Log {
  /**
   * @param {import('./store.js').Store} store
   * @param {{tree?:Object, container?:HTMLElement}} ctx
   */
  constructor(store, ctx) {
    this.store = store;
    this.tree = ctx.tree || null;
    this.body = ctx.container || document.getElementById("log-body");

    /** @type {RingBuffer} scrollback (5000) */
    this.ring = new RingBuffer(RING_CAP);
    /** @type {Array<Object>} telegrams queued for the next rAF flush */
    this.queue = [];
    /** @type {number|null} rAF handle */
    this.rafId = null;
    /** @type {boolean} following the tail */
    this.follow = true;
    /** @type {boolean} paused (buffer keeps filling, DOM frozen) */
    this.paused = false;
    /** @type {number} count of buffered-but-not-rendered rows while paused */
    this.pausedNew = 0;
    /** @type {number} count of new rows arrived while scrolled up */
    this.behindNew = 0;
    /** @type {number} oldest ring index currently rendered (for load-older) */
    this._oldestRendered = 0;
    /** @type {(row:Object)=>boolean} active filter predicate */
    this.filterFn = () => true;

    this._cacheControls();
    this._wireToolbar();
    this._wireScroll();
    this._buildBanners();
    this._buildResizeHandle();

    // Pause is shared with the global `p` shortcut via the store.
    store.on("paused", (paused) => this._setPaused(paused));
    store.on("filter", () => {}); // header search filter is separate from log filter
  }

  _cacheControls() {
    this.filterInput = document.getElementById("log-filter");
    this.pauseBtn = document.getElementById("log-pause");
    this.followBtn = document.getElementById("log-follow");
    this.clearBtn = document.getElementById("log-clear");
    this.newCountEl = document.getElementById("log-newcount");
  }

  _wireToolbar() {
    if (this.filterInput) {
      this.filterInput.addEventListener("input", () => this._applyFilter());
    }
    if (this.pauseBtn) {
      this.pauseBtn.addEventListener("click", () => this.store.setPaused());
    }
    if (this.followBtn) {
      this.followBtn.addEventListener("click", () => this._enableFollow());
    }
    if (this.clearBtn) {
      this.clearBtn.addEventListener("click", () => this.clear());
    }
  }

  _wireScroll() {
    this.body.addEventListener("scroll", () => {
      const nearBottom =
        this.body.scrollHeight - this.body.scrollTop - this.body.clientHeight < 24;
      if (nearBottom) {
        if (!this.follow) this._enableFollow();
      } else if (this.follow) {
        // Scrolled up: leave follow mode.
        this.follow = false;
        if (this.followBtn) this.followBtn.classList.remove("active");
      }
      // "Load older" when scrolled to the very top.
      if (this.body.scrollTop < 8) this._loadOlder();
    });
  }

  _buildBanners() {
    // Follow pill (returns to tail with +N indicator).
    this.followPill = document.createElement("button");
    this.followPill.type = "button";
    this.followPill.className = "log-follow-pill";
    this.followPill.hidden = true;
    this.followPill.addEventListener("click", () => this._enableFollow());
    // Resume banner (shown while paused).
    this.resumeBanner = document.createElement("button");
    this.resumeBanner.type = "button";
    this.resumeBanner.className = "log-resume-banner";
    this.resumeBanner.hidden = true;
    this.resumeBanner.addEventListener("click", () => this.store.setPaused(false));
    // Both float over the drawer.
    const drawer = document.getElementById("log-drawer") || this.body.parentElement;
    drawer.appendChild(this.followPill);
    drawer.appendChild(this.resumeBanner);
  }

  _buildResizeHandle() {
    const drawer = document.getElementById("log-drawer");
    if (!drawer || typeof document === "undefined") return;
    const handle = document.createElement("div");
    handle.className = "log-resize-handle";
    handle.title = "Drag to resize the log drawer";
    drawer.appendChild(handle);

    let startY = 0;
    let startH = 0;
    const onMove = (ev) => {
      // Dragging up grows the drawer (it is anchored to the bottom).
      const delta = startY - ev.clientY;
      const h = Math.min(window.innerHeight * 0.8, Math.max(80, startH + delta));
      document.documentElement.style.setProperty("--log-h", `${h}px`);
    };
    const onUp = () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
      document.body.style.userSelect = "";
    };
    handle.addEventListener("mousedown", (ev) => {
      ev.preventDefault();
      startY = ev.clientY;
      startH = drawer.getBoundingClientRect().height;
      document.body.style.userSelect = "none";
      window.addEventListener("mousemove", onMove);
      window.addEventListener("mouseup", onUp);
    });
  }

  // --- ingest (D1) ---------------------------------------------------------

  /**
   * Append a telegram from the live stream. Always buffered in the ring; only
   * rendered when it passes the filter and the drawer is not paused.
   * @param {Object} telegram
   */
  append(telegram) {
    if (!telegram) return;
    // Precompute the suspicious flag once (writes to zero-listener/unknown GA).
    telegram.__suspicious =
      telegram.dest_type === "group" &&
      telegram.apci === "write" &&
      this.store.isSuspiciousGa(telegram.destination);
    this.ring.push(telegram);

    if (this.paused) {
      this.pausedNew += 1;
      this._updatePausedBanner();
      return;
    }
    if (!this.filterFn(telegram)) return;
    this.queue.push(telegram);
    if (this.rafId == null) {
      this.rafId = requestAnimationFrame(() => this._flush());
    }
  }

  _flush() {
    this.rafId = null;
    if (!this.queue.length) return;
    const batch = this.queue;
    this.queue = [];

    const frag = document.createDocumentFragment();
    for (const t of batch) frag.appendChild(this._renderRow(t));
    this.body.appendChild(frag);

    this._trimDom();

    if (this.follow) {
      this.body.scrollTop = this.body.scrollHeight;
    } else {
      this.behindNew += batch.length;
      this._updateFollowPill();
    }
  }

  _trimDom() {
    let excess = this.body.childElementCount - DOM_CAP;
    while (excess-- > 0 && this.body.firstElementChild) {
      this.body.removeChild(this.body.firstElementChild);
    }
  }

  // --- rendering -----------------------------------------------------------

  _renderRow(t) {
    const row = cloneTpl("tpl-log-row");
    row.dataset.ga = t.destination || "";
    row.dataset.source = t.source || "";
    row.querySelector("[data-field=time]").textContent = formatTime(t.ts_utc);

    // Source / destination each show "addr name"; the full text is on the title
    // attribute so a truncated cell still reveals everything on hover.
    const src = row.querySelector("[data-field=source]");
    const srcText = [t.source, t.source_name].filter(Boolean).join(" ");
    src.textContent = srcText;
    if (srcText) src.title = srcText;

    const dest = row.querySelector("[data-field=dest]");
    const destText = [t.destination, t.destination_name].filter(Boolean).join(" ");
    dest.textContent = destText;
    if (destText) dest.title = destText;

    const apci = row.querySelector("[data-field=apci]");
    apci.textContent = apciGlyph(t.apci);
    apci.title = t.apci || "";

    row.querySelector("[data-field=value]").textContent =
      t.value != null && t.value !== "" ? String(t.value) : t.payload || "";
    row.querySelector("[data-field=dpt]").textContent = t.dpt || "";

    if (t.__suspicious) row.classList.add("suspicious");

    // Row click -> select GA + reveal in tree + flash sender; Alt-click -> device.
    row.addEventListener("click", (ev) => {
      if (ev.altKey && t.source) {
        this.store.select("device", t.source);
        return;
      }
      if (t.destination) {
        this.store.select("ga", t.destination);
        if (this.tree && typeof this.tree.expandTo === "function") {
          this.tree.expandTo(t.destination);
        }
        this._flashSenderCard(t.source);
      }
    });
    return row;
  }

  _flashSenderCard(source) {
    if (!source) return;
    const card = document.querySelector(`.device-card[data-device="${cssEscape(source)}"]`);
    if (!card) return;
    card.classList.remove("flash");
    void card.offsetWidth;
    card.classList.add("flash");
  }

  // --- filter (D3) ---------------------------------------------------------

  _applyFilter() {
    const q = this.filterInput ? this.filterInput.value : "";
    this.filterFn = parseFilter(q, (ga) => this.store.isSuspiciousGa(ga));
    this._rerender();
  }

  /** Re-render the DOM from the ring under the current filter. */
  _rerender() {
    const all = this.ring.toArray();
    const matches = [];
    for (const t of all) if (this.filterFn(t)) matches.push(t);
    // Cap to the DOM budget (keep the newest DOM_CAP matches).
    const start = Math.max(0, matches.length - DOM_CAP);
    const shown = matches.slice(start);

    this.body.textContent = "";
    const frag = document.createDocumentFragment();
    for (const t of shown) frag.appendChild(this._renderRow(t));
    this.body.appendChild(frag);

    this.behindNew = 0;
    this._updateFollowPill();
    if (this.follow) this.body.scrollTop = this.body.scrollHeight;
  }

  // --- pause / follow (D4) -------------------------------------------------

  _setPaused(paused) {
    if (paused === this.paused) return;
    this.paused = paused;
    if (this.pauseBtn) {
      this.pauseBtn.classList.toggle("active", paused);
      this.pauseBtn.textContent = paused ? "Resume" : "Pause";
    }
    if (paused) {
      this.pausedNew = 0;
      this._updatePausedBanner();
    } else {
      // Resume: re-render the tail from the ring so the freeze is seamless.
      this.resumeBanner.hidden = true;
      this._rerender();
    }
  }

  _updatePausedBanner() {
    if (!this.paused) {
      this.resumeBanner.hidden = true;
      return;
    }
    this.resumeBanner.hidden = false;
    this.resumeBanner.textContent = `paused · +${this.pausedNew} new · resume`;
  }

  _enableFollow() {
    this.follow = true;
    this.behindNew = 0;
    if (this.followBtn) this.followBtn.classList.add("active");
    this._updateFollowPill();
    this.body.scrollTop = this.body.scrollHeight;
  }

  _updateFollowPill() {
    if (this.follow || this.behindNew === 0) {
      this.followPill.hidden = true;
      return;
    }
    this.followPill.hidden = false;
    this.followPill.textContent = `⤓ follow (+${this.behindNew})`;
  }

  // --- load older (D4) -----------------------------------------------------

  _loadOlder() {
    // Prepend up to OLDER_CHUNK older matching rows that are not yet rendered.
    const all = this.ring.toArray();
    const matches = all.filter((t) => this.filterFn(t));
    const renderedCount = this.body.childElementCount;
    const available = matches.length - renderedCount;
    if (available <= 0) return;

    const take = Math.min(OLDER_CHUNK, available);
    const startIdx = available - take; // index into the not-yet-rendered head
    const older = matches.slice(startIdx, startIdx + take);

    const prevHeight = this.body.scrollHeight;
    const frag = document.createDocumentFragment();
    for (const t of older) frag.appendChild(this._renderRow(t));
    this.body.insertBefore(frag, this.body.firstChild);
    this._trimDomFromBottom();
    // Preserve the viewport position after the prepend.
    this.body.scrollTop += this.body.scrollHeight - prevHeight;
  }

  _trimDomFromBottom() {
    let excess = this.body.childElementCount - DOM_CAP;
    while (excess-- > 0 && this.body.lastElementChild) {
      this.body.removeChild(this.body.lastElementChild);
    }
  }

  // --- clear ---------------------------------------------------------------

  /** Drop all buffered + rendered rows. */
  clear() {
    this.ring.clear();
    this.queue = [];
    this.body.textContent = "";
    this.behindNew = 0;
    this.pausedNew = 0;
    this._updateFollowPill();
    this._updatePausedBanner();
  }
}

/**
 * Escape a string for use in a CSS attribute selector (CSS.escape polyfill-lite).
 * @param {string} s
 * @returns {string}
 */
function cssEscape(s) {
  if (typeof CSS !== "undefined" && typeof CSS.escape === "function") return CSS.escape(s);
  return String(s).replace(/["\\]/g, "\\$&");
}

/**
 * Entry point called by main.js. Returns the handle main.js appends to
 * (main.js calls `.append(telegram)`).
 * @param {import('./store.js').Store} store
 * @param {{tree?:Object, container?:HTMLElement}} ctx
 * @returns {Log}
 */
export function init(store, ctx) {
  return new Log(store, ctx || {});
}
