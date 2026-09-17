// inspector.js - the device / GA detail panel and the DPT send widgets
// (P2, P3, T1, T2). Also owns the header Problems panel (P5).
//
// It renders into #inspector-panel from the two <template> elements in
// index.html and rebuilds on every selection change. GA views carry a send
// widget whose value strings are exactly what bussard's `parse_value` accepts
// (see crates/bussard-model/src/codec.rs), so what the UI sends round-trips
// through the same encoder as `bussard write`. Sends are optimistic: a
// "sending…" state resolves when the echoed telegram for the GA arrives on the
// store's telegram topic, or surfaces the API error code/message inline.

import { groupWrite } from "./api.js";

const SEND_TIMEOUT_MS = 4000; // clear "sending…" if no echo arrives

/**
 * Instantiate a <template> by id and return its first element child.
 * @param {string} id
 * @returns {HTMLElement}
 */
function cloneTpl(id) {
  const tpl = document.getElementById(id);
  return tpl.content.firstElementChild.cloneNode(true);
}

/** Create an element with class + text in one call. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

/**
 * The inspector controller. Renders the currently selected device or GA and
 * wires the send widgets. One instance per page.
 */
class Inspector {
  /**
   * @param {import('./store.js').Store} store
   * @param {{tree?:Object, container?:HTMLElement}} ctx
   */
  constructor(store, ctx) {
    this.store = store;
    this.tree = ctx.tree || null;
    this.root = ctx.container || document.getElementById("inspector-panel");

    /** @type {Map<string, {onEcho:Function, status:HTMLElement, timer:number}>} */
    this._pendingSends = new Map();

    store.on("selection", (sel) => this.render(sel));
    store.on("ga-value", ({ ga, record }) => this._onLiveValue(ga, record));
    // Echo confirmation for optimistic sends arrives on the telegram topic.
    store.on("telegram", (t) => this._onTelegram(t));

    this._initProblemsPanel();
    this.render(store.selection);
  }

  // --- routing -------------------------------------------------------------

  /**
   * Render the panel for the current selection.
   * @param {{kind:?string, id:?string}} sel
   */
  render(sel) {
    this.root.textContent = "";
    if (!sel || !sel.kind) {
      this.root.appendChild(el("p", "empty-hint", "Select a device or group to inspect."));
      return;
    }
    if (sel.kind === "device") this._renderDevice(sel.id);
    else if (sel.kind === "ga") this._renderGa(sel.id);
  }

  // --- device view (P2) ----------------------------------------------------

  _renderDevice(addr) {
    const d = this.store.deviceByAddr.get(addr);
    if (!d) {
      this.root.appendChild(el("p", "empty-hint", `Unknown device ${addr}`));
      return;
    }
    const view = cloneTpl("tpl-inspector-device");
    view.querySelector("[data-field=addr]").textContent = d.address;
    view.querySelector("[data-field=name]").textContent = d.name || d.address;

    // Meta: floor/room + product.
    const meta = view.querySelector("[data-field=meta]");
    const loc = [d.floor, d.room].filter(Boolean).join(" · ");
    if (loc) meta.appendChild(el("span", "insp-chip", loc));
    if (d.product) {
      const p = [d.product.manufacturer, d.product.order_number].filter(Boolean).join(" ");
      if (p) meta.appendChild(el("span", "insp-chip", p));
    }
    if (d.description) meta.appendChild(el("span", "insp-desc", d.description));

    // Channels.
    const chSection = view.querySelector("[data-field=channels]");
    const channels = d.channels || [];
    if (channels.length) {
      chSection.appendChild(el("h3", "insp-h3", `Channels (${channels.length})`));
      const list = el("div", "insp-channels");
      for (const c of channels) {
        const chip = el("span", "insp-chip mono", c.key);
        if (c.name) chip.title = c.name;
        chip.append(document.createTextNode(c.name ? ` ${c.name}` : ""));
        list.appendChild(chip);
      }
      chSection.appendChild(list);
    }

    // Com-object table.
    const coSection = view.querySelector("[data-field=comobjects]");
    const cos = d.com_objects || [];
    coSection.appendChild(el("h3", "insp-h3", `Com objects (${cos.length})`));
    coSection.appendChild(this._comObjectTable(cos));

    this.root.appendChild(view);
  }

  _comObjectTable(cos) {
    const table = el("table", "insp-table co-table");
    const thead = el("thead");
    const hr = el("tr");
    for (const h of ["#", "Name", "DPT", "Flags", "Ch", "Send", "Listen"]) {
      hr.appendChild(el("th", null, h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    const tbody = el("tbody");
    for (const co of cos) {
      const tr = el("tr");
      const noLink = !co.send && !(co.listen && co.listen.length);
      if (noLink) tr.classList.add("unlinked");
      tr.appendChild(el("td", "mono", String(co.number)));
      tr.appendChild(el("td", null, co.name || "—"));
      tr.appendChild(el("td", "mono dim", co.dpt || "—"));
      tr.appendChild(el("td", "mono dim", co.flags || "—"));
      tr.appendChild(el("td", "mono dim", co.channel || "—"));

      // Send GA chip (clickable -> select the GA).
      const sendTd = el("td");
      if (co.send) sendTd.appendChild(this._gaChip(co.send));
      else sendTd.textContent = "—";
      tr.appendChild(sendTd);

      // Listen GA chips.
      const listenTd = el("td", "listen-cell");
      const listen = co.listen || [];
      if (listen.length) {
        for (const ga of listen) listenTd.appendChild(this._gaChip(ga));
      } else {
        listenTd.textContent = "—";
      }
      tr.appendChild(listenTd);

      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    return table;
  }

  /**
   * A clickable GA chip that selects the GA (and reveals it in the tree).
   * @param {string} ga
   * @returns {HTMLElement}
   */
  _gaChip(ga) {
    const btn = el("button", "ga-chip mono", ga);
    btn.type = "button";
    const g = this.store.groupByAddr.get(ga);
    if (g && g.name) btn.title = g.name;
    if (this.store.isSuspiciousGa(ga)) btn.classList.add("suspicious");
    btn.addEventListener("click", () => this._selectGa(ga));
    return btn;
  }

  /**
   * A clickable device chip that selects the device.
   * @param {string} addr
   * @param {string} [label]
   * @returns {HTMLElement}
   */
  _deviceChip(addr, label) {
    const d = this.store.deviceByAddr.get(addr);
    const text = label || (d && d.name) || addr;
    const btn = el("button", "device-chip", text);
    btn.type = "button";
    btn.title = addr;
    const sub = el("span", "chip-addr mono", addr);
    btn.appendChild(sub);
    btn.addEventListener("click", () => this.store.select("device", addr));
    return btn;
  }

  _selectGa(ga) {
    this.store.select("ga", ga);
    if (this.tree && typeof this.tree.expandTo === "function") this.tree.expandTo(ga);
  }

  // --- GA view (P3, T1, T2) ------------------------------------------------

  _renderGa(ga) {
    const g = this.store.groupByAddr.get(ga);
    if (!g) {
      this.root.appendChild(el("p", "empty-hint", `Unknown group ${ga}`));
      return;
    }
    const view = cloneTpl("tpl-inspector-ga");
    view.querySelector("[data-field=addr]").textContent = g.address;
    view.querySelector("[data-field=name]").textContent = g.name || "(unnamed)";
    const dptEl = view.querySelector("[data-field=dpt]");
    if (g.dpt) dptEl.textContent = g.dpt;
    else dptEl.hidden = true;

    // Meta: range path, protected marker, live value + updated-at.
    const meta = view.querySelector("[data-field=meta]");
    const rangePath = [g.range && g.range.main, g.range && g.range.middle]
      .filter(Boolean)
      .join(" › ");
    if (rangePath) meta.appendChild(el("span", "insp-chip", rangePath));
    if (g.protected) {
      const lock = el("span", "insp-chip protected-chip", "🔒 protected");
      meta.appendChild(lock);
    }
    const valWrap = el("span", "insp-live");
    const rec = this.store.lastValue.get(ga);
    valWrap.appendChild(el("span", "live-label", "value:"));
    const valEl = el("span", "live-value mono", this._formatValue(rec));
    valEl.dataset.ga = ga;
    valWrap.appendChild(valEl);
    const tsEl = el("span", "live-ts", rec && rec.ts_utc ? this._ago(rec.ts_utc) : "");
    tsEl.dataset.ga = ga;
    valWrap.appendChild(tsEl);
    meta.appendChild(valWrap);
    this._liveValueEl = valEl;
    this._liveTsEl = tsEl;

    // Send widget.
    const widgetSection = view.querySelector("[data-field=widget]");
    widgetSection.appendChild(el("h3", "insp-h3", "Send test value"));
    widgetSection.appendChild(this._buildSendWidget(g));

    // Senders / listeners.
    const sendersSection = view.querySelector("[data-field=senders]");
    this._buildRefList(sendersSection, "Senders", g.senders || []);
    const listenersSection = view.querySelector("[data-field=listeners]");
    this._buildRefList(listenersSection, "Listeners", g.listeners || []);

    this.root.appendChild(view);
  }

  _buildRefList(section, title, refs) {
    section.appendChild(el("h3", "insp-h3", `${title} (${refs.length})`));
    if (!refs.length) {
      section.appendChild(el("p", "insp-none", `no ${title.toLowerCase()}`));
      return;
    }
    const list = el("div", "ref-list");
    for (const r of refs) {
      const row = el("div", "ref-row");
      row.appendChild(this._deviceChip(r.device, r.device_name));
      const objTxt = r.object_name ? `#${r.object} ${r.object_name}` : `#${r.object}`;
      row.appendChild(el("span", "ref-obj dim", objTxt));
      list.appendChild(row);
    }
    section.appendChild(list);
  }

  // --- send widgets (T1) ---------------------------------------------------

  /**
   * Build the DPT-specific send widget for a GA. Value strings match
   * `parse_value` in bussard-model/src/codec.rs exactly. Protected GAs render
   * disabled behind a "force" arming checkbox. Every widget carries a raw
   * value field fallback (free-form string + optional DPT override), because
   * the server encodes with `parse_value` and has no raw-hex path.
   * @param {Object} g - group record.
   * @returns {HTMLElement}
   */
  _buildSendWidget(g) {
    const wrap = el("div", "send-widget");
    wrap.dataset.ga = g.address;

    // Status line (optimistic "sending…" / confirmation / error).
    const status = el("div", "send-status");
    status.hidden = true;

    // Protected arming.
    let armed = { value: !g.protected };
    let armBox = null;
    if (g.protected) {
      const armRow = el("label", "arm-row");
      armBox = el("input");
      armBox.type = "checkbox";
      armRow.appendChild(armBox);
      armRow.appendChild(el("span", null, "force write to protected GA"));
      wrap.appendChild(armRow);
      armBox.addEventListener("change", () => {
        armed.value = armBox.checked;
        this._setControlsDisabled(controls, !armed.value);
      });
    }

    // A send() closure captured by every control in this widget.
    const send = (value, dptOverride) => {
      if (g.protected && !armed.value) return;
      this._send(g, value, { dpt: dptOverride, force: g.protected && armed.value }, status);
    };

    const controls = el("div", "send-controls");
    this._populateControls(controls, g, send);
    wrap.appendChild(controls);

    // Raw value fallback (free-form value string + optional DPT override).
    wrap.appendChild(this._rawFallback(g, send));

    wrap.appendChild(status);
    if (g.protected) this._setControlsDisabled(controls, true);
    return wrap;
  }

  _setControlsDisabled(controls, disabled) {
    for (const c of controls.querySelectorAll("button, input, select")) {
      c.disabled = disabled;
    }
  }

  /**
   * Fill the controls container for a GA based on its DPT main/sub number.
   * Only value strings accepted by `parse_value` are emitted; DPTs the encoder
   * cannot parse from a string (1.017, 1.100, 3.007, 10/11/19) route through a
   * pragmatic override or the raw field.
   * @param {HTMLElement} controls
   * @param {Object} g
   * @param {(value:string, dptOverride?:string)=>void} send
   */
  _populateControls(controls, g, send) {
    const dpt = g.dpt || "";
    const [mainStr, subStr] = dpt.split(".");
    const main = parseInt(mainStr, 10);
    const sub = subStr || "";

    // DPT 1.x - booleans with subtype-specific labels.
    if (main === 1) {
      this._boolControls(controls, dpt, sub, send);
      return;
    }
    // DPT 3.007 - dimming control (brighter/darker + step). parse_value cannot
    // encode DPT 3 from a string, so these route through the raw field with a
    // hint; expose quick presets that fill it.
    if (main === 3) {
      const hint = el("p", "widget-hint", "DPT 3 control cannot be sent as a value; use the raw field with an explicit --dpt on the bus, or send a step below via 3.007.");
      controls.appendChild(hint);
      return;
    }
    // DPT 5.001 - percent slider + synced number.
    if (dpt === "5.001") {
      this._percentControls(controls, send);
      return;
    }
    // DPT 5.003 - angle 0-360.
    if (dpt === "5.003") {
      this._numberControl(controls, send, { min: 0, max: 360, step: 1, unit: "°" });
      return;
    }
    // DPT 5.x - unsigned byte 0-255.
    if (main === 5) {
      this._numberControl(controls, send, { min: 0, max: 255, step: 1 });
      return;
    }
    // DPT 9.x - 2-byte float with a unit hint.
    if (main === 9) {
      this._numberControl(controls, send, { step: 0.1, unit: unitForDpt9(dpt) });
      return;
    }
    // DPT 20.102 - HVAC mode dropdown.
    if (dpt === "20.102") {
      this._hvacControls(controls, send);
      return;
    }
    // DPT 6/7/8/12/13/14 - plain numbers.
    if ([6, 7, 8, 12, 13, 14].includes(main)) {
      this._numberControl(controls, send, numberRange(main));
      return;
    }
    // DPT 17/18 - scene number.
    if (main === 17 || main === 18) {
      this._numberControl(controls, send, { min: 0, max: 63, step: 1, label: "scene" });
      return;
    }
    // DPT 10/11/19 (time/date/datetime) and anything else: raw field only.
    const hint = el("p", "widget-hint", dpt
      ? `No structured widget for DPT ${dpt}; use the raw value field below.`
      : "This GA has no DPT; set one via --dpt in the raw field below.");
    controls.appendChild(hint);
  }

  _boolControls(controls, dpt, sub, send) {
    // Subtype label pairs that parse_value accepts (codec.rs bool parsing).
    // [falseLabel, falseValue, trueLabel, trueValue]
    const pairs = {
      "003": ["Disable", "disable", "Enable", "enable"],
      "008": ["Up", "up", "Down", "down"],
      "009": ["Open", "open", "Close", "close"],
      "010": ["Stop", "stop", "Start", "start"],
    };
    // 1.017 trigger, 1.100 heat/cool: parse_value has no words; send via 1.001.
    if (dpt === "1.017") {
      const trig = el("button", "send-btn primary", "Trigger");
      trig.type = "button";
      trig.addEventListener("click", () => send("on", "1.001"));
      controls.appendChild(trig);
      controls.appendChild(el("span", "widget-hint", "sent as 1.001 “on”"));
      return;
    }
    const pair = pairs[sub];
    if (pair) {
      const [flabel, fval, tlabel, tval] = pair;
      controls.appendChild(this._sendButton(tlabel, () => send(tval), "primary"));
      controls.appendChild(this._sendButton(flabel, () => send(fval), ""));
    } else {
      // 1.001/1.002/1.005/1.007/1.100 and the generic case: On/Off.
      controls.appendChild(this._sendButton("On", () => send("on"), "primary"));
      controls.appendChild(this._sendButton("Off", () => send("off"), ""));
    }
  }

  _percentControls(controls, send) {
    const row = el("div", "slider-row");
    const slider = el("input");
    slider.type = "range";
    slider.min = "0";
    slider.max = "100";
    slider.value = "50";
    const num = el("input");
    num.type = "number";
    num.min = "0";
    num.max = "100";
    num.step = "1";
    num.value = "50";
    num.className = "num-input";
    // Two-way sync.
    slider.addEventListener("input", () => { num.value = slider.value; });
    num.addEventListener("input", () => { slider.value = num.value; });
    const btn = this._sendButton("Send %", () => send(`${clampInt(num.value, 0, 100)}%`), "primary");
    row.append(slider, num, el("span", "unit", "%"), btn);
    controls.appendChild(row);
  }

  _numberControl(controls, send, opts) {
    const row = el("div", "slider-row");
    const num = el("input");
    num.type = "number";
    if (opts.min != null) num.min = String(opts.min);
    if (opts.max != null) num.max = String(opts.max);
    num.step = String(opts.step || 1);
    num.value = opts.min != null ? String(opts.min) : "0";
    num.className = "num-input";
    row.appendChild(num);
    if (opts.unit) row.appendChild(el("span", "unit", opts.unit));
    const build = () => {
      const raw = num.value.trim();
      if (opts.label === "scene") return `scene ${raw}`;
      return opts.unit && opts.unit !== "°" ? `${raw}${opts.unit}` : raw;
    };
    row.appendChild(this._sendButton("Send", () => send(build()), "primary"));
    controls.appendChild(row);
  }

  _hvacControls(controls, send) {
    const row = el("div", "slider-row");
    const select = el("select", "hvac-select");
    // Values are exactly what parse_value's HVAC parser accepts.
    const modes = [
      ["Auto", "auto"],
      ["Comfort", "comfort"],
      ["Standby", "standby"],
      ["Economy", "economy"],
      ["Building Protection", "building-protection"],
    ];
    for (const [label, value] of modes) {
      const opt = el("option", null, label);
      opt.value = value;
      select.appendChild(opt);
    }
    row.appendChild(select);
    row.appendChild(this._sendButton("Send", () => send(select.value), "primary"));
    controls.appendChild(row);
  }

  _rawFallback(g, send) {
    const details = el("details", "raw-fallback");
    const summary = el("summary", null, "Raw value");
    details.appendChild(summary);
    const row = el("div", "slider-row");
    const val = el("input");
    val.type = "text";
    val.className = "raw-input mono";
    val.placeholder = "value (e.g. on, 75%, 21.5)";
    const dptIn = el("input");
    dptIn.type = "text";
    dptIn.className = "raw-dpt mono";
    dptIn.placeholder = "--dpt (optional)";
    dptIn.size = 10;
    const btn = this._sendButton("Send raw", () => {
      const v = val.value.trim();
      if (!v) return;
      send(v, dptIn.value.trim() || undefined);
    }, "");
    val.addEventListener("keydown", (ev) => { if (ev.key === "Enter") btn.click(); });
    row.append(val, dptIn, btn);
    details.appendChild(row);
    details.appendChild(el("p", "widget-hint", "Sent verbatim through the encoder (no raw hex; server uses parse_value)."));
    return details;
  }

  _sendButton(label, onClick, variant) {
    const btn = el("button", `send-btn ${variant || ""}`.trim(), label);
    btn.type = "button";
    btn.addEventListener("click", onClick);
    return btn;
  }

  // --- send lifecycle (optimistic + echo confirmation) ---------------------

  /**
   * Perform a group write, show optimistic status, and resolve when the echoed
   * telegram arrives (or surface the API error inline).
   * @param {Object} g
   * @param {string} value
   * @param {{dpt?:string, force?:boolean}} opts
   * @param {HTMLElement} status
   */
  async _send(g, value, opts, status) {
    const ga = g.address;
    status.hidden = false;
    status.className = "send-status sending";
    status.textContent = `sending ${value}…`;

    // Arm echo confirmation before the request so we never miss a fast echo.
    const prev = this._pendingSends.get(ga);
    if (prev) {
      clearTimeout(prev.timer);
      this._pendingSends.delete(ga);
    }
    const pending = {
      value,
      status,
      timer: setTimeout(() => {
        this._pendingSends.delete(ga);
        if (status.classList.contains("sending")) {
          status.className = "send-status sent";
          status.textContent = `sent ${value} (no echo observed)`;
        }
      }, SEND_TIMEOUT_MS),
    };
    this._pendingSends.set(ga, pending);

    try {
      const res = await groupWrite(ga, value, opts);
      // Keep "sending…" until echo; note confirmed flag if present.
      if (res && res.confirmed === false) {
        status.textContent = `sent ${res.value != null ? res.value : value}…`;
      }
    } catch (err) {
      clearTimeout(pending.timer);
      this._pendingSends.delete(ga);
      const code = err.code ? ` [${err.code}]` : "";
      status.className = "send-status error";
      status.textContent = `error${code}: ${err.message}`;
    }
  }

  _onTelegram(t) {
    if (!t || !t.destination) return;
    const pending = this._pendingSends.get(t.destination);
    if (!pending) return;
    // Any write/response echo on the GA confirms the send.
    if (t.apci === "write" || t.apci === "response") {
      clearTimeout(pending.timer);
      this._pendingSends.delete(t.destination);
      pending.status.className = "send-status confirmed";
      const shown = t.value != null ? t.value : pending.value;
      pending.status.textContent = `confirmed: ${shown}`;
    }
  }

  _onLiveValue(ga, record) {
    if (!this._liveValueEl || this._liveValueEl.dataset.ga !== ga) return;
    this._liveValueEl.textContent = this._formatValue(record);
    if (this._liveTsEl) this._liveTsEl.textContent = record.ts_utc ? this._ago(record.ts_utc) : "";
  }

  _formatValue(rec) {
    if (!rec) return "—";
    if (rec.value != null && rec.value !== "") return String(rec.value);
    if (rec.payload) return rec.payload;
    return "—";
  }

  _ago(tsUtc) {
    const t = Date.parse(tsUtc);
    if (Number.isNaN(t)) return "";
    const secs = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (secs < 60) return `${secs}s ago`;
    if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
    return `${Math.round(secs / 3600)}h ago`;
  }

  // --- problems panel (P5) -------------------------------------------------

  _initProblemsPanel() {
    const btn = document.getElementById("problems-btn");
    if (!btn) return;
    let panel = document.getElementById("problems-panel");
    if (!panel) {
      panel = el("div", "problems-panel");
      panel.id = "problems-panel";
      panel.hidden = true;
      document.body.appendChild(panel);
    }
    this._problemsPanel = panel;

    btn.addEventListener("click", () => {
      if (panel.hidden) this._renderProblems(btn);
      panel.hidden = !panel.hidden;
    });
    document.addEventListener("click", (ev) => {
      if (panel.hidden) return;
      if (ev.target === btn || btn.contains(ev.target)) return;
      if (!panel.contains(ev.target)) panel.hidden = true;
    });
    document.addEventListener("keydown", (ev) => {
      if (ev.key === "Escape") panel.hidden = true;
    });
  }

  _renderProblems(btn) {
    const panel = this._problemsPanel;
    panel.textContent = "";
    // Position under the button.
    const rect = btn.getBoundingClientRect();
    panel.style.top = `${rect.bottom + 6}px`;
    panel.style.right = `${Math.max(8, window.innerWidth - rect.right)}px`;

    const problems = this.store.problems;
    panel.appendChild(el("div", "pp-head", `${problems.length} problems (P5)`));
    if (!problems.length) {
      panel.appendChild(el("p", "insp-none", "No problems detected."));
      return;
    }

    // Group by type for readability.
    const groups = {
      "unlinked-object": [],
      "ga-no-sender": [],
      "ga-no-listener": [],
    };
    for (const p of problems) (groups[p.type] || (groups[p.type] = [])).push(p);

    const titles = {
      "unlinked-object": "Unlinked com objects",
      "ga-no-sender": "Group addresses with no sender",
      "ga-no-listener": "Group addresses with no listener",
    };

    for (const type of Object.keys(groups)) {
      const items = groups[type];
      if (!items.length) continue;
      panel.appendChild(el("div", "pp-group", `${titles[type] || type} (${items.length})`));
      const list = el("div", "pp-list");
      for (const p of items) {
        const jump = el("button", "pp-item", null);
        jump.type = "button";
        jump.appendChild(el("span", "pp-msg", p.message));
        jump.addEventListener("click", () => {
          panel.hidden = true;
          if (p.type === "unlinked-object") {
            this.store.select("device", p.device);
          } else {
            this._selectGa(p.ga);
          }
        });
        list.appendChild(jump);
      }
      panel.appendChild(list);
    }
  }
}

// --- DPT helpers (module scope) --------------------------------------------

/**
 * Unit hint for DPT 9.x subtypes (temperature, illuminance, wind speed, …).
 * @param {string} dpt
 * @returns {string}
 */
function unitForDpt9(dpt) {
  switch (dpt) {
    case "9.001":
      return "°C";
    case "9.002":
      return "K"; // temperature difference
    case "9.004":
      return "lux";
    case "9.005":
      return "m/s";
    case "9.006":
      return "Pa";
    case "9.007":
      return "%";
    default:
      return "";
  }
}

/**
 * Numeric input range for the plain integer DPT families.
 * @param {number} main
 * @returns {{min?:number, max?:number, step:number}}
 */
function numberRange(main) {
  switch (main) {
    case 6:
      return { min: -128, max: 127, step: 1 };
    case 7:
      return { min: 0, max: 65535, step: 1 };
    case 8:
      return { min: -32768, max: 32767, step: 1 };
    case 12:
      return { min: 0, max: 4294967295, step: 1 };
    case 13:
      return { min: -2147483648, max: 2147483647, step: 1 };
    case 14:
      return { step: 0.1 };
    default:
      return { step: 1 };
  }
}

/** Clamp a value to an integer within [min, max]. */
function clampInt(v, min, max) {
  const n = Math.round(Number(v) || 0);
  return Math.min(max, Math.max(min, n));
}

/**
 * Entry point called by main.js.
 * @param {import('./store.js').Store} store
 * @param {{tree?:Object, container?:HTMLElement}} ctx
 * @returns {Inspector}
 */
export function init(store, ctx) {
  return new Inspector(store, ctx || {});
}
