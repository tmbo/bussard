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

    // Subtitle: floor/room location (device-specific), on the typed header line.
    const loc = [d.floor, d.room].filter(Boolean).join(" · ");
    view.querySelector("[data-field=subtitle]").textContent = loc || "no location";

    // Meta: product + description.
    const meta = view.querySelector("[data-field=meta]");
    if (d.product) {
      const p = [d.product.manufacturer, d.product.order_number].filter(Boolean).join(" ");
      if (p) meta.appendChild(el("span", "insp-chip", p));
    }
    if (d.description) meta.appendChild(el("span", "insp-desc", d.description));

    // Com-object table, grouped by channel (the standalone channels list is
    // gone: the channel is now the grouping key inside the table).
    const coSection = view.querySelector("[data-field=comobjects]");
    const cos = d.com_objects || [];
    // "Communicates" framing parallels the GA view's senders/listeners block.
    coSection.appendChild(el("h3", "insp-h3", `Communicates · com objects (${cos.length})`));
    coSection.appendChild(this._comObjectTable(d, cos));

    this.root.appendChild(view);
  }

  /**
   * Build the com-object table, grouped by channel. Each channel gets a subtle
   * group-header row (channel name, falling back to the channel key); com objects
   * without a channel fall under a trailing "General" group. Send/listen cells
   * show the GA chip plus a secondary line of the resolved remote devices.
   * @param {Object} d - device record.
   * @param {Array<Object>} cos - com objects.
   * @returns {HTMLElement}
   */
  _comObjectTable(d, cos) {
    const table = el("table", "insp-table co-table");
    const thead = el("thead");
    const hr = el("tr");
    for (const h of ["#", "Name", "DPT", "Flags", "Send", "Listen"]) {
      hr.appendChild(el("th", null, h));
    }
    thead.appendChild(hr);
    table.appendChild(thead);

    // Map channel key -> display name for group headers.
    const channelName = new Map();
    for (const c of d.channels || []) channelName.set(c.key, c.name || c.key);

    // Bucket com objects by channel key, preserving order. Objects with no
    // channel go into a trailing "General" bucket (key = "").
    const order = [];
    const buckets = new Map();
    for (const co of cos) {
      const key = co.channel || "";
      if (!buckets.has(key)) {
        buckets.set(key, []);
        order.push(key);
      }
      buckets.get(key).push(co);
    }
    // Ensure the "General" (no-channel) group renders last.
    order.sort((a, b) => (a === "" ? 1 : 0) - (b === "" ? 1 : 0));

    const tbody = el("tbody");
    const COL_COUNT = 6;
    for (const key of order) {
      const label = key === "" ? "General" : channelName.get(key) || key;
      const hRow = el("tr", "co-group");
      const hCell = el("td", null, label);
      hCell.colSpan = COL_COUNT;
      hRow.appendChild(hCell);
      tbody.appendChild(hRow);

      for (const co of buckets.get(key)) this._appendComObjectRow(tbody, d, co);
    }
    table.appendChild(tbody);
    return table;
  }

  /**
   * Append one com-object row to a tbody. Send/listen cells carry the GA chip
   * plus a secondary line naming the remote devices on that GA (the send GA's
   * listeners, or the listen GA's senders), excluding this device itself.
   * @param {HTMLElement} tbody
   * @param {Object} d - the owning device.
   * @param {Object} co - the com object.
   */
  _appendComObjectRow(tbody, d, co) {
    const tr = el("tr");
    const noLink = !co.send && !(co.listen && co.listen.length);
    if (noLink) tr.classList.add("unlinked");
    tr.appendChild(el("td", "mono", String(co.number)));
    tr.appendChild(el("td", null, co.name || "—"));
    tr.appendChild(el("td", "mono dim", co.dpt || "—"));
    tr.appendChild(el("td", "mono dim", co.flags || "—"));

    // Send GA: chip + the GA's listeners (the devices this send reaches).
    const sendTd = el("td", "link-cell");
    if (co.send) {
      sendTd.appendChild(this._gaLinkCell(co.send, "listeners", d.address, "→"));
    } else {
      sendTd.textContent = "—";
    }
    tr.appendChild(sendTd);

    // Listen GA(s): chip + each GA's senders (the devices that drive this listen).
    const listenTd = el("td", "link-cell");
    const listen = co.listen || [];
    if (listen.length) {
      for (const ga of listen) {
        listenTd.appendChild(this._gaLinkCell(ga, "senders", d.address, "←"));
      }
    } else {
      listenTd.textContent = "—";
    }
    tr.appendChild(listenTd);

    tbody.appendChild(tr);
  }

  /**
   * A GA chip plus a secondary line naming the remote devices on that GA. `side`
   * selects which endpoints to resolve: "listeners" for a send GA, "senders" for
   * a listen GA. The owning device is excluded. The inline list is capped at
   * ~3 devices with a clickable "+N more" that expands the rest.
   * @param {string} ga
   * @param {"listeners"|"senders"} side
   * @param {string} selfAddr - the owning device address (excluded from the list).
   * @param {string} arrow - direction glyph shown before the remote devices.
   * @returns {HTMLElement}
   */
  _gaLinkCell(ga, side, selfAddr, arrow) {
    const CAP = 3;
    const wrap = el("div", "ga-link");
    wrap.appendChild(this._gaChip(ga));

    const refs = (side === "listeners" ? this.store.gaListeners : this.store.gaSenders).get(ga) || [];
    // Deduplicate by device address and drop the owning device.
    const seen = new Set();
    const devices = [];
    for (const r of refs) {
      if (!r || !r.device || r.device === selfAddr || seen.has(r.device)) continue;
      seen.add(r.device);
      devices.push(r);
    }
    if (!devices.length) return wrap;

    const line = el("div", "ga-remotes");
    line.appendChild(el("span", "ga-arrow", arrow));
    const shown = devices.slice(0, CAP);
    for (const r of shown) line.appendChild(this._remoteDeviceChip(r));
    if (devices.length > CAP) {
      const more = el("button", "more-btn", `+${devices.length - CAP} more`);
      more.type = "button";
      more.addEventListener("click", () => {
        more.remove();
        for (const r of devices.slice(CAP)) line.appendChild(this._remoteDeviceChip(r));
      });
      line.appendChild(more);
    }
    wrap.appendChild(line);
    return wrap;
  }

  /**
   * A compact clickable device name (selects the device on click). Shows the
   * device name with its address, e.g. "Schaltaktor UV (1.1.7)".
   * @param {{device:string, device_name?:string}} ref
   * @returns {HTMLElement}
   */
  _remoteDeviceChip(ref) {
    const d = this.store.deviceByAddr.get(ref.device);
    const name = ref.device_name || (d && d.name) || ref.device;
    const btn = el("button", "remote-dev", `${name} (${ref.device})`);
    btn.type = "button";
    btn.title = `${name} (${ref.device})`;
    btn.addEventListener("click", () => this.store.select("device", ref.device));
    return btn;
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

    // Subtitle: range path (GA-specific), on the typed header line.
    const rangePath = [g.range && g.range.main, g.range && g.range.middle]
      .filter(Boolean)
      .join(" › ");
    view.querySelector("[data-field=subtitle]").textContent = rangePath || "no range";

    // Meta: protected marker, live value + updated-at.
    const meta = view.querySelector("[data-field=meta]");
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
   * payload fallback (free-form hex bytes + optional DPT override) that posts
   * `payload` to the extended group-write endpoint, so exotic DPTs without a
   * string grammar can still be sent verbatim.
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
    // A raw-payload send() closure: bytes go verbatim as hex via the extended
    // endpoint. `label` is what to show in the optimistic status line.
    const sendRaw = (payloadHex, dptOverride, label) => {
      if (g.protected && !armed.value) return;
      this._send(
        g,
        label,
        { dpt: dptOverride, force: g.protected && armed.value, payload: payloadHex },
        status,
      );
    };

    const controls = el("div", "send-controls");
    this._populateControls(controls, g, send, sendRaw);
    wrap.appendChild(controls);

    // Raw payload fallback (free-form hex bytes + optional DPT override).
    wrap.appendChild(this._rawFallback(g, sendRaw));

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
   * Value strings accepted by `parse_value` use the `send` path; DPTs the
   * encoder cannot parse from a string (1.017 trigger, 3.007 dimming, 10/11/19)
   * use `sendRaw` to post raw payload bytes, or fall back to the raw field.
   * @param {HTMLElement} controls
   * @param {Object} g
   * @param {(value:string, dptOverride?:string)=>void} send
   * @param {(payloadHex:string, dptOverride?:string, label?:string)=>void} sendRaw
   */
  _populateControls(controls, g, send, sendRaw) {
    const dpt = g.dpt || "";
    const [mainStr, subStr] = dpt.split(".");
    const main = parseInt(mainStr, 10);
    const sub = subStr || "";

    // DPT 1.x - booleans with subtype-specific labels.
    if (main === 1) {
      this._boolControls(controls, dpt, sub, send, sendRaw);
      return;
    }
    // DPT 3.007 - dimming control (brighter/darker + step). parse_value cannot
    // encode DPT 3 from a string, so expose quick raw-payload presets: the
    // 4-bit control code goes as a single byte via the raw endpoint.
    if (main === 3) {
      this._dimStepControls(controls, dpt || "3.007", sendRaw);
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
    // DPT 10/11/19 (time/date/datetime) and anything else: raw payload only.
    const hint = el("p", "widget-hint", dpt
      ? `No structured widget for DPT ${dpt}; use the raw payload field below.`
      : "This GA has no DPT; send raw payload bytes (optionally set a dpt) below.");
    controls.appendChild(hint);
  }

  _boolControls(controls, dpt, sub, send, sendRaw) {
    // Subtype label pairs that parse_value accepts (codec.rs bool parsing).
    // [falseLabel, falseValue, trueLabel, trueValue]
    const pairs = {
      "003": ["Disable", "disable", "Enable", "enable"],
      "008": ["Up", "up", "Down", "down"],
      "009": ["Open", "open", "Close", "close"],
      "010": ["Stop", "stop", "Start", "start"],
    };
    // 1.017 trigger has no parse_value grammar. Send a proper 1-bit raw payload
    // tagged as 1.017 (byte 0x01, packed identically to a 1.001 "on" on the
    // wire) instead of masquerading as 1.001.
    if (dpt === "1.017") {
      const trig = el("button", "send-btn primary", "Trigger");
      trig.type = "button";
      trig.addEventListener("click", () => sendRaw("01", "1.017", "trigger"));
      controls.appendChild(trig);
      controls.appendChild(el("span", "widget-hint", "1-bit trigger (raw 0x01, DPT 1.017)"));
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

  /**
   * DPT 3.007 dimming-control presets. The 4-bit value is direction (bit 3:
   * 1 = brighter, 0 = darker) plus a 3-bit step code (0 = break/stop). Each
   * preset sends the single byte as a raw payload tagged with the DPT.
   * @param {HTMLElement} controls
   * @param {string} dpt
   * @param {(payloadHex:string, dptOverride?:string, label?:string)=>void} sendRaw
   */
  _dimStepControls(controls, dpt, sendRaw) {
    const row = el("div", "slider-row");
    // step 1 = full step; 0x09 = brighter/step-1, 0x01 = darker/step-1.
    const presets = [
      ["Brighter", 0x09],
      ["Darker", 0x01],
      ["Break", 0x00],
    ];
    for (const [label, byte] of presets) {
      const hex = byte.toString(16).padStart(2, "0");
      row.appendChild(this._sendButton(label, () => sendRaw(hex, dpt, `${label} (0x${hex})`), label === "Brighter" ? "primary" : ""));
    }
    controls.appendChild(row);
    controls.appendChild(el("span", "widget-hint", "4-bit dimming control (raw byte, DPT 3.007)"));
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

  _rawFallback(g, sendRaw) {
    const details = el("details", "raw-fallback");
    const summary = el("summary", null, "Raw payload");
    details.appendChild(summary);
    const row = el("div", "slider-row");
    const val = el("input");
    val.type = "text";
    val.className = "raw-input mono";
    val.placeholder = "hex bytes (e.g. 0b64)";
    const dptIn = el("input");
    dptIn.type = "text";
    dptIn.className = "raw-dpt mono";
    dptIn.placeholder = "dpt (optional)";
    dptIn.size = 10;
    const btn = this._sendButton("Send raw", () => {
      const hex = val.value.trim().replace(/\s+/g, "");
      if (!hex) return;
      sendRaw(hex, dptIn.value.trim() || undefined, `raw ${hex}`);
    }, "");
    val.addEventListener("keydown", (ev) => { if (ev.key === "Enter") btn.click(); });
    row.append(val, dptIn, btn);
    details.appendChild(row);
    details.appendChild(el("p", "widget-hint", "Raw payload bytes sent verbatim. Validated against the DPT size when one is known; with no DPT, sent unpacked as a full octet."));
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
    } else {
      // Group by type for readability. Only one-sided linked GAs are problems:
      // unlinked com objects and fully-unlinked GAs are normal in KNX.
      const groups = {
        "ga-no-listener": [],
        "ga-no-sender": [],
      };
      for (const p of problems) (groups[p.type] || (groups[p.type] = [])).push(p);

      const titles = {
        "ga-no-listener": "Group addresses with senders but no listener",
        "ga-no-sender": "Group addresses with listeners but no sender",
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
            this._selectGa(p.ga);
          });
          list.appendChild(jump);
        }
        panel.appendChild(list);
      }
    }

    // Neutral info footer: unused com objects / group addresses are normal, so
    // they are shown as plain counts with no warning styling and no per-item list.
    const info = this.store.info || { unusedComObjects: 0, unusedGroupAddresses: 0 };
    if (info.unusedComObjects || info.unusedGroupAddresses) {
      const footer = el("div", "pp-info");
      footer.appendChild(
        el(
          "span",
          null,
          `${info.unusedComObjects} unused com objects · ${info.unusedGroupAddresses} unused group addresses`,
        ),
      );
      panel.appendChild(footer);
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
