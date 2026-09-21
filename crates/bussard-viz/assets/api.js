// api.js — thin transport layer over the bussard-viz HTTP endpoints.
//
// No DOM access. Wraps fetch() for the model/state/write endpoints and an
// EventSource for the live traffic stream. All URLs are absolute under the
// server root so the page works regardless of mount path.

/**
 * Fetch the immutable model projection.
 * @returns {Promise<Object>} parsed /api/model payload
 */
export async function fetchModel() {
  const res = await fetch("/api/model", { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`/api/model returned ${res.status}`);
  return res.json();
}

/**
 * Fetch the current bus + GA value snapshot.
 * @returns {Promise<Object>} parsed /api/state payload
 */
export async function fetchState() {
  const res = await fetch("/api/state", { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error(`/api/state returned ${res.status}`);
  return res.json();
}

/**
 * Ask the server to reload the model from disk (POST /api/reload).
 *
 * On success resolves to `{model_version, stats}`. On a broken model the server
 * keeps the old one and returns 422; this rejects with an Error carrying the
 * rich LoadError `.message`, plus `.code` (e.g. "model_invalid") and `.status`.
 *
 * @returns {Promise<{model_version:number, stats:Object}>}
 */
export async function reloadModel() {
  const res = await fetch("/api/reload", {
    method: "POST",
    headers: { Accept: "application/json" },
  });
  if (res.ok) return res.json();
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    // Non-JSON error body; fall through with a generic message.
  }
  const info = (payload && payload.error) || {};
  const err = new Error(info.message || `reload failed (${res.status})`);
  err.code = info.code || null;
  err.status = res.status;
  throw err;
}

/**
 * Send a group write for testing (T1). Resolves to the echoed telegram info
 * on success; rejects with an Error carrying `.code` and `.status` on failure.
 *
 * Sends exactly one of `value` (a DPT-formatted human string, encoded
 * server-side via parse_value) or `payload` (raw hex bytes, sent verbatim).
 * Pass the value positionally for the common case, or `opts.payload` for a raw
 * hex send (in which case `value` must be omitted / null).
 *
 * @param {string} address — group address
 * @param {?string} value — DPT-formatted value string; null when sending raw hex
 * @param {{dpt?:string, force?:boolean, payload?:string}} [opts]
 * @returns {Promise<Object>}
 */
export async function groupWrite(address, value, opts = {}) {
  const body = { address };
  if (opts.payload != null) body.payload = opts.payload;
  else body.value = value;
  if (opts.dpt) body.dpt = opts.dpt;
  if (opts.force) body.force = true;
  const res = await fetch("/api/group-write", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
  if (res.ok) return res.json();
  let payload = null;
  try {
    payload = await res.json();
  } catch {
    // Non-JSON error body; fall through with a generic message.
  }
  const info = (payload && payload.error) || {};
  const err = new Error(info.message || `group-write failed (${res.status})`);
  err.code = info.code || null;
  err.status = res.status;
  throw err;
}

/**
 * Open the live traffic SSE stream.
 *
 * Handles the three server event types (telegram/bus/gap). Native EventSource
 * reconnection is used (the browser resends Last-Event-ID automatically); we
 * additionally dedupe by skipping any telegram whose seq is <= the last one
 * we already delivered, which covers the replay-on-reconnect overlap.
 *
 * @param {(telegram:Object)=>void} onTelegram — called per new telegram row.
 * @param {(status:Object)=>void} onStatus — called on bus state changes.
 * @param {{backlog?:number, onGap?:(info:Object)=>void, onModel?:(info:Object)=>void, onProg?:(devices:Array<string>)=>void}} [opts]
 * @returns {{close:()=>void, source:EventSource}}
 */
export function connectTraffic(onTelegram, onStatus, opts = {}) {
  const backlog = opts.backlog == null ? 50 : opts.backlog;
  const url = `/api/traffic?backlog=${encodeURIComponent(backlog)}`;
  const source = new EventSource(url);
  let lastSeen = -1;

  source.addEventListener("telegram", (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    const seq = typeof msg.seq === "number" ? msg.seq : null;
    // Dedupe replayed telegrams on reconnect.
    if (seq !== null && seq <= lastSeen) return;
    if (seq !== null) lastSeen = seq;
    onTelegram(msg);
  });

  source.addEventListener("bus", (ev) => {
    let msg;
    try {
      msg = JSON.parse(ev.data);
    } catch {
      return;
    }
    onStatus(msg);
  });

  source.addEventListener("model", (ev) => {
    if (opts.onModel) {
      let msg = {};
      try {
        msg = JSON.parse(ev.data);
      } catch {
        // Malformed model event; still signal a reload with an empty payload.
      }
      opts.onModel(msg);
    }
  });

  source.addEventListener("prog", (ev) => {
    if (!opts.onProg) return;
    let msg = {};
    try {
      msg = JSON.parse(ev.data);
    } catch {
      // Malformed prog event; treat as "no devices in programming mode".
    }
    // Contract: { "devices": ["1.1.2", ...] }. Absent/empty => none.
    opts.onProg(Array.isArray(msg.devices) ? msg.devices : []);
  });

  source.addEventListener("gap", (ev) => {
    if (opts.onGap) {
      let msg = {};
      try {
        msg = JSON.parse(ev.data);
      } catch {
        // gap events may be empty; ignore parse failure.
      }
      opts.onGap(msg);
    }
  });

  return {
    source,
    close() {
      source.close();
    },
  };
}
