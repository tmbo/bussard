// UI of the certificate enrolment page: reads the link, derives the session
// key, scans or takes typed certificates, sends them to the relay encrypted,
// and shows bussard's result per label. Protocol: dev/enroll-protocol.md.

import {
  EnrollError,
  certificateMessage,
  checkCertificate,
  deriveSessionKey,
  doneMessage,
  extractFromQr,
  fingerprint,
  formatCertificate,
  generatePhoneKey,
  open,
  parseDown,
  parseLink,
  relayUrl,
  seal,
  toHex,
  utf8,
} from "./enroll.js";

const $ = (id) => document.getElementById(id);

const POLL_WAIT_S = 25;
const FETCH_TIMEOUT_MS = (POLL_WAIT_S + 10) * 1000;
const SCAN_INTERVAL_MS = 180;
const SCAN_MAX_EDGE = 720;

const STATUS_TEXT = {
  queued: "Waiting to send",
  sending: "Sending",
  sent: "Sent, waiting for bussard",
  stored: "Stored",
  unassigned: "Stored, no device in the model has this serial yet",
  already_stored: "Already stored",
  conflict: "Conflict: bussard holds a different key for this serial; nothing written",
  invalid: "bussard rejected the text",
  error: "Error",
  rejected: "Not sent",
};
const GOOD = new Set(["stored", "unassigned", "already_stored"]);
const BAD = new Set(["conflict", "invalid", "error", "rejected"]);

/** Session state for this page load. */
const state = {
  link: null,
  subtle: null,
  key: null,
  phone: null,
  nextId: 1,
  items: new Map(), // id -> item
  sentDigests: new Set(), // SHA-256 of each normalized text already sent
  sendQueue: [],
  sending: false,
  downAfter: 0,
  phase: "active", // active | finished | closed
  relayDown: false,
};

// -------------------------------------------------------------------- boot

async function main() {
  const subtle = globalThis.crypto?.subtle;
  if (!window.isSecureContext || !subtle) {
    return fatal("Open this page over https", "The browser offers its crypto functions only to secure pages.");
  }
  let link;
  try {
    link = parseLink(location.hash, location.origin);
  } catch (e) {
    return linkProblem(e);
  }
  // The fragment stays in the address bar on purpose: a reload must find the
  // session again. It holds only bussard's public key.
  let phone;
  try {
    phone = await generatePhoneKey(subtle);
  } catch {
    return fatal(
      "This browser is too old",
      "The page needs X25519 in the browser's WebCrypto, which current Safari, Chrome and Firefox have. Update the browser or use another one.",
    );
  }
  let key;
  try {
    key = await deriveSessionKey(subtle, phone.privateKey, phone.publicRaw, link);
  } catch (e) {
    return linkProblem(e);
  }
  Object.assign(state, { link, subtle, key, phone });

  $("fingerprint").textContent = (await fingerprint(subtle, link.bussardPublic)).replace("-", "‑");
  $("session").hidden = false;
  $("fatal").hidden = true;

  wireEntry();
  $("done").addEventListener("click", finish);
  window.addEventListener("hashchange", () => location.reload());

  startCamera();
  pollDown();
}

function fatal(title, text) {
  $("fatal-title").textContent = title;
  $("fatal-text").textContent = text;
  $("fatal").hidden = false;
  $("session").hidden = true;
  stopCamera();
}

function linkProblem(e) {
  const code = e instanceof EnrollError ? e.code : "";
  if (code === "link_missing") {
    return fatal(
      "Open the link from bussard",
      "This page needs the link that `bussard keys enroll` prints (or scan its QR code). The link carries the session; without it there is nothing to send to.",
    );
  }
  if (code === "link_version") {
    return fatal("This link needs a newer page", `${e.message}. Update bussard or reload this page.`);
  }
  return fatal(
    "The link is damaged",
    `${e?.message ?? e}. Copy the whole link again from bussard, or scan its QR code.`,
  );
}

// ------------------------------------------------------------------ banner

function banner(kind, text) {
  const el = $("banner");
  if (!text) {
    el.hidden = true;
    return;
  }
  el.className = `banner ${kind}`;
  el.textContent = text;
  el.hidden = false;
}

function setRelayDown(down) {
  if (state.phase === "closed") return;
  if (down === state.relayDown) return;
  state.relayDown = down;
  if (down) {
    banner("warn", "Cannot reach the relay. Check the phone's connection; the page keeps trying and sends what is waiting.");
  } else {
    banner(null, "");
  }
}

function closed(text) {
  if (state.phase === "closed") return;
  state.phase = "closed";
  state.relayDown = false;
  banner("info", text);
  stopCamera();
  $("capture").hidden = true;
  $("done").hidden = true;
  for (const item of state.items.values()) {
    if (item.status === "queued" || item.status === "sending") {
      item.status = "rejected";
      item.message = "The session ended before it was sent.";
      renderItem(item);
    }
  }
  state.sendQueue.length = 0;
}

// ------------------------------------------------------------------- entry

function wireEntry() {
  const input = $("typed");
  const sendBtn = $("send");
  const update = () => {
    const r = checkCertificate(input.value);
    renderTyped(r);
    // A label whose check fails is a typo: bussard rejects it, so it is not sent.
    sendBtn.disabled = r.status !== "ok" || state.phase !== "active";
    return r;
  };
  input.addEventListener("input", update);
  const submit = async () => {
    const r = update();
    if (r.status !== "ok") return;
    // Cleared after sending and on a duplicate alike: a certificate is
    // never shown again once it has left the field.
    const outcome = await submitCertificate(r, "typed");
    if (outcome === "queued" || outcome === "duplicate") {
      input.value = "";
      update();
    }
  };
  sendBtn.addEventListener("click", submit);
  input.addEventListener("keydown", (ev) => {
    if (ev.key === "Enter") {
      ev.preventDefault();
      submit();
    }
  });
}

function renderTyped(r) {
  const preview = $("typed-preview");
  const status = $("typed-status");
  status.className = "typed-status";
  preview.textContent = r.normalized ? formatCertificate(r.normalized) : "";
  switch (r.status) {
    case "empty":
      status.textContent = "Dashes and spaces are optional.";
      break;
    case "incomplete":
      status.textContent = `${r.normalized.length} of 36 characters`;
      break;
    case "malformed":
      status.classList.add("bad");
      status.textContent =
        r.char !== undefined
          ? `"${r.char}" is not on a certificate (letters A-Z and digits 2-7 only)`
          : `${r.normalized.length} characters: a certificate has 36`;
      break;
    case "bad_check":
      status.classList.add("bad");
      status.textContent = `Serial ${r.serial}. The check character does not match: a typo. Compare with the sticker.`;
      break;
    case "ok":
      status.classList.add("good");
      status.textContent = `Serial ${r.serial}. Check OK.`;
      break;
  }
}

// --------------------------------------------------------------- sending

async function digest(text) {
  return toHex(new Uint8Array(await state.subtle.digest("SHA-256", utf8(text))));
}

/**
 * Queue one checked certificate. Returns `queued`, or `duplicate` when the
 * same text was sent already on this page (it is not sent twice).
 */
async function submitCertificate(r, source) {
  if (state.phase !== "active") return "inactive";
  const d = await digest(r.normalized);
  if (state.sentDigests.has(d)) {
    const existing = [...state.items.values()].find((i) => i.digest === d);
    toast(`Already sent: serial ${r.serial}`);
    if (existing) flash(existing);
    return "duplicate";
  }
  state.sentDigests.add(d);
  const item = {
    id: state.nextId++,
    digest: d,
    serial: r.serial,
    source,
    status: "queued",
    plaintext: null,
  };
  item.plaintext = certificateMessage(item.id, r.normalized);
  state.items.set(item.id, item);
  renderItem(item);
  if (source === "scan") {
    toast(`Scanned serial ${r.serial}`);
    navigator.vibrate?.(60);
  }
  state.sendQueue.push(item);
  pumpSend();
  return "queued";
}

async function pumpSend() {
  if (state.sending) return;
  state.sending = true;
  try {
    let backoff = 1000;
    while (state.sendQueue.length > 0 && state.phase !== "closed") {
      const item = state.sendQueue[0];
      if (!item.control && item.status === "queued") {
        item.status = "sending";
        renderItem(item);
      }
      const outcome = await postUp(item.plaintext);
      if (outcome.ok) {
        setRelayDown(false);
        backoff = 1000;
        state.sendQueue.shift();
        if (item.control) {
          banner("info", "Sent. Waiting for bussard to close the session.");
        } else {
          // The certificate no longer needs to be in memory once sent.
          item.plaintext = null;
          if (item.status === "sending") item.status = "sent";
          renderItem(item);
        }
        continue;
      }
      if (outcome.gone) {
        closed("The session has ended or expired. Start a new one in bussard to add more certificates.");
        break;
      }
      if (outcome.fatal) {
        state.sendQueue.shift();
        if (item.control) continue;
        item.plaintext = null;
        item.status = "rejected";
        item.message = outcome.message;
        renderItem(item);
        continue;
      }
      setRelayDown(true);
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 15000);
    }
  } finally {
    state.sending = false;
  }
}

async function postUp(plaintext) {
  let envelope;
  try {
    envelope = await seal(state.subtle, state.key, {
      dir: "up",
      sidText: state.link.sidText,
      phonePublicText: state.phone.publicText,
      plaintext,
    });
  } catch (e) {
    return { fatal: true, message: String(e?.message ?? e) };
  }
  let res;
  try {
    res = await fetchWithTimeout(relayUrl(state.link.relay, state.link.sidText, "up"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(envelope),
    });
  } catch {
    return { retry: true };
  }
  if (res.status === 202 || res.ok) return { ok: true };
  if (res.status === 404) return { gone: true };
  if (res.status === 429) return { fatal: true, message: "The relay's limit for this session is reached." };
  if (res.status === 413 || res.status === 400) {
    return { fatal: true, message: `The relay refused the message (${res.status}).` };
  }
  return { retry: true };
}

// --------------------------------------------------------------- receiving

async function pollDown() {
  let backoff = 1000;
  while (state.phase !== "closed") {
    let res;
    try {
      res = await fetchWithTimeout(
        relayUrl(state.link.relay, state.link.sidText, "down", { after: state.downAfter, wait: POLL_WAIT_S }),
        { method: "GET" },
      );
    } catch {
      setRelayDown(true);
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 15000);
      continue;
    }
    if (res.status === 404) {
      closed(
        state.phase === "finished"
          ? closedText()
          : state.items.size === 0
          ? "This session does not exist or has expired. Start a new one in bussard and open its link."
          : "The session has ended or expired.",
      );
      return;
    }
    if (!res.ok) {
      setRelayDown(true);
      await sleep(backoff);
      backoff = Math.min(backoff * 2, 15000);
      continue;
    }
    let body;
    try {
      body = await res.json();
    } catch {
      body = null;
    }
    setRelayDown(false);
    backoff = 1000;
    if (!body || !Array.isArray(body.messages)) {
      await sleep(1000);
      continue;
    }
    for (const m of body.messages) {
      if (Number.isInteger(m?.seq) && m.seq > state.downAfter) state.downAfter = m.seq;
      await handleDown(m?.body);
    }
    if (body.closed === true) {
      closed(closedText());
      return;
    }
  }
}

async function handleDown(envelope) {
  // Several phones may share a session; only messages for this key count.
  if (!envelope || envelope.pk !== state.phone.publicText) return;
  let plaintext;
  try {
    plaintext = await open(state.subtle, state.key, {
      dir: "down",
      sidText: state.link.sidText,
      envelope,
    });
  } catch {
    return; // not for us, or forged: ignore
  }
  const msg = parseDown(plaintext);
  if (!msg) return;
  if (msg.type === "closed") {
    closed(closedText(msg.stored));
    return;
  }
  const item = state.items.get(msg.id);
  if (!item) return;
  item.status = msg.status;
  if (msg.serial) item.serial = msg.serial;
  item.ia = msg.ia;
  item.name = msg.name;
  item.message = msg.message;
  renderItem(item);
}

function closedText(stored) {
  const n = typeof stored === "number" ? stored : countGood();
  const what = n === 1 ? "1 certificate" : `${n} certificates`;
  return state.phase === "finished"
    ? `Finished. bussard stored ${what} from this session. You can close this page.`
    : `bussard ended the session; it stored ${what}. You can close this page.`;
}

function countGood() {
  return [...state.items.values()].filter((i) => GOOD.has(i.status)).length;
}

async function finish() {
  if (state.phase !== "active") return;
  state.phase = "finished";
  stopCamera();
  $("capture").hidden = true;
  $("done").disabled = true;
  banner("info", "Finishing: sending what is left, then telling bussard you are done.");
  state.sendQueue.push({ control: true, plaintext: doneMessage() });
  pumpSend();
}

// ----------------------------------------------------------------- list

function renderItem(item) {
  let li = document.getElementById(`item-${item.id}`);
  if (!li) {
    li = document.createElement("li");
    li.id = `item-${item.id}`;
    li.innerHTML =
      '<div class="row"><span class="serial"></span><span class="pill"></span></div>' +
      '<div class="masked"></div><div class="detail"></div>';
    $("labels").prepend(li);
  }
  const pill = li.querySelector(".pill");
  li.className = `label ${GOOD.has(item.status) ? "good" : BAD.has(item.status) ? "bad" : "pending"}`;
  li.querySelector(".serial").textContent = `Serial ${item.serial}`;
  // The certificate itself is never shown again: serial only, key masked.
  li.querySelector(".masked").textContent = "Key •••••••• (hidden)";
  pill.textContent = shortStatus(item.status);
  const parts = [];
  const long = STATUS_TEXT[item.status];
  if (item.status === "stored" && (item.ia || item.name)) {
    parts.push(`Stored for ${[item.ia, item.name].filter(Boolean).join(" ")}`);
  } else if (long && long !== pill.textContent) {
    parts.push(long);
  }
  if (item.message) parts.push(item.message);
  li.querySelector(".detail").textContent = parts.join(". ");
  const n = state.items.size;
  $("count").textContent = n ? `(${n})` : "";
  $("labels-empty").hidden = n > 0;
}

function shortStatus(status) {
  return (
    {
      queued: "waiting",
      sending: "sending",
      sent: "sent",
      stored: "stored",
      unassigned: "saved",
      already_stored: "known",
      conflict: "conflict",
      invalid: "invalid",
      error: "error",
      rejected: "not sent",
    }[status] ?? status
  );
}

function flash(item) {
  const li = document.getElementById(`item-${item.id}`);
  if (!li) return;
  li.classList.remove("flash");
  void li.offsetWidth; // restart the animation
  li.classList.add("flash");
  li.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

let toastTimer = 0;
function toast(text) {
  const el = $("scan-toast");
  el.textContent = text;
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, 2200);
}

// ---------------------------------------------------------------- camera

const camera = { stream: null, detector: null, jsqr: null, timer: 0, canvas: null, busy: false, lastMiss: 0 };

async function startCamera() {
  const msg = $("camera-msg");
  const btn = $("camera-start");
  btn.hidden = true;
  msg.hidden = true;
  if (!navigator.mediaDevices?.getUserMedia) {
    cameraMessage("This browser gives the page no camera. Type the certificates below.");
    return;
  }
  try {
    camera.stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
    });
  } catch (e) {
    const denied = e?.name === "NotAllowedError" || e?.name === "SecurityError";
    cameraMessage(
      denied
        ? "Camera access was refused. Allow it in the browser settings, or type the certificates below."
        : "No camera available. Type the certificates below.",
    );
    btn.hidden = false;
    btn.onclick = startCamera;
    return;
  }
  if (state.phase !== "active") {
    stopCamera();
    return;
  }
  const video = $("video");
  video.srcObject = camera.stream;
  try {
    await video.play();
  } catch {
    // iOS may need a tap before playback starts.
    btn.hidden = false;
    btn.onclick = () => {
      btn.hidden = true;
      video.play();
    };
  }
  await setupDecoder();
  scheduleScan();
}

function cameraMessage(text) {
  const msg = $("camera-msg");
  msg.textContent = text;
  msg.hidden = false;
}

async function setupDecoder() {
  if ("BarcodeDetector" in window) {
    try {
      const formats = await window.BarcodeDetector.getSupportedFormats();
      if (formats.includes("qr_code")) {
        camera.detector = new window.BarcodeDetector({ formats: ["qr_code"] });
        return;
      }
    } catch {
      // fall through to jsQR
    }
  }
  camera.jsqr = await loadJsQr();
  if (!camera.jsqr) cameraMessage("The QR decoder did not load. Type the certificates below.");
}

function loadJsQr() {
  if (window.jsQR) return Promise.resolve(window.jsQR);
  return new Promise((resolve) => {
    const s = document.createElement("script");
    s.src = "vendor/jsQR.js";
    s.onload = () => resolve(window.jsQR ?? null);
    s.onerror = () => resolve(null);
    document.head.appendChild(s);
  });
}

function scheduleScan() {
  clearTimeout(camera.timer);
  if (!camera.stream || state.phase !== "active") return;
  camera.timer = setTimeout(scanOnce, SCAN_INTERVAL_MS);
}

async function scanOnce() {
  const video = $("video");
  try {
    if (document.hidden || video.readyState < 2 || camera.busy) return;
    camera.busy = true;
    const payloads = await decodeFrame(video);
    for (const p of payloads) await onQr(p);
  } catch {
    // a frame that fails to decode is not an error
  } finally {
    camera.busy = false;
    scheduleScan();
  }
}

async function decodeFrame(video) {
  if (camera.detector) {
    const codes = await camera.detector.detect(video);
    return codes.map((c) => c.rawValue).filter(Boolean);
  }
  if (!camera.jsqr) return [];
  const w = video.videoWidth;
  const h = video.videoHeight;
  if (!w || !h) return [];
  const scale = Math.min(1, SCAN_MAX_EDGE / Math.max(w, h));
  const cw = Math.round(w * scale);
  const ch = Math.round(h * scale);
  camera.canvas ??= document.createElement("canvas");
  const canvas = camera.canvas;
  if (canvas.width !== cw) canvas.width = cw;
  if (canvas.height !== ch) canvas.height = ch;
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  ctx.drawImage(video, 0, 0, cw, ch);
  const img = ctx.getImageData(0, 0, cw, ch);
  const code = camera.jsqr(img.data, cw, ch, { inversionAttempts: "attemptBoth" });
  return code?.data ? [code.data] : [];
}

async function onQr(payload) {
  const text = extractFromQr(payload);
  if (!text) {
    const now = Date.now();
    if (now - camera.lastMiss > 3000) {
      camera.lastMiss = now;
      toast("This QR code holds no certificate.");
    }
    return;
  }
  const r = checkCertificate(text);
  if (r.status === "bad_check") {
    const now = Date.now();
    if (now - camera.lastMiss > 3000) {
      camera.lastMiss = now;
      toast(`Serial ${r.serial}: the code's check character does not match. Type the label instead.`);
    }
    return;
  }
  if (r.status !== "ok") return;
  await submitCertificate(r, "scan");
}

function stopCamera() {
  clearTimeout(camera.timer);
  if (camera.stream) {
    for (const t of camera.stream.getTracks()) t.stop();
    camera.stream = null;
  }
  const video = document.getElementById("video");
  if (video) video.srcObject = null;
}

// ------------------------------------------------------------------ util

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function fetchWithTimeout(url, init) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      mode: "cors",
    });
  } finally {
    clearTimeout(t);
  }
}

// Started last: everything above, the camera state included, is initialized.
main().catch((e) => fatal("Something went wrong", String(e?.message ?? e)));
