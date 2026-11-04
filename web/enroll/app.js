// UI of the certificate enrolment page: reads the link, derives the session
// key, asks once to confirm the session code, scans or takes typed
// certificates, sends them to the relay encrypted, and shows bussard's
// result per certificate. Protocol: dev/enroll-protocol.md. Wording and counting:
// ui.js.

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
import {
  PREF_KEYS,
  ScanGate,
  bottomInset,
  endCounts,
  forgetLinkFragment,
  readPref,
  sessionCheck,
  shortCode,
  shortStatus,
  statusDetail,
  statusTone,
  summaryText,
  takeLinkFragment,
  writePref,
} from "./ui.js";

const $ = (id) => document.getElementById(id);

const POLL_WAIT_S = 25;
const FETCH_TIMEOUT_MS = (POLL_WAIT_S + 10) * 1000;
const SCAN_INTERVAL_MS = 180;
const SCAN_MAX_EDGE = 720;
const FLASH_MS = 1100;

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
  phase: "confirm", // confirm | active | finished | closed
  relayDown: false,
  mode: "scan", // scan | type
};

/** localStorage, or null where the browser refuses it. */
function prefStore() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

/** sessionStorage (this tab only), or null where the browser refuses it. */
function tabStore() {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

// -------------------------------------------------------------------- boot

async function main() {
  const subtle = globalThis.crypto?.subtle;
  if (!window.isSecureContext || !subtle) {
    return fatal("Open this page over https", "The browser offers its crypto functions only to secure pages.");
  }
  // A new link opened in this tab (only the fragment changes) starts over.
  window.addEventListener("hashchange", () => location.reload());
  // The link leaves the address bar at once, so the history and a synced
  // browser never hold it; sessionStorage keeps it for a reload in this tab.
  const fragment = takeLinkFragment(location.hash, tabStore());
  if (location.hash) {
    try {
      history.replaceState(null, "", location.pathname + location.search);
    } catch {
      // the link stays visible; the page works the same
    }
  }
  let link;
  try {
    link = parseLink(fragment, location.origin);
  } catch (e) {
    forgetLinkFragment(tabStore());
    return linkProblem(e);
  }
  // Before the session code and the camera: does the session exist?
  if (!(await checkSession(link))) return;
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
    forgetLinkFragment(tabStore());
    return linkProblem(e);
  }
  Object.assign(state, { link, subtle, key, phone });

  const code = (await fingerprint(subtle, link.bussardPublic)).replace("-", "‑");
  $("fingerprint").textContent = code;
  $("code-chip-text").textContent = code;
  $("code-dialog-code").textContent = code;
  $("fatal").hidden = true;
  $("confirm").hidden = false;

  $("code-ok").addEventListener("click", confirmCode);
  $("code-bad").addEventListener("click", () => {
    state.phase = "closed";
    fatal(
      "The codes differ",
      "This page is not talking to your bussard, so nothing was sent. Close this page, stop the session in bussard and start a new one.",
      "error",
    );
  });
}

/** The session code matched: start the session proper. */
function confirmCode() {
  if (state.phase !== "confirm") return;
  state.phase = "active";
  unlockAudio(); // inside the tap, which iOS requires for sound
  $("confirm").hidden = true;
  $("session").hidden = false;
  $("bar").hidden = false;
  $("code-chip").hidden = false;
  $("top").classList.add("running");
  wireChrome();
  wireEntry();
  updateSummary();
  setMode(readPref(prefStore(), PREF_KEYS.mode, ["scan", "type"], "scan"), false);
  pollDown();
}

/**
 * Ask the relay once whether the session exists (`GET down` answers 404 for
 * an unknown or expired one). Shows the error state and returns false when
 * the page cannot go on.
 */
async function checkSession(link) {
  let res;
  let body = null;
  try {
    res = await fetchWithTimeout(relayUrl(link.relay, link.sidText, "down", { after: 0, wait: 0 }), {
      method: "GET",
    });
    try {
      body = await res.json();
    } catch {
      body = null;
    }
  } catch {
    res = null;
  }
  const verdict = res ? sessionCheck(res.status, body) : "unreachable";
  if (verdict === "open") return true;
  if (verdict === "gone") {
    forgetLinkFragment(tabStore());
    fatal(
      "This session does not exist or has expired",
      "Start a new session in bussard (bussard keys enroll) and open its link.",
      "error",
    );
  } else if (verdict === "ended") {
    forgetLinkFragment(tabStore());
    fatal(
      "This session has ended",
      "bussard closed it already. Start a new session in bussard to add more certificates.",
      "error",
    );
  } else {
    fatal(
      "Cannot reach the server",
      "The page could not check the session. Check the phone's connection and reload this page.",
      "error",
    );
  }
  return false;
}

function fatal(title, text, tone = "") {
  $("fatal-title").textContent = title;
  $("fatal-text").textContent = text;
  $("fatal").className = tone ? `panel fatal ${tone}` : "panel fatal";
  $("fatal").hidden = false;
  $("confirm").hidden = true;
  $("session").hidden = true;
  $("bar").hidden = true;
  $("code-chip").hidden = true;
  $("sound").hidden = true;
  stopCamera();
}

function linkProblem(e) {
  const code = e instanceof EnrollError ? e.code : "";
  if (code === "link_missing") {
    return fatal(
      "Open the link from bussard",
      "This page needs the link that `bussard keys enroll` prints (or scan its QR code). The link carries the session; without it there is nothing to send to.",
      "error",
    );
  }
  if (code === "link_version") {
    return fatal("This link needs a newer page", `${e.message}. Update bussard or reload this page.`, "error");
  }
  return fatal(
    "The link is damaged",
    `${e?.message ?? e}. Copy the whole link again from bussard, or scan its QR code.`,
    "error",
  );
}

// ------------------------------------------------------------------ chrome

/** Header tools, tabs, the finish bar and the keyboard inset. */
function wireChrome() {
  const dialog = $("code-dialog");
  $("code-chip").addEventListener("click", () => {
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  });
  $("code-dialog-close").addEventListener("click", () => {
    if (typeof dialog.close === "function") dialog.close();
    else dialog.removeAttribute("open");
  });

  sound.on = readPref(prefStore(), PREF_KEYS.sound, ["on", "off"], "on") === "on";
  renderSound();
  $("sound").hidden = false;
  $("sound").addEventListener("click", () => {
    sound.on = !sound.on;
    writePref(prefStore(), PREF_KEYS.sound, sound.on ? "on" : "off");
    renderSound();
    if (sound.on) {
      unlockAudio();
      beep("ok");
    }
  });

  for (const mode of ["scan", "type"]) {
    $(`tab-${mode}`).addEventListener("click", () => {
      unlockAudio();
      setMode(mode, true);
      // Focus inside the tap: iOS opens the keyboard only then.
      if (mode === "type") $("typed").focus();
    });
  }
  $("tab-scan").addEventListener("keydown", tabKeys);
  $("tab-type").addEventListener("keydown", tabKeys);

  $("done").addEventListener("click", finish);
  $("torch").addEventListener("click", toggleTorch);

  const vv = window.visualViewport;
  if (vv) {
    vv.addEventListener("resize", updateInset);
    vv.addEventListener("scroll", updateInset);
  }
  window.addEventListener("resize", updateInset);
  updateInset();
}

function tabKeys(ev) {
  if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
  ev.preventDefault();
  const next = state.mode === "scan" ? "type" : "scan";
  setMode(next, true);
  $(`tab-${next}`).focus();
}

/** Lift the bottom bar above whatever covers the layout viewport (iOS keyboard). */
function updateInset() {
  const px = bottomInset(window.innerHeight, window.visualViewport);
  const root = document.documentElement;
  root.style.setProperty("--kb", `${px}px`);
  root.classList.toggle("kb-open", px > 0);
}

/** Show Scan or Type; the camera runs only while Scan is shown. */
function setMode(mode, remember) {
  state.mode = mode;
  if (remember) writePref(prefStore(), PREF_KEYS.mode, mode);
  for (const m of ["scan", "type"]) {
    const on = m === mode;
    const tab = $(`tab-${m}`);
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
    $(`${m}-panel`).hidden = !on;
  }
  if (mode === "scan" && state.phase === "active") {
    if (!camera.stream && !camera.starting) startCamera();
  } else {
    stopCamera();
  }
}

// ------------------------------------------------------------------ banner

/** The status banner: a line of `text`, or a bold `title` with `text` below. */
function banner(kind, text, title) {
  const el = $("banner");
  if (!text && !title) {
    el.hidden = true;
    return;
  }
  el.className = `banner ${kind}`;
  el.replaceChildren();
  if (title) {
    const t = document.createElement("strong");
    t.className = "banner-title";
    t.textContent = title;
    el.append(t);
  }
  if (text) {
    const p = document.createElement("span");
    p.className = "banner-text";
    p.textContent = text;
    el.append(p);
  }
  el.hidden = false;
}

function setRelayDown(down) {
  if (state.phase === "closed") return;
  if (down === state.relayDown) return;
  state.relayDown = down;
  if (down) {
    banner("warn", "Cannot reach the server. Check the phone's connection; the page keeps trying and sends what is waiting.");
  } else {
    banner(null, "");
  }
}

/**
 * The session is over: `title` says how it ended (`tone` `info` or `error`),
 * the page's own count follows below it.
 */
function closed(title, tone = "info", stored) {
  if (state.phase === "closed") return;
  state.phase = "closed";
  state.relayDown = false;
  forgetLinkFragment(tabStore());
  stopCamera();
  $("capture").hidden = true;
  $("done").hidden = true;
  $("bar").classList.add("ended");
  $("sound").hidden = true;
  for (const item of state.items.values()) {
    if (item.status === "queued" || item.status === "sending") {
      item.status = "rejected";
      item.message = "The session ended before it was sent.";
      renderItem(item);
    }
  }
  state.sendQueue.length = 0;
  updateSummary();
  banner(tone, endCounts(itemStatuses(), stored), title);
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ------------------------------------------------------------------- entry

function wireEntry() {
  const input = $("typed");
  const sendBtn = $("send");
  const update = () => {
    const r = checkCertificate(input.value);
    renderTyped(r);
    // A certificate whose check does not match is never sent: bussard would refuse
    // it too (dev/enroll-protocol.md, "Certificate text").
    sendBtn.disabled = r.status !== "ok" || state.phase !== "active";
    return r;
  };
  input.addEventListener("input", update);
  const root = document.documentElement;
  input.addEventListener("focus", () => root.classList.add("typing"));
  input.addEventListener("blur", () => root.classList.remove("typing"));
  const submit = async () => {
    const r = update();
    if (r.status !== "ok") {
      if (r.status === "bad_check") beep("bad");
      return;
    }
    // Cleared after sending and on a duplicate alike: a certificate is
    // never shown again once it has left the field.
    const { outcome, item } = await submitCertificate(r, "typed");
    if (outcome !== "queued" && outcome !== "duplicate") return;
    input.value = "";
    update();
    const status = $("typed-status");
    if (outcome === "queued") {
      status.className = "typed-status good";
      status.textContent = `${shortCode(r.normalized)} sent. Type the next certificate, or Finish.`;
      pulse($("type-panel"), "ok");
      beep("ok");
    } else {
      status.className = "typed-status";
      status.textContent = `${shortCode(r.normalized)} is already in this session.`;
      if (item) flashRow(item);
    }
  };
  sendBtn.addEventListener("click", submit);
  // Keep the field focused across a tap on Send: the keyboard stays up for
  // the next certificate.
  sendBtn.addEventListener("pointerdown", (ev) => ev.preventDefault());
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
      status.textContent = `Serial number ${r.serial}. The check character does not match: most likely a typo. Compare with the sticker.`;
      break;
    case "ok":
      status.classList.add("good");
      status.textContent = `Serial number ${r.serial}. Check OK.`;
      break;
  }
}

// --------------------------------------------------------------- sending

async function digest(text) {
  return toHex(new Uint8Array(await state.subtle.digest("SHA-256", utf8(text))));
}

/**
 * Queue one checked certificate. Returns `{outcome: "queued", item}`, or
 * `{outcome: "duplicate", item}` with the earlier item when the same text was
 * sent already on this page (it is not sent twice). Feedback is the caller's.
 */
async function submitCertificate(r, source, d) {
  if (state.phase !== "active") return { outcome: "inactive" };
  d ??= await digest(r.normalized);
  if (state.sentDigests.has(d)) {
    const existing = [...state.items.values()].find((i) => i.digest === d);
    return { outcome: "duplicate", item: existing };
  }
  state.sentDigests.add(d);
  const item = {
    id: state.nextId++,
    digest: d,
    serial: r.serial,
    code: shortCode(r.normalized),
    source,
    status: "queued",
    plaintext: null,
  };
  item.plaintext = certificateMessage(item.id, r.normalized);
  state.items.set(item.id, item);
  renderItem(item);
  state.sendQueue.push(item);
  pumpSend();
  return { outcome: "queued", item };
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
        closed("The session has ended or expired.", "error");
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
      if (state.phase === "finished") closed(FINISHED);
      else closed("The session has ended or expired.", "error");
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
      closed(endTitle());
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
    closed(endTitle(), "info", msg.stored);
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

const FINISHED = "Finished. You can close this page.";

/** The end message: after Finish, or when bussard stopped the session. */
function endTitle() {
  return state.phase === "finished" ? FINISHED : "bussard ended the session. You can close this page.";
}

function itemStatuses() {
  return [...state.items.values()].map((i) => i.status);
}

async function finish() {
  if (state.phase !== "active") return;
  state.phase = "finished";
  stopCamera();
  $("capture").hidden = true;
  $("done").disabled = true;
  $("done").textContent = "Finishing…";
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
      '<div class="row"><span class="code"></span><span class="pill"></span></div>' +
      '<div class="serial"></div><div class="detail"></div>';
    $("labels").prepend(li);
    li.classList.add("enter");
    li.addEventListener("animationend", () => li.classList.remove("enter", "flash"));
  }
  const keep = [...li.classList].filter((c) => c === "enter" || c === "flash");
  li.className = ["label", statusTone(item.status), ...keep].join(" ");
  // The certificate is never shown whole again: the first and last group of
  // its printed code (what the sticker shows) and the serial number.
  li.querySelector(".code").textContent = item.code;
  li.querySelector(".serial").textContent = `Serial number ${item.serial}`;
  li.querySelector(".pill").textContent = shortStatus(item.status);
  li.querySelector(".detail").textContent = statusDetail(item);
  $("labels-empty").hidden = state.items.size > 0;
  updateSummary();
}

function updateSummary() {
  // Each count stays with its word when the bar wraps.
  $("summary").textContent = summaryText(itemStatuses())
    .split(" · ")
    .map((part) => part.replace(/ /g, "\u00a0"))
    // The dot stays at the end of a line, never starts the next one.
    .join("\u00a0· ");
}

function flashRow(item) {
  const li = document.getElementById(`item-${item.id}`);
  if (!li) return;
  li.classList.remove("flash");
  void li.offsetWidth; // restart the animation
  li.classList.add("flash");
  li.scrollIntoView({ block: "nearest", behavior: "smooth" });
}

// -------------------------------------------------------------- feedback

let flashTimer = 0;

/**
 * The overlay on the viewfinder: `ok` (green, new certificate), `repeat`
 * (neutral, already in this session or not a certificate) or `bad` (red,
 * the check does not match).
 */
function scanFlash(kind, title, text) {
  const el = $("scan-flash");
  el.className = `scan-flash ${kind}`;
  $("scan-flash-title").textContent = title;
  $("scan-flash-text").textContent = text;
  el.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => {
    el.hidden = true;
  }, kind === "ok" ? FLASH_MS : FLASH_MS + 600);
}

/** A short coloured pulse on a panel (Type mode's success). */
function pulse(el, kind) {
  el.classList.remove("pulse-ok", "pulse-bad");
  void el.offsetWidth;
  el.classList.add(`pulse-${kind}`);
}

const sound = { on: true, ctx: null };

function renderSound() {
  const btn = $("sound");
  btn.setAttribute("aria-pressed", String(sound.on));
  btn.setAttribute("aria-label", sound.on ? "Sound on, tap to mute" : "Sound off, tap to turn on");
  btn.classList.toggle("muted", !sound.on);
}

/** Create or resume the audio context; call from a tap (iOS needs one). */
function unlockAudio() {
  if (!sound.on) return;
  try {
    const Ctx = window.AudioContext ?? window.webkitAudioContext;
    if (!Ctx) return;
    sound.ctx ??= new Ctx();
    if (sound.ctx.state === "suspended") sound.ctx.resume().catch(() => {});
  } catch {
    sound.ctx = null;
  }
}

/** A short beep: `ok` rises, `bad` is low and longer. No sound when muted. */
function beep(kind) {
  if (!sound.on) return;
  const ctx = sound.ctx;
  if (!ctx || ctx.state !== "running") return;
  try {
    const notes = kind === "ok" ? [[1046, 0, 0.07], [1568, 0.08, 0.09]] : [[220, 0, 0.22]];
    for (const [freq, at, len] of notes) {
      const t = ctx.currentTime + at;
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = kind === "ok" ? "sine" : "square";
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.0001, t);
      gain.gain.exponentialRampToValueAtTime(kind === "ok" ? 0.3 : 0.12, t + 0.01);
      gain.gain.exponentialRampToValueAtTime(0.0001, t + len);
      osc.connect(gain).connect(ctx.destination);
      osc.start(t);
      osc.stop(t + len + 0.02);
    }
  } catch {
    // no sound is not an error
  }
}

// ---------------------------------------------------------------- camera

const camera = {
  stream: null,
  starting: false,
  detector: null,
  jsqr: null,
  timer: 0,
  canvas: null,
  busy: false,
  lastMiss: 0,
  gate: new ScanGate(),
  torch: false,
};

async function startCamera() {
  const msg = $("camera-msg");
  const btn = $("camera-start");
  btn.hidden = true;
  msg.hidden = true;
  if (!navigator.mediaDevices?.getUserMedia) {
    cameraMessage("This browser gives the page no camera. Use Type instead.");
    return;
  }
  camera.starting = true;
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } },
    });
  } catch (e) {
    const denied = e?.name === "NotAllowedError" || e?.name === "SecurityError";
    cameraMessage(
      denied
        ? "Camera access was refused. Allow it in the browser settings, or use Type."
        : "No camera available. Use Type instead.",
    );
    btn.hidden = false;
    btn.onclick = startCamera;
    return;
  } finally {
    camera.starting = false;
  }
  // Type mode or the end of the session may have come while the browser asked.
  if (state.phase !== "active" || state.mode !== "scan") {
    for (const t of stream.getTracks()) t.stop();
    return;
  }
  camera.stream = stream;
  const video = $("video");
  video.srcObject = stream;
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
  setupTorch();
  scheduleScan();
}

/**
 * Show the flashlight button where the camera offers a torch (Android
 * Chrome). Safari on iOS has no torch control, so the button stays hidden.
 */
function setupTorch() {
  const btn = $("torch");
  camera.torch = false;
  btn.setAttribute("aria-pressed", "false");
  let caps;
  try {
    caps = camera.stream?.getVideoTracks()[0]?.getCapabilities?.();
  } catch {
    caps = null;
  }
  btn.hidden = caps?.torch !== true;
}

async function toggleTorch() {
  const track = camera.stream?.getVideoTracks()[0];
  if (!track) return;
  const want = !camera.torch;
  try {
    await track.applyConstraints({ advanced: [{ torch: want }] });
    camera.torch = want;
  } catch {
    camera.torch = false;
  }
  $("torch").setAttribute("aria-pressed", String(camera.torch));
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
  if (!camera.jsqr) cameraMessage("The QR decoder did not load. Use Type instead.");
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
      scanFlash("repeat", "Not a certificate", "This QR code holds no certificate.");
    }
    return;
  }
  const r = checkCertificate(text);
  if (r.status !== "ok" && r.status !== "bad_check") return;
  const d = await digest(r.normalized);
  if (r.status === "bad_check") {
    if (camera.gate.decide(`bad:${d}`, false, Date.now()) === "hold") return;
    scanFlash("bad", "Check does not match", `${shortCode(r.normalized)}. Rescan, or type the code.`);
    beep("bad");
    return;
  }
  const decision = camera.gate.decide(d, state.sentDigests.has(d), Date.now());
  if (decision === "hold") return;
  const { outcome, item } = await submitCertificate(r, "scan", d);
  if (outcome === "queued") {
    scanFlash("ok", shortCode(r.normalized), "Sent");
    beep("ok");
  } else if (outcome === "duplicate") {
    scanFlash("repeat", shortCode(r.normalized), "Already in this session");
    if (item) flashRow(item);
  }
}

function stopCamera() {
  clearTimeout(camera.timer);
  if (camera.stream) {
    for (const t of camera.stream.getTracks()) t.stop();
    camera.stream = null;
  }
  camera.torch = false;
  const torch = document.getElementById("torch");
  if (torch) torch.hidden = true;
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
