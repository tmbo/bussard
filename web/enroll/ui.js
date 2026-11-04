// Display logic of the enrolment page that does not touch the DOM: status
// wording, the running summary, scan de-duplication, remembered choices and
// the link kept for a reload.
// Kept apart from app.js so `node --test` (web/tests/) can check it.

/**
 * The badge and the detail line per item status, as in the glossary's
 * "Certificate states" table (dev/glossary.md). Statuses from bussard are
 * those of dev/enroll-protocol.md; the others are the page's own (`queued`,
 * `sending`, `sent`, `rejected`). An empty detail means the badge says it.
 */
export const STATUS_WORDS = {
  queued: { short: "waiting", long: "" },
  sending: { short: "sending", long: "" },
  sent: { short: "sent", long: "waiting for bussard" },
  stored: { short: "added", long: "" },
  unassigned: {
    short: "no device yet",
    long:
      "no device in your project has this serial number; bussard matches it once it finds the device (bussard scan)",
  },
  already_stored: { short: "already known", long: "" },
  conflict: { short: "conflict", long: "your key store holds a different key for this device" },
  invalid: { short: "invalid", long: "check the code" },
  error: { short: "failed", long: "" },
  rejected: { short: "not sent", long: "" },
};

/** Statuses bussard has kept a certificate for. */
export const KEPT = new Set(["stored", "unassigned", "already_stored"]);
/** Statuses that need the user's attention. */
export const PROBLEM = new Set(["conflict", "invalid", "error", "rejected"]);
/** Statuses whose detail line is the reason (bussard's or the page's message). */
const REASON = new Set(["error", "rejected"]);

/** Row tone for a status: `good`, `wait` (kept, device pending), `bad` or `pending`. */
export function statusTone(status) {
  if (status === "unassigned") return "wait";
  if (KEPT.has(status)) return "good";
  if (PROBLEM.has(status)) return "bad";
  return "pending";
}

/** The badge word for a status. */
export function shortStatus(status) {
  return STATUS_WORDS[status]?.short ?? String(status);
}

/**
 * The detail line of a row: the device an added certificate went to
 * ("for 1.1.3 Kitchen actuator"), the reason for a failed or unsent one,
 * the glossary's line otherwise, or nothing where the badge says it.
 *
 * @param {{status: string, ia?: string, name?: string, message?: string}} item
 * @returns {string}
 */
export function statusDetail(item) {
  if (item.status === "stored") {
    const where = [item.ia, item.name].filter(Boolean).join(" ");
    return where ? `for ${where}` : "";
  }
  if (REASON.has(item.status)) return item.message ?? "";
  return STATUS_WORDS[item.status]?.long ?? "";
}

/**
 * The title of a certificate on the page: its printed code shortened to the
 * first and last group of six (`AAFDHW … X4VCNL`). The code, not the serial
 * number, is what the device's sticker shows.
 *
 * @param {string} normalized the 36 characters, no dashes
 * @returns {string}
 */
export function shortCode(normalized) {
  return `${normalized.slice(0, 6)} \u2026 ${normalized.slice(-6)}`;
}

/**
 * Counts per group over item statuses. `sent` is every certificate that
 * left the page (all but `rejected`); `inFlight` those without bussard's
 * answer yet.
 *
 * @param {Iterable<string>} statuses
 * @returns {{total: number, sent: number, added: number, noDevice: number,
 *   known: number, conflict: number, invalid: number, failed: number,
 *   notSent: number, inFlight: number}}
 */
export function countStatuses(statuses) {
  const c = {
    total: 0,
    sent: 0,
    added: 0,
    noDevice: 0,
    known: 0,
    conflict: 0,
    invalid: 0,
    failed: 0,
    notSent: 0,
    inFlight: 0,
  };
  for (const s of statuses) {
    c.total++;
    if (s === "rejected") {
      c.notSent++;
      continue;
    }
    c.sent++;
    if (s === "stored") c.added++;
    else if (s === "unassigned") c.noDevice++;
    else if (s === "already_stored") c.known++;
    else if (s === "conflict") c.conflict++;
    else if (s === "invalid") c.invalid++;
    else if (s === "error") c.failed++;
    else c.inFlight++;
  }
  return c;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/** The non-zero result groups in the glossary's words, in a fixed order. */
function resultParts(c) {
  const parts = [];
  if (c.added) parts.push(`${c.added} added`);
  if (c.known) parts.push(`${c.known} already known`);
  if (c.noDevice) parts.push(`${c.noDevice} no device yet`);
  if (c.conflict) parts.push(plural(c.conflict, "conflict", "conflicts"));
  if (c.invalid) parts.push(`${c.invalid} invalid`);
  if (c.failed) parts.push(`${c.failed} failed`);
  return parts;
}

/**
 * The bottom bar's summary, for example
 * `6 sent · 1 added · 4 already known · 1 no device yet`. Groups with no
 * certificate are left out; the bar wraps rather than shortens it.
 *
 * @param {Iterable<string>} statuses
 * @returns {string}
 */
export function summaryText(statuses) {
  const c = countStatuses(statuses);
  if (c.total === 0) return "Nothing sent yet";
  const parts = [];
  if (c.sent) parts.push(`${c.sent} sent`);
  parts.push(...resultParts(c));
  if (c.inFlight) parts.push(`${c.inFlight} waiting`);
  if (c.notSent) parts.push(`${c.notSent} not sent`);
  return parts.join(" · ");
}

/**
 * The line under the end message, counted from the page's own results:
 * `Sent 6 certificates to your bussard: 1 added, 5 already known.`
 * `stored` (bussard's `closed.stored`) is used only when the page has no
 * results of its own, for example after a reload.
 *
 * @param {Iterable<string>} statuses
 * @param {number} [stored]
 * @returns {string}
 */
export function endCounts(statuses, stored) {
  const c = countStatuses(statuses);
  if (c.sent === 0) {
    if (typeof stored === "number" && stored > 0) {
      return `bussard added ${plural(stored, "certificate", "certificates")} in this session.`;
    }
    return "No certificates were sent from this page.";
  }
  const parts = resultParts(c);
  if (c.inFlight) parts.push(`${c.inFlight} without an answer`);
  const head = `Sent ${plural(c.sent, "certificate", "certificates")} to your bussard`;
  return parts.length ? `${head}: ${parts.join(", ")}.` : `${head}.`;
}

/** Milliseconds a certificate must be out of view before it counts as presented again. */
export const SCAN_HOLD_MS = 2500;

/**
 * Decides what a decoded QR code means. The camera reads the same label
 * several times a second while it is in view, so a key seen less than
 * `holdMs` ago is `hold` (no feedback). After that, a key already in the
 * session is `repeat`; anything else is `new`.
 */
export class ScanGate {
  /** @param {number} [holdMs] */
  constructor(holdMs = SCAN_HOLD_MS) {
    this.holdMs = holdMs;
    this.lastSeen = new Map();
  }

  /**
   * @param {string} key a digest of the normalized text, never the text
   * @param {boolean} inSession whether the label is in this session already
   * @param {number} now milliseconds
   * @returns {"new" | "repeat" | "hold"}
   */
  decide(key, inSession, now) {
    const last = this.lastSeen.get(key);
    this.lastSeen.set(key, now);
    if (last !== undefined && now - last < this.holdMs) return "hold";
    return inSession ? "repeat" : "new";
  }
}

/** Keys of the choices the page remembers in this browser. */
export const PREF_KEYS = { mode: "bussard.enroll.mode", sound: "bussard.enroll.sound" };

/**
 * Read a remembered choice. Storage may be missing or throw (private mode,
 * blocked site data); the default applies then.
 *
 * @param {Storage | undefined | null} storage
 * @param {string} key
 * @param {string[]} allowed
 * @param {string} fallback
 * @returns {string}
 */
export function readPref(storage, key, allowed, fallback) {
  try {
    const v = storage?.getItem(key);
    return allowed.includes(v) ? v : fallback;
  } catch {
    return fallback;
  }
}

/**
 * Remember a choice; a storage that throws is ignored.
 *
 * @param {Storage | undefined | null} storage
 * @param {string} key
 * @param {string} value
 */
export function writePref(storage, key, value) {
  try {
    storage?.setItem(key, value);
  } catch {
    // not remembered; the page works the same
  }
}

/**
 * sessionStorage key of the link fragment. It holds the session id and
 * bussard's public key only, never a certificate or a session key, and lives
 * as long as the tab.
 */
export const LINK_KEY = "bussard.enroll.link";

/**
 * The link fragment for this tab. A fragment in the address bar wins and is
 * kept in `storage` (sessionStorage), because the page then removes it from
 * the address bar and the history; a reload in the same tab finds it there.
 * Returns "" when there is neither.
 *
 * @param {string} hash `location.hash`
 * @param {Storage | undefined | null} storage
 * @returns {string}
 */
export function takeLinkFragment(hash, storage) {
  const fragment = String(hash ?? "").replace(/^#/, "");
  if (fragment !== "") {
    writePref(storage, LINK_KEY, fragment);
    return fragment;
  }
  try {
    return storage?.getItem(LINK_KEY) ?? "";
  } catch {
    return "";
  }
}

/**
 * Drop the kept link fragment (the session has ended or the link is broken).
 *
 * @param {Storage | undefined | null} storage
 */
export function forgetLinkFragment(storage) {
  try {
    storage?.removeItem(LINK_KEY);
  } catch {
    // nothing kept
  }
}

/**
 * What the relay's answer to the first `GET down` says about the session:
 * `open`, `gone` (404: unknown or expired), `ended` (bussard closed it
 * already) or `unreachable` (anything else; the relay or the network failed).
 *
 * @param {number} status HTTP status
 * @param {unknown} body the parsed JSON answer, or null
 * @returns {"open" | "gone" | "ended" | "unreachable"}
 */
export function sessionCheck(status, body) {
  if (status === 404) return "gone";
  if (status < 200 || status > 299) return "unreachable";
  if (!body || typeof body !== "object" || !Array.isArray(body.messages)) return "unreachable";
  return body.closed === true ? "ended" : "open";
}

/**
 * Pixels the on-screen keyboard (or anything else) covers at the bottom of
 * the layout viewport, from `window.innerHeight` and `visualViewport`. iOS
 * Safari keeps the layout viewport when the keyboard opens, so a fixed bar
 * must be lifted by this much to stay visible.
 *
 * @param {number} innerHeight
 * @param {{height: number, offsetTop: number} | undefined | null} vv
 * @returns {number}
 */
export function bottomInset(innerHeight, vv) {
  if (!vv) return 0;
  const covered = innerHeight - (vv.height + vv.offsetTop);
  // Toolbar animations leave a pixel or two; only a real overlap counts.
  return covered > 40 ? Math.round(covered) : 0;
}
