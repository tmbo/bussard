// Display logic of the enrolment page that does not touch the DOM: status
// wording, the running summary, scan de-duplication and remembered choices.
// Kept apart from app.js so `node --test` (web/tests/) can check it.

/**
 * Short status word (the row's pill) and the longer detail line per item
 * status. Statuses from bussard are those of dev/enroll-protocol.md; the
 * others are the page's own (`queued`, `sending`, `sent`, `rejected`).
 */
export const STATUS_WORDS = {
  queued: { short: "waiting", long: "Waiting to send" },
  sending: { short: "sending", long: "Sending" },
  sent: { short: "sent", long: "Sent, waiting for bussard" },
  stored: { short: "saved", long: "Saved for its device" },
  unassigned: {
    short: "waiting for device",
    long: "Kept until a device in the model has this serial",
  },
  already_stored: { short: "already known", long: "bussard already had this certificate" },
  conflict: {
    short: "conflict",
    long: "bussard holds a different key for this serial; nothing written",
  },
  invalid: { short: "invalid", long: "bussard rejected the text" },
  error: { short: "error", long: "Error" },
  rejected: { short: "not sent", long: "Not sent" },
};

/** Statuses bussard has kept a certificate for. */
export const KEPT = new Set(["stored", "unassigned", "already_stored"]);
/** Statuses that need the user's attention. */
export const PROBLEM = new Set(["conflict", "invalid", "error", "rejected"]);

/** Row tone for a status: `good`, `wait` (kept, device pending), `bad` or `pending`. */
export function statusTone(status) {
  if (status === "unassigned") return "wait";
  if (KEPT.has(status)) return "good";
  if (PROBLEM.has(status)) return "bad";
  return "pending";
}

/** The pill word for a status. */
export function shortStatus(status) {
  return STATUS_WORDS[status]?.short ?? String(status);
}

/**
 * The detail line of a row: where a saved certificate went (address and name
 * when bussard sends them), the longer wording otherwise, then bussard's or
 * the page's message.
 *
 * @param {{status: string, ia?: string, name?: string, message?: string}} item
 * @returns {string}
 */
export function statusDetail(item) {
  const parts = [];
  const where = [item.ia, item.name].filter(Boolean).join(" ");
  if (item.status === "stored" && where) {
    parts.push(`Saved for ${where}`);
  } else {
    const long = STATUS_WORDS[item.status]?.long;
    if (long) parts.push(long);
  }
  if (item.message) parts.push(item.message);
  return parts.join(". ");
}

/**
 * Counts per group over item statuses.
 *
 * @param {Iterable<string>} statuses
 * @returns {{total: number, saved: number, waiting: number, known: number,
 *   problems: number, inFlight: number}}
 */
export function countStatuses(statuses) {
  const c = { total: 0, saved: 0, waiting: 0, known: 0, problems: 0, inFlight: 0 };
  for (const s of statuses) {
    c.total++;
    if (s === "stored") c.saved++;
    else if (s === "unassigned") c.waiting++;
    else if (s === "already_stored") c.known++;
    else if (PROBLEM.has(s)) c.problems++;
    else c.inFlight++;
  }
  return c;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * The bottom bar's summary in short words, for example
 * `3 labels · 2 saved · 1 waiting`, so it fits the narrow bar; the rows carry
 * the full wording. Groups with no label are left out.
 *
 * @param {Iterable<string>} statuses
 * @returns {string}
 */
export function summaryText(statuses) {
  const c = countStatuses(statuses);
  if (c.total === 0) return "No labels yet";
  const parts = [plural(c.total, "label", "labels")];
  if (c.saved) parts.push(`${c.saved} saved`);
  if (c.waiting) parts.push(`${c.waiting} waiting`);
  if (c.known) parts.push(`${c.known} known`);
  if (c.inFlight) parts.push(`${c.inFlight} sending`);
  if (c.problems) parts.push(`${c.problems} failed`);
  return parts.join(" · ");
}

/** Milliseconds a label must be out of view before it counts as presented again. */
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
