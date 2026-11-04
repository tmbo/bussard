// The phone key of a session, kept across reloads (dev/enroll-protocol.md,
// "Reconnect"). The page keeps its X25519 private key as a non-extractable
// WebCrypto CryptoKey in IndexedDB, keyed by the session id, so a reload or a
// network switch comes back as the same phone. Page script can store and use
// the key but never read its bytes.
//
// The logic runs over a small async key-value backend: `indexedDbBackend()`
// in the browser, a Map in the tests (web/tests/phonekey.test.js).

/** How long a kept phone key lives: the protocol's maximum session length. */
export const PHONE_KEY_MAX_AGE_MS = 4 * 60 * 60 * 1000;

const DB_NAME = "bussard-enroll";
const STORE = "phone-keys";

/**
 * The IndexedDB backend, or `null` when the browser offers none (a private
 * window may refuse it); the page then works without reconnect-after-reload.
 *
 * @returns {Promise<{get: Function, put: Function, delete: Function, keys: Function} | null>}
 */
export async function indexedDbBackend(idb = globalThis.indexedDB) {
  if (!idb) return null;
  let db;
  try {
    db = await new Promise((resolve, reject) => {
      const req = idb.open(DB_NAME, 1);
      req.onupgradeneeded = () => req.result.createObjectStore(STORE);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
  const run = (mode, fn) =>
    new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, mode);
      const req = fn(tx.objectStore(STORE));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
  return {
    get: (key) => run("readonly", (s) => s.get(key)),
    put: (key, value) => run("readwrite", (s) => s.put(value, key)),
    delete: (key) => run("readwrite", (s) => s.delete(key)),
    keys: () => run("readonly", (s) => s.getAllKeys()),
  };
}

/**
 * Kept phone keys over `backend`. Every method swallows storage errors: a
 * failed write only costs the reconnect after a reload.
 */
export class PhoneKeys {
  /**
   * @param {object | null} backend from `indexedDbBackend()`, or a test's Map wrapper
   * @param {() => number} now clock in milliseconds
   */
  constructor(backend, now = Date.now) {
    this.backend = backend;
    this.now = now;
  }

  /**
   * The kept phone of session `sid`: `{privateKey, publicRaw, nextId,
   * confirmed}`, or `null` when there is none or it is too old. Drops every
   * kept key older than the maximum session length on the way.
   */
  async load(sid) {
    if (!this.backend) return null;
    try {
      await this.prune();
      const record = await this.backend.get(sid);
      if (!record || !record.privateKey || !(record.publicRaw instanceof Uint8Array)) return null;
      return {
        privateKey: record.privateKey,
        publicRaw: record.publicRaw,
        nextId: Number.isInteger(record.nextId) && record.nextId > 0 ? record.nextId : 1,
        confirmed: record.confirmed === true,
      };
    } catch {
      return null;
    }
  }

  /** Keeps a new phone key for `sid`. */
  async save(sid, { privateKey, publicRaw }) {
    await this.write(sid, () => ({ privateKey, publicRaw, created: this.now(), nextId: 1, confirmed: false }));
  }

  /** Records the next certificate id, so a reload does not reuse one. */
  async setNextId(sid, nextId) {
    await this.write(sid, (record) => record && { ...record, nextId });
  }

  /** Records that the user confirmed the session code. */
  async setConfirmed(sid) {
    await this.write(sid, (record) => record && { ...record, confirmed: true });
  }

  /** Forgets the phone key of `sid`: the session ended. */
  async forget(sid) {
    if (!this.backend) return;
    try {
      await this.backend.delete(sid);
    } catch {
      // nothing kept, or nothing to do
    }
  }

  /** Deletes every kept key older than the maximum session length. */
  async prune() {
    const cutoff = this.now() - PHONE_KEY_MAX_AGE_MS;
    for (const key of await this.backend.keys()) {
      const record = await this.backend.get(key);
      if (!record || !(record.created > cutoff)) await this.backend.delete(key);
    }
  }

  async write(sid, update) {
    if (!this.backend) return;
    try {
      const next = update(await this.backend.get(sid));
      if (next) await this.backend.put(sid, next);
    } catch {
      // the reconnect after a reload is lost, nothing else
    }
  }
}
