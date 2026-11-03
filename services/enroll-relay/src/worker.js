// bussard enrolment relay: a mailbox for the certificate enrolment protocol.
//
// Contract: dev/enroll-protocol.md, "Relay API". The relay stores and forwards
// encrypted envelopes. It never decrypts, never inspects ciphertext beyond the
// envelope's shape, and never logs a request or response body.
//
// One Durable Object per session id holds the session's metadata and messages.
// The Worker in front routes requests to it and adds CORS headers on the two
// phone-side endpoints (POST up, GET down) only.

/** Session lifetime in seconds, counted from the PUT that created it. */
const SESSION_TTL_SECONDS = 30 * 60;
/** Messages per direction per session. */
const MAX_MESSAGES = 200;
/** Serialized envelope size limit in bytes. */
const MAX_ENVELOPE_BYTES = 4096;
/** Upper bound of a long poll, in seconds. */
const MAX_WAIT_SECONDS = 25;

/** A session id: 16 random bytes, base64url without padding. */
const SID_RE = /^[A-Za-z0-9_-]{22}$/;
/** A non-empty base64url string without padding. */
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const ROUTE_RE = /^\/v1\/sessions\/([^/]+)(?:\/(up|down))?$/;

function json(status, value, headers = {}) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers },
  });
}

function error(status, message) {
  return json(status, { error: message });
}

/** True for the endpoints the phone page calls cross-origin. */
function isPhoneEndpoint(method, dir) {
  return (method === 'POST' && dir === 'up') || (method === 'GET' && dir === 'down');
}

function withCors(response) {
  const headers = new Headers(response.headers);
  headers.set('access-control-allow-origin', '*');
  return new Response(response.body, { status: response.status, headers });
}

function preflight(dir) {
  return new Response(null, {
    status: 204,
    headers: {
      'access-control-allow-origin': '*',
      'access-control-allow-methods': dir === 'up' ? 'POST' : 'GET',
      'access-control-allow-headers': 'content-type',
      'access-control-max-age': '86400',
    },
  });
}

/**
 * The session TTL in seconds. `SESSION_TTL_SECONDS` in the environment may
 * shorten it (the expiry tests run a relay with a 2-second TTL); it can never
 * lengthen it past the protocol's 30 minutes.
 */
function sessionTtlSeconds(env) {
  const configured = Number(env && env.SESSION_TTL_SECONDS);
  if (Number.isFinite(configured) && configured > 0 && configured < SESSION_TTL_SECONDS) {
    return configured;
  }
  return SESSION_TTL_SECONDS;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Compares two equal-length hex digests without an early exit. */
function digestsEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function bearerToken(request) {
  const header = request.headers.get('authorization') || '';
  const match = /^Bearer ([^\s]+)$/.exec(header);
  return match ? match[1] : null;
}

/** Parses a non-negative integer query parameter; `null` when malformed. */
function parseCount(value, fallback) {
  if (value === null) {
    return fallback;
  }
  return /^\d{1,15}$/.test(value) ? Number(value) : null;
}

/** Parses `wait` in seconds (fractions allowed), clamped to the 25-second cap. */
function parseWait(value) {
  if (value === null) {
    return 0;
  }
  if (!/^\d{1,9}(\.\d{1,3})?$/.test(value)) {
    return null;
  }
  return Math.min(Number(value), MAX_WAIT_SECONDS);
}

/** Validates an envelope's shape: `{"v": 1, "pk", "n", "c"}`, all base64url. */
function isEnvelope(value) {
  return (
    value !== null &&
    typeof value === 'object' &&
    !Array.isArray(value) &&
    value.v === 1 &&
    ['pk', 'n', 'c'].every((k) => typeof value[k] === 'string' && B64URL_RE.test(value[k]))
  );
}

function messageKey(dir, seq) {
  return `m:${dir}:${String(seq).padStart(6, '0')}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = ROUTE_RE.exec(url.pathname);
    if (!route) {
      return error(404, 'not found');
    }
    const [, sid, dir] = route;
    const method = request.method;

    if (method === 'OPTIONS') {
      return dir ? preflight(dir) : error(405, 'method not allowed');
    }

    let response;
    if (!SID_RE.test(sid)) {
      response = method === 'PUT' && !dir ? error(400, 'malformed session id') : error(404, 'unknown session');
    } else {
      const stub = env.SESSIONS.get(env.SESSIONS.idFromName(sid));
      response = await stub.fetch(request);
    }
    return isPhoneEndpoint(method, dir) ? withCors(response) : response;
  },
};

/** One enrolment session: owner token hash, two message queues, expiry. */
export class Session {
  constructor(state, env) {
    this.storage = state.storage;
    this.env = env;
    /** `null` when no session exists; loaded once per object instance. */
    this.meta = undefined;
    this.ready = null;
    /** Long-poll waiters per direction. */
    this.waiters = { up: new Set(), down: new Set() };
  }

  load() {
    if (!this.ready) {
      this.ready = this.storage.get('meta').then((meta) => {
        this.meta = meta ?? null;
      });
    }
    return this.ready;
  }

  /** Drops the session if it has expired. Returns true while it is live. */
  async live() {
    await this.load();
    if (this.meta && Date.now() >= this.meta.expires) {
      await this.forget();
    }
    return this.meta !== null;
  }

  async forget() {
    this.meta = null;
    await this.storage.deleteAll();
    await this.storage.deleteAlarm();
    this.wakeAll();
  }

  wake(dir) {
    for (const resolve of this.waiters[dir]) {
      resolve();
    }
    this.waiters[dir].clear();
  }

  wakeAll() {
    this.wake('up');
    this.wake('down');
  }

  async alarm() {
    await this.load();
    await this.forget();
  }

  async isOwner(request) {
    const token = bearerToken(request);
    return token !== null && digestsEqual(await sha256Hex(token), this.meta.owner);
  }

  async fetch(request) {
    const url = new URL(request.url);
    const [, , dir] = ROUTE_RE.exec(url.pathname);
    const method = request.method;

    if (!dir) {
      if (method === 'PUT') return this.create(request);
      if (method === 'DELETE') return this.close(request);
      return error(405, 'method not allowed');
    }
    if (method === 'POST') return this.post(request, dir);
    if (method === 'GET') return this.read(request, url, dir);
    return error(405, 'method not allowed');
  }

  async create(request) {
    const token = bearerToken(request);
    if (token === null) {
      return error(401, 'owner token required');
    }
    if (await this.live()) {
      return error(409, 'session exists');
    }
    let body;
    try {
      body = await request.json();
    } catch {
      return error(400, 'body must be a JSON object');
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      return error(400, 'body must be a JSON object');
    }
    const now = Date.now();
    // Another PUT may have created the session while the body was read.
    if (this.meta && now < this.meta.expires) {
      return error(409, 'session exists');
    }
    const expires = now + sessionTtlSeconds(this.env) * 1000;
    this.meta = {
      owner: await sha256Hex(token),
      created: now,
      expires,
      closed: false,
      seq: { up: 0, down: 0 },
    };
    await this.storage.put('meta', this.meta);
    await this.storage.setAlarm(expires);
    return json(201, {});
  }

  async close(request) {
    if (!(await this.live())) {
      return error(404, 'unknown session');
    }
    if (!(await this.isOwner(request))) {
      return error(401, 'owner token required');
    }
    if (!this.meta) {
      return error(404, 'unknown session');
    }
    if (!this.meta.closed) {
      // Drop the messages now; keep only the metadata so reads can answer
      // `closed: true` until the expiry alarm removes that too.
      this.meta = { ...this.meta, closed: true };
      await this.storage.deleteAll();
      await this.storage.put('meta', this.meta);
      // deleteAll may or may not drop the alarm depending on the storage
      // backend; set it again so the metadata still goes at expiry.
      await this.storage.setAlarm(this.meta.expires);
      this.wakeAll();
    }
    return new Response(null, { status: 204 });
  }

  async post(request, dir) {
    if (!(await this.live()) || this.meta.closed) {
      return error(404, 'unknown session');
    }
    if (dir === 'down' && !(await this.isOwner(request))) {
      return error(401, 'owner token required');
    }
    const declared = Number(request.headers.get('content-length'));
    if (Number.isFinite(declared) && declared > MAX_ENVELOPE_BYTES) {
      return error(429, 'envelope too large');
    }
    const bytes = new Uint8Array(await request.arrayBuffer());
    if (bytes.byteLength > MAX_ENVELOPE_BYTES) {
      return error(429, 'envelope too large');
    }
    let text;
    let envelope;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
      envelope = JSON.parse(text);
    } catch {
      return error(400, 'body must be an envelope');
    }
    if (!isEnvelope(envelope)) {
      return error(400, 'body must be an envelope');
    }
    // Re-check after the awaits above: the session may have closed or expired.
    if (!(await this.live()) || this.meta.closed) {
      return error(404, 'unknown session');
    }
    if (this.meta.seq[dir] >= MAX_MESSAGES) {
      return error(429, 'message limit reached');
    }
    // Assign the sequence number synchronously so concurrent posts never share one.
    const seq = this.meta.seq[dir] + 1;
    this.meta = { ...this.meta, seq: { ...this.meta.seq, [dir]: seq } };
    await this.storage.put({ meta: this.meta, [messageKey(dir, seq)]: JSON.stringify(envelope) });
    this.wake(dir);
    return json(202, { seq });
  }

  async read(request, url, dir) {
    if (!(await this.live())) {
      return error(404, 'unknown session');
    }
    if (dir === 'up' && !(await this.isOwner(request))) {
      return error(401, 'owner token required');
    }
    const after = parseCount(url.searchParams.get('after'), 0);
    const wait = parseWait(url.searchParams.get('wait'));
    if (after === null || wait === null) {
      return error(400, 'after and wait must be non-negative numbers');
    }

    const deadline = Date.now() + wait * 1000;
    for (;;) {
      if (!(await this.live())) {
        return error(404, 'unknown session');
      }
      if (this.meta.closed) {
        return this.messages([], true);
      }
      const pending = await this.pending(dir, after);
      const remaining = deadline - Date.now();
      if (pending.length > 0 || remaining <= 0) {
        return this.messages(pending, false);
      }
      await new Promise((resolve) => {
        // A post or close may have landed while `pending` awaited storage.
        if (!this.meta || this.meta.closed || this.meta.seq[dir] > after) {
          resolve();
          return;
        }
        const timer = setTimeout(done, remaining);
        const waiters = this.waiters[dir];
        function done() {
          clearTimeout(timer);
          waiters.delete(done);
          resolve();
        }
        waiters.add(done);
      });
    }
  }

  async pending(dir, after) {
    if (after >= this.meta.seq[dir]) {
      return [];
    }
    const prefix = `m:${dir}:`;
    const stored = await this.storage.list({ prefix, start: messageKey(dir, after + 1) });
    return [...stored].map(([key, body]) => ({ seq: Number(key.slice(prefix.length)), body }));
  }

  messages(list, closed) {
    // Bodies were validated and serialized on the way in; splice them in as is.
    const items = list.map(({ seq, body }) => `{"seq":${seq},"body":${body}}`).join(',');
    return new Response(`{"messages":[${items}],"closed":${closed}}`, {
      status: 200,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }
}
