// Runs src/worker.js under Node for the tests: an HTTP server in front of the
// Worker's fetch handler and an in-memory stand-in for the Durable Object
// namespace (storage, alarms). It covers only the runtime surface the relay
// uses. The same cases run against `wrangler dev` (workerd) by setting
// RELAY_URL; see README.md.

import { createServer } from 'node:http';
import worker, { Session } from '../src/worker.js';

class MemoryStorage {
  constructor(onAlarm) {
    this.data = new Map();
    this.alarmTimer = null;
    this.onAlarm = onAlarm;
  }

  async get(key) {
    return structuredClone(this.data.get(key));
  }

  async put(keyOrEntries, value) {
    const entries = typeof keyOrEntries === 'string' ? { [keyOrEntries]: value } : keyOrEntries;
    for (const [k, v] of Object.entries(entries)) {
      this.data.set(k, structuredClone(v));
    }
  }

  async delete(keys) {
    for (const k of Array.isArray(keys) ? keys : [keys]) {
      this.data.delete(k);
    }
  }

  async deleteAll() {
    this.data.clear();
  }

  async list({ prefix = '', start = '' } = {}) {
    const keys = [...this.data.keys()].filter((k) => k.startsWith(prefix) && k >= start).sort();
    return new Map(keys.map((k) => [k, structuredClone(this.data.get(k))]));
  }

  async setAlarm(when) {
    clearTimeout(this.alarmTimer);
    this.alarmTimer = setTimeout(() => this.onAlarm(), Math.max(0, when - Date.now()));
    this.alarmTimer.unref();
  }

  async deleteAlarm() {
    clearTimeout(this.alarmTimer);
    this.alarmTimer = null;
  }
}

class MemoryNamespace {
  constructor(env) {
    this.env = env;
    this.objects = new Map();
  }

  idFromName(name) {
    return name;
  }

  get(id) {
    if (!this.objects.has(id)) {
      let object;
      const storage = new MemoryStorage(() => object.alarm());
      object = new Session({ storage }, this.env);
      this.objects.set(id, object);
    }
    const object = this.objects.get(id);
    return { fetch: (request) => object.fetch(request) };
  }
}

/**
 * Starts the relay on 127.0.0.1 with an ephemeral port. `vars` are the Worker
 * environment variables (for example `SESSION_TTL_SECONDS`). Resolves to
 * `{ url, close }`.
 */
export async function startRelay(vars = {}) {
  const env = { ...vars };
  env.SESSIONS = new MemoryNamespace(env);
  const server = createServer(async (req, res) => {
    try {
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const body = Buffer.concat(chunks);
      const request = new Request(`http://${req.headers.host}${req.url}`, {
        method: req.method,
        headers: Object.entries(req.headers).flatMap(([k, v]) =>
          Array.isArray(v) ? v.map((x) => [k, x]) : [[k, v]],
        ),
        body: ['GET', 'HEAD'].includes(req.method) ? undefined : body,
      });
      const response = await worker.fetch(request, env);
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    } catch (err) {
      res.writeHead(500, { 'content-type': 'text/plain' });
      res.end(String(err && err.message));
    }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address();
  return {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(resolve);
      }),
  };
}
