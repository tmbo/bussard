// Runs the data-driven Relay API cases in cases.json. The format is described
// in README.md ("API cases"); bussard's local relay (#729) runs the same file.
//
// Without RELAY_URL the cases run against src/worker.js under Node
// (node-host.mjs). With RELAY_URL (and RELAY_URL_SHORT_TTL for the expiry
// cases, a relay whose sessions expire after `short_ttl_seconds`) they run
// against any relay, for example `wrangler dev`.

import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { startRelay } from './node-host.mjs';

const spec = JSON.parse(readFileSync(new URL('./cases.json', import.meta.url), 'utf8'));
const relays = {};
const local = [];

before(async () => {
  if (process.env.RELAY_URL) {
    relays.default = process.env.RELAY_URL.replace(/\/$/, '');
    if (process.env.RELAY_URL_SHORT_TTL) {
      relays.short_ttl = process.env.RELAY_URL_SHORT_TTL.replace(/\/$/, '');
    }
    return;
  }
  const normal = await startRelay();
  const short = await startRelay({ SESSION_TTL_SECONDS: String(spec.short_ttl_seconds) });
  local.push(normal, short);
  relays.default = normal.url;
  relays.short_ttl = short.url;
});

after(async () => {
  await Promise.all(local.map((relay) => relay.close()));
});

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

/** Replaces every `{"$envelope": name}` with that fixture. */
function resolve(value) {
  if (Array.isArray(value)) {
    return value.map(resolve);
  }
  if (value && typeof value === 'object') {
    if (Object.keys(value).length === 1 && '$envelope' in value) {
      return spec.fixtures.envelopes[value.$envelope];
    }
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, resolve(v)]));
  }
  return value;
}

function bodyText(body) {
  if ('json' in body) return JSON.stringify(body.json);
  if ('raw' in body) return body.raw;
  if ('envelope' in body) return JSON.stringify(spec.fixtures.envelopes[body.envelope]);
  if ('envelope_bytes' in body) {
    const base = JSON.stringify(spec.fixtures.envelope_bytes_template);
    const pad = 'A'.repeat(body.envelope_bytes - Buffer.byteLength(base));
    return JSON.stringify({ ...spec.fixtures.envelope_bytes_template, c: pad });
  }
  throw new Error(`unknown body ${JSON.stringify(body)}`);
}

async function send(base, ctx, step) {
  const headers = { ...(step.headers || {}) };
  if (step.auth) headers.authorization = `Bearer ${ctx.tokens[step.auth]}`;
  if (step.origin) headers.origin = step.origin;
  let body;
  if (step.body) {
    body = bodyText(step.body);
    headers['content-type'] = 'application/json';
  }
  const started = Date.now();
  const response = await fetch(base + step.path.replaceAll('{sid}', ctx.sid), {
    method: step.method,
    headers,
    body,
  });
  const text = await response.text();
  return { response, text, elapsed: Date.now() - started };
}

function check(label, result, expect) {
  const { response, text, elapsed } = result;
  if (expect.status !== undefined) {
    assert.equal(response.status, expect.status, `${label}: status (body ${text})`);
  }
  if (expect.json !== undefined) {
    assert.deepEqual(JSON.parse(text), resolve(expect.json), `${label}: body`);
  }
  for (const [name, value] of Object.entries(expect.headers || {})) {
    assert.equal(response.headers.get(name), value, `${label}: header ${name}`);
  }
  if (expect.min_ms !== undefined) {
    assert.ok(elapsed >= expect.min_ms, `${label}: took ${elapsed} ms, expected at least ${expect.min_ms}`);
  }
  if (expect.max_ms !== undefined) {
    assert.ok(elapsed <= expect.max_ms, `${label}: took ${elapsed} ms, expected at most ${expect.max_ms}`);
  }
}

describe('relay API cases', { concurrency: true }, () => {
  for (const c of spec.cases) {
    const relay = c.relay || 'default';
    test(c.name, async (t) => {
      const base = relays[relay];
      if (!base) {
        t.skip(`no ${relay} relay (set RELAY_URL_SHORT_TTL)`);
        return;
      }
      const ctx = {
        sid: b64url(randomBytes(16)),
        tokens: { owner: b64url(randomBytes(32)), other: b64url(randomBytes(32)) },
      };
      const pending = {};
      for (const [index, step] of c.steps.entries()) {
        const label = `step ${index + 1}`;
        if (step.sleep_ms !== undefined) {
          await new Promise((r) => setTimeout(r, step.sleep_ms));
        } else if (step.await !== undefined) {
          check(label, await pending[step.await], step.expect);
        } else if (step.async !== undefined) {
          pending[step.async] = send(base, ctx, step);
        } else {
          for (let i = 0; i < (step.repeat || 1); i += 1) {
            check(`${label} #${i + 1}`, await send(base, ctx, step), step.expect);
          }
        }
      }
    });
  }
});
