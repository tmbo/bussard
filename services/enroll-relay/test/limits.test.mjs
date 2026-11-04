// The Worker's own limit, outside the shared cases (bussard's local relay
// has none): session creations per client IP per minute
// (dev/enroll-protocol.md, "Relay API").

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { startRelay } from './node-host.mjs';

let relay;

before(async () => {
  relay = await startRelay({ CREATES_PER_IP_PER_MINUTE: '3' });
});

after(async () => {
  await relay.close();
});

const b64url = (bytes) => Buffer.from(bytes).toString('base64url');

async function create(ip) {
  const headers = {
    authorization: `Bearer ${b64url(randomBytes(32))}`,
    'content-type': 'application/json',
  };
  if (ip) headers['cf-connecting-ip'] = ip;
  const response = await fetch(`${relay.url}/v1/sessions/${b64url(randomBytes(16))}`, {
    method: 'PUT',
    headers,
    body: '{}',
  });
  await response.text();
  return response.status;
}

test('test_create_limit_per_client_ip', async () => {
  for (let i = 0; i < 3; i += 1) {
    assert.equal(await create('203.0.113.7'), 201);
  }
  assert.equal(await create('203.0.113.7'), 429);
  // Another address has its own budget.
  assert.equal(await create('198.51.100.2'), 201);
});

test('test_create_limit_skipped_without_client_ip', async () => {
  for (let i = 0; i < 5; i += 1) {
    assert.equal(await create(null), 201);
  }
});
