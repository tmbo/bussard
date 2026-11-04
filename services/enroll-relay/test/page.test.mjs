// The enrolment page served by the Worker at /enroll/ (#797): the files of
// web/enroll/, the security headers on every response, and the page policy
// matching the page's own <meta> policy.
//
// Without RELAY_URL it runs against src/worker.js under Node (node-host.mjs);
// with RELAY_URL against any deployment of the Worker, for example
// `wrangler dev` or the hosted relay (README.md, "Deploy").

import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { API_CSP, PAGE_CSP, SECURITY_HEADERS } from '../src/headers.js';
import { startRelay } from './node-host.mjs';

const pageDir = new URL('../../../web/enroll/', import.meta.url);
let base;
let local;

before(async () => {
  if (process.env.RELAY_URL) {
    base = process.env.RELAY_URL.replace(/\/$/, '');
    return;
  }
  local = await startRelay();
  base = local.url;
});

after(async () => {
  await local?.close();
});

function assertSecurityHeaders(res, csp) {
  for (const [name, value] of Object.entries(SECURITY_HEADERS)) {
    assert.equal(res.headers.get(name), value, name);
  }
  if (csp !== undefined) {
    assert.equal(res.headers.get('content-security-policy'), csp);
  }
}

test('test_page_index_served_with_headers', async () => {
  const res = await fetch(`${base}/enroll/`);
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /^text\/html/);
  assert.equal(await res.text(), readFileSync(new URL('index.html', pageDir), 'utf8'));
  assertSecurityHeaders(res, PAGE_CSP);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
});

test('test_page_files_served_with_headers', async () => {
  for (const [file, type] of [
    ['app.js', /javascript/],
    ['enroll.js', /javascript/],
    ['phonekey.js', /javascript/],
    ['ui.js', /javascript/],
    ['style.css', /^text\/css/],
    ['vendor/jsQR.js', /javascript/],
  ]) {
    const res = await fetch(`${base}/enroll/${file}`);
    assert.equal(res.status, 200, file);
    assert.match(res.headers.get('content-type'), type, file);
    assert.equal(await res.text(), readFileSync(new URL(file, pageDir), 'utf8'), file);
    assertSecurityHeaders(res, PAGE_CSP);
  }
});

test('test_page_without_slash_redirects', async () => {
  const res = await fetch(`${base}/enroll`, { redirect: 'manual' });
  assert.equal(res.status, 301);
  assert.equal(new URL(res.headers.get('location'), base).pathname, '/enroll/');
  assertSecurityHeaders(res, PAGE_CSP);
});

test('test_page_unknown_file_is_404', async () => {
  const res = await fetch(`${base}/enroll/missing.js`);
  assert.equal(res.status, 404);
  await res.arrayBuffer();
  assertSecurityHeaders(res, PAGE_CSP);
});

test('test_page_post_is_405', async () => {
  const res = await fetch(`${base}/enroll/`, { method: 'POST', body: 'x' });
  assert.equal(res.status, 405);
  await res.arrayBuffer();
  assertSecurityHeaders(res, PAGE_CSP);
});

test('test_relay_responses_carry_security_headers', async () => {
  for (const path of ['/', '/v1/sessions/AAAAAAAAAAAAAAAAAAAAAA/down']) {
    const res = await fetch(`${base}${path}`);
    assert.equal(res.status, 404, path);
    await res.arrayBuffer();
    assertSecurityHeaders(res, API_CSP);
  }
});

test('test_page_csp_matches_meta_policy', () => {
  // The header policy is the <meta> policy plus frame-ancestors, which only
  // a header can carry. Compared as directive sets.
  const html = readFileSync(new URL('index.html', pageDir), 'utf8');
  const meta = /http-equiv="Content-Security-Policy" content="([^"]+)"/.exec(html);
  assert.ok(meta, 'index.html has a CSP <meta>');
  const directives = (policy) =>
    new Set(policy.split(';').map((d) => d.trim().replace(/\s+/g, ' ')).filter(Boolean));
  const header = directives(PAGE_CSP);
  assert.ok(header.delete("frame-ancestors 'none'"));
  assert.deepEqual(header, directives(meta[1]));
});
