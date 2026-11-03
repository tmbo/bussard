# enroll-relay

The hosted relay for the certificate enrolment protocol (#201, #731): a
Cloudflare Worker that passes encrypted envelopes between `bussard keys
enroll` and the phone page. The contract is `dev/enroll-protocol.md`,
section "Relay API". The relay never decrypts and never logs a body.

```
src/worker.js        the Worker and the Session Durable Object
wrangler.toml        Worker config: one Durable Object class, no account, no route
test/cases.json      the Relay API cases, shared with bussard's local relay (#729)
test/cases.test.mjs  runs the cases with `node --test`
test/node-host.mjs   runs the Worker under Node with in-memory Durable Objects
```

There are no npm dependencies, runtime or dev. `wrangler` is only used to run
the Worker in workerd and to deploy it, through `npx` (see below). It is not
listed in `package.json` because its dependency tree carries LGPL-licensed
optional packages (`sharp`'s libvips binaries, via miniflare); bussard takes
no copyleft dependency, not even a dev-only one.

## How it works

One Durable Object per session id holds the owner token's SHA-256, the two
message queues and the expiry. The Worker routes `/v1/sessions/{sid}[/up|/down]`
to the session's object and adds `Access-Control-Allow-Origin: *` to the two
phone endpoints (`POST up`, `GET down`) and to their `OPTIONS` preflights.
No other response carries a CORS header.

A long poll (`wait`) waits for a post in its direction, the session's
`DELETE`, or its expiry, whichever comes first. The object sets an alarm
for 30 minutes after the `PUT`; the alarm deletes everything. A request that
arrives after expiry but before the alarm deletes the session itself.

Where the protocol leaves a choice, the relay answers as follows (the cases
pin each one):

| situation | answer |
|---|---|
| missing or wrong owner token | `401` (after the `404` check: an unknown session is `404` first) |
| `PUT` with a session id that is not 22 base64url characters | `400`; the other endpoints answer `404` |
| `PUT` body that is not a JSON object | `400` |
| posted body that is not `{"v": 1, "pk", "n", "c"}` with base64url strings | `400` |
| envelope over 4096 bytes, or the 201st message in a direction | `429` |
| `after` or `wait` not a non-negative number | `400`; `wait` above 25 is cut to 25 |
| `POST up` or `POST down` after `DELETE` | `404` |
| `DELETE` again after `DELETE` | `204` |
| `PUT` on a deleted session before it expires | `409` |
| a long poll pending when the session expires | `404` |

`DELETE` drops the messages at once and keeps only the metadata, so reads
answer `{"messages": [], "closed": true}` until expiry.

## Tests

```
cd services/enroll-relay
npm test
```

This runs `test/cases.json` against the Worker under Node (`node-host.mjs`, an
HTTP server and an in-memory stand-in for Durable Object storage and alarms).
CI runs it in the `enroll-relay` job. To run the same cases against workerd,
start two `wrangler dev` instances, one with the short TTL the expiry cases
need, and point the runner at them:

```
npx wrangler@4 dev --ip 127.0.0.1 --port 8787
npx wrangler@4 dev --ip 127.0.0.1 --port 8788 --inspector-port 9230 --var SESSION_TTL_SECONDS:2
RELAY_URL=http://127.0.0.1:8787 RELAY_URL_SHORT_TTL=http://127.0.0.1:8788 npm test
```

`SESSION_TTL_SECONDS` can only shorten the 30 minutes, never lengthen them.
Without `RELAY_URL_SHORT_TTL` the expiry cases are skipped.

## API cases

`test/cases.json` is the conformance list for any relay: this Worker and
bussard's in-process local relay (#729), which runs the same file from Rust.
Top level:

| key | meaning |
|---|---|
| `format` | `1` |
| `short_ttl_seconds` | the session TTL of the relay the `short_ttl` cases run against (2) |
| `fixtures.envelopes` | named envelopes; `up1` and `down1` are the envelopes of `dev/enroll/vectors-v1.json` |
| `fixtures.envelope_bytes_template` | the envelope used to build a body of an exact size |
| `cases` | the list of cases |

A case has a `name`, an optional `relay` (`"default"` or `"short_ttl"`) and
`steps`, run in order. Each case gets a fresh random session id (16 bytes,
base64url) substituted for `{sid}` in paths, and two fresh random tokens
(32 bytes, base64url): `owner` and `other`. Cases are independent and may run
concurrently against one relay.

A step is one of:

- a request: `method`, `path`, and optionally
  - `auth`: `"owner"` or `"other"`, sent as `Authorization: Bearer <token>`;
    omitted means no `Authorization` header;
  - `origin`: sent as the `Origin` header;
  - `headers`: extra request headers;
  - `body`, one of `{"json": value}` (serialized compactly),
    `{"raw": "text"}`, `{"envelope": "<fixture name>"}` (the fixture
    serialized compactly), or `{"envelope_bytes": N}`: the template with `c`
    set to `N - len(template serialized with c = "")` letters `A`, so the
    compact serialization (`{"v":1,"pk":"…","n":"…","c":"AAAA…"}`, keys in
    that order) is exactly N bytes. A body is sent with
    `Content-Type: application/json`;
  - `repeat`: send the same request N times, each checked against `expect`;
  - `async`: a label; the request is sent and the case moves on without
    waiting for the answer;
  - `expect` (below).
- `{"await": "<label>", "expect": {…}}`: wait for an `async` request and check it.
- `{"sleep_ms": N}`.

`expect` holds any of:

- `status`: the HTTP status;
- `json`: the response body, compared as JSON values (key order ignored);
  `{"$envelope": "<name>"}` anywhere in it stands for that fixture;
- `headers`: response header name to exact value, or `null` for "absent";
- `min_ms`, `max_ms`: bounds on the time from sending the request to the
  complete answer.

## Deploy

Deployment is the owner's decision (#731: account and hostname). Nothing in
this directory names an account or a route. With a Cloudflare account on the
Workers Free plan or higher (SQLite-backed Durable Objects are available on
both):

1. `cd services/enroll-relay && npx wrangler@4 login`.
2. Pick the hostname, for example `relay.bussard.tmbo.dev`, on a zone in that
   account, and add the route to `wrangler.toml`:

   ```toml
   routes = [{ pattern = "relay.bussard.tmbo.dev", custom_domain = true }]
   ```

3. `npx wrangler@4 deploy`. The first deploy applies migration `v1`, which
   creates the `Session` Durable Object class.
4. Check it: `curl -i https://relay.bussard.tmbo.dev/v1/sessions/AAAAAAAAAAAAAAAAAAAAAA/down`
   answers `404` with `access-control-allow-origin: *`. Or run the cases
   against it: `RELAY_URL=https://relay.bussard.tmbo.dev npm test` (the
   expiry cases are skipped).
5. Set bussard's default relay URL to the hostname (#201, #729).

Keep Workers Logs off (`[observability] enabled = false`): request URLs carry
session ids. Do not add `console.log` to the Worker; `wrangler tail` would
show it. Do not set `SESSION_TTL_SECONDS` in production; it exists for tests.
