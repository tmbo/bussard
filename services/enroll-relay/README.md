# enroll-relay

The hosted relay for the certificate enrolment protocol (#201, #731): a
Cloudflare Worker that passes encrypted envelopes between `bussard keys
enroll` and the phone page. The same Worker serves that page
(`web/enroll/`) at `/enroll/`, so page and relay are one origin (#797). The contract is `dev/enroll-protocol.md`,
section "Relay API". The relay never decrypts and never logs a body.

```
src/worker.js        the Worker (page and relay routes) and the Session Durable Object
src/headers.js       the security headers and the page's CSP
wrangler.toml        Worker config: the page as static assets, one Durable Object class
test/cases.json      the Relay API cases, shared with bussard's local relay (#729)
test/cases.test.mjs  runs the cases with `node --test`
test/page.test.mjs   the page routes and the headers of every response
test/limits.test.mjs the Worker-only limit: session creations per client IP
test/node-host.mjs   runs the Worker under Node with in-memory Durable Objects
                     and web/enroll/ as the assets binding
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
`DELETE`, or its expiry, whichever comes first. At most 4 long polls wait per
direction; a fifth answers the oldest at once with what it has, so a phone
that reloaded is never locked out by its own stale polls.

The expiry slides: 15 minutes after the session's last write (the `PUT` or
an accepted `POST`), never later than 4 hours after the `PUT`. Reads and
`DELETE` do not move it. The object keeps its alarm on the current expiry;
the alarm deletes everything. A request that arrives after expiry but
before the alarm deletes the session itself.

A second Durable Object class, `CreateLimit`, keeps one counter per client
IP (`CF-Connecting-IP`): at most 10 `PUT`s per IP in a one-minute window,
`429` beyond. Without that header (not behind Cloudflare) nothing is
counted.

Where the protocol leaves a choice, the relay answers as follows (the cases
pin each one):

| situation | answer |
|---|---|
| missing or wrong owner token | `401` (after the `404` check: an unknown session is `404` first) |
| `PUT` with a session id that is not 22 base64url characters | `400`; the other endpoints answer `404` |
| `PUT` body that is not a JSON object | `400` |
| posted body that is not `{"v": 2, "pk", "n", "c"}` with base64url strings | `400` |
| envelope over 4096 bytes, or the 501st message in a direction | `429` |
| a fifth long poll in one direction | `200`; the oldest open one answers at once |
| the 11th `PUT` from one client IP within a minute (Worker only) | `429` |
| `after` or `wait` not a non-negative number | `400`; `wait` above 25 is cut to 25 |
| `POST up` or `POST down` after `DELETE` | `404` |
| `DELETE` again after `DELETE` | `204` |
| `PUT` on a deleted session before it expires | `409` |
| a long poll pending when the session expires | `404` |

## The page

`wrangler.toml` binds `../../web/enroll` as static assets (`ASSETS`), as it
is in the repository: no build step, no copy. `run_worker_first = true`
sends every request through the Worker, so no file is served without its
headers. The Worker maps `/enroll/` to `index.html` and `/enroll/<file>` to
`<file>`, redirects `/enroll` to `/enroll/` (`301`; the browser keeps the
link's fragment), answers `405` to anything but `GET` and `HEAD` there, and
sets `Cache-Control: no-cache` so a deploy reaches phones at once.

Every response, page or relay, carries:

| header | value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | page: the `<meta>` policy of `index.html` plus `frame-ancestors 'none'` (`connect-src 'self'`); relay: `default-src 'none'; frame-ancestors 'none'` |

`test/page.test.mjs` checks that the header policy and the page's `<meta>`
policy name the same directives. The old address,
`https://bussard.tmbo.dev/enroll/`, now holds a notice without script
(`website/enroll/index.html`).

`DELETE` drops the messages at once and keeps only the metadata, so reads
answer `{"messages": [], "closed": true}` until expiry.

## Tests

```
cd services/enroll-relay
npm test
```

This runs `test/cases.json` and `test/page.test.mjs` against the Worker under
Node (`node-host.mjs`, an HTTP server, an in-memory stand-in for Durable
Object storage and alarms, and `web/enroll/` as the assets binding).
CI runs it in the `enroll-relay` job. To run the same cases against workerd,
start two `wrangler dev` instances, one with the short lifetimes the expiry
cases need, and point the runner at them. Raise the creation limit for the
run, since the cases create sessions faster than a person does:

```
npx wrangler@4 dev --ip 127.0.0.1 --port 8787 --var CREATES_PER_IP_PER_MINUTE:1000
npx wrangler@4 dev --ip 127.0.0.1 --port 8788 --inspector-port 9230 \
  --var SESSION_IDLE_SECONDS:2 --var SESSION_MAX_SECONDS:4 --var CREATES_PER_IP_PER_MINUTE:1000
RELAY_URL=http://127.0.0.1:8787 RELAY_URL_SHORT=http://127.0.0.1:8788 npm test
```

`SESSION_IDLE_SECONDS` and `SESSION_MAX_SECONDS` can only shorten the
15 minutes and 4 hours, never lengthen them. Without `RELAY_URL_SHORT` the
expiry cases are skipped.

## API cases

`test/cases.json` is the conformance list for any relay: this Worker and
bussard's in-process local relay (#729), which runs the same file from Rust.
Top level:

| key | meaning |
|---|---|
| `format` | `2` |
| `short` | `idle_seconds` (2) and `max_seconds` (4): the lifetimes of the relay the `short` cases run against |
| `fixtures.envelopes` | named envelopes; `up1` and `down1` are the first certificate and its result in `dev/enroll/vectors-v2.json` |
| `fixtures.envelope_bytes_template` | the envelope used to build a body of an exact size |
| `cases` | the list of cases |

A case has a `name`, an optional `relay` (`"default"` or `"short"`) and
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
    compact serialization (`{"v":2,"pk":"…","n":"…","c":"AAAA…"}`, keys in
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

The project's relay runs on the owner's Cloudflare account at
`bussard-relay.tmbo.dev` (decided 2026-11-03, #731; one label below the
zone, because Cloudflare's universal certificate covers `*.tmbo.dev` but not
`*.bussard.tmbo.dev`, where the first choice never got a certificate); `wrangler.toml` carries
that route and turns the `workers.dev` URL off. On the Workers Free plan or
higher (SQLite-backed Durable Objects are available on both):

1. `cd services/enroll-relay && npx wrangler@4 login`.
2. `npx wrangler@4 deploy`. The first deploy applies migrations `v1` and
   `v2`, which create the `Session` and `CreateLimit` Durable Object
   classes. Every deploy uploads `web/enroll/` as the Worker's static
   assets, so deploy again after a change to the page.
3. Check the relay: `curl -i https://bussard-relay.tmbo.dev/v1/sessions/AAAAAAAAAAAAAAAAAAAAAA/down`
   answers `404` with `access-control-allow-origin: *`.
4. Check the page (#797): `curl -sI https://bussard-relay.tmbo.dev/enroll/`
   answers `200` with `content-type: text/html`, `content-security-policy`
   ending in `frame-ancestors 'none'` and containing `connect-src 'self'`,
   `strict-transport-security`, `x-content-type-options: nosniff`,
   `referrer-policy: no-referrer` and `x-frame-options: DENY`.
5. Or run both suites against it: `RELAY_URL=https://bussard-relay.tmbo.dev npm test`
   (the expiry cases are skipped). The cases create about 30 sessions, so
   from one address they run into the limit of 10 per minute; the page
   suite alone does not.

The same checks run locally against `npx wrangler@4 dev --ip 127.0.0.1 --port 8787`
(`RELAY_URL=http://127.0.0.1:8787 npm test`); the assets binding works
there too.

The deploy of #797 moves the page's default address from
`https://bussard.tmbo.dev/enroll/` (GitHub Pages) to
`https://bussard-relay.tmbo.dev/enroll/`. The site workflow replaces the old
page with the moved notice on the first push to `main` after the merge, so
deploy the Worker right after that merge; until then no hosted page answers.

A self-hosted copy replaces the `routes` entry with a hostname on its own
zone, and needs a self-hosted page too (`[enroll] page` and `relay` in
`bussard.toml`), because the hosted page only connects to the project's relay.

Keep Workers Logs off (`[observability] enabled = false`): request URLs carry
session ids. Do not add `console.log` to the Worker; `wrangler tail` would
show it. Do not set `SESSION_IDLE_SECONDS`, `SESSION_MAX_SECONDS` or
`CREATES_PER_IP_PER_MINUTE` in production; they exist for tests.

The code limits (messages, envelope size, long polls, creations per IP) are
the relay's own. A Cloudflare rate-limiting rule on the dashboard and a
billing alert are the owner's, outside this repository.
