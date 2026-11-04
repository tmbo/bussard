// Response headers of the enrolment Worker (#797). A module of its own
// because a Worker's entry module may export only handlers and classes.

/**
 * The page's policy. It repeats the `<meta>` policy of web/enroll/index.html
 * (page.test.mjs checks that) and adds `frame-ancestors`, which a `<meta>`
 * policy cannot carry. The network is this origin only: the relay.
 */
export const PAGE_CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
  "media-src 'self' blob: mediastream:; connect-src 'self'; base-uri 'none'; " +
  "form-action 'none'; manifest-src 'none'; worker-src 'none'; frame-src 'none'; " +
  "object-src 'none'; frame-ancestors 'none'";

/** The policy of every other response (relay JSON, errors, redirects). */
export const API_CSP = "default-src 'none'; frame-ancestors 'none'";

/** Headers on every response. */
export const SECURITY_HEADERS = {
  'strict-transport-security': 'max-age=31536000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'x-frame-options': 'DENY',
};
