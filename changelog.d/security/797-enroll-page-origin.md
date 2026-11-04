- The certificate enrolment page moved to `https://bussard-relay.tmbo.dev/enroll/`,
  served by the relay's Worker on the relay's origin with a CSP header
  (`connect-src 'self'`, `frame-ancestors 'none'`), HSTS, `nosniff` and
  `Referrer-Policy: no-referrer` (#797). It is no longer part of the docs
  site; `https://bussard.tmbo.dev/enroll/` shows a notice. This is the new
  default `[enroll] page`. The CI workflows pin every action to a commit SHA,
  the docs toolchain installs with `--require-hashes`, and the vendored jsQR
  1.4.0 has its sha256 recorded and checked.
