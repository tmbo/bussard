- Certificate enrolment over MCP and in local mode (#732): the tools
  `knx_enroll_certificates` (returns the link and the fingerprint) and
  `knx_enroll_status` (serial, address, name and status per label) run the
  `bussard keys enroll` session in the server process; no tool input or
  output carries a label or a key. `bussard keys enroll --local` and
  `local: true` serve the enrolment page and the relay on 127.0.0.1, one
  origin, for a browser on the same computer without a hosted relay.
- `bussard keys enroll` defaults to the hosted relay
  `https://relay.bussard.tmbo.dev` (`--relay`, then `[enroll] relay`, then
  the default); `--relay` is no longer required (#732).
