- `services/enroll-relay/`: the hosted relay for certificate enrolment as a
  Cloudflare Worker with one Durable Object per session, implementing the
  Relay API of `dev/enroll-protocol.md` (#731). Its API cases
  (`test/cases.json`) are shared with bussard's local relay. Not deployed yet.
