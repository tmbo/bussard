- Certificate enrolment speaks protocol v2: one phone per session (another
  phone that opens the link is refused and reported), a slow session code
  (PBKDF2, 10^6 iterations), a session ends when no phone joins within 10
  minutes, 15 minutes after the phone's last sign of life (the open page
  sends one every 5) or after 4 hours, an `invalid` result names no device,
  the relay must be https (plain http only on loopback), and a page or relay
  other than the default gets a warning (#796).
- The relays expire a session 15 minutes after its last write (at most 4
  hours), keep at most 4 long polls per direction, allow 500 messages per
  direction, and the hosted relay allows 10 new sessions per client IP and
  minute (#796).
