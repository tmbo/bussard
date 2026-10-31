- The offline oracle no longer fails rows on ETS-only writes it cannot compare
  (the security object's tool key, send sequence and activation mode command,
  and `PID_PROGMODE` from the address assignment): they are listed as not
  compared. A row that pins `props=` is judged on its memory verdict, with the
  property verdict checked by the pin, so a known property difference no longer
  hides a memory difference (#683).
