- `knx_discard_edits` on a group address whose Data Secure state the session
  flipped restores the key store as `knx_undo` does (#336). A plan of a Secure
  System B device reads PID 61 only when a security change is pending or no
  earlier read is cached; `apply` and `flash` always read it (#336).
  `flash --json` carries the "Data Secure off for <GA>" line as
  `security_object` (#336).
