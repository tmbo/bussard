- `apply` and `flash` of a Data Secure device read the security object's load
  state (PID 5) back and are not verified unless it is Loaded; a write that
  stops between the security object's Unload and LoadCompleted says that the
  device now drops every secured group telegram and that `bussard apply <ia>`
  again is the remedy (#534).
