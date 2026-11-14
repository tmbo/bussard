- `flash` plans `LdCtrlMasterReset` on System 7 when the procedure resets the
  device before its load: the confirmed Master Reset with the op's erase code,
  then a reconnect, as ETS sends it (#1065, the Hager 0701 `A-E0ED-10-0B6F`).
  A reset after the load has begun stays refused.
