- `flash` plans `LdCtrlMasterReset` on System 7 when the procedure resets the
  device before its load: the confirmed Master Reset with the op's erase code,
  then a reconnect, as ETS sends it (#1065, the Hager 0701 `A-E0ED-10-0B6F`).
  A reset after the load has begun stays refused.
  A reset that would undo an earlier step of the procedure (other than a
  property write, which is read back), a reset of the individual address
  (erase codes 2 and 3) and a value beyond one octet are refused; the
  parameter-only download refuses a System 7 reset instead of dropping it.
