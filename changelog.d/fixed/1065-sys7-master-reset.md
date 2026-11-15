- `flash` plans `LdCtrlMasterReset` on System 7 when the procedure resets the
  device before its load: the confirmed Master Reset with the op's erase code,
  then a reconnect, as ETS sends it (#1065, the Hager 0701 `A-E0ED-10-0B6F`).
  A reset after the load has begun stays refused. Also refused: a reset that
  would undo an earlier step of the procedure (a property write is read back,
  unless the program's `LoadedImage` restores another value there), a reset
  whose erased load-state machines are not loaded again after it, a reset of
  the individual address (erase codes 2 and 3) and a value beyond one octet.
  The parameter-only download refuses a System 7 reset instead of dropping it.
