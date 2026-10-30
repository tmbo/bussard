- `flash` runs `LdCtrlDelay`: the op pauses the download for its
  `MilliSeconds` on System B and System 7, shows as a step in the plan and in
  the `-v` log, and no longer refuses the 16 System 7 (0701) applications that
  put a 200 ms delay before the restart (#615).
