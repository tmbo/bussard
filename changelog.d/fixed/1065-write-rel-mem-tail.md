- `flash` no longer refuses a program whose parameter reaches past its
  `LdCtrlWriteRelMem` `Size` when the octets past it hold the fill byte of the
  segment's filled allocation: the device holds them without a write, as in
  ETS's download (#1065, the Gira push-button rockers `A-1161-23-518D` and
  `A-1162-21-2E13`).
