- knx-sim's devices run a Style 3 transport layer (03_03_04 §5.4.3 with
  AN210) (#511): an out-of-window numbered telegram draws a `T_NAK`, a
  repeated `T_Connect` from the connected client is ignored with the
  sequences kept, one from another client is refused with `T_Disconnect`, a
  connection idle for 6 s closes with a `T_Disconnect`, an unacknowledged
  response is repeated every 3 s up to three times, and `T_ACK`/`T_NAK` from
  the client are honoured. Transport control frames go out at system
  priority. The `l4_strict_drop` device option (or
  `Device::with_strict_l4_drop`) keeps the old silent drop for desync tests.
