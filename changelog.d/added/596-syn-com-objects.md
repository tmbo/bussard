- The synthetic product `syn-com-objects` ("Chirp switchboard",
  `NEST-CHIRP`, #604 row 27) has one com object per size from 1 bit to 14
  bytes, every combination of the C, R, W, T and U flags, priorities Low,
  High and Alert and a read-on-init object, captured with ETS as the
  regression row of the group-object descriptors (#541, #545, #540). It
  differs in one descriptor: an unlinked object with no flags, which ETS
  writes and bussard leaves at `00 00` (#686, row `expect=differs`).
