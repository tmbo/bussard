- knx-sim's System 7 devices take ETS's partial download: the load-status
  bytes at 0xB6EA+ answer whichever way load control is driven, and each
  object reports the program id its TaskSegment record carried as PID 13
  (the `ApplicationId` ETS reads back first) (#433).
