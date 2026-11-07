- knx-sim answers `PID_MCB_TABLE` of a loadable object the tool streamed
  nothing into with an empty image (size 0, the CRC of no octets) instead of
  refusing the read: ETS loads object 4 of the Schneider STYAS6xx programs
  empty and reported a read of a protected memory area (#422).
