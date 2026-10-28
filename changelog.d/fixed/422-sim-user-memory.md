- knx-sim answers `A_UserMemory_Write` and `A_UserMemory_Read` (20-bit
  addresses, read-back response in verify mode): ETS writes a segment above
  0xFFFF with them on devices without the extended memory service (Zennio
  DALIBOX, a 418 kB object at 0x10000) (#422).
