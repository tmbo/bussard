- The synthetic products `syn-user-memory` ("Big prey larder", `NEST-LARDER`,
  #604 row 22) and its twin `syn-user-memory-extmem` (`NEST-LARDERX`) carry an
  8448-octet parameter segment that knx-sim places at 0x10000, without and
  with `SupportsExtendedMemoryServices`, captured with ETS: ETS writes it with
  `A_UserMemory_Write` without the option and `A_MemoryExtended_Write` with
  it, as bussard does since #472; both rows are identical.
