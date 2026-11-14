- knx-sim simulates a BCU 2 (System 2, masks 0020, 0021 and 0025): the three
  property-driven load-state machines with the KNX 3/5/2 §3.31.3 records, the
  BCU 2 memory map and system table, and four access levels (#525). 90 of the
  94 corpus BCU 2 programs load with their own procedure; the ETS sweep now
  starts them, and the synthetic product `syn-bcu2-0021` waits for its first
  capture. bussard still refuses to flash a BCU 2.
