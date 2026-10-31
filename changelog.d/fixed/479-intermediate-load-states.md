- A load-state machine that answers `Unloading` (4) or `LoadCompleting` (5)
  no longer fails the flash: bussard names both states and re-reads every 3 s
  for up to 30 s (KNX 3/5/1 §4.23.2.4.1, 3/5/2 §3.31.4.1) on System B and on
  both System 7 forms (0705 property, 0701 memory-mapped), then fails with
  the last state. knx-sim's `intermediate_load_states` device option reports
  them (#479).
