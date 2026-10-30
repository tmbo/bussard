- Synthetic product `syn-s7-lsm5` (Fifth-twig sensor, `NEST-TWIG5`):
  `syn-s7-0701` with a TaskSegment on LsmIdx 5 inside LSM 3's load, captured
  with ETS (#604 row 15). ETS sends no LSM 5 record; bussard sends the
  TaskSegment and fails against knx-sim, which the sim-loop baseline lists
  under #489.
