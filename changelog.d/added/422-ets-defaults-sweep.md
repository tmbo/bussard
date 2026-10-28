- The ETS defaults sweep (`tools/ets-sweep/defaults.py`, `oracle.py`) has ETS
  download every corpus application into knx-sim and compares each capture
  with bussard's dry-run flash (epic #419, part 3 #422). knx-sim answers
  connectionless descriptor and property reads, and takes per-device property
  overrides (`properties:`) for the identity ETS checks before a download.
