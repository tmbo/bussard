- The offline oracle compares load control with ETS (#419): every record bussard
  sends a load-state machine (Unload, StartLoading, LoadCompleted, the segment,
  TaskSegment and TaskCtrl records, as `PID_LOAD_STATE_CONTROL` or as the System 7
  memory-mapped record at 0x0104) against the capture, per object in order, as
  its own verdict next to the memory and property verdicts. `flash --dry-run
  --dump-images` lists the records per step in `plan.json`, and a rows file pins
  the expected verdict with `loadctl=`.
