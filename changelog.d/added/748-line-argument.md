- `knx_plan_device`, `knx_apply_device` and `knx_reconstruct_device` take
  `line: "1.1"`, the MCP form of `plan --line`, `apply --line` and
  `reconstruct --line` (#748). Each runs through the function the CLI calls,
  now in `bussard-service` (`line`, `reconstruct_line`). A line apply is one
  job with one plan digest over the line; every device is backed up, written
  and verified by its own read-back, and the result lists each device.
