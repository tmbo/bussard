- The MCP server talks to a homeowner (#306). The server instructions say who
  reads the replies and how to name things (rooms, device, channel and group
  names; ids only in tool calls). Every edit, undo, discard, pending change,
  plan, apply, restore, restart, backup, read-back and Home Assistant result
  carries a `summary` in names, and an edit's `validation` a `for_the_human`
  line. `knx_plan_device` adds `what_you_will_notice`: the device and room,
  how long the write takes, what keeps working, the changes in plain words and
  what to test afterwards. `knx_show_device`, `knx_get_group` and
  `knx_model_lookup` take `technical` like `knx_get_device`: by default they
  leave out the ETS ids and wire detail, and `technical: true` returns the
  payload as before. `next_step` names devices by name and room.
