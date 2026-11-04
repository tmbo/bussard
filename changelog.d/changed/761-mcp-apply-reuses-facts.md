- `knx_apply_device` reuses the device facts its digest check read for the
  table write, the parameter write and the read-back, as `bussard apply`
  does, instead of reading the device descriptor, the maximum APDU length and
  the interface objects again on each connection; an apply over MCP now sends
  the same requests as the CLI (#761).
