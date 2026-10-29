- `knx_describe_device` takes the FDSK fallback of `bussard describe` through the
  same service function: a device without a tool key that refuses the plain walk
  and answers under its factory key is reported `factory_key: true` (#571).
  `knx_clear_security_log` clears the security failures log (PID 55) and resets
  the report over MCP, in two calls behind the question `secure diag --clear`
  asks (#571).
