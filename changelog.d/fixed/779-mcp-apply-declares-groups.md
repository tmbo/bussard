- `knx_apply_device`, with `address` and with `line`, declares the group
  addresses the device files use but `groups.toml` does not define before it
  writes, as `bussard apply` and `apply --line` do, through the same function;
  the result lists them in `declared` (#779).
