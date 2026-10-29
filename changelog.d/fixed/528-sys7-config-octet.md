- The public System 7 CONFIG octet helper `sys7_config_byte` now follows Group
  Object Table Realisation Type 2 like the flash post-pass (bit 7 is the U
  flag, the segment selector and priority come from the product's template)
  and is the one definition both use; the unused `sys7_group_objects` and
  `SYS7_DEFAULT_RAM_FLAGS_PTR` are removed (#528).
