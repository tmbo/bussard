- One JSON shape per flow, second half (#904): the `--json` output of `scan`, `status`,
  `status <ADDRESS>`, `show`, `history`, `undo`, `backup`, `reconstruct`, `validate`, `audit`,
  `diff`, `groups reserve`, `groups secure`, `keys import`, `keys export`, `export`, `test`,
  `keys enroll`, `secure diag` and `interface secure` is now the object the matching MCP tool
  returns (`knx_find_devices`, the `live` part of `knx_show_device`, `knx_describe_change`,
  `knx_history`, `knx_backup_device`, `knx_reconstruct_device`, `knx_validate`, `knx_audit`,
  `knx_diff_project`, `knx_reserve_groups`, `knx_import_file`, `knx_export`, `knx_run_tests`,
  the enrolment tools, `knx_clear_security_log`, `knx_interface_secure`), which adds only the
  chat envelope and the job fields. The Home Assistant, bus, telegram, project-view and
  model-edit tools return typed results too. Renamed keys: `scan --json` and `knx_find_devices`
  say `devices` (was `found`), `order_number` (was `order`) and `known` (was `model_status`),
  and `missing_from_bus` lists only the scanned range; `diff --json` says `from`/`to` (was
  `a`/`b`) and carries the second side's `source`; `keys import --json` says `path` (was
  `source`); `interface secure --json` says `address` (was `device`); `interface secure` and
  `secure diag` say `reason` (was `error`); `knx_reconstruct_device` returns the comparison as
  `differences` (was `diff`) and drops `identity_line`; a scoped `knx_show_device` lists the
  other pages as `block_summary` and `inactive_channel_summary`. `validate`, `status <ADDRESS>`,
  `scan`, `backup` and `reconstruct` are `schema: 2`. `knx_audit` now has `products`,
  `knx_write_group` `gateway`, and `commission --json` the identification and read-back of each
  device whose address was written.
