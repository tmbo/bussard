- Internal: `bussard flash` (also `--parameters-only` and `--dry-run`),
  `plan`, `apply` and `restore` and the MCP tier's `knx_plan_device`,
  `knx_apply_device` and `knx_restore_tables` read, plan and write a device
  through one module, `bussard_service::program`: one read of identity,
  tables, parameter memory, PID 54 and PID 61, one plan with its
  fingerprints, one table and parameter write ending in the independent
  read-back, one flash with its freshness gate and lock update, and one
  observer for progress and the question. The bytes written, the CLI output
  and the MCP result keys are unchanged. The MCP tier's device read now opens
  its session as the CLI's does: it waits for a reconnecting tunnel and
  retries a connect a gateway link loss cut short (#901).
