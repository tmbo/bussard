- One JSON shape per flow (#904): the `--json` output of `plan`, `plan --line`, `apply --line`,
  `flash`, `flash --parameters-only`, `restart`, `assign`, `commission`, `describe`, `read` and
  `write` is now the same object the matching MCP tool returns, which adds only `summary`,
  `next_step`, `what_you_will_notice` and the job fields. These shapes are `schema: 2`. Renamed or
  moved keys: `plan` → `table_plan` and the MCP plan's `parameters` → `parameter_plan` (the
  CLI's parameter read-back stays `parameters`), `identity` is the verdict object everywhere (no
  longer a sentence), `unchanged` is the list of links, line runs carry `total`, `changed`,
  `unchanged`, `skipped`, `failed` at the top (no `totals`), `flash --json` says `address`,
  `mask` and `device`/`model` (was `device`, `device_mask`, `old`/`new`), `assign --json` says
  `address` and nests the read-back under `readback` (was `to` and top-level fields),
  `describe --json` and `read --json` say `reason` (was `error`), `knx_write_group` drops the
  nested `written` object, `knx_restart_device` drops `outcome`, an interface apply says
  `properties_written` (was `written`), and absent values are left out instead of `null`.
