- A list of supported devices ships in the binary (#1089): the application
  programs bussard has checked against ETS, each with its category and
  evidence (#1097). `flash`, `apply` (also `--line`),
  `restore`, `replace` and `commission --flash/--apply` refuse a device that
  is not on it on a real gateway, before anything is written;
  `--allow-unsupported` writes it anyway and the history record says
  `support: forced`. A loopback gateway reports the verdict but never
  refuses. `plan`, `describe` and `device` print the verdict, and
  `bussard device --supported` lists the entries. Over MCP,
  `knx_show_device`, `knx_find_devices` and `knx_plan_device` carry
  `support`; the write tools refuse with `code: unsupported_device` and take
  `allow_unsupported: true` only with the digest of a plan that reported the
  device unsupported. Reads are not affected.
