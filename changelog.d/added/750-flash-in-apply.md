- `knx_apply_device` loads the application program `bussard.lock` pins when a
  device runs another one or none (#750). `knx_plan_device` says in its
  sentences that the application must be loaded and what it replaces, and one
  yes to its digest runs the load, the read-back and the lock update as one
  job. The flash flow (pre-flight, freshness decision, download with its
  read-back, lock update) moved from the CLI into `bussard-service`, and
  `bussard flash` and the tool both run it.
