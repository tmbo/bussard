- The safety net around an apply is in chat (#717): `knx_backup_device` and
  `knx_reconstruct_device` (default tier, read-only on the bus, not in
  `--passive`) back devices up and diff a device's tables against the model;
  `knx_restore_tables` and `knx_restart_device` (programming tier) write a
  backup's link tables back with `knx_apply_device`'s write and read-back, and
  restart a device in the form ETS uses, each after the human's yes. They call
  the `bussard-service` functions `bussard backup`, `reconstruct`, `restore`
  and `restart` use.
