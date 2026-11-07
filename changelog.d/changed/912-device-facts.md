- One device facts record (#912): the flash download is seeded from the
  stored facts record instead of a second `DeviceFacts` struct, the
  lock-key derivation in bussard-project is named `LockKeys`, and a backup
  run's per-device result is its manifest row. No change to what is written
  to a device or to the backup files.
