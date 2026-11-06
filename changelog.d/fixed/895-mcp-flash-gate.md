- The assistant's flash and application load now ask the factory-freshness
  gate `bussard flash` decides with, without `--force`: a device that runs
  another application is refused there too (it was loaded over on a plan's
  yes), naming `bussard flash --force` at the terminal. The plan digest's
  device fingerprint is now the `state_hash` the plan reports, and the
  lock-pin override rule lives in the service with the CLI (#895).
