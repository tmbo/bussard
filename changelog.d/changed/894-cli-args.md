- Internal: each CLI subcommand is now an arguments struct that runs itself,
  the thin wrapper modules around `bussard-service` are gone, and the three
  progress displays are one. No change to flags, help text or `--json` output
  (#894).
