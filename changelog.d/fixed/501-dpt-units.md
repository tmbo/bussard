- `read`, `monitor` and the MCP tools show the unit of every integer and float
  sub-type of KNX 03_07_02 §3.5-§3.15 (#501): `7.600` reads `6500 K`, `13.100`
  `3600 s`, `9.002` `20 K`, `5.004` `50 %`, counters `pulses`, and `write`
  accepts the same suffix (`write <ga> "6500 K"`). A `5.003` angle decodes to
  one decimal (`180.7 °`) instead of truncating to whole degrees.
