- `read`, `monitor`, `write` and the MCP group tools know the word pair of every
  `1.xxx` sub-type of KNX 03_07_02 §3.1 and `1.100` (#499): a `1.018` presence
  object shows `Occupied`, a `1.019` contact `Closed`, and `write <ga> night`
  works on a `1.024` address. `1.009` now reads `Close` (was `Closed`), the
  spec's word.
