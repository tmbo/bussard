- The offline oracle has `run=flash` rows: knx-sim replays ETS's first download,
  bussard flashes against it, and the row judges the state the device ends with
  (memory, property values, load states), showing and optionally pinning whether
  bussard kept objects (`skip=taken|none`) next to both operation lists. The rows
  come from `flash_rows` in `captures/synthetic/manifest.json` (#1127).
