- The offline oracle has `run=flash` rows: knx-sim replays ETS's first download,
  bussard flashes the same application against it, and the row judges the state
  the device ends with (memory, property values, load states), showing whether
  bussard's resident check wrote nothing (`skip=`) and both operation lists
  (#1127).
