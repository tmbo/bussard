- The offline oracle compares partial downloads: a `run=apply` row starts
  knx-sim from ETS's state before the step (the earlier captures replayed with
  the new `replay:` config key), runs `bussard apply` against it and compares
  the device memory after it and the load-control records with ETS's partial
  download (`knxtrace statediff`); `tools/ets-sweep/apply_rows.py` writes the
  rows of a recorded series (#469).
