- knx-sim: the `master_reset` device option models a device without the
  Master Reset: `refuse` answers every erase code with error code 2 and runs
  nothing, `basic` runs the request as a Basic Restart without an answer
  (default `supported`). The synthetic capture tooling has a `bare-restart`
  run variant of `syn-master-reset` that uses `refuse`; ETS 6.4.1 fails that
  download with "UnsupportedEraseCode" (#611).
