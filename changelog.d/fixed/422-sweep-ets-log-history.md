- The ETS sweep keeps the `ETS6.log` lines that end a run as "ets logged a
  failure" (`ets_log` in `driver.json` and `defaults.json`), and the newest
  entry of ETS's history pane instead of its first four lines, which for some
  runs were only the pane's header and `1.1.1` (#422).
