- `apply` on a System 7 device now loads the tables in the order ETS 6.4.1
  uses for a table-only download and ends with a basic restart, as ETS does
  (#433). It waits for the device to answer again before the parameter write
  and the read-back, so the read-back also shows the write survived the
  restart. The plan's `writes` line says `then a restart`.
