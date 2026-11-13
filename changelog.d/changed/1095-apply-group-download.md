- `apply` of a link change on System B (mask 07B0, 27B0, 57B0) now runs the
  partial download ETS runs: it unloads the group-object, association and
  address tables, reloads all three, completes them and restarts the device,
  then reads it back (#1095).
