- `apply` of a link change on System B (mask 07B0, 27B0, 57B0) with product
  data now runs the partial download ETS runs: it unloads the group-object,
  association and address tables, reloads all three, completes them and
  restarts the device, then reads it back. The plan and its question name
  the restart. With a parameter change in the same apply, the parameter
  download sends the one restart. A device whose group-object table cannot
  be read keeps the link-tables-only write (#1095).
