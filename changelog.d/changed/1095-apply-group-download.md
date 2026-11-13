- `apply` of a link change on System B (mask 07B0, 27B0, 57B0) with product
  data now runs the partial download ETS runs: it unloads the group-object,
  association and address tables, reloads all three, completes them and
  restarts the device in the same session, then reads it back. `apply --line`
  restarts each such device. The plan and its question name the restart. A
  restart that could not be sent fails the result and stays pending: the next
  `plan` offers it and the next `apply` sends it. A write of the link tables
  alone (`restore`, no product data) refuses a group-object table a failed
  download left unloaded (#1095).
