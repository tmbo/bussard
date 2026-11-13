- `apply` no longer refuses a Data Secure link on group object 0. Object 0 has
  no group-object table entry, so it has no PID 61 security flag; its group
  keys (PID 53) follow its links, as ETS writes them. The plan reads the
  group key table's count, so a group address linked only through object 0
  that joins or leaves Data Secure is planned and written (#1094).
