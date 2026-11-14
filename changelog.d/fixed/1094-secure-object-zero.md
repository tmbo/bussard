- `apply` no longer refuses a Data Secure link on group object 0. Object 0 has
  no group-object table entry, so it has no PID 61 security flag; its group
  keys (PID 53) follow its links, as ETS writes them. A verified secured write
  (and `adopt`, where the keyring and the flags agree) records the group
  addresses of the device's group key table in `bussard.lock`
  (`group_keys`); `plan` compares the project's keyed addresses with that
  record and cross-checks the device's entry count. Without a key store or
  without a record the key side is not compared, and the plan says so (#1094).
