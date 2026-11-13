- `apply` no longer refuses a Data Secure link on group object 0: it has no
  group-object security flag, and the download writes the group keys and the
  flags of the other objects as ETS does (#1094).
