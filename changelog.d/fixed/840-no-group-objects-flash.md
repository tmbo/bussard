- `flash` of a System B program without group objects (the ekinex KNX IP
  interface secure) no longer refuses with "no table image was supplied":
  like ETS it allocates the empty address, association and group-object
  tables and writes none of them, and reads each table's own load check.
