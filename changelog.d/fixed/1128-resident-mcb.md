- Re-flashing the same application reads each memory control block from entry
  1, entry by entry, as the standard numbers the entries and ETS reads them; it
  read element 0, the number of entries, as entry 1. The download keeps only the
  group-object table when its MCB matches, as ETS does on the house devices, and
  only where the product declares that MCB check; the application object and the
  address and association tables are always reloaded, so the lone unload of
  object 5 and the program version write to a loaded object are gone. A refused
  read reloads the object; a failure after the keep runs the download in full.
  The parameter backup sums a multi-entry MCB table instead of taking entry 1
  (#1128, #1127).
