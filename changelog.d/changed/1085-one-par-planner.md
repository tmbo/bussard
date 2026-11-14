- A parameter-only download (`flash --parameters-only`, `apply`, `restore
  --parameters`) of a System B program spliced into the master template now
  runs the mask's `par` procedure for programs with parameter memory too, as
  ETS does: it reads the base pointer before the unload and checks it after
  the load, and runs the procedure's steps without `AppliesTo` (MergeId 7's
  MCB checks of the tables, for example). Only the parameter octets that
  differ from the device are written, as before. A device whose tables differ
  from the project is refused before anything is written. `bussard plan`
  reads the fixed property writes only when a write will run, and a second
  parameter backup within the same second no longer replaces the first
  (#1085).
