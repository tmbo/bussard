- The System B parameter-only download, and the parameter part of `apply`, run
  the partial download of Configuration Procedures §3.5.3 as ETS runs the
  product's `par` procedure: Unload, Load, the relative allocation in Mode 0,
  the writes at the base the device reports after the allocation,
  LoadCompleted (#543). It refuses an object that is not `Loaded` before the
  Unload, writes the whole image where the device moved the segment, and stops
  where the reference reads zero. The MCB check stays.
