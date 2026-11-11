- `flash --parameters-only` and `apply` send the parameter-only download of a
  program whose parameters all live in properties and whose load procedure has
  no `par` allocation (Hager `M-0009_A-E802-13-7620`), as ETS sends it: obj4
  Unload and StartLoading, the parameter reset (`EraseCode="5"`), every
  property write of the `par` procedure, then LoadCompleted and the restart.
  They refused it before (#1052).
