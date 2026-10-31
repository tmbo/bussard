- `bussard flash` writes a parameter that lives in an interface-object
  property (`<Parameter><Property …/>`) on System B devices, as ETS does: an
  `LdCtrlWriteProp` without `InlineData` writes the value the parameters
  compose, and the read-back after the flash or an apply compares it. Before,
  the write was skipped and the flash reported success while the device did
  not hold the parameter. A write that no parameter supplies a value for is
  refused. The offline oracle's headline verdict now reads `differs` when the
  memory is identical but the property writes differ (#669).
