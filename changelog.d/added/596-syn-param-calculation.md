- The synthetic product `syn-param-calculation` ("Prey calculator",
  `NEST-CALC`, #604 row 11) has an inline JavaScript `<ParameterCalculation>`
  with two placed outputs, one of them a hidden `LegacyPatchAlways`
  parameter, captured with ETS for #427 and #450: at defaults ETS writes both
  outputs at their defaults without running the script, and writes the hidden
  `LegacyPatchAlways` output, as bussard does. The generator gained
  calculations and `legacy_patch_always`.
