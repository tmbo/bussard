- The synthetic product `syn-le-order` ("Tree-altitude meter", `NEST-ALTI`,
  #604 row 4) declares `ParameterByteOrder="LittleEndian"` with signed 16- and
  32-bit numbers, a DPT 9 float and an IEEE-754 Single float at asymmetric
  defaults, captured with ETS for #403. The generator renders the `float`
  parameter type kind and the `ParameterByteOrder` option; its rendering paths
  have unit tests (`test_generate.py`).
