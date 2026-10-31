- The synthetic product `syn-module-repeat` ("Triple chick feeder",
  `NEST-TRIFEED`, #604 row 19) instantiates a `ModuleDef` three times by a
  `<Repeat>`, each instance's parameter and com-object base drawn from an
  `<Allocator>`, captured with ETS as the regression row of #449: ETS writes
  the three module parameters at +0x10, +0x14 and +0x18 and objects 2 to 4,
  as bussard does (row identical). The generator gained allocators, module
  definitions and `<Repeat>`.
