- The synthetic product `syn-product-07b0` ("Nest-building planner",
  `NEST-PLAN`, #604 row 37) spells out a 07B0 download as one
  `ProductProcedure` with the tables as relative segments on LSM 1 to 3, the
  Siemens shape of #614, captured with ETS: ETS allocates and writes each
  table at its length, not at the op's `Size`, adds no unload of object 5 and
  no restart, and the row is identical. The generator gained the 07B0 product
  procedure, and the synthetic sim loop's flashability gate passes the empty
  tables `bussard flash` would.
