- Synthetic product `syn-s7-static-split` ("Fixed-fork perch",
  `NEST-FORK`): `syn-s7-choose-split` with the split of the parameter
  AbsSegment outside any `<choose>` and a placed parameter in the gap, with
  its ETS capture (#657). ETS allocates and writes the two parts and never
  touches the gap, as in the `<choose>` case; the row is
  `expect=not-comparable` while bussard refuses the product.
