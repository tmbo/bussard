- The synthetic product `syn-dynamic-tests` ("Worm-movement detector",
  `NEST-WORM`, #604 row 28) has a `<Channel>` whose block holds three
  `<choose>`s with single-value, value-list, comparison and default `<when>`
  tests, one com object per branch, captured with ETS as a regression row of
  the Dynamic evaluator (#345): ETS takes the same branches as bussard (row
  identical). The generator gained channels and chooses inside a block.
