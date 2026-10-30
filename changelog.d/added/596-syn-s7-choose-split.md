- Synthetic product `syn-s7-choose-split` (Split-branch perch, `NEST-SPLIT`):
  `syn-s7-0705` with a load-procedure `<choose>` whose taken branch allocates
  the parameter AbsSegment in two parts around a placed parameter, captured
  with ETS (#604 row 9). ETS allocates and writes the two parts only and never
  touches the gap; bussard refuses the product (#411).
