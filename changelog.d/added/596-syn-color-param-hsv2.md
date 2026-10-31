- Synthetic product `syn-color-param-hsv2` (`NEST-COLHSV2`): the HSV twin of
  `syn-color-param` with two non-primary defaults (`#FC35C7`, `#90F32C`),
  captured with ETS. ETS writes `DF C9 FC` and `3F D0 F3`: hue times
  255/360, saturation times 255, both truncated, and value the largest RGB
  component. The row is `expect=differs` until #616 is fixed.
