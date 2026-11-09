- `bussard flash` no longer writes a property the device holds already after
  the procedure's parameter reset: the catalogue's `LoadedImage` lists those
  values, and ETS leaves the writes out (the Hager STYM/STXM generation
  `M-0009_A-E0D0` to `A-E0D3`, and `A-E0EE`). The post-flash read-back still
  compares them with the project, and a parameter-only download writes them.
  A count-less write the `LoadedImage` records as one element is one element,
  and an undeclared write from a later element sends that element, not the
  whole property (`A-E0EE`). A declared write of the all-zero placeholder to a
  property no parameter is placed in sends nothing, as ETS (`A-20B6`,
  `A-20B8`, `A-20B9`) (#951, #971).
