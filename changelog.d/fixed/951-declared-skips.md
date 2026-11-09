- `bussard flash` no longer writes a property the device holds already after
  the procedure's parameter reset: the catalogue's `LoadedImage` lists those
  values (objects relative to the mask's `FirstAppObjectIdx`), and ETS leaves
  the writes out (the Hager STYM/STXM generation `M-0009_A-E0D0` to `A-E0D3`,
  and `A-E0EE`). A write after another write of the procedure to the same
  elements is always sent. bussard reads every such property during the
  download and writes it as before when the device holds something else; the
  post-flash read-back compares it with the project, and a parameter-only
  download writes it. A count-less write the `LoadedImage` records as one
  element is one element, and an undeclared write from a later element sends
  that element, not the whole property (`A-E0EE`) (#951).
