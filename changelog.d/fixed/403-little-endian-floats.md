- A product with `ParameterByteOrder="LittleEndian"` gets its float
  parameters (DPT 9, IEEE-754 Single and Double) written least significant
  octet first, as ETS writes them, and `bussard device` and the read-back
  decode them in that order. Before, bussard wrote these floats big-endian
  and the device held different values than ETS would have written. The
  ETS capture of the synthetic `syn-le-order` is the regression test
  (#403).
