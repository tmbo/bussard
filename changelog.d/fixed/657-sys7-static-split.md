- A System 7 load procedure that allocates an absolute segment in parts
  outside any `<choose>`, with a parameter placed in the gap (the Jung
  `A-5015-13`), is planned as ETS downloads it instead of refused: the parts
  are allocated and written, the gap is kept on the device and its parameters
  are reported as kept, matching the synthetic `syn-s7-static-split` capture
  (#657).
