- The application program is modelled once (#906): the product model is built
  straight from the parsed application program instead of being written as YAML
  and parsed back through a second set of structs, the Dynamic tree has one serde
  form, static parameter placement is computed once for the image writer and the
  read-back decoder, and the parameter rows of `plan`, `reconstruct` and the MCP
  read-backs are bussard-download's own. No byte written to a device changes; on
  the reference installation a command that rebuilds the product models takes
  6.3 s instead of 12.7 s.
