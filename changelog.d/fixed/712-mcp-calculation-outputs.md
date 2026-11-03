- `knx_get_device` lists the parameters a `<ParameterCalculation>` computes in
  `computed_parameters`, with the value a download writes and the
  calculation's id, and `knx_set_parameter` refuses a calculation output (also
  with `force`), naming the inputs to set instead, as ETS shows outputs
  read-only (#712).
