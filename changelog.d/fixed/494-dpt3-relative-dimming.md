- Relative dimming and blind steps (DPT 3.007, 3.008) can be written and
  inferred (#494). `write`, `knx_write_group`, the viz and Home Assistant rules
  take `increase 25%`, `down 50%`, `up` or `break`; `read` and `monitor` print
  the step size (`Increase 25 %`) where they printed the code as if it were a
  count of steps (`Increase step 3`); `knx_infer_group` proposes 3.007 for a
  4-bit payload.
