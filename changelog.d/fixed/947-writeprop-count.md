- A load procedure's property write of more than 255 elements is no longer
  refused. It goes out in requests of at most 15 elements, as ETS sends it.
  The offline oracle now judges a procedure's own `PID_LOAD_STATE_CONTROL`
  writes as load controls (#947).
