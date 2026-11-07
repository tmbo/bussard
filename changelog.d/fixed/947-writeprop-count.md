- A load procedure's property write of more than 255 elements is no longer
  refused. It goes out in requests of at most 15 elements, as ETS sends it.
  A procedure's own unload, start-loading or load-completed write to an
  object's load state (ise smart connect, object 8) is confirmed by the state
  the device answers instead of failing as an unconfirmed write, and the
  offline oracle judges it with the load controls (#947).
