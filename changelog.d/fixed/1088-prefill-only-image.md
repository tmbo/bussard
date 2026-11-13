- The offline oracle no longer reports a memory write bussard does not send: a
  `--dump-images` plan marks an image that holds only its segment's pre-fill
  octet as `fill_only`, and the operation-order check leaves it out, as the
  flash and ETS both write none of it (#1088).
