- `flash` sends a relative allocation (`LdCtrlRelSegment`) with the product's
  `Mode` and `Fill` octets as given, as ETS does: a `Mode="0" Fill="255"`
  record now carries `00 ff` instead of `00 00`. The device behaviour is the
  same (Mode 0 keeps the memory); the load-control records are now identical
  to ETS's capture of `syn-relseg-fill` (#480).
