- The synthetic product `syn-s7-hidden-default-ets4` ("Vintage egg heater",
  `NEST-EGGV4`) is `syn-s7-hidden-default` with `MinEtsVersion="4.0"` in
  schema project/23, captured with ETS for #448: ETS keeps the hidden
  parameter's template, so on System 7 `MinEtsVersion` decides, not the schema
  bussard keys on (row `expect=differs`). The generator gained
  `min_ets_version`.
