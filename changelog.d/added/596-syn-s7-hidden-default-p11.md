- The synthetic product `syn-s7-hidden-default-p11` ("Heirloom egg heater",
  `NEST-EGGOLD`) is `syn-s7-hidden-default` in schema project/11, the schema
  of the #448 vendor applications. ETS keeps the segment template for its
  hidden parameter where the project/23 twin gets the default, so the
  schema, not the System 7 mask, decides (#448; row identical). The generator
  gained `[application] schema = 11`, and the signer signs a product in its
  own schema (`signer.exe --schema`).
