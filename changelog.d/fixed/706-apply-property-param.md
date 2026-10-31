- `bussard apply`, `bussard plan`, `bussard flash --parameters-only` and the
  MCP apply compare the interface-object properties a product places
  parameters in (#669) with what the device holds, so a change to such a
  parameter alone is planned and written with its read-back instead of
  ending as "nothing to do". The plan names it (`territory-mark (object 4
  PID 201) = 07, was 5A`; `writes: parameter property (object 4 PID 201)`)
  (#706).
