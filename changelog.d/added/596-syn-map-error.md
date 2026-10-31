- The synthetic product `syn-map-error` ("False-alarm filter", `NEST-FALSE`,
  #604 row 38) wraps an `LdCtrlUnload LsmIdx="5"` of `syn-product-07b0` in
  `LdCtrlMapError` (`0xC0042B08` to 0 and back), the Siemens shape of #614,
  captured with ETS: ETS sends the unload to object 5 ahead of the other
  unloads, as bussard does, and the row is identical. The generator gained
  `LdCtrlMapError` in the 07B0 product procedure.
