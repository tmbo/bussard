- The CLI and the MCP server are checked to write the same requests for the
  same change over the synthetic catalogue (epic #596, step 8, the #314
  class): `bussard plan` and `apply` (or `flash`) against `knx_plan_device`
  and `knx_apply_device`, on knx-sim from the same flashed state, for every
  product's apply and for the flash of the products whose switches show or
  hide a com-object. All 45 simulated products write identically.
