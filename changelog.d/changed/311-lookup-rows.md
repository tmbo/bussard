- `knx_model_lookup` lists a capability repeated on several channels of a
  device once, with `channels`, and one repeated on devices of one
  application once, with `also_on`; a device whose com-objects send the
  measured value the query names (DPT 9.004 for "Helligkeit") comes first,
  with those objects in `sends`. `knx_get_device` returns the keyed
  parameters only and counts the ETS-internal `hidden@`/`label@` values in
  `hidden_parameters` (`technical: true` includes them; 16.7 KB to 10.3 KB on
  a 16-fold binary input) (#311).
