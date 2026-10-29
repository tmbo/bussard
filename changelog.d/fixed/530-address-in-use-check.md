- `assign` and `adopt` check on the bus that the target address is free before
  writing it (a connect and a descriptor read, step 1 of the standard's
  `NM_IndividualAddress_Write`), refuse when a device answers there, naming
  its mask, manufacturer and order number, and take `--force` to proceed
  (#530). `commission` counts an answering address as commissioned only when
  the device there reports the model's order number; any other answer refuses
  that device as an address in use. `replace` names the same details.
