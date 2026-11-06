- knx-sim sizes a property a product declares with `LdCtrlDeclarePropDesc` as
  an array of the declared type as far as its writes reach, so ETS can read
  the Gira Eco's PID 69 in chunks, and it answers `A_FunctionPropertyExt_Command`
  on a function property a product calls by object type (the Gira
  IR-Gateway's PID 208 of type 65281) (#422).
