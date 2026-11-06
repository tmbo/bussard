- knx-sim compares only the first `Count` octets of an `LdCtrlCompareProp`
  whose `InlineData` is longer than `Count` elements can hold: the Gira
  IR-Gateway's PID 78 compare carries a seventh padding octet, the sim served
  it, and ETS reported a hardware type mismatch (#422).
