- knx-sim takes the last `Count` octets of a longer `LdCtrlCompareProp`
  `InlineData` as the compared value (the leading octets are padding), and the
  ETS sweep seeds a device property a parameter names by `ObjectType="0"`:
  the Gira IR-Gateway's hardware type is `00 00 00 20 00 03` (#422).
