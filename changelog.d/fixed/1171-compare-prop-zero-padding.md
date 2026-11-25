- `flash` no longer fails a real device's `LdCtrlCompareProp` whose `InlineData`
  pads the property with trailing zeros: the Ekinex EK-E72-TP compares the
  six-octet `PID_HARDWARE_TYPE` against ten octets, and the device answers six.
  When every octet past the device's answer is zero, the octets it holds are
  compared; any other difference still stops the flash (#1171).
