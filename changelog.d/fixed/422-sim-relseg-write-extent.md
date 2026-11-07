- knx-sim allocates an application program segment at least as large as the
  product's `LdCtrlWriteRelMem` writes into it: the Hager TYMS616D and
  TYMS620D request 258 octets on object 4 and write 642 and 802, which the sim
  refused, so ETS reported that the device does not respond (#422).
