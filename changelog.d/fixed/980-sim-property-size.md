- knx-sim describes a property a System 7 load procedure writes without
  `InlineData` with the size the product gives it: the text parameter placed
  in it, else its `LdCtrlDeclarePropDesc`, else one octet. The MDT Central
  Operation Unit Smart capture that showed one-octet label writes predates
  this sizing (#841) and is retaken; tests now hold it (#980).
