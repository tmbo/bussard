- knx-sim answers `A_FunctionPropertyCommand` and
  `A_FunctionPropertyState_Read` (KNX 3/3/7 §3.4.7) and declares the function
  properties a product's `LdCtrlInvokeFunctionProp` steps call as
  `PDT_FUNCTION`: the Siemens 0701 programs call object 5's PID 52 before the
  download, the sim stayed silent, and ETS reported "Das Gerät antwortet
  nicht" (#422).
