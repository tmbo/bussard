- `bussard flash` no longer refuses a load procedure that calls a function
  property with `LdCtrlInvokeFunctionProp` (the Hager and Berker 0701
  programs of the ETS sweep, two Hager and one Gira 07B0). The call goes out
  as ETS sends it, and a device that answers with an error, or not at all,
  fails the flash. System 7 programs that declare a property with
  `LdCtrlDeclarePropDesc` are planned as on System B (#946).
