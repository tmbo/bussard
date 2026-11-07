- `bussard flash` no longer refuses a System B load procedure that declares
  a property with `LdCtrlDeclarePropDesc` (the five Hager 07B0 actuators of
  the ETS sweep and about 30 more applications in the catalogue). The
  declaration sends nothing; the property write after it goes out in elements
  of the declared type, with the value the parameters compose, as ETS writes
  it (#938).
