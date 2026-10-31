- The synthetic product `syn-s7-delay` ("Slow-hatch timer", `NEST-HATCH`,
  #604 row 39) adds `LdCtrlDelay MilliSeconds="200"` before the restart of
  `syn-s7-0701`, captured with ETS for #615: ETS pauses 211 ms after the last
  LoadCompleted and before `A_Restart`, where bussard pauses too; the row is
  identical. The generator gained `LdCtrlDelay` on System 7.
