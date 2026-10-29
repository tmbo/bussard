- A System 7 `LdCtrlAbsSegment SegType="1"` now goes out as a stack-segment
  allocation (Additional Load Controls subtype 01) as ETS sends it, not as a
  data segment; any other `SegType` refuses the plan (#487).
