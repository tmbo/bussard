- `LdCtrlWriteRelMem Size` bounds what a System B flash streams: an
  application whose `RelativeSegment` is larger than its allocation (ABB
  Caldion, eight corpus applications) no longer writes past the allocation,
  and its MCB check runs over the written length. A parameter value past the
  written size refuses the plan (#564).
