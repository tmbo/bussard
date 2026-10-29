- System 7 downloads lower `LdCtrlTaskPtr` (the Task Pointer Record) and
  `LdCtrlTaskCtrl2` (Task Control Record 2) to their Additional Load Controls
  records (segment types 03h and 05h, 11 octets memory mapped, 10 by
  property) instead of refusing the procedure, and knx-sim accepts both while
  Loading (#527).
