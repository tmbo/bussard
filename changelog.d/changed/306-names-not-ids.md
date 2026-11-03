- Change sentences (`bussard status`, `history`, `show`, `undo`, `diff` and
  the MCP edit results) name a group address or device by its name alone; the
  address follows only when the name is not unique or the group address is
  protected, and an unnamed one still reads as its address (#306). A com
  object without a name of its own is called by its vendor text, and a
  channel without a name or vendor text is left out. The Home Assistant
  automation sentence and its default alias use group-address names. The
  technical restart line of `knx_restart_device` moved from `summary` to
  `outcome`.
