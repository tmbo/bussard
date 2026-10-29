- An application that does not announce `SupportsExtendedMemoryServices`
  (Zennio DIMinBOX and DALIBOX, ABB Caldion and RoomTouch, Busch-Jaeger Split
  Unit Gateway) has its memory above `0xFFFF` written and read with
  `A_UserMemory_Write`/`A_UserMemory_Read` as ETS does, in `flash`, `apply`,
  `backup` and the MCP tools, instead of `A_MemoryExtended_*`, a service
  such a device does not offer. `knxtrace` decodes the user-memory services,
  so the oracle compares these downloads (#472).
