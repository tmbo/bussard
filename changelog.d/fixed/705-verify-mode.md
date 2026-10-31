- A System B download (07B0, 27B0, 57B0) of an application written over the
  plain memory services switches the device's verify mode on before its first
  `Verify="true"` memory write, as ETS does: it reads `PID_DEVICE_CONTROL`,
  writes bit 2 only when it is clear, and compares the `A_Memory_Response`
  echo of every later write with the octets written. A Data Secure or
  extended-memory application is left alone, as ETS leaves it. The offline
  oracle records ETS's read of the property and does not count the planned
  write where ETS found the bit already set (#705).
