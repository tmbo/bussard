- A System 7 flash of a 0701 application whose load procedure names a task
  segment on load state machine 5 (Busch-Jaeger applications such as the
  binary input `A002-13`) no longer sends that record. The memory-mapped form
  has machines 1 to 4 only, ETS sends no record for 5, and the record failed
  the flash on a device that leaves the machine Unloaded (#489).
