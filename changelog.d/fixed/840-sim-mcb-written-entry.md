- knx-sim keeps a `PID_MCB_TABLE` entry a tool writes while the object is
  Loading and reads back its size, CRC control byte and access as written,
  with the CRC it computes over that many octets of the segment (Resources
  §4.2.27). It answered access `0xFF` and the written span's size instead
  (ekinex A-4945, #840).
