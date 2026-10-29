- A gateway status error names the KNXnet/IP code and its meaning, e.g.
  `E_NO_MORE_UNIQUE_CONNECTIONS` or `E_KNX_CONNECTION`, instead of a bare hex
  value (#517). `E_NO_MORE_UNIQUE_CONNECTIONS` (0x25) points at the duplicated
  tunnelling address (PID 53) to fix.
