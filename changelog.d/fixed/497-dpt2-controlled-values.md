- The 1-bit controlled values (DPT 2.001-2.012, forced operation) decode,
  encode and parse (#497). `monitor` and `read` show `Control: On` or
  `No control` where they showed `0x03`, and `write <ga> "control on"`,
  `"control down"` (2.008) or `release` is accepted.
