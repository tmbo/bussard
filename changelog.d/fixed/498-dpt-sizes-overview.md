- Every fixed-width DPT main type of the KNX 03_07_02 overview has a size
  (#498): E004, the monitor's size note and the raw-payload check of `write`
  now cover 15.x, 21.x, 22.x, 26.x, 27.x, 29.x and the 2xx structured types
  (a one-octet payload to a 245.600 GA is refused). The 2-bit 23.x and 3-bit
  31.x values are packed into the APCI, where a raw `write --payload` sent
  them as a separate data octet.
