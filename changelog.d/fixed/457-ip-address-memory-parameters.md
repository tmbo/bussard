- A `TypeIPAddress` parameter stored in memory (the Zennio ALLinBOX DNS
  servers) is written as the address's four octets and read back as the
  dotted quad, where the flash kept the template octets without a word. A
  parameter of an unknown type that has a value but no width now refuses
  (#457).
