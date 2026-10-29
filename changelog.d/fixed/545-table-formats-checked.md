- The association table's entry format is now read from the device (the
  property description of `PID_TABLE`) by `describe`, `adopt`, `apply` and the
  flash pre-flight, which refuse a format-0 table (one-octet TSAP and ASAP)
  instead of misreading or overwriting it; the flash records the format in its
  device facts. Com-object sizes follow the full value field type table
  (Resources Table 88, up to 252 octets), and a System B plan refuses an
  `ObjectSize` without a code instead of writing it as 1 bit (#545).
