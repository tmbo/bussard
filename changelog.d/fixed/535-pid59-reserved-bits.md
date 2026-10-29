- The `PID_SEQUENCE_NUMBER_SENDING` write of `ip-secure on` writes the clock or
  the device's own counter, whichever is higher, and accepts the confirmation
  the device already protects with the new value; a device whose counter ran
  ahead of the clock no longer fails the step as a stale sequence (#535).
- A secured frame with one of the six reserved bits above the inner APCI set
  is refused by bussard's Data Secure decoder and dropped by knx-sim without
  a failure count, its sequence still counted as received (#535).
