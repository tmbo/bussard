- The 4-bit check of a KNX Secure device certificate is CRC-4 over the serial
  number and the FDSK with the polynomial x^4 + x + 1, MSB first (not
  reflected), init 0, confirmed against real device labels. bussard, the
  phone enrolment page and `tools/ets-sweep` checked the reflected
  CRC-4/ITU instead, which real labels fail. A label whose check does not
  match is now refused as mistyped (`invalid`, nothing written) even when its
  serial number matches a device, and the page no longer offers to send it
  (#201, #728).
