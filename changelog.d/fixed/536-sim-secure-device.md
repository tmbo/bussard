- knx-sim's Data Secure device follows the standard where it was more lenient
  or stricter (#536): a Sync_Req raises the stored tool-access counter (as
  does bussard's mock device role), a Sync_Req within 1 s of the last
  Sync_Res is ignored, a Sync_Req carrying the device's own serial number is
  answered, PID 61 octets with reserved bits set are accepted and the bits
  ignored, and a secured group telegram is checked in the standard's order,
  a tool-access flag on it counting an access error.
