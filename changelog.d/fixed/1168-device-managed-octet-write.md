- A parameter-only download now writes the octets of a device-managed
  parameter (`Access="None"`, such as a download flag) at your project's
  value even when the device held that value when bussard read it, as a
  complete download does. A Jung heating actuator (`A-20E0`) cleared its
  download flag during the load, so the MCB check of the octet's entry
  failed and the restart was not sent (#1168). The octets ride along with a
  download that changes something else; a device whose only difference is
  such an octet still plans as nothing to write (#289), and an octet the
  download keeps is still not written. The plan says how many such octets
  it writes besides the ones that differ.
