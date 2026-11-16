- A parameter-only download now writes the octets of a device-managed
  parameter (`Access="None"`, such as a download flag) at your project's
  value even when the device held that value when bussard read it, the way
  a complete download writes them. A Jung heating actuator (`A-20E0`)
  cleared its download flag during the load, so the MCB check of the
  octet's entry failed and the restart was not sent (#1168). No capture
  shows yet whether ETS's own partial download rewrites the flag (capture
  plan #572). The octets ride along with a download that changes something
  else: a device whose only difference is such an octet still plans as
  nothing to write (#289), an octet the download keeps is still not
  written, a restore leaves them as the device holds them, and the closing
  read-back does not compare them. The plan counts them among the
  parameter octets and says how many there are.
