- `bussard keys add-certificate` enters device certificates (the 36-character
  FDSK labels) into the key store, from the terminal without echo or with
  `--stdin`. The label's serial number selects the device; a serial no device
  has yet is kept and attached when `bussard assign` reads it off a device. A
  different key already held for a serial is a conflict and is never
  overwritten. `keys show` lists the unassigned certificates and the
  secure-capable devices without a factory key. Every surface enters labels
  through `bussard_service::enroll_certificate` (#728).
