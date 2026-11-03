- `bussard.lock` records each device's serial number (`serial_number`, lock
  version 4) when `adopt`, `assign`, `scan` or `describe` reads it, so
  `bussard keys add-certificate` and the phone enrolment session match a
  certificate to a device ETS never saw and report its address and name. A
  certificate entered before its device was read is attached to it in the key
  store as soon as one of those commands reads the serial. `describe` shows
  the serial. A lock without serial numbers is still written as version 3
  (#752).
