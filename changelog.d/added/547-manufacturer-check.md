- The System B flash pre-flight reads the device's `PID_MANUFACTURER_ID`
  (object 0, PID 12) before anything is unloaded and refuses, naming both
  manufacturers, when it is neither the application's manufacturer nor its
  `OriginalManufacturer`; `--force` overrides as for a resident application.
  This is step 04 of the KNX download procedure and adds one read to a
  flash (#547).
