- ETS sweep part 4, not yet run live: `secure.py` runs the secure-capable
  applications against a factory-state sim device with a synthetic FDSK and
  serial number, has the driver set the project password, enter the device
  certificate and export the keyring, and checks that knxtrace decodes the
  capture end to end; `secure.py cert` writes and checks certificate labels
  (#423).
