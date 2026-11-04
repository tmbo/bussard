- ETS capture of a KNX Data Secure download: ETS 6.4.1 commissions the
  synthetic product syn-secure in knx-sim (FDSK session, tool key, security
  mode, then the download under the tool key). The ETS sweep driver now
  handles ETS's Data Secure dialogs: the project password, the device
  certificate when the device is added, and the keyring export with
  certificates. Synthetic keyrings are exported under a public password and
  committed next to the capture. The offline oracle takes a per-row keyring
  (`keyring=`) to decode the secured frames. The syn-secure row is compared:
  the memory and load control are identical to ETS. The security object's
  writes differ until the keyring imports into a key store (#858) (#423).
