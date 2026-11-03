- bussard can manage a KNX IP interface over a KNXnet/IP device management
  connection (connection type 03h), plain over UDP or inside a KNXnet/IP
  Secure session of the management user (#523). `--device-management` asks
  for it on `plan`/`apply` of an interface, `describe` and `interface secure`;
  without the flag these commands fall back to it when the interface is the
  gateway and has no free tunnel slot or a duplicated tunnel address.
  Property reads and writes go as `M_PropRead`/`M_PropWrite`, the rest as
  cEMI transport-layer frames; the tunnel stays the default.
