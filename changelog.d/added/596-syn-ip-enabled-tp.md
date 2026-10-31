- The synthetic product `syn-ip-enabled-tp` ("Treetop uplink", `NEST-UPLINK`,
  #604 row 34) is `syn-minimal` on hardware with a KNX IP interface built in
  (`IsIPEnabled`, `AdditionalAddressesCount="2"`), captured with ETS for
  #455. After the application ETS writes the KNXnet/IP parameter object
  (PIDs 51, 66, 67, 76 in two writes, 55, 53), and bussard writes the same
  block: the row is identical with `props=ok(8)`. The generator gained
  `ip_enabled` and `additional_addresses_count`. `capture.py` gives such a
  product's sim the KNXnet/IP object and plans its row with the sweep
  project's `[knxnet]` table, and the knx-sim replay reads `knxnet` from
  `sim.yaml`.
