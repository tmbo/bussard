- Synthetic product `syn-ip-address-param` (Homing beacon, `NEST-HOMING`):
  `syn-minimal` with a reached `TypeIPAddress` parameter in memory, default
  192.168.27.21, captured with ETS (#604 row 21): ETS writes `C0 A8 1B 15`,
  and so does bussard (regression row for #457). The generator renders the
  `ip_address` type kind.
