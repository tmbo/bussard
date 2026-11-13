- The offline oracle's diff now counts, per memory region, the octets bussard
  writes that ETS never wrote into an allocation without fill: they are not
  compared, and after ETS's download the device keeps what it held there
  (#1084). The synthetic product `syn-relseg-dataless-hidden` asks ETS which
  value a hidden parameter's octets get under a Fill other than `00`.
