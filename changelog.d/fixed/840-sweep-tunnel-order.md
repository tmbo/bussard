- The ETS sweep's oracle model gives an IP device whose application declares
  `<BusInterfaces>` its tunnelling addresses in the order ETS assigns them,
  descending from `.255` (1.1.255 to 1.1.248 for eight), and keeps the
  ascending order for one with only `AdditionalAddressesCount` (#840).
