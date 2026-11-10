- `apply` and `flash --parameters-only` write a parameter change to a program
  whose parameters all live in interface-object properties (the Hager 07B0
  actuators) instead of refusing it: the download matches ETS's
  parameter-only download of such a program. The parameter backup taken
  first records those properties, and `restore --parameters` puts them
  back (#944).
