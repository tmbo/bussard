- The offline oracle gives a property-only row (a `properties` plan, mask 0021,
  the KNX IP interface shape) the property parity as its verdict, as it already
  did for the `interface secure` plan: identical when every property write
  matches, differs on any write only one side sent. ETS's commissioning writes
  stay listed, not counted. The Enertex IP Secure Interface rows (plain, Data
  Secure and the parameter set) now read identical instead of not comparable
  (#1043).
