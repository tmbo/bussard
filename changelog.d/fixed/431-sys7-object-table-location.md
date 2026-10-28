- `apply` on a System 7 device writes the address table alone, bounded by its
  segment, and no longer moves the octets behind it as if they were the
  group-object table (#431). The group-object table is read where the
  product declares it, its descriptors numbered from 0 as on the device. A
  device that refuses that read keeps its plain table read. Without product
  data and a reported association table, the address table is not grown.
