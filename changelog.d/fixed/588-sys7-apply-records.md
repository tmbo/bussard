- `bussard apply` on a System 7 device now writes what ETS's partial download
  writes (#588): it no longer writes the address table's first entry (the
  device's own address), it sends the product's own allocation record for each
  table segment (the whole segment with the product's access octet, as `flash`
  does, instead of the written length with access `f2`), and it rewrites the
  group-object table on LSM 3 also when no communication flag changes. The
  EK-E72 partial-download oracle rows are identical on memory and load control.
