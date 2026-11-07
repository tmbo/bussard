- Internal: the project model walks the Dynamic tree with one visitor,
  evaluates each device once for the device view and its lookups, writes
  `bussard.lock` from its serde structs, merges an edited device file with
  one recursive merge, and shares one descriptor between decoding, parsing and
  encoding the integer DPTs. No change to `bussard.lock`, device files,
  `knx_show_device` or `--json` output (#907).
