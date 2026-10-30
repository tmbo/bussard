- Synthetic product `syn-union-bitfields` (Feather-bit packer, `NEST-BITS`):
  `syn-minimal` with a 16-bit union of two member types and three sub-octet
  parameters packed into one octet by `BitOffset`, captured with ETS (#604
  row 29): ETS writes `0A 0B` and `56`, and so does bussard (regression row
  for the packing). The generator checks that a `bit_offset` lies in 0..7.
