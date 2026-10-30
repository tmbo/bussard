- `bussard flash` of a product without `knx_master.xml` (or with a `<KNX/>`
  stub, as the synthetic product catalogue ships) plans the full download of a
  `MergedProcedure` application: bussard carries the complete-download
  load-procedure template of the System B masks 07B0, 27B0 and 57B0 and uses it
  when the product's master data has none for the mask. A product's own master
  data still wins, so vendor downloads are unchanged (#607).
