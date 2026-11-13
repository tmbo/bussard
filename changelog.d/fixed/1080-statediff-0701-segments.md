- The offline oracle's partial-download comparison (`knxtrace statediff`)
  reads a mask 0701 `AbsSegment` load-control record at the right offset,
  with the same parser as the operation-order comparison, and keeps every
  segment of an object. It read the record one octet early, so a 0701
  `run=apply` or `run=params` row named its regions after the wrong
  addresses (LSM 1 at 0x0040 instead of 0x4000). Verdicts do not change
  (#1080).
