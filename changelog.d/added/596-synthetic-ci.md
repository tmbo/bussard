- CI replays the synthetic products' committed ETS captures on every push,
  with no vendor data (#596): the offline oracle `--check` over
  `captures/synthetic/rows.txt`, knx-sim's calibration replay of each capture
  against the memory image ETS wrote (`image.json`), and the flash-then-plan
  sim loop over the synthetic catalogue in the `sim-conformance` job.
