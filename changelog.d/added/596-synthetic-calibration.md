- `tools/ets-sweep/synthetic/calibrate.py` runs a synthetic product and the
  product it was cloned from through the ETS sweep, distils each capture into
  a knx-sim request fixture (`synthetic/distil.py`), runs the offline oracle row
  of each, replays both fixtures in knx-sim and prints whether ETS, the oracle
  and the sim treat the two alike (#596). knx-sim's `ets_calibration.rs` gains
  an environment-gated replay of such fixtures.
