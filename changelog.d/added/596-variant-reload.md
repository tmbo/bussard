- Run variants of the synthetic products (#604): `capture.py --variant` runs
  several ETS downloads in one knx-sim session and commits the last one with
  its base. The `reload` variant of `syn-s7-0705` and `syn-s7-0701` shows that
  ETS runs no pre-download unload pass on a device that holds the same
  application (#488). The offline oracle gained `state=loaded`, a per-row
  model template (`dir=`) and `run=params`; knx-sim's calibration replays a
  variant's base first.
