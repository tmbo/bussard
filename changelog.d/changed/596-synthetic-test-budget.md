- The synthetic catalogue's CI tests scale with the catalogue: the oracle
  rows test checks the rows on four workers and names each failing row with
  its time, the knx-sim flash-then-plan loop runs as four shards, and the
  oracle test passes the resolved Python interpreter to the script (a pyenv
  shim made a row take 18 s instead of 2 s). CI now also runs the synthetic
  product generator's unit tests and `generate.py --check` (#596).
