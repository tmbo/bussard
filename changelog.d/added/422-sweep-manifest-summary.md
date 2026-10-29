- ETS sweep: `oracle.py` imports each product file once and shares it across
  its rows (seconds instead of minutes and 1.6 GB per row of a catalogue file),
  `defaults.py` refuses a capture from a catalog row of another application
  version (`--relabel` for recorded results), and `summary.py` writes the
  labels-only outcome manifest and the parity summary per mask family and
  manufacturer with the verdict changes since the previous run (#422).
