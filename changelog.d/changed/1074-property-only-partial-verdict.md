- The offline oracle gives a parameter-only download that writes no memory
  on either side (a property-only program) the property parity as its
  verdict, as it does for a property-only plan (#1043). The ETS sweep's
  `params.py partial` no longer pins such a row, so its first run on an
  empty `--work` directory gives the same verdict as the second; the two
  synthetic property-only partial rows read identical instead of not
  comparable (#1074).
