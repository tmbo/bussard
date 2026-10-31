- `tools/ets-sweep/synthetic/capture.py` refuses to re-capture a synthetic
  product whose XML changed without an `[application] version` bump (ETS keeps
  the application it imported first under the same version and reports
  "imported" anyway), names the version to bump to, and fails when the
  captured download carries another program version than the spec's. A
  re-capture recomputes the row options from the new verdicts and keeps
  hand-set ones. The ETS sweep's `oracle.py` writes `state=fresh` on System 7
  rows, from the same function the synthetic rows use (#650, #640).
