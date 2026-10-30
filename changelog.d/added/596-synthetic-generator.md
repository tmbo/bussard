- `tests-support/synthetic-products/`: fabricated `M-00FA` products for
  checking bussard, knx-sim and ETS against each other without vendor data
  (#596). A TOML spec per product renders deterministically into committed
  product XML (`generate.py`, stdlib Python), zipped on demand with a stub
  `knx_master.xml`; `bussard-prod` and knx-sim read every product in an
  ungated test. The first product, `syn-minimal` (07B0, merged procedure, two
  parameters, two objects), is the baseline the others derive from. The VM
  signer (`tools/ets-sweep/synthetic/sign.py`) now puts ETS's own master data
  in place of the stub, which ETS 6.4 refuses on import.
