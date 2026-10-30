- The synthetic product `syn-minimal` ("Nest-side light switch",
  `NEST-LIGHT`) is captured once with ETS 6.4.1 into knx-sim and committed
  under `captures/synthetic/` with its oracle row (`rows.txt`, identical at
  100.0 % coverage) and a manifest of the ETS version, simulator build and
  product XML digest (#596). `tools/ets-sweep/synthetic/capture.py` runs the
  whole flow; `95-offline-oracle.sh` accepts a product XML directory in a row
  and zips it with the stub master; an ungated test fails when a product's XML
  changed since its capture. The synthetic product generator now escapes `-`
  in ids as ETS does (`NEST.2DLIGHT`).
