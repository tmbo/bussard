- The synthetic product `syn-secure` ("Nest-guard lock", `NEST-GUARD`, #604
  row 18) is `syn-minimal` made KNX Data Secure capable: `IsSecureEnabled`
  with room for 4 group keys and 4 sender addresses. bussard imports it with
  those capacities, and knx-sim builds it as a factory-fresh secure device
  with a synthetic FDSK and serial number. A factory-state sim device now
  keeps the security table sizes its product declares. `capture.py` captures
  a secure product through the sweep's secure project (#423); the capture
  itself is still pending.
