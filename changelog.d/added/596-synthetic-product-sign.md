- `tools/ets-sweep/synthetic/` clones the KNX Virtual DA.tp into a renamed
  `M-00FA` product and signs a fabricated `.knxprod` in the ETS VM with ETS's
  own signing library (`sign.py` plus our `signer.cs`, compiled there), so ETS
  can import products of the synthetic catalogue (#596).
