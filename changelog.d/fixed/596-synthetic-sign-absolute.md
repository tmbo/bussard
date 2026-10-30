- `tools/ets-sweep/synthetic/sign.py` writes a directory signature ETS 6.4
  accepts (the signer signed from a relative path before, and ETS refused the
  file with "Projektdatei hat keine gültige Signatur"); the signed DA.tp clone
  imports into ETS's catalogue. `--dir-only` signs without rehashing (#596).
