- knx-sim keeps an object that is in `Loading`, with its allocated segment,
  across a master reset with erase code 4, 5 or 6, so ETS's KNX Virtual DA.tp
  download (StartLoading, RelSegment, master reset erase code 4, parameter
  writes) completes again. Outside a load procedure the reset still unloads
  (#600).
