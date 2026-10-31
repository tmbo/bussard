- `bussard flash` sends a load procedure's `LdCtrlMasterReset` as the
  confirmed Master Reset (`A_Restart` restart type 1 with the erase code and
  channel) to every device, KNX Virtual included, as ETS does. The KNX Virtual
  DA.tp capture shows ETS sending that form and the device answering it; the
  bare `A_Restart` bussard sent there was a misreading of the capture's other
  restarts. A device that refuses it (error code 2, "unsupported erase code")
  now fails the flash, as it fails ETS's download, instead of getting a Basic
  Restart ETS never sends (#611).
