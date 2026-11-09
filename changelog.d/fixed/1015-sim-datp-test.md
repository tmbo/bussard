- knx-sim reports the empty `PID_MCB_TABLE` entry of #422 only for an object
  that reached Loaded; a never-loaded object that holds nothing reports no
  entry again, so the re-download skip is never taken on a blank device and
  the DA.tp calibration test passes with its fixture present (#1015).
