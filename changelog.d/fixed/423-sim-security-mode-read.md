- knx-sim answers the security-mode read (PID 51) with the return code, the
  ReadServiceID and the mode, as ETS 6 expects before a secure download, and
  sends no state after a negative load-control return code (#423).
