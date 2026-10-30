- `bussard flash` and the MCP flash detect KNX Virtual by its `M-00FA_A-25xx`
  application ids (the "KNX Virtual" catalogue section 25), not by
  manufacturer `0x00FA` alone. Other `M-00FA` applications (OpenKNX, the
  synthetic catalogue) now get the confirmed Master Reset and hold one
  connection for the download, like every other device (#605).
