- A System 7 flash runs the pre-download unload of LSMs 1 to 4 and the restart
  only when the device's probed state calls for it: an LSM in Loaded, Loading
  or Error, or a resident application id. A device whose every LSM answers
  Unloaded gets none, as ETS gives none to a factory-fresh device. A device
  left mid-load (Loading) now keeps the pass. `flash --dry-run --resident`
  takes System 7 LSM states, and the offline oracle's `state=fresh` row option
  plans a capture of a fresh device that way (#488).
