- `bussard flash` onto a System B device that already holds the same
  application runs the product's `AppliesTo="par"` load procedure, as ETS
  does: the application segment is allocated without the fill flag (Mode 0),
  an object that reads Unloaded and is not loaded gets no unload, and no
  factory reset opens the download; the group-object table stays when its
  MCB already matches. A device holding another application, or none, keeps
  the `full` procedure (#490). `flash --dry-run --resident FILE` plans
  against a recorded device state, and the offline oracle passes it the
  state ETS read from the capture, so the house rows compare
  `loadctl=identical`.
