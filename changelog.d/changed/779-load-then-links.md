- `knx_plan_device` no longer refuses to load a self-contained application
  whose links would differ from the project (#779). The plan says the
  application is loaded and then the links are written, one yes covers both,
  and `knx_apply_device` writes the links after the verified download as
  `bussard apply` does, with its own read-back (`links` in the result). The
  result is verified only when that read-back matches the project. The same
  holds for a parameter change that needs a full download.
