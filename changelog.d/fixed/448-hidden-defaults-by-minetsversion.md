- On System 7 the parameters the configuration does not show are written at
  their defaults by the application's `MinEtsVersion` (5 or later), not by its
  schema version, as ETS does: a project/23 application with
  `MinEtsVersion` 4.0 keeps the segment template (synthetic twins
  `syn-s7-hidden-default` and `syn-s7-hidden-default-ets4`) (#448).
