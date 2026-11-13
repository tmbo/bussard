- `flash` no longer leaves out a fixed property write (`InlineData`) to an
  object its object walk did not find: the write goes to the index the load
  procedure names, as ETS sends it, and a device without that object fails
  the flash with the object and property named. The read-back after a flash
  compares every property the flash wrote, fixed values included, on every
  system; a skipped template step for an absent object is named in the
  result. The walk is bounded by the 8-bit object index instead of 16, so a
  device with more objects (the Hager 07B0 actuators have 32) is seen in
  full (#1073).
