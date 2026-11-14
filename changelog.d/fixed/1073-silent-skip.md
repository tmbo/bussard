- `flash` no longer leaves out a fixed property write (`InlineData`) to an
  object its object walk did not find: the write goes to the index the load
  procedure names, as ETS sends it, and a device without that object fails
  the flash with the object and property named. A segment write to an object
  the device lacks fails the flash instead of landing in another object's
  segment. The read-back after a flash compares every property the flash
  wrote, fixed values included, on every system: an MCB entry without the
  CRC the device computes, the PEI type not at all. A skipped template step
  for an absent object is named in the result. The object walk is no longer
  cut at 16 objects (the Hager 07B0 actuators have 32), ends where a device
  answers the device object again, runs once per session, and a stored
  object table of exactly 16 is checked and read again when the device has
  more (#1073).
