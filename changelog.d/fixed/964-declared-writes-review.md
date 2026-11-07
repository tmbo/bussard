- Property writes from a load procedure: the dry-run dump splits a System B
  write to an object named by type into the requests the flash sends; a
  program that is not Data Secure enabled has a by-type write with a PID past
  8 bits refused at plan time instead of failing after the unload; the write
  and the read-back find a by-type object with one lookup, also past a walk
  that stops short; the all-zero PID 13 placeholder is refused on every write
  when neither an application id nor a parameter supplies it, and takes the
  id of the object it names; a declared property with one parameter placed by
  index and another by type is refused instead of written in part; and an
  undeclared write with `InlineData` honours its `Count` (#964).
