- A com-object's transmission priority now reaches the device (#541). The
  product's `Priority` (`High`, `Alert`, `System`; a ref overrides its base
  object) is written into bits 9-8 of a System B group-object descriptor and
  bits 1-0 of a System 7 CONFIG octet; before, every descriptor went out Low.
  The product model carries it as `priority:` (model format 8).
