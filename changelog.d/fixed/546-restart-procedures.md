- A load procedure's `LdCtrlMasterReset` now goes out as the confirmed Master
  Reset with the op's erase code and channel number on every device but KNX
  Virtual (which keeps the bare `A_Restart` its capture shows); an
  "unsupported erase code" answer falls back to a basic restart, as the
  standard asks of a client that finds no support. The restart process time a
  device announces is waited out in full, with a warning above 60 s, instead
  of being capped at 60 s (#546).
