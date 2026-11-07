- The ETS sweep driver stops serving before it closes its socket on a
  self-restart, so a new upload no longer leaves the VM without a driver
  (#422).
