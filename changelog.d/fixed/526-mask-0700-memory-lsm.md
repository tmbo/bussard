- A System 7 device on mask `0700` is now driven through the memory-mapped load
  state machine, the realisation the KNX profile makes mandatory there, instead
  of the optional property one; knx-sim picks the same realisation per mask
  when a device's config omits `lsm_access` (#526).
