- knx-sim: a Data Secure device checks the GO flags (PID 61) against the
  group-object table it is loading, not a 4095 fallback, so ETS can program
  the flags of a device with more than 4095 group objects (#423).
