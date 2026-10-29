- The tunnel reads the interface's max APDU length (tunnelling feature 07)
  right after CONNECT, as ETS does, when the interface's extended description
  shows it serves feature services; `Tunnel::feature_get` reads any feature.
  Inbound TUNNELLING_FEATURE frames are now ACKed and sequence-counted like a
  TUNNELLING_REQUEST, so a FEATURE_INFO no longer knocks the inbound sequence
  out of step (KNXnet/IP Tunnelling 3/8/4 §3, #514).
