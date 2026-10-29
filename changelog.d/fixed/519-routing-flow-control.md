- Routing now paces its ROUTING_INDICATIONs as the standard requires: at
  most 50 per second with at least 5 ms between two, and after a
  ROUTING_BUSY a random extra wait of up to N x 50 ms on top of the busy
  time, with the busy counter N (KNX IP 3/2/6 §2.1, Routing 3/8/5 §2.3.5).
  Routing datagrams leave with a multicast TTL of 16, PID_TTL's default
  (3/8/3 §2.5.18), instead of the OS default of 1 that never crosses an IP
  router (#519).
