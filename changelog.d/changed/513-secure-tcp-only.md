- A KNXnet/IP Secure tunnelling session runs over TCP only, as the KNX
  standard requires (KNX IP Secure 3/8/9 §2.2.3.3, §2.2.3.6.4). The opt-in
  `--secure-transport udp` is gone (`auto` and `tcp` stay), and an interface
  that advertises Secure but refuses the TCP connect is reported with the
  likely causes instead of a hint to try UDP. knx-sim and the testkit mock
  discard a SESSION_REQUEST over UDP, as TSSK test 2.2.25 expects (#513).
