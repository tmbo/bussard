- A TUNNELLING_ACK with an error status now makes the tunnel repeat the
  request once and then treat the link as lost, as a missing ACK does; the
  send failed at once before. Only an inbound frame one behind the expected
  sequence is ACKed as a repeat; one two or more behind is dropped without an
  ACK (KNXnet/IP Tunnelling 3/8/4 §2.6.1, #516).
