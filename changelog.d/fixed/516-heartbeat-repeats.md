- An unanswered heartbeat is now repeated three times before the tunnel counts
  as lost, four CONNECTIONSTATE_REQUESTs in all, as KNXnet/IP Core §5.4 asks;
  it gave up after three in total before (#516). The wider duplicate-ACK
  window of the tunnel is now documented as a deviation from Tunnelling §2.6.1.
