- An unanswered heartbeat is now repeated three times before the tunnel counts
  as lost, four CONNECTIONSTATE_REQUESTs in all, as KNXnet/IP Core §5.4 asks;
  it gave up after three in total before (#516).
