- `tools/ets-sweep`: ETS 6 downloads a product into knx-sim without a hand on
  the VM (epic #419, part 1 #420): a UI Automation plus OCR driver inside the
  Windows VM, a sweep script that runs the sim in the VM and keeps the capture,
  and the knx-sim behaviour ETS needs that bussard never asked for (tunnelling
  feature services, L_Data.con, a T_ACK before every answer, the request's
  sequence number in the answer, verify-mode memory echo, a PID_TABLE
  description, plain SEARCH_REQUEST, a configurable tunnel address, a pcap of
  the gateway's own datagrams).
