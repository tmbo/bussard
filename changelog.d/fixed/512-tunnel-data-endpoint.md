- A plain UDP tunnel now sends its TUNNELLING_REQUESTs and ACKs to the data
  endpoint the gateway names in its CONNECT_RESPONSE, and receives them from
  there, while CONNECTIONSTATE and DISCONNECT stay on the control endpoint
  (#512, KNXnet/IP Core §5.2, §8.6.3). A gateway that serves a tunnel on its
  own data port no longer times out every frame after a successful CONNECT;
  one that uses a single port, as most do, sees no change. knx-sim can serve
  that split with `gateway.data_port`, and the testkit `MockGateway` and
  `RawGateway` with `data_port()` and `bind_with_data_port()`.
