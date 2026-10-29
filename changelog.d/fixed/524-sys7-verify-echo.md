- A System 7 download in verify mode compares every `A_Memory_Response` echo
  with the octets it wrote and fails the step on a difference, naming the
  address and both values (#524). The session sets verify mode again on every
  new connection before its next write, `flash -v` reports the echoes compared,
  and knx-sim clears verify mode with the connection, as the standard says.
