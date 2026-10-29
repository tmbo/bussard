- knx-sim no longer opens Loading on a System 7 Task allocation record that
  arrives in Unloaded: per the load state machine transition table
  (Resources Table 94) a record or a LoadCompleted in Unloaded leaves the LSM
  Unloaded, so a tool that sends a record before StartLoading no longer passes
  the conformance loop (#529).
