- knx-sim keeps the program version (PID 13) writable when a load-procedure
  compare seeds it: ETS stamps it at the end of the download, and the sim
  refused the write on an Enertex IP system device (#422).
