- knx-sim's System B IP interface keeps the manufacturer properties its
  product writes on the KNXnet/IP parameter object (the Siemens IP Interface
  Secure's PID 236), so ETS can describe and write them; the ETS sweep reads
  `IsIPEnabled="1"` of older product files as IP-enabled, so the Jung Sonos
  gateway's sim has the KNXnet/IP object ETS looks for (#422).
