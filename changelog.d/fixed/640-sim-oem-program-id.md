- knx-sim reports the original manufacturer of an OEM application (`-O0002`
  on Busch-Jaeger's ABB programs) in the program id, as a real device does;
  ETS copies it into the TaskSegment records, and 40 Busch-Jaeger captures
  differed from the house device because the sim reported 0007 (#640).
