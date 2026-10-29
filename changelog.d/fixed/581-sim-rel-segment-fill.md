- knx-sim honours the `Mode`/`Fill` octets of a relative allocation
  (Configuration Procedures §3.5.1.2): a filled download over a previous image
  no longer leaves that image's octets where the new one equals the fill byte,
  which failed the MCB check of the ALLinBOX 1612 sim-loop runs (#581).
