- Device support comes in three categories (#1097): `proven` (bussard wrote
  a real device with the application and the read-back matched), `likely`
  (computed from the committed ETS sweep: identical image and load control
  for every captured build, coverage at least 95 %, and a proven device for
  every mask; or a house device with an identical ETS capture) and
  unsupported (a known problem naming its issue and cause, or unknown). `proven` and `likely` write without
  `--allow-unsupported`; a plan, the write and the assistant say a `likely`
  device is not confirmed on a real device. The list now holds 4 proven and
  1040 likely applications, and 83 with a known problem (79 the sweep finds
  differing from ETS, 4 named by an open bug), refused with their issue. `bussard device --supported`, `--json` and
  the MCP `support` block report the `category`.
  `tools/supported-devices/generate.py` computes the list, and CI fails when
  it is stale. The synthetic products are no longer listed, and the Theben
  Meteodata (mask `0701`, no proven device yet) is unknown until a live run
  is recorded.
