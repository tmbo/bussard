- `bussard ha-config` emits `invert: true` for a 1.009 Open/Close contact
  mapped to a `window`, `door`, `opening` or `garage_door` binary_sensor
  (#496). 1.009 is 0 = open (KNX 03_07_02 §3.1), the inverse of 1.019, and
  Home Assistant showed such a window as closed while it was open.
