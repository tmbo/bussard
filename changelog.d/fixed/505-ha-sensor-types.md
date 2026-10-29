- `bussard ha` gives a sensor the Home Assistant KNX `type` of its exact
  sub-type for `7.x`, `9.x`, `12.x`, `13.x` and `14.x` (#505): `7.600` is
  `color_temperature`, `7.005` `time_period_sec`, `13.100`
  `long_delta_timesec`, `13.011`-`13.016` the apparent, reactive and MWh energy
  types, so HA shows kelvin and seconds with a device class instead of pulses.
  An unknown `12.x` now uses `4byte_unsigned` instead of the signed
  `pulse_4byte`, and an unknown `7.x` `2byte_unsigned`.
