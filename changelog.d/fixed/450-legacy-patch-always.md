- A hidden parameter declaring `LegacyPatchAlways="true"` is written at its default,
  as ETS does whatever `DownloadInvisibleParameters` says (#450): the Zennio
  DALI-BOX group limits, the Flat and Flat Display brightness and LED night
  settings, and the ABB Data Logging and Busch-Jaeger Dim Slave hidden values now
  match ETS. A `LegacyPatchAlways` parameter that is also computed by a
  `<ParameterCalculation>` gets its default, not the computed value, until #427.
