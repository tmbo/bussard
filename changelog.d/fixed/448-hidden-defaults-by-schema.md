- `flash` writes the parameters the configuration does not show at their
  defaults on a System 7 application of schema project/21 or later without
  `DownloadInvisibleParameters`, as ETS 6 does; older System 7 applications
  keep the segment template, System B ones are unchanged. Established by the
  synthetic twins `syn-s7-hidden-default` (project/23, defaults written) and
  `syn-s7-hidden-default-p11` (project/11, template kept) and the sweep's
  Busch-Jaeger `A-FF11-15` (project/20, template kept) (#448).
