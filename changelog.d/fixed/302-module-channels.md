- `knx_show_device`, `bussard device` and `knx_model_lookup` list the channels
  of a module instance the configuration does not reach (a Jung actuator's
  switch outputs while it runs blinds) as inactive, with the parameters that
  enable them. An enable step no longer names an internal (`Access="None"`)
  parameter: it names the parameter that sets it, or says "enabled by ETS
  only". A capability lookup evaluates only the pages holding a match and
  builds each application's condition index once, about half the CPU time on
  a 47-device installation (#302).
