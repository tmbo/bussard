- knx-sim resolves the property writes of a module definition's load
  procedure per module instance (`BaseObjIdx`, `BaseStartElement`), so the
  objects a module instance addresses exist: the Schneider STXF121's metering
  modules write PID 208 of objects 6 to 9, the sim held none of them, and ETS
  reported "Die ausgewählte Geräte-Ressource ist zurzeit nicht verfügbar" (#422).
