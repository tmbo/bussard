- knx-sim merges the `LdCtrlCompareProp` steps that check single elements of
  one property (`StartElement`, `Count`) into that property's element array:
  the Siemens 07B0 actuators compare object 4's PID 246 element by element and
  the sim answered every element with the first compare's value, so ETS
  refused the download with "Das Schreiben in den Speicherbereich ist
  fehlgeschlagen" (#422).
