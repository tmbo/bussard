- Parameter calculations: values a program computes with a `<ParameterCalculation>`
  script (VBScript or JavaScript), such as an Ekinex EK-E72's fan block or a
  Jung LED dimmer's dimming curve, are now computed in the Dynamic evaluation
  and written instead of their vendor defaults (#427). As in ETS, a script
  runs only once one of its inputs differs from its default. The EK-E72's match its
  devices byte for byte; the Jung curves are not yet compared with an ETS
  download. A script outside the supported subset, calculations that do not
  settle, and a model value a calculation would replace refuse the device's
  write, naming the calculation, instead of writing a value the script did not
  compute.
