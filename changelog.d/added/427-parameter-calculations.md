- Parameter calculations: values a program computes with a `<ParameterCalculation>`
  script (VBScript or JavaScript), such as an Ekinex EK-E72's fan block or a
  Jung LED dimmer's dimming curve, are now computed in the Dynamic evaluation
  and written instead of their vendor defaults (#427). As in ETS, a script
  runs only once one of its inputs differs from its default. Verified byte for
  byte against ETS downloads of the EK-E72, a Jung LED dimmer and the synthetic
  product that changes a calculation's input. A script outside the supported subset, calculations that do not
  settle, and a model value a calculation would replace refuse the device's
  write, naming the calculation, instead of writing a value the script did not
  compute.
