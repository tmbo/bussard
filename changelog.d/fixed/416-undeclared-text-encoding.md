- A text parameter of a program that declares no `TextParameterEncoding` is
  written in ISO 8859-1, NUL-padded to its field, as ETS 6 writes it (the
  capture of the synthetic product `syn-text-undeclared`: "Störung" as
  `53 74 F6 72 75 6E 67 00 ...`). Such programs with accented defaults, ABB
  `M-0002_A-A016-22` among them, plan again instead of being refused. A
  character whose octet is not settled by the capture (the euro sign, the
  eight ISO 8859-15 replacements, anything beyond U+00FF) is still refused
  (#416).
