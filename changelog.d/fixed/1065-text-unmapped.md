- A text parameter of a program without `TextParameterEncoding` whose value holds
  a character none of ISO 8859-1, Windows-1252 and ISO 8859-15 has (such as `℃`)
  is written with `?` for it, as ETS writes it, instead of refusing the program
  (#1065, the KNX Smart Touch S3 `A-0098-12-75FF`).
