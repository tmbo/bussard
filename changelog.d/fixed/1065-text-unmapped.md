- A text parameter of a program without `TextParameterEncoding` is written as
  ETS 6 writes it: Windows-1252, Windows' best-fit look-alike for a character
  1252 lacks (`Ł` as `L`), and `?` for the rest (two for an emoji). The euro
  sign, `œ` and every other character are no longer refused (#1065, the KNX
  Smart Touch S3 `A-0098-12-75FF`, captured on `syn-text-unmapped`).
- `validate` warns with W051, and `plan` and `flash` print a note, when a text
  value holds characters the download writes as a look-alike or `?` (#1065).
