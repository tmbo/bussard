- Synthetic products `syn-color-param` (Plumage colour lamp, `NEST-COLOUR`)
  and its twin `syn-color-param-hsv` (`NEST-COLHSV`): `syn-minimal` with a
  reached `TypeColor` parameter in memory, default `#FF0000`, in the RGB and
  the HSV space, captured with ETS (#604 row 40). RGB: ETS writes `FF 00 00`,
  as bussard does. HSV: ETS converts the RGB value and writes `00 FF FF`,
  bussard `FF 00 00`; the row is `expect=differs` until #616 is fixed. The
  generator renders the `color` type kind.
