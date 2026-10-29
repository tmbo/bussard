- A DPT 9 (2-octet float) group value is encoded as the nearest
  representable code (#493). The encoder rounded the mantissa once per
  exponent step and could land up to two resolution steps off: 50.01 went out
  as 50.04, -2621.45 as -2624.00. Group values and `<TypeFloat Encoding="DPT 9">`
  parameter images now share one rounding rule (smallest exponent, ties to
  even, as ETS writes).
