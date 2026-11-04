- A colour parameter declared as text with a `(?# TypeColor:RGB)` or `(?# TypeColor:HSV)`
  pattern (ekinex, MDT) is written as its 3 colour octets, as ETS does, instead of 7
  ASCII characters over the parameters that follow it. A colour space bussard does not
  encode is refused (#833).
