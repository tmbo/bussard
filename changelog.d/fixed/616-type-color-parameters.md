- A `TypeColor` parameter (`Space` `RGB`, `RGBW` or `HSV`) has its own type:
  its value `#FF0000` is written as one octet per component in the written
  order, read back and shown by `bussard device` the same way, and checked
  when set. The flash refused it as a non-integer, so four Ekinex
  applications could not be programmed at their defaults. Product models move
  to format 11 and regenerate on the next command (#616).
