- knx-sim describes a property a product's load procedure writes with
  `Count` > 1 as `Count` elements of the generic PDT of their size, and takes
  and reads it element by element, so ETS writes it as it would to a real
  device instead of skipping the write (#692).
