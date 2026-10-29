- A `<choose>` on a parameter that is never shown, has no memory and is not a
  `TypeNone` label takes no `<when default="true">` branch, as in ETS (#474): the
  Zennio Flat push buttons no longer enable the 4 or 5 dummy objects ETS leaves
  out of the group-object table. Never-shown `TypeNone` switches (ABB, Busch-Jaeger)
  still open their default branches.
