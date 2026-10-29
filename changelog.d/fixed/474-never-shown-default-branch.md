- A `<choose>` whose only branch is `<when default="true">`, on a parameter that is
  never shown, has no memory, is not a `TypeNone` label and is not
  `Access="None"`, takes no branch, as in ETS (#474): the Zennio Flat push buttons
  no longer enable the 4 or 5 dummy objects ETS leaves out of the group-object
  table. A default branch beside other `<when>`s, and one on an `Access="None"` or
  `TypeNone` switch (ABB, Busch-Jaeger, Zennio IRSC), is still taken.
