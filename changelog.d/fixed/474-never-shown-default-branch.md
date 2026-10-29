- A `<choose>` whose only branch is `<when default="true">`, on a read-only
  (`Access="Read"`) parameter that is never shown, has no memory and is not a
  `TypeNone` label, takes no branch, as in ETS (#474): the Zennio Flat push buttons
  no longer enable the 4 or 5 dummy objects ETS leaves out of the group-object
  table. A default branch beside other `<when>`s, and the only default branch on a
  read-write, `Access="None"` or `TypeNone` steering parameter (ABB and
  Busch-Jaeger channel switches, Zennio IRSC), is still taken.
