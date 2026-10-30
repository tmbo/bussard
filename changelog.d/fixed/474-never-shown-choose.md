- On a System B application, a `<choose>` whose only branch is the default
  one, on a parameter that has no memory and that no page shows, now selects
  no branch, as ETS does: the com objects behind it get no group-object
  descriptor and its parameters are not reached. The synthetic
  `syn-choose-never-shown` capture now compares identical. System 7
  programs keep taking such branches, as ETS does there. Product models move
  to format 12 (`virtual: true` on such parameters) and regenerate on the
  next command (#474).
