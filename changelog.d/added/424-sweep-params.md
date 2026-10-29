- ETS sweep part 5, not yet run live: `params.py` draws seeded parameter
  configurations (page switches bussard's `device --json` names first, then
  enumeration and integer parameters off their defaults), has the driver set
  them on ETS's parameter pages, download and export the project, and compares
  each capture with `bussard import` of that export (#424).
