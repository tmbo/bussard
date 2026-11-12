- Internal (ETS sweep): the driver finds radio buttons whose circles sit a few
  pixels above the label's text line and clicks their centre, and tells two
  parameter pages of one name apart (`page_n`); `params.py` writes module
  parameter keys in bussard's selector form (`MD-2_M-13_MI-1_...`, `_MI-<n>`
  for a `<Repeat>`) and keeps the case of a page name when it picks the module
  instance, so an input read as 'Eingang l:' is no longer taken for
  'Eingang L:' (#1054, #1050).
