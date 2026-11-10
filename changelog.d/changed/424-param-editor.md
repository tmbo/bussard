- Internal (ETS sweep): the parameter editor of the ETS driver works on
  channel products: it walks every page of ETS's page tree, reads each row's
  control (checkbox, radio buttons, dropdown, number or text field) and value
  from the screen, and sets a change by page and label with a read-back.
  `params.py run` draws each configuration from that survey (page switches
  first, then other rows, then rows of the pages that appeared), builds the
  oracle's model from the values ETS shows afterwards, `--representative`
  runs `tools/ets-sweep/params-subset.json`, and `params.py partial` captures
  ETS's parameter-only download (#424).
