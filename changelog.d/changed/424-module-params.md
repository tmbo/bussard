- Internal (ETS sweep): the parameter-set oracle maps a change on a module's
  page to the parameter of that module instance (the instance's pages in
  tree order, the page text's `{{...}}` placeholders matched), keeps an
  editable virtual parameter that feeds calculations, and the driver logs
  what it saw before it walks the tree for a page (#424).
