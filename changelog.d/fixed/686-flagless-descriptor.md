- A System B group-object table now carries the descriptor of a shown,
  unlinked com object with no flags at all: its priority and size code
  (`03 00` for a Low 1-bit object), as ETS writes it. bussard wrote `00 00`
  (#686).
