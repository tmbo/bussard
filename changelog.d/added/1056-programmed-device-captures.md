- ETS references for a programmed device are gated in CI: a download over
  a programmed 07B0 device (`syn-minimal` `reload` and `other-app`), a new
  Data Secure product with a pre-filled segment (`syn-secure-fill`, the
  answer to #1081: ETS sends no factory reset), ETS's unload of the
  application (`syn-minimal`, `syn-s7-0705`), the address assignment
  (`syn-minimal` `assign`), a secured address next to plain ones
  (`syn-secure` `links`) and two more link-change downloads (#1056).
